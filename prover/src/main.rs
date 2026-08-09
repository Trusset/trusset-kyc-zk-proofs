//! `trusset-prover` binary entrypoint.
//!
//! Reads a JSON job spec from stdin, emits NDJSON events to stdout, writes
//! per-subject bundles to disk. Env vars:
//!
//!   - `TRUSSET_KYC_MASTER_KEY`   (required, 32-byte hex)
//!   - `TRUSSET_KYC_SIGNING_KEY`  (required, 32-byte hex)
//!
//! Exit codes: 0 ok, 2 partial (≥1 subject failed), 1 batch-aborting
//! (env / config / parse error).

use std::collections::BTreeMap;
use std::io::Read;
use trusset_circuits_common::{conjectured_security_bits, STARK_SECURITY_BITS};
use trusset_prover::{
    audit::AuditLog,
    bundle::build_subject_bundle,
    errors::{ErrorCode, ProverError, Result},
    io::{Event, EventStream},
    job::{parse_config_hash, Job},
    rekey::rekey_bundle,
    sign::SigningSecret,
};

const ENV_MASTER_KEY: &str = "TRUSSET_KYC_MASTER_KEY";
const ENV_SIGNING_KEY: &str = "TRUSSET_KYC_SIGNING_KEY";
const ENV_NEW_MASTER_KEY: &str = "TRUSSET_KYC_NEW_MASTER_KEY";

fn main() {
    let exit_code = run();
    std::process::exit(exit_code);
}

fn run() -> i32 {
    // Startup gate: refuse to prove with `ProofOptions` that fall below
    // the published security floor. The constants are also checked at
    // compile time in `circuits/common/src/proof_options.rs`; this is the
    // operator-visible failure with a stable error code.
    if conjectured_security_bits() < STARK_SECURITY_BITS {
        eprintln!(
            "[prover] fatal: {}: pinned ProofOptions give {} conjectured bits, below the {}-bit floor",
            ErrorCode::WeakProofOptions,
            conjectured_security_bits(),
            STARK_SECURITY_BITS
        );
        return 1;
    }

    if let Some(bundle_dir) = rekey_target() {
        return run_rekey(&bundle_dir);
    }

    let mut events = EventStream::new(std::io::stdout());

    let (master_key, signing_key) = match load_keys() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };

    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        eprintln!("[prover] fatal: stdin: {}", e);
        return 1;
    }

    let job = match Job::parse_from_slice(stdin.as_bytes()) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };

    let config_hash = match parse_config_hash(&job.config_hash) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };

    let now_iso = current_iso_timestamp();

    // Open the spec §12.12 audit log under the configured output dir.
    // Soft-fails (writer = None) if the directory can't be created or
    // the file can't be opened — audit logging must never break the
    // prover's main flow.
    let mut audit = AuditLog::open(std::path::Path::new(&job.output_root));

    // Collect list commitment source hashes for the audit-log header.
    // We record the source SHA-256 (already authenticated in
    // manifest.lists) rather than recomputing the Rescue Merkle root
    // — both bind the list, and source SHA-256 is already present.
    let list_hashes: BTreeMap<String, String> = job
        .list_commitments
        .iter()
        .map(|(k, v)| (k.clone(), v.source_sha256.clone()))
        .collect();
    audit.emit_run_start(
        &now_iso,
        &job.config_hash,
        &list_hashes,
        job.skip_proofs,
        job.subjects.len(),
    );

    let _ = events.emit(&Event::Start {
        subjects: job.subjects.len(),
    });

    let mut ok = 0usize;
    let mut failed = 0usize;

    for subject in &job.subjects {
        let event_ts = current_iso_timestamp();
        let _ = events.emit(&Event::SubjectStart {
            subject_id: &subject.subject_id,
        });
        audit.emit_subject_start(&event_ts, &subject.subject_id);
        match build_subject_bundle(
            &job,
            subject,
            &master_key,
            &signing_key,
            &config_hash,
            &now_iso,
        ) {
            Ok(report) => {
                ok += 1;
                for t in &report.leaf_timings {
                    let leaf_ts = current_iso_timestamp();
                    let _ = events.emit(&Event::LeafProved {
                        subject_id: &subject.subject_id,
                        field: &t.field,
                        proof_bytes: t.proof_bytes,
                        ms: t.ms,
                    });
                    audit.emit_leaf_proved(
                        &leaf_ts,
                        &subject.subject_id,
                        &t.field,
                        t.proof_bytes,
                        t.ms,
                    );
                }
                let done_ts = current_iso_timestamp();
                let _ = events.emit(&Event::SubjectDone {
                    subject_id: &subject.subject_id,
                    bundle_path: &report.bundle_path.to_string_lossy(),
                });
                audit.emit_subject_done(&done_ts, &subject.subject_id);
            }
            Err(e) => {
                failed += 1;
                let fail_ts = current_iso_timestamp();
                let _ = events.fail(&subject.subject_id, e.code.clone(), &e.message);
                audit.emit_subject_failed(&fail_ts, &subject.subject_id, &e.code);
            }
        }
    }

    let end_ts = current_iso_timestamp();
    let _ = events.emit(&Event::Done { ok, failed });
    audit.emit_run_done(&end_ts, ok, failed);

    if failed == 0 {
        0
    } else if ok > 0 {
        2
    } else {
        1
    }
}

/// `--rekey-subject <bundle-dir>`: rotate one bundle's `secrets.enc` from
/// `TRUSSET_KYC_MASTER_KEY` to `TRUSSET_KYC_NEW_MASTER_KEY` without
/// re-proving. Returns `None` for a normal proving run.
fn rekey_target() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--rekey-subject" {
            return args.next();
        }
    }
    None
}

fn run_rekey(bundle_dir: &str) -> i32 {
    let old_master = match load_master_key(ENV_MASTER_KEY) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };
    let new_master = match load_master_key(ENV_NEW_MASTER_KEY) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };
    match rekey_bundle(std::path::Path::new(bundle_dir), &old_master, &new_master) {
        Ok(report) => {
            println!(
                "rekeyed {} ({} bytes) for {}",
                report.secrets_path.display(),
                report.bytes_written,
                report.subject_id
            );
            0
        }
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            1
        }
    }
}

fn load_master_key(env_name: &str) -> Result<[u8; 32]> {
    let hex_value = std::env::var(env_name).map_err(|_| {
        ProverError::new(
            ErrorCode::KeyMissing,
            format!("env var {} is required (32-byte hex)", env_name),
        )
    })?;
    let bytes = hex::decode(hex_value.trim().trim_start_matches("0x")).map_err(|_| {
        ProverError::new(ErrorCode::KeyMalformed, format!("{} is not hex", env_name))
    })?;
    if bytes.len() != 32 {
        return Err(ProverError::new(
            ErrorCode::KeyMalformed,
            format!(
                "{} must be 32 bytes (64 hex chars), got {}",
                env_name,
                bytes.len()
            ),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_keys() -> Result<([u8; 32], SigningSecret)> {
    let master_hex = std::env::var(ENV_MASTER_KEY).map_err(|_| {
        ProverError::new(
            ErrorCode::KeyMissing,
            format!("env var {} is required (32-byte hex)", ENV_MASTER_KEY),
        )
    })?;
    let signing_hex = std::env::var(ENV_SIGNING_KEY).map_err(|_| {
        ProverError::new(
            ErrorCode::KeyMissing,
            format!("env var {} is required (32-byte hex)", ENV_SIGNING_KEY),
        )
    })?;

    let master_bytes = hex::decode(master_hex.trim().trim_start_matches("0x"))
        .map_err(|_| ProverError::new(ErrorCode::KeyMalformed, "master key is not hex"))?;
    if master_bytes.len() != 32 {
        return Err(ProverError::new(
            ErrorCode::KeyMalformed,
            format!(
                "master key must be 32 bytes (64 hex chars), got {}",
                master_bytes.len()
            ),
        ));
    }
    let mut master = [0u8; 32];
    master.copy_from_slice(&master_bytes);

    let signing = SigningSecret::from_hex(&signing_hex)?;
    Ok((master, signing))
}

/// Produce a deterministic-format ISO 8601 timestamp at second granularity.
/// We render manually rather than pull in `chrono` to keep the dependency
/// surface minimal.
fn current_iso_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    // Days since 1970-01-01.
    let days = secs / 86_400;
    let seconds_today = (secs % 86_400) as u64;
    let h = seconds_today / 3600;
    let m = (seconds_today % 3600) / 60;
    let s = seconds_today % 60;
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

/// Inverse of `dispatch::days_from_civil` (Howard Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
