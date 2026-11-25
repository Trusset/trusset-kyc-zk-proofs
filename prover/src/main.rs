//! `trusset-prover` binary entrypoint.
//!
//! Reads a JSON job spec from stdin, emits NDJSON events to stdout, writes
//! per-subject bundles to disk. Key material, see `keys.rs`:
//!
//!   - from the CLI on the first stdin line when `TRUSSET_KYC_KEYS_STDIN=1`
//!     (the operator path: encrypted key file or macOS keychain), or
//!   - `TRUSSET_KYC_MASTER_KEY` / `TRUSSET_KYC_SIGNING_KEY` (CI only).
//!
//! Exit codes: 0 ok, 2 partial (≥1 subject failed), 1 batch-aborting
//! (env / config / parse error).

use std::collections::BTreeMap;
use std::io::Read;
use trusset_bundle_format::manifest::ToolchainBlock;
use trusset_circuits_common::{conjectured_security_bits, STARK_SECURITY_BITS};
use trusset_prover::{
    audit::AuditLog,
    bundle::{build_subject_bundle_with_toolchain, check_list_commitments, dry_run_subject},
    dates::epoch_days_to_iso_date,
    errors::{ErrorCode, ProverError, Result},
    io::{Event, EventStream},
    job::{parse_config_hash, Job},
    keys::{take_stdin_keys, StdinKeys},
    rekey::rekey_bundle,
    sign::SigningSecret,
};

const ENV_MASTER_KEY: &str = "TRUSSET_KYC_MASTER_KEY";
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

    let mut stdin = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut stdin) {
        eprintln!("[prover] fatal: stdin: {}", e);
        return 1;
    }
    let mut stdin_keys = match take_stdin_keys(&mut stdin) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };

    let job = match Job::parse_from_slice(stdin.as_bytes()) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[prover] fatal: {}", e);
            return 1;
        }
    };

    // Refuse an unpinned wall-clock epoch unless the operator asked for one.
    // A bundle proved against `utc_today` cannot be reproduced after the day
    // it was made: every per-subject key, nonce, commitment, and leaf hash is
    // derived from `epoch_days`. That makes the single thing an auditor asks
    // for — "reproduce this bundle" — impossible, so it is refused rather
    // than warned about.
    if let Err(e) = check_epoch_pinning(&job) {
        eprintln!("[prover] fatal: {}", e);
        return 1;
    }
    if job.unpinned_epoch {
        eprintln!(
            "[prover] ############################################################\n\
             [prover] # DEVELOPMENT MODE: UNPINNED EPOCH                          #\n\
             [prover] # epochDaysSource is utc_today, resolved to {} ({:>5}).  #\n\
             [prover] # These bundles CANNOT be reproduced after today and are    #\n\
             [prover] # marked unpinnedEpoch in the manifest for the rest of      #\n\
             [prover] # their lives. Do not issue evidence this way.              #\n\
             [prover] ############################################################",
            epoch_days_to_iso_date(job.epoch_days),
            job.epoch_days
        );
    }

    // Cross-check every list once, before any subject: a stale registry is a
    // property of the batch, not of a subject, and reporting it per subject
    // buries it.
    if let Err(e) = check_list_commitments(&job) {
        eprintln!("[prover] fatal: {}", e);
        return 1;
    }

    if job.dry_run {
        return run_dry(&job, &mut events);
    }

    let (master_key, signing_key) = match load_keys(&mut stdin_keys) {
        Ok(k) => k,
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
    let toolchain = toolchain_block();

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
        match build_subject_bundle_with_toolchain(
            &job,
            subject,
            &master_key,
            &signing_key,
            &config_hash,
            &now_iso,
            toolchain.as_ref(),
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

/// Refuse to prove against a wall-clock epoch that was not pinned, unless the
/// operator passed the development flag that the CLI translates into
/// `unpinned_epoch`.
fn check_epoch_pinning(job: &Job) -> Result<()> {
    let Some(source) = job.epoch_days_source.as_deref() else {
        // A job from pre-v3 tooling says nothing about its epoch source. It is
        // not this build's place to retroactively refuse those.
        return Ok(());
    };
    if source == "utc_today" && !job.unpinned_epoch {
        return Err(ProverError::new(
            ErrorCode::UnpinnedEpoch,
            format!(
                "security.epochDaysSource is \"utc_today\", which resolves to whatever day the \
                 batch happens to run ({}, epoch day {}). Every per-subject key, nonce, \
                 commitment and leaf hash derives from that number, so a bundle proved this way \
                 cannot be reproduced tomorrow and cannot satisfy an audit that asks you to. \
                 Fix: set \"epochDaysSource\": \"fixed:{}\" in config.json to pin today's date as \
                 the batch as-of date, or \"env:TRUSSET_KYC_EPOCH_DAYS\" to supply it per run. \
                 To proceed anyway for development only, re-run with --dev-unpinned-epoch.",
                epoch_days_to_iso_date(job.epoch_days),
                job.epoch_days,
                job.epoch_days
            ),
        ));
    }
    Ok(())
}

/// Which binary produced a bundle. Recorded because a v3 bundle must be
/// verifiable years later, and "some version of the tool" is not enough to
/// rebuild a verifier that accepts it. The digest is of the running
/// executable, so it cannot be claimed rather than measured.
fn toolchain_block() -> Option<ToolchainBlock> {
    let exe = std::env::current_exe().ok()?;
    let bytes = std::fs::read(exe).ok()?;
    Some(ToolchainBlock {
        prover_version: env!("CARGO_PKG_VERSION").to_string(),
        prover_sha256: trusset_bundle_format::archive::sha256_hex(&bytes),
        // Advisory only, and supplied by the build environment. The digest
        // above is the identifier that cannot be misstated.
        source_commit: std::env::var("TRUSSET_KYC_SOURCE_COMMIT").ok(),
    })
}

/// Dry run: validate every leaf of every subject, report every problem, write
/// nothing. Needs no key material, so an operator can check a batch before
/// they have finished setting the tool up.
fn run_dry(job: &Job, events: &mut EventStream<std::io::Stdout>) -> i32 {
    let _ = events.emit(&Event::Start {
        subjects: job.subjects.len(),
    });
    let mut total_problems = 0usize;
    let mut clean = 0usize;
    for subject in &job.subjects {
        let problems = dry_run_subject(job, subject);
        if problems.is_empty() {
            clean += 1;
            let _ = events.emit(&Event::SubjectDone {
                subject_id: &subject.subject_id,
                bundle_path: "",
            });
            continue;
        }
        total_problems += problems.len();
        for p in &problems {
            let _ = events.emit(&Event::LeafFailed {
                subject_id: &p.subject_id,
                field: p.leaf.as_deref().unwrap_or(""),
                error_code: p.code.as_str(),
                message: &p.message,
            });
        }
        let _ = events.fail(
            &subject.subject_id,
            problems[0].code.clone(),
            &format!("{} problem(s) on this subject", problems.len()),
        );
    }
    let _ = events.emit(&Event::Done {
        ok: clean,
        failed: job.subjects.len() - clean,
    });
    if total_problems == 0 {
        0
    } else {
        2
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

fn load_keys(keys: &mut StdinKeys) -> Result<([u8; 32], SigningSecret)> {
    let master = keys.master_key()?;
    let signing = keys.signing_key()?;
    Ok((*master, signing))
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
    let (y, mo, d) = trusset_prover::dates::civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}
