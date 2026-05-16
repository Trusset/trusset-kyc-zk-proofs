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

use std::io::Read;
use trusset_prover::{
    bundle::build_subject_bundle,
    errors::{ErrorCode, ProverError, Result},
    io::{Event, EventStream},
    job::{parse_config_hash, Job},
    sign::SigningSecret,
};

const ENV_MASTER_KEY: &str = "TRUSSET_KYC_MASTER_KEY";
const ENV_SIGNING_KEY: &str = "TRUSSET_KYC_SIGNING_KEY";

fn main() {
    let exit_code = run();
    std::process::exit(exit_code);
}

fn run() -> i32 {
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

    let _ = events.emit(&Event::Start {
        subjects: job.subjects.len(),
    });

    let mut ok = 0usize;
    let mut failed = 0usize;

    for subject in &job.subjects {
        let _ = events.emit(&Event::SubjectStart {
            subject_id: &subject.subject_id,
        });
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
                let _ = events.emit(&Event::SubjectDone {
                    subject_id: &subject.subject_id,
                    bundle_path: &report.bundle_path.to_string_lossy(),
                });
            }
            Err(e) => {
                failed += 1;
                let _ = events.fail(&subject.subject_id, e.code.clone(), &e.message);
            }
        }
    }

    let _ = events.emit(&Event::Done { ok, failed });

    if failed == 0 {
        0
    } else if ok > 0 {
        2
    } else {
        1
    }
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
    let days = (secs / 86_400) as i64;
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
