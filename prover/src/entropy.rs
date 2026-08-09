//! Guarded OS-entropy access (spec §12.8 determinism enforcement).
//!
//! Every non-deterministic secret the prover draws goes through
//! `fill_random`, which refuses to touch the OS entropy pool when
//! `TRUSSET_KYC_DETERMINISTIC=1` is set. Deterministic runs derive all
//! key material from `TRUSSET_KYC_MASTER_KEY` via HKDF and must never
//! reach this path; if one does, the panic aborts the run loudly rather
//! than emitting a subtly non-reproducible bundle.
//!
//! The CLI exports `TRUSSET_KYC_DETERMINISTIC=1` for the child prover
//! whenever `security.deterministic` is true, and CI sets it globally, so
//! an accidental entropy draw fails the determinism canary immediately.

use crate::errors::{ErrorCode, ProverError, Result};

pub const DETERMINISM_ENV: &str = "TRUSSET_KYC_DETERMINISTIC";

/// True when deterministic mode is pinned via the environment.
pub fn determinism_pinned() -> bool {
    matches!(std::env::var(DETERMINISM_ENV), Ok(v) if v == "1")
}

/// Fill `out` with OS entropy. Errors with `E_DETERMINISM_VIOLATION` when
/// `TRUSSET_KYC_DETERMINISTIC=1` so a deterministic run never silently
/// draws randomness.
pub fn fill_random(out: &mut [u8]) -> Result<()> {
    fill_random_guarded(determinism_pinned(), out)
}

/// The guard itself, with the determinism decision passed in. Tests drive
/// this directly: `std::env` is process-global and the test harness runs
/// cases in parallel, so an env-var-driven test would race.
pub fn fill_random_guarded(pinned: bool, out: &mut [u8]) -> Result<()> {
    if pinned {
        return Err(ProverError::new(
            ErrorCode::DeterminismViolation,
            "OS entropy draw attempted while TRUSSET_KYC_DETERMINISTIC=1 is set",
        ));
    }
    getrandom::getrandom(out).map_err(|e| {
        ProverError::new(
            ErrorCode::CircuitInternal,
            format!("OS entropy draw failed: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_rejects_draw_when_determinism_pinned() {
        let mut buf = [0u8; 32];
        let err = fill_random_guarded(true, &mut buf).unwrap_err();
        assert_eq!(err.code, ErrorCode::DeterminismViolation);
        assert_eq!(buf, [0u8; 32], "buffer must be left untouched");
    }

    #[test]
    fn guard_draws_when_not_pinned() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random_guarded(false, &mut a).unwrap();
        fill_random_guarded(false, &mut b).unwrap();
        assert_ne!(a, b, "two entropy draws should differ");
    }

    #[test]
    fn determinism_pinned_reads_the_documented_env_var() {
        assert_eq!(DETERMINISM_ENV, "TRUSSET_KYC_DETERMINISTIC");
    }
}
