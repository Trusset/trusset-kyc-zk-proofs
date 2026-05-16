//! `age_threshold` circuit (spec §6.1).
//!
//! Statement: "I know `(dob_days, nonce)` such that
//! `Rescue(COMMITMENT_TAG ‖ 8 ‖ dob_days_le ‖ nonce) == commitment`,
//!  `current_epoch_days >= dob_days` (no time travel),
//!  `current_epoch_days - dob_days >= min_age_days`."
//!
//! Operating on days rather than seconds keeps the range-check cost low.
//! `current_epoch_days` is supplied by the operator at proving time
//! (`config.security.epochDaysSource`, plan edge case 5) and recorded in
//! the manifest so banks can diff against their verification time.
//!
//! # Status: Phase 2A — see `preimage_knowledge` for stub-mode caveat.

use sha2::{Digest as _, Sha256};
use trusset_circuits_common::{
    compute_commitment, digest_to_bytes, hash_bytes_with_tag, CircuitId, Digest, StubProof,
    StubProofError, NONCE_LEN, PUBLIC_DIGEST_TAG,
};
use zeroize::Zeroize;

pub const CIRCUIT_ID: CircuitId = CircuitId::AgeThreshold;

/// Sanity bound on `dob_days` and `current_epoch_days`. Roughly year 9999.
const MAX_PLAUSIBLE_DAYS: u64 = 3_652_500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Minimum age in days. For age-18 in years, supply `18 * 365 = 6570`
    /// (the configuration layer in `cli/src/config.ts` converts years→days
    /// when reading `params.minAgeYears`).
    pub min_age_days: u64,
}

impl Default for Params {
    fn default() -> Self {
        // 18 years in days; matches `config.example.json` default of minAgeYears=18.
        Self { min_age_days: 6570 }
    }
}

impl Params {
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"trusset-kyc-v2:age_threshold:params");
        h.update(self.min_age_days.to_le_bytes());
        h.finalize().into()
    }
}

pub struct Witness {
    /// Days since 1970-01-01 of the subject's date of birth.
    pub dob_days: u64,
    pub nonce: [u8; NONCE_LEN],
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.dob_days.zeroize();
        self.nonce.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub commitment: Digest,
    pub min_age_days: u64,
    pub current_epoch_days: u64,
}

impl PublicInputs {
    /// Canonical encoding: `commitment(32) ‖ min_age_days_le(8) ‖ current_epoch_days_le(8)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&digest_to_bytes(&self.commitment));
        out.extend_from_slice(&self.min_age_days.to_le_bytes());
        out.extend_from_slice(&self.current_epoch_days.to_le_bytes());
        out
    }

    pub fn digest(&self) -> Digest {
        hash_bytes_with_tag(&PUBLIC_DIGEST_TAG, &self.canonical_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// `dob_days > current_epoch_days` — would imply a future birth date.
    TimeTravel { dob_days: u64, current_epoch_days: u64 },
    /// `current_epoch_days - dob_days < min_age_days`. Maps to `E_AGE_BELOW_MIN`.
    BelowMinimum {
        age_days: u64,
        min_age_days: u64,
    },
    /// Either timestamp exceeds `MAX_PLAUSIBLE_DAYS`.
    OutOfRange,
    CommitmentMismatch,
    /// `params.min_age_days` does not match `public.min_age_days`.
    MinAgeMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// Canonical witness serialization fed into the commitment hash:
/// fixed 8 bytes, little-endian.
fn witness_bytes(dob_days: u64) -> [u8; 8] {
    dob_days.to_le_bytes()
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(&witness_bytes(witness.dob_days), &witness.nonce)
}

pub fn validate(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<(), ValidateError> {
    if witness.dob_days > MAX_PLAUSIBLE_DAYS || public.current_epoch_days > MAX_PLAUSIBLE_DAYS {
        return Err(ValidateError::OutOfRange);
    }
    if params.min_age_days != public.min_age_days {
        return Err(ValidateError::MinAgeMismatch);
    }
    if witness.dob_days > public.current_epoch_days {
        return Err(ValidateError::TimeTravel {
            dob_days: witness.dob_days,
            current_epoch_days: public.current_epoch_days,
        });
    }
    let age_days = public.current_epoch_days - witness.dob_days;
    if age_days < public.min_age_days {
        return Err(ValidateError::BelowMinimum {
            age_days,
            min_age_days: public.min_age_days,
        });
    }
    let recomputed = compute_commitment(&witness_bytes(witness.dob_days), &witness.nonce);
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

/// # Phase 2B TODO
/// Real Winterfell AIR must enforce:
///   1. Rescue commitment opens correctly over `(dob_days, nonce)`.
///   2. `current_epoch_days - dob_days = age_days` (subtraction trace).
///   3. `age_days - min_age_days = slack` with `slack >= 0` (range check
///      via boolean decomposition over `log2(MAX_PLAUSIBLE_DAYS) ≈ 22` bits).
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
    Ok(proof.to_bytes().to_vec())
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    let parsed = StubProof::from_bytes(proof_bytes)?;
    parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: u64 = 20587; // ~2026-05-14
    const TWENTY_YEARS_AGO: u64 = TODAY - 20 * 365;
    const TEN_YEARS_AGO: u64 = TODAY - 10 * 365;

    fn witness(dob_days: u64) -> Witness {
        Witness {
            dob_days,
            nonce: [0x33; NONCE_LEN],
        }
    }

    fn public_inputs(w: &Witness, min_age_days: u64, current: u64) -> PublicInputs {
        PublicInputs {
            commitment: commit(w),
            min_age_days,
            current_epoch_days: current,
        }
    }

    #[test]
    fn params_default_is_18_years() {
        assert_eq!(Params::default().min_age_days, 6570);
    }

    #[test]
    fn validate_accepts_twenty_year_old_for_age_18() {
        let w = witness(TWENTY_YEARS_AGO);
        let p = public_inputs(&w, 6570, TODAY);
        assert!(validate(&w, &p, &Params { min_age_days: 6570 }).is_ok());
    }

    #[test]
    fn validate_rejects_ten_year_old_for_age_18() {
        let w = witness(TEN_YEARS_AGO);
        let p = public_inputs(&w, 6570, TODAY);
        let age_days = TODAY - TEN_YEARS_AGO;
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 6570 }),
            Err(ValidateError::BelowMinimum {
                age_days,
                min_age_days: 6570,
            })
        );
    }

    #[test]
    fn validate_rejects_future_dob() {
        let w = witness(TODAY + 1);
        let p = public_inputs(&w, 6570, TODAY);
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 6570 }),
            Err(ValidateError::TimeTravel {
                dob_days: TODAY + 1,
                current_epoch_days: TODAY,
            })
        );
    }

    #[test]
    fn validate_rejects_out_of_range() {
        let w = witness(MAX_PLAUSIBLE_DAYS + 1);
        let p = PublicInputs {
            commitment: commit(&w),
            min_age_days: 6570,
            current_epoch_days: TODAY,
        };
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 6570 }),
            Err(ValidateError::OutOfRange)
        );
    }

    #[test]
    fn validate_rejects_params_public_min_age_drift() {
        let w = witness(TWENTY_YEARS_AGO);
        let p = public_inputs(&w, 6570, TODAY);
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 7300 }),
            Err(ValidateError::MinAgeMismatch)
        );
    }

    #[test]
    fn validate_rejects_commitment_mismatch() {
        let w = witness(TWENTY_YEARS_AGO);
        let mut p = public_inputs(&w, 6570, TODAY);
        p.commitment[2] = trusset_circuits_common::Felt::new(0xc0ffee);
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 6570 }),
            Err(ValidateError::CommitmentMismatch)
        );
    }

    #[test]
    fn prove_verify_roundtrip() {
        let w = witness(TWENTY_YEARS_AGO);
        let p = public_inputs(&w, 6570, TODAY);
        let bytes = prove(&w, &p, &Params { min_age_days: 6570 }).unwrap();
        assert!(verify(&bytes, &p).is_ok());
    }

    #[test]
    fn verify_rejects_proof_for_different_current_epoch() {
        let w = witness(TWENTY_YEARS_AGO);
        let p1 = public_inputs(&w, 6570, TODAY);
        let bytes = prove(&w, &p1, &Params { min_age_days: 6570 }).unwrap();
        let p2 = public_inputs(&w, 6570, TODAY + 1);
        // pub_digest differs because current_epoch_days is part of canonical bytes.
        assert!(verify(&bytes, &p2).is_err());
    }

    #[test]
    fn params_hash_changes_with_min_age() {
        assert_ne!(
            Params { min_age_days: 6570 }.hash(),
            Params { min_age_days: 7300 }.hash()
        );
    }

    #[test]
    fn prove_is_deterministic() {
        let w = witness(TWENTY_YEARS_AGO);
        let p = public_inputs(&w, 6570, TODAY);
        let a = prove(&w, &p, &Params { min_age_days: 6570 }).unwrap();
        let b = prove(&w, &p, &Params { min_age_days: 6570 }).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn exact_min_age_boundary_accepts() {
        // current - dob == min_age_days exactly → valid.
        let w = witness(TODAY - 6570);
        let p = public_inputs(&w, 6570, TODAY);
        assert!(validate(&w, &p, &Params { min_age_days: 6570 }).is_ok());
    }

    #[test]
    fn one_day_short_rejects() {
        let w = witness(TODAY - 6569);
        let p = public_inputs(&w, 6570, TODAY);
        assert_eq!(
            validate(&w, &p, &Params { min_age_days: 6570 }),
            Err(ValidateError::BelowMinimum {
                age_days: 6569,
                min_age_days: 6570,
            })
        );
    }
}
