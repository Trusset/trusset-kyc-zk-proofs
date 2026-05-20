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
//! # Status
//!
//! - **Stub path** (`--features stub-proofs`, Phase 2A default): typed
//!   layer + 120-byte placeholder.
//! - **Prod-proofs path** (`--features prod-proofs-age`, Phase 2B):
//!   real Winterfell roundtrip via `air`, `prover`, `verifier`. Current
//!   AIR is a PLACEHOLDER — does not enforce the age predicate yet.

#[cfg(feature = "prod-proofs-age")]
pub mod air;
#[cfg(feature = "prod-proofs-age")]
pub mod prover;
#[cfg(feature = "prod-proofs-age")]
pub mod verifier;

use sha2::{Digest as _, Sha256};
#[cfg(not(feature = "prod-proofs-age"))]
use trusset_circuits_common::StubProof;
use trusset_circuits_common::{
    compute_commitment, digest_to_bytes, hash_bytes_with_tag, CircuitId, Digest, Felt,
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
    TimeTravel {
        dob_days: u64,
        current_epoch_days: u64,
    },
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
    /// Winterfell prover failed (prod-proofs-age path only).
    WinterfellProverError(String),
}

#[derive(Debug)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
    #[cfg(feature = "prod-proofs-age")]
    WinterfellVerifyError(verifier::AirVerifyError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// Canonical felt-encoding of the witness for the v2 commitment scheme.
/// A 1-felt vector carrying the dob_days value as a single Goldilocks
/// limb (fits since dob_days ≤ MAX_PLAUSIBLE_DAYS < 2^22 < 2^63).
pub fn witness_to_felts(dob_days: u64) -> [Felt; 1] {
    [Felt::new(dob_days)]
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(witness.dob_days),
        &witness.nonce,
    )
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
    let recomputed = compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(witness.dob_days),
        &witness.nonce,
    );
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    #[cfg(feature = "prod-proofs-age")]
    {
        use trusset_circuits_common::stark_options;
        let pi = prover::public_to_air(
            &public.commitment,
            public.min_age_days,
            public.current_epoch_days,
        );
        let seed = [0u8; 32];
        let bytes = prover::build_proof(
            witness.dob_days,
            &witness.nonce,
            public.min_age_days,
            public.current_epoch_days,
            &pi,
            stark_options(),
            &seed,
        )
        .map_err(|e| ValidateError::WinterfellProverError(format!("{e:?}")))?;
        Ok(bytes)
    }
    #[cfg(not(feature = "prod-proofs-age"))]
    {
        let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
        Ok(proof.to_bytes().to_vec())
    }
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    #[cfg(feature = "prod-proofs-age")]
    {
        let pi = prover::public_to_air(
            &public.commitment,
            public.min_age_days,
            public.current_epoch_days,
        );
        verifier::verify_proof(proof_bytes, pi).map_err(VerifyError::WinterfellVerifyError)
    }
    #[cfg(not(feature = "prod-proofs-age"))]
    {
        let parsed = StubProof::from_bytes(proof_bytes)?;
        parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
        Ok(())
    }
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

    // -------------------------------------------------------------
    // AIR-time negative-witness sweeps (Stage 6)
    //
    // These bypass `validate()` and call `prover::build_proof` directly
    // with spec-violating witnesses. The 22-bit boolean range
    // decomposition on `slack = current_epoch_days − dob_days − min_age_days`
    // MUST cause the prover to fail before emitting a proof.
    //
    // Mechanism: for time-travel and underage, the "slack" value as a
    // field element wraps to a large value (close to the Goldilocks prime)
    // that does NOT decompose into 22 boolean bits. The AIR's
    // linear-combination constraint (slack == Σ bit_i · 2^i) fails.
    // -------------------------------------------------------------

    #[cfg(feature = "prod-proofs-age")]
    fn try_prove_air_only(
        dob_days: u64,
        min_age_days: u64,
        current_epoch_days: u64,
    ) -> Result<Vec<u8>, String> {
        use trusset_circuits_common::{compute_commitment, stark_options, CircuitId, Felt};
        let nonce = [0x22u8; NONCE_LEN];
        let witness_felts = [Felt::new(dob_days)];
        let commitment = compute_commitment(CircuitId::AgeThreshold, &witness_felts, &nonce);
        let pi = prover::public_to_air(&commitment, min_age_days, current_epoch_days);
        // Debug builds: Winterfell `debug_assert!`s panic on bad trace.
        // Release builds: `debug_assert!`s compiled out; prover emits invalid
        // bytes which the verifier then rejects. Chain prove+verify so the
        // wrapper's rejection contract holds in both profiles.
        let prove_result = std::panic::catch_unwind(|| {
            prover::build_proof(
                dob_days,
                &nonce,
                min_age_days,
                current_epoch_days,
                &pi,
                stark_options(),
                &[0u8; 32],
            )
        });
        let proof_bytes = match prove_result {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(format!("ProverError: {e:?}")),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "unknown panic".to_string());
                return Err(format!("Prover panic: {msg}"));
            }
        };
        let pi_verify = prover::public_to_air(&commitment, min_age_days, current_epoch_days);
        match verifier::verify_proof(&proof_bytes, pi_verify) {
            Ok(()) => Ok(proof_bytes),
            Err(e) => Err(format!("VerifierError: {e:?}")),
        }
    }

    #[cfg(feature = "prod-proofs-age")]
    #[test]
    fn air_rejects_time_travel() {
        // dob_days > current_epoch_days: person hasn't been born yet.
        // slack = current - dob - min_age wraps to a large field value
        // that doesn't fit in 22 bits.
        let result = try_prove_air_only(TODAY + 100, 6570, TODAY);
        assert!(
            result.is_err(),
            "AIR must reject time-travel witness, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-age")]
    #[test]
    fn air_rejects_underage() {
        // dob_days = TODAY - 1000 (about 2.7 years old), min_age = 6570 (18 years).
        // slack = -5570 wraps to large field value → bit-decomp fails.
        let result = try_prove_air_only(TODAY - 1000, 6570, TODAY);
        assert!(result.is_err(), "AIR must reject underage witness, got Ok");
    }

    #[cfg(feature = "prod-proofs-age")]
    #[test]
    fn air_rejects_one_day_short() {
        // Boundary: exactly one day short of min_age → slack = -1 → wraps.
        let result = try_prove_air_only(TODAY - 6569, 6570, TODAY);
        assert!(
            result.is_err(),
            "AIR must reject witness one day short of min_age, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-age")]
    #[test]
    fn air_accepts_exact_min_age() {
        // Boundary: exactly min_age days old → slack = 0 → bits all 0 → accepts.
        let result = try_prove_air_only(TODAY - 6570, 6570, TODAY);
        assert!(
            result.is_ok(),
            "AIR must accept exact-min-age witness, got {:?}",
            result.err()
        );
    }

    #[cfg(feature = "prod-proofs-age")]
    #[test]
    fn air_accepts_well_over_min_age() {
        // 30-year-old, min_age = 18 years → slack = 4380 days, fits in 22 bits.
        let result = try_prove_air_only(TODAY - 10950, 6570, TODAY);
        assert!(
            result.is_ok(),
            "AIR must accept 30-year-old witness, got {:?}",
            result.err()
        );
    }
}
