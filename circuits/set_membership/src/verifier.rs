//! Winterfell verifier wrapper for `set_membership`.

use trusset_circuits_common::STARK_SECURITY_BITS;
use winterfell::{verify, AcceptableOptions, Proof};

use crate::air::{AirHashFn, AirRandomCoin, AirVectorCommitment, SetAir, SetAirPublicInputs};

#[derive(Debug)]
pub enum AirVerifyError {
    ProofDeserializeFailed(String),
    VerifyFailed(String),
}

pub fn verify_proof(proof_bytes: &[u8], public: SetAirPublicInputs) -> Result<(), AirVerifyError> {
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|e| AirVerifyError::ProofDeserializeFailed(format!("{e:?}")))?;
    let accept = AcceptableOptions::MinConjecturedSecurity(STARK_SECURITY_BITS);
    verify::<SetAir, AirHashFn, AirRandomCoin, AirVectorCommitment>(proof, public, &accept)
        .map_err(|e| AirVerifyError::VerifyFailed(format!("{e:?}")))
}
