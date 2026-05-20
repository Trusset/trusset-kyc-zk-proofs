//! Winterfell verifier wrapper for `preimage_knowledge`.
//!
//! This is the counterparty entry point: takes serialized proof bytes +
//! reconstructed public inputs and runs Winterfell's verify function with
//! the workspace-pinned `AcceptableOptions`. The verifier is intentionally
//! the only place that decides what proof parameters are acceptable, and
//! it pins the conjectured-security floor to `STARK_SECURITY_BITS` from
//! `trusset_circuits_common::proof_options` (currently 100 bits).

use trusset_circuits_common::STARK_SECURITY_BITS;
use winterfell::{verify, AcceptableOptions, Proof};

use crate::air::{
    AirHashFn, AirRandomCoin, AirVectorCommitment, PreimageAir, PreimageAirPublicInputs,
};

#[derive(Debug)]
pub enum AirVerifyError {
    /// Serialized proof bytes failed to parse.
    ProofDeserializeFailed(String),
    /// Winterfell verifier rejected the proof.
    VerifyFailed(String),
}

/// Verify a serialized Winterfell proof against the given public inputs.
pub fn verify_proof(
    proof_bytes: &[u8],
    public_inputs: PreimageAirPublicInputs,
) -> Result<(), AirVerifyError> {
    let proof = Proof::from_bytes(proof_bytes)
        .map_err(|e| AirVerifyError::ProofDeserializeFailed(format!("{e:?}")))?;
    let accept = AcceptableOptions::MinConjecturedSecurity(STARK_SECURITY_BITS);
    verify::<PreimageAir, AirHashFn, AirRandomCoin, AirVectorCommitment>(
        proof,
        public_inputs,
        &accept,
    )
    .map_err(|e| AirVerifyError::VerifyFailed(format!("{e:?}")))
}
