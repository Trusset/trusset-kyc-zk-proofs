//! `preimage_knowledge` circuit (spec §6.4).
//!
//! Statement: "I know `(value, nonce)` such that
//! `Rescue(COMMITMENT_TAG ‖ len ‖ value ‖ nonce) == commitment`."
//!
//! The catch-all leaf type for identity-binding fields where there is no
//! meaningful predicate to disclose (`firstName`, `lastName`,
//! `documentNumber`, ...). Its ZK value is non-malleability and a uniform
//! "every leaf is a STARK" manifest property (spec §6.4 note).
//!
//! # Status: Phase 2A
//!
//! Phase 2A delivers the typed witness / public-input / params layer and a
//! deterministic `StubProof` that exercises downstream infrastructure
//! (prover binary, manifest builder, verifier façade). The actual Winterfell
//! AIR with Rescue gates is Phase 2B work — until then, manifests carry
//! `mode: "stub"` and production verifiers reject these proofs.

use sha2::{Digest as _, Sha256};
use trusset_circuits_common::{
    compute_commitment, hash_bytes_with_tag, CircuitId, Digest, StubProof, StubProofError,
    NONCE_LEN, PUBLIC_DIGEST_TAG, DIGEST_LEN_BYTES,
};
use zeroize::Zeroize;

pub const CIRCUIT_ID: CircuitId = CircuitId::PreimageKnowledge;
pub const DEFAULT_MAX_VALUE_BYTES: usize = 128;

/// Operator-configurable parameters for the preimage_knowledge circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Maximum allowed length (in bytes, after NFC encoding) of the witness
    /// value. Inputs longer than this are rejected with
    /// `ValidateError::ValueTooLong` rather than silently truncated.
    pub max_value_bytes: usize,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            max_value_bytes: DEFAULT_MAX_VALUE_BYTES,
        }
    }
}

impl Params {
    /// SHA-256 of the canonical params encoding. Folded into the per-leaf
    /// seed and used as a public input binding (plan §4 determinism).
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"trusset-kyc-v2:preimage_knowledge:params");
        h.update((self.max_value_bytes as u64).to_le_bytes());
        h.finalize().into()
    }
}

/// Private witness. Auto-zeroed on drop.
pub struct Witness {
    pub value: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.value.zeroize();
        self.nonce.zeroize();
    }
}

/// Public inputs sealed into every proof and into the leaf hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub commitment: Digest,
}

impl PublicInputs {
    /// Canonical byte encoding consumed by `Self::digest()` and by the
    /// leaf-hash builder in `prover/src/leaf.rs`. Fixed layout:
    ///   `commitment_bytes(32)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        use trusset_circuits_common::digest_to_bytes;
        digest_to_bytes(&self.commitment).to_vec()
    }

    /// Public-inputs digest, used as the `pub_digest` field of `StubProof`
    /// and bound into the leaf hash (spec §7).
    pub fn digest(&self) -> Digest {
        hash_bytes_with_tag(&PUBLIC_DIGEST_TAG, &self.canonical_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// Value exceeds `Params::max_value_bytes`. Maps to error code
    /// `E_CIRCUIT_INTERNAL` upstream because the input layer should have
    /// caught this — reaching here means a misconfigured caller.
    ValueTooLong { len: usize, max: usize },
    /// Commitment in public inputs does not match the recomputed commitment
    /// from the witness. Indicates a bug or a tampered witness/public-input
    /// pair.
    CommitmentMismatch,
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

/// Plain-Rust witness validation. This is the predicate that a real
/// Winterfell AIR will enforce in Phase 2B.
pub fn validate(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<(), ValidateError> {
    if witness.value.len() > params.max_value_bytes {
        return Err(ValidateError::ValueTooLong {
            len: witness.value.len(),
            max: params.max_value_bytes,
        });
    }
    let recomputed = compute_commitment(&witness.value, &witness.nonce);
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

/// Build the public commitment from a witness. Helper for callers that
/// construct the public inputs from the witness (the typical prover path).
pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(&witness.value, &witness.nonce)
}

/// Generate a stub proof.
///
/// # Errors
/// `ValidateError` if the witness/public-input pair is inconsistent.
///
/// # Phase 2B TODO
/// Replace the body with a Winterfell `Air` impl that constrains:
///   - Rescue-Prime over `(value_padded ‖ nonce)` equals `commitment`.
///   - `len(value) <= max_value_bytes` (range check via boolean decomposition).
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
    Ok(proof.to_bytes().to_vec())
}

/// Verify a stub proof against public inputs. Phase 2B replaces this with
/// `winter_verifier::verify(proof, public_inputs, air)`.
pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    let parsed = StubProof::from_bytes(proof_bytes)?;
    parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
    Ok(())
}

/// Canonical commitment helper for variable-length value bytes.
/// Re-exported for the prover binary; identical to `compute_commitment` from
/// `trusset_circuits_common` but namespaced under the circuit so callers
/// don't have to import the common crate directly.
pub fn commit_value(value: &[u8], nonce: &[u8; NONCE_LEN]) -> Digest {
    compute_commitment(value, nonce)
}

/// Length of a stub proof for this circuit (constant across all four).
pub fn proof_len_bytes() -> usize {
    trusset_circuits_common::STUB_PROOF_LEN
}

/// Length of a digest in bytes — re-exported for ergonomics in tests.
pub const DIGEST_BYTES: usize = DIGEST_LEN_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_witness() -> Witness {
        Witness {
            value: b"Alice".to_vec(),
            nonce: [0xab; NONCE_LEN],
        }
    }

    fn fixture_public(w: &Witness) -> PublicInputs {
        PublicInputs {
            commitment: commit(w),
        }
    }

    #[test]
    fn params_default_is_128_bytes() {
        assert_eq!(Params::default().max_value_bytes, DEFAULT_MAX_VALUE_BYTES);
    }

    #[test]
    fn params_hash_changes_with_params() {
        assert_ne!(
            Params { max_value_bytes: 128 }.hash(),
            Params { max_value_bytes: 64 }.hash()
        );
    }

    #[test]
    fn validate_accepts_correct_witness() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        assert!(validate(&w, &p, &Params::default()).is_ok());
    }

    #[test]
    fn validate_rejects_value_too_long() {
        let w = Witness {
            value: vec![0u8; 200],
            nonce: [0; NONCE_LEN],
        };
        let p = PublicInputs {
            commitment: commit(&w),
        };
        let err = validate(
            &w,
            &p,
            &Params {
                max_value_bytes: 128,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ValidateError::ValueTooLong { len: 200, max: 128 }));
    }

    #[test]
    fn validate_rejects_commitment_mismatch() {
        let w = fixture_witness();
        let mut p = fixture_public(&w);
        // Tamper one limb of the public commitment.
        p.commitment[0] = trusset_circuits_common::Felt::new(0xdeadbeefu64);
        assert_eq!(
            validate(&w, &p, &Params::default()),
            Err(ValidateError::CommitmentMismatch)
        );
    }

    #[test]
    fn prove_verify_roundtrip() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let bytes = prove(&w, &p, &Params::default()).unwrap();
        assert_eq!(bytes.len(), proof_len_bytes());
        assert!(verify(&bytes, &p).is_ok());
    }

    #[test]
    fn verify_rejects_proof_for_different_public_inputs() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let bytes = prove(&w, &p, &Params::default()).unwrap();

        // Build a different public-inputs (different commitment).
        let w2 = Witness {
            value: b"Bob".to_vec(),
            nonce: [0xcd; NONCE_LEN],
        };
        let p2 = fixture_public(&w2);
        assert!(verify(&bytes, &p2).is_err());
    }

    #[test]
    fn verify_rejects_tampered_proof_bytes() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let mut bytes = prove(&w, &p, &Params::default()).unwrap();
        bytes[100] ^= 0x01;
        assert!(verify(&bytes, &p).is_err());
    }

    #[test]
    fn verify_rejects_wrong_circuit_id_bytes() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let mut bytes = prove(&w, &p, &Params::default()).unwrap();
        bytes[16] = CircuitId::TierThreshold.as_u8();
        // The binding tag is computed against PreimageKnowledge, so flipping
        // the id alone causes BindingTagMismatch — but if both id and tag
        // are tampered, WrongCircuitId fires first.
        assert!(verify(&bytes, &p).is_err());
    }

    #[test]
    fn empty_value_is_valid() {
        let w = Witness {
            value: Vec::new(),
            nonce: [0u8; NONCE_LEN],
        };
        let p = PublicInputs {
            commitment: commit(&w),
        };
        // Spec §6.4 + plan edge case 8: preimage_knowledge accepts empty
        // strings; other circuits reject them.
        assert!(validate(&w, &p, &Params::default()).is_ok());
        let bytes = prove(&w, &p, &Params::default()).unwrap();
        assert!(verify(&bytes, &p).is_ok());
    }

    #[test]
    fn prove_is_deterministic() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let a = prove(&w, &p, &Params::default()).unwrap();
        let b = prove(&w, &p, &Params::default()).unwrap();
        assert_eq!(a, b, "stub proof must be byte-deterministic across runs");
    }
}
