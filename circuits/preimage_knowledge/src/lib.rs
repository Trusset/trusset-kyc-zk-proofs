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
//! # Status
//!
//! - **Stub path** (`--features stub-proofs`, Phase 2A default): typed
//!   witness / public-input / params layer + deterministic `StubProof`.
//!   Manifests carry `mode: "stub"` and production verifiers reject the
//!   bundle.
//! - **Prod-proofs path** (`--features prod-proofs-preimage`, Phase 2B):
//!   real Winterfell AIR + prover + verifier via `air`, `prover`,
//!   `verifier` modules. Current implementation uses a PLACEHOLDER AIR
//!   (see `air.rs` SCOPE notes) that exercises the full Winterfell
//!   roundtrip without enforcing the Rescue-Prime commitment opening yet.
//!   Step 2.b in the Phase 2B rollout replaces the placeholder
//!   constraints with the real relation per `docs/CIRCUITS.md`.

#[cfg(feature = "prod-proofs-preimage")]
pub mod air;
#[cfg(feature = "prod-proofs-preimage")]
pub mod prover;
#[cfg(feature = "prod-proofs-preimage")]
pub mod verifier;

use sha2::{Digest as _, Sha256};
#[cfg(not(feature = "prod-proofs-preimage"))]
use trusset_circuits_common::StubProof;
use trusset_circuits_common::{
    bytes_to_field, compute_commitment, hash_bytes_with_tag, CircuitId, Digest, Felt,
    StubProofError, DIGEST_LEN_BYTES, NONCE_LEN, PUBLIC_DIGEST_TAG,
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
    /// Winterfell prover failed (prod-proofs-preimage path only).
    WinterfellProverError(String),
}

#[derive(Debug)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
    /// Winterfell verifier rejected the proof (prod-proofs-preimage path only).
    #[cfg(feature = "prod-proofs-preimage")]
    WinterfellVerifyError(verifier::AirVerifyError),
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
    let recomputed = compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(&witness.value),
        &witness.nonce,
    );
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

/// Maximum number of felts returned by `witness_to_felts`, regardless of
/// the actual value length. Set to `20` so that the **total Rescue input
/// length** is exactly 32 felts (= 4 absorption blocks × 8 rate width),
/// giving a clean AIR with all 4 blocks absorbing the full rate.
///
/// Breakdown of the 32 input felts to `compute_commitment`:
/// `tag(5) + circuit_id(1) + length_felt(1) + padded_witness(20) + nonce(5) = 32`.
///
/// 20 felts accommodates any witness up to `139 bytes` (= `20 × 7 − 1`
/// for the `0x01` suffix), which comfortably covers
/// `DEFAULT_MAX_VALUE_BYTES = 128`.
///
/// Why fixed? The downstream Winterfell AIR has a fixed trace shape
/// (Issue 1 from `docs/STEP_2B_COMMITMENT_DESIGN.md`). Every commitment
/// absorbs exactly 20 felts of witness regardless of `value.len()`;
/// the `0x01` suffix marks end-of-value and zero-padding distinguishes
/// shorter values from longer-with-trailing-zeros variants.
pub const MAX_PADDED_WITNESS_FELTS: usize = 20;

/// Canonical felt-encoding of the witness value for the v2 commitment
/// scheme. Returns AT LEAST `MAX_PADDED_WITNESS_FELTS` felts (exactly
/// that count for any value with `len ≤ DEFAULT_MAX_VALUE_BYTES`).
///
/// Encoding:
/// 1. Append `0x01` distinguishing suffix to `value`.
/// 2. Chunk into 7-byte little-endian Goldilocks limbs via `bytes_to_field`.
/// 3. Zero-pad the felt vector up to `MAX_PADDED_WITNESS_FELTS`.
///
/// For values larger than `DEFAULT_MAX_VALUE_BYTES`, the natural felt
/// count exceeds `MAX_PADDED_WITNESS_FELTS` and no shrinking happens —
/// `commit()` still produces a digest for such values (a different one
/// than the AIR would compute), but `validate()` rejects oversize values
/// before the AIR ever runs. The AIR's own trace builder will assert
/// `MAX_PADDED_WITNESS_FELTS` exactly.
///
/// The `0x01` suffix prevents collisions where `bytes_to_field` would
/// otherwise collapse trailing-zero variants (e.g. `"abc"` vs `"abc\0"`)
/// into the same `Felt` within the last 7-byte chunk. Zero-padding to a
/// fixed felt count then makes the trace shape fixed for the AIR; the
/// suffix's position within the felts marks the real end-of-value, so
/// distinct values still encode to distinct felt vectors.
///
/// Collision-freeness argument (for values within max): two byte values
/// `v1 != v2` produce suffix-padded sequences `v1‖[0x01]` and `v2‖[0x01]`,
/// each then zero-padded to `MAX_PADDED_WITNESS_FELTS` felts. If `v1`
/// and `v2` differ in length, the suffix `0x01` lands at distinct byte
/// positions — at least one felt differs. If same length, stripping
/// the common suffix gives `v1 == v2`, contradiction.
pub fn witness_to_felts(value: &[u8]) -> Vec<Felt> {
    let mut padded = Vec::with_capacity(value.len() + 1);
    padded.extend_from_slice(value);
    padded.push(0x01);
    let mut felts = bytes_to_field(&padded);
    while felts.len() < MAX_PADDED_WITNESS_FELTS {
        felts.push(Felt::new(0));
    }
    felts
}

/// Build the public commitment from a witness. Helper for callers that
/// construct the public inputs from the witness (the typical prover path).
pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(&witness.value),
        &witness.nonce,
    )
}

/// Generate a proof.
///
/// - Under `stub-proofs` (Phase 2A default): emits the 120-byte
///   `StubProof` artifact.
/// - Under `prod-proofs-preimage` (Phase 2B): runs the placeholder
///   Winterfell AIR (see `air.rs` SCOPE notes); Step 2.b replaces the AIR
///   body with the real Rescue-Prime relation.
///
/// # Errors
/// `ValidateError` if the witness/public-input pair is inconsistent, or
/// (when prod-proofs are enabled) if the Winterfell prover fails.
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    #[cfg(feature = "prod-proofs-preimage")]
    {
        use trusset_circuits_common::stark_options;
        let limbs = prover::digest_to_air_limbs(&public.commitment);
        let pi = air::PreimageAirPublicInputs { commitment: limbs };
        let seed = [0u8; 32];
        let bytes =
            prover::build_proof(&witness.value, &witness.nonce, &pi, stark_options(), &seed)
                .map_err(|e| ValidateError::WinterfellProverError(format!("{e:?}")))?;
        Ok(bytes)
    }
    #[cfg(not(feature = "prod-proofs-preimage"))]
    {
        let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
        Ok(proof.to_bytes().to_vec())
    }
}

/// Verify a proof against public inputs.
pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    #[cfg(feature = "prod-proofs-preimage")]
    {
        let limbs = prover::digest_to_air_limbs(&public.commitment);
        let pi = air::PreimageAirPublicInputs { commitment: limbs };
        verifier::verify_proof(proof_bytes, pi).map_err(VerifyError::WinterfellVerifyError)
    }
    #[cfg(not(feature = "prod-proofs-preimage"))]
    {
        let parsed = StubProof::from_bytes(proof_bytes)?;
        parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
        Ok(())
    }
}

/// Canonical commitment helper for variable-length value bytes.
/// Re-exported for the prover binary; convenience wrapper around the
/// circuit's `witness_to_felts` + `compute_commitment` chain.
pub fn commit_value(value: &[u8], nonce: &[u8; NONCE_LEN]) -> Digest {
    compute_commitment(CIRCUIT_ID, &witness_to_felts(value), nonce)
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

    /// Regression: prior to the `0x01` suffix in `witness_to_felts`,
    /// `bytes_to_field("abc")` and `bytes_to_field("abc\0")` collapsed to
    /// the same `Felt` (both zero-pad the same 7-byte chunk to the same
    /// `u64`), producing identical commitments for distinct byte values.
    /// That's a hiding-commitment soundness gap. This test pins that the
    /// suffix breaks the collision.
    #[test]
    fn commitment_distinguishes_trailing_zero_byte_within_chunk() {
        let nonce = [0xcd; NONCE_LEN];
        let c_short = commit(&Witness {
            value: b"abc".to_vec(),
            nonce,
        });
        let c_with_zero = commit(&Witness {
            value: b"abc\0".to_vec(),
            nonce,
        });
        let c_with_two_zeros = commit(&Witness {
            value: b"abc\0\0".to_vec(),
            nonce,
        });
        assert_ne!(c_short, c_with_zero, "abc vs abc\\0 must differ");
        assert_ne!(c_short, c_with_two_zeros, "abc vs abc\\0\\0 must differ");
        assert_ne!(
            c_with_zero, c_with_two_zeros,
            "abc\\0 vs abc\\0\\0 must differ"
        );
    }

    #[test]
    fn commitment_distinguishes_empty_from_single_zero() {
        let nonce = [0xcd; NONCE_LEN];
        let c_empty = commit(&Witness {
            value: vec![],
            nonce,
        });
        let c_zero = commit(&Witness {
            value: vec![0u8],
            nonce,
        });
        assert_ne!(
            c_empty, c_zero,
            "empty value and single zero byte must commit distinctly"
        );
    }

    /// `witness_to_felts` must always return exactly `MAX_PADDED_WITNESS_FELTS`
    /// felts so the AIR can use a fixed trace shape.
    #[test]
    fn witness_to_felts_padding_returns_fixed_felt_count() {
        for len in [0usize, 1, 6, 7, 13, 14, 50, 100, 128] {
            let value: Vec<u8> = (0u8..len as u8).collect();
            let felts = witness_to_felts(&value);
            assert_eq!(
                felts.len(),
                MAX_PADDED_WITNESS_FELTS,
                "value.len() = {len} should still produce {} felts",
                MAX_PADDED_WITNESS_FELTS
            );
        }
    }

    /// Padding must NOT collapse byte values that differ in their actual
    /// content but happen to share the same felt-vector length after
    /// padding. The 0x01 suffix at the real end-of-value position
    /// distinguishes shorter values from longer ones.
    #[test]
    fn padded_witness_distinguishes_different_lengths_at_chunk_boundaries() {
        // value.len() = 6: suffix lands at byte 6 in first chunk
        // value.len() = 7: suffix lands at byte 0 of second chunk
        let nonce = [0x77; NONCE_LEN];
        let c_six = commit(&Witness {
            value: vec![0xaa; 6],
            nonce,
        });
        let c_seven = commit(&Witness {
            value: vec![0xaa; 7],
            nonce,
        });
        assert_ne!(
            c_six, c_seven,
            "6-byte and 7-byte values must commit distinctly"
        );
    }

    /// Oversize values (those larger than the AIR's max) produce more
    /// than `MAX_PADDED_WITNESS_FELTS` felts. `commit()` works on them,
    /// but `validate()` rejects them BEFORE the AIR sees them, and the
    /// AIR's trace builder asserts the exact felt count.
    #[test]
    fn witness_to_felts_oversize_value_exceeds_max() {
        let too_long = vec![0u8; DEFAULT_MAX_VALUE_BYTES + 100];
        let felts = witness_to_felts(&too_long);
        assert!(
            felts.len() > MAX_PADDED_WITNESS_FELTS,
            "oversize value should produce a felt count larger than the AIR-fixed max"
        );
    }

    #[test]
    fn params_hash_changes_with_params() {
        assert_ne!(
            Params {
                max_value_bytes: 128
            }
            .hash(),
            Params {
                max_value_bytes: 64
            }
            .hash()
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
        assert!(matches!(
            err,
            ValidateError::ValueTooLong { len: 200, max: 128 }
        ));
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
        // Stub-mode proofs are exactly 120 bytes; real Winterfell proofs
        // are several KB. The length assertion only applies in stub mode.
        #[cfg(not(feature = "prod-proofs-preimage"))]
        assert_eq!(bytes.len(), proof_len_bytes());
        #[cfg(feature = "prod-proofs-preimage")]
        assert!(
            bytes.len() > proof_len_bytes(),
            "real proof should exceed stub size"
        );
        let r = verify(&bytes, &p);
        assert!(r.is_ok(), "verify failed: {:?}", r);
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
        // Tamper a byte in the proof; both stub and real Winterfell proofs
        // must reject it. Pick an index that falls inside both formats.
        let idx = bytes.len() / 2;
        bytes[idx] ^= 0x01;
        assert!(verify(&bytes, &p).is_err());
    }

    /// Stub-specific: tampering byte 16 (the stub magic + circuit-id byte)
    /// is meaningful only in the stub format. The Winterfell verifier
    /// rejects on the broader cryptographic check, not on a byte-16
    /// magic, so we gate this test to stub mode.
    #[cfg(not(feature = "prod-proofs-preimage"))]
    #[test]
    fn verify_rejects_wrong_circuit_id_bytes() {
        let w = fixture_witness();
        let p = fixture_public(&w);
        let mut bytes = prove(&w, &p, &Params::default()).unwrap();
        bytes[16] = CircuitId::TierThreshold.as_u8();
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

    // -------------------------------------------------------------
    // AIR-time negative-witness sweeps (Stage 14)
    //
    // These bypass `validate()` and call `prover::build_proof` directly
    // with witnesses whose commitment does NOT open to the public
    // commitment. The AIR's row-FINAL_ROW boundary constraint
    // (`state[4..8] = commitment`) MUST cause the prover to fail before
    // emitting a proof, confirming the commitment-opening soundness we
    // shipped in Stage 11 is real (not trivially-accepted).
    //
    // The length-range predicate (`value.len() ≤ max_value_bytes`) is
    // still enforced by `validate()` OUTSIDE the AIR until the in-AIR
    // length-range predicate ships (Stage 15+ separate design).
    // -------------------------------------------------------------

    #[cfg(feature = "prod-proofs-preimage")]
    fn try_prove_air_only(
        value_for_trace: &[u8],
        nonce_for_trace: [u8; NONCE_LEN],
        public_commitment: trusset_circuits_common::Digest,
    ) -> Result<Vec<u8>, String> {
        use trusset_circuits_common::stark_options;
        let limbs = prover::digest_to_air_limbs(&public_commitment);
        let pi = air::PreimageAirPublicInputs { commitment: limbs };
        // Debug builds: Winterfell `debug_assert!`s panic on bad trace.
        // Release builds: `debug_assert!`s are compiled out; the prover emits
        // invalid bytes which the verifier then rejects. Run both stages so
        // the wrapper's rejection contract works in both profiles.
        let prove_result = std::panic::catch_unwind(|| {
            prover::build_proof(
                value_for_trace,
                &nonce_for_trace,
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
        let pi_verify = air::PreimageAirPublicInputs { commitment: limbs };
        match verifier::verify_proof(&proof_bytes, pi_verify) {
            Ok(()) => Ok(proof_bytes),
            Err(e) => Err(format!("VerifierError: {e:?}")),
        }
    }

    #[cfg(feature = "prod-proofs-preimage")]
    #[test]
    fn air_rejects_different_value_for_same_commitment() {
        // Build the public commitment from "alice"; try to prove with "bob".
        // The trace builder will produce a trace whose final-row rate is
        // the commitment of "bob", not "alice" — boundary constraint fails.
        let nonce = [0x33u8; NONCE_LEN];
        let alice_witness = Witness {
            value: b"alice".to_vec(),
            nonce,
        };
        let alice_commitment = commit(&alice_witness);
        let result = try_prove_air_only(b"bob", nonce, alice_commitment);
        assert!(
            result.is_err(),
            "AIR must reject value='bob' against alice's commitment, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-preimage")]
    #[test]
    fn air_rejects_different_nonce_for_same_commitment() {
        // Build commitment from (alice, nonce1); try to prove with (alice, nonce2).
        let alice_with_nonce1 = Witness {
            value: b"alice".to_vec(),
            nonce: [0x11u8; NONCE_LEN],
        };
        let public_commitment = commit(&alice_with_nonce1);
        let result = try_prove_air_only(b"alice", [0x22u8; NONCE_LEN], public_commitment);
        assert!(
            result.is_err(),
            "AIR must reject mismatched nonce for same value, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-preimage")]
    #[test]
    fn air_rejects_tampered_commitment_limbs() {
        // Honest witness, but tamper one limb of the public commitment.
        let w = fixture_witness();
        let mut tampered = commit(&w);
        tampered[2] = trusset_circuits_common::Felt::new(0xdeadbeefu64);
        let result = try_prove_air_only(&w.value, w.nonce, tampered);
        assert!(
            result.is_err(),
            "AIR must reject tampered commitment, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-preimage")]
    #[test]
    fn air_accepts_honest_witness() {
        // Positive control: confirm the negative tests above are meaningful
        // by verifying that an HONEST witness passes the same code path.
        let w = fixture_witness();
        let public_commitment = commit(&w);
        let result = try_prove_air_only(&w.value, w.nonce, public_commitment);
        assert!(
            result.is_ok(),
            "AIR must accept honest witness through the same code path, got {:?}",
            result.err()
        );
    }
}
