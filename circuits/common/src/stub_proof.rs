//! Phase 2A placeholder proof format.
//!
//! ## IMPORTANT — this is NOT a STARK
//!
//! A `StubProof` carries the same public-input bindings a real STARK proof
//! would carry, framed by a magic header so the verifier can refuse them in
//! production mode (spec §10 `--skip-proofs` semantics).
//!
//! Phase 2B replaces this with real Winterfell AIR proofs per spec §6.
//! Until then, the manifest must carry `"mode": "stub"` and counterparty
//! verifiers will reject the bundle unless `TRUSSET_KYC_ALLOW_STUB=1`.
//!
//! ## Layout (120 bytes)
//!
//! ```text
//! 0..16    magic        = b"TRUSSET-V2-STUB!"
//! 16       circuit_id   (CircuitId::as_u8)
//! 17..24   reserved     (zero)
//! 24..56   commitment   (Digest, BE per limb)
//! 56..88   pub_digest   (Digest)
//! 88..120  binding_tag  (Digest)
//! ```
//!
//! ## Phase 2B byte-exactness reference
//!
//! Phase 2B replaces only the *content* of `proofs/<field>.bin` with real
//! Winterfell STARK bytes. Every surrounding byte (commitment, publicInputs,
//! publicDigest, paramsHash, proofDigest, leafHash, kycHash, signing
//! canonical view, secrets.enc layout) must stay byte-identical for the same
//! witness + master key. The contracts below are the ground truth — when a
//! new AIR is wired in, its public inputs MUST hash to the same publicDigest
//! the stub path already produces.
//!
//! ### Domain tags (32-byte ASCII, see `domain.rs`)
//!
//! ```text
//! LEAF_TAG            "TRUSSET-KYC-V2:LEAF-------------"  (subject leaf)
//! NODE_TAG            "TRUSSET-KYC-V2:NODE-------------"  (subject Merkle)
//! PUBLIC_DIGEST_TAG   "TRUSSET-KYC-V2:PUB-DIGEST-------"  (public-input digest)
//! PROOF_DIGEST_TAG    "TRUSSET-KYC-V2:PRF-DIGEST-------"  (proof-bytes digest)
//! SET_LEAF_TAG        "TRUSSET-KYC-V2:SET-LEAF---------"  (allowlist leaves)
//! SET_NODE_TAG        "TRUSSET-KYC-V2:SET-NODE---------"  (allowlist Merkle)
//! COMMITMENT_TAG      "TRUSSET-KYC-V2:COMMIT-----------"  (hiding commitment)
//! ```
//!
//! ### Canonical serialization (`serialize.rs`)
//!
//! - `u64`: little-endian, 8 bytes
//! - `u32`: little-endian, 4 bytes
//! - `u8`: 1 byte
//! - byte-slice: `u32_le(len) ‖ bytes`
//! - `Digest`: 4 × `u64::to_be_bytes()` = 32 bytes
//!
//! ### Per-circuit `paramsHash` (SHA-256 over tagged params)
//!
//! ```text
//! age_threshold:       SHA256("trusset-kyc-v2:age_threshold:params"
//!                              ‖ min_age_days_le8)
//! set_membership:      SHA256("trusset-kyc-v2:set_membership:params"
//!                              ‖ u64_le(len(list_id)) ‖ list_id_utf8)
//! tier_threshold:      SHA256("trusset-kyc-v2:tier_threshold:params"
//!                              ‖ min_tier_u8)
//! preimage_knowledge:  SHA256("trusset-kyc-v2:preimage_knowledge:params"
//!                              ‖ max_value_bytes_le8)
//! ```
//!
//! ### Per-circuit `publicDigest` canonical bytes
//!
//! All four pipe their canonical-bytes through `Rescue(PUBLIC_DIGEST_TAG ‖ ...)`.
//!
//! ```text
//! age_threshold (48 B):       commitment_be32 ‖ min_age_days_le8
//!                              ‖ current_epoch_days_le8
//! set_membership (65 B):      commitment_be32 ‖ set_root_be32 ‖ set_depth_u8
//! tier_threshold (33 B):      commitment_be32 ‖ min_tier_u8
//! preimage_knowledge (32 B):  commitment_be32
//! ```
//!
//! ### Hiding commitment (identical formula across all four circuits)
//!
//! ```text
//! commitment = Rescue(COMMITMENT_TAG ‖ u32_le(len(witness_bytes))
//!                                    ‖ witness_bytes ‖ nonce_32)
//! ```
//!
//! - age:                 `witness_bytes = dob_days_le8`               (8 B)
//! - tier:                `witness_bytes = [tier_u8]`                  (1 B)
//! - set / preimage:      `witness_bytes = value` (variable)
//!
//! ### Per-leaf nonce (HKDF, `seed.rs`)
//!
//! ```text
//! subject_seed = HKDF-SHA256(ikm=MASTER_KEY, salt=b"trusset-kyc-v2/subject",
//!                            info=subject_id ‖ epoch_days_le8 ‖ config_hash_32
//!                                 ‖ circuits_version_le4)
//! leaf_seed    = HKDF-SHA256(ikm=subject_seed, salt=b"trusset-kyc-v2/leaf",
//!                            info=field_name ‖ circuit_id_u8 ‖ params_hash_32)
//! ```
//!
//! Phase 2B extends this with `prover_seed = HKDF(leaf_seed, "prover-seed")`
//! as the ONLY entropy source for the Winterfell prover PRNG (no `OsRng`).

use crate::{
    digest_from_bytes, digest_to_bytes, hash_bytes_with_tag, CircuitId, Digest, DIGEST_LEN_BYTES,
    PROOF_DIGEST_TAG,
};

pub const STUB_MAGIC: &[u8; 16] = b"TRUSSET-V2-STUB!";
pub const STUB_PROOF_LEN: usize = 120;

const RESERVED_RANGE: core::ops::Range<usize> = 17..24;
const COMMITMENT_RANGE: core::ops::Range<usize> = 24..56;
const PUB_DIGEST_RANGE: core::ops::Range<usize> = 56..88;
const BINDING_TAG_RANGE: core::ops::Range<usize> = 88..120;

#[derive(Debug, PartialEq, Eq)]
pub enum StubProofError {
    WrongLength,
    BadMagic,
    UnknownCircuitId(u8),
    ReservedNotZero,
    WrongCircuitId { expected: u8, actual: u8 },
    CommitmentMismatch,
    PublicDigestMismatch,
    BindingTagMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StubProof {
    pub circuit_id: CircuitId,
    pub commitment: Digest,
    pub pub_digest: Digest,
    pub binding_tag: Digest,
}

impl StubProof {
    /// Build a stub proof with the binding tag computed from the inputs.
    pub fn build(circuit_id: CircuitId, commitment: Digest, pub_digest: Digest) -> Self {
        let binding_tag = compute_binding_tag(circuit_id, &commitment, &pub_digest);
        Self {
            circuit_id,
            commitment,
            pub_digest,
            binding_tag,
        }
    }

    pub fn to_bytes(&self) -> [u8; STUB_PROOF_LEN] {
        let mut out = [0u8; STUB_PROOF_LEN];
        out[0..16].copy_from_slice(STUB_MAGIC);
        out[16] = self.circuit_id.as_u8();
        // reserved range already zero
        out[COMMITMENT_RANGE].copy_from_slice(&digest_to_bytes(&self.commitment));
        out[PUB_DIGEST_RANGE].copy_from_slice(&digest_to_bytes(&self.pub_digest));
        out[BINDING_TAG_RANGE].copy_from_slice(&digest_to_bytes(&self.binding_tag));
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StubProofError> {
        if bytes.len() != STUB_PROOF_LEN {
            return Err(StubProofError::WrongLength);
        }
        if &bytes[0..16] != STUB_MAGIC {
            return Err(StubProofError::BadMagic);
        }
        let circuit_id =
            CircuitId::try_from(bytes[16]).map_err(StubProofError::UnknownCircuitId)?;
        if bytes[RESERVED_RANGE].iter().any(|b| *b != 0) {
            return Err(StubProofError::ReservedNotZero);
        }

        let mut commitment_bytes = [0u8; DIGEST_LEN_BYTES];
        commitment_bytes.copy_from_slice(&bytes[COMMITMENT_RANGE]);
        let commitment = digest_from_bytes(&commitment_bytes);

        let mut pub_bytes = [0u8; DIGEST_LEN_BYTES];
        pub_bytes.copy_from_slice(&bytes[PUB_DIGEST_RANGE]);
        let pub_digest = digest_from_bytes(&pub_bytes);

        let mut binding_bytes = [0u8; DIGEST_LEN_BYTES];
        binding_bytes.copy_from_slice(&bytes[BINDING_TAG_RANGE]);
        let binding_tag = digest_from_bytes(&binding_bytes);

        Ok(Self {
            circuit_id,
            commitment,
            pub_digest,
            binding_tag,
        })
    }

    /// Structural verification against expected public bindings. Does NOT
    /// constitute STARK verification — callers must additionally enforce a
    /// `mode != "stub"` policy in production paths.
    pub fn check(
        &self,
        expected_circuit: CircuitId,
        expected_commitment: &Digest,
        expected_pub_digest: &Digest,
    ) -> Result<(), StubProofError> {
        if self.circuit_id != expected_circuit {
            return Err(StubProofError::WrongCircuitId {
                expected: expected_circuit.as_u8(),
                actual: self.circuit_id.as_u8(),
            });
        }
        if &self.commitment != expected_commitment {
            return Err(StubProofError::CommitmentMismatch);
        }
        if &self.pub_digest != expected_pub_digest {
            return Err(StubProofError::PublicDigestMismatch);
        }
        let expected_tag = compute_binding_tag(self.circuit_id, &self.commitment, &self.pub_digest);
        if self.binding_tag != expected_tag {
            return Err(StubProofError::BindingTagMismatch);
        }
        Ok(())
    }
}

fn compute_binding_tag(circuit_id: CircuitId, commitment: &Digest, pub_digest: &Digest) -> Digest {
    let mut buf = Vec::with_capacity(16 + 1 + DIGEST_LEN_BYTES + DIGEST_LEN_BYTES);
    buf.extend_from_slice(STUB_MAGIC);
    buf.push(circuit_id.as_u8());
    buf.extend_from_slice(&digest_to_bytes(commitment));
    buf.extend_from_slice(&digest_to_bytes(pub_digest));
    hash_bytes_with_tag(&PROOF_DIGEST_TAG, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_bytes_with_tag, LEAF_TAG};

    fn sample_digest(seed: u8) -> Digest {
        hash_bytes_with_tag(&LEAF_TAG, &[seed])
    }

    fn sample_proof(circuit: CircuitId) -> StubProof {
        StubProof::build(circuit, sample_digest(1), sample_digest(2))
    }

    #[test]
    fn build_to_bytes_is_fixed_length() {
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let b = p.to_bytes();
        assert_eq!(b.len(), STUB_PROOF_LEN);
    }

    #[test]
    fn bytes_start_with_magic() {
        let b = sample_proof(CircuitId::TierThreshold).to_bytes();
        assert_eq!(&b[..16], STUB_MAGIC);
    }

    #[test]
    fn roundtrip_through_bytes() {
        let p = sample_proof(CircuitId::AgeThreshold);
        let parsed = StubProof::from_bytes(&p.to_bytes()).unwrap();
        assert_eq!(p.circuit_id, parsed.circuit_id);
        assert_eq!(p.commitment, parsed.commitment);
        assert_eq!(p.pub_digest, parsed.pub_digest);
        assert_eq!(p.binding_tag, parsed.binding_tag);
    }

    #[test]
    fn check_accepts_valid_proof() {
        let commit = sample_digest(1);
        let pub_d = sample_digest(2);
        let p = StubProof::build(CircuitId::SetMembership, commit, pub_d);
        assert!(p.check(CircuitId::SetMembership, &commit, &pub_d).is_ok());
    }

    #[test]
    fn check_rejects_wrong_circuit_id() {
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let result = p.check(CircuitId::TierThreshold, &p.commitment, &p.pub_digest);
        assert!(matches!(result, Err(StubProofError::WrongCircuitId { .. })));
    }

    #[test]
    fn check_rejects_wrong_commitment() {
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let wrong = sample_digest(99);
        assert_eq!(
            p.check(CircuitId::PreimageKnowledge, &wrong, &p.pub_digest),
            Err(StubProofError::CommitmentMismatch)
        );
    }

    #[test]
    fn check_rejects_wrong_pub_digest() {
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let wrong = sample_digest(99);
        assert_eq!(
            p.check(CircuitId::PreimageKnowledge, &p.commitment, &wrong),
            Err(StubProofError::PublicDigestMismatch)
        );
    }

    #[test]
    fn from_bytes_rejects_bad_magic() {
        let mut b = sample_proof(CircuitId::PreimageKnowledge).to_bytes();
        b[0] = b'X';
        assert_eq!(StubProof::from_bytes(&b), Err(StubProofError::BadMagic));
    }

    #[test]
    fn from_bytes_rejects_wrong_length() {
        let short = [0u8; STUB_PROOF_LEN - 1];
        assert_eq!(
            StubProof::from_bytes(&short),
            Err(StubProofError::WrongLength)
        );
    }

    #[test]
    fn from_bytes_rejects_unknown_circuit_id() {
        let mut b = sample_proof(CircuitId::PreimageKnowledge).to_bytes();
        b[16] = 99;
        assert!(matches!(
            StubProof::from_bytes(&b),
            Err(StubProofError::UnknownCircuitId(99))
        ));
    }

    #[test]
    fn from_bytes_rejects_nonzero_reserved() {
        let mut b = sample_proof(CircuitId::PreimageKnowledge).to_bytes();
        b[20] = 1;
        assert_eq!(
            StubProof::from_bytes(&b),
            Err(StubProofError::ReservedNotZero)
        );
    }

    #[test]
    fn check_rejects_tampered_binding_tag() {
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let mut b = p.to_bytes();
        // Flip a bit in the binding tag region.
        b[100] ^= 0x01;
        let tampered = StubProof::from_bytes(&b).unwrap();
        assert_eq!(
            tampered.check(p.circuit_id, &p.commitment, &p.pub_digest),
            Err(StubProofError::BindingTagMismatch)
        );
    }

    #[test]
    fn check_rejects_tampered_commitment_bytes() {
        // If a caller swaps the commitment bytes inside the proof, the
        // commitment-mismatch check fires first.
        let p = sample_proof(CircuitId::PreimageKnowledge);
        let mut b = p.to_bytes();
        b[30] ^= 0xff;
        let tampered = StubProof::from_bytes(&b).unwrap();
        assert_eq!(
            tampered.check(p.circuit_id, &p.commitment, &p.pub_digest),
            Err(StubProofError::CommitmentMismatch)
        );
    }
}
