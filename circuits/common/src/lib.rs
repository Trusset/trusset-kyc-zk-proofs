//! Shared primitives for Trusset KYC v2 circuits.
//!
//! This crate is consumed by every circuit, the prover binary, the verifier
//! crate, and the list-commit helper. Any change here is a workspace-wide
//! crypto change and must be reviewed accordingly.

pub mod circuit_id;
pub mod commitment;
pub mod domain;
pub mod field;
pub mod hash;
pub mod proof_options;
pub mod rescue_air;
pub mod seed;
pub mod serialize;
pub mod stub_proof;

pub use circuit_id::CircuitId;
pub use commitment::{compute_commitment, NONCE_LEN};
pub use domain::{
    COMMITMENT_TAG, DOMAIN_TAG_BYTES, LEAF_BIND_TAG, LEAF_TAG, MERKLE_PAD_TAG, MERKLE_ROOT_TAG,
    NODE_TAG, PROOF_DIGEST_TAG, PUBLIC_DIGEST_TAG, SET_LEAF_TAG, SET_NODE_TAG,
};
pub use field::{
    bytes_to_field, field_to_bytes, nfc_canonicalize, string_to_field_canonical, Felt,
};
pub use hash::{
    hash_bytes_with_tag, hash_elements, hash_felts_with_tag, hash_two, hash_two_with_tag,
    rescue_merge_raw, Digest, DIGEST_LEN_BYTES, DIGEST_LEN_FELTS,
};
pub use proof_options::{
    conjectured_security_bits, stark_options, MAX_SET_VALUE_BYTES_PADDED,
    MAX_WORKSPACE_TRACE_LENGTH, STARK_BLOWUP_FACTOR, STARK_FRI_FOLDING_FACTOR,
    STARK_FRI_REMAINDER_MAX_DEGREE, STARK_GRINDING_FACTOR, STARK_NUM_QUERIES, STARK_SECURITY_BITS,
};
pub use seed::{
    derive_deterministic_subject_key, derive_leaf_seed, derive_prover_seed, derive_subject_seed,
    MASTER_KEY_LEN, PROVER_SEED_INFO, SEED_LEN,
};
pub use serialize::{
    bytes32_to_hex, digest_from_bytes, digest_to_bytes, digest_to_hex, hex_to_digest,
    write_canonical_bytes, write_canonical_u64,
};
pub use stub_proof::{StubProof, StubProofError, STUB_MAGIC, STUB_PROOF_LEN};

/// Bumped whenever a backwards-incompatible change is made to leaf encoding,
/// Merkle layout, AIR constraints, or serialization. Folded into every
/// per-subject HKDF info string so a circuits-version bump invalidates all
/// caches and forces re-proving.
/// Bumped 1 → 2 in Phase 2B Step-B with the v2 felt-level commitment
/// scheme (see `commitment.rs`). Bumped 2 → 3 in v2.1.0 when the
/// `set_membership` AIR gained the Merkle-walk carry and sibling binding
/// constraints; the v2 AIR is retained for verifying existing bundles.
pub const CIRCUITS_VERSION: u32 = 3;

#[cfg(test)]
mod stability_tests {
    use super::*;

    /// `CIRCUITS_VERSION` is folded into every per-subject HKDF info string
    /// AND surfaced in `manifest.circuits_version`. A bump invalidates
    /// every existing bundle. The test exists so an engineer who changes
    /// constraints (and should bump) cannot silently land a behavior
    /// change without also touching the version constant: any AIR rework
    /// that changes commitment values MUST be paired with a bump here AND
    /// a corresponding update to `docs/MIGRATION_FROM_V1.md`.
    #[test]
    fn circuits_version_is_pinned() {
        assert_eq!(
            CIRCUITS_VERSION, 3,
            "CIRCUITS_VERSION bump requires migration doc update"
        );
    }
}
