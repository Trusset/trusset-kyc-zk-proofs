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
pub mod seed;
pub mod serialize;
pub mod stub_proof;

pub use circuit_id::CircuitId;
pub use commitment::{compute_commitment, NONCE_LEN};
pub use domain::{
    COMMITMENT_TAG, DOMAIN_TAG_BYTES, LEAF_TAG, NODE_TAG, PROOF_DIGEST_TAG, PUBLIC_DIGEST_TAG,
    SET_LEAF_TAG, SET_NODE_TAG,
};
pub use field::{bytes_to_field, field_to_bytes, string_to_field_canonical, Felt};
pub use hash::{
    hash_bytes_with_tag, hash_elements, hash_felts_with_tag, hash_two, hash_two_with_tag,
    rescue_merge_raw, Digest, DIGEST_LEN_BYTES, DIGEST_LEN_FELTS,
};
pub use seed::{derive_leaf_seed, derive_subject_seed, MASTER_KEY_LEN, SEED_LEN};
pub use serialize::{
    digest_from_bytes, digest_to_bytes, digest_to_hex, hex_to_digest, write_canonical_bytes,
    write_canonical_u64,
};
pub use stub_proof::{StubProof, StubProofError, STUB_MAGIC, STUB_PROOF_LEN};

/// Bumped whenever a backwards-incompatible change is made to leaf encoding,
/// Merkle layout, AIR constraints, or serialization. Folded into every
/// per-subject HKDF info string so a circuits-version bump invalidates all
/// caches and forces re-proving.
pub const CIRCUITS_VERSION: u32 = 1;
