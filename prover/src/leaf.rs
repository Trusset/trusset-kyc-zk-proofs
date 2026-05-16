//! Re-export of leaf hash builders from `trusset-bundle-format`.
//!
//! This module exists only to avoid a sweeping rename across the prover
//! codebase. New code should `use trusset_bundle_format::leaf::*;` directly.

pub use trusset_bundle_format::leaf::{compute_leaf_hash, compute_proof_digest};
