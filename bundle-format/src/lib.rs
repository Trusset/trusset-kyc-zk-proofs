//! Shared bundle primitives — consumed by both `trusset-prover` and
//! `trusset-verifier`. WASM-compatible (no `std::fs`, no `std::env`).
//!
//! Modules:
//!   - `leaf`     spec §7 leaf hash + proof digest
//!   - `merkle`   sorted Rescue Merkle root over leaf hashes
//!   - `manifest` `Manifest` struct, sentinel signing, canonical JSON
//!   - `sign`     ed25519 signature verification (no signing — that's prover-only)
//!   - `claims`   v3 claim descriptors, validity intervals, binding digest
//!   - `registry` v3 append-only list registry, root history, revocations
//!   - `archive`  v3 self-contained archive container

pub mod archive;
pub mod claims;
pub mod leaf;
pub mod manifest;
pub mod merkle;
pub mod registry;
pub mod sign;
