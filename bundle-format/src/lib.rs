//! Shared bundle primitives — consumed by both `trusset-prover` and
//! `trusset-verifier`. WASM-compatible (no `std::fs`, no `std::env`).
//!
//! Modules:
//!   - `leaf`     spec §7 leaf hash + proof digest
//!   - `merkle`   sorted Rescue Merkle root over leaf hashes
//!   - `manifest` `Manifest` struct, sentinel signing, canonical JSON
//!   - `sign`     ed25519 signature verification (no signing — that's prover-only)

pub mod leaf;
pub mod manifest;
pub mod merkle;
pub mod sign;
