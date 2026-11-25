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
//!   - `predicates` v3.1 predicate table shared with the on-chain hub
//!   - `header`   v3.1 signed header binding a root to one attestation
//!   - `disclosure` v3.1 single-leaf disclosure document
//!   - `attestation` v3.1 `attestation.json` for the hub's attest calldata

pub mod archive;
pub mod attestation;
pub mod claims;
pub mod disclosure;
pub mod header;
pub mod leaf;
pub mod manifest;
pub mod merkle;
pub mod predicates;
pub mod registry;
pub mod sign;
