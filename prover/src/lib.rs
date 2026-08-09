//! Prover internals exposed for integration testing.
//!
//! The `trusset-prover` binary is a thin wrapper over these modules
//! (see `src/main.rs`). End-to-end tests in `tests/end_to_end.rs` consume
//! this library API directly to avoid relying on a stable CLI surface
//! while phases are still in flux.

pub mod audit;
pub mod bundle;
pub mod dispatch;
pub mod encrypt;
pub mod entropy;
pub mod errors;
pub mod io;
pub mod job;
pub mod leaf;
pub mod manifest;
pub mod merkle;
pub mod rekey;
pub mod sign;
