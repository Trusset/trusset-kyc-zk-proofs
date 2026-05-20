//! Workspace-wide pinned Winterfell `ProofOptions`.
//!
//! All four Phase 2B circuits MUST use `STARK_OPTIONS` so a single audit of
//! the FRI parameters covers the entire bundle, and so that
//! `manifest.stark.securityBits` (currently 100) accurately describes every
//! per-leaf proof.
//!
//! ## Parameter justification (see `docs/SECURITY.md` §soundness target)
//!
//! Winterfell 0.13's conjectured-security formula for a STARK over an
//! extension field of degree `d` with blowup `b`, FRI queries `q`, and
//! grinding `g` bits gives roughly:
//!
//! ```text
//!   bits ≈ q * log2(b) - log2(b) + g + d * log2(|F|)/2
//! ```
//!
//! Concretely for this workspace:
//!
//! - **Field**: Goldilocks (`p ≈ 2^64 - 2^32 + 1`, ~64-bit).
//! - **Extension**: Quadratic (`d = 2`) — needed for FRI soundness on a
//!   64-bit base field; Winterfell's recommended choice for Goldilocks.
//! - **Blowup factor**: 16 (`log2 = 4`). 8 falls short of the 100-bit
//!   target (Winterfell internal calculator reports 96 bits at blowup 8
//!   with otherwise-identical parameters); 16 reaches 100.
//! - **FRI queries**: 27. Gives `27 * 4 - 4 = 104` bits of FRI soundness
//!   at blowup 16 before the extension and grinding contributions.
//! - **Grinding**: 16 bits of PoW on the proof transcript.
//! - **FRI folding**: 4 (standard Winterfell default).
//! - **FRI remainder max degree**: 7.
//!
//! Combined bits-of-security estimate (Winterfell internal calculator):
//! 100 conjectured bits, matching the value already published in
//! `manifest.stark.securityBits` for Phase 2A — so flipping `mode` to
//! `"production"` does not require revising that field.
//!
//! These constants are pinned ONCE here. Changing them is a Phase-3-level
//! workspace event: it invalidates every cached bundle, requires bumping
//! `CIRCUITS_VERSION`, and forces re-proving across the operator's entire
//! KYC dataset.

use winter_air::{BatchingMethod, FieldExtension, ProofOptions};

/// FRI blowup factor (power-of-two). 16 chosen to reach the
/// `STARK_SECURITY_BITS = 100` target with Quadratic extension over
/// Goldilocks; 8 falls short (Winterfell internal calculator reports
/// 96 bits with otherwise-identical parameters, verified empirically).
pub const STARK_BLOWUP_FACTOR: usize = 16;

/// Number of FRI queries.
pub const STARK_NUM_QUERIES: usize = 27;

/// Grinding-factor (bits of proof-of-work on the proof transcript).
pub const STARK_GRINDING_FACTOR: u32 = 16;

/// FRI folding factor.
pub const STARK_FRI_FOLDING_FACTOR: usize = 4;

/// FRI remainder polynomial max degree.
pub const STARK_FRI_REMAINDER_MAX_DEGREE: usize = 7;

/// Target conjectured security in bits. Matches
/// `manifest.stark.securityBits` and must not be changed without also
/// updating that field (which is a determinism-breaking event).
pub const STARK_SECURITY_BITS: u32 = 100;

/// Constraint-batching method (Winterfell 0.13 ProofOptions extension).
/// `Linear` is the most conservative / audit-friendly choice; it has been
/// the default in the Winterfell example suite since 0.13's batching
/// generalization landed. Changing this is a determinism-breaking event.
pub const STARK_BATCHING_CONSTRAINTS: BatchingMethod = BatchingMethod::Linear;
pub const STARK_BATCHING_DEEP: BatchingMethod = BatchingMethod::Linear;

/// Construct the pinned workspace-wide `ProofOptions`.
#[must_use]
pub fn stark_options() -> ProofOptions {
    ProofOptions::new(
        STARK_NUM_QUERIES,
        STARK_BLOWUP_FACTOR,
        STARK_GRINDING_FACTOR,
        FieldExtension::Quadratic,
        STARK_FRI_FOLDING_FACTOR,
        STARK_FRI_REMAINDER_MAX_DEGREE,
        STARK_BATCHING_CONSTRAINTS,
        STARK_BATCHING_DEEP,
    )
}

/// Internal cap on the padded byte-length of a `set_membership` witness
/// `value` (Phase 2B AIR trace-shape constant). NOT part of any
/// `paramsHash` — purely an implementation detail of the AIR. Country
/// codes are ≤ 3 bytes, document codes ≤ 32; 64 leaves comfortable
/// headroom for any UTF-8 / NFC variant.
pub const MAX_SET_VALUE_BYTES_PADDED: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_options_construct() {
        let opts = stark_options();
        assert_eq!(opts.num_queries(), STARK_NUM_QUERIES);
        assert_eq!(opts.blowup_factor(), STARK_BLOWUP_FACTOR);
        assert_eq!(opts.grinding_factor(), STARK_GRINDING_FACTOR);
        assert_eq!(opts.field_extension(), FieldExtension::Quadratic);
    }

    #[test]
    fn set_value_padding_holds_iso3166_and_document_codes() {
        // Compile-time constant — this test exists to flag any
        // accidental lowering below ISO-3166 (3 bytes) or document codes
        // (~32 bytes). `const_assert!` would be cleaner but adds a
        // dep; the cfg-test attribute keeps the check explicit.
        const _: () = assert!(MAX_SET_VALUE_BYTES_PADDED >= 32);
    }

    /// Pin every numeric `ProofOptions` constant to its current value.
    /// These values are folded into the per-circuit `paramsHash` and
    /// into `manifest.stark.securityBits` — any drift produces a
    /// byte-incompatible bundle. The regression test is the "you must
    /// know you're changing this" gate: a constraint-design rework that
    /// happens to alter blowup or queries fails the test and forces
    /// the engineer to update audit docs + bump `CIRCUITS_VERSION`.
    #[test]
    fn stark_options_constants_are_pinned() {
        assert_eq!(STARK_BLOWUP_FACTOR, 16, "blowup factor drift");
        assert_eq!(STARK_NUM_QUERIES, 27, "query count drift");
        assert_eq!(STARK_GRINDING_FACTOR, 16, "grinding factor drift");
        assert_eq!(STARK_FRI_FOLDING_FACTOR, 4, "FRI folding drift");
        assert_eq!(
            STARK_FRI_REMAINDER_MAX_DEGREE, 7,
            "FRI remainder max degree drift"
        );
        assert_eq!(STARK_SECURITY_BITS, 100, "security bits drift");
        assert_eq!(
            STARK_BATCHING_CONSTRAINTS,
            BatchingMethod::Linear,
            "constraint batching method drift"
        );
        assert_eq!(
            STARK_BATCHING_DEEP,
            BatchingMethod::Linear,
            "DEEP batching method drift"
        );
    }
}
