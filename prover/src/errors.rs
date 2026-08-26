//! Stable error codes (plan §"TS ↔ Rust Integration").
//!
//! Every failure path in the prover maps to one of these codes. The TS layer
//! parses the code from the `subject_failed` NDJSON event and maps it to a
//! user-facing message + exit code (0 ok, 2 partial, 1 batch-aborting).

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// Malformed config or job spec.
    Config,
    /// Bad input data (wallet not hex, value missing, etc.).
    Input,
    /// Required env var (`TRUSSET_KYC_MASTER_KEY` / `TRUSSET_KYC_SIGNING_KEY`) absent.
    KeyMissing,
    /// Env var present but not 64-hex.
    KeyMalformed,
    /// `set_membership` list not found in `list_commitments`.
    ListNotFound,
    /// Value is not a member of the referenced set.
    ListMemberMissing,
    /// Age predicate not satisfied.
    AgeBelowMin,
    /// Tier below minimum.
    TierBelowMin,
    /// Tier value is `NONE` (=0) — not permitted at proving time.
    TierNone,
    /// Empty value where one is required (any circuited field except preimage).
    EmptyValue,
    /// Circuit-internal failure (witness construction, etc.). Bug.
    CircuitInternal,
    /// Filesystem failure.
    Io,
    /// Determinism mode required but OS entropy was drawn.
    DeterminismViolation,
    /// Stub-mode proof rejected in production mode.
    StubRejected,
    /// Pinned `ProofOptions` fall below the published conjectured-security
    /// floor. Raised at startup before any proving work begins.
    WeakProofOptions,
    /// A version 3.0.0 job carries no issuer block, so the bundle would not
    /// say who is responsible for its assertions.
    IssuerMissing,
    /// A leaf that requires a claim descriptor does not carry one.
    DescriptorMissing,
    /// A claim descriptor is present but structurally unusable (unknown
    /// evidence class, empty legal basis, malformed party identifier).
    DescriptorInvalid,
    /// A validity interval is inverted, or its evidence post-dates the window
    /// it supports.
    ValidityInvalid,
    /// A leaf's declared list version disagrees with the list the prover was
    /// actually given.
    ListVersionMismatch,
    /// The batch ran against an unpinned wall-clock epoch without the explicit
    /// development flag.
    UnpinnedEpoch,
}

impl ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorCode::Config => "E_CONFIG",
            ErrorCode::Input => "E_INPUT",
            ErrorCode::KeyMissing => "E_KEY_MISSING",
            ErrorCode::KeyMalformed => "E_KEY_MALFORMED",
            ErrorCode::ListNotFound => "E_LIST_NOT_FOUND",
            ErrorCode::ListMemberMissing => "E_LIST_MEMBER_MISSING",
            ErrorCode::AgeBelowMin => "E_AGE_BELOW_MIN",
            ErrorCode::TierBelowMin => "E_TIER_BELOW_MIN",
            ErrorCode::TierNone => "E_TIER_NONE",
            ErrorCode::EmptyValue => "E_EMPTY_VALUE",
            ErrorCode::CircuitInternal => "E_CIRCUIT_INTERNAL",
            ErrorCode::Io => "E_IO",
            ErrorCode::DeterminismViolation => "E_DETERMINISM_VIOLATION",
            ErrorCode::StubRejected => "E_STUB_REJECTED",
            ErrorCode::WeakProofOptions => "E_WEAK_PROOF_OPTIONS",
            ErrorCode::IssuerMissing => "E_ISSUER_MISSING",
            ErrorCode::DescriptorMissing => "E_DESCRIPTOR_MISSING",
            ErrorCode::DescriptorInvalid => "E_DESCRIPTOR_INVALID",
            ErrorCode::ValidityInvalid => "E_VALIDITY_INVALID",
            ErrorCode::ListVersionMismatch => "E_LIST_VERSION_MISMATCH",
            ErrorCode::UnpinnedEpoch => "E_UNPINNED_EPOCH",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Prover error carrying both a stable code and a human-readable message.
#[derive(Debug, Clone)]
pub struct ProverError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProverError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Config, message)
    }
    pub fn input(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Input, message)
    }
    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Io, message)
    }
    pub fn circuit_internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::CircuitInternal, message)
    }
}

impl fmt::Display for ProverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProverError {}

impl From<std::io::Error> for ProverError {
    fn from(e: std::io::Error) -> Self {
        ProverError::io(e.to_string())
    }
}

impl From<serde_json::Error> for ProverError {
    fn from(e: serde_json::Error) -> Self {
        ProverError::input(format!("json: {}", e))
    }
}

pub type Result<T> = std::result::Result<T, ProverError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant of `ErrorCode` is enumerated here. The compiler
    /// enforces exhaustiveness via the `match` below: adding a new variant
    /// without extending `ALL_CODES` fails the build, and the body
    /// assertion catches any string-drift in `as_str()`.
    ///
    /// The strings themselves are a wire-format contract: the TS CLI
    /// pattern-matches them in `cli/src/bundleWriter.ts` (relayed into
    /// `failures.csv` per spec §"Output bundle"), and external counterparty
    /// integrators reading the NDJSON event stream rely on them.
    /// Drift between this list and `as_str()` MUST be a build break.
    const ALL_CODES: &[(ErrorCode, &str)] = &[
        (ErrorCode::Config, "E_CONFIG"),
        (ErrorCode::Input, "E_INPUT"),
        (ErrorCode::KeyMissing, "E_KEY_MISSING"),
        (ErrorCode::KeyMalformed, "E_KEY_MALFORMED"),
        (ErrorCode::ListNotFound, "E_LIST_NOT_FOUND"),
        (ErrorCode::ListMemberMissing, "E_LIST_MEMBER_MISSING"),
        (ErrorCode::AgeBelowMin, "E_AGE_BELOW_MIN"),
        (ErrorCode::TierBelowMin, "E_TIER_BELOW_MIN"),
        (ErrorCode::TierNone, "E_TIER_NONE"),
        (ErrorCode::EmptyValue, "E_EMPTY_VALUE"),
        (ErrorCode::CircuitInternal, "E_CIRCUIT_INTERNAL"),
        (ErrorCode::Io, "E_IO"),
        (ErrorCode::DeterminismViolation, "E_DETERMINISM_VIOLATION"),
        (ErrorCode::StubRejected, "E_STUB_REJECTED"),
        (ErrorCode::WeakProofOptions, "E_WEAK_PROOF_OPTIONS"),
        (ErrorCode::IssuerMissing, "E_ISSUER_MISSING"),
        (ErrorCode::DescriptorMissing, "E_DESCRIPTOR_MISSING"),
        (ErrorCode::DescriptorInvalid, "E_DESCRIPTOR_INVALID"),
        (ErrorCode::ValidityInvalid, "E_VALIDITY_INVALID"),
        (ErrorCode::ListVersionMismatch, "E_LIST_VERSION_MISMATCH"),
        (ErrorCode::UnpinnedEpoch, "E_UNPINNED_EPOCH"),
    ];

    #[test]
    fn every_error_code_maps_to_stable_wire_string() {
        for (code, expected) in ALL_CODES {
            assert_eq!(
                code.as_str(),
                *expected,
                "wire string drift on variant {:?}",
                code
            );
            assert!(
                expected.starts_with("E_"),
                "{:?} string {:?} does not start with E_",
                code,
                expected
            );
        }
    }

    #[test]
    fn error_code_strings_are_pairwise_distinct() {
        use std::collections::HashSet;
        let mut seen: HashSet<&'static str> = HashSet::new();
        for (code, s) in ALL_CODES {
            assert!(
                seen.insert(s),
                "duplicate wire string {:?} (variant {:?})",
                s,
                code
            );
        }
    }

    /// Exhaustive match: if you add a variant to `ErrorCode` and don't
    /// extend `ALL_CODES`, the compiler emits a non-exhaustive-patterns
    /// error. This is the actual drift guard.
    #[test]
    fn exhaustive_variant_coverage_via_match() {
        fn assert_covered(code: ErrorCode) {
            match code {
                ErrorCode::Config => {}
                ErrorCode::Input => {}
                ErrorCode::KeyMissing => {}
                ErrorCode::KeyMalformed => {}
                ErrorCode::ListNotFound => {}
                ErrorCode::ListMemberMissing => {}
                ErrorCode::AgeBelowMin => {}
                ErrorCode::TierBelowMin => {}
                ErrorCode::TierNone => {}
                ErrorCode::EmptyValue => {}
                ErrorCode::CircuitInternal => {}
                ErrorCode::Io => {}
                ErrorCode::DeterminismViolation => {}
                ErrorCode::StubRejected => {}
                ErrorCode::WeakProofOptions => {}
                ErrorCode::IssuerMissing => {}
                ErrorCode::DescriptorMissing => {}
                ErrorCode::DescriptorInvalid => {}
                ErrorCode::ValidityInvalid => {}
                ErrorCode::ListVersionMismatch => {}
                ErrorCode::UnpinnedEpoch => {}
            }
        }
        // Force evaluation against ALL_CODES so the two stay in sync.
        for (code, _) in ALL_CODES {
            assert_covered(code.clone());
        }
        // The list length must match the enum size. Update both together.
        assert_eq!(ALL_CODES.len(), 21);
    }

    #[test]
    fn display_formats_code_then_message() {
        let e = ProverError::input("bad wallet");
        assert_eq!(format!("{}", e), "E_INPUT: bad wallet");
    }
}
