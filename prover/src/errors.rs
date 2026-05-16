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

    #[test]
    fn codes_render_as_underscore_prefixed_constants() {
        assert_eq!(ErrorCode::KeyMissing.as_str(), "E_KEY_MISSING");
        assert_eq!(ErrorCode::AgeBelowMin.as_str(), "E_AGE_BELOW_MIN");
        assert_eq!(ErrorCode::StubRejected.as_str(), "E_STUB_REJECTED");
    }

    #[test]
    fn display_formats_code_then_message() {
        let e = ProverError::input("bad wallet");
        assert_eq!(format!("{}", e), "E_INPUT: bad wallet");
    }
}
