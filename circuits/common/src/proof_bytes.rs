//! Canonical STARK proof bytes.
//!
//! Winterfell's `Proof::from_bytes` stops reading once the proof is complete
//! and ignores anything after it, and `proof_digest` packs bytes into field
//! elements with zero padding and no length prefix. Together that means a
//! proof with a trailing zero byte can carry the same `proofDigest` and
//! verify as the same proof. Nothing false is proved that way, but a 3.1.0
//! verifier requires one byte string per proof: the bytes must be exactly the
//! serialization of the proof they decode to.

use winterfell::Proof;

/// True when `bytes` decodes to a Winterfell proof and re-serializes to the
/// same bytes.
#[must_use]
pub fn is_canonical_proof_bytes(bytes: &[u8]) -> bool {
    match Proof::from_bytes(bytes) {
        Ok(p) => p.to_bytes() == bytes,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_and_empty_are_not_canonical() {
        assert!(!is_canonical_proof_bytes(&[]));
        assert!(!is_canonical_proof_bytes(&[1, 2, 3]));
    }
}
