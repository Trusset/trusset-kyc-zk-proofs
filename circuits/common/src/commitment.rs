//! Rescue hiding commitment used by all four circuits.
//!
//! `commitment = Rescue(COMMITMENT_TAG ‖ u32_le(value.len()) ‖ value ‖ nonce)`
//!
//! The length prefix prevents any ambiguity between `(value, nonce)` and
//! `(value || nonce_prefix, nonce_suffix)` for different value lengths.
//! Without it, an attacker could find two distinct witness pairs hashing to
//! the same commitment.

use crate::{hash_bytes_with_tag, Digest, COMMITMENT_TAG};

pub const NONCE_LEN: usize = 32;

/// Compute the commitment for arbitrary value bytes and a 32-byte nonce.
/// Used by `preimage_knowledge` and `set_membership` directly; the
/// fixed-width circuits (`tier_threshold`, `age_threshold`) serialize their
/// witness into bytes first and pass through here.
pub fn compute_commitment(value: &[u8], nonce: &[u8; NONCE_LEN]) -> Digest {
    let len: u32 = value
        .len()
        .try_into()
        .expect("commitment value length exceeds u32::MAX");
    let mut buf = Vec::with_capacity(4 + value.len() + NONCE_LEN);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
    buf.extend_from_slice(nonce);
    hash_bytes_with_tag(&COMMITMENT_TAG, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let a = compute_commitment(b"hello", &[0u8; 32]);
        let b = compute_commitment(b"hello", &[0u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn nonce_change_changes_commitment() {
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        assert_ne!(
            compute_commitment(b"x", &n1),
            compute_commitment(b"x", &n2)
        );
    }

    #[test]
    fn value_change_changes_commitment() {
        let n = [0u8; 32];
        assert_ne!(
            compute_commitment(b"x", &n),
            compute_commitment(b"y", &n)
        );
    }

    #[test]
    fn length_prefix_breaks_concatenation_attack() {
        // Without a length prefix, ("ab", b"\0\0...") and ("a", b"b\0...")
        // could collide. With it, they must not.
        let nonce_a = [0u8; 32];
        let mut nonce_b = [0u8; 32];
        nonce_b[0] = b'b';
        assert_ne!(
            compute_commitment(b"ab", &nonce_a),
            compute_commitment(b"a", &nonce_b)
        );
    }
}
