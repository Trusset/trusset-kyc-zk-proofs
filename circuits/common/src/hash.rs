//! Rescue-Prime hashing primitives.
//!
//! Uses Winterfell's `Rp64_256` instantiation: state width 12 (4 capacity +
//! 8 rate), 4-felt digest = 32 bytes, target 128-bit collision resistance.
//!
//! All Rescue calls in this codebase go through one of `hash_elements`,
//! `hash_bytes_with_tag`, `hash_felts_with_tag`, or `hash_two`. Don't reach
//! for `Rp64_256` directly elsewhere — domain separation is what keeps the
//! various uses of Rescue from cross-colliding (spec §12.1).

use winter_crypto::{hashers::Rp64_256, ElementHasher, Hasher};

use crate::domain::{DOMAIN_TAG_BYTES, NODE_TAG};
use crate::field::{bytes_to_field, Felt};

pub const DIGEST_LEN_FELTS: usize = 4;
pub const DIGEST_LEN_BYTES: usize = 32;

/// 4-felt Rescue-Prime digest.
pub type Digest = [Felt; DIGEST_LEN_FELTS];

/// Winterfell's concrete digest type for Rp64_256. We work with our own
/// `[Felt; 4]` alias at the API boundary; this alias is only used internally
/// to bridge to Winterfell's `Hasher` trait API.
type Rp64Digest = <Rp64_256 as Hasher>::Digest;

fn digest_from_element(d: Rp64Digest) -> Digest {
    let elements = d.as_elements();
    [elements[0], elements[1], elements[2], elements[3]]
}

fn element_from_digest(d: &Digest) -> Rp64Digest {
    Rp64Digest::from(*d)
}

/// Hash a slice of field elements with Rescue-Prime.
pub fn hash_elements(elements: &[Felt]) -> Digest {
    digest_from_element(Rp64_256::hash_elements(elements))
}

/// Hash bytes prefixed with a 32-byte domain tag. The combined sequence is
/// chunked into Goldilocks limbs and passed through Rescue-Prime.
///
/// Two calls with different tags but otherwise identical bodies produce
/// independent digests — the basic invariant the spec requires (§12.1).
pub fn hash_bytes_with_tag(tag: &[u8; DOMAIN_TAG_BYTES], body: &[u8]) -> Digest {
    let mut buf = Vec::with_capacity(DOMAIN_TAG_BYTES + body.len());
    buf.extend_from_slice(tag);
    buf.extend_from_slice(body);
    let felts = bytes_to_field(&buf);
    hash_elements(&felts)
}

/// Hash a tag (as bytes) followed by a body of field elements. Used when
/// the body is already in field form (e.g. an inner hash result, or the
/// canonical felt encoding of a value).
pub fn hash_felts_with_tag(tag: &[u8; DOMAIN_TAG_BYTES], body: &[Felt]) -> Digest {
    let mut elements = bytes_to_field(tag);
    elements.extend_from_slice(body);
    hash_elements(&elements)
}

/// Merge two digests under the `NODE_TAG` domain. This is the basic Merkle
/// inner-node operation used by `prover/src/merkle.rs` and the set Merkle
/// tree (which uses `SET_NODE_TAG` via `hash_two_with_tag`).
pub fn hash_two(a: &Digest, b: &Digest) -> Digest {
    hash_two_with_tag(&NODE_TAG, a, b)
}

/// Like `hash_two` but with an explicit domain tag, for the set Merkle tree.
pub fn hash_two_with_tag(tag: &[u8; DOMAIN_TAG_BYTES], a: &Digest, b: &Digest) -> Digest {
    // Build [tag_felts ‖ a ‖ b]. We don't use Rp64_256::merge directly because
    // it doesn't accept a domain tag; routing through `hash_elements` keeps
    // every call uniformly tagged. The cost is one extra absorption — small
    // compared to the FRI cost a circuit will pay.
    let mut elements = bytes_to_field(tag);
    elements.extend_from_slice(a);
    elements.extend_from_slice(b);
    hash_elements(&elements)
}

/// Re-export of the raw Rescue merge primitive, for circuits that need to
/// constrain it inside an AIR without our domain-tag wrapper.
pub fn rescue_merge_raw(a: &Digest, b: &Digest) -> Digest {
    digest_from_element(Rp64_256::merge(&[element_from_digest(a), element_from_digest(b)]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{LEAF_TAG, PROOF_DIGEST_TAG, PUBLIC_DIGEST_TAG, SET_NODE_TAG};

    fn zero_digest() -> Digest {
        [Felt::new(0u64); DIGEST_LEN_FELTS]
    }

    #[test]
    fn hash_is_deterministic() {
        let a = hash_elements(&[Felt::new(1u64), Felt::new(2u64), Felt::new(3u64)]);
        let b = hash_elements(&[Felt::new(1u64), Felt::new(2u64), Felt::new(3u64)]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_yield_different_digests() {
        let a = hash_elements(&[Felt::new(1u64)]);
        let b = hash_elements(&[Felt::new(2u64)]);
        assert_ne!(a, b);
    }

    #[test]
    fn domain_tags_produce_independent_digests() {
        let body = b"alice";
        let leaf_h = hash_bytes_with_tag(&LEAF_TAG, body);
        let pub_h = hash_bytes_with_tag(&PUBLIC_DIGEST_TAG, body);
        let prf_h = hash_bytes_with_tag(&PROOF_DIGEST_TAG, body);
        // All three differ from each other and from the zero digest.
        assert_ne!(leaf_h, pub_h);
        assert_ne!(leaf_h, prf_h);
        assert_ne!(pub_h, prf_h);
        assert_ne!(leaf_h, zero_digest());
    }

    #[test]
    fn hash_two_is_order_sensitive() {
        let a = hash_bytes_with_tag(&LEAF_TAG, b"left");
        let b = hash_bytes_with_tag(&LEAF_TAG, b"right");
        let ab = hash_two(&a, &b);
        let ba = hash_two(&b, &a);
        assert_ne!(ab, ba, "merge must be order-sensitive — sort happens at the leaf layer");
    }

    #[test]
    fn hash_two_with_different_tags_differ() {
        let a = hash_bytes_with_tag(&LEAF_TAG, b"foo");
        let b = hash_bytes_with_tag(&LEAF_TAG, b"bar");
        let node = hash_two(&a, &b);
        let set_node = hash_two_with_tag(&SET_NODE_TAG, &a, &b);
        assert_ne!(
            node, set_node,
            "main-tree and set-tree merges must produce different digests"
        );
    }

    #[test]
    fn digest_length_invariant() {
        let d = hash_bytes_with_tag(&LEAF_TAG, b"x");
        assert_eq!(d.len(), DIGEST_LEN_FELTS);
        assert_eq!(DIGEST_LEN_FELTS * 8, DIGEST_LEN_BYTES);
    }
}
