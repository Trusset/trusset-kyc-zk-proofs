//! Rescue hiding commitment used by all four circuits (v2, felt-level).
//!
//! ## Format
//!
//! ```text
//! commitment = Rescue(
//!     bytes_to_field(COMMITMENT_TAG)         // 5 felts (32-byte tag chunked at 7 bytes/felt)
//!   ‖ Felt(circuit_id as u64)                 // 1 felt (cross-circuit domain separation)
//!   ‖ Felt(witness_felts.len() as u64)        // 1 felt (length prefix — collision resistance)
//!   ‖ witness_felts                           // N felts (per-circuit witness encoding)
//!   ‖ bytes_to_field(nonce)                   // 5 felts (32-byte nonce)
//! )
//! ```
//!
//! ## v1 → v2 rationale
//!
//! v1 hashed BYTES (`Rescue(COMMITMENT_TAG ‖ u32_le(value.len()) ‖ value ‖
//! nonce)`) which forced byte-chunking of all inputs into 7-byte Goldilocks
//! limbs. The chunking embeds witness bytes at arbitrary bit positions
//! inside felts, which makes AIR-side predicate binding require expensive
//! byte decomposition (~250 trace columns for `tier_threshold`'s 1-byte
//! witness — see `docs/STEP_2B_COMMITMENT_DESIGN.md`).
//!
//! v2 feeds **felts** directly to Rescue. Witness predicates can now bind
//! to specific felts in the input vector without bit-level decomposition,
//! collapsing trace widths from ~250 to ~16 columns. The `COMMITMENT_TAG`
//! and `nonce` are still byte-chunked (they are byte-typed externally and
//! the 7 domain tags are frozen wire-format), but they are NEVER subject
//! to predicate binding so the chunking is harmless.
//!
//! ## Cross-circuit domain separation
//!
//! v2 adds `circuit_id` as the felt immediately after the tag. This
//! prevents a malicious operator from reinterpreting a commitment minted
//! under one circuit as one minted under another circuit (e.g., a
//! `tier_threshold` commitment cannot be re-bound as a `preimage_knowledge`
//! commitment by changing only the `circuit` field in a leaf). v1 did not
//! have this protection — same `(value_bytes, nonce)` produced the same
//! commitment regardless of which circuit was claiming it.
//!
//! ## Length prefix
//!
//! Variable-length witnesses (preimage_knowledge, set_membership) supply
//! variable `witness_felts` vectors. The explicit length felt prevents
//! ambiguity between e.g. `(witness=[a,b], nonce=[c,d,...])` and
//! `(witness=[a], nonce=[b,c,d,...])`.

use crate::{bytes_to_field, hash_elements, CircuitId, Digest, Felt, COMMITMENT_TAG};

pub const NONCE_LEN: usize = 32;

/// Compute the v2 felt-level hiding commitment.
///
/// `witness_felts` is the per-circuit canonical felt encoding of the
/// witness value (NOT including the nonce). Per-circuit helpers live in
/// each circuit crate; conventionally they are named `witness_to_felts`.
pub fn compute_commitment(
    circuit_id: CircuitId,
    witness_felts: &[Felt],
    nonce: &[u8; NONCE_LEN],
) -> Digest {
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    let nonce_felts = bytes_to_field(nonce);
    let mut elements: Vec<Felt> =
        Vec::with_capacity(tag_felts.len() + 2 + witness_felts.len() + nonce_felts.len());
    elements.extend_from_slice(&tag_felts);
    elements.push(Felt::new(u64::from(circuit_id.as_u8())));
    elements.push(Felt::new(witness_felts.len() as u64));
    elements.extend_from_slice(witness_felts);
    elements.extend_from_slice(&nonce_felts);
    hash_elements(&elements)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid() -> CircuitId {
        CircuitId::PreimageKnowledge
    }

    #[test]
    fn determinism() {
        let w = [Felt::new(1), Felt::new(2)];
        let a = compute_commitment(cid(), &w, &[0u8; 32]);
        let b = compute_commitment(cid(), &w, &[0u8; 32]);
        assert_eq!(a, b);
    }

    #[test]
    fn nonce_change_changes_commitment() {
        let w = [Felt::new(7)];
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        assert_ne!(
            compute_commitment(cid(), &w, &n1),
            compute_commitment(cid(), &w, &n2)
        );
    }

    #[test]
    fn witness_change_changes_commitment() {
        let n = [0u8; 32];
        assert_ne!(
            compute_commitment(cid(), &[Felt::new(1)], &n),
            compute_commitment(cid(), &[Felt::new(2)], &n)
        );
    }

    #[test]
    fn length_prefix_breaks_concatenation_attack() {
        // ([a, b], nonce_a) vs ([a], nonce_b) where nonce_b starts with b's
        // 7-byte chunk — length prefix must keep these distinct.
        let n = [0u8; 32];
        assert_ne!(
            compute_commitment(cid(), &[Felt::new(1), Felt::new(2)], &n),
            compute_commitment(cid(), &[Felt::new(1)], &n)
        );
    }

    #[test]
    fn circuit_id_separates_commitments() {
        // Same witness and nonce, different circuit_id → different
        // commitments. v1 did NOT have this protection.
        let w = [Felt::new(42)];
        let n = [0u8; 32];
        let a = compute_commitment(CircuitId::TierThreshold, &w, &n);
        let b = compute_commitment(CircuitId::AgeThreshold, &w, &n);
        assert_ne!(a, b, "circuit_id must produce distinct commitments");
    }

    #[test]
    fn empty_witness_is_valid() {
        // Should never happen in practice (every circuit has at least one
        // witness felt) but the formula handles empty witnesses too.
        let a = compute_commitment(cid(), &[], &[0u8; 32]);
        let b = compute_commitment(cid(), &[], &[1u8; 32]);
        assert_ne!(a, b);
    }
}
