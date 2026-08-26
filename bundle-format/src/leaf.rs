//! Leaf hash construction per spec §7.
//!
//! ```text
//! public_digest = Rescue(PUBLIC_DIGEST_TAG ‖ canonical(public_inputs))
//! proof_digest  = Rescue(PROOF_DIGEST_TAG  ‖ proof_bytes)
//! leaf_hash     = Rescue(
//!                   LEAF_TAG
//!                   ‖ len_le(field_name) ‖ field_name_bytes
//!                   ‖ circuit_id u8
//!                   ‖ len_le(wallet_bytes) ‖ wallet_bytes
//!                   ‖ epoch_days_le8
//!                   ‖ commitment_be32
//!                   ‖ public_digest_be32
//!                   ‖ proof_digest_be32
//!                   [‖ binding_digest_be32]     v3 only, when the leaf
//!                                               carries a binding block
//!                 )
//! ```
//!
//! The binding digest is appended only when present. A v2 leaf hashes over
//! exactly the bytes it always did, so bundles issued before v3 keep their
//! leaf hashes, their `kycHash`, and their manifest signature. Whether a
//! given leaf has a binding block is read from the manifest, so there is no
//! ambiguity about which preimage a verifier should reconstruct.

use trusset_circuits_common::{
    digest_to_bytes, hash_bytes_with_tag, write_canonical_bytes, write_canonical_u64, CircuitId,
    Digest, LEAF_TAG, PROOF_DIGEST_TAG,
};

/// Compute the `proof_digest` from raw proof bytes.
pub fn compute_proof_digest(proof_bytes: &[u8]) -> Digest {
    hash_bytes_with_tag(&PROOF_DIGEST_TAG, proof_bytes)
}

/// Compute the per-leaf hash sealed into the Merkle tree (v2 preimage).
pub fn compute_leaf_hash(
    field_name: &str,
    circuit_id: CircuitId,
    wallet_bytes: &[u8],
    epoch_days: u64,
    commitment: &Digest,
    public_digest: &Digest,
    proof_digest: &Digest,
) -> Digest {
    compute_leaf_hash_bound(
        field_name,
        circuit_id,
        wallet_bytes,
        epoch_days,
        commitment,
        public_digest,
        proof_digest,
        None,
    )
}

/// Compute the per-leaf hash, optionally binding the v3 claim-descriptor /
/// validity / list-version block. `binding = None` reproduces the v2 preimage
/// byte for byte.
#[allow(clippy::too_many_arguments)]
pub fn compute_leaf_hash_bound(
    field_name: &str,
    circuit_id: CircuitId,
    wallet_bytes: &[u8],
    epoch_days: u64,
    commitment: &Digest,
    public_digest: &Digest,
    proof_digest: &Digest,
    binding: Option<&Digest>,
) -> Digest {
    let extra = if binding.is_some() { 32 } else { 0 };
    let mut body = Vec::with_capacity(
        4 + field_name.len() + 1 + 4 + wallet_bytes.len() + 8 + 32 + 32 + 32 + extra,
    );
    write_canonical_bytes(&mut body, field_name.as_bytes());
    body.push(circuit_id.as_u8());
    write_canonical_bytes(&mut body, wallet_bytes);
    write_canonical_u64(&mut body, epoch_days);
    body.extend_from_slice(&digest_to_bytes(commitment));
    body.extend_from_slice(&digest_to_bytes(public_digest));
    body.extend_from_slice(&digest_to_bytes(proof_digest));
    if let Some(b) = binding {
        body.extend_from_slice(&digest_to_bytes(b));
    }
    hash_bytes_with_tag(&LEAF_TAG, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusset_circuits_common::hash_bytes_with_tag as h;

    fn d(seed: u8) -> Digest {
        h(&LEAF_TAG, &[seed])
    }

    #[test]
    fn proof_digest_is_deterministic() {
        let a = compute_proof_digest(b"hello");
        let b = compute_proof_digest(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn proof_digest_differs_per_bytes() {
        assert_ne!(compute_proof_digest(b"a"), compute_proof_digest(b"b"));
    }

    #[test]
    fn leaf_hash_changes_with_each_input_component() {
        let base = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );

        // Field name.
        let v1 = compute_leaf_hash(
            "lastName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        assert_ne!(base, v1);

        // Circuit id.
        let v2 = compute_leaf_hash(
            "firstName",
            CircuitId::TierThreshold,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        assert_ne!(base, v2);

        // Wallet.
        let v3 = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[9, 9, 9],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        assert_ne!(base, v3);

        // Epoch days.
        let v4 = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20588,
            &d(1),
            &d(2),
            &d(3),
        );
        assert_ne!(base, v4);

        // Commitment.
        let v5 = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(99),
            &d(2),
            &d(3),
        );
        assert_ne!(base, v5);

        // Public digest.
        let v6 = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(99),
            &d(3),
        );
        assert_ne!(base, v6);

        // Proof digest.
        let v7 = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(99),
        );
        assert_ne!(base, v7);
    }

    #[test]
    fn binding_changes_the_leaf_hash_and_absence_reproduces_v2() {
        let unbound = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        let explicit_none = compute_leaf_hash_bound(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
            None,
        );
        assert_eq!(
            unbound, explicit_none,
            "a leaf with no binding must hash exactly as it did under v2"
        );

        let bound = compute_leaf_hash_bound(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
            Some(&d(7)),
        );
        assert_ne!(unbound, bound);

        let other = compute_leaf_hash_bound(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
            Some(&d(8)),
        );
        assert_ne!(bound, other, "the binding digest must be load-bearing");
    }

    #[test]
    fn leaf_hash_is_deterministic() {
        let a = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        let b = compute_leaf_hash(
            "firstName",
            CircuitId::PreimageKnowledge,
            &[1, 2, 3],
            20587,
            &d(1),
            &d(2),
            &d(3),
        );
        assert_eq!(a, b);
    }
}
