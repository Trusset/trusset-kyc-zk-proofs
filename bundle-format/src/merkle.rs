//! Rescue Merkle root over lex-sorted leaf hashes (spec §8).
//!
//! Two constructions live here:
//!
//! `compute_root` is the v1 convention (`manifest.merkleVersion` absent or
//! 1), kept for verifying existing bundles:
//!   1. Sort leaves by their byte representation (lexicographic).
//!   2. Pair adjacent leaves; the smaller goes left.
//!   3. Duplicate the final node on odd layers.
//!   4. Combine with `hash_two` under `NODE_TAG`.
//!
//! `compute_root_v2` (`manifest.merkleVersion: 2`, the v2.1.0 default)
//! removes the structural ambiguities of v1 - odd-layer duplication, the
//! single-leaf root equaling the leaf itself, and a root that commits to
//! neither leaf count nor arity:
//!   1. Sort leaves by their byte representation (lexicographic).
//!   2. Pad the sorted layer to `next_power_of_two().max(2)` with
//!      `Rescue(MERKLE_PAD_TAG ‖ leaf_count_le8)` padding leaves.
//!   3. Pair adjacent nodes; the smaller goes left; combine with
//!      `hash_two` under `NODE_TAG`. No layer is ever odd.
//!   4. Wrap: `root = Rescue(MERKLE_ROOT_TAG ‖ inner_root ‖
//!      leaf_count_le8 ‖ arity_u8)` with arity fixed at 2.

use trusset_circuits_common::{
    digest_to_bytes, hash_bytes_with_tag, hash_two, Digest, MERKLE_PAD_TAG, MERKLE_ROOT_TAG,
};

pub const MERKLE_VERSION_V1: u32 = 1;
pub const MERKLE_VERSION_V2: u32 = 2;
pub const MERKLE_ARITY: u8 = 2;

/// Sort leaves in-place (by big-endian byte representation) and compute the
/// Rescue Merkle root. Returns `(root, sorted_indices)` where
/// `sorted_indices[i]` is the original index of the leaf now at position `i`.
/// The caller uses `sorted_indices` to reorder the manifest's `leaves[]` to
/// match the tree's leaf order.
pub fn compute_root(leaves: &[Digest]) -> (Digest, Vec<usize>) {
    assert!(
        !leaves.is_empty(),
        "cannot build Merkle root from empty leaves"
    );

    // Sort by byte representation. Stable for equal hashes (shouldn't happen
    // in practice — two equal leaves means two identical leaf hashes).
    let mut indexed: Vec<(usize, Digest, [u8; 32])> = leaves
        .iter()
        .enumerate()
        .map(|(i, d)| (i, *d, digest_to_bytes(d)))
        .collect();
    indexed.sort_by(|a, b| a.2.cmp(&b.2));

    let sorted_indices: Vec<usize> = indexed.iter().map(|t| t.0).collect();
    let mut layer: Vec<Digest> = indexed.into_iter().map(|t| t.1).collect();

    if layer.len() == 1 {
        return (layer[0], sorted_indices);
    }

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for i in (0..layer.len()).step_by(2) {
            let left = layer[i];
            let right = if i + 1 < layer.len() {
                layer[i + 1]
            } else {
                left // duplicate last on odd layer
            };
            // Within a pair, the smaller hash goes first. This preserves the v1
            // sort-pair invariant — verifiers can re-pair without tracking
            // which side was originally left.
            let (a, b) = if digest_to_bytes(&left) <= digest_to_bytes(&right) {
                (left, right)
            } else {
                (right, left)
            };
            next.push(hash_two(&a, &b));
        }
        layer = next;
    }

    (layer[0], sorted_indices)
}

/// The v2 padding leaf for a tree of `leaf_count` real leaves.
pub fn padding_leaf(leaf_count: u64) -> Digest {
    hash_bytes_with_tag(&MERKLE_PAD_TAG, &leaf_count.to_le_bytes())
}

/// Sort leaves (by big-endian byte representation), pad to a power of two,
/// and compute the v2 Rescue Merkle root with the leaf count and arity
/// bound into the final wrap. Returns `(root, sorted_indices)` with the
/// same `sorted_indices` contract as `compute_root`.
pub fn compute_root_v2(leaves: &[Digest]) -> (Digest, Vec<usize>) {
    assert!(
        !leaves.is_empty(),
        "cannot build Merkle root from empty leaves"
    );

    let leaf_count = leaves.len() as u64;
    let mut indexed: Vec<(usize, Digest, [u8; 32])> = leaves
        .iter()
        .enumerate()
        .map(|(i, d)| (i, *d, digest_to_bytes(d)))
        .collect();
    indexed.sort_by(|a, b| a.2.cmp(&b.2));

    let sorted_indices: Vec<usize> = indexed.iter().map(|t| t.0).collect();
    let mut layer: Vec<Digest> = indexed.into_iter().map(|t| t.1).collect();

    let target = leaves.len().next_power_of_two().max(2);
    let pad = padding_leaf(leaf_count);
    layer.resize(target, pad);

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for i in (0..layer.len()).step_by(2) {
            let left = layer[i];
            let right = layer[i + 1];
            let (a, b) = if digest_to_bytes(&left) <= digest_to_bytes(&right) {
                (left, right)
            } else {
                (right, left)
            };
            next.push(hash_two(&a, &b));
        }
        layer = next;
    }

    let mut wrap = Vec::with_capacity(32 + 8 + 1);
    wrap.extend_from_slice(&digest_to_bytes(&layer[0]));
    wrap.extend_from_slice(&leaf_count.to_le_bytes());
    wrap.push(MERKLE_ARITY);
    (hash_bytes_with_tag(&MERKLE_ROOT_TAG, &wrap), sorted_indices)
}

/// Dispatch on the manifest's `merkleVersion` (absent = 1).
pub fn compute_root_versioned(leaves: &[Digest], version: u32) -> Option<(Digest, Vec<usize>)> {
    match version {
        MERKLE_VERSION_V1 => Some(compute_root(leaves)),
        MERKLE_VERSION_V2 => Some(compute_root_v2(leaves)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusset_circuits_common::{hash_bytes_with_tag, LEAF_TAG};

    fn leaf(seed: u8) -> Digest {
        hash_bytes_with_tag(&LEAF_TAG, &[seed])
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        let l = leaf(1);
        let (root, idx) = compute_root(&[l]);
        assert_eq!(root, l);
        assert_eq!(idx, vec![0]);
    }

    #[test]
    fn two_leaves_combine_smaller_first() {
        let a = leaf(1);
        let b = leaf(2);
        let (r1, _) = compute_root(&[a, b]);
        let (r2, _) = compute_root(&[b, a]);
        // Sort-stable: input order doesn't matter, only leaf values do.
        assert_eq!(r1, r2);
    }

    #[test]
    fn sorted_indices_recover_original_positions() {
        let leaves: Vec<Digest> = (0u8..7).map(leaf).collect();
        let (_, idx) = compute_root(&leaves);
        assert_eq!(idx.len(), leaves.len());
        // Every original index appears exactly once.
        let mut seen = idx.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..leaves.len()).collect::<Vec<_>>());
        // Leaves are sorted by digest bytes.
        let sorted_bytes: Vec<[u8; 32]> =
            idx.iter().map(|i| digest_to_bytes(&leaves[*i])).collect();
        let mut expected = sorted_bytes.clone();
        expected.sort();
        assert_eq!(sorted_bytes, expected);
    }

    #[test]
    fn odd_layer_duplicates_last_node() {
        // 3 leaves: a layer of 3 → next layer is [hash(a,b), hash(c,c)] (= 2 nodes)
        // → root = hash(min, max) of those.
        let leaves: Vec<Digest> = (0u8..3).map(leaf).collect();
        let (root, _) = compute_root(&leaves);
        // Just check it's reproducible.
        let (root2, _) = compute_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn root_is_deterministic_across_runs() {
        let leaves: Vec<Digest> = (0u8..10).map(leaf).collect();
        let (a, _) = compute_root(&leaves);
        let (b, _) = compute_root(&leaves);
        assert_eq!(a, b);
    }

    #[test]
    fn changing_a_leaf_changes_the_root() {
        let mut leaves: Vec<Digest> = (0u8..4).map(leaf).collect();
        let (r1, _) = compute_root(&leaves);
        leaves[2] = leaf(99);
        let (r2, _) = compute_root(&leaves);
        assert_ne!(r1, r2);
    }

    #[test]
    fn v2_single_leaf_root_differs_from_the_leaf() {
        let l = leaf(1);
        let (root, idx) = compute_root_v2(&[l]);
        assert_ne!(root, l);
        assert_eq!(idx, vec![0]);
    }

    #[test]
    fn v2_root_is_input_order_independent_and_deterministic() {
        let a = leaf(1);
        let b = leaf(2);
        let c = leaf(3);
        let (r1, _) = compute_root_v2(&[a, b, c]);
        let (r2, _) = compute_root_v2(&[c, a, b]);
        assert_eq!(r1, r2);
        let (r3, _) = compute_root_v2(&[a, b, c]);
        assert_eq!(r1, r3);
    }

    #[test]
    fn v2_covers_all_required_leaf_counts() {
        let mut seen = Vec::new();
        for n in [1usize, 2, 3, 5, 7, 8, 9] {
            let leaves: Vec<Digest> = (0..n as u8).map(leaf).collect();
            let (root, idx) = compute_root_v2(&leaves);
            assert_eq!(idx.len(), n);
            let mut sorted = idx.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..n).collect::<Vec<_>>());
            seen.push(root);
        }
        for i in 0..seen.len() {
            for j in (i + 1)..seen.len() {
                assert_ne!(seen[i], seen[j], "roots for different leaf counts collide");
            }
        }
    }

    #[test]
    fn v2_leaf_count_is_bound_into_the_root() {
        // Under v1, [a, b, c] and [a, b, c, c] can produce the same root
        // (odd-layer duplication). Under v2 the explicit duplicate is a
        // fourth real leaf and the count binding separates the roots.
        let leaves3: Vec<Digest> = (0u8..3).map(leaf).collect();
        let mut leaves4 = leaves3.clone();
        leaves4.push(leaves3[2]);
        let (r3, _) = compute_root_v2(&leaves3);
        let (r4, _) = compute_root_v2(&leaves4);
        assert_ne!(r3, r4);
    }

    #[test]
    fn v1_duplicate_last_leaf_ambiguity_exists_and_v2_removes_it() {
        // v1 promotes the last node of an odd layer by hashing it with
        // itself, so a leaf set plus a second copy of its lexicographically
        // largest leaf collapses to the identical root. The duplicate must
        // be the largest leaf: that is the one v1 promotes.
        let leaves3: Vec<Digest> = (0u8..3).map(leaf).collect();
        let largest = *leaves3
            .iter()
            .max_by_key(|d| digest_to_bytes(d))
            .expect("non-empty");
        let mut leaves4 = leaves3.clone();
        leaves4.push(largest);

        let (v1_r3, _) = compute_root(&leaves3);
        let (v1_r4, _) = compute_root(&leaves4);
        assert_eq!(
            v1_r3, v1_r4,
            "the documented v1 duplication ambiguity should reproduce"
        );

        let (v2_r3, _) = compute_root_v2(&leaves3);
        let (v2_r4, _) = compute_root_v2(&leaves4);
        assert_ne!(
            v2_r3, v2_r4,
            "v2 must distinguish 3 leaves from 4 leaves with a repeat"
        );
    }

    #[test]
    fn v2_padding_leaf_is_never_a_real_leaf() {
        for n in 1u64..=16 {
            let pad = padding_leaf(n);
            for seed in 0u8..32 {
                assert_ne!(pad, leaf(seed));
            }
        }
        assert_ne!(padding_leaf(3), padding_leaf(5));
    }

    #[test]
    fn v2_padded_tree_differs_from_tree_with_pad_as_real_leaf() {
        // Three real leaves pad to four with pad(3). A tree whose fourth
        // REAL leaf equals pad(4) binds count 4 and yields a different
        // root, so a padding node can never be claimed as a member.
        let leaves3: Vec<Digest> = (0u8..3).map(leaf).collect();
        let mut forged = leaves3.clone();
        forged.push(padding_leaf(3));
        let (r_padded, _) = compute_root_v2(&leaves3);
        let (r_forged, _) = compute_root_v2(&forged);
        assert_ne!(r_padded, r_forged);
    }

    #[test]
    fn v2_differs_from_v1_for_every_shape() {
        for n in [1usize, 2, 3, 5, 7, 8, 9] {
            let leaves: Vec<Digest> = (0..n as u8).map(leaf).collect();
            let (v1, _) = compute_root(&leaves);
            let (v2, _) = compute_root_v2(&leaves);
            assert_ne!(v1, v2, "v1 and v2 roots collide at {} leaves", n);
        }
    }

    #[test]
    fn versioned_dispatch_selects_the_right_construction() {
        let leaves: Vec<Digest> = (0u8..5).map(leaf).collect();
        let (v1, _) = compute_root(&leaves);
        let (v2, _) = compute_root_v2(&leaves);
        assert_eq!(compute_root_versioned(&leaves, 1).unwrap().0, v1);
        assert_eq!(compute_root_versioned(&leaves, 2).unwrap().0, v2);
        assert!(compute_root_versioned(&leaves, 3).is_none());
    }
}
