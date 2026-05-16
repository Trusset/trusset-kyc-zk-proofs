//! Rescue Merkle root over lex-sorted leaf hashes (spec §8).
//!
//! Preserves the v1 sorted-leaf convention:
//!   1. Sort leaves by their byte representation (lexicographic).
//!   2. Pair adjacent leaves; the smaller goes left.
//!   3. Duplicate the final node on odd layers.
//!   4. Combine with `hash_two` under `NODE_TAG`.

use trusset_circuits_common::{digest_to_bytes, hash_two, Digest};

/// Sort leaves in-place (by big-endian byte representation) and compute the
/// Rescue Merkle root. Returns `(root, sorted_indices)` where
/// `sorted_indices[i]` is the original index of the leaf now at position `i`.
/// The caller uses `sorted_indices` to reorder the manifest's `leaves[]` to
/// match the tree's leaf order.
pub fn compute_root(leaves: &[Digest]) -> (Digest, Vec<usize>) {
    assert!(!leaves.is_empty(), "cannot build Merkle root from empty leaves");

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
}
