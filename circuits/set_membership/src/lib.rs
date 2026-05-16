//! `set_membership` circuit (spec §6.2).
//!
//! Statement: "I know `(value, nonce, merkle_path)` such that
//! `Rescue(COMMITMENT_TAG ‖ len ‖ value ‖ nonce) == commitment`
//!  and walking the Merkle path from `value` with the provided siblings
//!  yields `set_root`."
//!
//! The set tree uses `SET_LEAF_TAG` for leaves and `SET_NODE_TAG` for inner
//! nodes — distinct from the main per-subject leaf tree's `LEAF_TAG` /
//! `NODE_TAG` so a set leaf can never be mistaken for a subject leaf
//! (spec §12.1 domain separation).
//!
//! Set leaves are computed as `Rescue(SET_LEAF_TAG ‖ value_canonical)`,
//! where `value_canonical = bytes_to_field(NFC(value))` for string values.
//! This matches what `trusset-list-commit` (Phase 4) will emit when ingesting
//! a plain text list like ISO-3166 alpha-3.
//!
//! # Status: Phase 2A — see `preimage_knowledge` for stub-mode caveat.

use sha2::{Digest as _, Sha256};
use trusset_circuits_common::{
    bytes_to_field, compute_commitment, digest_to_bytes, hash_bytes_with_tag, hash_elements,
    hash_two_with_tag, string_to_field_canonical, CircuitId, Digest, StubProof, StubProofError,
    DIGEST_LEN_BYTES, NONCE_LEN, PUBLIC_DIGEST_TAG, SET_LEAF_TAG, SET_NODE_TAG,
};
use zeroize::Zeroize;

pub const CIRCUIT_ID: CircuitId = CircuitId::SetMembership;
pub const MAX_SET_DEPTH: u8 = 32;

/// Side of a sibling node in a Merkle path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

impl Side {
    pub fn as_u8(self) -> u8 {
        match self {
            Side::Left => 0,
            Side::Right => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathStep {
    pub sibling: Digest,
    /// Position of the *current* node relative to its parent. `Left` means
    /// the current node is the left child and the sibling is the right.
    pub side: Side,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Identifier of the list this predicate references (e.g.
    /// `"country_allowlist"`). Bound into params_hash so swapping lists
    /// invalidates determinism caches.
    pub list_id: String,
}

impl Params {
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"trusset-kyc-v2:set_membership:params");
        // Length-prefix the list_id so different lists with prefix
        // relationships ("country" vs "country_allow") never collide.
        h.update((self.list_id.len() as u64).to_le_bytes());
        h.update(self.list_id.as_bytes());
        h.finalize().into()
    }
}

pub struct Witness {
    pub value: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
    pub merkle_path: Vec<PathStep>,
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.value.zeroize();
        self.nonce.zeroize();
        // PathStep is public anyway (sibling digests are derivable from the
        // public root), but zeroing is cheap and avoids accidental copies.
        for step in self.merkle_path.iter_mut() {
            for f in step.sibling.iter_mut() {
                *f = trusset_circuits_common::Felt::new(0);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub commitment: Digest,
    pub set_root: Digest,
    pub set_depth: u8,
}

impl PublicInputs {
    /// Canonical encoding: `commitment(32) ‖ set_root(32) ‖ set_depth(1)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * DIGEST_LEN_BYTES + 1);
        out.extend_from_slice(&digest_to_bytes(&self.commitment));
        out.extend_from_slice(&digest_to_bytes(&self.set_root));
        out.push(self.set_depth);
        out
    }

    pub fn digest(&self) -> Digest {
        hash_bytes_with_tag(&PUBLIC_DIGEST_TAG, &self.canonical_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidateError {
    EmptyValue,
    PathDepthMismatch { expected: u8, got: usize },
    PathTooDeep { depth: usize, max: u8 },
    CommitmentMismatch,
    /// Walking the Merkle path from the witnessed value did not reach the
    /// public `set_root`. Maps to error code `E_LIST_MEMBER_MISSING`.
    NotInSet,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// Compute the set-tree leaf digest for a (UTF-8, pre-NFC) value.
/// `trusset-list-commit` uses the same routine when committing a list.
pub fn set_leaf_digest(value_bytes: &[u8]) -> Digest {
    // Canonicalize to felts (NFC + 7-byte chunks) so a list committed from
    // text aligns with witnesses derived from JSON / CSV inputs that share
    // the same NFC canonical form (plan edge case 7).
    let value_str = core::str::from_utf8(value_bytes).unwrap_or_default();
    let felts = if value_bytes.is_ascii() && !value_str.is_empty() {
        // Fast path: ASCII bypass for the common case (ISO country codes).
        bytes_to_field(value_bytes)
    } else if !value_str.is_empty() {
        string_to_field_canonical(value_str)
    } else {
        // Non-UTF-8 values are still hashed as raw bytes — list-commit
        // tooling produces UTF-8 by construction, but defensive.
        bytes_to_field(value_bytes)
    };
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let mut combined = tag_felts;
    combined.extend_from_slice(&felts);
    hash_elements(&combined)
}

/// Walk a Merkle path from a leaf digest up to a root using `SET_NODE_TAG`
/// merging. Returns the computed root.
pub fn walk_merkle_path(leaf: Digest, path: &[PathStep]) -> Digest {
    let mut node = leaf;
    for step in path {
        node = match step.side {
            Side::Left => hash_two_with_tag(&SET_NODE_TAG, &node, &step.sibling),
            Side::Right => hash_two_with_tag(&SET_NODE_TAG, &step.sibling, &node),
        };
    }
    node
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(&witness.value, &witness.nonce)
}

pub fn validate(
    witness: &Witness,
    public: &PublicInputs,
    _params: &Params,
) -> Result<(), ValidateError> {
    if witness.value.is_empty() {
        return Err(ValidateError::EmptyValue);
    }
    if witness.merkle_path.len() != public.set_depth as usize {
        return Err(ValidateError::PathDepthMismatch {
            expected: public.set_depth,
            got: witness.merkle_path.len(),
        });
    }
    if public.set_depth > MAX_SET_DEPTH {
        return Err(ValidateError::PathTooDeep {
            depth: public.set_depth as usize,
            max: MAX_SET_DEPTH,
        });
    }
    let recomputed = compute_commitment(&witness.value, &witness.nonce);
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    let leaf = set_leaf_digest(&witness.value);
    let root = walk_merkle_path(leaf, &witness.merkle_path);
    if root != public.set_root {
        return Err(ValidateError::NotInSet);
    }
    Ok(())
}

/// # Phase 2B TODO
/// Real Winterfell AIR must enforce:
///   1. Rescue commitment opens correctly over `(value_padded, nonce)`.
///   2. Each Merkle step computes `parent = Rescue(SET_NODE_TAG ‖ a ‖ b)` with
///      `(a, b) = side ? (sibling, node) : (node, sibling)`.
///   3. After `set_depth` steps, the resulting node equals `set_root`.
///   4. The first leaf hash equals `Rescue(SET_LEAF_TAG ‖ value_felts)`.
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
    Ok(proof.to_bytes().to_vec())
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    let parsed = StubProof::from_bytes(proof_bytes)?;
    parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
    Ok(())
}

/// Build a complete binary Merkle tree from a list of value byte-strings and
/// return `(root, depth, leaves[])`. Used by tests and by
/// `trusset-list-commit` (Phase 4) for ingesting plain lists.
///
/// Trees are padded to the next power of two by duplicating the last leaf —
/// matches the v1 sorted Merkle convention (plan §"Output bundle").
pub fn build_set_tree(values: &[&[u8]]) -> (Digest, u8, Vec<Digest>) {
    assert!(!values.is_empty(), "cannot build a set tree from zero values");
    let mut leaves: Vec<Digest> = values.iter().map(|v| set_leaf_digest(v)).collect();
    // Round to power of two by duplicating last.
    let target = leaves.len().next_power_of_two().max(2);
    while leaves.len() < target {
        leaves.push(*leaves.last().unwrap());
    }
    let depth = (target as f64).log2() as u8;
    let mut layer = leaves.clone();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            next.push(hash_two_with_tag(&SET_NODE_TAG, &chunk[0], &chunk[1]));
        }
        layer = next;
    }
    (layer[0], depth, leaves)
}

/// Produce the Merkle inclusion path for `index` against a leaves vector
/// returned by `build_set_tree`.
pub fn inclusion_path(leaves: &[Digest], index: usize) -> Vec<PathStep> {
    let mut path = Vec::new();
    let mut idx = index;
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        let pair = idx ^ 1;
        let sibling = layer[pair];
        let side = if idx & 1 == 0 { Side::Left } else { Side::Right };
        path.push(PathStep { sibling, side });
        let mut next = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            next.push(hash_two_with_tag(&SET_NODE_TAG, &chunk[0], &chunk[1]));
        }
        layer = next;
        idx /= 2;
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_list() -> Vec<&'static [u8]> {
        // 4 entries → depth 2.
        vec![&b"DEU"[..], &b"FRA"[..], &b"USA"[..], &b"GBR"[..]]
    }

    fn witness_for(values: &[&[u8]], pick: usize) -> (Witness, PublicInputs, Params) {
        let (root, depth, leaves) = build_set_tree(values);
        let path = inclusion_path(&leaves, pick);
        let nonce = [0x44; NONCE_LEN];
        let value = values[pick].to_vec();
        let commitment = compute_commitment(&value, &nonce);
        let witness = Witness {
            value,
            nonce,
            merkle_path: path,
        };
        let public = PublicInputs {
            commitment,
            set_root: root,
            set_depth: depth,
        };
        let params = Params {
            list_id: "country_allowlist".to_string(),
        };
        (witness, public, params)
    }

    #[test]
    fn build_tree_correct_depth_for_four_leaves() {
        let (_, depth, _) = build_set_tree(&fixture_list());
        assert_eq!(depth, 2);
    }

    #[test]
    fn build_tree_pads_to_power_of_two() {
        // 3 leaves → padded to 4, depth = 2.
        let (_, depth, leaves) = build_set_tree(&[b"A", b"B", b"C"]);
        assert_eq!(leaves.len(), 4);
        assert_eq!(depth, 2);
        // Padding duplicates the last leaf.
        assert_eq!(leaves[2], leaves[3]);
    }

    #[test]
    fn walk_path_recovers_root() {
        let (root, _, leaves) = build_set_tree(&fixture_list());
        for (i, _) in fixture_list().iter().enumerate() {
            let path = inclusion_path(&leaves, i);
            let computed = walk_merkle_path(leaves[i], &path);
            assert_eq!(computed, root, "leaf {} did not walk to root", i);
        }
    }

    #[test]
    fn validate_accepts_member_witness() {
        let list = fixture_list();
        let (w, p, params) = witness_for(&list, 2); // "USA"
        assert!(validate(&w, &p, &params).is_ok());
    }

    #[test]
    fn validate_rejects_empty_value() {
        let list = fixture_list();
        let (root, depth, leaves) = build_set_tree(&list);
        let path = inclusion_path(&leaves, 0);
        let w = Witness {
            value: vec![],
            nonce: [0; NONCE_LEN],
            merkle_path: path,
        };
        let p = PublicInputs {
            commitment: w.value.clone().into_iter().fold(commit(&w), |c, _| c),
            set_root: root,
            set_depth: depth,
        };
        assert_eq!(
            validate(
                &w,
                &p,
                &Params {
                    list_id: "x".into(),
                }
            ),
            Err(ValidateError::EmptyValue)
        );
    }

    #[test]
    fn validate_rejects_path_depth_mismatch() {
        let list = fixture_list();
        let (mut w, p, params) = witness_for(&list, 0);
        // Drop one step from the path → length mismatch.
        w.merkle_path.pop();
        assert_eq!(
            validate(&w, &p, &params),
            Err(ValidateError::PathDepthMismatch {
                expected: 2,
                got: 1,
            })
        );
    }

    #[test]
    fn validate_rejects_non_member() {
        let list = fixture_list();
        let (mut w, p, params) = witness_for(&list, 0); // "DEU"
        // Lie about the value while keeping the same path → root won't match.
        w.value = b"XYZ".to_vec();
        w.nonce = [0x55; NONCE_LEN];
        let bad_commitment = compute_commitment(&w.value, &w.nonce);
        let p_bad = PublicInputs {
            commitment: bad_commitment,
            ..p
        };
        assert_eq!(validate(&w, &p_bad, &params), Err(ValidateError::NotInSet));
    }

    #[test]
    fn validate_rejects_commitment_mismatch() {
        let list = fixture_list();
        let (w, mut p, params) = witness_for(&list, 1);
        p.commitment[0] = trusset_circuits_common::Felt::new(99);
        assert_eq!(validate(&w, &p, &params), Err(ValidateError::CommitmentMismatch));
    }

    #[test]
    fn validate_rejects_tampered_sibling() {
        let list = fixture_list();
        let (mut w, p, params) = witness_for(&list, 0);
        w.merkle_path[0].sibling[0] = trusset_circuits_common::Felt::new(1234);
        assert_eq!(validate(&w, &p, &params), Err(ValidateError::NotInSet));
    }

    #[test]
    fn prove_verify_roundtrip() {
        let list = fixture_list();
        let (w, p, params) = witness_for(&list, 1);
        let bytes = prove(&w, &p, &params).unwrap();
        assert!(verify(&bytes, &p).is_ok());
    }

    #[test]
    fn verify_rejects_proof_for_different_set_root() {
        let list = fixture_list();
        let (w, p, params) = witness_for(&list, 0);
        let bytes = prove(&w, &p, &params).unwrap();
        let mut p2 = p.clone();
        p2.set_root[0] = trusset_circuits_common::Felt::new(7);
        assert!(verify(&bytes, &p2).is_err());
    }

    #[test]
    fn set_leaf_digest_is_distinct_from_subject_leaf_tag() {
        // Sanity: same value bytes hashed under SET_LEAF_TAG vs LEAF_TAG
        // must produce different digests.
        let v = b"DEU";
        let set_leaf = set_leaf_digest(v);
        let mut subject_leaf_bytes = Vec::new();
        subject_leaf_bytes.extend_from_slice(v);
        let subject_leaf = trusset_circuits_common::hash_bytes_with_tag(
            &trusset_circuits_common::LEAF_TAG,
            v,
        );
        assert_ne!(set_leaf, subject_leaf);
    }

    #[test]
    fn params_hash_changes_with_list_id() {
        assert_ne!(
            Params {
                list_id: "country_allowlist".into(),
            }
            .hash(),
            Params {
                list_id: "document_types".into(),
            }
            .hash()
        );
    }

    #[test]
    fn prove_is_deterministic() {
        let list = fixture_list();
        let (w, p, params) = witness_for(&list, 1);
        let a = prove(&w, &p, &params).unwrap();
        let b = prove(&w, &p, &params).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn larger_tree_depth_eight() {
        // 256 leaves → depth 8 (matches realistic ISO-3166 alpha-3 list size).
        let raw: Vec<Vec<u8>> = (0..256)
            .map(|i| format!("L{:03}", i).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let (root, depth, leaves) = build_set_tree(&refs);
        assert_eq!(depth, 8);
        // Spot-check inclusion for the first, middle, and last entry.
        for &idx in &[0usize, 128, 255] {
            let path = inclusion_path(&leaves, idx);
            assert_eq!(walk_merkle_path(leaves[idx], &path), root);
        }
    }
}
