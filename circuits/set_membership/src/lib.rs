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
//! # Status
//!
//! - **Stub path** (`--features stub-proofs`, Phase 2A default).
//! - **Prod-proofs path** (`--features prod-proofs-set`, Phase 2B):
//!   real Winterfell roundtrip via `air`, `prover`, `verifier`. PLACEHOLDER
//!   constraints — does not enforce Merkle opening yet.

#[cfg(feature = "prod-proofs-set")]
pub mod air;
#[cfg(feature = "prod-proofs-set")]
pub mod air_v2;
#[cfg(feature = "prod-proofs-set")]
pub mod prover;
#[cfg(feature = "prod-proofs-set")]
pub mod verifier;

use sha2::{Digest as _, Sha256};
#[cfg(not(feature = "prod-proofs-set"))]
use trusset_circuits_common::StubProof;
use trusset_circuits_common::{
    bytes_to_field, compute_commitment, digest_to_bytes, hash_bytes_with_tag, hash_elements,
    hash_two_with_tag, nfc_canonicalize, CircuitId, Digest, StubProofError, DIGEST_LEN_BYTES,
    NONCE_LEN, PUBLIC_DIGEST_TAG, SET_LEAF_TAG, SET_NODE_TAG,
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
    PathDepthMismatch {
        expected: u8,
        got: usize,
    },
    PathTooDeep {
        depth: usize,
        max: u8,
    },
    CommitmentMismatch,
    /// Walking the Merkle path from the witnessed value did not reach the
    /// public `set_root`. Maps to error code `E_LIST_MEMBER_MISSING`.
    NotInSet,
    /// Winterfell prover failed (prod-proofs-set path only).
    WinterfellProverError(String),
}

#[derive(Debug)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
    #[cfg(feature = "prod-proofs-set")]
    WinterfellVerifyError(verifier::AirVerifyError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// NFC-canonicalize a value for the set-leaf hash. ASCII bypasses the
/// unicode-normalization library cost; non-UTF-8 bytes pass through
/// unchanged (defensive — list-commit tooling produces UTF-8 by
/// construction).
fn canonicalize_set_value(value_bytes: &[u8]) -> Vec<u8> {
    if value_bytes.is_ascii() {
        value_bytes.to_vec()
    } else if let Ok(s) = core::str::from_utf8(value_bytes) {
        nfc_canonicalize(s).into_bytes()
    } else {
        value_bytes.to_vec()
    }
}

/// Compute the set-tree leaf digest for a (UTF-8, pre-NFC) value.
/// `trusset-list-commit` uses the same routine when committing a list.
///
/// Stage 16 layout: input is `SET_LEAF_TAG (5 felts) ‖
/// witness_to_felts(NFC(value)) (12 felts) = 17 felts`. Hashed via
/// Rescue (3 absorption blocks). The `witness_to_felts` helper handles
/// the `0x01` distinguishing suffix and zero-padding to a fixed
/// `MAX_PADDED_WITNESS_FELTS = 12` count, which keeps the in-AIR trace
/// shape fixed.
///
/// **Operator action on Stage 16 upgrade**: the `set_leaf_digest` value
/// for every set entry changes vs Stage 15 (which hashed unpadded
/// `bytes_to_field(value ‖ 0x01)`). Re-run `trusset-list-commit` for
/// every list after upgrade; `CIRCUITS_VERSION` stays at 2 (the JSON
/// wire format doesn't shift — only the internal set_leaf hash value).
pub fn set_leaf_digest(value_bytes: &[u8]) -> Digest {
    let canonical = canonicalize_set_value(value_bytes);
    let felts = witness_to_felts(&canonical);
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

/// Maximum number of felts returned by `witness_to_felts`, regardless of
/// the actual value length. Sized so the **total Rescue input** is
/// exactly 24 felts (= 3 absorption blocks × 8 rate width):
/// `tag(5) + circuit_id(1) + length_felt(1) + padded_witness(12) + nonce(5) = 24`.
///
/// 12 felts accommodates any value up to `83 bytes` (= `12 × 7 − 1` for
/// the `0x01` suffix), well above the workspace-pinned
/// `MAX_SET_VALUE_BYTES_PADDED = 64` cap.
///
/// Why fixed? Same rationale as preimage_knowledge — Winterfell needs a
/// fixed trace shape. The `0x01` suffix marks end-of-value and
/// zero-padding distinguishes shorter values from longer-with-trailing-
/// zeros variants.
pub const MAX_PADDED_WITNESS_FELTS: usize = 12;

/// Canonical felt-encoding of the witness value for the v2 commitment
/// scheme. Returns AT LEAST `MAX_PADDED_WITNESS_FELTS` felts (exactly
/// that count for any value with `len ≤ MAX_SET_VALUE_BYTES_PADDED = 64`).
///
/// Encoding:
/// 1. Append `0x01` distinguishing suffix to `value`.
/// 2. Chunk into 7-byte little-endian Goldilocks limbs via `bytes_to_field`.
/// 3. Zero-pad the felt vector up to `MAX_PADDED_WITNESS_FELTS`.
///
/// For values larger than the AIR's max, the natural felt count exceeds
/// `MAX_PADDED_WITNESS_FELTS` and no shrinking happens — `commit()`
/// still produces a digest, but `validate()` rejects oversize values
/// before the AIR ever runs. The AIR's trace builder asserts the exact
/// felt count.
///
/// Mirrors `preimage_knowledge::witness_to_felts` exactly in structure.
/// Collision-freeness argument is identical (the `0x01` suffix prevents
/// `bytes_to_field` from collapsing trailing-zero variants within the
/// same 7-byte chunk; zero-padding to a fixed felt count makes the trace
/// shape fixed for the AIR while the suffix carries the distinguishing
/// information).
pub fn witness_to_felts(value: &[u8]) -> Vec<trusset_circuits_common::Felt> {
    let mut padded = Vec::with_capacity(value.len() + 1);
    padded.extend_from_slice(value);
    padded.push(0x01);
    let mut felts = bytes_to_field(&padded);
    while felts.len() < MAX_PADDED_WITNESS_FELTS {
        felts.push(trusset_circuits_common::Felt::new(0));
    }
    felts
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(&witness.value),
        &witness.nonce,
    )
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
    let recomputed = compute_commitment(
        CIRCUIT_ID,
        &witness_to_felts(&witness.value),
        &witness.nonce,
    );
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

pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    #[cfg(feature = "prod-proofs-set")]
    {
        use trusset_circuits_common::stark_options;
        let pi = prover::public_to_air(&public.commitment, &public.set_root, public.set_depth);
        let seed = [0u8; 32];
        let bytes = prover::build_proof(
            &witness.value,
            &witness.nonce,
            &witness.merkle_path,
            &pi,
            stark_options(),
            &seed,
        )
        .map_err(|e| ValidateError::WinterfellProverError(format!("{e:?}")))?;
        Ok(bytes)
    }
    #[cfg(not(feature = "prod-proofs-set"))]
    {
        let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
        Ok(proof.to_bytes().to_vec())
    }
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    #[cfg(feature = "prod-proofs-set")]
    {
        let pi = prover::public_to_air(&public.commitment, &public.set_root, public.set_depth);
        verifier::verify_proof(proof_bytes, pi).map_err(VerifyError::WinterfellVerifyError)
    }
    #[cfg(not(feature = "prod-proofs-set"))]
    {
        let parsed = StubProof::from_bytes(proof_bytes)?;
        parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
        Ok(())
    }
}

/// Verify a proof produced under the frozen circuitsVersion 2 constraint
/// set. Existing bundles verify through this path; new issuance always
/// uses `verify`.
pub fn verify_v2(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    #[cfg(feature = "prod-proofs-set")]
    {
        let pi = prover::public_to_air(&public.commitment, &public.set_root, public.set_depth);
        verifier::verify_proof_v2(proof_bytes, pi).map_err(VerifyError::WinterfellVerifyError)
    }
    #[cfg(not(feature = "prod-proofs-set"))]
    {
        let parsed = StubProof::from_bytes(proof_bytes)?;
        parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
        Ok(())
    }
}

/// Build a complete binary Merkle tree from a list of value byte-strings and
/// return `(root, depth, leaves[])`. Used by tests and by
/// `trusset-list-commit` (Phase 4) for ingesting plain lists.
///
/// Trees are padded to the next power of two by duplicating the last leaf —
/// matches the v1 sorted Merkle convention (plan §"Output bundle").
pub fn build_set_tree(values: &[&[u8]]) -> (Digest, u8, Vec<Digest>) {
    assert!(
        !values.is_empty(),
        "cannot build a set tree from zero values"
    );
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
        let side = if idx & 1 == 0 {
            Side::Left
        } else {
            Side::Right
        };
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
        let commitment = compute_commitment(CIRCUIT_ID, &witness_to_felts(&value), &nonce);
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

    /// Regression: the v2 commitment for set_membership must distinguish
    /// byte values that differ only in trailing-zero bytes within the
    /// same 7-byte chunk. The `0x01` suffix in `witness_to_felts` enforces
    /// this.
    #[test]
    fn commitment_distinguishes_trailing_zero_byte_within_chunk() {
        let nonce = [0x44; NONCE_LEN];
        let c_short = compute_commitment(CIRCUIT_ID, &witness_to_felts(b"DEU"), &nonce);
        let c_with_zero = compute_commitment(CIRCUIT_ID, &witness_to_felts(b"DEU\0"), &nonce);
        assert_ne!(
            c_short, c_with_zero,
            "DEU vs DEU\\0 must commit distinctly under v2 set commitment"
        );
    }

    /// Regression: `set_leaf_digest` must distinguish byte values that
    /// differ only in trailing-zero bytes within the same 7-byte chunk.
    /// Previously `bytes_to_field("DEU")` and `bytes_to_field("DEU\0")`
    /// collapsed to the same `Felt`, producing identical Merkle leaves —
    /// two distinct set values would occupy the same tree position. The
    /// `0x01` suffix inside `set_leaf_digest` (mirroring the
    /// `witness_to_felts` fix) closes this gap.
    #[test]
    fn set_leaf_digest_distinguishes_trailing_zero_byte_within_chunk() {
        let leaf_no_zero = set_leaf_digest(b"DEU");
        let leaf_one_zero = set_leaf_digest(b"DEU\0");
        let leaf_two_zeros = set_leaf_digest(b"DEU\0\0");
        assert_ne!(
            leaf_no_zero, leaf_one_zero,
            "DEU vs DEU\\0 leaves must differ"
        );
        assert_ne!(
            leaf_no_zero, leaf_two_zeros,
            "DEU vs DEU\\0\\0 leaves must differ"
        );
        assert_ne!(
            leaf_one_zero, leaf_two_zeros,
            "DEU\\0 vs DEU\\0\\0 leaves must differ"
        );
    }

    /// Regression: `set_leaf_digest` for the empty value vs a single zero
    /// byte must produce distinct leaves.
    #[test]
    fn set_leaf_digest_distinguishes_empty_from_single_zero() {
        let leaf_empty = set_leaf_digest(b"");
        let leaf_zero = set_leaf_digest(b"\0");
        assert_ne!(
            leaf_empty, leaf_zero,
            "empty value and single zero byte must produce distinct leaves"
        );
    }

    /// `witness_to_felts` must always return at least `MAX_PADDED_WITNESS_FELTS`
    /// felts (exactly that count for any value within the AIR-trace cap) so
    /// the downstream AIR can use a fixed trace shape.
    #[test]
    fn witness_to_felts_padding_returns_fixed_felt_count_for_in_range_values() {
        for len in [
            0usize, 1, 3, // ISO 3166 country codes
            7, 8, 32, // document codes
            63, 64, // MAX_SET_VALUE_BYTES_PADDED
        ] {
            let value: Vec<u8> = (0u8..(len % 256) as u8).collect();
            let value = if value.len() < len {
                let mut v = value;
                v.resize(len, 0xa5);
                v
            } else {
                value
            };
            let felts = witness_to_felts(&value);
            assert_eq!(
                felts.len(),
                MAX_PADDED_WITNESS_FELTS,
                "value.len() = {len} should produce exactly {} felts",
                MAX_PADDED_WITNESS_FELTS
            );
        }
    }

    /// Distinct-length boundary check at the chunk boundary (6/7 bytes
    /// fit in one chunk-with-suffix, 7/8 cross into a second chunk).
    #[test]
    fn padded_witness_distinguishes_different_lengths_at_chunk_boundaries() {
        let nonce = [0x88; NONCE_LEN];
        let c6 = compute_commitment(CIRCUIT_ID, &witness_to_felts(&[0xaa; 6]), &nonce);
        let c7 = compute_commitment(CIRCUIT_ID, &witness_to_felts(&[0xaa; 7]), &nonce);
        assert_ne!(c6, c7, "6-byte and 7-byte values must commit distinctly");
    }

    /// Oversize values produce more than the AIR-fixed felt count. The AIR
    /// trace builder will assert MAX_PADDED_WITNESS_FELTS exactly;
    /// `validate()` rejects oversize values before the AIR sees them.
    #[test]
    fn witness_to_felts_oversize_value_exceeds_max() {
        let too_long = vec![0u8; 200];
        let felts = witness_to_felts(&too_long);
        assert!(
            felts.len() > MAX_PADDED_WITNESS_FELTS,
            "oversize value should produce more than {} felts",
            MAX_PADDED_WITNESS_FELTS
        );
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
        let bad_commitment = compute_commitment(CIRCUIT_ID, &witness_to_felts(&w.value), &w.nonce);
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
        assert_eq!(
            validate(&w, &p, &params),
            Err(ValidateError::CommitmentMismatch)
        );
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
        let subject_leaf =
            trusset_circuits_common::hash_bytes_with_tag(&trusset_circuits_common::LEAF_TAG, v);
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

    // -------------------------------------------------------------
    // AIR-time negative-witness sweeps (Stage 14)
    //
    // Same pattern as preimage_knowledge: bypass `validate()` and call
    // `prover::build_proof` directly. The AIR's commitment-opening
    // boundary at row 44 MUST reject witnesses that don't open the
    // public commitment.
    //
    // The Merkle-walk predicate (set_leaf + set_depth conditional-swap
    // rounds reaching set_root) is still enforced by `validate()`
    // OUTSIDE the AIR until the in-AIR Merkle walk ships (Stage 15+
    // novel cryptographic work).
    // -------------------------------------------------------------

    #[cfg(feature = "prod-proofs-set")]
    fn try_prove_set_air_only(
        value_for_trace: &[u8],
        nonce_for_trace: [u8; NONCE_LEN],
        path_for_trace: Vec<PathStep>,
        public_commitment: trusset_circuits_common::Digest,
        set_root: trusset_circuits_common::Digest,
        set_depth: u8,
    ) -> Result<Vec<u8>, String> {
        use trusset_circuits_common::stark_options;
        let pi = prover::public_to_air(&public_commitment, &set_root, set_depth);
        // In debug mode, Winterfell's prover triggers `debug_assert!` panics
        // when the trace violates boundary constraints — we catch those. In
        // release mode, `debug_assert!`s are compiled out and the prover
        // happily emits invalid-looking bytes; the rejection then comes from
        // the verifier. Calling both ensures the wrapper correctly reports
        // rejection in either build profile.
        let path_clone = path_for_trace.clone();
        let prove_result = std::panic::catch_unwind(move || {
            prover::build_proof(
                value_for_trace,
                &nonce_for_trace,
                &path_clone,
                &pi,
                stark_options(),
                &[0u8; 32],
            )
        });
        let proof_bytes = match prove_result {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return Err(format!("ProverError: {e:?}")),
            Err(p) => {
                let msg = p
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
                    .unwrap_or_else(|| "unknown panic".to_string());
                return Err(format!("Prover panic: {msg}"));
            }
        };
        // Verify the produced bytes against the same public inputs. If the
        // trace was inconsistent with the public commitment or set_root, this
        // is where the rejection materializes in release mode.
        let pi_verify = prover::public_to_air(&public_commitment, &set_root, set_depth);
        match verifier::verify_proof(&proof_bytes, pi_verify) {
            Ok(()) => Ok(proof_bytes),
            Err(e) => Err(format!("VerifierError: {e:?}")),
        }
    }

    #[cfg(feature = "prod-proofs-set")]
    #[test]
    fn air_rejects_different_value_for_same_commitment() {
        let list = fixture_list();
        let (w, p, _) = witness_for(&list, 0); // DEU
                                               // Try to prove with "FRA" while keeping DEU's public commitment.
        let result = try_prove_set_air_only(
            b"FRA",
            w.nonce,
            w.merkle_path.clone(),
            p.commitment,
            p.set_root,
            p.set_depth,
        );
        assert!(
            result.is_err(),
            "AIR must reject 'FRA' against DEU's commitment, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-set")]
    #[test]
    fn air_rejects_different_nonce_for_same_commitment() {
        let list = fixture_list();
        let (w, p, _) = witness_for(&list, 1); // FRA with nonce = [0x44; 32]
        let alt_nonce = [0x99u8; NONCE_LEN];
        let result = try_prove_set_air_only(
            &w.value,
            alt_nonce,
            w.merkle_path.clone(),
            p.commitment,
            p.set_root,
            p.set_depth,
        );
        assert!(
            result.is_err(),
            "AIR must reject mismatched nonce for same value, got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-set")]
    #[test]
    fn air_rejects_tampered_commitment_limbs() {
        let list = fixture_list();
        let (w, p, _) = witness_for(&list, 2); // USA
        let mut tampered = p.commitment;
        tampered[1] = trusset_circuits_common::Felt::new(0xfeedface_u64);
        let result = try_prove_set_air_only(
            &w.value,
            w.nonce,
            w.merkle_path.clone(),
            tampered,
            p.set_root,
            p.set_depth,
        );
        assert!(
            result.is_err(),
            "AIR must reject tampered commitment, got Ok"
        );
    }

    /// The soundness fix (circuitsVersion 3): a prover commits to a
    /// non-member value but tries to prove membership by grafting a real
    /// member's Merkle walk onto its own commitment. The commitment opens
    /// (row 44) and the walk reaches `set_root` (boundary), but the
    /// non-member's `set_leaf` (row 89) never enters the carry chain. The
    /// v3 carry binding rejects it; the frozen v2 AIR - which left the
    /// carry column unconstrained - accepts it, which is the exact hole
    /// this fix closes.
    #[cfg(feature = "prod-proofs-set")]
    #[test]
    fn v3_rejects_nonmember_grafted_onto_member_walk_while_v2_accepts() {
        use trusset_circuits_common::stark_options;
        use winterfell::Prover;

        let list = fixture_list();
        let (member_w, member_p, _) = witness_for(&list, 0); // DEU, a real member
        let nonmember_value: &[u8] = b"ZZZ"; // not in the fixture list
        let nonmember_nonce = [0x7cu8; NONCE_LEN];

        // Public inputs the forger presents: the non-member's own
        // commitment, but the real set_root and depth.
        let nonmember_commitment = compute_commitment(
            CircuitId::SetMembership,
            &witness_to_felts(nonmember_value),
            &nonmember_nonce,
        );

        // Two honest traces: one opens to the non-member (its walk does
        // NOT reach set_root), the other is the member's real inclusion.
        let nm_trace =
            prover::build_trace(nonmember_value, &nonmember_nonce, &member_w.merkle_path);
        let member_trace =
            prover::build_trace(&member_w.value, &member_w.nonce, &member_w.merkle_path);

        // Graft: rows 0..MERKLE_ROW_START from the non-member (commitment +
        // set_leaf), rows MERKLE_ROW_START.. from the member (the walk that
        // reaches set_root). Force the witness-binding band (cols 12..24)
        // to the non-member's witness across every row so the constancy
        // constraint stays satisfied.
        let width = air::TRACE_WIDTH;
        let length = air::TRACE_LENGTH;
        let nm_witness = witness_to_felts(nonmember_value);
        let mut forged = winterfell::TraceTable::new(width, length);
        for row in 0..length {
            for col in 0..width {
                let witness_cols =
                    air::COL_WITNESS_START..air::COL_WITNESS_START + MAX_PADDED_WITNESS_FELTS;
                let v = if witness_cols.contains(&col) {
                    nm_witness[col - air::COL_WITNESS_START]
                } else if row < air::MERKLE_ROW_START {
                    nm_trace.get(col, row)
                } else {
                    member_trace.get(col, row)
                };
                forged.set(col, row, v);
            }
        }

        let pi = prover::public_to_air(
            &nonmember_commitment,
            &member_p.set_root,
            member_p.set_depth,
        );

        // The grafted trace has a self-consistent non-member commitment and
        // a valid-looking walk to set_root, so an honest run produces
        // proof bytes under both constraint sets.
        let v3_prover = prover::SetProver::new(stark_options(), pi.clone());
        let v2_prover = prover::SetProverV2::new(stark_options(), pi.clone());

        let forged_v3 = forged.clone();
        let v3_bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            v3_prover.prove(forged_v3)
        }));
        let forged_v2 = forged.clone();
        let v2_bytes = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            v2_prover.prove(forged_v2)
        }));

        // v3: the carry binding fails the forged trace. In debug builds the
        // prover panics on the boundary/transition assertion; in release it
        // emits bytes the verifier rejects. Either way, no accepted proof.
        let v3_accepted = matches!(&v3_bytes, Ok(Ok(p))
            if verifier::verify_proof(&p.to_bytes(), pi.clone()).is_ok());
        assert!(
            !v3_accepted,
            "circuitsVersion 3 AIR must reject a non-member grafted onto a member walk"
        );

        // v2: the frozen AIR leaves the carry unconstrained, so the forged
        // trace verifies - this is the documented pre-v2.1 soundness gap.
        let v2_accepted = matches!(&v2_bytes, Ok(Ok(p))
            if verifier::verify_proof_v2(&p.to_bytes(), pi.clone()).is_ok());
        assert!(
            v2_accepted,
            "frozen circuitsVersion 2 AIR is expected to accept the forgery (the gap v3 closes)"
        );
    }

    #[cfg(feature = "prod-proofs-set")]
    #[test]
    fn air_accepts_honest_witness() {
        // Positive control: honest witness must pass through the same
        // try_prove_set_air_only path.
        let list = fixture_list();
        let (w, p, _) = witness_for(&list, 3); // GBR
        let result = try_prove_set_air_only(
            &w.value,
            w.nonce,
            w.merkle_path.clone(),
            p.commitment,
            p.set_root,
            p.set_depth,
        );
        assert!(
            result.is_ok(),
            "AIR must accept honest witness, got {:?}",
            result.err()
        );
    }
}
