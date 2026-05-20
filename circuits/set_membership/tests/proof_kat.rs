//! KAT + negative-witness sweep for set_membership (prod-proofs only).

#![cfg(feature = "prod-proofs-set")]

use sha2::{Digest as _, Sha256};
use trusset_circuit_set_membership::{
    build_set_tree, commit, prove, validate, verify, Params, PublicInputs, ValidateError, Witness,
};
use trusset_circuits_common::NONCE_LEN;

fn pub_inputs(w: &Witness, set_root: trusset_circuits_common::Digest, depth: u8) -> PublicInputs {
    PublicInputs {
        commitment: commit(w),
        set_root,
        set_depth: depth,
    }
}

fn fixture_tree() -> (Witness, PublicInputs) {
    let values_owned: Vec<Vec<u8>> = vec![
        b"DEU".to_vec(),
        b"FRA".to_vec(),
        b"USA".to_vec(),
        b"GBR".to_vec(),
    ];
    let values_refs: Vec<&[u8]> = values_owned.iter().map(|v| v.as_slice()).collect();
    let (root, depth, _leaves) = build_set_tree(&values_refs);
    // Build merkle_path for "FRA" (index 1).
    use trusset_circuit_set_membership::{set_leaf_digest, PathStep, Side};
    use trusset_circuits_common::{hash_two_with_tag, SET_NODE_TAG};
    // Manually compute path for index 1 in a depth-2 tree of 4 leaves.
    let leaves: Vec<_> = values_owned.iter().map(|v| set_leaf_digest(v)).collect();
    // Tree: row0 = leaves, row1 = pair-merges, row2 = root.
    // For index 1: sibling at depth0 = leaves[0] (Left). At depth1 sibling = merge(leaves[2], leaves[3]) (Right).
    let pair_23 = hash_two_with_tag(&SET_NODE_TAG, &leaves[2], &leaves[3]);
    let path = vec![
        PathStep {
            sibling: leaves[0],
            side: Side::Right,
        },
        PathStep {
            sibling: pair_23,
            side: Side::Left,
        },
    ];
    let w = Witness {
        value: b"FRA".to_vec(),
        nonce: [0xab; NONCE_LEN],
        merkle_path: path,
    };
    let p = pub_inputs(&w, root, depth);
    (w, p)
}

#[test]
fn proof_bytes_are_deterministic() {
    let (w, p) = fixture_tree();
    let params = Params {
        list_id: "country_allowlist".to_string(),
    };
    let a = prove(&w, &p, &params).unwrap();
    let b = prove(&w, &p, &params).unwrap();
    assert_eq!(Sha256::digest(&a).as_slice(), Sha256::digest(&b).as_slice());
}

#[test]
fn roundtrip_accepts_valid_member() {
    let (w, p) = fixture_tree();
    let params = Params {
        list_id: "country_allowlist".to_string(),
    };
    let bytes = prove(&w, &p, &params).unwrap();
    assert!(verify(&bytes, &p).is_ok());
}

#[test]
fn predicate_rejects_empty_value() {
    let w = Witness {
        value: Vec::new(),
        nonce: [0; NONCE_LEN],
        merkle_path: Vec::new(),
    };
    let p = PublicInputs {
        commitment: commit(&w),
        set_root: [trusset_circuits_common::Felt::new(0); 4],
        set_depth: 0,
    };
    assert!(matches!(
        validate(
            &w,
            &p,
            &Params {
                list_id: "x".to_string()
            }
        ),
        Err(ValidateError::EmptyValue)
    ));
}

#[test]
fn predicate_rejects_path_depth_mismatch() {
    let (w_ok, p_ok) = fixture_tree();
    // Truncate merkle path to wrong length.
    let w = Witness {
        value: w_ok.value.clone(),
        nonce: w_ok.nonce,
        merkle_path: w_ok.merkle_path[..1].to_vec(),
    };
    assert!(matches!(
        validate(
            &w,
            &p_ok,
            &Params {
                list_id: "x".to_string()
            }
        ),
        Err(ValidateError::PathDepthMismatch { .. })
    ));
}

#[test]
fn cross_root_verify_fails() {
    let (w, p) = fixture_tree();
    let params = Params {
        list_id: "x".to_string(),
    };
    let bytes = prove(&w, &p, &params).unwrap();
    let p_bad = PublicInputs {
        commitment: p.commitment,
        set_root: [trusset_circuits_common::Felt::new(123); 4],
        set_depth: p.set_depth,
    };
    assert!(verify(&bytes, &p_bad).is_err());
}
