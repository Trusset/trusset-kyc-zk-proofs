//! Wall-clock micro-benchmark for set_membership placeholder AIR.

#![cfg(feature = "prod-proofs-set")]

use std::time::Instant;
use trusset_circuit_set_membership::{
    build_set_tree, commit, prove, set_leaf_digest, verify, Params, PathStep, PublicInputs, Side,
    Witness,
};
use trusset_circuits_common::{hash_two_with_tag, NONCE_LEN, SET_NODE_TAG};

#[test]
#[ignore = "perf measurement; run with --ignored"]
fn bench_set_prove_verify() {
    let values: Vec<Vec<u8>> = vec![
        b"DEU".to_vec(),
        b"FRA".to_vec(),
        b"USA".to_vec(),
        b"GBR".to_vec(),
    ];
    let value_refs: Vec<&[u8]> = values.iter().map(|v| v.as_slice()).collect();
    let (root, depth, _) = build_set_tree(&value_refs);

    let leaves: Vec<_> = values.iter().map(|v| set_leaf_digest(v)).collect();
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
    let p = PublicInputs {
        commitment: commit(&w),
        set_root: root,
        set_depth: depth,
    };
    let params = Params {
        list_id: "country_allowlist".to_string(),
    };

    let iters = 5;
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_size = 0usize;

    for _ in 0..iters {
        let t = Instant::now();
        let bytes = prove(&w, &p, &params).unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_size = bytes.len();
        let t = Instant::now();
        verify(&bytes, &p).unwrap();
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!(
        "PERF set_membership: prove_p50={:.1}ms verify_p50={:.2}ms proof_size={}B iters={}",
        prove_ms[iters / 2],
        verify_ms[iters / 2],
        proof_size,
        iters
    );
}
