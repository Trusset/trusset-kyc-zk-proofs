//! Wall-clock micro-benchmark for tier_threshold placeholder AIR.

#![cfg(feature = "prod-proofs-tier")]

use std::time::Instant;
use trusset_circuit_tier_threshold::{
    commit, prove, verify, Params, PublicInputs, Witness, TIER_PROFESSIONAL, TIER_RETAIL,
};
use trusset_circuits_common::NONCE_LEN;

#[test]
#[ignore = "perf measurement; run with --ignored"]
fn bench_tier_prove_verify() {
    let w = Witness {
        tier: TIER_PROFESSIONAL,
        nonce: [0xab; NONCE_LEN],
    };
    let p = PublicInputs {
        commitment: commit(&w),
        min_tier: TIER_RETAIL,
    };

    let iters = 5;
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_size = 0usize;

    for _ in 0..iters {
        let t = Instant::now();
        let bytes = prove(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL,
            },
        )
        .unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_size = bytes.len();
        let t = Instant::now();
        verify(&bytes, &p).unwrap();
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!(
        "PERF tier_threshold: prove_p50={:.1}ms verify_p50={:.2}ms proof_size={}B iters={}",
        prove_ms[iters / 2],
        verify_ms[iters / 2],
        proof_size,
        iters
    );
}
