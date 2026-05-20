//! Wall-clock micro-benchmark for age_threshold placeholder AIR.

#![cfg(feature = "prod-proofs-age")]

use std::time::Instant;
use trusset_circuit_age_threshold::{commit, prove, verify, Params, PublicInputs, Witness};
use trusset_circuits_common::NONCE_LEN;

#[test]
#[ignore = "perf measurement; run with --ignored"]
fn bench_age_prove_verify() {
    let w = Witness {
        dob_days: 2000,
        nonce: [0xab; NONCE_LEN],
    };
    let p = PublicInputs {
        commitment: commit(&w),
        min_age_days: 6570,
        current_epoch_days: 20587,
    };

    let iters = 5;
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_size = 0usize;

    for _ in 0..iters {
        let t = Instant::now();
        let bytes = prove(&w, &p, &Params { min_age_days: 6570 }).unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_size = bytes.len();
        let t = Instant::now();
        verify(&bytes, &p).unwrap();
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());

    println!(
        "PERF age_threshold: prove_p50={:.1}ms verify_p50={:.2}ms proof_size={}B iters={}",
        prove_ms[iters / 2],
        verify_ms[iters / 2],
        proof_size,
        iters
    );
}
