//! Wall-clock micro-benchmark for the placeholder Winterfell AIR.
//!
//! Not a benchmark harness — just a `--ignored` test that prints prove
//! time, verify time, and proof size to stdout. Run with:
//!
//! ```text
//! cargo test --release -p trusset-circuit-preimage-knowledge \
//!     --features prod-proofs-preimage --test perf_bench -- --ignored --nocapture
//! ```
//!
//! Numbers feed `docs/PERFORMANCE.md` § "Phase 2B Step-A measurements".

#![cfg(feature = "prod-proofs-preimage")]

use std::time::Instant;
use trusset_circuit_preimage_knowledge::{commit, prove, verify, Params, PublicInputs, Witness};
use trusset_circuits_common::NONCE_LEN;

#[test]
#[ignore = "perf measurement; run with --ignored"]
fn bench_preimage_prove_verify() {
    let w = Witness {
        value: b"Alice".to_vec(),
        nonce: [0xab; NONCE_LEN],
    };
    let p = PublicInputs {
        commitment: commit(&w),
    };

    let iters = 5;
    let mut prove_ms = Vec::new();
    let mut verify_ms = Vec::new();
    let mut proof_size = 0usize;

    for _ in 0..iters {
        let t = Instant::now();
        let bytes = prove(&w, &p, &Params::default()).unwrap();
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_size = bytes.len();

        let t = Instant::now();
        verify(&bytes, &p).unwrap();
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
    }

    prove_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    verify_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let prove_p50 = prove_ms[iters / 2];
    let verify_p50 = verify_ms[iters / 2];

    println!(
        "PERF preimage_knowledge: prove_p50={:.1}ms verify_p50={:.2}ms proof_size={}B iters={}",
        prove_p50, verify_p50, proof_size, iters
    );
}
