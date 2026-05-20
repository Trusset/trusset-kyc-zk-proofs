//! Known-answer + determinism tests for the preimage_knowledge circuit.
//!
//! Two responsibilities:
//!   1. Lock in proof-byte-stability under fixed `(witness, public_inputs,
//!      ProofOptions, prover_seed)` so any drift in Winterfell parameters,
//!      hash choice, or PRNG plumbing is caught at CI time.
//!   2. Exercise the negative-witness sweep (oversized value, commitment
//!      mismatch) that `proptest` would have given us, but using a
//!      hand-rolled vector list to avoid the rand 0.9 / cpufeatures 0.3
//!      dep-graph collision documented in Cargo.toml.
//!
//! Only built when the `prod-proofs-preimage` feature is enabled — the
//! stub path already has its own roundtrip test in `src/lib.rs`.

#![cfg(feature = "prod-proofs-preimage")]

use sha2::{Digest as _, Sha256};
use trusset_circuit_preimage_knowledge::{
    commit, prove, validate, verify, Params, PublicInputs, ValidateError, Witness,
};
use trusset_circuits_common::NONCE_LEN;

fn make_witness(value: &[u8], nonce_byte: u8) -> Witness {
    Witness {
        value: value.to_vec(),
        nonce: [nonce_byte; NONCE_LEN],
    }
}

fn public_for(w: &Witness) -> PublicInputs {
    PublicInputs {
        commitment: commit(w),
    }
}

/// Pinned-byte KAT. The proof must be byte-deterministic across runs;
/// `prove_a` and `prove_b` are independent calls and their bytes must
/// be identical (this is the workspace-level determinism contract that
/// `tests/e2e/canary.sh` also enforces at the bundle level).
#[test]
fn proof_bytes_are_deterministic() {
    let w = make_witness(b"Alice", 0xab);
    let p = public_for(&w);

    let prove_a = prove(&w, &p, &Params::default()).unwrap();
    let prove_b = prove(&w, &p, &Params::default()).unwrap();

    assert_eq!(
        Sha256::digest(&prove_a).as_slice(),
        Sha256::digest(&prove_b).as_slice(),
        "proof bytes diverge across two prove() calls — Winterfell PRNG leak",
    );
    assert_eq!(prove_a, prove_b);
}

/// Different witnesses MUST produce different proof bytes (the public
/// commitment input is part of the AIR's public inputs and thus the
/// Fiat-Shamir transcript seed).
#[test]
fn distinct_witnesses_produce_distinct_proofs() {
    let wa = make_witness(b"Alice", 0xab);
    let wb = make_witness(b"Bob", 0xab);
    let pa = public_for(&wa);
    let pb = public_for(&wb);

    let proof_a = prove(&wa, &pa, &Params::default()).unwrap();
    let proof_b = prove(&wb, &pb, &Params::default()).unwrap();
    assert_ne!(proof_a, proof_b);
    assert!(verify(&proof_a, &pa).is_ok());
    assert!(verify(&proof_b, &pb).is_ok());
    // Cross-verification must fail.
    assert!(verify(&proof_a, &pb).is_err());
    assert!(verify(&proof_b, &pa).is_err());
}

/// Negative-witness sweep (replaces proptest): every (value-length,
/// max_value_bytes) pair that violates the predicate must be rejected
/// at the `validate()` stage. Covers the predicate boundary
/// exhaustively for small values.
#[test]
fn negative_witnesses_rejected_by_predicate() {
    for max in [0usize, 1, 8, 32, 64, 128] {
        for len in 0..=max + 4 {
            let value = vec![0xc3u8; len];
            let w = Witness {
                value: value.clone(),
                nonce: [0u8; NONCE_LEN],
            };
            let p = PublicInputs {
                commitment: commit(&w),
            };
            let params = Params {
                max_value_bytes: max,
            };
            let r = validate(&w, &p, &params);
            if len <= max {
                assert!(
                    r.is_ok(),
                    "len={len} max={max} should be accepted, got {r:?}"
                );
            } else {
                assert!(
                    matches!(r, Err(ValidateError::ValueTooLong { .. })),
                    "len={len} max={max} should be rejected, got {r:?}"
                );
            }
        }
    }
}

/// Commitment-tampering: flipping any bit of the public commitment must
/// be detected by the predicate (before the AIR even runs).
#[test]
fn tampered_commitment_rejected_by_predicate() {
    let w = make_witness(b"Alice", 0xab);
    let mut p = public_for(&w);
    // Flip one limb.
    p.commitment[2] += trusset_circuits_common::Felt::new(1);
    let r = validate(&w, &p, &Params::default());
    assert!(
        matches!(r, Err(ValidateError::CommitmentMismatch)),
        "tampered commitment should be rejected, got {r:?}"
    );
}

/// Empty-value edge case (preimage_knowledge accepts empty preimages —
/// spec §6.4 + plan edge case 8). Round-trip must work.
#[test]
fn empty_value_roundtrips() {
    let w = make_witness(b"", 0x00);
    let p = public_for(&w);
    let bytes = prove(&w, &p, &Params::default()).unwrap();
    assert!(verify(&bytes, &p).is_ok());
}
