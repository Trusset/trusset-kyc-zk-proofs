//! Byte-equality KAT for the Rescue-Prime AIR gadget vs
//! `winter_crypto::hashers::Rp64_256`.
//!
//! These tests pin the relationship between the host-side trace generator
//! in `trusset_circuits_common::rescue_air` and Winterfell's reference
//! Rescue-Prime hasher. If Winterfell ever changes the instantiation
//! (round constants, MDS, S-box exponent), these tests fail loudly — the
//! AIR gadget would otherwise silently produce traces inconsistent with
//! the hash function used elsewhere in the workspace
//! (`circuits/common/src/hash.rs`).

use trusset_circuits_common::hash::rescue_merge_raw;
use trusset_circuits_common::rescue_air::{
    apply_permutation, enforce_first_half, enforce_second_half, extract_digest,
    hash_elements_via_trace, merge_via_trace, periodic_round_constants, permutation_trace, ARK1,
    ARK2, NUM_ROUNDS, PERMUTATION_TRACE_ROWS, STATE_WIDTH, SUB_ROUNDS_PER_PERMUTATION,
};
use trusset_circuits_common::{hash_elements, Digest, Felt};
use winter_crypto::{hashers::Rp64_256, ElementHasher};
use winter_math::FieldElement;

fn entry_state(seed: u64) -> [Felt; STATE_WIDTH] {
    std::array::from_fn(|i| {
        Felt::new(
            seed.wrapping_add(i as u64)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15),
        )
    })
}

// ---------------------------------------------------------------------------
// apply_permutation byte-equality
// ---------------------------------------------------------------------------

#[test]
fn apply_permutation_matches_rp64_256_zero_state() {
    let mut a = [Felt::ZERO; STATE_WIDTH];
    let mut b = [Felt::ZERO; STATE_WIDTH];
    apply_permutation(&mut a);
    Rp64_256::apply_permutation(&mut b);
    assert_eq!(a, b, "permutation of zero state must match Rp64_256");
}

#[test]
fn apply_permutation_matches_rp64_256_random_state() {
    for seed in [1u64, 2, 7, 31, 1234567, u64::MAX] {
        let mut a = entry_state(seed);
        let mut b = entry_state(seed);
        apply_permutation(&mut a);
        Rp64_256::apply_permutation(&mut b);
        assert_eq!(a, b, "permutation differs from Rp64_256 for seed {seed}");
    }
}

// ---------------------------------------------------------------------------
// hash_elements byte-equality
// ---------------------------------------------------------------------------

fn assert_hash_elements_matches(elements: &[Felt]) {
    let state = hash_elements_via_trace(elements);
    let digest_air = extract_digest(&state);
    let digest_native = Rp64_256::hash_elements(elements);
    assert_eq!(
        digest_air,
        *digest_native.as_elements(),
        "hash_elements digest differs for {} input felts",
        elements.len()
    );
    // Also confirm the trusset_circuits_common::hash_elements wrapper agrees.
    let wrapper_digest: Digest = hash_elements(elements);
    assert_eq!(digest_air, wrapper_digest, "wrapper hash_elements drift");
}

#[test]
fn hash_elements_empty_matches_rp64_256() {
    assert_hash_elements_matches(&[]);
}

#[test]
fn hash_elements_one_felt_matches_rp64_256() {
    assert_hash_elements_matches(&[Felt::new(0)]);
    assert_hash_elements_matches(&[Felt::new(1)]);
    assert_hash_elements_matches(&[Felt::new(42)]);
    assert_hash_elements_matches(&[Felt::new(u64::MAX - 1)]);
}

#[test]
fn hash_elements_partial_block_matches_rp64_256() {
    for n in [2usize, 3, 5, 7] {
        let v: Vec<Felt> = (0..n).map(|i| Felt::new(i as u64 * 13 + 7)).collect();
        assert_hash_elements_matches(&v);
    }
}

#[test]
fn hash_elements_full_block_matches_rp64_256() {
    // exactly RATE_WIDTH = 8: single absorption + one permutation
    let v: Vec<Felt> = (0..8u64).map(|i| Felt::new(i * 31 + 1)).collect();
    assert_hash_elements_matches(&v);
}

#[test]
fn hash_elements_two_full_blocks_matches_rp64_256() {
    // 16 elements = exactly 2 absorption blocks
    let v: Vec<Felt> = (0..16u64).map(|i| Felt::new(i * 257 + 11)).collect();
    assert_hash_elements_matches(&v);
}

#[test]
fn hash_elements_partial_third_block_matches_rp64_256() {
    // 17 elements = 2 full blocks + 1 leftover (triggers final permutation
    // on a partial block).
    let v: Vec<Felt> = (0..17u64).map(|i| Felt::new(i * 991 + 3)).collect();
    assert_hash_elements_matches(&v);
}

#[test]
fn hash_elements_long_input_matches_rp64_256() {
    // 100 elements = 12 full blocks + 4 leftover, exercises many
    // permutation chains.
    let v: Vec<Felt> = (0..100u64)
        .map(|i| Felt::new(i.wrapping_mul(0xDEAD_BEEF)))
        .collect();
    assert_hash_elements_matches(&v);
}

// ---------------------------------------------------------------------------
// merge byte-equality
// ---------------------------------------------------------------------------

#[test]
fn merge_matches_rp64_256_zero_inputs() {
    let zero: Digest = [Felt::ZERO; 4];
    let state = merge_via_trace(&zero, &zero);
    let digest_air = extract_digest(&state);
    let digest_native = rescue_merge_raw(&zero, &zero);
    assert_eq!(digest_air, digest_native);
}

#[test]
fn merge_matches_rp64_256_sample_inputs() {
    let a: Digest = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    let b: Digest = [
        Felt::new(100),
        Felt::new(200),
        Felt::new(300),
        Felt::new(400),
    ];
    let state = merge_via_trace(&a, &b);
    let digest_air = extract_digest(&state);
    let digest_native = rescue_merge_raw(&a, &b);
    assert_eq!(digest_air, digest_native);
}

#[test]
fn merge_is_order_sensitive_via_trace() {
    let a: Digest = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
    let b: Digest = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];
    let ab = extract_digest(&merge_via_trace(&a, &b));
    let ba = extract_digest(&merge_via_trace(&b, &a));
    assert_ne!(ab, ba, "trace merge must be order-sensitive");
}

// ---------------------------------------------------------------------------
// permutation_trace shape and final-row equivalence
// ---------------------------------------------------------------------------

#[test]
fn permutation_trace_has_15_rows_each_12_felts() {
    let entry = entry_state(99);
    let rows = permutation_trace(entry);
    assert_eq!(rows.len(), PERMUTATION_TRACE_ROWS);
    assert_eq!(rows.len(), 15);
    for row in rows.iter() {
        assert_eq!(row.len(), STATE_WIDTH);
        assert_eq!(row.len(), 12);
    }
}

#[test]
fn permutation_trace_row_0_is_entry() {
    let entry = entry_state(42);
    let rows = permutation_trace(entry);
    assert_eq!(rows[0], entry);
}

#[test]
fn permutation_trace_final_row_equals_apply_permutation() {
    let entry = entry_state(7);
    let rows = permutation_trace(entry);
    let mut direct = entry;
    apply_permutation(&mut direct);
    assert_eq!(rows[PERMUTATION_TRACE_ROWS - 1], direct);
}

// ---------------------------------------------------------------------------
// AIR constraint residuals are zero on a valid trace
// ---------------------------------------------------------------------------

#[test]
fn first_half_constraint_is_zero_on_valid_trace() {
    let entry = entry_state(11);
    let rows = permutation_trace(entry);
    let mut result = [Felt::ZERO; STATE_WIDTH];
    for round in 0..NUM_ROUNDS {
        enforce_first_half(
            &rows[2 * round],
            &rows[2 * round + 1],
            &ARK1[round],
            &mut result,
        );
        for (i, r) in result.iter().enumerate() {
            assert_eq!(
                *r,
                Felt::ZERO,
                "first-half residual nonzero at round {round}, index {i}"
            );
        }
    }
}

#[test]
fn second_half_constraint_is_zero_on_valid_trace() {
    let entry = entry_state(13);
    let rows = permutation_trace(entry);
    let mut result = [Felt::ZERO; STATE_WIDTH];
    for round in 0..NUM_ROUNDS {
        enforce_second_half(
            &rows[2 * round + 1],
            &rows[2 * round + 2],
            &ARK2[round],
            &mut result,
        );
        for (i, r) in result.iter().enumerate() {
            assert_eq!(
                *r,
                Felt::ZERO,
                "second-half residual nonzero at round {round}, index {i}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// AIR constraint residuals are nonzero on a tampered trace
// ---------------------------------------------------------------------------

#[test]
fn first_half_constraint_rejects_tampered_intermediate() {
    let entry = entry_state(17);
    let mut rows = permutation_trace(entry);
    // Tamper one element of an intermediate first-half row.
    rows[1][3] += Felt::new(2);
    let mut result = [Felt::ZERO; STATE_WIDTH];
    enforce_first_half(&rows[0], &rows[1], &ARK1[0], &mut result);
    assert!(
        result.iter().any(|r| *r != Felt::ZERO),
        "tampered first-half intermediate must produce nonzero residual"
    );
}

#[test]
fn second_half_constraint_rejects_tampered_intermediate() {
    let entry = entry_state(19);
    let mut rows = permutation_trace(entry);
    // Tamper one element of an intermediate second-half row.
    rows[2][5] += Felt::new(7);
    let mut result = [Felt::ZERO; STATE_WIDTH];
    enforce_second_half(&rows[1], &rows[2], &ARK2[0], &mut result);
    assert!(
        result.iter().any(|r| *r != Felt::ZERO),
        "tampered second-half intermediate must produce nonzero residual"
    );
}

#[test]
fn first_half_constraint_rejects_wrong_ark() {
    let entry = entry_state(23);
    let rows = permutation_trace(entry);
    let wrong_ark = ARK1[1]; // intentionally using ARK for the wrong round
    let mut result = [Felt::ZERO; STATE_WIDTH];
    enforce_first_half(&rows[0], &rows[1], &wrong_ark, &mut result);
    assert!(
        result.iter().any(|r| *r != Felt::ZERO),
        "using ARK for wrong round must produce nonzero residual"
    );
}

// ---------------------------------------------------------------------------
// Periodic-column helper sanity
// ---------------------------------------------------------------------------

#[test]
fn periodic_columns_have_expected_layout() {
    let cols = periodic_round_constants();
    // 24 columns: 12 ARK1 + 12 ARK2
    assert_eq!(cols.len(), STATE_WIDTH * 2);
    for col in &cols {
        assert_eq!(col.len(), SUB_ROUNDS_PER_PERMUTATION);
    }
    // Verify all 7 rounds × 12 state width × 2 (ARK1/ARK2) constants populated.
    for round in 0..NUM_ROUNDS {
        for i in 0..STATE_WIDTH {
            assert_eq!(cols[i][2 * round], ARK1[round][i]);
            assert_eq!(cols[i][2 * round + 1], Felt::ZERO);
            assert_eq!(cols[STATE_WIDTH + i][2 * round], Felt::ZERO);
            assert_eq!(cols[STATE_WIDTH + i][2 * round + 1], ARK2[round][i]);
        }
    }
}
