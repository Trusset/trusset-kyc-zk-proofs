//! Stage 16 work-in-progress — full 33-column trace assembly, no AIR yet.
//!
//! Companion to `stage16_trace_shape.rs` (validated cols 0..12 Rescue
//! state math) and `stage16_periodic_columns.rs` (validated the 34
//! periodic columns). This file assembles the FULL Stage 16 trace
//! across all 33 columns and verifies the cross-column invariants the
//! AIR's transition constraints will enforce:
//!
//!   - state cols (0..12): Rescue + absorption + setup + pad math
//!   - witness cols (12..24): constant across all rows
//!   - side bit (24): boolean ∈ {0,1} at merge setup rows
//!   - sibling cols (25..29): witnessed at merge setup rows
//!   - carry cols (29..33): propagate level-entry node through each
//!     30-row merge level
//!
//! When the AIR lands, the production prover's trace builder will
//! reproduce this exact 33-column layout, and the AIR's transition
//! constraints will read these columns to verify the cross-column
//! invariants encoded here.
//!
//! Status: work-in-progress. The production AIR remains at Stage 13
//! (commitment opening only). This file provides the verified
//! end-to-end trace assembly that the next-session AIR impl can drop
//! into the prover's `build_v2_state_trace`.

#![cfg(feature = "prod-proofs-set")]
// AIR-style explicit indexing matches spec math more directly than
// enumerate() / copy_from_slice; kept consistent with production AIR
// files which use the same allow set.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]

use trusset_circuit_set_membership::{witness_to_felts, PathStep, MAX_PADDED_WITNESS_FELTS};
use trusset_circuits_common::{
    bytes_to_field, compute_commitment, hash_two_with_tag, rescue_air, CircuitId, COMMITMENT_TAG,
    SET_LEAF_TAG, SET_NODE_TAG,
};
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// Stage 16 trace constants (mirrors stage16_trace_shape.rs).
const TRACE_WIDTH: usize = 33;
const TRACE_LENGTH: usize = 2048;
const COMMIT_FINAL_ROW: usize = 44;
const SETLEAF_ROW_START: usize = 45;
const SETLEAF_FINAL_ROW: usize = 89;
const MERKLE_ROW_START: usize = 90;
const MERGE_ROWS_PER_LEVEL: usize = 30;

// Column bands.
const COL_WITNESS_START: usize = 12;
const COL_SIDE_BIT: usize = 24;
const COL_SIBLING_START: usize = 25;
const COL_CARRY_START: usize = 29;

// --------------------------------------------------------------------
// Phase builders (cols 0..12 Rescue state — same as stage16_trace_shape.rs)
// --------------------------------------------------------------------

fn build_commitment_rows(value: &[u8], nonce: &[u8; 32]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    let nonce_felts = bytes_to_field(nonce);
    let witness_felts = witness_to_felts(value);

    let mut input = [BaseElement::ZERO; 24];
    input[0..5].copy_from_slice(&tag_felts);
    input[5] = BaseElement::new(u64::from(CircuitId::SetMembership.as_u8()));
    input[6] = BaseElement::new(MAX_PADDED_WITNESS_FELTS as u64);
    input[7..19].copy_from_slice(&witness_felts);
    input[19..24].copy_from_slice(&nonce_felts);

    let mut rows: Vec<[BaseElement; 12]> = Vec::with_capacity(45);
    let mut state = [BaseElement::ZERO; 12];
    state[0] = BaseElement::new(24);
    state[4..12].copy_from_slice(&input[0..8]);
    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);
    let mut current = block1[14];

    for i in 0..8 {
        current[4 + i] += input[8 + i];
    }
    rows.push(current);
    let block2 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block2[1..]);
    current = block2[14];

    for i in 0..8 {
        current[4 + i] += input[16 + i];
    }
    rows.push(current);
    let block3 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block3[1..]);

    rows
}

fn build_setleaf_rows(value: &[u8]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let witness_felts = witness_to_felts(value);

    let mut input = [BaseElement::ZERO; 24];
    input[0..5].copy_from_slice(&tag_felts);
    input[5..17].copy_from_slice(&witness_felts);

    let mut rows: Vec<[BaseElement; 12]> = Vec::with_capacity(45);
    let mut state = [BaseElement::ZERO; 12];
    state[0] = BaseElement::new(17);
    state[4..12].copy_from_slice(&input[0..8]);
    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);
    let mut current = block1[14];

    for i in 0..8 {
        current[4 + i] += input[8 + i];
    }
    rows.push(current);
    let block2 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block2[1..]);
    current = block2[14];

    for i in 0..8 {
        current[4 + i] += input[16 + i];
    }
    rows.push(current);
    let block3 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block3[1..]);

    rows
}

/// Per-merge-level 30-row Rescue state computation. Returns the 30
/// state rows AND the merged digest (= state[4..8] at level end).
fn build_merge_level_rows(
    current_node: [BaseElement; 4],
    sibling: [BaseElement; 4],
    side: u8,
) -> ([[BaseElement; 12]; 30], [BaseElement; 4]) {
    let side_e = BaseElement::new(u64::from(side));
    let one_minus_side = BaseElement::ONE - side_e;

    let mut node_in_a = [BaseElement::ZERO; 4];
    let mut node_in_b = [BaseElement::ZERO; 4];
    for i in 0..4 {
        node_in_a[i] = one_minus_side * current_node[i] + side_e * sibling[i];
        node_in_b[i] = side_e * current_node[i] + one_minus_side * sibling[i];
    }

    let tag_felts = bytes_to_field(&SET_NODE_TAG);
    let mut input = [BaseElement::ZERO; 16];
    input[0..5].copy_from_slice(&tag_felts);
    input[5..9].copy_from_slice(&node_in_a);
    input[9..13].copy_from_slice(&node_in_b);

    let mut rows = [[BaseElement::ZERO; 12]; 30];
    let mut state = [BaseElement::ZERO; 12];
    state[0] = BaseElement::new(13);
    state[4..12].copy_from_slice(&input[0..8]);
    let block1 = rescue_air::permutation_trace(state);
    rows[..15].copy_from_slice(&block1);
    let mut current = block1[14];

    for i in 0..8 {
        current[4 + i] += input[8 + i];
    }
    rows[15] = current;
    let block2 = rescue_air::permutation_trace(current);
    rows[16..30].copy_from_slice(&block2[1..15]);
    let final_state = block2[14];

    let merged: [BaseElement; 4] = [
        final_state[4],
        final_state[5],
        final_state[6],
        final_state[7],
    ];
    (rows, merged)
}

// --------------------------------------------------------------------
// Full 33-column trace assembly
// --------------------------------------------------------------------

/// Assemble the full 33-column × 2048-row Stage 16 trace for an honest
/// witness.
///
/// Column layout:
///   0..12  : Rescue state (12-felt sponge)
///   12..24 : witness_felts[0..12] (binding, constant across all rows)
///   24     : side_bit at merge setup rows; 0 elsewhere
///   25..29 : sibling[0..4] at merge setup rows; 0 elsewhere
///   29..33 : current_node_carry[0..4] — propagated through each level
///
/// Carry semantics: at every row of a Merkle level (rows 90+30k..89+30k+30),
/// the carry holds the INPUT node to that level. For level k=0, this is
/// the set_leaf (= state[4..8] at row 89). For k>0, this is the merged
/// digest from level k-1 (= state[4..8] at row 89+30k).
///
/// Stall padding: rows past the final Merkle level repeat the final
/// state's row content; carry stays at the final merged digest (= root).
fn build_full_stage16_trace(
    value: &[u8],
    nonce: &[u8; 32],
    path: &[PathStep],
) -> Vec<[BaseElement; TRACE_WIDTH]> {
    let set_depth = path.len();
    assert!(set_depth <= 32, "set_depth must be ≤ 32");

    let mut trace: Vec<[BaseElement; TRACE_WIDTH]> =
        vec![[BaseElement::ZERO; TRACE_WIDTH]; TRACE_LENGTH];

    // ---- Cols 0..12: Rescue state ----
    let commit_rows = build_commitment_rows(value, nonce);
    let setleaf_rows = build_setleaf_rows(value);

    // Commitment phase: rows 0..=44.
    for k in 0..45 {
        for c in 0..12 {
            trace[k][c] = commit_rows[k][c];
        }
    }
    // Set_leaf phase: rows 45..=89.
    for k in 0..45 {
        for c in 0..12 {
            trace[SETLEAF_ROW_START + k][c] = setleaf_rows[k][c];
        }
    }

    // Merkle walk: chain through each level.
    let mut current_node: [BaseElement; 4] = [
        setleaf_rows[44][4],
        setleaf_rows[44][5],
        setleaf_rows[44][6],
        setleaf_rows[44][7],
    ];

    for (level, step) in path.iter().enumerate() {
        let level_start = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        let side = step.side.as_u8();
        let level_input_node = current_node;
        let (level_rows, merged) = build_merge_level_rows(level_input_node, step.sibling, side);

        // Side bit, sibling, AND carry are CARRIED CONSTANT across the
        // level's 30 rows. The AIR's per-column constancy constraints
        // (for cols 24, 25..29, 29..33) enforce this between intra-level
        // transitions; this matches what the AIR's absorb_b transition
        // constraint needs (reading side/sibling 15 rows after they're
        // witnessed at the setup row).
        for k in 0..MERGE_ROWS_PER_LEVEL {
            for c in 0..12 {
                trace[level_start + k][c] = level_rows[k][c];
            }
            trace[level_start + k][COL_SIDE_BIT] = BaseElement::new(u64::from(side));
            for c in 0..4 {
                trace[level_start + k][COL_SIBLING_START + c] = step.sibling[c];
            }
            for c in 0..4 {
                trace[level_start + k][COL_CARRY_START + c] = level_input_node[c];
            }
        }

        current_node = merged;
    }

    // ---- Stall padding past the final Merkle level ----
    let merkle_final_row = if set_depth > 0 {
        MERKLE_ROW_START + set_depth * MERGE_ROWS_PER_LEVEL - 1
    } else {
        SETLEAF_FINAL_ROW
    };
    for k in (merkle_final_row + 1)..TRACE_LENGTH {
        for c in 0..12 {
            trace[k][c] = trace[merkle_final_row][c];
        }
        for c in 0..4 {
            trace[k][COL_CARRY_START + c] = current_node[c];
        }
    }

    // ---- Cols 12..24: witness binding, constant across ALL rows ----
    let witness_felts = witness_to_felts(value);
    assert_eq!(witness_felts.len(), MAX_PADDED_WITNESS_FELTS);
    for k in 0..TRACE_LENGTH {
        for c in 0..MAX_PADDED_WITNESS_FELTS {
            trace[k][COL_WITNESS_START + c] = witness_felts[c];
        }
    }

    trace
}

/// Compute the depth-dependent boundary row where set_root should appear.
fn merkle_final_row_for_depth(set_depth: usize) -> usize {
    MERKLE_ROW_START + set_depth * MERGE_ROWS_PER_LEVEL - 1
}

// --------------------------------------------------------------------
// Stage 16 reference: padded set_leaf + padded Merkle tree
//
// The Stage 16 design changes `set_leaf_digest` from unpadded to padded
// (`witness_to_felts(value)` instead of unpadded bytes-to-field). This
// produces different leaf hashes than the production `set_leaf_digest`
// / `build_set_tree` / `inclusion_path` helpers (which still ship the
// Stage 15 unpadded variant; the production wire format won't change
// until Stage 16 lands atomically).
//
// To validate the Stage 16 trace builder end-to-end, we need a separate
// host-side reference tree built from PADDED set_leaf hashes. The
// helpers below mirror `build_set_tree` and `inclusion_path` but use
// the padded set_leaf primitive.
// --------------------------------------------------------------------

fn padded_set_leaf(value: &[u8]) -> [BaseElement; 4] {
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let witness_felts = witness_to_felts(value);
    let mut combined = tag_felts;
    combined.extend_from_slice(&witness_felts);
    trusset_circuits_common::hash_elements(&combined)
}

fn build_padded_set_tree(values: &[&[u8]]) -> ([BaseElement; 4], u8, Vec<[BaseElement; 4]>) {
    assert!(!values.is_empty());
    let mut leaves: Vec<[BaseElement; 4]> = values.iter().map(|v| padded_set_leaf(v)).collect();
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

fn padded_inclusion_path(leaves: &[[BaseElement; 4]], index: usize) -> Vec<PathStep> {
    use trusset_circuit_set_membership::Side;
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

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

fn fixture_witness(idx: usize) -> (Vec<u8>, [u8; 32], Vec<PathStep>, [BaseElement; 4]) {
    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (root, _, leaves) = build_padded_set_tree(&values);
    let value = values[idx].to_vec();
    let nonce = [0x44u8; 32];
    let path = padded_inclusion_path(&leaves, idx);
    (value, nonce, path, root)
}

#[test]
fn full_trace_has_33_cols_and_2048_rows() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    assert_eq!(trace.len(), TRACE_LENGTH);
    for row in &trace {
        assert_eq!(row.len(), TRACE_WIDTH);
    }
}

#[test]
fn full_trace_commitment_boundary_matches_compute_commitment() {
    let (value, nonce, path, _) = fixture_witness(2); // "USA"
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    let trace_commit: [BaseElement; 4] = [
        trace[COMMIT_FINAL_ROW][4],
        trace[COMMIT_FINAL_ROW][5],
        trace[COMMIT_FINAL_ROW][6],
        trace[COMMIT_FINAL_ROW][7],
    ];
    let expected = compute_commitment(CircuitId::SetMembership, &witness_to_felts(&value), &nonce);
    assert_eq!(trace_commit, expected);
}

#[test]
fn full_trace_setleaf_boundary_matches_padded_off_air() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);

    let trace_setleaf: [BaseElement; 4] = [
        trace[SETLEAF_FINAL_ROW][4],
        trace[SETLEAF_FINAL_ROW][5],
        trace[SETLEAF_FINAL_ROW][6],
        trace[SETLEAF_FINAL_ROW][7],
    ];
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let witness_felts = witness_to_felts(&value);
    let mut combined = tag_felts;
    combined.extend_from_slice(&witness_felts);
    let expected = trusset_circuits_common::hash_elements(&combined);
    assert_eq!(trace_setleaf, expected);
}

#[test]
fn full_trace_set_root_boundary_matches_off_air_root() {
    let (value, nonce, path, expected_root) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    let merkle_final = merkle_final_row_for_depth(path.len());
    let trace_root: [BaseElement; 4] = [
        trace[merkle_final][4],
        trace[merkle_final][5],
        trace[merkle_final][6],
        trace[merkle_final][7],
    ];
    assert_eq!(
        trace_root, expected_root,
        "state[4..8] at depth-dependent boundary row must equal off-AIR set_root"
    );
}

#[test]
fn full_trace_witness_binding_columns_constant_across_all_rows() {
    let (value, nonce, path, _) = fixture_witness(1);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    let witness_felts = witness_to_felts(&value);
    for k in 0..TRACE_LENGTH {
        for c in 0..MAX_PADDED_WITNESS_FELTS {
            assert_eq!(
                trace[k][COL_WITNESS_START + c],
                witness_felts[c],
                "witness col {} mismatch at row {}",
                c,
                k
            );
        }
    }
}

#[test]
fn full_trace_carry_at_level_0_setup_equals_set_leaf() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);

    // Carry at row 90 (level 0 setup) must equal state[4..8] at row 89 (set_leaf).
    let set_leaf: [BaseElement; 4] = [
        trace[SETLEAF_FINAL_ROW][4],
        trace[SETLEAF_FINAL_ROW][5],
        trace[SETLEAF_FINAL_ROW][6],
        trace[SETLEAF_FINAL_ROW][7],
    ];
    let carry_at_level_0: [BaseElement; 4] = [
        trace[MERKLE_ROW_START][COL_CARRY_START],
        trace[MERKLE_ROW_START][COL_CARRY_START + 1],
        trace[MERKLE_ROW_START][COL_CARRY_START + 2],
        trace[MERKLE_ROW_START][COL_CARRY_START + 3],
    ];
    assert_eq!(
        carry_at_level_0, set_leaf,
        "current_node_carry at level 0 setup must equal set_leaf"
    );
}

#[test]
fn full_trace_carry_at_level_k_equals_merged_node_from_level_k_minus_1() {
    // Use a depth-8 tree (256 leaves) so we have plenty of levels to test.
    let raw: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("L{:03}", i).into_bytes())
        .collect();
    let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    let (_, depth, leaves) = build_padded_set_tree(&refs);
    assert_eq!(depth, 8);
    let target_idx = 42;
    let path = padded_inclusion_path(&leaves, target_idx);

    let trace = build_full_stage16_trace(&raw[target_idx], &[0x77; 32], &path);

    // For each level k in 1..depth, carry at the level's setup row
    // must equal state[4..8] at the end of the prior level.
    for k in 1..(depth as usize) {
        let setup_row = MERKLE_ROW_START + k * MERGE_ROWS_PER_LEVEL;
        let prior_end_row = setup_row - 1;
        let carry_at_k: [BaseElement; 4] = [
            trace[setup_row][COL_CARRY_START],
            trace[setup_row][COL_CARRY_START + 1],
            trace[setup_row][COL_CARRY_START + 2],
            trace[setup_row][COL_CARRY_START + 3],
        ];
        let merged_from_prior: [BaseElement; 4] = [
            trace[prior_end_row][4],
            trace[prior_end_row][5],
            trace[prior_end_row][6],
            trace[prior_end_row][7],
        ];
        assert_eq!(
            carry_at_k,
            merged_from_prior,
            "carry at level {} setup must equal merged node from level {}",
            k,
            k - 1
        );
    }
}

#[test]
fn full_trace_carry_constant_within_each_level() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    for level in 0..path.len() {
        let level_start = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        let level_end = level_start + MERGE_ROWS_PER_LEVEL - 1;
        for c in 0..4 {
            let initial = trace[level_start][COL_CARRY_START + c];
            for k in level_start..=level_end {
                assert_eq!(
                    trace[k][COL_CARRY_START + c],
                    initial,
                    "carry col {} drifted at row {} within level {}",
                    c,
                    k,
                    level
                );
            }
        }
    }
}

#[test]
fn full_trace_side_bit_boolean_at_each_level_setup() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    for (level, step) in path.iter().enumerate() {
        let setup_row = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        let side = trace[setup_row][COL_SIDE_BIT];
        // side ∈ {0, 1}
        let is_bool = side == BaseElement::ZERO || side == BaseElement::ONE;
        assert!(is_bool, "side at level {} not boolean", level);
        // matches the off-AIR step.side
        assert_eq!(side, BaseElement::new(u64::from(step.side.as_u8())));
    }
}

#[test]
fn full_trace_sibling_cols_at_setup_equal_path_step_sibling() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    for (level, step) in path.iter().enumerate() {
        let setup_row = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        for c in 0..4 {
            assert_eq!(
                trace[setup_row][COL_SIBLING_START + c],
                step.sibling[c],
                "sibling col {} at level {} setup mismatch",
                c,
                level
            );
        }
    }
}

#[test]
fn full_trace_stall_padding_holds_final_row_content() {
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);
    let merkle_final = merkle_final_row_for_depth(path.len());
    // Rows past merkle_final should equal trace[merkle_final] in cols 0..12.
    for k in (merkle_final + 1)..TRACE_LENGTH {
        for c in 0..12 {
            assert_eq!(
                trace[k][c], trace[merkle_final][c],
                "stall row {} col {} drifted from merkle_final",
                k, c
            );
        }
    }
}

#[test]
fn full_trace_handles_depth_8_tree_end_to_end() {
    let raw: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("L{:03}", i).into_bytes())
        .collect();
    let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    let (root, depth, leaves) = build_padded_set_tree(&refs);
    assert_eq!(depth, 8);

    for target_idx in &[0usize, 1, 7, 127, 255] {
        let path = padded_inclusion_path(&leaves, *target_idx);
        let trace = build_full_stage16_trace(&raw[*target_idx], &[0xab; 32], &path);
        let merkle_final = merkle_final_row_for_depth(path.len());
        let trace_root: [BaseElement; 4] = [
            trace[merkle_final][4],
            trace[merkle_final][5],
            trace[merkle_final][6],
            trace[merkle_final][7],
        ];
        assert_eq!(
            trace_root, root,
            "trace root mismatch for leaf {} at depth 8",
            target_idx
        );
    }
}

/// **End-to-end invariant**: a chained-walk through the carry band
/// (without using the build_merge_level_rows return value) reaches
/// the off-AIR root. This validates that the carry-column propagation
/// is the load-bearing connection between adjacent levels: an AIR
/// constraint that enforces `carry[next_level_setup] = state[4..8][prior_level_end]`
/// is sufficient to chain the walk all the way to set_root.
#[test]
fn full_trace_carry_chain_reaches_off_air_root() {
    let (value, nonce, path, expected_root) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);

    // Walk through the trace one level at a time, reading carry at each
    // level setup, computing merged digest via off-AIR primitive, and
    // confirming it matches state[4..8] at the level end.
    for (level, step) in path.iter().enumerate() {
        let setup_row = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        let end_row = setup_row + MERGE_ROWS_PER_LEVEL - 1;

        let carry: [BaseElement; 4] = [
            trace[setup_row][COL_CARRY_START],
            trace[setup_row][COL_CARRY_START + 1],
            trace[setup_row][COL_CARRY_START + 2],
            trace[setup_row][COL_CARRY_START + 3],
        ];
        let expected_merge = match step.side {
            trusset_circuit_set_membership::Side::Left => {
                hash_two_with_tag(&SET_NODE_TAG, &carry, &step.sibling)
            }
            trusset_circuit_set_membership::Side::Right => {
                hash_two_with_tag(&SET_NODE_TAG, &step.sibling, &carry)
            }
        };
        let actual_merge: [BaseElement; 4] = [
            trace[end_row][4],
            trace[end_row][5],
            trace[end_row][6],
            trace[end_row][7],
        ];
        assert_eq!(
            actual_merge, expected_merge,
            "in-trace merge result at level {} diverges from off-AIR hash_two_with_tag",
            level
        );
    }

    // Final state[4..8] at the last Merkle row equals the off-AIR root.
    let merkle_final = merkle_final_row_for_depth(path.len());
    let trace_root: [BaseElement; 4] = [
        trace[merkle_final][4],
        trace[merkle_final][5],
        trace[merkle_final][6],
        trace[merkle_final][7],
    ];
    assert_eq!(trace_root, expected_root);
}

#[test]
fn full_trace_side_and_sibling_constant_within_each_level() {
    // The AIR's per-column constancy constraints carry `side_bit` and
    // `sibling[0..4]` constant across each merge level's 30 rows.
    // This is required so the absorb_b transition (15 rows after setup)
    // can read the same side and sibling values that were witnessed
    // at the setup transition.
    //
    // Outside Merkle levels (rows 0..89 and stall padding), these
    // columns stay deterministically zero.
    let (value, nonce, path, _) = fixture_witness(2);
    let trace = build_full_stage16_trace(&value, &nonce, &path);

    // Within each level, side + sibling are constant.
    for level in 0..path.len() {
        let level_start = MERKLE_ROW_START + level * MERGE_ROWS_PER_LEVEL;
        let initial_side = trace[level_start][COL_SIDE_BIT];
        for k in 0..MERGE_ROWS_PER_LEVEL {
            assert_eq!(
                trace[level_start + k][COL_SIDE_BIT],
                initial_side,
                "side bit drifted at row {} within level {}",
                level_start + k,
                level
            );
            for c in 0..4 {
                assert_eq!(
                    trace[level_start + k][COL_SIBLING_START + c],
                    trace[level_start][COL_SIBLING_START + c],
                    "sibling col {} drifted at row {} within level {}",
                    c,
                    level_start + k,
                    level
                );
            }
        }
    }

    // Outside Merkle levels, side + sibling are zero.
    let merkle_final = merkle_final_row_for_depth(path.len());
    for k in 0..TRACE_LENGTH {
        let in_merkle = (MERKLE_ROW_START..=merkle_final).contains(&k);
        if in_merkle {
            continue;
        }
        assert_eq!(
            trace[k][COL_SIDE_BIT],
            BaseElement::ZERO,
            "side bit outside Merkle phase at row {} should be zero",
            k
        );
        for c in 0..4 {
            assert_eq!(
                trace[k][COL_SIBLING_START + c],
                BaseElement::ZERO,
                "sibling col {} outside Merkle phase at row {} should be zero",
                c,
                k
            );
        }
    }
}
