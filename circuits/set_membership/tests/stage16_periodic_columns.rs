//! Stage 16 work-in-progress — periodic-column reference, no AIR yet.
//!
//! Companion to `stage16_trace_shape.rs`. That file validated the trace
//! math (the row contents the AIR must enforce); this file validates the
//! periodic-column shape (the selectors and round constants the AIR will
//! reference inside `evaluate_transition`).
//!
//! Periodic columns in Winterfell are length-`TRACE_LENGTH` arrays
//! evaluated at the row index of each transition. The Stage 16 AIR needs
//! ~40 of them. Getting selectors firing at the exact right indices is
//! mechanical but error-prone — if a selector turns on one row early or
//! late, the AIR will accept malformed traces. The tests here are the
//! verified reference for the next-session AIR impl.
//!
//! Status: work-in-progress. The actual production AIR remains at Stage
//! 13. This file gives the next session a CI-validated periodic-column
//! builder it can drop into `Air::get_periodic_column_values`.

#![cfg(feature = "prod-proofs-set")]
// AIR-style explicit row indexing matches the spec math more directly
// than enumerate() and is the convention used by the production AIR
// files. Keeping it here keeps the reference style consistent.
#![allow(clippy::needless_range_loop)]

use trusset_circuits_common::{bytes_to_field, rescue_air, SET_LEAF_TAG, SET_NODE_TAG};
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// Stage 16 trace constants (mirrors stage16_trace_shape.rs). Some
// constants below are sourced from the design memo but unused in this
// particular file (they're cross-referenced by stage16_trace_shape.rs);
// keeping them here as a single source of truth.
#[allow(dead_code)]
const TRACE_LENGTH: usize = 2048;
#[allow(dead_code)]
const COMMIT_ROWS: usize = 45;
#[allow(dead_code)]
const SETLEAF_ROW_START: usize = 45;
#[allow(dead_code)]
const SETLEAF_FINAL_ROW: usize = 89;
const MERKLE_ROW_START: usize = 90;
const MERGE_ROWS_PER_LEVEL: usize = 30;
const MAX_SET_DEPTH: usize = 32;
const MAX_ACTIVE_ROW: usize = MERKLE_ROW_START + MAX_SET_DEPTH * MERGE_ROWS_PER_LEVEL; // 1050

/// Index into the periodic columns vector. The names match the design
/// memo Stage 16 addendum's periodic-column table.
mod periodic {
    pub const ARK_COMBINED_START: usize = 0; // 12 cols (per state position)
    pub const SEL_RESCUE_FIRST: usize = 12;
    pub const SEL_RESCUE_SECOND: usize = 13;
    pub const SEL_PAD: usize = 14;
    pub const SEL_COMMIT_ABSORB1: usize = 15;
    pub const SEL_COMMIT_ABSORB2: usize = 16;
    pub const SEL_SETLEAF_SETUP: usize = 17;
    pub const SEL_SETLEAF_ABSORB1: usize = 18;
    pub const SEL_SETLEAF_ABSORB2: usize = 19;
    pub const SEL_MERGE_SETUP_A: usize = 20;
    pub const SEL_MERGE_ABSORB_B: usize = 21;
    pub const SEL_BIND_ROW_0: usize = 22;
    pub const SETLEAF_TAG_START: usize = 23; // 5 cols
    pub const NODE_TAG_START: usize = 28; // 5 cols
    pub const SEL_SET_ROOT_BOUNDARY: usize = 33;
    pub const TOTAL: usize = 34;
}

/// Build all Stage 16 periodic columns for a given `set_depth`. Returns
/// a vector of `TOTAL` columns, each of length `TRACE_LENGTH = 2048`.
///
/// **Design note**: `sel_walk_pad` and `sel_set_root_boundary` are
/// depth-dependent — the AIR construction reads `set_depth` from public
/// inputs and emits the corresponding periodic columns. Soundness
/// rationale: `set_depth` is a public input, so the verifier can
/// independently reconstruct the same periodic columns; no information
/// is leaked.
fn build_periodic_columns(set_depth: u8) -> Vec<Vec<BaseElement>> {
    assert!(
        (set_depth as usize) <= MAX_SET_DEPTH,
        "set_depth must be ≤ MAX_SET_DEPTH"
    );
    let depth = set_depth as usize;

    let mut cols: Vec<Vec<BaseElement>> = (0..periodic::TOTAL)
        .map(|_| vec![BaseElement::ZERO; TRACE_LENGTH])
        .collect();

    // -------- Rescue selectors (first / second / pad) --------
    //
    // Commitment phase (rows 0..44): 3 Rescue blocks each spanning 14
    // sub-round transitions. The block boundary transitions (14, 29, 44)
    // are absorption rows where neither first nor second fires.
    //
    // Set_leaf phase (rows 45..89): 3 Rescue blocks. The transition at
    // row 44 is the commitment→setleaf setup row (state[0]=17 etc.), so
    // it's not a Rescue sub-round. Blocks span rows 45..59, 60..74, 75..89.
    //
    // Merkle phase (rows 90..89+30*depth): 2 Rescue blocks per level,
    // each spanning 14 sub-rounds, with a setup_a row at the start and
    // an absorb_b row in the middle.
    //
    // Stall rows (90+30*depth onwards): sel_pad fires.
    let block_starts: Vec<usize> = build_block_starts(depth);
    for &block_start in &block_starts {
        // Each block has 14 sub-round transitions starting at
        // block_start: rows block_start..block_start+14, alternating
        // first-half (even index within block) and second-half (odd).
        for sub in 0..14 {
            let row = block_start + sub;
            if sub % 2 == 0 {
                cols[periodic::SEL_RESCUE_FIRST][row] = BaseElement::ONE;
            } else {
                cols[periodic::SEL_RESCUE_SECOND][row] = BaseElement::ONE;
            }
        }
    }

    // -------- ARK combined (12 cols, multiplexed by sub-round) --------
    //
    // At each first-half transition, ARK1[round_within_permutation] applies.
    // At each second-half transition, ARK2[round_within_permutation] applies.
    // The AIR's transition constraint reads these as a single 12-col band.
    for &block_start in &block_starts {
        for round in 0..rescue_air::NUM_ROUNDS {
            let row_first = block_start + 2 * round;
            let row_second = block_start + 2 * round + 1;
            for i in 0..rescue_air::STATE_WIDTH {
                cols[periodic::ARK_COMBINED_START + i][row_first] = rescue_air::ARK1[round][i];
                cols[periodic::ARK_COMBINED_START + i][row_second] = rescue_air::ARK2[round][i];
            }
        }
    }

    // -------- Commitment absorption selectors --------
    // sel_commit_absorb1 fires at transition 14 (block 1 → 2).
    // sel_commit_absorb2 fires at transition 29 (block 2 → 3).
    cols[periodic::SEL_COMMIT_ABSORB1][14] = BaseElement::ONE;
    cols[periodic::SEL_COMMIT_ABSORB2][29] = BaseElement::ONE;

    // -------- Set_leaf setup + absorption selectors --------
    // sel_setleaf_setup fires at transition 44 (commitment end → set_leaf row 45 setup).
    cols[periodic::SEL_SETLEAF_SETUP][44] = BaseElement::ONE;
    // sel_setleaf_absorb1 fires at transition 59 (block 1 → 2 within setleaf phase).
    cols[periodic::SEL_SETLEAF_ABSORB1][59] = BaseElement::ONE;
    // sel_setleaf_absorb2 fires at transition 74 (block 2 → 3 within setleaf phase).
    cols[periodic::SEL_SETLEAF_ABSORB2][74] = BaseElement::ONE;

    // -------- Merkle setup / absorb selectors (depth-dependent) --------
    // For each level k in 0..depth:
    //   - sel_merge_setup_a fires at transition (MERKLE_ROW_START - 1) + k*30 = 89 + 30*k
    //     (the transition INTO row 90 + 30*k, which is the setup_a row)
    //   - sel_merge_absorb_b fires at transition (MERKLE_ROW_START + 14) + k*30 = 104 + 30*k
    for k in 0..depth {
        let setup_a_transition = MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL;
        let absorb_b_transition = MERKLE_ROW_START + 14 + k * MERGE_ROWS_PER_LEVEL;
        if setup_a_transition < TRACE_LENGTH {
            cols[periodic::SEL_MERGE_SETUP_A][setup_a_transition] = BaseElement::ONE;
        }
        if absorb_b_transition < TRACE_LENGTH {
            cols[periodic::SEL_MERGE_ABSORB_B][absorb_b_transition] = BaseElement::ONE;
        }
    }

    // -------- Set_root boundary --------
    // Fires at the LAST transition of the Merkle walk:
    //   merkle_final_row = MERKLE_ROW_START + depth*30 - 1 = 89 + 30*depth
    // sel_set_root_boundary fires at this row index.
    let merkle_final_row = MERKLE_ROW_START + depth * MERGE_ROWS_PER_LEVEL - 1;
    if merkle_final_row < TRACE_LENGTH {
        cols[periodic::SEL_SET_ROOT_BOUNDARY][merkle_final_row] = BaseElement::ONE;
    }

    // -------- Stall padding --------
    // sel_pad fires at every transition from merkle_final_row onwards
    // (rows where the trace state is constant — next equals current).
    // Note: the transition at merkle_final_row itself is where set_root
    // gets asserted, then everything past that stalls until trace end.
    let pad_start = merkle_final_row + 1;
    let pad_end = TRACE_LENGTH - 1;
    if pad_start < pad_end {
        for cell in cols[periodic::SEL_PAD][pad_start..pad_end].iter_mut() {
            *cell = BaseElement::ONE;
        }
    }

    // -------- Row-0 binding selector --------
    // sel_bind_row_0 fires at transition 0 only (state[11][0] = witness_col[0]).
    cols[periodic::SEL_BIND_ROW_0][0] = BaseElement::ONE;

    // -------- Domain tag felts --------
    // setleaf_tag_felts[0..5] injected at transition 44 (the setleaf setup row).
    let setleaf_tag = bytes_to_field(&SET_LEAF_TAG);
    for i in 0..5 {
        cols[periodic::SETLEAF_TAG_START + i][44] = setleaf_tag[i];
    }

    // node_tag_felts[0..5] injected at each merge_setup_a transition.
    let node_tag = bytes_to_field(&SET_NODE_TAG);
    for k in 0..depth {
        let setup_a_transition = MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL;
        if setup_a_transition < TRACE_LENGTH {
            for i in 0..5 {
                cols[periodic::NODE_TAG_START + i][setup_a_transition] = node_tag[i];
            }
        }
    }

    cols
}

/// Block-start row indices for every Rescue absorption block in the
/// trace, given a depth.
///
/// Commitment phase: blocks at rows 0, 15, 30 (3 blocks).
/// Set_leaf phase: blocks at rows 45, 60, 75 (3 blocks).
/// Merkle phase: for each level k in 0..depth, blocks at rows
///   90 + 30*k and 90 + 30*k + 15 (2 blocks per level).
fn build_block_starts(depth: usize) -> Vec<usize> {
    let mut starts = vec![0usize, 15, 30, 45, 60, 75];
    for k in 0..depth {
        let level_start = MERKLE_ROW_START + k * MERGE_ROWS_PER_LEVEL;
        starts.push(level_start);
        starts.push(level_start + 15);
    }
    starts
}

// --------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------

#[test]
fn periodic_columns_have_correct_count_and_length() {
    let cols = build_periodic_columns(8);
    assert_eq!(cols.len(), periodic::TOTAL);
    for (i, col) in cols.iter().enumerate() {
        assert_eq!(col.len(), TRACE_LENGTH, "column {} wrong length", i);
    }
}

#[test]
fn rescue_first_second_selectors_partition_sub_rounds() {
    let cols = build_periodic_columns(8);
    let depth: usize = 8;
    // Total expected sub-rounds:
    //   Commitment: 3 blocks × 14 = 42
    //   Set_leaf:   3 blocks × 14 = 42
    //   Merkle:     2 × depth blocks × 14 = 14 * 2 * 8 = 224
    let expected_sub_rounds = 3 * 14 + 3 * 14 + 2 * depth * 14;

    let first_count: usize = cols[periodic::SEL_RESCUE_FIRST]
        .iter()
        .filter(|&&v| v == BaseElement::ONE)
        .count();
    let second_count: usize = cols[periodic::SEL_RESCUE_SECOND]
        .iter()
        .filter(|&&v| v == BaseElement::ONE)
        .count();

    assert_eq!(first_count, expected_sub_rounds / 2);
    assert_eq!(second_count, expected_sub_rounds / 2);
    assert_eq!(first_count + second_count, expected_sub_rounds);
}

#[test]
fn rescue_first_and_second_selectors_are_mutually_exclusive() {
    let cols = build_periodic_columns(32);
    for row in 0..TRACE_LENGTH {
        let f = cols[periodic::SEL_RESCUE_FIRST][row];
        let s = cols[periodic::SEL_RESCUE_SECOND][row];
        assert!(
            !(f == BaseElement::ONE && s == BaseElement::ONE),
            "first and second selectors both fire at row {}",
            row
        );
    }
}

#[test]
fn commit_absorb_selectors_fire_at_exact_transitions() {
    let cols = build_periodic_columns(8);
    // sel_commit_absorb1 fires only at row 14.
    for row in 0..TRACE_LENGTH {
        let want = row == 14;
        let got = cols[periodic::SEL_COMMIT_ABSORB1][row] == BaseElement::ONE;
        assert_eq!(got, want, "sel_commit_absorb1[{}] mismatch", row);
    }
    // sel_commit_absorb2 fires only at row 29.
    for row in 0..TRACE_LENGTH {
        let want = row == 29;
        let got = cols[periodic::SEL_COMMIT_ABSORB2][row] == BaseElement::ONE;
        assert_eq!(got, want, "sel_commit_absorb2[{}] mismatch", row);
    }
}

#[test]
fn setleaf_setup_and_absorb_selectors_fire_at_exact_transitions() {
    let cols = build_periodic_columns(8);
    let cases = [
        (periodic::SEL_SETLEAF_SETUP, 44usize, "sel_setleaf_setup"),
        (periodic::SEL_SETLEAF_ABSORB1, 59, "sel_setleaf_absorb1"),
        (periodic::SEL_SETLEAF_ABSORB2, 74, "sel_setleaf_absorb2"),
    ];
    for (idx, expected_row, name) in &cases {
        for row in 0..TRACE_LENGTH {
            let want = row == *expected_row;
            let got = cols[*idx][row] == BaseElement::ONE;
            assert_eq!(got, want, "{}[{}] mismatch", name, row);
        }
    }
}

#[test]
fn merge_setup_a_selectors_fire_at_every_level_for_depth_32() {
    let depth = 32u8;
    let cols = build_periodic_columns(depth);
    let mut expected: Vec<usize> = Vec::new();
    for k in 0..(depth as usize) {
        expected.push(MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL);
    }
    // Verify each expected row has selector=1 and no others do.
    let fired: Vec<usize> = (0..TRACE_LENGTH)
        .filter(|&row| cols[periodic::SEL_MERGE_SETUP_A][row] == BaseElement::ONE)
        .collect();
    assert_eq!(fired, expected, "sel_merge_setup_a fires at wrong rows");
}

#[test]
fn merge_absorb_b_selectors_fire_at_every_level_for_depth_32() {
    let depth = 32u8;
    let cols = build_periodic_columns(depth);
    let mut expected: Vec<usize> = Vec::new();
    for k in 0..(depth as usize) {
        expected.push(MERKLE_ROW_START + 14 + k * MERGE_ROWS_PER_LEVEL);
    }
    let fired: Vec<usize> = (0..TRACE_LENGTH)
        .filter(|&row| cols[periodic::SEL_MERGE_ABSORB_B][row] == BaseElement::ONE)
        .collect();
    assert_eq!(fired, expected);
}

#[test]
fn merge_selectors_truncate_at_low_depth() {
    // For depth=2, only 2 levels of Merkle merges → selectors fire only
    // at the first 2 instances.
    let cols = build_periodic_columns(2);
    let setup_a_count = cols[periodic::SEL_MERGE_SETUP_A]
        .iter()
        .filter(|&&v| v == BaseElement::ONE)
        .count();
    let absorb_b_count = cols[periodic::SEL_MERGE_ABSORB_B]
        .iter()
        .filter(|&&v| v == BaseElement::ONE)
        .count();
    assert_eq!(setup_a_count, 2);
    assert_eq!(absorb_b_count, 2);
}

#[test]
fn set_root_boundary_fires_at_depth_dependent_row() {
    for depth in [1u8, 2, 8, 16, 32] {
        let cols = build_periodic_columns(depth);
        let expected_row = MERKLE_ROW_START + (depth as usize) * MERGE_ROWS_PER_LEVEL - 1;
        let fired: Vec<usize> = (0..TRACE_LENGTH)
            .filter(|&row| cols[periodic::SEL_SET_ROOT_BOUNDARY][row] == BaseElement::ONE)
            .collect();
        assert_eq!(
            fired,
            vec![expected_row],
            "set_root boundary at wrong row for depth {}",
            depth
        );
        assert!(expected_row <= MAX_ACTIVE_ROW);
    }
}

#[test]
fn pad_selector_fires_after_set_root_boundary() {
    let depth = 8u8;
    let cols = build_periodic_columns(depth);
    let merkle_final_row = MERKLE_ROW_START + (depth as usize) * MERGE_ROWS_PER_LEVEL - 1;
    for row in 0..TRACE_LENGTH {
        let pad_fires = cols[periodic::SEL_PAD][row] == BaseElement::ONE;
        let should_fire = row > merkle_final_row && row < TRACE_LENGTH - 1;
        assert_eq!(pad_fires, should_fire, "sel_pad[{}] mismatch", row);
    }
}

#[test]
fn bind_row_0_fires_only_at_transition_0() {
    let cols = build_periodic_columns(8);
    for row in 0..TRACE_LENGTH {
        let want = row == 0;
        let got = cols[periodic::SEL_BIND_ROW_0][row] == BaseElement::ONE;
        assert_eq!(got, want, "sel_bind_row_0[{}] mismatch", row);
    }
}

#[test]
fn setleaf_tag_felts_appear_at_setup_row_only() {
    let cols = build_periodic_columns(8);
    let expected_tag = bytes_to_field(&SET_LEAF_TAG);
    for tag_i in 0..5 {
        let col = &cols[periodic::SETLEAF_TAG_START + tag_i];
        for row in 0..TRACE_LENGTH {
            let want = if row == 44 {
                expected_tag[tag_i]
            } else {
                BaseElement::ZERO
            };
            assert_eq!(col[row], want, "setleaf_tag[{}][{}] mismatch", tag_i, row);
        }
    }
}

#[test]
fn node_tag_felts_appear_at_every_merge_setup_for_depth_8() {
    let depth = 8u8;
    let cols = build_periodic_columns(depth);
    let expected_tag = bytes_to_field(&SET_NODE_TAG);
    for tag_i in 0..5 {
        let col = &cols[periodic::NODE_TAG_START + tag_i];
        let mut expected_rows: Vec<usize> = Vec::new();
        for k in 0..(depth as usize) {
            expected_rows.push(MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL);
        }
        for row in 0..TRACE_LENGTH {
            let want = if expected_rows.contains(&row) {
                expected_tag[tag_i]
            } else {
                BaseElement::ZERO
            };
            assert_eq!(col[row], want, "node_tag[{}][{}] mismatch", tag_i, row);
        }
    }
}

#[test]
fn ark_combined_values_at_first_sub_round_match_ark1_round_0() {
    // At transition 0 (first sub-round of commitment block 1), the
    // ark_combined columns must carry ARK1[round=0][i].
    let cols = build_periodic_columns(8);
    for i in 0..rescue_air::STATE_WIDTH {
        let want = rescue_air::ARK1[0][i];
        let got = cols[periodic::ARK_COMBINED_START + i][0];
        assert_eq!(got, want, "ARK1[0][{}] mismatch at row 0", i);
    }
    // At transition 1 (second-half of round 0), ark_combined carries ARK2[0][i].
    for i in 0..rescue_air::STATE_WIDTH {
        let want = rescue_air::ARK2[0][i];
        let got = cols[periodic::ARK_COMBINED_START + i][1];
        assert_eq!(got, want, "ARK2[0][{}] mismatch at row 1", i);
    }
}

#[test]
fn ark_combined_values_at_setleaf_block_boundary_reset() {
    // At transition 45 (first sub-round of set_leaf block 1), the
    // ark_combined columns must reset to ARK1[0][i] — the Rescue
    // permutation starts a fresh schedule at every block.
    let cols = build_periodic_columns(8);
    for i in 0..rescue_air::STATE_WIDTH {
        let want = rescue_air::ARK1[0][i];
        let got = cols[periodic::ARK_COMBINED_START + i][45];
        assert_eq!(
            got, want,
            "ARK at set_leaf block start (row 45) should reset to ARK1[0][{}]",
            i
        );
    }
}

#[test]
fn ark_combined_values_at_merge_block_boundaries_reset() {
    // At every merge level's row 90 + 30*k (block 1 first sub-round)
    // and row 105 + 30*k (block 2 first sub-round), ark must be ARK1[0][i].
    let cols = build_periodic_columns(32);
    for k in 0..32 {
        for offset in &[0usize, 15] {
            let row = MERKLE_ROW_START + k * MERGE_ROWS_PER_LEVEL + offset;
            if row >= TRACE_LENGTH {
                continue;
            }
            for i in 0..rescue_air::STATE_WIDTH {
                let want = rescue_air::ARK1[0][i];
                let got = cols[periodic::ARK_COMBINED_START + i][row];
                assert_eq!(
                    got, want,
                    "ARK at merge block (level {}, row {}) should reset to ARK1[0][{}]",
                    k, row, i
                );
            }
        }
    }
}

#[test]
fn block_starts_partition_active_trace_rows() {
    // The block_starts helper must produce exactly the right block-entry
    // row indices.
    let starts = build_block_starts(8);
    let expected: Vec<usize> = vec![
        0, 15, 30, // commitment blocks
        45, 60, 75, // set_leaf blocks
        90, 105, // level 0
        120, 135, // level 1
        150, 165, // level 2
        180, 195, // level 3
        210, 225, // level 4
        240, 255, // level 5
        270, 285, // level 6
        300, 315, // level 7
    ];
    assert_eq!(starts, expected);
}
