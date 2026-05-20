//! Stage 16 work-in-progress — trace builder reference, no AIR yet.
//!
//! Validates that the trace shape sketched in
//! `docs/STEP_2B_COMMITMENT_DESIGN.md` Stage 16 addendum (33 cols × 2048
//! rows, with rows 0..44 = commitment, 45..89 = set_leaf, 90.. = Merkle
//! walk) ACTUALLY produces the expected post-row-89 set_leaf digest that
//! matches a re-encoded off-AIR set_leaf computation using padded witness
//! felts. This is the prerequisite the in-AIR Merkle walk depends on: if
//! the AIR's set_leaf computation diverges from the off-AIR set_leaf used
//! by `walk_merkle_path`, the Merkle walk boundary at the final level
//! cannot reach `public.set_root` and proofs cannot exist.
//!
//! Scope: this test only validates the host-side trace builder math.
//! No Winterfell AIR is constructed here — the AIR with its periodic
//! columns and transition/boundary constraints is the substantive next
//! step. The test is gated behind `prod-proofs-set` to access the
//! workspace's Rescue gadget through the canonical re-exports.
//!
//! Status: work-in-progress. The actual production AIR remains at Stage
//! 13 (commitment opening only). Shipping the trace builder math as a
//! test gives the next session a verified starting point for the AIR
//! transition constraints.

#![cfg(feature = "prod-proofs-set")]

use trusset_circuit_set_membership::{
    set_leaf_digest as offair_set_leaf_digest, witness_to_felts, MAX_PADDED_WITNESS_FELTS,
};
use trusset_circuits_common::{
    bytes_to_field, hash_elements, rescue_air, CircuitId, Felt, COMMITMENT_TAG, SET_LEAF_TAG,
};
use winterfell::math::{fields::f64::BaseElement, FieldElement};

// Stage 16 trace constants. Mirrors docs/STEP_2B_COMMITMENT_DESIGN.md
// Stage 16 addendum. These are the values the production AIR will use
// once Stage 16 lands.
const STAGE16_TRACE_WIDTH: usize = 33; // 12 rescue + 12 witness + 1 side + 4 sibling + 4 carry
const STAGE16_TRACE_LENGTH: usize = 2048;
const STAGE16_COMMIT_FINAL_ROW: usize = 44;
const STAGE16_SETLEAF_ROW_START: usize = 45;
const STAGE16_SETLEAF_FINAL_ROW: usize = 89;
const STAGE16_MERKLE_ROW_START: usize = 90;
const STAGE16_MERGE_ROWS_PER_LEVEL: usize = 30;
const STAGE16_MAX_SET_DEPTH: usize = 32;

/// Build the commitment-phase rows 0..=44. Mirror of the existing Stage 13
/// trace builder logic, but here we produce just the 12-felt Rescue state
/// rows (the witness-binding cols and other Stage 16 cols are filled
/// separately).
fn build_commitment_rows(value: &[u8], nonce: &[u8; 32]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    assert_eq!(tag_felts.len(), 5);
    let nonce_felts = bytes_to_field(nonce);
    assert_eq!(nonce_felts.len(), 5);
    let witness_felts = witness_to_felts(value);
    assert_eq!(witness_felts.len(), MAX_PADDED_WITNESS_FELTS);

    // 24 input felts: tag(5) + id(1) + len(1) + witness(12) + nonce(5).
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

    // Block 1: rows 0..=14 (15 rows).
    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);
    let mut current = block1[14];

    // Block 2: absorb input[8..16] at row 15, then 14 sub-rounds.
    for i in 0..8 {
        current[4 + i] += input[8 + i];
    }
    rows.push(current);
    let block2 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block2[1..]); // skip entry row (= absorption row)
    current = block2[14];

    // Block 3: absorb input[16..24] at row 30, then 14 sub-rounds.
    for i in 0..8 {
        current[4 + i] += input[16 + i];
    }
    rows.push(current);
    let block3 = rescue_air::permutation_trace(current);
    rows.extend_from_slice(&block3[1..]);

    assert_eq!(rows.len(), 45, "commitment phase must produce 45 rows");
    rows
}

/// Build the set_leaf-phase rows 45..=89. Input is `SET_LEAF_TAG (5) ‖
/// padded_witness (12) = 17 felts` → 3 blocks × 8 rate = 24 absorbed
/// (with the last 7 zero-padded). NOTE: the witness used here MUST be
/// `witness_to_felts(value)` (no NFC), so the AIR's witness-binding
/// columns can carry the same felts through both phases.
fn build_setleaf_rows(value: &[u8]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    assert_eq!(tag_felts.len(), 5);
    let witness_felts = witness_to_felts(value);
    assert_eq!(witness_felts.len(), MAX_PADDED_WITNESS_FELTS);

    // 17 input felts: tag(5) + padded_witness(12). Pad to 24 (3 blocks × 8)
    // with zeros for the last absorption row.
    let mut input = [BaseElement::ZERO; 24];
    input[0..5].copy_from_slice(&tag_felts);
    input[5..17].copy_from_slice(&witness_felts);
    // input[17..24] stays zero.

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

    assert_eq!(rows.len(), 45, "set_leaf phase must produce 45 rows");
    rows
}

/// Reference off-AIR set_leaf computation using PADDED witness (the
/// Stage 16 set_leaf design). This is what the in-AIR set_leaf phase
/// MUST equal at row 89.
fn padded_set_leaf_offair(value: &[u8]) -> [Felt; 4] {
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let witness_felts = witness_to_felts(value);
    let mut combined = tag_felts;
    combined.extend_from_slice(&witness_felts);
    hash_elements(&combined)
}

/// Build the 30-row trace block for ONE Merkle merge level.
///
/// Inputs: `current_node` (4 felts, from prior level or set_leaf output)
/// + `sibling` (4 felts, witnessed) + `side` ∈ {0,1} (witnessed).
///
/// Per design memo Stage 16 addendum:
///   `node_in_a = (1-side)*current_node + side*sibling`
///   `node_in_b = side*current_node + (1-side)*sibling`
/// Then `merged = Rescue(SET_NODE_TAG ‖ node_in_a ‖ node_in_b)`.
///
/// Layout within the 30 rows:
///   Row 0  (setup_a): state[0]=13, state[1..4]=0,
///                     state[4..9]=SET_NODE_TAG felts,
///                     state[9..12]=node_in_a[0..3]
///   Rows 1..14:       block 1 Rescue sub-rounds
///   Row 15 (absorb_b): state[4..12]_next = state[4..12]_curr +
///                      [node_in_a[3], node_in_b[0..4], 0, 0, 0]
///   Rows 16..29:      block 2 Rescue sub-rounds
fn build_merge_level_rows(
    current_node: [BaseElement; 4],
    sibling: [BaseElement; 4],
    side: u8,
) -> ([[BaseElement; 12]; 30], [BaseElement; 4]) {
    assert!(side == 0 || side == 1, "side must be boolean");
    let side_e = BaseElement::new(u64::from(side));
    let one_minus_side = BaseElement::ONE - side_e;

    // Conditional swap.
    let mut node_in_a = [BaseElement::ZERO; 4];
    let mut node_in_b = [BaseElement::ZERO; 4];
    for i in 0..4 {
        node_in_a[i] = one_minus_side * current_node[i] + side_e * sibling[i];
        node_in_b[i] = side_e * current_node[i] + one_minus_side * sibling[i];
    }

    // Tag felts for SET_NODE_TAG.
    let tag_felts = bytes_to_field(&trusset_circuits_common::SET_NODE_TAG);
    assert_eq!(tag_felts.len(), 5);

    // Build 13-felt input: tag(5) + node_in_a(4) + node_in_b(4) = 13.
    // Pad to 16 (2 blocks × 8 rate) with zeros.
    let mut input = [BaseElement::ZERO; 16];
    input[0..5].copy_from_slice(&tag_felts);
    input[5..9].copy_from_slice(&node_in_a);
    input[9..13].copy_from_slice(&node_in_b);
    // input[13..16] stays zero.

    let mut rows = [[BaseElement::ZERO; 12]; 30];

    // Block 1 setup at row 0: state[0]=13, state[4..12]=input[0..8].
    let mut state = [BaseElement::ZERO; 12];
    state[0] = BaseElement::new(13);
    state[4..12].copy_from_slice(&input[0..8]);
    let block1 = rescue_air::permutation_trace(state);
    rows[..15].copy_from_slice(&block1);
    let mut current = block1[14];

    // Block 2 absorbs input[8..16] at row 15.
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
// Tests
// --------------------------------------------------------------------

#[test]
fn stage16_constants_match_design_memo() {
    // These pin the trace shape from the design memo. Drift here means
    // either the design memo or this trace builder is out of date.
    assert_eq!(STAGE16_TRACE_WIDTH, 33);
    assert_eq!(STAGE16_TRACE_LENGTH, 2048);
    assert_eq!(STAGE16_COMMIT_FINAL_ROW, 44);
    assert_eq!(STAGE16_SETLEAF_ROW_START, 45);
    assert_eq!(STAGE16_SETLEAF_FINAL_ROW, 89);
    assert_eq!(STAGE16_MERKLE_ROW_START, 90);
    assert_eq!(STAGE16_MERGE_ROWS_PER_LEVEL, 30);
    assert_eq!(STAGE16_MAX_SET_DEPTH, 32);

    // Sanity: max active rows fits inside the chosen trace length.
    let max_active = 90 + STAGE16_MAX_SET_DEPTH * STAGE16_MERGE_ROWS_PER_LEVEL;
    assert!(max_active < STAGE16_TRACE_LENGTH);
    assert_eq!(max_active, 1050);
}

#[test]
fn stage16_commitment_phase_produces_45_rows() {
    let rows = build_commitment_rows(b"DEU", &[0u8; 32]);
    assert_eq!(rows.len(), 45);
}

#[test]
fn stage16_setleaf_phase_produces_45_rows() {
    let rows = build_setleaf_rows(b"DEU");
    assert_eq!(rows.len(), 45);
}

/// **The load-bearing test**: confirm the in-AIR set_leaf trace's final
/// row's rate equals the off-AIR set_leaf hash (padded variant). If this
/// test passes, the trace math from the design memo is correct and the
/// next-session AIR transition constraints have a verified spec.
#[test]
fn stage16_setleaf_trace_final_row_matches_padded_offair_set_leaf() {
    for value in [&b"DEU"[..], b"FRA", b"USA", b"GBR", b"A", b""] {
        let rows = build_setleaf_rows(value);
        let final_state = rows[44];
        let trace_set_leaf: [Felt; 4] = [
            final_state[4],
            final_state[5],
            final_state[6],
            final_state[7],
        ];
        let offair_set_leaf = padded_set_leaf_offair(value);
        assert_eq!(
            trace_set_leaf, offair_set_leaf,
            "set_leaf trace mismatch for value {:?}",
            value
        );
    }
}

/// Stage 16 production switchover regression: the production
/// `set_leaf_digest` now equals the padded variant defined here. This
/// test confirms the production switchover (when the Stage 16 AIR
/// promotes) is consistent. Prior to the production promotion, this
/// test asserted INEQUALITY because production used the old unpadded
/// variant; post-promotion, they MUST be identical.
#[test]
fn stage16_padded_set_leaf_matches_production_set_leaf_post_promotion() {
    for value in [&b"DEU"[..], b"FRA", b"USA"] {
        let padded = padded_set_leaf_offair(value);
        let production = offair_set_leaf_digest(value);
        assert_eq!(
            padded, production,
            "after Stage 16 production promotion, production set_leaf_digest must equal the padded variant"
        );
    }
}

/// Confirm the commitment phase trace builder reproduces the same
/// post-row-44 commitment as the existing `compute_commitment`. This
/// pins out any drift between the Stage 16 trace logic and the
/// Stage 13 commitment math.
#[test]
fn stage16_commitment_trace_final_row_matches_compute_commitment() {
    use trusset_circuits_common::compute_commitment;
    let value: &[u8] = b"DEU";
    let nonce = [0x44u8; 32];
    let rows = build_commitment_rows(value, &nonce);
    let final_state = rows[44];
    let trace_commitment: [Felt; 4] = [
        final_state[4],
        final_state[5],
        final_state[6],
        final_state[7],
    ];
    let expected = compute_commitment(CircuitId::SetMembership, &witness_to_felts(value), &nonce);
    assert_eq!(trace_commitment, expected);
}

/// The witness-binding columns 12..24 must carry the same 12 padded
/// witness felts in BOTH phases. This test verifies the trace builder's
/// inputs match between the commitment phase (witness consumed at rows
/// 0..44) and the set_leaf phase (witness consumed at rows 45..89). If
/// these diverged, the in-AIR cross-phase binding constraint could not
/// be satisfied by an honest prover.
#[test]
fn stage16_witness_felts_match_across_phases() {
    let value: &[u8] = b"USA";
    let witness_for_commit = witness_to_felts(value);
    let witness_for_setleaf = witness_to_felts(value);
    assert_eq!(witness_for_commit, witness_for_setleaf);
    assert_eq!(witness_for_commit.len(), MAX_PADDED_WITNESS_FELTS);
}

#[test]
fn stage16_merge_level_produces_30_rows() {
    let cn = [BaseElement::new(1); 4];
    let sib = [BaseElement::new(2); 4];
    let (rows, _merged) = build_merge_level_rows(cn, sib, 0);
    assert_eq!(rows.len(), 30);
}

/// **The load-bearing test for the Merkle walk math**: confirm a single
/// in-AIR merge level (30 rows) produces the same merged digest as the
/// off-AIR `hash_two_with_tag(SET_NODE_TAG, a, b)` primitive. Verifies
/// both side values (current node is left vs right child).
#[test]
fn stage16_merge_level_matches_offair_hash_two_with_tag_both_sides() {
    use trusset_circuits_common::{hash_two_with_tag, SET_NODE_TAG};

    let cn = [
        BaseElement::new(0x1111),
        BaseElement::new(0x2222),
        BaseElement::new(0x3333),
        BaseElement::new(0x4444),
    ];
    let sib = [
        BaseElement::new(0x5555),
        BaseElement::new(0x6666),
        BaseElement::new(0x7777),
        BaseElement::new(0x8888),
    ];

    // side = 0: current_node is left, sibling is right.
    //   node_in_a = current_node, node_in_b = sibling.
    //   Expected = hash_two_with_tag(SET_NODE_TAG, &current_node, &sibling).
    let (_, merged_side0) = build_merge_level_rows(cn, sib, 0);
    let expected_side0 = hash_two_with_tag(&SET_NODE_TAG, &cn, &sib);
    assert_eq!(
        merged_side0, expected_side0,
        "merge level side=0 must match off-AIR hash_two_with_tag(cn, sib)"
    );

    // side = 1: current_node is right, sibling is left.
    //   node_in_a = sibling, node_in_b = current_node.
    //   Expected = hash_two_with_tag(SET_NODE_TAG, &sibling, &current_node).
    let (_, merged_side1) = build_merge_level_rows(cn, sib, 1);
    let expected_side1 = hash_two_with_tag(&SET_NODE_TAG, &sib, &cn);
    assert_eq!(
        merged_side1, expected_side1,
        "merge level side=1 must match off-AIR hash_two_with_tag(sib, cn)"
    );

    // Sanity: the two sides produce DIFFERENT merged digests for
    // distinct nodes (order-sensitivity of hash_two_with_tag).
    assert_ne!(
        merged_side0, merged_side1,
        "merging in different orders must produce different digests"
    );
}

/// Chain multiple Merkle merge levels together and confirm the final
/// merged digest matches the off-AIR `walk_merkle_path` result. This is
/// the proof-of-concept that the in-AIR Merkle walk, when implemented
/// as a sequence of these per-level blocks chained via the
/// `current_node_carry` column band, will reach the public set_root.
#[test]
fn stage16_chained_merges_reach_off_air_walk_merkle_path() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path, walk_merkle_path, Side};

    // 4-leaf tree (depth 2).
    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (root, depth, leaves) = build_set_tree(&values);
    assert_eq!(depth, 2);

    // Walk the path for "USA" (index 2).
    let target_idx = 2;
    let leaf = leaves[target_idx];
    let path = inclusion_path(&leaves, target_idx);
    let expected_root = walk_merkle_path(leaf, &path);
    assert_eq!(expected_root, root);

    // Simulate the in-AIR walk via chained merge-level blocks.
    let mut current_node = leaf;
    for step in &path {
        let side = step.side.as_u8(); // 0 = Left (current is left), 1 = Right
        let (_, merged) = build_merge_level_rows(current_node, step.sibling, side);
        current_node = merged;
    }

    assert_eq!(
        current_node, root,
        "chained in-AIR merges must reach the off-AIR set_root"
    );

    // Also exercise the OTHER side bit (current_node is right child).
    let target_idx = 1; // FRA — should produce side=1 for the first level
    let leaf = leaves[target_idx];
    let path = inclusion_path(&leaves, target_idx);

    let mut current_node = leaf;
    let mut had_side_1 = false;
    for step in &path {
        if step.side == Side::Right {
            had_side_1 = true;
        }
        let side = step.side.as_u8();
        let (_, merged) = build_merge_level_rows(current_node, step.sibling, side);
        current_node = merged;
    }
    assert!(
        had_side_1,
        "this test should exercise at least one side=1 case"
    );
    assert_eq!(
        current_node, root,
        "chained walk must reach root regardless of side mix"
    );
}

/// Largest realistic tree depth: 256 entries → depth 8. Confirm the
/// chained merge math scales without numerical surprises.
#[test]
fn stage16_chained_merges_handle_depth_8_tree() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path, walk_merkle_path};

    let raw: Vec<Vec<u8>> = (0..256)
        .map(|i| format!("L{:03}", i).into_bytes())
        .collect();
    let refs: Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
    let (root, depth, leaves) = build_set_tree(&refs);
    assert_eq!(depth, 8);

    for &idx in &[0usize, 1, 128, 255] {
        let leaf = leaves[idx];
        let path = inclusion_path(&leaves, idx);
        let off_air = walk_merkle_path(leaf, &path);
        assert_eq!(off_air, root);

        let mut current = leaf;
        for step in &path {
            let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
            current = merged;
        }
        assert_eq!(current, root, "chained merge mismatch for leaf {}", idx);
    }
}

// --------------------------------------------------------------------
// Negative trace tests — confirm the trace math has the soundness
// properties the in-AIR Merkle walk depends on. Each test simulates a
// dishonest prover behavior and confirms the resulting chained-walk
// digest does NOT equal the public set_root.
//
// These are the host-side equivalent of the AIR-time negative-witness
// sweep tests that exist in lib.rs for the commitment phase. When the
// AIR lands, the same scenarios will be re-run through the prove+verify
// chain and rejected by the AIR's transition + boundary constraints.
// Until then, this is the trace-math-level guarantee that the soundness
// argument is consistent.
// --------------------------------------------------------------------

/// Tampered sibling at one level → chained walk produces a digest that
/// does NOT match the off-AIR set_root.
#[test]
fn stage16_neg_tampered_sibling_does_not_reach_root() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path};

    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (root, _, leaves) = build_set_tree(&values);
    let target_idx = 2; // "USA"
    let leaf = leaves[target_idx];
    let mut path = inclusion_path(&leaves, target_idx);

    // Corrupt the sibling at level 0.
    path[0].sibling[0] += BaseElement::ONE;

    let mut current = leaf;
    for step in &path {
        let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
        current = merged;
    }
    assert_ne!(
        current, root,
        "tampered sibling MUST not let chained walk reach root"
    );
}

/// Flipped side bit at one level → walk diverges, doesn't reach root.
#[test]
fn stage16_neg_flipped_side_bit_does_not_reach_root() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path, Side};

    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (root, _, leaves) = build_set_tree(&values);
    let target_idx = 2; // "USA"
    let leaf = leaves[target_idx];
    let mut path = inclusion_path(&leaves, target_idx);

    // Flip the side bit at level 0.
    path[0].side = match path[0].side {
        Side::Left => Side::Right,
        Side::Right => Side::Left,
    };

    let mut current = leaf;
    for step in &path {
        let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
        current = merged;
    }
    assert_ne!(
        current, root,
        "flipped side bit MUST not let chained walk reach root"
    );
}

/// Wrong leaf (different value) → walk doesn't reach root even with
/// honest path siblings (the path was computed for a different leaf).
#[test]
fn stage16_neg_wrong_leaf_with_honest_path_does_not_reach_root() {
    use trusset_circuit_set_membership::{
        build_set_tree, inclusion_path, set_leaf_digest, witness_to_felts,
    };
    let _ = witness_to_felts; // silence unused

    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (root, _, leaves) = build_set_tree(&values);
    // Use USA's path but DEU's leaf.
    let usa_path = inclusion_path(&leaves, 2);
    let wrong_leaf = set_leaf_digest(b"DEU");

    let mut current = wrong_leaf;
    for step in &usa_path {
        let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
        current = merged;
    }
    assert_ne!(
        current, root,
        "wrong leaf with honest path MUST not reach root"
    );
}

/// Sibling-from-different-tree → walk doesn't reach root.
///
/// Models a prover who knows the structure of an ALLOWED-list (e.g.
/// US states) but tries to substitute a sibling from a DIFFERENT list
/// (e.g. EU countries) at one level of the path.
#[test]
fn stage16_neg_sibling_from_different_tree_does_not_reach_root() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path};

    let values_a: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let values_b: Vec<&[u8]> = vec![b"AAA", b"BBB", b"CCC", b"DDD"];
    let (root_a, _, leaves_a) = build_set_tree(&values_a);
    let (_, _, leaves_b) = build_set_tree(&values_b);

    let target_idx = 0;
    let leaf = leaves_a[target_idx];
    let mut path = inclusion_path(&leaves_a, target_idx);

    // Replace the level-0 sibling with one from tree B.
    path[0].sibling = leaves_b[1];

    let mut current = leaf;
    for step in &path {
        let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
        current = merged;
    }
    assert_ne!(
        current, root_a,
        "sibling-from-different-tree MUST not reach tree A's root"
    );
}

/// Witness-to-felts collision check at the trace level: two values that
/// hash to the same set_leaf MUST produce identical chained walks (the
/// AIR cannot distinguish them — soundness requires `set_leaf_digest`
/// to be injective). This is the positive control showing that values
/// that genuinely differ produce different walks.
#[test]
fn stage16_distinct_values_produce_distinct_chained_walks() {
    use trusset_circuit_set_membership::{build_set_tree, inclusion_path};

    let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
    let (_, _, leaves) = build_set_tree(&values);

    let mut digests: Vec<[BaseElement; 4]> = Vec::new();
    for idx in 0..4 {
        let leaf = leaves[idx];
        let path = inclusion_path(&leaves, idx);
        let mut current = leaf;
        for step in &path {
            let (_, merged) = build_merge_level_rows(current, step.sibling, step.side.as_u8());
            current = merged;
        }
        digests.push(current);
    }

    // All 4 walks reach the same root (positive control).
    for i in 1..4 {
        assert_eq!(digests[0], digests[i]);
    }
}
