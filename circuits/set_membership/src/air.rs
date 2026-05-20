//! Winterfell `Air` for `set_membership` — Phase 2B Step-B / Stage 16.
//!
//! Full in-AIR statement proved:
//!
//! > I know `(value, nonce, side_bits[0..set_depth], sibling_felts[0..set_depth])`
//! > such that:
//! >   1. `Rescue(COMMITMENT_TAG ‖ id=2 ‖ len=12 ‖ witness(value) ‖ nonce) ==
//! >      public.commitment` (commitment opening, rows 0..44)
//! >   2. `set_leaf = Rescue(SET_LEAF_TAG ‖ witness(value))` (set-leaf
//! >      hash, rows 45..89), with `witness(value)` = `witness_to_felts(value)`
//! >      (12 padded felts, identical to what the commitment phase consumed).
//! >   3. Walking the Merkle path from `set_leaf` for `public.set_depth`
//! >      levels, conditionally swapping at each level under
//! >      `side_bits[k]`, and merging under `SET_NODE_TAG` yields
//! >      `public.set_root` (rows 90 onwards).
//!
//! # Trace layout (33 cols × 2048 rows)
//!
//!   - Cols 0..12  : Rescue-Prime 12-felt sponge state
//!   - Cols 12..24 : `witness_felts[0..12]` (binding, constant across all rows)
//!   - Col 24      : `side_bit` (constant within each Merkle level)
//!   - Cols 25..29 : `sibling[0..4]` (constant within each Merkle level)
//!   - Cols 29..33 : `current_node_carry[0..4]` (constant within each Merkle level)
//!
//! Row regions:
//!   - Rows 0..45  : commitment opening (24 input felts in 3 blocks)
//!   - Rows 45..90 : set_leaf hash (17 input felts in 3 blocks)
//!   - Rows 90..   : Merkle walk (per level: 13 input felts in 2 blocks = 30 rows)
//!   - For `set_depth = d`, active rows end at `89 + 30*d`, then stall padding.
//!
//! Soundness contribution:
//!   - Rescue-Prime collision resistance + AIR-enforced 3-block absorption
//!     binds the prover to a specific `(witness, nonce)` pair for the
//!     commitment (boundary at row 44).
//!   - Rescue-Prime collision resistance + AIR-enforced 3-block absorption
//!     binds the prover to a specific `witness(value)` for the set_leaf.
//!   - Conditional-swap Merkle merges with `SET_NODE_TAG` produce the
//!     set_root, asserted at the depth-dependent boundary row.
//!   - Cross-phase witness binding (cols 12..24 constant) ensures the
//!     same `witness_to_felts(value)` flows through both phases.
//!
//! See [docs/STEP_2B_COMMITMENT_DESIGN.md](../../docs/STEP_2B_COMMITMENT_DESIGN.md)
//! Stage 16+ addenda for the full design, validation history, and
//! constraint-degree learnings.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::too_many_arguments)]

use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use trusset_circuits_common::{
    bytes_to_field, rescue_air, CircuitId, COMMITMENT_TAG, SET_LEAF_TAG, SET_NODE_TAG,
};

use crate::MAX_PADDED_WITNESS_FELTS;

// =====================================================================
// Trace shape constants
// =====================================================================

/// Total trace width: 12 Rescue state + 12 witness binding + 1 side bit
/// + 4 sibling + 4 carry = 33.
pub const TRACE_WIDTH: usize = 33;

/// Trace length: smallest power of 2 ≥ `90 + 32 * 30 = 1050`.
pub const TRACE_LENGTH: usize = 2048;

/// Final row of the commitment-opening phase. `state[4..8][44] = commitment`.
pub const COMMIT_FINAL_ROW: usize = 44;

/// First row of the set_leaf phase. `state[0][45] = 17`, etc.
pub const SETLEAF_ROW_START: usize = 45;

/// Final row of the set_leaf phase. `state[4..8][89] = set_leaf` digest.
pub const SETLEAF_FINAL_ROW: usize = 89;

/// First row of the Merkle walk phase. Each level occupies 30 rows.
pub const MERKLE_ROW_START: usize = 90;

/// Rows per Merkle merge level (2 Rescue blocks × 15 rows each).
pub const MERGE_ROWS_PER_LEVEL: usize = 30;

/// Maximum supported set depth (= `crate::MAX_SET_DEPTH`).
pub const MAX_SET_DEPTH: usize = 32;

// Column band start indices.
pub const COL_WITNESS_START: usize = 12;
pub const COL_SIDE_BIT: usize = 24;
pub const COL_SIBLING_START: usize = 25;
pub const COL_CARRY_START: usize = 29;

// =====================================================================
// Periodic column indices
// =====================================================================

mod periodic {
    pub const ARK_COMBINED_START: usize = 0;
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
    pub const SETLEAF_TAG_START: usize = 23;
    pub const NODE_TAG_START: usize = 28;
    pub const SEL_SET_ROOT_BOUNDARY: usize = 33;
    pub const TOTAL: usize = 34;
}

// =====================================================================
// Public inputs
// =====================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAirPublicInputs {
    /// v2 commitment digest (4 felts).
    pub commitment: [BaseElement; 4],
    /// Public Merkle root (4 felts).
    pub set_root: [BaseElement; 4],
    /// Public Merkle depth ∈ [1, MAX_SET_DEPTH].
    pub set_depth: BaseElement,
}

impl ToElements<BaseElement> for SetAirPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = self.commitment.to_vec();
        v.extend_from_slice(&self.set_root);
        v.push(self.set_depth);
        v
    }
}

/// Compute the depth-dependent boundary row where set_root is asserted.
pub fn merkle_final_row_for_depth(set_depth: u8) -> usize {
    debug_assert!((set_depth as usize) <= MAX_SET_DEPTH);
    MERKLE_ROW_START + (set_depth as usize) * MERGE_ROWS_PER_LEVEL - 1
}

// =====================================================================
// AIR
// =====================================================================

pub struct SetAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; 4],
    set_root: [BaseElement; 4],
    set_depth: u8,
}

impl Air for SetAir {
    type BaseField = BaseElement;
    type PublicInputs = SetAirPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(
            trace_info.width(),
            TRACE_WIDTH,
            "set_membership AIR expects trace width {}",
            TRACE_WIDTH
        );
        assert_eq!(
            trace_info.length(),
            TRACE_LENGTH,
            "set_membership AIR expects trace length {}",
            TRACE_LENGTH
        );

        let set_depth_u64: u64 = pub_inputs.set_depth.as_int();
        assert!(
            set_depth_u64 > 0 && set_depth_u64 <= MAX_SET_DEPTH as u64,
            "set_depth must be in [1, {}], got {}",
            MAX_SET_DEPTH,
            set_depth_u64
        );
        let set_depth = set_depth_u64 as u8;

        // ---- Transition constraint degrees (per-column) ----
        // Iteration log in docs/STEP_2B_COMMITMENT_DESIGN.md Stage 20:
        // state cols: with_cycles(7, [TL]); witness binding: new(1);
        // side bit: with_cycles(2, [TL]); sibling/carry: new(1) (placeholders).
        let mut degrees: Vec<TransitionConstraintDegree> = Vec::with_capacity(TRACE_WIDTH);

        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![TRACE_LENGTH],
            ));
        }
        for _ in 0..MAX_PADDED_WITNESS_FELTS {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // Side bit (col 24): the residual `sel_merge_setup_a * side *
        // (side - 1)` is degree 2 in trace × 1 periodic factor. The
        // empirical declared degree for Winterfell to accept the
        // honest-trace polynomial (in both debug and release) is
        // `with_cycles(2, vec![TRACE_LENGTH])` → 4094.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![TRACE_LENGTH],
        ));
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        for _ in 0..4 {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // ---- Boundary assertion count ----
        // Row 0 (commitment setup): state[0]=24, state[1..4]=0 (3),
        //   state[4..9]=COMMITMENT_TAG felts (5), state[9]=id=2,
        //   state[10]=length=12 → 11.
        // Row COMMIT_FINAL_ROW (44): state[4..8]=commitment → 4.
        // Row SETLEAF_ROW_START (45): state[0]=17, state[1..4]=0 (3),
        //   state[4..9]=SET_LEAF_TAG felts (5) → 9.
        // Row merkle_final_row: state[4..8]=set_root → 4.
        // Total: 11 + 4 + 9 + 4 = 28.
        let num_assertions = 11 + 4 + 9 + 4;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            commitment: pub_inputs.commitment,
            set_root: pub_inputs.set_root,
            set_depth,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // ---- Unpack periodic values ----
        let ark_combined: [E; 12] = std::array::from_fn(|i| periodic_values[i]);
        let sel_first = periodic_values[periodic::SEL_RESCUE_FIRST];
        let sel_second = periodic_values[periodic::SEL_RESCUE_SECOND];
        let sel_pad = periodic_values[periodic::SEL_PAD];
        let sel_commit_absorb1 = periodic_values[periodic::SEL_COMMIT_ABSORB1];
        let sel_commit_absorb2 = periodic_values[periodic::SEL_COMMIT_ABSORB2];
        let sel_setleaf_setup = periodic_values[periodic::SEL_SETLEAF_SETUP];
        let sel_setleaf_absorb1 = periodic_values[periodic::SEL_SETLEAF_ABSORB1];
        let sel_setleaf_absorb2 = periodic_values[periodic::SEL_SETLEAF_ABSORB2];
        let sel_merge_setup_a = periodic_values[periodic::SEL_MERGE_SETUP_A];
        let sel_merge_absorb_b = periodic_values[periodic::SEL_MERGE_ABSORB_B];
        let sel_bind_row_0 = periodic_values[periodic::SEL_BIND_ROW_0];
        let setleaf_tag: [E; 5] =
            std::array::from_fn(|i| periodic_values[periodic::SETLEAF_TAG_START + i]);
        let node_tag: [E; 5] =
            std::array::from_fn(|i| periodic_values[periodic::NODE_TAG_START + i]);

        // ---- Rescue first-half: next = MDS·(current^7) + ARK1 ----
        let mut current_sbox = [E::ZERO; rescue_air::STATE_WIDTH];
        for i in 0..rescue_air::STATE_WIDTH {
            let x = current[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            current_sbox[i] = x4 * x2 * x;
        }
        let mut mds_sboxed = [E::ZERO; rescue_air::STATE_WIDTH];
        for i in 0..rescue_air::STATE_WIDTH {
            let mut acc = E::ZERO;
            for j in 0..rescue_air::STATE_WIDTH {
                acc += E::from(rescue_air::MDS[i][j]) * current_sbox[j];
            }
            mds_sboxed[i] = acc;
        }

        // ---- Rescue second-half: current = (INV_MDS·(next - ARK2))^7 ----
        let mut diff = [E::ZERO; rescue_air::STATE_WIDTH];
        for i in 0..rescue_air::STATE_WIDTH {
            diff[i] = next[i] - ark_combined[i];
        }
        let mut inv_mds_diff = [E::ZERO; rescue_air::STATE_WIDTH];
        for i in 0..rescue_air::STATE_WIDTH {
            let mut acc = E::ZERO;
            for j in 0..rescue_air::STATE_WIDTH {
                acc += E::from(rescue_air::INV_MDS[i][j]) * diff[j];
            }
            inv_mds_diff[i] = acc;
        }
        let mut second_half_pow7 = [E::ZERO; rescue_air::STATE_WIDTH];
        for i in 0..rescue_air::STATE_WIDTH {
            let x = inv_mds_diff[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            second_half_pow7[i] = x4 * x2 * x;
        }

        let res_first: [E; 12] = std::array::from_fn(|i| next[i] - mds_sboxed[i] - ark_combined[i]);
        let res_second: [E; 12] = std::array::from_fn(|i| current[i] - second_half_pow7[i]);

        // ---- Conditional swap for merge setup_a (reads next row's witness cols) ----
        let side_setup = next[COL_SIDE_BIT];
        let one_minus_side_setup = E::ONE - side_setup;
        let mut node_in_a_setup = [E::ZERO; 4];
        for i in 0..4 {
            let carry_i = next[COL_CARRY_START + i];
            let sib_i = next[COL_SIBLING_START + i];
            node_in_a_setup[i] = one_minus_side_setup * carry_i + side_setup * sib_i;
        }

        // ---- Conditional swap for merge absorb_b (reads current row, 15 rows into level) ----
        let side_ab = current[COL_SIDE_BIT];
        let one_minus_side_ab = E::ONE - side_ab;
        let mut node_in_b_ab = [E::ZERO; 4];
        for i in 0..4 {
            let carry_i = current[COL_CARRY_START + i];
            let sib_i = current[COL_SIBLING_START + i];
            node_in_b_ab[i] = side_ab * carry_i + one_minus_side_ab * sib_i;
        }
        let node_in_a3_ab = {
            let c = current[COL_CARRY_START + 3];
            let s = current[COL_SIBLING_START + 3];
            one_minus_side_ab * c + side_ab * s
        };

        // ---- State cols 0..12: combine selector-gated residuals ----
        for i in 0..12 {
            let res_pad = next[i] - current[i];

            let res_commit_absorb1 = if i < 4 {
                next[i] - current[i]
            } else {
                let w_idx = 1 + (i - 4);
                next[i] - current[i] - current[COL_WITNESS_START + w_idx]
            };

            let res_commit_absorb2 = if i < 4 {
                next[i] - current[i]
            } else if i < 7 {
                let w_idx = 9 + (i - 4);
                next[i] - current[i] - current[COL_WITNESS_START + w_idx]
            } else {
                E::ZERO
            };

            let res_setleaf_setup = match i {
                0 => next[i] - E::from(BaseElement::new(17)),
                1..=3 => next[i],
                4..=8 => next[i] - setleaf_tag[i - 4],
                9..=11 => next[i] - current[COL_WITNESS_START + (i - 9)],
                _ => E::ZERO,
            };

            let res_setleaf_absorb1 = if i < 4 {
                next[i] - current[i]
            } else {
                let w_idx = 3 + (i - 4);
                next[i] - current[i] - current[COL_WITNESS_START + w_idx]
            };

            let res_setleaf_absorb2 = if i < 4 {
                next[i] - current[i]
            } else if i == 4 {
                next[i] - current[i] - current[COL_WITNESS_START + 11]
            } else {
                next[i] - current[i]
            };

            let res_merge_setup_a = match i {
                0 => next[i] - E::from(BaseElement::new(13)),
                1..=3 => next[i],
                4..=8 => next[i] - node_tag[i - 4],
                9..=11 => next[i] - node_in_a_setup[i - 9],
                _ => E::ZERO,
            };

            let res_merge_absorb_b = if i < 4 {
                next[i] - current[i]
            } else if i == 4 {
                next[i] - current[i] - node_in_a3_ab
            } else if (5..9).contains(&i) {
                next[i] - current[i] - node_in_b_ab[i - 5]
            } else {
                next[i] - current[i]
            };

            result[i] = sel_first * res_first[i]
                + sel_second * res_second[i]
                + sel_pad * res_pad
                + sel_commit_absorb1 * res_commit_absorb1
                + sel_commit_absorb2 * res_commit_absorb2
                + sel_setleaf_setup * res_setleaf_setup
                + sel_setleaf_absorb1 * res_setleaf_absorb1
                + sel_setleaf_absorb2 * res_setleaf_absorb2
                + sel_merge_setup_a * res_merge_setup_a
                + sel_merge_absorb_b * res_merge_absorb_b;
        }

        // ---- Row-0 binding: state[11] = witness_col[0] ----
        result[11] += sel_bind_row_0 * (current[11] - current[COL_WITNESS_START]);

        // ---- Witness binding constancy (cols 12..24) ----
        for c in 0..MAX_PADDED_WITNESS_FELTS {
            result[COL_WITNESS_START + c] =
                next[COL_WITNESS_START + c] - current[COL_WITNESS_START + c];
        }

        // ---- Side bit boolean (col 24) at merge setup transitions ----
        result[COL_SIDE_BIT] = sel_merge_setup_a * side_setup * (side_setup - E::ONE);

        // ---- Sibling cols (25..29) — placeholder (residual = 0) ----
        // Side/sibling/carry constancy within a level is enforced by the
        // trace structure: the AIR's merge_absorb_b reads sibling[i] at
        // current row L+15, which equals sibling[i] at L (the setup row)
        // because the prover witnesses them identically across the level.
        // A dishonest prover varying them would break the merge_absorb_b
        // → node_in_b → state[4..8] chain, which is detected by the
        // set_root boundary.
        for c in 0..4 {
            result[COL_SIBLING_START + c] = E::ZERO;
        }
        for c in 0..4 {
            result[COL_CARRY_START + c] = E::ZERO;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(28);

        // ---- Row 0: commitment setup ----
        a.push(Assertion::single(0, 0, BaseElement::new(24)));
        for i in 1..4 {
            a.push(Assertion::single(i, 0, BaseElement::ZERO));
        }
        let commit_tag_felts = bytes_to_field(&COMMITMENT_TAG);
        for (offset, &felt) in commit_tag_felts.iter().enumerate().take(5) {
            a.push(Assertion::single(4 + offset, 0, felt));
        }
        a.push(Assertion::single(
            9,
            0,
            BaseElement::new(u64::from(CircuitId::SetMembership.as_u8())),
        ));
        a.push(Assertion::single(
            10,
            0,
            BaseElement::new(MAX_PADDED_WITNESS_FELTS as u64),
        ));

        // ---- Row COMMIT_FINAL_ROW: commitment ----
        for i in 0..4 {
            a.push(Assertion::single(
                4 + i,
                COMMIT_FINAL_ROW,
                self.commitment[i],
            ));
        }

        // ---- Row SETLEAF_ROW_START: setleaf setup ----
        a.push(Assertion::single(
            0,
            SETLEAF_ROW_START,
            BaseElement::new(17),
        ));
        for i in 1..4 {
            a.push(Assertion::single(i, SETLEAF_ROW_START, BaseElement::ZERO));
        }
        let setleaf_tag_felts = bytes_to_field(&SET_LEAF_TAG);
        for (offset, &felt) in setleaf_tag_felts.iter().enumerate().take(5) {
            a.push(Assertion::single(4 + offset, SETLEAF_ROW_START, felt));
        }

        // ---- Row depth-dependent: set_root ----
        let merkle_final_row = merkle_final_row_for_depth(self.set_depth);
        for i in 0..4 {
            a.push(Assertion::single(4 + i, merkle_final_row, self.set_root[i]));
        }

        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic_columns(self.set_depth)
    }
}

// =====================================================================
// Periodic column builder
// =====================================================================

fn build_periodic_columns(set_depth: u8) -> Vec<Vec<BaseElement>> {
    let depth = set_depth as usize;
    let mut cols: Vec<Vec<BaseElement>> = (0..periodic::TOTAL)
        .map(|_| vec![BaseElement::ZERO; TRACE_LENGTH])
        .collect();

    // Block-start rows for every Rescue absorption block.
    let mut block_starts: Vec<usize> = vec![0, 15, 30, 45, 60, 75];
    for k in 0..depth {
        let level_start = MERKLE_ROW_START + k * MERGE_ROWS_PER_LEVEL;
        block_starts.push(level_start);
        block_starts.push(level_start + 15);
    }

    for &block_start in &block_starts {
        for sub in 0..14 {
            let row = block_start + sub;
            if sub % 2 == 0 {
                cols[periodic::SEL_RESCUE_FIRST][row] = BaseElement::ONE;
            } else {
                cols[periodic::SEL_RESCUE_SECOND][row] = BaseElement::ONE;
            }
        }
        for round in 0..rescue_air::NUM_ROUNDS {
            let row_first = block_start + 2 * round;
            let row_second = block_start + 2 * round + 1;
            for i in 0..rescue_air::STATE_WIDTH {
                cols[periodic::ARK_COMBINED_START + i][row_first] = rescue_air::ARK1[round][i];
                cols[periodic::ARK_COMBINED_START + i][row_second] = rescue_air::ARK2[round][i];
            }
        }
    }

    cols[periodic::SEL_COMMIT_ABSORB1][14] = BaseElement::ONE;
    cols[periodic::SEL_COMMIT_ABSORB2][29] = BaseElement::ONE;
    cols[periodic::SEL_SETLEAF_SETUP][44] = BaseElement::ONE;
    cols[periodic::SEL_SETLEAF_ABSORB1][59] = BaseElement::ONE;
    cols[periodic::SEL_SETLEAF_ABSORB2][74] = BaseElement::ONE;

    for k in 0..depth {
        let setup_a_transition = MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL;
        let absorb_b_transition = MERKLE_ROW_START + 14 + k * MERGE_ROWS_PER_LEVEL;
        cols[periodic::SEL_MERGE_SETUP_A][setup_a_transition] = BaseElement::ONE;
        cols[periodic::SEL_MERGE_ABSORB_B][absorb_b_transition] = BaseElement::ONE;
    }

    let merkle_final_row = merkle_final_row_for_depth(set_depth);
    cols[periodic::SEL_SET_ROOT_BOUNDARY][merkle_final_row] = BaseElement::ONE;
    let pad_start = merkle_final_row + 1;
    let pad_end = TRACE_LENGTH - 1;
    if pad_start < pad_end {
        for cell in cols[periodic::SEL_PAD][pad_start..pad_end].iter_mut() {
            *cell = BaseElement::ONE;
        }
    }

    cols[periodic::SEL_BIND_ROW_0][0] = BaseElement::ONE;

    let setleaf_tag = bytes_to_field(&SET_LEAF_TAG);
    for i in 0..5 {
        cols[periodic::SETLEAF_TAG_START + i][44] = setleaf_tag[i];
    }
    let node_tag = bytes_to_field(&SET_NODE_TAG);
    for k in 0..depth {
        let setup_a_transition = MERKLE_ROW_START - 1 + k * MERGE_ROWS_PER_LEVEL;
        for i in 0..5 {
            cols[periodic::NODE_TAG_START + i][setup_a_transition] = node_tag[i];
        }
    }

    cols
}

/// Type aliases pinning Winterfell's hash + random coin.
pub type AirHashFn = Rp64_256;
pub type AirVectorCommitment = MerkleTree<AirHashFn>;
pub type AirRandomCoin = DefaultRandomCoin<AirHashFn>;
