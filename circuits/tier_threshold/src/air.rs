//! Winterfell `Air` for `tier_threshold` — Phase 2B Step-B real
//! commitment-opening AIR.

// AIR transition / boundary code expresses mathematical formulas
// (`sum_j MDS[i][j] * v[j]`, `state[CAPACITY_RANGE_START..]`, etc.) where
// explicit indices match the math directly. The `.iter().enumerate()`
// suggestions from clippy make the code harder to map back to the spec.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::doc_overindented_list_items)]

//!
//! # Scope
//!
//! This AIR proves the **v2 felt-level Rescue commitment opening**:
//!
//! > I know `(tier, nonce)` such that
//! > `Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(3) ‖ Felt(1) ‖
//! > [Felt(tier as u64)] ‖ bytes_to_field(nonce)) == commitment`.
//!
//! Soundness comes from Rescue-Prime's collision resistance combined with
//! the AIR-enforced sub-round transitions. The `tier ∈ {1,2,3}` and
//! `tier ≥ min_tier` predicate constraints are validated at proof-generation
//! time by `crate::validate()` but are **not yet enforced inside the AIR**.
//! That predicate layer (Pattern A accumulator columns) is the next
//! incremental work item — see `docs/STEP_2B_COMMITMENT_DESIGN.md` Stage 4.
//!
//! Even without the in-AIR predicate, this AIR is a meaningful soundness
//! improvement over the Step-A placeholder: a malicious prover can no
//! longer fabricate a proof for an arbitrary commitment — they must know
//! a `(tier, nonce)` pair whose v2 commitment equals the public
//! commitment. The application-level `validate()` check provides the
//! final guarantee that `tier ∈ {1,2,3}`.
//!
//! # Trace layout (32 rows × 12 columns)
//!
//! Columns 0..11 hold the 12-element Rescue-Prime state.
//!
//! - **Row 0**: post-first-absorption state. `state[0] = 13`,
//!   `state[1..4] = 0`, `state[4..12] = input_felts[0..8]` (5 tag felts,
//!   circuit_id=3, length=1, tier).
//! - **Rows 1..14**: 14 sub-round states of block 1's Rescue permutation.
//! - **Row 15**: absorption row. `state[0..4][15] = state[0..4][14]`,
//!   `state[4..9][15] = state[4..9][14] + nonce_felts[0..5]` (prover-free
//!   delta; capacity / high-rate preservation enforced),
//!   `state[9..12][15] = state[9..12][14]`.
//! - **Rows 16..29**: 14 sub-round states of block 2's Rescue permutation.
//!   Row 29's `state[4..8]` is the v2 commitment digest.
//! - **Rows 30..31**: stall padding. `state[k][30] = state[k][29]`.
//!
//! # Transition selectors (periodic columns of length 32)
//!
//! - `selector_first_half[k]`: 1 at `k ∈ {0,2,4,6,8,10,12, 15,17,19,21,23,25,27}`.
//! - `selector_second_half[k]`: 1 at `k ∈ {1,3,5,7,9,11,13, 16,18,20,22,24,26,28}`.
//! - `selector_absorb[k]`: 1 at `k = 14`.
//! - `selector_pad[k]`: 1 at `k ∈ {29, 30}`.
//!
//! Exactly one selector is 1 per active transition `k ∈ {0..30}`; all four
//! are 0 at `k = 31` (no transition fires from the last row).

use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use trusset_circuits_common::{bytes_to_field, rescue_air, CircuitId, COMMITMENT_TAG};

/// Trace column layout:
/// - 0..12 : Rescue-Prime state (12 cols)
/// - 12    : tier_col — witness tier value, constrained to equal `state[11][0]`
///           at row 0 and constant through row 2 (Pattern A walk window)
/// - 13    : acc_tier — Pattern A accumulator for `tier ∈ {1, 2, 3}`
/// - 14    : slack_col — `slack = tier - min_tier`, constrained at row 0 and
///           constant through row 2
/// - 15    : acc_slack — Pattern A accumulator for `slack ∈ {0, 1, 2}`
pub const STATE_COLS: usize = rescue_air::STATE_WIDTH;
pub const COL_TIER: usize = 12;
pub const COL_ACC_TIER: usize = 13;
pub const COL_SLACK: usize = 14;
pub const COL_ACC_SLACK: usize = 15;
pub const TRACE_WIDTH: usize = 16;

/// Trace length: power-of-two accommodating 30 active rows + 2 stall rows.
pub const TRACE_LENGTH: usize = 32;

/// Row index of the final post-block-2 state. `state[4..8][FINAL_ROW]`
/// equals the v2 commitment.
pub const FINAL_ROW: usize = 29;

/// Row at which Pattern A accumulators reach 0 (predicate satisfied).
pub const PREDICATE_FINAL_ROW: usize = 3;

/// Public inputs presented to the AIR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierAirPublicInputs {
    /// 4-felt v2 commitment digest. Pinned at `state[4..8][FINAL_ROW]`.
    pub commitment: [BaseElement; 4],
    /// Minimum tier (1..=3). Used by the AIR to bind `slack_col[0] =
    /// tier_col[0] - min_tier`, enabling the `slack ∈ {0,1,2}` Pattern A
    /// accumulator to prove `tier ≥ min_tier` AND `tier ≤ min_tier + 2`
    /// (equivalently `tier ∈ {min_tier, min_tier+1, min_tier+2}`).
    pub min_tier: BaseElement,
}

impl ToElements<BaseElement> for TierAirPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = self.commitment.to_vec();
        v.push(self.min_tier);
        v
    }
}

/// Winterfell `Air` for tier_threshold.
pub struct TierAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; 4],
    min_tier: BaseElement,
}

impl Air for TierAir {
    type BaseField = BaseElement;
    type PublicInputs = TierAirPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(
            trace_info.width(),
            TRACE_WIDTH,
            "tier_threshold AIR expects trace width {}",
            TRACE_WIDTH
        );
        assert_eq!(
            trace_info.length(),
            TRACE_LENGTH,
            "tier_threshold AIR expects trace length {}",
            TRACE_LENGTH
        );

        // Per-column transition-constraint degrees:
        // - State cols (0..12): degree 7 in trace + 1 periodic factor (selectors/ARK).
        // - tier_col (12), slack_col (14): degree 1 in trace + 1 periodic factor.
        // - acc_tier (13), acc_slack (15): degree 2 in trace + 1 periodic factor
        //   (the Pattern A walk involves acc_curr * tier_col_curr).
        let mut degrees: Vec<TransitionConstraintDegree> = (0..STATE_COLS)
            .map(|_| TransitionConstraintDegree::with_cycles(7, vec![TRACE_LENGTH]))
            .collect();
        // Col 12: tier_col constancy / binding.
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            vec![TRACE_LENGTH],
        ));
        // Col 13: acc_tier walk.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![TRACE_LENGTH],
        ));
        // Col 14: slack_col constancy / binding.
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            vec![TRACE_LENGTH],
        ));
        // Col 15: acc_slack walk.
        degrees.push(TransitionConstraintDegree::with_cycles(
            2,
            vec![TRACE_LENGTH],
        ));

        // Boundary assertions:
        //   Row 0: state[0]=13, state[1..4]=0, state[4..9]=tag, state[9]=circuit_id,
        //          state[10]=1, acc_tier=1, acc_slack=1.  (= 11 + 2 = 13)
        //   Row FINAL_ROW: state[4..8]=commitment. (= 4)
        //   Row PREDICATE_FINAL_ROW (=3): acc_tier=0, acc_slack=0. (= 2)
        //   Total: 13 + 4 + 2 = 19.
        let num_assertions = 13 + 4 + 2;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            commitment: pub_inputs.commitment,
            min_tier: pub_inputs.min_tier,
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

        // Periodic layout (21 columns total):
        //   0..12: ark_combined[i] for i in 0..12  (state-col ARK constants)
        //   12   : selector_first_half
        //   13   : selector_second_half
        //   14   : selector_absorb
        //   15   : selector_pad
        //   16   : selector_bind_row_0       (1 at transition 0, 0 elsewhere)
        //   17   : selector_predicate_const  (1 at transitions 0..1, 0 elsewhere)
        //   18   : selector_pattern_a        (1 at transitions 0..2, 0 elsewhere)
        //   19   : p_tier_periodic           ([1, 2, 3, 0, 0, ..., 0])
        //   20   : p_slack_periodic          ([0, 1, 2, 0, 0, ..., 0])
        let ark_combined = &periodic_values[0..STATE_COLS];
        let sel_first = periodic_values[STATE_COLS];
        let sel_second = periodic_values[STATE_COLS + 1];
        let sel_absorb = periodic_values[STATE_COLS + 2];
        let sel_pad = periodic_values[STATE_COLS + 3];
        let sel_bind_row_0 = periodic_values[STATE_COLS + 4];
        let sel_predicate_const = periodic_values[STATE_COLS + 5];
        let sel_pattern_a = periodic_values[STATE_COLS + 6];
        let p_tier = periodic_values[STATE_COLS + 7];
        let p_slack = periodic_values[STATE_COLS + 8];

        // First-half: next = MDS · (current^7) + ARK1
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

        // Second-half: current = (INV_MDS · (next - ARK2))^7
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

        // State-column constraints (Rescue + absorption + padding).
        for i in 0..STATE_COLS {
            let res_first = next[i] - mds_sboxed[i] - ark_combined[i];
            let res_second = current[i] - second_half_pow7[i];
            let res_pad = next[i] - current[i];

            let is_preserved_position = !(4..9).contains(&i);
            let res_absorb = if is_preserved_position {
                next[i] - current[i]
            } else {
                E::ZERO
            };

            result[i] = sel_first * res_first
                + sel_second * res_second
                + sel_absorb * res_absorb
                + sel_pad * res_pad;
        }

        // ---- Predicate constraints (cols 12..16) ----
        let min_tier_e = E::from(self.min_tier);

        // Col 12 (tier_col): combination of
        //   (a) binding at row 0: state[11] = tier_col
        //   (b) constancy at rows 0..2: tier_col_next = tier_col_curr
        let res_tier_binding = current[11] - current[COL_TIER];
        let res_tier_const = next[COL_TIER] - current[COL_TIER];
        result[COL_TIER] = sel_bind_row_0 * res_tier_binding + sel_predicate_const * res_tier_const;

        // Col 14 (slack_col): combination of
        //   (a) binding at row 0: slack_col = tier_col - min_tier
        //   (b) constancy at rows 0..2: slack_col_next = slack_col_curr
        let res_slack_binding = current[COL_SLACK] - current[COL_TIER] + min_tier_e;
        let res_slack_const = next[COL_SLACK] - current[COL_SLACK];
        result[COL_SLACK] =
            sel_bind_row_0 * res_slack_binding + sel_predicate_const * res_slack_const;

        // Col 13 (acc_tier): Pattern A walk at transitions 0..2.
        //   acc_tier_next = acc_tier_curr * (tier_col_curr - p_tier_curr)
        // Active only when sel_pattern_a = 1; free elsewhere.
        let res_acc_tier =
            next[COL_ACC_TIER] - current[COL_ACC_TIER] * (current[COL_TIER] - p_tier);
        result[COL_ACC_TIER] = sel_pattern_a * res_acc_tier;

        // Col 15 (acc_slack): Pattern A walk at transitions 0..2.
        //   acc_slack_next = acc_slack_curr * (slack_col_curr - p_slack_curr)
        let res_acc_slack =
            next[COL_ACC_SLACK] - current[COL_ACC_SLACK] * (current[COL_SLACK] - p_slack);
        result[COL_ACC_SLACK] = sel_pattern_a * res_acc_slack;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(13 + 4 + 2);
        // Row 0 capacity.
        a.push(Assertion::single(0, 0, BaseElement::new(13)));
        for i in 1..4 {
            a.push(Assertion::single(i, 0, BaseElement::ZERO));
        }
        // Row 0 tag felts state[4..9].
        let tag_felts = bytes_to_field(&COMMITMENT_TAG);
        for (offset, &felt) in tag_felts.iter().enumerate().take(5) {
            a.push(Assertion::single(4 + offset, 0, felt));
        }
        // Row 0 circuit_id, length.
        a.push(Assertion::single(
            9,
            0,
            BaseElement::new(u64::from(CircuitId::TierThreshold.as_u8())),
        ));
        a.push(Assertion::single(10, 0, BaseElement::new(1)));
        // state[11][0] = tier — intentionally unconstrained directly (private).
        // Its value is bound to tier_col[0] by the row-0 transition constraint
        // on COL_TIER (selector_bind_row_0 * (state[11] - tier_col) = 0).

        // Predicate accumulators initialized at row 0.
        a.push(Assertion::single(COL_ACC_TIER, 0, BaseElement::ONE));
        a.push(Assertion::single(COL_ACC_SLACK, 0, BaseElement::ONE));

        // Row FINAL_ROW: state[4..8] = commitment.
        for i in 0..4 {
            a.push(Assertion::single(4 + i, FINAL_ROW, self.commitment[i]));
        }

        // Row PREDICATE_FINAL_ROW: Pattern A accumulators reach 0.
        //   acc_tier[3] = (tier-1)(tier-2)(tier-3) = 0 iff tier ∈ {1,2,3}
        //   acc_slack[3] = slack(slack-1)(slack-2) = 0 iff slack ∈ {0,1,2}
        //                                                 iff tier ∈ {min_tier, min_tier+1, min_tier+2}
        a.push(Assertion::single(
            COL_ACC_TIER,
            PREDICATE_FINAL_ROW,
            BaseElement::ZERO,
        ));
        a.push(Assertion::single(
            COL_ACC_SLACK,
            PREDICATE_FINAL_ROW,
            BaseElement::ZERO,
        ));

        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic_columns()
    }
}

/// 21 periodic columns of length 32:
/// - 0..12: ark_combined (12 cols, one per state position)
/// - 12:    selector_first_half
/// - 13:    selector_second_half
/// - 14:    selector_absorb
/// - 15:    selector_pad
/// - 16:    selector_bind_row_0
/// - 17:    selector_predicate_const
/// - 18:    selector_pattern_a
/// - 19:    p_tier_periodic
/// - 20:    p_slack_periodic
fn build_periodic_columns() -> Vec<Vec<BaseElement>> {
    const NUM_PERIODIC: usize = STATE_COLS + 9;
    let mut cols: Vec<Vec<BaseElement>> = (0..NUM_PERIODIC)
        .map(|_| vec![BaseElement::ZERO; TRACE_LENGTH])
        .collect();

    // Block 1: transitions 0..13 = 14 sub-rounds (7 rounds × 2 halves).
    for round in 0..rescue_air::NUM_ROUNDS {
        let k_first = 2 * round;
        let k_second = 2 * round + 1;
        cols[STATE_COLS][k_first] = BaseElement::ONE;
        cols[STATE_COLS + 1][k_second] = BaseElement::ONE;
        for i in 0..STATE_COLS {
            cols[i][k_first] = rescue_air::ARK1[round][i];
            cols[i][k_second] = rescue_air::ARK2[round][i];
        }
    }

    // Transition 14: absorption.
    cols[STATE_COLS + 2][14] = BaseElement::ONE;

    // Block 2: transitions 15..28.
    for round in 0..rescue_air::NUM_ROUNDS {
        let k_first = 15 + 2 * round;
        let k_second = 16 + 2 * round;
        cols[STATE_COLS][k_first] = BaseElement::ONE;
        cols[STATE_COLS + 1][k_second] = BaseElement::ONE;
        for i in 0..STATE_COLS {
            cols[i][k_first] = rescue_air::ARK1[round][i];
            cols[i][k_second] = rescue_air::ARK2[round][i];
        }
    }

    // Transitions 29, 30: padding stall.
    cols[STATE_COLS + 3][29] = BaseElement::ONE;
    cols[STATE_COLS + 3][30] = BaseElement::ONE;

    // --- Predicate-related periodic columns ---
    // selector_bind_row_0: 1 at transition 0 only.
    cols[STATE_COLS + 4][0] = BaseElement::ONE;

    // selector_predicate_const: 1 at transitions 0, 1 (enforces tier_col[1]
    // = tier_col[0], slack_col[1] = slack_col[0], same for transition 1).
    cols[STATE_COLS + 5][0] = BaseElement::ONE;
    cols[STATE_COLS + 5][1] = BaseElement::ONE;

    // selector_pattern_a: 1 at transitions 0, 1, 2 (the Pattern A walk).
    cols[STATE_COLS + 6][0] = BaseElement::ONE;
    cols[STATE_COLS + 6][1] = BaseElement::ONE;
    cols[STATE_COLS + 6][2] = BaseElement::ONE;

    // p_tier_periodic = [1, 2, 3, 0, ..., 0]
    cols[STATE_COLS + 7][0] = BaseElement::new(1);
    cols[STATE_COLS + 7][1] = BaseElement::new(2);
    cols[STATE_COLS + 7][2] = BaseElement::new(3);

    // p_slack_periodic = [0, 1, 2, 0, ..., 0]
    cols[STATE_COLS + 8][0] = BaseElement::new(0);
    cols[STATE_COLS + 8][1] = BaseElement::new(1);
    cols[STATE_COLS + 8][2] = BaseElement::new(2);

    cols
}

/// Type-aliases pinning Winterfell's hash & random-coin for proof-byte
/// stability across native and WASM builds. `Rp64_256` matches the
/// Rescue-Prime instance used outside the AIR for leaf/commitment hashing.
pub type AirHashFn = Rp64_256;
pub type AirVectorCommitment = MerkleTree<AirHashFn>;
pub type AirRandomCoin = DefaultRandomCoin<AirHashFn>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_columns_shape() {
        let cols = build_periodic_columns();
        // 12 ark + 4 rescue selectors + 5 predicate periodic = 21
        assert_eq!(cols.len(), STATE_COLS + 9);
        for col in &cols {
            assert_eq!(col.len(), TRACE_LENGTH);
        }
    }

    #[test]
    fn selector_first_half_at_correct_indices() {
        let cols = build_periodic_columns();
        let s = &cols[STATE_COLS];
        let expected: Vec<usize> = vec![0, 2, 4, 6, 8, 10, 12, 15, 17, 19, 21, 23, 25, 27];
        for k in 0..TRACE_LENGTH {
            assert_eq!(s[k] == BaseElement::ONE, expected.contains(&k));
        }
    }

    #[test]
    fn selector_second_half_at_correct_indices() {
        let cols = build_periodic_columns();
        let s = &cols[STATE_COLS + 1];
        let expected: Vec<usize> = vec![1, 3, 5, 7, 9, 11, 13, 16, 18, 20, 22, 24, 26, 28];
        for k in 0..TRACE_LENGTH {
            assert_eq!(s[k] == BaseElement::ONE, expected.contains(&k));
        }
    }

    #[test]
    fn selector_absorb_at_row_14_only() {
        let cols = build_periodic_columns();
        let s = &cols[STATE_COLS + 2];
        for k in 0..TRACE_LENGTH {
            assert_eq!(s[k] == BaseElement::ONE, k == 14);
        }
    }

    #[test]
    fn selector_pad_at_rows_29_and_30() {
        let cols = build_periodic_columns();
        let s = &cols[STATE_COLS + 3];
        for k in 0..TRACE_LENGTH {
            assert_eq!(s[k] == BaseElement::ONE, k == 29 || k == 30);
        }
    }

    #[test]
    fn selectors_mutually_exclusive_on_active_transitions() {
        let cols = build_periodic_columns();
        for k in 0..31 {
            let count = (cols[STATE_COLS][k] == BaseElement::ONE) as usize
                + (cols[STATE_COLS + 1][k] == BaseElement::ONE) as usize
                + (cols[STATE_COLS + 2][k] == BaseElement::ONE) as usize
                + (cols[STATE_COLS + 3][k] == BaseElement::ONE) as usize;
            assert_eq!(
                count, 1,
                "exactly one selector should fire at transition {k}"
            );
        }
        // Row 31: no transition fires.
        let count = (cols[STATE_COLS][31] == BaseElement::ONE) as usize
            + (cols[STATE_COLS + 1][31] == BaseElement::ONE) as usize
            + (cols[STATE_COLS + 2][31] == BaseElement::ONE) as usize
            + (cols[STATE_COLS + 3][31] == BaseElement::ONE) as usize;
        assert_eq!(count, 0, "no selector should fire at terminal row 31");
    }
}
