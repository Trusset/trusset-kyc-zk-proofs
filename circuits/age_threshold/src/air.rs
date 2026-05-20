//! Winterfell `Air` for `age_threshold` — Phase 2B Step-B real
//! commitment-opening AIR.

// See `tier_threshold::air` for the rationale on these allows.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::doc_overindented_list_items)]

//!
//! # Scope
//!
//! This AIR proves the **v2 felt-level Rescue commitment opening**:
//!
//! > I know `(dob_days, nonce)` such that
//! > `Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(1) ‖ Felt(1) ‖
//! > [Felt(dob_days)] ‖ bytes_to_field(nonce)) == commitment`.
//!
//! The age-threshold predicate (`age_days = current_epoch_days - dob_days`,
//! `age_days >= min_age_days`, 22-bit boolean range check on slack) is
//! validated at proof-generation time by `crate::validate()` but is **not
//! yet enforced inside the AIR** — that boolean-decomposition predicate
//! layer is the next incremental work item.
//!
//! Trace layout, periodic-column structure, and selector logic are
//! identical to [`crate::tier_threshold`]'s real AIR (same 13-felt input,
//! 2-block absorption, 32-row trace). Only the `circuit_id` constant
//! pinned at `state[9][0]` differs (AgeThreshold = 1 vs TierThreshold = 3).

use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use trusset_circuits_common::{bytes_to_field, rescue_air, CircuitId, COMMITMENT_TAG};

/// Trace column layout:
/// - 0..12  : Rescue-Prime state (12 cols)
/// - 12..34 : `bit_0..bit_21` — boolean decomposition of
///            `slack = current_epoch_days − dob_days − min_age_days` at row 0.
///            Each bit is enforced ∈ {0,1} by a degree-2 transition
///            constraint masked to row 0. The linear-combination constraint
///            (transition constraint #34) enforces
///            `(current_epoch_days − state[11][0] − min_age_days) = Σ bit_i · 2^i`.
pub const STATE_COLS: usize = rescue_air::STATE_WIDTH;
pub const NUM_SLACK_BITS: usize = 22;
pub const COL_BIT_START: usize = STATE_COLS;
pub const TRACE_WIDTH: usize = STATE_COLS + NUM_SLACK_BITS;

/// Trace length: 32 = 30 active + 2 stall padding.
pub const TRACE_LENGTH: usize = 32;

/// Row index of the final post-block-2 state. `state[4..8][FINAL_ROW]`
/// equals the v2 commitment.
pub const FINAL_ROW: usize = 29;

/// Number of transition constraints:
/// - 12 state-column constraints (Rescue + absorption + padding)
/// - 22 boolean constraints (one per bit_i)
/// - 1 linear-combination constraint (slack = Σ bit_i · 2^i)
pub const NUM_TRANSITION_CONSTRAINTS: usize = STATE_COLS + NUM_SLACK_BITS + 1;

/// Public inputs presented to the AIR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgeAirPublicInputs {
    /// 4-felt v2 commitment digest. Pinned at `state[4..8][FINAL_ROW]`.
    pub commitment: [BaseElement; 4],
    /// Public minimum age in days. Not enforced inside the AIR yet
    /// (predicate work is the next iteration); kept for API stability.
    pub min_age_days: BaseElement,
    /// Public current-epoch day. Not enforced inside the AIR yet.
    pub current_epoch_days: BaseElement,
}

impl ToElements<BaseElement> for AgeAirPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = self.commitment.to_vec();
        v.push(self.min_age_days);
        v.push(self.current_epoch_days);
        v
    }
}

/// Winterfell `Air` for age_threshold.
pub struct AgeAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; 4],
    min_age_days: BaseElement,
    current_epoch_days: BaseElement,
}

impl Air for AgeAir {
    type BaseField = BaseElement;
    type PublicInputs = AgeAirPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(
            trace_info.width(),
            TRACE_WIDTH,
            "age_threshold AIR expects trace width {}",
            TRACE_WIDTH
        );
        assert_eq!(
            trace_info.length(),
            TRACE_LENGTH,
            "age_threshold AIR expects trace length {}",
            TRACE_LENGTH
        );

        // Constraint degrees:
        // - State cols (0..12): with_cycles(7, [32]) for Rescue + absorption + padding
        // - Bit cols (12..34): with_cycles(2, [32]) for boolean check
        //   (sel_bind_row_0 * bit * (bit - 1))
        // - Linear-combination constraint: with_cycles(1, [32]) for
        //   sel_bind_row_0 * (slack_value - Σ bit_i * 2^i)
        let mut degrees: Vec<TransitionConstraintDegree> = (0..STATE_COLS)
            .map(|_| TransitionConstraintDegree::with_cycles(7, vec![TRACE_LENGTH]))
            .collect();
        for _ in 0..NUM_SLACK_BITS {
            degrees.push(TransitionConstraintDegree::with_cycles(
                2,
                vec![TRACE_LENGTH],
            ));
        }
        degrees.push(TransitionConstraintDegree::with_cycles(
            1,
            vec![TRACE_LENGTH],
        ));

        // Row-0 boundary count: state[0]=13 + state[1..4]=0 (3) +
        // state[4..9]=tag_felts (5) + state[9]=circuit_id (1) +
        // state[10]=1 length (1) = 11. Plus row 29 commitment (4) = 15.
        let num_assertions = 11 + 4;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            commitment: pub_inputs.commitment,
            min_age_days: pub_inputs.min_age_days,
            current_epoch_days: pub_inputs.current_epoch_days,
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

        // Periodic layout (17 columns total):
        //   0..12 : ark_combined[i] (per state position)
        //   12    : selector_first_half
        //   13    : selector_second_half
        //   14    : selector_absorb
        //   15    : selector_pad
        //   16    : selector_bind_row_0
        let ark_combined = &periodic_values[0..STATE_COLS];
        let sel_first = periodic_values[STATE_COLS];
        let sel_second = periodic_values[STATE_COLS + 1];
        let sel_absorb = periodic_values[STATE_COLS + 2];
        let sel_pad = periodic_values[STATE_COLS + 3];
        let sel_bind_row_0 = periodic_values[STATE_COLS + 4];

        // First-half Rescue: next = MDS · (current^7) + ARK1
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

        // Second-half Rescue: current = (INV_MDS · (next - ARK2))^7
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

        // State-column constraints (cols 0..12).
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

        // ---- 22-bit boolean decomposition of slack ----
        // Each bit_i at row 0 must be in {0, 1}.
        // Constraint (one per bit): sel_bind_row_0 * bit_i_curr * (bit_i_curr - 1) = 0.
        for i in 0..NUM_SLACK_BITS {
            let bit = current[COL_BIT_START + i];
            let bool_residual = bit * (bit - E::ONE);
            result[COL_BIT_START + i] = sel_bind_row_0 * bool_residual;
        }

        // ---- Linear-combination constraint (last) ----
        //   sel_bind_row_0 * ((current_epoch_days - state[11] - min_age_days)
        //                     - Σ bit_i * 2^i) = 0
        // Combined with the boolean checks, this proves that
        //   slack = current_epoch_days - dob_days - min_age_days ∈ [0, 2^22)
        // since slack equals a sum of {0,1} bits each weighted by a power of 2.
        // Rejects time-travel (dob_days > current_epoch_days) and underage
        // (current_epoch_days - dob_days < min_age_days), since either wraps
        // the field value out of [0, 2^22).
        let ce_e = E::from(self.current_epoch_days);
        let min_age_e = E::from(self.min_age_days);
        let slack_value = ce_e - current[11] - min_age_e;
        let mut bit_sum = E::ZERO;
        for i in 0..NUM_SLACK_BITS {
            let weight = E::from(BaseElement::new(1u64 << i));
            bit_sum += current[COL_BIT_START + i] * weight;
        }
        let linear_residual = slack_value - bit_sum;
        result[COL_BIT_START + NUM_SLACK_BITS] = sel_bind_row_0 * linear_residual;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(11 + 4);
        a.push(Assertion::single(0, 0, BaseElement::new(13)));
        for i in 1..4 {
            a.push(Assertion::single(i, 0, BaseElement::ZERO));
        }
        let tag_felts = bytes_to_field(&COMMITMENT_TAG);
        for (offset, &felt) in tag_felts.iter().enumerate().take(5) {
            a.push(Assertion::single(4 + offset, 0, felt));
        }
        a.push(Assertion::single(
            9,
            0,
            BaseElement::new(u64::from(CircuitId::AgeThreshold.as_u8())),
        ));
        a.push(Assertion::single(10, 0, BaseElement::new(1)));
        for i in 0..4 {
            a.push(Assertion::single(4 + i, FINAL_ROW, self.commitment[i]));
        }
        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic_columns()
    }
}

/// 17 periodic columns of length 32:
/// - 0..12: ark_combined
/// - 12..16: Rescue selectors (first/second/absorb/pad)
/// - 16: selector_bind_row_0 (= [1, 0, ..., 0])
fn build_periodic_columns() -> Vec<Vec<BaseElement>> {
    const NUM_PERIODIC: usize = STATE_COLS + 5;
    let mut cols: Vec<Vec<BaseElement>> = (0..NUM_PERIODIC)
        .map(|_| vec![BaseElement::ZERO; TRACE_LENGTH])
        .collect();

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

    cols[STATE_COLS + 2][14] = BaseElement::ONE;

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

    cols[STATE_COLS + 3][29] = BaseElement::ONE;
    cols[STATE_COLS + 3][30] = BaseElement::ONE;

    // selector_bind_row_0: 1 at transition 0 only.
    cols[STATE_COLS + 4][0] = BaseElement::ONE;

    cols
}

pub type AirHashFn = Rp64_256;
pub type AirVectorCommitment = MerkleTree<AirHashFn>;
pub type AirRandomCoin = DefaultRandomCoin<AirHashFn>;
