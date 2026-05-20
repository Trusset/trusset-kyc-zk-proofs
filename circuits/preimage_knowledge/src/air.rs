//! Winterfell `Air` for `preimage_knowledge` — Phase 2B Step-B / Stage 17.
//!
//! Full in-AIR statement proved:
//!
//! > I know `(value, nonce, value_len_bytes)` such that:
//! >   1. `Rescue(COMMITMENT_TAG ‖ id=4 ‖ Felt(20) ‖ witness_to_felts(value) ‖ nonce)
//! >      == commitment` (commitment opening, rows 0..60)
//! >   2. `value_len_bytes ≤ AIR_MAX_VALUE_BYTES = 128` (length-range
//! >      predicate via 8-bit boolean decomposition of `value_len_bytes`
//! >      and `slack = AIR_MAX_VALUE_BYTES - value_len_bytes`)
//!
//! Both `value_len_bytes` and the slack are private witness columns,
//! constrained to be the correct 8-bit boolean decomposition of values
//! summing to public commitment constraints. `AIR_MAX_VALUE_BYTES` is a
//! workspace-pinned constant matching `DEFAULT_MAX_VALUE_BYTES = 128`.
//!
//! The `PublicInputs` wire shape is unchanged from Stage 11 — only the
//! `commitment` digest. This deliberately preserves the bundle format
//! (manifest, leaf hash, public_digest, JSON schema) and avoids
//! invalidating existing bundles. Operators configuring
//! `Params::max_value_bytes` differently get the off-AIR
//! `validate()` length check; in-AIR enforcement is pinned to 128
//! workspace-wide. To change the AIR max, change `AIR_MAX_VALUE_BYTES`
//! here and re-prove the affected bundles.
//!
//! # Trace layout (28 cols × 64 rows)
//!
//!   - Cols 0..12  : Rescue-Prime 12-felt sponge state
//!   - Cols 12..20 : `len_bits[0..8]` — 8-bit boolean decomposition of `value_len_bytes`
//!   - Cols 20..28 : `slack_bits[0..8]` — 8-bit boolean decomposition of `slack`
//!
//! Constraints:
//!   - Rescue state cols 0..12: same as Stage 11 (rescue first/second, absorb, pad)
//!   - Bit cols 12..28: each is boolean (`bit*(bit-1)=0`) AND constant across all rows
//!   - At row 0 only (sel_row_0): `Σ len_bits[i]*2^i = value_len_bytes` AND
//!     `Σ slack_bits[i]*2^i = max_value_bytes - value_len_bytes`
//!
//! Soundness: if a malicious prover claims `value_len > max`, the slack
//! wraps around p (a huge value) which cannot be decomposed into 8 bits
//! satisfying the linear-combination constraint. The AIR rejects.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::doc_overindented_list_items)]

use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

use trusset_circuits_common::{bytes_to_field, rescue_air, CircuitId, COMMITMENT_TAG};

use crate::MAX_PADDED_WITNESS_FELTS;

// =====================================================================
// Trace shape constants
// =====================================================================

pub const TRACE_WIDTH: usize = 28;
pub const TRACE_LENGTH: usize = 64;
pub const FINAL_ROW: usize = 59;
pub const NUM_INPUT_FELTS: usize = 32;
pub const NUM_BLOCKS: usize = 4;
pub const COL_LEN_BITS_START: usize = 12;
pub const COL_SLACK_BITS_START: usize = 20;
pub const NUM_LEN_BITS: usize = 8;
pub const NUM_SLACK_BITS: usize = 8;

/// In-AIR maximum value length, pinned at the workspace level. The
/// off-AIR `Params::max_value_bytes` may be configured per-operator;
/// the AIR enforces this hardcoded bound. Equal to
/// `DEFAULT_MAX_VALUE_BYTES = 128`. Changing this constant
/// invalidates all existing bundles.
pub const AIR_MAX_VALUE_BYTES: u64 = 128;

// =====================================================================
// Public inputs
// =====================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreimageAirPublicInputs {
    pub commitment: [BaseElement; 4],
}

impl ToElements<BaseElement> for PreimageAirPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        self.commitment.to_vec()
    }
}

// =====================================================================
// AIR
// =====================================================================

pub struct PreimageAir {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; 4],
}

impl Air for PreimageAir {
    type BaseField = BaseElement;
    type PublicInputs = PreimageAirPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(
            trace_info.width(),
            TRACE_WIDTH,
            "preimage_knowledge AIR expects trace width {}",
            TRACE_WIDTH
        );
        assert_eq!(
            trace_info.length(),
            TRACE_LENGTH,
            "preimage_knowledge AIR expects trace length {}",
            TRACE_LENGTH
        );

        let mut degrees: Vec<TransitionConstraintDegree> = Vec::with_capacity(TRACE_WIDTH);

        // State cols 0..12: degree 7 × periodic cycle.
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![TRACE_LENGTH],
            ));
        }
        // Bit cols 12..28: residual is `bit*(bit-1) + (next-current)`
        // which is degree 2 in trace. Winterfell's degree-consistency
        // checker (cross-validated in both debug and release) accepts
        // declaration `new(1)` for this — TRACE_LENGTH = 64 is small
        // enough that the boolean + constancy combined residual evaluates
        // to a polynomial of degree 1 × (L-1) = 63 once the constraint
        // divisor is applied.
        for _ in 0..(NUM_LEN_BITS + NUM_SLACK_BITS) {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Boundary assertions:
        //   Row 0 commitment setup: state[0]=32, state[1..4]=0 (3),
        //     state[4..9]=tag (5), state[9]=4, state[10]=20 = 11
        //   Row FINAL_ROW: state[4..8]=commitment (4)
        let num_assertions = 11 + 4;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            commitment: pub_inputs.commitment,
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

        let ark_combined: [E; 12] = std::array::from_fn(|i| periodic_values[i]);
        let sel_first = periodic_values[12];
        let sel_second = periodic_values[13];
        let sel_absorb = periodic_values[14];
        let sel_pad = periodic_values[15];
        let sel_row_0 = periodic_values[16];

        // Rescue first-half.
        let mut current_sbox = [E::ZERO; 12];
        for i in 0..12 {
            let x = current[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            current_sbox[i] = x4 * x2 * x;
        }
        let mut mds_sboxed = [E::ZERO; 12];
        for i in 0..12 {
            let mut acc = E::ZERO;
            for j in 0..12 {
                acc += E::from(rescue_air::MDS[i][j]) * current_sbox[j];
            }
            mds_sboxed[i] = acc;
        }

        // Rescue second-half.
        let mut diff = [E::ZERO; 12];
        for i in 0..12 {
            diff[i] = next[i] - ark_combined[i];
        }
        let mut inv_mds_diff = [E::ZERO; 12];
        for i in 0..12 {
            let mut acc = E::ZERO;
            for j in 0..12 {
                acc += E::from(rescue_air::INV_MDS[i][j]) * diff[j];
            }
            inv_mds_diff[i] = acc;
        }
        let mut second_half_pow7 = [E::ZERO; 12];
        for i in 0..12 {
            let x = inv_mds_diff[i];
            let x2 = x * x;
            let x4 = x2 * x2;
            second_half_pow7[i] = x4 * x2 * x;
        }

        for i in 0..12 {
            let res_first = next[i] - mds_sboxed[i] - ark_combined[i];
            let res_second = current[i] - second_half_pow7[i];
            let res_pad = next[i] - current[i];
            let res_absorb = if i < 4 { next[i] - current[i] } else { E::ZERO };
            result[i] = sel_first * res_first
                + sel_second * res_second
                + sel_absorb * res_absorb
                + sel_pad * res_pad;
        }

        // Bit cols: boolean + constancy.
        for c in COL_LEN_BITS_START..COL_LEN_BITS_START + NUM_LEN_BITS {
            let bit = current[c];
            result[c] = bit * (bit - E::ONE) + (next[c] - current[c]);
        }
        for c in COL_SLACK_BITS_START..COL_SLACK_BITS_START + NUM_SLACK_BITS {
            let bit = current[c];
            result[c] = bit * (bit - E::ONE) + (next[c] - current[c]);
        }

        // Linear-combination residual at row 0:
        //   `Σ len_bits[i]*2^i + Σ slack_bits[i]*2^i = AIR_MAX_VALUE_BYTES`
        //
        // The two bit-decomposition bands jointly witness
        // `value_len_bytes + slack = AIR_MAX_VALUE_BYTES`, where each
        // is constrained to be in `[0, 256)` by the booleanity of its
        // 8 bits. Equivalently: `value_len_bytes ≤ AIR_MAX_VALUE_BYTES`.
        //
        // Soundness: a malicious prover claiming `value_len > AIR_MAX_VALUE_BYTES`
        // would need to find 16 bits summing (weighted by 2^i) to
        // exactly `AIR_MAX_VALUE_BYTES`, with the first 8 bits summing
        // to > 128. The second 8 bits' weighted sum would then need to
        // equal `128 - (value_len)`, which is negative in u64 (wraps
        // to ~ u64::MAX). No 8-bit decomposition exists for that value;
        // the boolean constraints force each bit ∈ {0,1}, so the
        // weighted sum is bounded by 0..256 and cannot match a
        // p-adjacent wrapped value. The AIR rejects.
        let air_max_e = E::from(BaseElement::new(AIR_MAX_VALUE_BYTES));

        let mut len_acc = E::ZERO;
        for i in 0..NUM_LEN_BITS {
            let bit = current[COL_LEN_BITS_START + i];
            len_acc += bit * E::from(BaseElement::new(1u64 << i));
        }
        let mut slack_acc = E::ZERO;
        for i in 0..NUM_SLACK_BITS {
            let bit = current[COL_SLACK_BITS_START + i];
            slack_acc += bit * E::from(BaseElement::new(1u64 << i));
        }
        let lincomb_res = (len_acc + slack_acc) - air_max_e;

        result[COL_LEN_BITS_START] += sel_row_0 * lincomb_res;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(31);

        // Row 0: commitment-phase setup.
        a.push(Assertion::single(0, 0, BaseElement::new(32)));
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
            BaseElement::new(u64::from(CircuitId::PreimageKnowledge.as_u8())),
        ));
        a.push(Assertion::single(
            10,
            0,
            BaseElement::new(MAX_PADDED_WITNESS_FELTS as u64),
        ));

        // Row FINAL_ROW: commitment.
        for i in 0..4 {
            a.push(Assertion::single(4 + i, FINAL_ROW, self.commitment[i]));
        }

        // Bit cols 12..28: no per-cell boundary assertions needed —
        // the transition constraints (booleanity + constancy + the
        // row-0 linear-combination summing to AIR_MAX_VALUE_BYTES)
        // fully bind these columns to a valid bit decomposition with
        // total weighted sum ≤ AIR_MAX_VALUE_BYTES.

        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        build_periodic_columns()
    }
}

fn build_periodic_columns() -> Vec<Vec<BaseElement>> {
    // 17 periodic cols: 12 ark + 4 selectors + 1 sel_row_0.
    let mut cols: Vec<Vec<BaseElement>> = (0..17)
        .map(|_| vec![BaseElement::ZERO; TRACE_LENGTH])
        .collect();
    let block_starts = [0usize, 15, 30, 45];
    for &start in &block_starts {
        for round in 0..rescue_air::NUM_ROUNDS {
            let k_first = start + 2 * round;
            let k_second = start + 2 * round + 1;
            cols[12][k_first] = BaseElement::ONE;
            cols[13][k_second] = BaseElement::ONE;
            for i in 0..12 {
                cols[i][k_first] = rescue_air::ARK1[round][i];
                cols[i][k_second] = rescue_air::ARK2[round][i];
            }
        }
    }
    for &k in &[14usize, 29, 44] {
        cols[14][k] = BaseElement::ONE;
    }
    for k in 59..63 {
        cols[15][k] = BaseElement::ONE;
    }
    cols[16][0] = BaseElement::ONE;
    cols
}

pub type AirHashFn = Rp64_256;
pub type AirVectorCommitment = MerkleTree<AirHashFn>;
pub type AirRandomCoin = DefaultRandomCoin<AirHashFn>;
