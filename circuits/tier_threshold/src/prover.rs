//! Winterfell `Prover` for the tier_threshold real AIR.

// Trace-builder code uses explicit indices to populate per-row state
// (`for (row_idx, row) in state_rows.iter().enumerate()` plus a nested
// `for col in 0..STATE_COLS { trace.set(col, row_idx, row[col]) }`),
// which is clearer than fully-iterator-based equivalents.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]

use winterfell::{
    crypto::{DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement},
    matrix::ColMatrix,
    AuxRandElements, CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, PartitionOptions,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
};

use crate::air::{
    AirHashFn, TierAir, TierAirPublicInputs, COL_ACC_SLACK, COL_ACC_TIER, COL_SLACK, COL_TIER,
    STATE_COLS, TRACE_LENGTH, TRACE_WIDTH,
};

/// Build the 16-col × 32-row Winterfell trace table for the real
/// commitment-opening + Pattern A predicate AIR.
///
/// Trace structure:
/// - Cols 0..12 : Rescue state (from `build_v2_state_trace`).
/// - Col 12 (`tier_col`): `tier` at rows 0..2 (constrained), then varying.
/// - Col 13 (`acc_tier`): Pattern A walk: 1, (tier-1), (tier-1)(tier-2), 0, then free.
/// - Col 14 (`slack_col`): `tier-min_tier` at rows 0..2, then varying.
/// - Col 15 (`acc_slack`): Pattern A walk for slack ∈ {0,1,2}.
///
/// Rows 3..31 for tier_col / slack_col / accumulator columns are filled
/// with deterministic non-trivial values to ensure the column polynomial
/// has degree (L-1). The transition constraints are masked off on those
/// rows so the values are arbitrary as far as the AIR is concerned.
pub fn build_trace(tier: u8, nonce: &[u8; 32], min_tier: u8) -> TraceTable<BaseElement> {
    let state_rows = build_v2_state_trace(tier, nonce);
    debug_assert_eq!(state_rows.len(), TRACE_LENGTH);
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);

    // Fill state columns (0..12).
    for (row_idx, row) in state_rows.iter().enumerate() {
        for col in 0..STATE_COLS {
            trace.set(col, row_idx, row[col]);
        }
    }

    // --- Predicate columns ---
    let tier_felt = BaseElement::new(u64::from(tier));
    let slack_felt = BaseElement::new(u64::from(tier.wrapping_sub(min_tier)));

    // tier_col: tier at rows 0..2, then varying.
    trace.set(COL_TIER, 0, tier_felt);
    trace.set(COL_TIER, 1, tier_felt);
    trace.set(COL_TIER, 2, tier_felt);
    for k in 3..TRACE_LENGTH {
        // Use distinct non-zero values to ensure polynomial degree L-1.
        trace.set(
            COL_TIER,
            k,
            BaseElement::new((k as u64).wrapping_mul(7) + 31),
        );
    }

    // slack_col: slack at rows 0..2, then varying.
    trace.set(COL_SLACK, 0, slack_felt);
    trace.set(COL_SLACK, 1, slack_felt);
    trace.set(COL_SLACK, 2, slack_felt);
    for k in 3..TRACE_LENGTH {
        trace.set(
            COL_SLACK,
            k,
            BaseElement::new((k as u64).wrapping_mul(13) + 41),
        );
    }

    // acc_tier: Pattern A walk:
    //   row 0: 1
    //   row 1: (tier - 1)
    //   row 2: (tier - 1)(tier - 2)
    //   row 3: (tier - 1)(tier - 2)(tier - 3) = 0 for tier ∈ {1,2,3}
    let acc0 = BaseElement::ONE;
    let acc1 = acc0 * (tier_felt - BaseElement::new(1));
    let acc2 = acc1 * (tier_felt - BaseElement::new(2));
    let acc3 = acc2 * (tier_felt - BaseElement::new(3));
    trace.set(COL_ACC_TIER, 0, acc0);
    trace.set(COL_ACC_TIER, 1, acc1);
    trace.set(COL_ACC_TIER, 2, acc2);
    trace.set(COL_ACC_TIER, 3, acc3);
    for k in 4..TRACE_LENGTH {
        trace.set(
            COL_ACC_TIER,
            k,
            BaseElement::new((k as u64).wrapping_mul(17) + 53),
        );
    }

    // acc_slack: Pattern A walk for slack ∈ {0, 1, 2}.
    let s0 = BaseElement::ONE;
    let s1 = s0 * (slack_felt - BaseElement::new(0));
    let s2 = s1 * (slack_felt - BaseElement::new(1));
    let s3 = s2 * (slack_felt - BaseElement::new(2));
    trace.set(COL_ACC_SLACK, 0, s0);
    trace.set(COL_ACC_SLACK, 1, s1);
    trace.set(COL_ACC_SLACK, 2, s2);
    trace.set(COL_ACC_SLACK, 3, s3);
    for k in 4..TRACE_LENGTH {
        trace.set(
            COL_ACC_SLACK,
            k,
            BaseElement::new((k as u64).wrapping_mul(19) + 61),
        );
    }

    trace
}

pub struct TierProver {
    options: ProofOptions,
    public_inputs: TierAirPublicInputs,
}

impl TierProver {
    pub fn new(options: ProofOptions, public_inputs: TierAirPublicInputs) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for TierProver {
    type BaseField = BaseElement;
    type Air = TierAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = AirHashFn;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> TierAirPublicInputs {
        self.public_inputs.clone()
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub fn build_proof(
    tier: u8,
    nonce: &[u8; 32],
    min_tier: u8,
    public: &TierAirPublicInputs,
    options: ProofOptions,
    _prover_seed: &[u8; 32],
) -> Result<Vec<u8>, winterfell::ProverError> {
    let trace = build_trace(tier, nonce, min_tier);
    let prover = TierProver::new(options, public.clone());
    let proof = prover.prove(trace)?;
    Ok(proof.to_bytes())
}

pub fn public_to_air(
    commitment: &trusset_circuits_common::Digest,
    min_tier: u8,
) -> TierAirPublicInputs {
    TierAirPublicInputs {
        commitment: [commitment[0], commitment[1], commitment[2], commitment[3]],
        min_tier: BaseElement::new(u64::from(min_tier)),
    }
}

// ============================================================================
// v2 real-AIR trace structure (Phase 2B Step-B Stage 3)
// ============================================================================
//
// These helpers build the row-by-row state trace for the real tier_threshold
// AIR using the shared Rescue gadget (`trusset_circuits_common::rescue_air`)
// and the v2 felt-level commitment (`trusset_circuits_common::compute_commitment`).
//
// The full AIR — including transition constraints, boundary constraints,
// Pattern A predicate columns, and the wire-up to a Winterfell Prover — is
// being built incrementally. This module currently provides:
//
//   1. `build_v2_input_felts(tier, nonce)` — produces the 13-felt input
//      vector for v2 commitment, byte-equal to what compute_commitment hashes.
//   2. `build_v2_state_trace(tier, nonce)` — produces the 30-row 12-column
//      state trace covering 2 absorption blocks. The final row's rate
//      portion equals the v2 commitment (verified by tests).
//   3. `RESCUE_INPUT_FELTS` and `RESCUE_BLOCKS` constants for the trace shape.
//
// The AIR transition constraints + boundary constraints + predicate columns
// are deferred to the next iteration; see `docs/STEP_2B_COMMITMENT_DESIGN.md`
// "Implementation status" section.

use trusset_circuits_common::rescue_air::{
    self as rescue_air, CAPACITY_RANGE_START, PERMUTATION_TRACE_ROWS, RATE_RANGE_START, RATE_WIDTH,
    STATE_WIDTH,
};
use trusset_circuits_common::{bytes_to_field, CircuitId, COMMITMENT_TAG};

/// Number of input felts to the v2 Rescue commitment for tier_threshold.
///
/// Layout: 5 tag felts + 1 circuit_id felt + 1 length felt + 1 tier felt + 5
/// nonce felts = **13 felts**.
pub const RESCUE_INPUT_FELTS: usize = 13;

/// Number of Rescue absorption blocks needed to absorb `RESCUE_INPUT_FELTS`
/// at the rate width of 8. For 13 felts: ceil(13/8) = **2 blocks**.
pub const RESCUE_BLOCKS: usize = 2;

/// Active trace rows in the AIR-friendly layout (explicit absorption row).
///
/// Row 0: initial state (post-first-absorption).
/// Rows 1-14: 14 sub-round states of block 1.
/// Row 15: absorption row — state[4..9] gets nonce_felts added (witness-
///         supplied; AIR enforces capacity preservation only).
/// Rows 16-29: 14 sub-round states of block 2.
/// Row 29: final state — `state[4..8]` equals v2 commitment.
///
/// Total: 30 rows. Padded to the next power of two = 32 in the Winterfell
/// `TraceTable`. Rows 30-31 are pure stall rows (`next = current`).
pub const REAL_TRACE_ROWS: usize = 30;

/// Power-of-two padded trace length used by the Winterfell `TraceTable`.
pub const REAL_TRACE_LENGTH: usize = 32;

/// Build the 13-felt input vector for the v2 commitment of (tier, nonce).
/// Byte-equal to the elements fed into `Rp64_256::hash_elements` by
/// `compute_commitment(CircuitId::TierThreshold, &[Felt::new(tier)], nonce)`.
pub fn build_v2_input_felts(tier: u8, nonce: &[u8; 32]) -> [BaseElement; RESCUE_INPUT_FELTS] {
    let mut out = [BaseElement::ZERO; RESCUE_INPUT_FELTS];
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    debug_assert_eq!(tag_felts.len(), 5, "COMMITMENT_TAG must chunk to 5 felts");
    let nonce_felts = bytes_to_field(nonce);
    debug_assert_eq!(nonce_felts.len(), 5, "nonce must chunk to 5 felts");

    // 0..5 : tag felts
    out[0..5].copy_from_slice(&tag_felts);
    // 5    : circuit_id
    out[5] = BaseElement::new(u64::from(CircuitId::TierThreshold.as_u8()));
    // 6    : witness felt count (=1 for tier_threshold)
    out[6] = BaseElement::new(1);
    // 7    : tier (the single witness felt)
    out[7] = BaseElement::new(u64::from(tier));
    // 8..13: nonce felts
    out[8..13].copy_from_slice(&nonce_felts);
    out
}

/// Build the row-by-row state trace for the 2-block Rescue absorption in
/// the AIR-friendly **explicit-absorption-row** layout.
///
/// Returns exactly `REAL_TRACE_LENGTH = 32` rows of 12-element state.
///
/// Layout:
/// - Row 0: post-first-absorption state. `state[0]=13`, `state[1..4]=0`,
///   `state[4..12]=input_felts[0..8]`.
/// - Rows 1-14: 14 sub-round states of block 1 permutation. Row 14 is the
///   post-block-1-permutation state.
/// - Row 15: **absorption row**. `state[0..4][15] = state[0..4][14]`
///   (capacity unchanged), `state[4..9][15] = state[4..9][14] +
///   input_felts[8..13]` (nonce felts absorbed), `state[9..12][15] =
///   state[9..12][14]` (rest of rate unchanged).
/// - Rows 16-29: 14 sub-round states of block 2 permutation. Row 29 is the
///   final state; `state[4..8][29]` equals the v2 commitment.
/// - Rows 30-31: stall rows. `state[i][30] = state[i][29]` for all i;
///   same for row 31.
pub fn build_v2_state_trace(tier: u8, nonce: &[u8; 32]) -> Vec<[BaseElement; STATE_WIDTH]> {
    let input_felts = build_v2_input_felts(tier, nonce);

    let mut rows: Vec<[BaseElement; STATE_WIDTH]> = Vec::with_capacity(REAL_TRACE_LENGTH);

    // Row 0: initial state (post-first-absorption).
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE_START] = BaseElement::new(RESCUE_INPUT_FELTS as u64);
    for i in 0..RATE_WIDTH {
        state[RATE_RANGE_START + i] = input_felts[i];
    }

    // Rows 0..14: block 1's 15-row permutation trace (row 0 entry + 14
    // sub-round outputs).
    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);
    debug_assert_eq!(rows.len(), 15);

    // Row 15: absorption row. Take block1's row 14 (post-permutation) and
    // add nonce felts to rate[0..5].
    let mut absorbed = block1[PERMUTATION_TRACE_ROWS - 1];
    for i in 0..5 {
        absorbed[RATE_RANGE_START + i] += input_felts[8 + i];
    }
    rows.push(absorbed);
    debug_assert_eq!(rows.len(), 16);

    // Rows 16..29: block 2's 14 sub-round outputs (skip block2[0] since it
    // is the entry state, which we already have at row 15).
    let block2 = rescue_air::permutation_trace(absorbed);
    rows.extend_from_slice(&block2[1..]);
    debug_assert_eq!(rows.len(), 30);

    // Rows 30-31: stall padding (state unchanged from row 29).
    let final_state = rows[REAL_TRACE_ROWS - 1];
    rows.push(final_state);
    rows.push(final_state);

    debug_assert_eq!(rows.len(), REAL_TRACE_LENGTH);
    rows
}

/// Extract the v2 commitment digest from the final active row of the trace.
/// The digest lives at `state[4..8]` per `Rp64_256` convention, and is
/// stable from row 29 (final permutation output) through rows 30-31 (stall
/// padding).
pub fn final_digest_from_trace(
    trace: &[[BaseElement; STATE_WIDTH]],
) -> trusset_circuits_common::Digest {
    let last = trace.last().expect("trace must have at least one row");
    [last[4], last[5], last[6], last[7]]
}

#[cfg(test)]
mod v2_real_trace_tests {
    use super::*;
    use trusset_circuits_common::compute_commitment;

    fn assert_trace_matches_v2_commitment(tier: u8, nonce: &[u8; 32]) {
        let trace = build_v2_state_trace(tier, nonce);
        let trace_digest = final_digest_from_trace(&trace);
        let expected = compute_commitment(
            CircuitId::TierThreshold,
            &[BaseElement::new(u64::from(tier))],
            nonce,
        );
        assert_eq!(
            trace_digest, expected,
            "final trace row's rate portion must equal v2 commitment"
        );
    }

    #[test]
    fn input_felts_length_is_13() {
        let felts = build_v2_input_felts(1, &[0u8; 32]);
        assert_eq!(felts.len(), RESCUE_INPUT_FELTS);
    }

    #[test]
    fn input_felts_circuit_id_at_position_5() {
        let felts = build_v2_input_felts(1, &[0u8; 32]);
        assert_eq!(
            felts[5],
            BaseElement::new(u64::from(CircuitId::TierThreshold.as_u8()))
        );
    }

    #[test]
    fn input_felts_length_at_position_6_is_1() {
        let felts = build_v2_input_felts(1, &[0u8; 32]);
        assert_eq!(felts[6], BaseElement::new(1));
    }

    #[test]
    fn input_felts_tier_at_position_7() {
        let felts = build_v2_input_felts(2, &[0u8; 32]);
        assert_eq!(felts[7], BaseElement::new(2));
    }

    #[test]
    fn trace_length_is_32_with_30_active_rows() {
        assert_eq!(REAL_TRACE_ROWS, 30);
        assert_eq!(REAL_TRACE_LENGTH, 32);
        let trace = build_v2_state_trace(1, &[0u8; 32]);
        assert_eq!(trace.len(), 32);
    }

    #[test]
    fn padding_rows_30_31_equal_row_29() {
        let trace = build_v2_state_trace(2, &[0u8; 32]);
        assert_eq!(trace[30], trace[29], "row 30 must stall (= row 29)");
        assert_eq!(trace[31], trace[29], "row 31 must stall (= row 29)");
    }

    #[test]
    fn absorption_row_15_preserves_capacity_and_high_rate() {
        let nonce = [0x42u8; 32];
        let trace = build_v2_state_trace(1, &nonce);
        // Capacity [0..4] unchanged from row 14
        for i in 0..4 {
            assert_eq!(trace[15][i], trace[14][i], "capacity[{i}] preserved");
        }
        // High rate [9..12] unchanged from row 14
        for i in 9..12 {
            assert_eq!(
                trace[15][i], trace[14][i],
                "rate position {i} preserved (not absorbed)"
            );
        }
        // Low rate [4..9] = row 14 + input_felts[8..13]
        let input_felts = build_v2_input_felts(1, &nonce);
        for i in 0..5 {
            assert_eq!(
                trace[15][RATE_RANGE_START + i],
                trace[14][RATE_RANGE_START + i] + input_felts[8 + i],
                "rate position {} absorbs input_felts[{}]",
                RATE_RANGE_START + i,
                8 + i
            );
        }
    }

    #[test]
    fn trace_state_at_row_0_has_capacity_13() {
        let trace = build_v2_state_trace(1, &[0u8; 32]);
        assert_eq!(trace[0][0], BaseElement::new(13));
        assert_eq!(trace[0][1], BaseElement::ZERO);
        assert_eq!(trace[0][2], BaseElement::ZERO);
        assert_eq!(trace[0][3], BaseElement::ZERO);
    }

    #[test]
    fn trace_state_at_row_0_rate_holds_first_8_input_felts() {
        let nonce = [0u8; 32];
        let trace = build_v2_state_trace(2, &nonce);
        let input_felts = build_v2_input_felts(2, &nonce);
        for i in 0..RATE_WIDTH {
            assert_eq!(
                trace[0][RATE_RANGE_START + i],
                input_felts[i],
                "rate[{i}] at row 0 should be input_felt[{i}]"
            );
        }
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_tier_1() {
        assert_trace_matches_v2_commitment(1, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_tier_2() {
        assert_trace_matches_v2_commitment(2, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_tier_3() {
        assert_trace_matches_v2_commitment(3, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_varied_nonces() {
        for n in [0u8, 1, 7, 42, 255] {
            let nonce = [n; 32];
            for tier in [1u8, 2, 3] {
                assert_trace_matches_v2_commitment(tier, &nonce);
            }
        }
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_random_nonce() {
        let mut nonce = [0u8; 32];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) & 0xFF) as u8;
        }
        assert_trace_matches_v2_commitment(2, &nonce);
    }

    #[test]
    fn different_tiers_produce_different_digests() {
        let nonce = [0u8; 32];
        let d1 = final_digest_from_trace(&build_v2_state_trace(1, &nonce));
        let d2 = final_digest_from_trace(&build_v2_state_trace(2, &nonce));
        let d3 = final_digest_from_trace(&build_v2_state_trace(3, &nonce));
        assert_ne!(d1, d2);
        assert_ne!(d2, d3);
        assert_ne!(d1, d3);
    }

    #[test]
    fn different_nonces_produce_different_digests() {
        let d1 = final_digest_from_trace(&build_v2_state_trace(1, &[1u8; 32]));
        let d2 = final_digest_from_trace(&build_v2_state_trace(1, &[2u8; 32]));
        assert_ne!(d1, d2);
    }
}
