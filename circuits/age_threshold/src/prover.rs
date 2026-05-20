//! Winterfell `Prover` for the age_threshold real AIR.

// See `tier_threshold::prover` for the rationale on these allows.
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
    AgeAir, AgeAirPublicInputs, AirHashFn, COL_BIT_START, NUM_SLACK_BITS, STATE_COLS, TRACE_LENGTH,
    TRACE_WIDTH,
};

/// Build the 34-col × 32-row Winterfell trace table for the real
/// commitment-opening + 22-bit boolean range-check AIR.
///
/// Trace layout:
/// - Cols 0..12: Rescue state (from `build_v2_state_trace`).
/// - Cols 12..34: 22 boolean bit columns. At row 0, bit_i = (slack >> i) & 1
///   where slack = current_epoch_days − dob_days − min_age_days.
///   Rows 1..31 of each bit column hold deterministic non-trivial values so
///   the column polynomial has degree (L-1); the boolean constraint is masked
///   off on those rows by `selector_bind_row_0`.
pub fn build_trace(
    dob_days: u64,
    nonce: &[u8; 32],
    min_age_days: u64,
    current_epoch_days: u64,
) -> TraceTable<BaseElement> {
    let state_rows = build_v2_state_trace(dob_days, nonce);
    debug_assert_eq!(state_rows.len(), TRACE_LENGTH);
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);

    // Fill state columns.
    for (row_idx, row) in state_rows.iter().enumerate() {
        for col in 0..STATE_COLS {
            trace.set(col, row_idx, row[col]);
        }
    }

    // Compute slack as the integer difference if non-negative; otherwise
    // the trace will fail the AIR linear-combination constraint (sound
    // rejection). saturating_sub keeps the host-side math safe for the
    // negative case (we still get a valid-shape trace, just one whose
    // bit decomposition doesn't equal the field-value of ce - dob - min).
    let slack: u64 = current_epoch_days
        .saturating_sub(dob_days)
        .saturating_sub(min_age_days);

    // Fill bit cols.
    for i in 0..NUM_SLACK_BITS {
        let bit = (slack >> i) & 1;
        trace.set(COL_BIT_START + i, 0, BaseElement::new(bit));
        for k in 1..TRACE_LENGTH {
            // Distinct non-zero values so each bit column has polynomial
            // degree (L-1). The boolean + linear constraints are masked
            // off at rows > 0 by `selector_bind_row_0`.
            let v = ((k as u64).wrapping_mul(31)).wrapping_add((i as u64).wrapping_mul(17) + 7);
            trace.set(COL_BIT_START + i, k, BaseElement::new(v));
        }
    }

    trace
}

pub struct AgeProver {
    options: ProofOptions,
    public_inputs: AgeAirPublicInputs,
}

impl AgeProver {
    pub fn new(options: ProofOptions, public_inputs: AgeAirPublicInputs) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for AgeProver {
    type BaseField = BaseElement;
    type Air = AgeAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> AgeAirPublicInputs {
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
    dob_days: u64,
    nonce: &[u8; 32],
    min_age_days: u64,
    current_epoch_days: u64,
    public: &AgeAirPublicInputs,
    options: ProofOptions,
    _prover_seed: &[u8; 32],
) -> Result<Vec<u8>, winterfell::ProverError> {
    let trace = build_trace(dob_days, nonce, min_age_days, current_epoch_days);
    let prover = AgeProver::new(options, public.clone());
    let proof = prover.prove(trace)?;
    Ok(proof.to_bytes())
}

pub fn public_to_air(
    commitment: &trusset_circuits_common::Digest,
    min_age_days: u64,
    current_epoch_days: u64,
) -> AgeAirPublicInputs {
    AgeAirPublicInputs {
        commitment: [commitment[0], commitment[1], commitment[2], commitment[3]],
        min_age_days: BaseElement::new(min_age_days),
        current_epoch_days: BaseElement::new(current_epoch_days),
    }
}

// ============================================================================
// v2 real-AIR trace structure (Phase 2B Step-B Stage 3)
// ============================================================================
//
// Mirrors `circuits/tier_threshold/src/prover.rs` v2 helpers. Same 13-felt /
// 2-block / 29-row trace shape — only the witness encoding differs (8-byte
// `dob_days` instead of 1-byte `tier`, both encoded as a single Goldilocks
// felt under the v2 scheme).

use trusset_circuits_common::rescue_air::{
    self as rescue_air, CAPACITY_RANGE_START, PERMUTATION_TRACE_ROWS, RATE_RANGE_START, RATE_WIDTH,
    STATE_WIDTH,
};
use trusset_circuits_common::{bytes_to_field, CircuitId, COMMITMENT_TAG};

/// Layout: 5 tag + 1 circuit_id + 1 length + 1 dob_days + 5 nonce = 13.
pub const RESCUE_INPUT_FELTS: usize = 13;

/// ceil(13 / 8) = 2.
pub const RESCUE_BLOCKS: usize = 2;

/// 30 active rows (explicit-absorption layout, matches tier_threshold).
pub const REAL_TRACE_ROWS: usize = 30;

/// Power-of-two padded trace length used by the Winterfell `TraceTable`.
pub const REAL_TRACE_LENGTH: usize = 32;

/// Build the 13-felt input vector for the v2 commitment of (dob_days, nonce).
pub fn build_v2_input_felts(dob_days: u64, nonce: &[u8; 32]) -> [BaseElement; RESCUE_INPUT_FELTS] {
    let mut out = [BaseElement::ZERO; RESCUE_INPUT_FELTS];
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    let nonce_felts = bytes_to_field(nonce);
    out[0..5].copy_from_slice(&tag_felts);
    out[5] = BaseElement::new(u64::from(CircuitId::AgeThreshold.as_u8()));
    out[6] = BaseElement::new(1);
    out[7] = BaseElement::new(dob_days);
    out[8..13].copy_from_slice(&nonce_felts);
    out
}

/// Build the 32-row absorption-row-explicit state trace for the v2
/// Rescue absorption of (dob_days, nonce). Final active row (29) has
/// `state[4..8]` equal to the v2 commitment; rows 30-31 are stall padding.
pub fn build_v2_state_trace(dob_days: u64, nonce: &[u8; 32]) -> Vec<[BaseElement; STATE_WIDTH]> {
    let input_felts = build_v2_input_felts(dob_days, nonce);
    let mut rows: Vec<[BaseElement; STATE_WIDTH]> = Vec::with_capacity(REAL_TRACE_LENGTH);

    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE_START] = BaseElement::new(RESCUE_INPUT_FELTS as u64);
    for i in 0..RATE_WIDTH {
        state[RATE_RANGE_START + i] = input_felts[i];
    }

    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);

    let mut absorbed = block1[PERMUTATION_TRACE_ROWS - 1];
    for i in 0..5 {
        absorbed[RATE_RANGE_START + i] += input_felts[8 + i];
    }
    rows.push(absorbed);

    let block2 = rescue_air::permutation_trace(absorbed);
    rows.extend_from_slice(&block2[1..]);

    let final_state = rows[REAL_TRACE_ROWS - 1];
    rows.push(final_state);
    rows.push(final_state);

    debug_assert_eq!(rows.len(), REAL_TRACE_LENGTH);
    rows
}

/// Extract the v2 commitment digest from the final row of the state trace.
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

    fn assert_trace_matches_v2_commitment(dob_days: u64, nonce: &[u8; 32]) {
        let trace = build_v2_state_trace(dob_days, nonce);
        let trace_digest = final_digest_from_trace(&trace);
        let expected = compute_commitment(
            CircuitId::AgeThreshold,
            &[BaseElement::new(dob_days)],
            nonce,
        );
        assert_eq!(
            trace_digest, expected,
            "final trace row's rate portion must equal v2 commitment"
        );
    }

    #[test]
    fn input_felts_length_is_13() {
        assert_eq!(
            build_v2_input_felts(20_000, &[0u8; 32]).len(),
            RESCUE_INPUT_FELTS
        );
    }

    #[test]
    fn input_felts_circuit_id_at_position_5() {
        let felts = build_v2_input_felts(20_000, &[0u8; 32]);
        assert_eq!(
            felts[5],
            BaseElement::new(u64::from(CircuitId::AgeThreshold.as_u8()))
        );
    }

    #[test]
    fn input_felts_dob_days_at_position_7() {
        let felts = build_v2_input_felts(20_587, &[0u8; 32]);
        assert_eq!(felts[7], BaseElement::new(20_587));
    }

    #[test]
    fn trace_length_is_32_with_30_active_rows() {
        assert_eq!(REAL_TRACE_ROWS, 30);
        assert_eq!(REAL_TRACE_LENGTH, 32);
        assert_eq!(build_v2_state_trace(20_000, &[0u8; 32]).len(), 32);
    }

    #[test]
    fn padding_rows_30_31_equal_row_29() {
        let trace = build_v2_state_trace(20_587, &[0u8; 32]);
        assert_eq!(trace[30], trace[29]);
        assert_eq!(trace[31], trace[29]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_at_18yo() {
        // dob 20 years before 2026-05-17 epoch = ~6570 days ago
        assert_trace_matches_v2_commitment(20_587 - 6570, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_at_zero_dob() {
        assert_trace_matches_v2_commitment(0, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_varied() {
        for dob in [0u64, 1, 365, 6570, 20_587, 100_000, 1_000_000] {
            for n in [0u8, 7, 42, 255] {
                assert_trace_matches_v2_commitment(dob, &[n; 32]);
            }
        }
    }

    #[test]
    fn different_dob_days_produce_different_digests() {
        let d1 = final_digest_from_trace(&build_v2_state_trace(10_000, &[0u8; 32]));
        let d2 = final_digest_from_trace(&build_v2_state_trace(10_001, &[0u8; 32]));
        assert_ne!(d1, d2);
    }
}
