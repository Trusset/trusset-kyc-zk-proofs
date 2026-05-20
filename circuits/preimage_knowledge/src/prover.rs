//! Winterfell `Prover` for the preimage_knowledge real AIR.

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

use trusset_circuits_common::rescue_air::{
    self, CAPACITY_RANGE_START, PERMUTATION_TRACE_ROWS, RATE_RANGE_START, RATE_WIDTH, STATE_WIDTH,
};
use trusset_circuits_common::{bytes_to_field, CircuitId, COMMITMENT_TAG};

use crate::air::{
    AirHashFn, PreimageAir, PreimageAirPublicInputs, AIR_MAX_VALUE_BYTES, COL_LEN_BITS_START,
    COL_SLACK_BITS_START, NUM_BLOCKS, NUM_INPUT_FELTS, NUM_LEN_BITS, NUM_SLACK_BITS, TRACE_LENGTH,
    TRACE_WIDTH,
};
use crate::MAX_PADDED_WITNESS_FELTS;

/// Build the 32-felt v2 commitment input vector for `(value, nonce)`.
pub fn build_v2_input_felts(value: &[u8], nonce: &[u8; 32]) -> [BaseElement; NUM_INPUT_FELTS] {
    let mut out = [BaseElement::ZERO; NUM_INPUT_FELTS];
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    debug_assert_eq!(tag_felts.len(), 5);
    let nonce_felts = bytes_to_field(nonce);
    debug_assert_eq!(nonce_felts.len(), 5);

    // 0..5  : tag felts
    out[0..5].copy_from_slice(&tag_felts);
    // 5     : circuit_id
    out[5] = BaseElement::new(u64::from(CircuitId::PreimageKnowledge.as_u8()));
    // 6     : witness felt count (= MAX_PADDED_WITNESS_FELTS)
    out[6] = BaseElement::new(MAX_PADDED_WITNESS_FELTS as u64);
    // 7..27 : padded witness felts (20 felts)
    let witness_felts = crate::witness_to_felts(value);
    assert!(
        witness_felts.len() >= MAX_PADDED_WITNESS_FELTS,
        "witness_to_felts must produce at least {} felts (got {})",
        MAX_PADDED_WITNESS_FELTS,
        witness_felts.len()
    );
    out[7..7 + MAX_PADDED_WITNESS_FELTS]
        .copy_from_slice(&witness_felts[..MAX_PADDED_WITNESS_FELTS]);
    // 27..32: nonce felts (5 felts)
    out[27..32].copy_from_slice(&nonce_felts);
    out
}

/// Build the row-by-row state trace for the 4-block Rescue absorption.
/// Returns exactly `TRACE_LENGTH = 64` rows.
///
/// Block layout:
/// - Row 0: post-first-absorption (state[0]=32, rate[0..8]=input[0..8])
/// - Rows 1-14: block 1 sub-rounds
/// - Row 15: absorption row 2 (rate += input[8..16])
/// - Rows 16-29: block 2 sub-rounds
/// - Row 30: absorption row 3 (rate += input[16..24])
/// - Rows 31-44: block 3 sub-rounds
/// - Row 45: absorption row 4 (rate += input[24..32])
/// - Rows 46-59: block 4 sub-rounds
/// - Rows 60-63: stall padding
pub fn build_v2_state_trace(value: &[u8], nonce: &[u8; 32]) -> Vec<[BaseElement; STATE_WIDTH]> {
    let input_felts = build_v2_input_felts(value, nonce);
    let mut rows: Vec<[BaseElement; STATE_WIDTH]> = Vec::with_capacity(TRACE_LENGTH);

    // Row 0: state[0] = num_input_felts, state[4..12] = input_felts[0..8].
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE_START] = BaseElement::new(NUM_INPUT_FELTS as u64);
    for i in 0..RATE_WIDTH {
        state[RATE_RANGE_START + i] = input_felts[i];
    }

    // Block 1: rows 0..14 (15 rows total).
    let block1 = rescue_air::permutation_trace(state);
    rows.extend_from_slice(&block1);
    debug_assert_eq!(rows.len(), 15);

    // Absorb subsequent blocks.
    let mut current_state = block1[PERMUTATION_TRACE_ROWS - 1];
    for block in 1..NUM_BLOCKS {
        // Absorption row.
        for i in 0..RATE_WIDTH {
            current_state[RATE_RANGE_START + i] += input_felts[block * RATE_WIDTH + i];
        }
        rows.push(current_state);

        // 14 sub-round rows for this block.
        let block_trace = rescue_air::permutation_trace(current_state);
        rows.extend_from_slice(&block_trace[1..]);

        current_state = block_trace[PERMUTATION_TRACE_ROWS - 1];
    }
    debug_assert_eq!(rows.len(), 60);

    // Stall padding rows 60..64 (4 rows).
    let final_state = rows[59];
    for _ in 0..4 {
        rows.push(final_state);
    }

    debug_assert_eq!(rows.len(), TRACE_LENGTH);
    rows
}

/// Extract the v2 commitment digest from the final row's rate output.
pub fn final_digest_from_trace(
    trace: &[[BaseElement; STATE_WIDTH]],
) -> trusset_circuits_common::Digest {
    let last = trace.last().expect("trace must have at least one row");
    [last[4], last[5], last[6], last[7]]
}

/// Build the 28-col × 64-row Winterfell trace table for Stage 17.
///
/// Cols 0..12: Rescue state from `build_v2_state_trace`.
/// Cols 12..20: 8-bit boolean decomposition of `value.len() as u64`.
/// Cols 20..28: 8-bit boolean decomposition of `AIR_MAX_VALUE_BYTES - value.len()`.
///
/// The trace builder reads `value.len()` directly — the prover is
/// trusted to use the actual byte length; if not, the AIR's
/// linear-combination residual catches the lie at the bit decomposition.
pub fn build_trace(value: &[u8], nonce: &[u8; 32]) -> TraceTable<BaseElement> {
    let state_rows = build_v2_state_trace(value, nonce);
    debug_assert_eq!(state_rows.len(), TRACE_LENGTH);
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);

    // Cols 0..12: Rescue state.
    for (row_idx, row) in state_rows.iter().enumerate() {
        for col in 0..12 {
            trace.set(col, row_idx, row[col]);
        }
    }

    // Cols 12..28: bit-decomposition bands (constant across all rows).
    let value_len_bytes = value.len() as u64;
    let slack = AIR_MAX_VALUE_BYTES.wrapping_sub(value_len_bytes);
    for row_idx in 0..TRACE_LENGTH {
        for i in 0..NUM_LEN_BITS {
            let bit = (value_len_bytes >> i) & 1;
            trace.set(COL_LEN_BITS_START + i, row_idx, BaseElement::new(bit));
        }
        for i in 0..NUM_SLACK_BITS {
            let bit = (slack >> i) & 1;
            trace.set(COL_SLACK_BITS_START + i, row_idx, BaseElement::new(bit));
        }
    }

    trace
}

/// Winterfell `Prover` impl.
pub struct PreimageProver {
    options: ProofOptions,
    public_inputs: PreimageAirPublicInputs,
}

impl PreimageProver {
    pub fn new(options: ProofOptions, public_inputs: PreimageAirPublicInputs) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for PreimageProver {
    type BaseField = BaseElement;
    type Air = PreimageAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> PreimageAirPublicInputs {
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
    value: &[u8],
    nonce: &[u8; 32],
    public: &PreimageAirPublicInputs,
    options: ProofOptions,
    _prover_seed: &[u8; 32],
) -> Result<Vec<u8>, winterfell::ProverError> {
    let trace = build_trace(value, nonce);
    let prover = PreimageProver::new(options, public.clone());
    let proof = prover.prove(trace)?;
    Ok(proof.to_bytes())
}

/// Convert a `trusset_circuits_common::Digest` into the AIR's
/// `[BaseElement; 4]` representation.
pub fn digest_to_air_limbs(digest: &trusset_circuits_common::Digest) -> [BaseElement; 4] {
    let mut out = [BaseElement::ZERO; 4];
    for i in 0..4 {
        out[i] = digest[i];
    }
    out
}

#[cfg(test)]
mod v2_real_trace_tests {
    use super::*;
    use trusset_circuits_common::compute_commitment;

    fn assert_trace_matches_v2_commitment(value: &[u8], nonce: &[u8; 32]) {
        let trace = build_v2_state_trace(value, nonce);
        let trace_digest = final_digest_from_trace(&trace);
        let expected = compute_commitment(
            CircuitId::PreimageKnowledge,
            &crate::witness_to_felts(value),
            nonce,
        );
        assert_eq!(
            trace_digest,
            expected,
            "final trace row's rate must equal v2 commitment for value.len()={}",
            value.len()
        );
    }

    #[test]
    fn input_felts_length_is_32() {
        let felts = build_v2_input_felts(b"alice", &[0u8; 32]);
        assert_eq!(felts.len(), NUM_INPUT_FELTS);
    }

    #[test]
    fn input_felts_layout() {
        let felts = build_v2_input_felts(b"alice", &[0u8; 32]);
        // Felt 5: circuit_id (PreimageKnowledge = 4).
        assert_eq!(felts[5], BaseElement::new(4));
        // Felt 6: length = 20.
        assert_eq!(felts[6], BaseElement::new(20));
    }

    #[test]
    fn trace_length_is_64() {
        assert_eq!(TRACE_LENGTH, 64);
        let trace = build_v2_state_trace(b"alice", &[0u8; 32]);
        assert_eq!(trace.len(), 64);
    }

    #[test]
    fn padding_rows_60_to_63_equal_row_59() {
        let trace = build_v2_state_trace(b"alice", &[0u8; 32]);
        for k in 60..64 {
            assert_eq!(trace[k], trace[59], "row {k} must stall (= row 59)");
        }
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_empty_value() {
        assert_trace_matches_v2_commitment(b"", &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_short_value() {
        assert_trace_matches_v2_commitment(b"alice", &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_full_length_value() {
        let value = vec![0xa5u8; 128];
        assert_trace_matches_v2_commitment(&value, &[0u8; 32]);
    }

    #[test]
    fn trace_final_row_matches_v2_commitment_varied() {
        for len in [0usize, 1, 7, 8, 14, 50, 100, 128] {
            let value: Vec<u8> = (0u8..len as u8).collect();
            for n in [0u8, 7, 42] {
                assert_trace_matches_v2_commitment(&value, &[n; 32]);
            }
        }
    }

    #[test]
    fn different_values_produce_different_digests() {
        let nonce = [0u8; 32];
        let d_alice = final_digest_from_trace(&build_v2_state_trace(b"alice", &nonce));
        let d_bob = final_digest_from_trace(&build_v2_state_trace(b"bob", &nonce));
        assert_ne!(d_alice, d_bob);
    }
}
