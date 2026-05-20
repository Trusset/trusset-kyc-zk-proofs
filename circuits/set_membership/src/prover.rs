//! Winterfell `Prover` for the set_membership Stage 16 AIR.
//!
//! Trace builder for the 33-col × 2048-row trace covering commitment
//! opening (rows 0..45), set_leaf hash (rows 45..90), and conditional-
//! swap Merkle walk (rows 90 onwards), with witness binding + side bit
//! + sibling + carry column bands across the full trace.

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

use trusset_circuits_common::{
    bytes_to_field, rescue_air, CircuitId, COMMITMENT_TAG, SET_LEAF_TAG, SET_NODE_TAG,
};

use crate::air::{
    merkle_final_row_for_depth, AirHashFn, SetAir, SetAirPublicInputs, COL_CARRY_START,
    COL_SIBLING_START, COL_SIDE_BIT, COL_WITNESS_START, MERGE_ROWS_PER_LEVEL, MERKLE_ROW_START,
    SETLEAF_FINAL_ROW, SETLEAF_ROW_START, TRACE_LENGTH, TRACE_WIDTH,
};
use crate::{PathStep, MAX_PADDED_WITNESS_FELTS};

// =====================================================================
// Trace builder helpers (per-phase row generators)
// =====================================================================

/// Build commitment-phase rows 0..45 (cols 0..12 only).
fn build_commitment_rows(value: &[u8], nonce: &[u8; 32]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    let nonce_felts = bytes_to_field(nonce);
    let witness_felts = crate::witness_to_felts(value);
    debug_assert_eq!(tag_felts.len(), 5);
    debug_assert_eq!(nonce_felts.len(), 5);
    debug_assert_eq!(witness_felts.len(), MAX_PADDED_WITNESS_FELTS);

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

    debug_assert_eq!(rows.len(), 45);
    rows
}

/// Build set_leaf-phase rows 45..90 (cols 0..12 only).
fn build_setleaf_rows(value: &[u8]) -> Vec<[BaseElement; 12]> {
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let witness_felts = crate::witness_to_felts(value);

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

    debug_assert_eq!(rows.len(), 45);
    rows
}

/// Build one Merkle merge level's 30 rows (cols 0..12) and return the
/// merged digest. Input: current node digest, sibling digest, side bit.
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

// =====================================================================
// Full 33-col × 2048-row trace assembly
// =====================================================================

/// Build the full 33-column × 2048-row Stage 16 trace table for an
/// honest witness.
pub fn build_trace(value: &[u8], nonce: &[u8; 32], path: &[PathStep]) -> TraceTable<BaseElement> {
    let set_depth = path.len();
    debug_assert!(set_depth > 0 && set_depth <= 32);

    let mut rows: Vec<[BaseElement; TRACE_WIDTH]> =
        vec![[BaseElement::ZERO; TRACE_WIDTH]; TRACE_LENGTH];

    // ---- Cols 0..12: Rescue state ----
    let commit_rows = build_commitment_rows(value, nonce);
    let setleaf_rows = build_setleaf_rows(value);
    for k in 0..45 {
        for c in 0..12 {
            rows[k][c] = commit_rows[k][c];
            rows[SETLEAF_ROW_START + k][c] = setleaf_rows[k][c];
        }
    }

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
        for k in 0..MERGE_ROWS_PER_LEVEL {
            for c in 0..12 {
                rows[level_start + k][c] = level_rows[k][c];
            }
            // Side, sibling, and carry are constant within the level.
            rows[level_start + k][COL_SIDE_BIT] = BaseElement::new(u64::from(side));
            for c in 0..4 {
                rows[level_start + k][COL_SIBLING_START + c] = step.sibling[c];
                rows[level_start + k][COL_CARRY_START + c] = level_input_node[c];
            }
        }
        current_node = merged;
    }

    // Stall padding past the last Merkle level: replicate the final
    // row's state cols and hold carry at the final merged digest.
    let merkle_final_row = if set_depth > 0 {
        MERKLE_ROW_START + set_depth * MERGE_ROWS_PER_LEVEL - 1
    } else {
        SETLEAF_FINAL_ROW
    };
    for k in (merkle_final_row + 1)..TRACE_LENGTH {
        for c in 0..12 {
            rows[k][c] = rows[merkle_final_row][c];
        }
        for c in 0..4 {
            rows[k][COL_CARRY_START + c] = current_node[c];
        }
        // Vary `COL_SIDE_BIT` across stall rows so the column
        // polynomial always has non-trivial degree even when the
        // active Merkle path happens to be all-left or all-right
        // (e.g., index-0 leaves). All merge selectors are 0 in stall
        // rows, so the side-bit boolean and conditional-swap
        // constraints are killed here — only the polynomial degree of
        // the column matters, which Winterfell's debug-mode evaluator
        // checks against the declared `with_cycles(2, [TRACE_LENGTH])`
        // degree. Alternating 0/1 forces degree = TRACE_LENGTH - 1,
        // which the declared degree comfortably absorbs.
        rows[k][COL_SIDE_BIT] = BaseElement::new((k as u64) & 1);
    }

    // ---- Cols 12..24: witness binding, constant across ALL rows ----
    let witness_felts = crate::witness_to_felts(value);
    for k in 0..TRACE_LENGTH {
        for c in 0..MAX_PADDED_WITNESS_FELTS {
            rows[k][COL_WITNESS_START + c] = witness_felts[c];
        }
    }

    // Materialize as a TraceTable.
    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row_idx, row) in rows.iter().enumerate() {
        for col in 0..TRACE_WIDTH {
            trace.set(col, row_idx, row[col]);
        }
    }
    trace
}

/// Extract the final-row digest. Kept for backward compatibility with
/// callers that want the set_root from a trace.
pub fn final_digest_from_trace(
    trace: &[[BaseElement; TRACE_WIDTH]],
    set_depth: u8,
) -> trusset_circuits_common::Digest {
    let row = merkle_final_row_for_depth(set_depth);
    [trace[row][4], trace[row][5], trace[row][6], trace[row][7]]
}

// =====================================================================
// Prover
// =====================================================================

pub struct SetProver {
    options: ProofOptions,
    public_inputs: SetAirPublicInputs,
}

impl SetProver {
    pub fn new(options: ProofOptions, public_inputs: SetAirPublicInputs) -> Self {
        Self {
            options,
            public_inputs,
        }
    }
}

impl Prover for SetProver {
    type BaseField = BaseElement;
    type Air = SetAir;
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

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> SetAirPublicInputs {
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

/// Top-level build_proof. Takes the witness `(value, nonce, path)` plus
/// the public inputs and produces serialized proof bytes.
pub fn build_proof(
    value: &[u8],
    nonce: &[u8; 32],
    path: &[PathStep],
    public: &SetAirPublicInputs,
    options: ProofOptions,
    _prover_seed: &[u8; 32],
) -> Result<Vec<u8>, winterfell::ProverError> {
    let trace = build_trace(value, nonce, path);
    let prover = SetProver::new(options, public.clone());
    let proof = prover.prove(trace)?;
    Ok(proof.to_bytes())
}

/// Build `SetAirPublicInputs` from circuit-level public inputs.
pub fn public_to_air(
    commitment: &trusset_circuits_common::Digest,
    set_root: &trusset_circuits_common::Digest,
    set_depth: u8,
) -> SetAirPublicInputs {
    SetAirPublicInputs {
        commitment: [commitment[0], commitment[1], commitment[2], commitment[3]],
        set_root: [set_root[0], set_root[1], set_root[2], set_root[3]],
        set_depth: BaseElement::new(u64::from(set_depth)),
    }
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_set_tree, inclusion_path, witness_to_felts};
    use trusset_circuits_common::compute_commitment;

    #[test]
    fn build_trace_shape() {
        use winterfell::Trace;
        let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
        let (_, _, leaves) = build_set_tree(&values);
        let path = inclusion_path(&leaves, 0);
        let trace = build_trace(b"DEU", &[0u8; 32], &path);
        assert_eq!(trace.width(), TRACE_WIDTH);
        assert_eq!(trace.length(), TRACE_LENGTH);
    }

    #[test]
    fn build_trace_commitment_boundary() {
        let values: Vec<&[u8]> = vec![b"DEU", b"FRA", b"USA", b"GBR"];
        let (_, _, leaves) = build_set_tree(&values);
        let path = inclusion_path(&leaves, 0);
        let value = b"DEU";
        let nonce = [0x55u8; 32];
        let trace = build_trace(value, &nonce, &path);

        let trace_commit = [
            trace.get(4, 44),
            trace.get(5, 44),
            trace.get(6, 44),
            trace.get(7, 44),
        ];
        let expected =
            compute_commitment(CircuitId::SetMembership, &witness_to_felts(value), &nonce);
        assert_eq!(trace_commit, expected);
    }
}
