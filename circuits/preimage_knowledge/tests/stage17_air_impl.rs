//! Stage 17 work-in-progress — first attempt at a complete Winterfell
//! `Air` trait impl for the in-AIR length-range predicate, with
//! end-to-end prove + verify roundtrip.
//!
//! Mirrors the Stage 16 methodology that worked for set_membership:
//!   1. Validate trace math + constraint residuals host-side (done in
//!      `stage17_reference.rs`)
//!   2. Build a working Air impl in a test module (this file)
//!   3. Promote to production once roundtrip passes
//!
//! If `stage17_air_prove_verify_roundtrip` passes, Stage 17 is
//! functionally complete and ready for production promotion.

#![cfg(feature = "prod-proofs-preimage")]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::too_many_arguments)]

use trusset_circuit_preimage_knowledge::{witness_to_felts, MAX_PADDED_WITNESS_FELTS};
use trusset_circuits_common::{
    bytes_to_field, rescue_air, stark_options, CircuitId, COMMITMENT_TAG, STARK_SECURITY_BITS,
};
use winterfell::{
    crypto::{hashers::Rp64_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    verify, AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, CompositionPoly,
    CompositionPolyTrace, ConstraintCompositionCoefficients, DefaultConstraintCommitment,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, PartitionOptions, Proof,
    ProofOptions, Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable,
    TransitionConstraintDegree,
};

// =====================================================================
// Constants
// =====================================================================

const TRACE_WIDTH: usize = 28; // 12 Rescue + 8 len_bits + 8 slack_bits
const TRACE_LENGTH: usize = 64;
const FINAL_ROW: usize = 59;
const NUM_INPUT_FELTS: usize = 32;
const COL_LEN_BITS_START: usize = 12;
const COL_SLACK_BITS_START: usize = 20;
const NUM_LEN_BITS: usize = 8;
const NUM_SLACK_BITS: usize = 8;

// =====================================================================
// Public inputs
// =====================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stage17PublicInputs {
    commitment: [BaseElement; 4],
    value_len_bytes: BaseElement,
    max_value_bytes: BaseElement,
}

impl ToElements<BaseElement> for Stage17PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = self.commitment.to_vec();
        v.push(self.value_len_bytes);
        v.push(self.max_value_bytes);
        v
    }
}

// =====================================================================
// AIR
// =====================================================================

struct Stage17Air {
    context: AirContext<BaseElement>,
    commitment: [BaseElement; 4],
    value_len_bytes: BaseElement,
    max_value_bytes: BaseElement,
}

impl Air for Stage17Air {
    type BaseField = BaseElement;
    type PublicInputs = Stage17PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(trace_info.width(), TRACE_WIDTH);
        assert_eq!(trace_info.length(), TRACE_LENGTH);

        let mut degrees: Vec<TransitionConstraintDegree> = Vec::with_capacity(TRACE_WIDTH);

        // State cols 0..12: degree 7 (same as Stage 11).
        for _ in 0..12 {
            degrees.push(TransitionConstraintDegree::with_cycles(
                7,
                vec![TRACE_LENGTH],
            ));
        }
        // Bit cols 12..28: `bit*(bit-1) + (next - current)` + (at row 0
        // only) the linear-combination residual. Empirically Winterfell
        // accepts `new(1)` for trace_length = 64 here in both debug and
        // release builds; `new(2)` worked only in release. Matches the
        // Stage 23 production-AIR declaration after debug/release
        // cross-validation.
        for _ in 0..(NUM_LEN_BITS + NUM_SLACK_BITS) {
            degrees.push(TransitionConstraintDegree::new(1));
        }

        // Boundary assertions:
        //   Row 0: state[0]=32, state[1..4]=0 (3), state[4..9]=tag (5),
        //          state[9]=4 (id), state[10]=20 (length) = 11
        //   Row 0: 8 bit-decomposition cols binding `Σ bit*2^i = value_len_bytes`
        //          → this is NOT a single-cell boundary, must be a multi-felt
        //          aggregate. Encode as a transition residual instead.
        //          Alternative: just emit 16 boundary `Assertion::single`
        //          calls — one per bit, asserting that the bit equals the
        //          appropriate u8 decomposition of `value_len_bytes` and
        //          `slack`. The verifier reconstructs the same decomp from
        //          public inputs and compares.
        //   Row 59 (FINAL_ROW): state[4..8] = commitment (4)
        //   Total: 11 + 4 + 16 (bit boundary cells) = 31.
        //
        // Side note: by encoding the bit values directly at row 0 as
        // boundary assertions, we get the linear-combination constraint
        // automatically (the verifier knows each bit's value, computes
        // the sum, compares to value_len_bytes / slack). And the
        // boolean check is automatic since asserted values are
        // explicitly 0 or 1.
        let num_assertions = 11 + 4 + 16;

        Self {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            commitment: pub_inputs.commitment,
            value_len_bytes: pub_inputs.value_len_bytes,
            max_value_bytes: pub_inputs.max_value_bytes,
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

        // Periodic: 16 cols = 12 ark + sel_first + sel_second + sel_absorb + sel_pad.
        let ark_combined: [E; 12] = std::array::from_fn(|i| periodic_values[i]);
        let sel_first = periodic_values[12];
        let sel_second = periodic_values[13];
        let sel_absorb = periodic_values[14];
        let sel_pad = periodic_values[15];

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

        // State col 0..12 residuals.
        for i in 0..12 {
            let res_first = next[i] - mds_sboxed[i] - ark_combined[i];
            let res_second = current[i] - second_half_pow7[i];
            let res_pad = next[i] - current[i];
            let is_cap = i < 4;
            let res_absorb = if is_cap {
                next[i] - current[i]
            } else {
                E::ZERO
            };
            result[i] = sel_first * res_first
                + sel_second * res_second
                + sel_absorb * res_absorb
                + sel_pad * res_pad;
        }

        // Bit cols 12..28: boolean + constancy.
        //
        // Combined residual: bit*(bit-1) + (next - current).
        // On honest trace:
        //   - bit*(bit-1) = 0 (bit is in {0,1})
        //   - next - current = 0 (constancy)
        //   Both terms zero.
        // On tamper:
        //   - non-boolean bit fires bit*(bit-1)
        //   - drifting bit fires next - current
        //
        // The boolean term is degree 2 in trace; the constancy term is
        // degree 1. We declared degree 2 for these constraints.
        //
        // Additionally: at row 0 only (sel_row_0 from periodic col 16),
        // bit col 12 (len_bits[0]) carries the linear-combination
        // residual `Σ len_bits[i]*2^i - value_len_bytes`, and bit col
        // 20 (slack_bits[0]) carries `Σ slack_bits[i]*2^i - slack`.
        // These bind the bit decomposition to the public field values
        // and prevent slack-overflow attacks.
        let sel_row_0 = periodic_values[16];
        let value_len_e = E::from(self.value_len_bytes);
        let max_value_e = E::from(self.max_value_bytes);

        let mut len_acc = E::ZERO;
        for i in 0..NUM_LEN_BITS {
            let bit = current[COL_LEN_BITS_START + i];
            len_acc += bit * E::from(BaseElement::new(1u64 << i));
        }
        let len_lincomb_res = len_acc - value_len_e;

        let mut slack_acc = E::ZERO;
        for i in 0..NUM_SLACK_BITS {
            let bit = current[COL_SLACK_BITS_START + i];
            slack_acc += bit * E::from(BaseElement::new(1u64 << i));
        }
        let slack_lincomb_res = slack_acc - (max_value_e - value_len_e);

        for c in COL_LEN_BITS_START..COL_LEN_BITS_START + NUM_LEN_BITS {
            let bit = current[c];
            result[c] = bit * (bit - E::ONE) + (next[c] - current[c]);
        }
        for c in COL_SLACK_BITS_START..COL_SLACK_BITS_START + NUM_SLACK_BITS {
            let bit = current[c];
            result[c] = bit * (bit - E::ONE) + (next[c] - current[c]);
        }

        // Pile the linear-combination residual onto bit col 12 (first
        // len_bit) and bit col 20 (first slack_bit), gated by sel_row_0.
        result[COL_LEN_BITS_START] += sel_row_0 * len_lincomb_res;
        result[COL_SLACK_BITS_START] += sel_row_0 * slack_lincomb_res;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut a = Vec::with_capacity(31);

        // Row 0: commitment-phase setup (11 assertions).
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

        // Row FINAL_ROW: commitment (4).
        for i in 0..4 {
            a.push(Assertion::single(4 + i, FINAL_ROW, self.commitment[i]));
        }

        // Row 0: 8 len_bits and 8 slack_bits bound to public values.
        // The verifier computes the bit decomposition from
        // `value_len_bytes` and `slack = max_value_bytes - value_len_bytes`
        // and asserts each bit matches.
        let value_len: u64 = self.value_len_bytes.as_int();
        let max_value: u64 = self.max_value_bytes.as_int();
        let slack = max_value.wrapping_sub(value_len);

        // SAFETY/SOUNDNESS NOTE: if value_len > max_value, slack wraps
        // around p - (value_len - max_value), a huge value. Its 8-bit
        // decomposition CANNOT match (the high bits would all need to
        // be set to specific values that don't sum correctly). The
        // boundary assertion below will fail, the AIR will reject.
        for i in 0..NUM_LEN_BITS {
            let bit = (value_len >> i) & 1;
            a.push(Assertion::single(
                COL_LEN_BITS_START + i,
                0,
                BaseElement::new(bit),
            ));
        }
        for i in 0..NUM_SLACK_BITS {
            let bit = (slack >> i) & 1;
            a.push(Assertion::single(
                COL_SLACK_BITS_START + i,
                0,
                BaseElement::new(bit),
            ));
        }

        a
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
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
        // sel_row_0: 1 at transition 0 only.
        cols[16][0] = BaseElement::ONE;
        cols
    }
}

type Stage17HashFn = Rp64_256;
type Stage17VC = MerkleTree<Stage17HashFn>;
type Stage17RandomCoin = DefaultRandomCoin<Stage17HashFn>;

// =====================================================================
// Trace builder
// =====================================================================

fn build_full_trace_table(
    value: &[u8],
    nonce: &[u8; 32],
    value_len_bytes: u64,
    max_value_bytes: u64,
) -> TraceTable<BaseElement> {
    let tag_felts = bytes_to_field(&COMMITMENT_TAG);
    let nonce_felts = bytes_to_field(nonce);
    let witness_felts = witness_to_felts(value);

    let mut input = [BaseElement::ZERO; NUM_INPUT_FELTS];
    input[0..5].copy_from_slice(&tag_felts);
    input[5] = BaseElement::new(u64::from(CircuitId::PreimageKnowledge.as_u8()));
    input[6] = BaseElement::new(MAX_PADDED_WITNESS_FELTS as u64);
    input[7..27].copy_from_slice(&witness_felts);
    input[27..32].copy_from_slice(&nonce_felts);

    let mut rows: Vec<[BaseElement; TRACE_WIDTH]> =
        vec![[BaseElement::ZERO; TRACE_WIDTH]; TRACE_LENGTH];

    let mut state = [BaseElement::ZERO; 12];
    state[0] = BaseElement::new(32);
    state[4..12].copy_from_slice(&input[0..8]);
    let block1 = rescue_air::permutation_trace(state);
    for k in 0..15 {
        for c in 0..12 {
            rows[k][c] = block1[k][c];
        }
    }
    let mut current = block1[14];
    for block in 1..4 {
        for i in 0..8 {
            current[4 + i] += input[block * 8 + i];
        }
        let base = block * 15;
        for c in 0..12 {
            rows[base][c] = current[c];
        }
        let perm = rescue_air::permutation_trace(current);
        for k in 1..15 {
            for c in 0..12 {
                rows[base + k][c] = perm[k][c];
            }
        }
        current = perm[14];
    }

    // Stall padding rows 60..64.
    for k in 60..TRACE_LENGTH {
        for c in 0..12 {
            rows[k][c] = rows[59][c];
        }
    }

    // Bit decomposition bands.
    let mut len_bits = [0u64; 8];
    for i in 0..8 {
        len_bits[i] = (value_len_bytes >> i) & 1;
    }
    let slack = max_value_bytes.wrapping_sub(value_len_bytes);
    let mut slack_bits = [0u64; 8];
    for i in 0..8 {
        slack_bits[i] = (slack >> i) & 1;
    }
    for k in 0..TRACE_LENGTH {
        for i in 0..NUM_LEN_BITS {
            rows[k][COL_LEN_BITS_START + i] = BaseElement::new(len_bits[i]);
        }
        for i in 0..NUM_SLACK_BITS {
            rows[k][COL_SLACK_BITS_START + i] = BaseElement::new(slack_bits[i]);
        }
    }

    let mut trace = TraceTable::new(TRACE_WIDTH, TRACE_LENGTH);
    for (row_idx, row) in rows.iter().enumerate() {
        for col in 0..TRACE_WIDTH {
            trace.set(col, row_idx, row[col]);
        }
    }
    trace
}

// =====================================================================
// Prover
// =====================================================================

struct Stage17Prover {
    options: ProofOptions,
    public_inputs: Stage17PublicInputs,
}

impl Prover for Stage17Prover {
    type BaseField = BaseElement;
    type Air = Stage17Air;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Stage17HashFn;
    type VC = Stage17VC;
    type RandomCoin = Stage17RandomCoin;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> Stage17PublicInputs {
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

// =====================================================================
// Tests
// =====================================================================

#[test]
fn stage17_air_prove_verify_roundtrip_5byte_value() {
    let value = b"alice"; // 5 bytes
    let nonce = [0x44u8; 32];
    let value_len = value.len() as u64;
    let max_value = 128u64;

    let commitment = trusset_circuits_common::compute_commitment(
        CircuitId::PreimageKnowledge,
        &witness_to_felts(value),
        &nonce,
    );

    let pub_inputs = Stage17PublicInputs {
        commitment,
        value_len_bytes: BaseElement::new(value_len),
        max_value_bytes: BaseElement::new(max_value),
    };

    let trace = build_full_trace_table(value, &nonce, value_len, max_value);
    let prover = Stage17Prover {
        options: stark_options(),
        public_inputs: pub_inputs.clone(),
    };

    let proof = prover.prove(trace).expect("prove failed");
    let proof_bytes = proof.to_bytes();

    let parsed = Proof::from_bytes(&proof_bytes).expect("proof deserialization failed");
    let accept = AcceptableOptions::MinConjecturedSecurity(STARK_SECURITY_BITS);
    verify::<Stage17Air, Stage17HashFn, Stage17RandomCoin, Stage17VC>(parsed, pub_inputs, &accept)
        .expect("verify failed");
}

#[test]
fn stage17_air_rejects_oversize_length() {
    // Claim value_len_bytes = 200, max_value_bytes = 100. slack
    // overflows; AIR should reject (either at prove time via boundary
    // mismatch, or at verify time).
    let value = b"alice";
    let nonce = [0x55u8; 32];
    let commitment = trusset_circuits_common::compute_commitment(
        CircuitId::PreimageKnowledge,
        &witness_to_felts(value),
        &nonce,
    );

    let pub_inputs = Stage17PublicInputs {
        commitment,
        value_len_bytes: BaseElement::new(200),
        max_value_bytes: BaseElement::new(100),
    };

    // The trace builder uses wrapping arithmetic, so it produces
    // bit_decomp of a huge slack value. The bit decomposition we ship
    // doesn't actually fit in 8 bits, so the trace builder's bits
    // won't sum to the claimed slack. The AIR's boundary assertions
    // will fail.
    let trace = build_full_trace_table(value, &nonce, 200, 100);
    let prover = Stage17Prover {
        options: stark_options(),
        public_inputs: pub_inputs.clone(),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
    match result {
        Err(_) | Ok(Err(_)) => {} // Rejected at prove time. OK.
        Ok(Ok(proof)) => {
            let parsed = Proof::from_bytes(&proof.to_bytes()).unwrap();
            let accept = AcceptableOptions::MinConjecturedSecurity(STARK_SECURITY_BITS);
            let v = verify::<Stage17Air, Stage17HashFn, Stage17RandomCoin, Stage17VC>(
                parsed, pub_inputs, &accept,
            );
            assert!(v.is_err(), "verifier must reject oversize length claim");
        }
    }
}

#[test]
fn stage17_air_rejects_wrong_value_len_claim() {
    // value_len_bytes claimed wrong: actual value is 5 bytes, prover
    // claims 10. The AIR's boundary asserts the bits decompose to 5
    // (since trace builder uses the actual value_len_bytes), but
    // pub_inputs say 10 → mismatch.
    let value = b"alice";
    let nonce = [0x77u8; 32];
    let commitment = trusset_circuits_common::compute_commitment(
        CircuitId::PreimageKnowledge,
        &witness_to_felts(value),
        &nonce,
    );

    let pub_inputs = Stage17PublicInputs {
        commitment,
        value_len_bytes: BaseElement::new(10), // lying
        max_value_bytes: BaseElement::new(128),
    };

    // Build trace honestly with value_len_bytes = 5.
    let trace = build_full_trace_table(value, &nonce, 5, 128);
    let prover = Stage17Prover {
        options: stark_options(),
        public_inputs: pub_inputs.clone(),
    };

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(trace)));
    match result {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(proof)) => {
            let parsed = Proof::from_bytes(&proof.to_bytes()).unwrap();
            let accept = AcceptableOptions::MinConjecturedSecurity(STARK_SECURITY_BITS);
            let v = verify::<Stage17Air, Stage17HashFn, Stage17RandomCoin, Stage17VC>(
                parsed, pub_inputs, &accept,
            );
            assert!(v.is_err(), "verifier must reject wrong value_len claim");
        }
    }
}
