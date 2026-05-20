//! Workspace-shared Rescue-Prime AIR gadget.
//!
//! This module is the foundation for Phase 2B Step-B real circuit
//! constraints. It exposes:
//!
//! 1. **Pinned constants** (`STATE_WIDTH`, `RATE_WIDTH`, `NUM_ROUNDS`, `ARK1`,
//!    `ARK2`, `MDS`, `INV_MDS`, `ALPHA`, `INV_ALPHA`, `DIGEST_RANGE_*`) —
//!    mirrors the `winter_crypto::hashers::Rp64_256` instantiation that the
//!    rest of the workspace uses outside AIRs (`circuits/common/src/hash.rs`).
//!    A single audit of these constants covers every Rescue use in the
//!    codebase.
//!
//! 2. **Host-side reference permutation** (`apply_permutation`,
//!    `permutation_trace`, `hash_elements_via_trace`) — byte-equal to
//!    `Rp64_256::apply_permutation` and `Rp64_256::hash_elements`, verified
//!    by [`circuits/common/tests/rescue_air_kat.rs`]. Circuits use these to
//!    build per-row trace tables.
//!
//! 3. **AIR transition-constraint helpers** (`enforce_first_half`,
//!    `enforce_second_half`) — emit the degree-7 polynomial constraints that
//!    bind one sub-round transition between consecutive rows.
//!
//! ## Rescue round structure (matches Rp64_256)
//!
//! Each of the 7 rounds has two halves:
//!
//! ```text
//! First half (sub-round 2k):
//!     state ← state .^ 7              (forward S-box, degree 7)
//!     state ← MDS · state
//!     state ← state + ARK1[k]
//!
//! Second half (sub-round 2k+1):
//!     state ← state .^ (1/7)          (inverse S-box, hard to constrain forward)
//!     state ← MDS · state
//!     state ← state + ARK2[k]
//! ```
//!
//! AIR encoding strategy:
//!
//! - **First-half constraint** (forward S-box, easy):
//!   `next = MDS · (current .^ 7) + ARK1[k]`
//!   → residual `next − MDS · (current.^7) − ARK1[k] = 0`
//!   Degree 7 in `current`.
//!
//! - **Second-half constraint** (inverse S-box, encode backwards):
//!   `current = (MDS⁻¹ · (next − ARK2[k])) .^ 7`
//!   → residual `(MDS⁻¹ · (next − ARK2[k])).^7 − current = 0`
//!   Degree 7 in `next`.
//!
//! Both halves stay at degree 7, fitting within Winterfell's constraint
//! degree budget under the workspace-pinned `STARK_OPTIONS` (blowup 16,
//! quadratic extension — supports composition polynomials up to degree
//! `(blowup - 1) × trace_degree = 15 × (L-1)`).
//!
//! ## Trace shape per permutation
//!
//! One Rescue permutation occupies 15 rows: row 0 is the entry state, rows
//! 1..14 are the post-sub-round states. The final permuted state lives in
//! row 14. Circuits typically pad to the next power of two; for a single
//! permutation the smallest acceptable Winterfell trace length is 16.
//!
//! ## Determinism
//!
//! This module performs no I/O, no allocation outside of `permutation_trace`
//! (which returns a fixed-size array), no RNG. All randomness in circuits
//! using this gadget must flow from
//! `trusset_circuits_common::derive_prover_seed`.

use winter_crypto::hashers::Rp64_256;
use winter_math::FieldElement;

use crate::field::Felt;
use crate::hash::Digest;

// ============================================================================
// Pinned constants (mirror `Rp64_256`)
// ============================================================================

/// State width: 12 field elements = 4 capacity + 8 rate.
pub const STATE_WIDTH: usize = 12;

/// Rate width: 8 field elements (where input is absorbed).
pub const RATE_WIDTH: usize = 8;

/// Capacity width: 4 field elements (reserved, never directly accept input).
pub const CAPACITY_WIDTH: usize = 4;

/// Index of the first rate element in the state. Rate occupies `[4..12)`.
pub const RATE_RANGE_START: usize = 4;

/// Index of the first capacity element. Capacity occupies `[0..4)`.
pub const CAPACITY_RANGE_START: usize = 0;

/// Number of full Rescue rounds.
pub const NUM_ROUNDS: usize = 7;

/// Number of sub-rounds per permutation (2 per round).
pub const SUB_ROUNDS_PER_PERMUTATION: usize = NUM_ROUNDS * 2;

/// Number of trace rows produced by `permutation_trace` (entry + 14
/// sub-round transitions = 15).
pub const PERMUTATION_TRACE_ROWS: usize = SUB_ROUNDS_PER_PERMUTATION + 1;

/// Digest output range within the state (state[4..8] after final
/// permutation).
pub const DIGEST_RANGE_START: usize = 4;
pub const DIGEST_RANGE_END: usize = 8;

/// Digest width: 4 field elements = 32 bytes.
pub const DIGEST_WIDTH: usize = DIGEST_RANGE_END - DIGEST_RANGE_START;

/// S-box exponent.
pub const ALPHA: u64 = 7;

/// Inverse S-box exponent over Goldilocks: `7^(-1) mod (p-1)`.
pub const INV_ALPHA: u64 = 10_540_996_611_094_048_183;

/// Round constants for the first half of each Rescue round.
pub const ARK1: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = Rp64_256::ARK1;

/// Round constants for the second half of each Rescue round.
pub const ARK2: [[Felt; STATE_WIDTH]; NUM_ROUNDS] = Rp64_256::ARK2;

/// MDS matrix (12×12 over Goldilocks).
pub const MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = Rp64_256::MDS;

/// Inverse MDS matrix.
pub const INV_MDS: [[Felt; STATE_WIDTH]; STATE_WIDTH] = Rp64_256::INV_MDS;

// ============================================================================
// Host-side reference operations (byte-equal to Rp64_256)
// ============================================================================

#[inline(always)]
fn apply_sbox_felts(state: &mut [Felt; STATE_WIDTH]) {
    for s in state.iter_mut() {
        *s = s.exp7();
    }
}

#[inline(always)]
fn apply_inv_sbox_felts(state: &mut [Felt; STATE_WIDTH]) {
    for s in state.iter_mut() {
        *s = s.exp(INV_ALPHA);
    }
}

#[inline(always)]
fn apply_mds_felts(state: &mut [Felt; STATE_WIDTH]) {
    let mut result = [Felt::ZERO; STATE_WIDTH];
    for (i, row) in MDS.iter().enumerate() {
        let mut acc = Felt::ZERO;
        for (j, m) in row.iter().enumerate() {
            acc += *m * state[j];
        }
        result[i] = acc;
    }
    *state = result;
}

#[inline(always)]
fn add_constants_felts(state: &mut [Felt; STATE_WIDTH], ark: &[Felt; STATE_WIDTH]) {
    for (s, k) in state.iter_mut().zip(ark.iter()) {
        *s += *k;
    }
}

/// Apply one Rescue sub-round to `state` in place.
///
/// `is_first_half = true` ⇒ S-box (x^7) → MDS → +ARK1\[round\]
/// `is_first_half = false` ⇒ inverse S-box (x^(1/7)) → MDS → +ARK2\[round\]
fn apply_sub_round(state: &mut [Felt; STATE_WIDTH], round: usize, is_first_half: bool) {
    if is_first_half {
        apply_sbox_felts(state);
        apply_mds_felts(state);
        add_constants_felts(state, &ARK1[round]);
    } else {
        apply_inv_sbox_felts(state);
        apply_mds_felts(state);
        add_constants_felts(state, &ARK2[round]);
    }
}

/// Apply a full Rescue-Prime permutation (7 rounds × 2 sub-rounds = 14
/// sub-rounds) to `state` in place. Byte-equal to
/// `Rp64_256::apply_permutation`.
pub fn apply_permutation(state: &mut [Felt; STATE_WIDTH]) {
    for round in 0..NUM_ROUNDS {
        apply_sub_round(state, round, true);
        apply_sub_round(state, round, false);
    }
}

/// Produce the per-row state trace for a single Rescue permutation.
///
/// - Row 0: entry state
/// - Row `2k + 1` (k ∈ 0..7): state after first half of round k
/// - Row `2k + 2` (k ∈ 0..7): state after second half of round k
/// - Row 14: final permuted state
pub fn permutation_trace(
    entry_state: [Felt; STATE_WIDTH],
) -> [[Felt; STATE_WIDTH]; PERMUTATION_TRACE_ROWS] {
    let mut rows = [[Felt::ZERO; STATE_WIDTH]; PERMUTATION_TRACE_ROWS];
    rows[0] = entry_state;
    let mut state = entry_state;
    for round in 0..NUM_ROUNDS {
        apply_sub_round(&mut state, round, true);
        rows[2 * round + 1] = state;
        apply_sub_round(&mut state, round, false);
        rows[2 * round + 2] = state;
    }
    rows
}

/// Mirror of `Rp64_256::hash_elements`: initialize the state with
/// `state[0] = num_elements`, absorb elements into the rate one at a time,
/// applying a permutation each time the rate fills, and one final
/// permutation if any elements remain in the rate. Returns the final state;
/// the digest is `state[4..8]`.
///
/// This function is the host-side reference used by circuits' prover-side
/// trace construction. Byte-equality with `winter_crypto::Hasher::hash_elements`
/// is enforced by `rescue_air_kat`.
pub fn hash_elements_via_trace(elements: &[Felt]) -> [Felt; STATE_WIDTH] {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE_START] = Felt::new(elements.len() as u64);
    let mut i = 0usize;
    for &el in elements {
        state[RATE_RANGE_START + i] += el;
        i += 1;
        if i == RATE_WIDTH {
            apply_permutation(&mut state);
            i = 0;
        }
    }
    if i > 0 {
        apply_permutation(&mut state);
    }
    state
}

/// Mirror of `Rp64_256::merge`: copy two digests into the rate, set
/// capacity\[0\] to `RATE_WIDTH = 8`, apply one permutation. Returns the
/// final state; digest is `state[4..8]`.
pub fn merge_via_trace(a: &Digest, b: &Digest) -> [Felt; STATE_WIDTH] {
    let mut state = [Felt::ZERO; STATE_WIDTH];
    state[CAPACITY_RANGE_START] = Felt::new(RATE_WIDTH as u64);
    state[RATE_RANGE_START..RATE_RANGE_START + DIGEST_WIDTH].copy_from_slice(a);
    state[RATE_RANGE_START + DIGEST_WIDTH..RATE_RANGE_START + RATE_WIDTH].copy_from_slice(b);
    apply_permutation(&mut state);
    state
}

/// Extract the 4-felt digest from a permuted state.
pub fn extract_digest(state: &[Felt; STATE_WIDTH]) -> Digest {
    [
        state[DIGEST_RANGE_START],
        state[DIGEST_RANGE_START + 1],
        state[DIGEST_RANGE_START + 2],
        state[DIGEST_RANGE_START + 3],
    ]
}

// ============================================================================
// AIR transition-constraint helpers
// ============================================================================

/// Compute `x^7` element-wise via the same multiplication chain Winterfell
/// uses for `BaseElement::exp7`. Works for any extension field element.
#[inline(always)]
fn pow7<E: FieldElement>(x: E) -> E {
    let x2 = x.square();
    let x4 = x2.square();
    let x3 = x2 * x;
    x3 * x4
}

/// Multiply a constant `Felt` matrix by an `E`-vector, returning an
/// `E`-vector. Used for both MDS and INV_MDS layers inside constraints.
#[inline(always)]
fn mds_mul<E>(matrix: &[[Felt; STATE_WIDTH]; STATE_WIDTH], v: &[E; STATE_WIDTH]) -> [E; STATE_WIDTH]
where
    E: FieldElement<BaseField = Felt>,
{
    let mut out = [E::ZERO; STATE_WIDTH];
    for (i, row) in matrix.iter().enumerate() {
        let mut acc = E::ZERO;
        for (j, m) in row.iter().enumerate() {
            acc += E::from(*m) * v[j];
        }
        out[i] = acc;
    }
    out
}

/// Enforce the first-half Rescue sub-round transition for round `k`:
///
/// ```text
/// next == MDS · (current .^ 7) + ARK1[k]
/// ```
///
/// Writes 12 constraint residuals into `result`. Constraint degree 7 in
/// `current`.
///
/// The caller is responsible for the periodic gating that selects which
/// `ARK1[k]` is active on each row.
pub fn enforce_first_half<E>(
    current: &[E; STATE_WIDTH],
    next: &[E; STATE_WIDTH],
    ark1: &[E; STATE_WIDTH],
    result: &mut [E; STATE_WIDTH],
) where
    E: FieldElement<BaseField = Felt>,
{
    let mut sboxed = [E::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        sboxed[i] = pow7(current[i]);
    }
    let mds_sboxed = mds_mul(&MDS, &sboxed);
    for i in 0..STATE_WIDTH {
        result[i] = mds_sboxed[i] + ark1[i] - next[i];
    }
}

/// Enforce the second-half Rescue sub-round transition for round `k`:
///
/// ```text
/// current == (MDS⁻¹ · (next − ARK2[k])) .^ 7
/// ```
///
/// Equivalent to `next == MDS · current .^ (1/7) + ARK2[k]` but encoded
/// backwards so that the constraint stays polynomial (degree 7 in `next`).
///
/// Writes 12 constraint residuals into `result`.
pub fn enforce_second_half<E>(
    current: &[E; STATE_WIDTH],
    next: &[E; STATE_WIDTH],
    ark2: &[E; STATE_WIDTH],
    result: &mut [E; STATE_WIDTH],
) where
    E: FieldElement<BaseField = Felt>,
{
    let mut diff = [E::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        diff[i] = next[i] - ark2[i];
    }
    let inv_mds_diff = mds_mul(&INV_MDS, &diff);
    for i in 0..STATE_WIDTH {
        result[i] = pow7(inv_mds_diff[i]) - current[i];
    }
}

// ============================================================================
// Periodic-column helpers for circuit AIRs
// ============================================================================

/// Build the 24 periodic columns needed to drive a Rescue permutation in
/// AIR transitions. For a 14-row sub-round sequence:
///
/// - Columns `0..12`: ARK1 values active on first-half rows (rows 0, 2, 4,
///   …, 12), zero on second-half rows.
/// - Columns `12..24`: ARK2 values active on second-half rows (rows 1, 3,
///   5, …, 13), zero on first-half rows.
///
/// The returned vector has 24 inner `Vec<Felt>` each of length 14 (the
/// period of one permutation). Circuits with multi-permutation traces
/// concatenate or extend the period as needed.
///
/// Note: callers also typically supply a separate boolean "selector"
/// periodic column to mask the constraint when the trace continues beyond
/// the permutation (e.g. for length-decomposition rows or stall rows).
pub fn periodic_round_constants() -> Vec<Vec<Felt>> {
    let mut columns: Vec<Vec<Felt>> = (0..STATE_WIDTH * 2)
        .map(|_| vec![Felt::ZERO; SUB_ROUNDS_PER_PERMUTATION])
        .collect();
    for round in 0..NUM_ROUNDS {
        let first_half_row = 2 * round;
        let second_half_row = 2 * round + 1;
        for i in 0..STATE_WIDTH {
            columns[i][first_half_row] = ARK1[round][i];
            columns[STATE_WIDTH + i][second_half_row] = ARK2[round][i];
        }
    }
    columns
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use winter_crypto::ElementHasher;

    fn sample_state() -> [Felt; STATE_WIDTH] {
        std::array::from_fn(|i| Felt::new((i as u64) + 1))
    }

    #[test]
    fn constants_match_winter_crypto() {
        assert_eq!(STATE_WIDTH, Rp64_256::STATE_WIDTH);
        assert_eq!(NUM_ROUNDS, Rp64_256::NUM_ROUNDS);
        for round in 0..NUM_ROUNDS {
            for i in 0..STATE_WIDTH {
                assert_eq!(ARK1[round][i], Rp64_256::ARK1[round][i]);
                assert_eq!(ARK2[round][i], Rp64_256::ARK2[round][i]);
            }
        }
        for i in 0..STATE_WIDTH {
            for j in 0..STATE_WIDTH {
                assert_eq!(MDS[i][j], Rp64_256::MDS[i][j]);
                assert_eq!(INV_MDS[i][j], Rp64_256::INV_MDS[i][j]);
            }
        }
    }

    #[test]
    fn apply_permutation_matches_rp64_256() {
        let mut a = sample_state();
        let mut b = sample_state();
        apply_permutation(&mut a);
        Rp64_256::apply_permutation(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn permutation_trace_final_row_matches_apply_permutation() {
        let entry = sample_state();
        let rows = permutation_trace(entry);
        let mut direct = entry;
        apply_permutation(&mut direct);
        assert_eq!(rows[PERMUTATION_TRACE_ROWS - 1], direct);
    }

    #[test]
    fn hash_elements_via_trace_empty_matches_winter_crypto() {
        let elements: Vec<Felt> = vec![];
        let state = hash_elements_via_trace(&elements);
        let digest_air = extract_digest(&state);
        let digest_native = Rp64_256::hash_elements(&elements);
        assert_eq!(digest_air, *digest_native.as_elements());
    }

    #[test]
    fn hash_elements_via_trace_one_felt_matches_winter_crypto() {
        let elements = vec![Felt::new(42)];
        let state = hash_elements_via_trace(&elements);
        let digest_air = extract_digest(&state);
        let digest_native = Rp64_256::hash_elements(&elements);
        assert_eq!(digest_air, *digest_native.as_elements());
    }

    #[test]
    fn hash_elements_via_trace_exact_rate_block_matches_winter_crypto() {
        let elements: Vec<Felt> = (0u64..8).map(Felt::new).collect();
        let state = hash_elements_via_trace(&elements);
        let digest_air = extract_digest(&state);
        let digest_native = Rp64_256::hash_elements(&elements);
        assert_eq!(digest_air, *digest_native.as_elements());
    }

    #[test]
    fn enforce_first_half_zero_on_valid_trace() {
        let entry = sample_state();
        let rows = permutation_trace(entry);
        let mut result = [Felt::ZERO; STATE_WIDTH];
        for round in 0..NUM_ROUNDS {
            enforce_first_half(
                &rows[2 * round],
                &rows[2 * round + 1],
                &ARK1[round],
                &mut result,
            );
            for r in result.iter() {
                assert_eq!(
                    *r,
                    Felt::ZERO,
                    "first-half residual nonzero at round {round}"
                );
            }
        }
    }

    #[test]
    fn enforce_second_half_zero_on_valid_trace() {
        let entry = sample_state();
        let rows = permutation_trace(entry);
        let mut result = [Felt::ZERO; STATE_WIDTH];
        for round in 0..NUM_ROUNDS {
            enforce_second_half(
                &rows[2 * round + 1],
                &rows[2 * round + 2],
                &ARK2[round],
                &mut result,
            );
            for r in result.iter() {
                assert_eq!(
                    *r,
                    Felt::ZERO,
                    "second-half residual nonzero at round {round}"
                );
            }
        }
    }

    #[test]
    fn enforce_first_half_nonzero_on_tampered_trace() {
        let entry = sample_state();
        let mut rows = permutation_trace(entry);
        // Flip one element of the intermediate row.
        rows[1][0] += Felt::ONE;
        let mut result = [Felt::ZERO; STATE_WIDTH];
        enforce_first_half(&rows[0], &rows[1], &ARK1[0], &mut result);
        let any_nonzero = result.iter().any(|r| *r != Felt::ZERO);
        assert!(
            any_nonzero,
            "tampered first-half row must produce nonzero residual"
        );
    }

    #[test]
    fn periodic_round_constants_shape_is_24_columns_of_14() {
        let cols = periodic_round_constants();
        assert_eq!(cols.len(), STATE_WIDTH * 2);
        for col in &cols {
            assert_eq!(col.len(), SUB_ROUNDS_PER_PERMUTATION);
        }
        // Spot check: row 0 of ARK1 columns equals ARK1[0]; second-half rows
        // of ARK1 columns are zero; mirror for ARK2.
        for i in 0..STATE_WIDTH {
            assert_eq!(cols[i][0], ARK1[0][i]);
            assert_eq!(cols[i][1], Felt::ZERO);
            assert_eq!(cols[STATE_WIDTH + i][0], Felt::ZERO);
            assert_eq!(cols[STATE_WIDTH + i][1], ARK2[0][i]);
        }
    }

    #[test]
    fn merge_via_trace_matches_rp64_256_merge() {
        use crate::hash::rescue_merge_raw;
        let a: Digest = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
        let b: Digest = [Felt::new(5), Felt::new(6), Felt::new(7), Felt::new(8)];
        let state = merge_via_trace(&a, &b);
        let digest_air = extract_digest(&state);
        let digest_native = rescue_merge_raw(&a, &b);
        assert_eq!(digest_air, digest_native);
    }
}
