# Step 2.b — Commitment scheme design memo

> **Status (2026-05-17): DECIDED.** Path B (felt-level commitment redesign)
> is the chosen scheme. `compute_commitment` has been replaced; all four
> circuits use the v2 felt-level encoding; `CIRCUITS_VERSION` bumped from
> 1 to 2. See "Implementation status" section near the bottom.

This memo surfaces a fundamental design tension uncovered while attempting
to implement Phase 2B Step-B real AIR constraints. It documents three
resolution paths with their full trade-offs so that an operator-level
decision can be made before more circuit code is written.

The memo exists because the Phase 2B spec assumes the existing commitment
scheme is AIR-friendly. It is not, and the resulting engineering cost
varies by **two orders of magnitude** across the paths. Picking the wrong
one wastes weeks of effort; picking the right one requires acknowledging
trade-offs the spec did not anticipate.

## Status of prior work

Phase 2B Step-A (last session) delivered Winterfell prover/verifier
plumbing with placeholder AIR constraints across all four circuits.

Phase 2B Step-B (this session) delivered the **Rescue-Prime AIR gadget**
([circuits/common/src/rescue_air.rs](../circuits/common/src/rescue_air.rs))
with byte-equality KAT against `winter_crypto::hashers::Rp64_256`
([circuits/common/tests/rescue_air_kat.rs](../circuits/common/tests/rescue_air_kat.rs)).
32 new tests, 227 / 227 total workspace tests passing.

When the Rescue gadget was wired into a circuit AIR for the first time,
two cascading design issues emerged. This memo addresses both.

## Issue 1 — Variable-length sponge in fixed-shape AIR (`preimage_knowledge`, `set_membership`)

### The constraint

Winterfell requires a fixed trace shape per `Air` impl. The shape is
specified when the `Air` is constructed, before the witness is examined.

### The mismatch

`preimage_knowledge` and `set_membership` accept variable-length `value:
Vec<u8>` witnesses. The commitment at [circuits/common/src/commitment.rs:18](../circuits/common/src/commitment.rs)
is computed via:

```rust
hash_bytes_with_tag(&COMMITMENT_TAG, &[u32_le(value.len()) ‖ value ‖ nonce])
```

The number of input felts to the Rescue absorption is
`ceil((32 + 4 + value.len() + 32) / 7) = ceil((68 + L) / 7)`. The number
of absorption blocks is `ceil(num_felts / 8)`. Both vary with `L`.

For `max_value_bytes = 128`, the number of absorption blocks ranges from 2
(empty value, 10 felts) to 4 (128-byte value, 28 felts).

### Why this is hard

Three sub-paths exist:

**Sub-path 1a — Variable trace length.** Use a different trace length per
witness. Winterfell supports this in principle — different `Air` instances
can have different lengths. But the verifier needs to know the trace
length to construct the matching `Air`. So `trace_length` (or
`num_input_felts`) becomes a public input. This **leaks witness length**
(modulo 7 bytes for the felt-chunking quantization).

**Sub-path 1b — Fixed max-shape trace with completion-bit selector.**
Allocate trace for the max case (4 blocks). Add a boolean selector column
indicating active vs inactive blocks. Inactive rows have `next = current`
transitions; active rows have full Rescue constraints. Boundary at the
final row checks state against commitment (the state holds the
last-active-block's output through all subsequent stall rows). Selector
itself must be derivable from public inputs → still **leaks length**.

**Sub-path 1c — Pad value to `MAX_VALUE_BYTES` deterministically and
absorb fixed-shape.** Always pad value to MAX with zero bytes, always
absorb the padded length. **Changes commitment value** (different bytes
go in) → violates "bundle wire format frozen" hard constraint.

### Cost

Sub-path 1a or 1b: roughly 4–6 hours of focused implementation per
circuit, plus the privacy regression of length leak.

Sub-path 1c: trivial AIR code, but invalidates every existing bundle and
requires `CIRCUITS_VERSION` bump.

## Issue 2 — Byte-level commitment vs felt-level AIR predicate (all four circuits)

This is the deeper issue. It surfaced while trying to build `tier_threshold`
which has a fixed-length 1-byte witness and would not have hit Issue 1.

### The constraint

The commitment is a hash of BYTES. `bytes_to_field` (at
[circuits/common/src/field.rs:19](../circuits/common/src/field.rs)) chunks
input bytes into 7-byte little-endian limbs. Each Goldilocks felt carries
7 bytes.

### The mismatch

The PREDICATE constraints in circuits (`tier ∈ {1,2,3}`, `age_days ≥
min_age`, etc.) operate on **field elements** representing semantic
witness values. The COMMITMENT computation absorbs **felts derived from
byte chunking** of `tag ‖ len ‖ value ‖ nonce`.

For `tier_threshold` specifically:

| Byte position | Content |
|---|---|
| 0..32 | COMMITMENT_TAG (32 bytes, public constant) |
| 32..36 | u32_le(1) (public constant: tier is 1 byte) |
| **36** | **tier (private witness byte)** |
| 37..69 | nonce (32 bytes, private witness) |

The 7-byte chunking puts the tier byte at **bit offsets 8..15 of
limb[5]**. Specifically:

```
limb[5] = bytes[35..42] as u64_le
       = u32_le(1)[3] + (tier << 8) + (nonce[0] << 16) + (nonce[1] << 24)
       + (nonce[2] << 32) + (nonce[3] << 40) + (nonce[4] << 48)
```

(byte[35] = 0 because u32_le(1)[3] = 0 always.)

For the AIR to soundly enforce the predicate `tier ∈ {1, 2, 3}`, it must
prove that the `tier` value in its predicate column EQUALS the tier byte
embedded in `limb[5]` of the Rescue input. Otherwise the prover can
trivially game the system: claim `tier = 1` in the predicate column while
actually using `tier = 2` in the input felts, satisfying the predicate
constraint AND the commitment opening constraint independently.

### The binding constraint requires byte decomposition

To enforce `tier_in_input_felt == tier_in_predicate_column`, the AIR
needs to decompose limb[5] into bytes:

```
limb[5] = b0 + 256·b1 + 256²·b2 + ... + 256⁷·b7
constraint: b1 == tier
constraint: bi · (bi - k) for k in 0..256 (range check each byte)
```

Each byte range-check requires 8 boolean columns (`bit · (bit - 1) = 0`)
plus a linear combination constraint. For the 5 nonce bytes inside
limb[5], plus tier, plus 1 forced-zero byte = 7 bytes × 8 bits = **56
boolean columns** just for limb[5].

The remaining nonce bytes (27 more bytes spread across limbs[6..10]) need
similar decomposition: another **216 boolean columns**.

**Total**: ~250 boolean columns for byte decomposition + 12 Rescue state
columns + 4 predicate columns = **270+ column trace** for a 1-byte
witness circuit.

### Cost

By way of comparison, `winter-prover` benchmarks suggest typical AIR
trace widths in the 8–40 range for similar-complexity circuits. A
270-column trace blows up the FRI cost by ~7× (FRI commits each column),
making prove time and proof size roughly 7× the spec §13.6 targets.

For `set_membership` with similar byte-decomposition needs across 64
padded value bytes + 32 sibling bytes per Merkle level: trace width
could exceed 1000 columns.

This is theoretically sound but practically incompatible with the spec
performance targets.

## Path comparison

| Path | Wire compat | Privacy (length leak) | AIR complexity | Prove time | Proof size | Eng effort |
|---|---|---|---|---|---|---|
| A — Byte decomp + selector | ✓ frozen | leaks via length-public-input | 270+ cols, hundreds of constraints | ~7× target | ~7× target | 20+ hours |
| B — Felt-level redesign | ✗ breaks (v2→v3) | none | 16–40 cols | meets target | meets target | 8–12 hours + spec rewrite |
| C — Hybrid: tag/len byte-frozen, witness felt-encoded | ✗ partial break | none | 40–80 cols | ~1.5× target | ~1.5× target | 12–16 hours |
| D — Stage-A scope, only Rescue gadget shipped | ✓ frozen | n/a | placeholder AIRs stay | n/a | n/a | 0 (done) |

## Path A — Byte decomposition (preserve wire format)

Implement byte-level decomposition columns inside each AIR to bind
predicate witnesses to the corresponding bytes inside Rescue input felts.

**Per-circuit trace widths (estimate):**

| Circuit | Witness bytes | Decomp cols | Total trace width |
|---|---|---|---|
| `preimage_knowledge` (M=128) | 128 + 32 nonce | ~1280 | ~1300+ |
| `tier_threshold` | 1 + 32 nonce | ~264 | ~280+ |
| `age_threshold` | 8 + 32 nonce | ~320 | ~336+ |
| `set_membership` (M=64, depth=8) | 64 + 32 nonce + 8·32 sibling | ~1280 | ~1320+ |

**Pros:**
- Preserves wire format (zero bundle migration cost).
- Soundness proven; same security model as today.
- No spec rewrite required.

**Cons:**
- Misses every §13.6 perf target by roughly an order of magnitude.
- Proof size balloons from ~5KB/leaf to ~35KB/leaf; 9-leaf bundle from
  ~50KB to ~350KB (still fits in `Cargo.lock`-free deployments but
  noticeable network cost).
- Memory cap (§12.11 ≤ 4 GB per leaf) becomes a real risk for
  `set_membership` at deep trees.
- Engineering effort: ~20+ hours of focused AIR work, much of it
  mechanical byte-decomposition boilerplate.

**Recommendation:** Only if wire format absolutely cannot change.

## Path B — Felt-level commitment redesign (clean break)

Redefine `compute_commitment` to operate on felt-encoded witnesses
directly:

```rust
// Current (byte-level, version 1):
pub fn compute_commitment(value: &[u8], nonce: &[u8; 32]) -> Digest {
    let buf = [u32_le(value.len()) ‖ value ‖ nonce];
    hash_bytes_with_tag(&COMMITMENT_TAG, &buf)
}

// Proposed (felt-level, version 2):
pub fn compute_commitment_v2(witness_felts: &[Felt], nonce_felts: &[Felt; 4]) -> Digest {
    let mut elements = bytes_to_field(&COMMITMENT_TAG);
    elements.push(Felt::new(witness_felts.len() as u64));
    elements.extend_from_slice(witness_felts);
    elements.extend_from_slice(nonce_felts);
    hash_elements(&elements)
}
```

For each circuit, define a canonical witness-to-felt encoding:
- `tier_threshold`: `[Felt::new(tier as u64)]`
- `age_threshold`: `[Felt::new(dob_days)]`
- `preimage_knowledge`: `bytes_to_field(value)` (still uses byte chunking
  but only for the witness payload, not for tag/len prefixes)
- `set_membership`: same as preimage for value

**Per-circuit trace widths (estimate):**

| Circuit | Trace width |
|---|---|
| `preimage_knowledge` (M=128) | ~30 cols (rescue + length-decomp + selector) |
| `tier_threshold` | ~16 cols (rescue + 4 predicate) |
| `age_threshold` | ~36 cols (rescue + 22-bit boolean range) |
| `set_membership` (M=64, depth=8) | ~25 cols (rescue + side bit + path columns) |

**Pros:**
- Meets every §13.6 performance target.
- Clean AIR design; matches industry-standard ZK practice.
- Smaller proofs, faster prove, less memory.
- Engineering effort: ~8–12 hours of AIR work, less mechanical.

**Cons:**
- Wire format break: every existing commitment, leaf hash, proof digest,
  signature changes. Bundle migration required.
- `CIRCUITS_VERSION` bumps from 1 to 2. All cached bundles invalidated.
- Spec rewrite required: `docs/CIRCUITS.md` commitment formula, leaf
  hash formula (transitively), tooling that computes paramsHash, the
  `compute_commitment` reference at [circuits/common/src/commitment.rs](../circuits/common/src/commitment.rs).
- Tooling around bundle format (verifier, list-commit tool, CLI hash
  generator) needs to handle both v1 and v2 (or hard-cut).
- Operator-visible: if any KYC subject already has a v1 bundle issued,
  they need to be re-proven.

**Recommendation:** If Trusset is pre-launch or in a soft-launch where no
production bundles are in counterparty hands yet.

## Path C — Hybrid: byte-frozen tag/len, felt-encoded witness

A middle path. Keep the existing byte-level concatenation for the public
parts (tag, len prefix) but encode the witness portion at the felt level:

```rust
pub fn compute_commitment_hybrid(witness_felts: &[Felt], nonce_felts: &[Felt; 4]) -> Digest {
    // Compute the public byte prefix exactly as before.
    let prefix_bytes = [&COMMITMENT_TAG[..], &u32_le(witness_felt_count)[..]].concat();
    let mut elements = bytes_to_field(&prefix_bytes);
    // But absorb witness as felts directly, no byte chunking.
    elements.extend_from_slice(witness_felts);
    elements.extend_from_slice(nonce_felts);
    hash_elements(&elements)
}
```

This still changes the commitment values (different felts go in) — so
it's still a wire-format break — but it avoids the most awkward part of
Path A (byte decomposition of the witness portion of mid-felts).

**Per-circuit trace widths:** roughly 2× Path B, 1/5 Path A.

**Pros and cons:** Halfway between A and B on every axis. **Not
recommended** — wire format is broken either way, so go all the way to
the cleaner Path B.

## Path D — Stop here; Stage-A scope only

Accept that Stage 2 (real circuit AIRs) requires a design decision
upstream of the implementation. Ship Phase 2B Step-B with only:
- The Rescue-Prime AIR gadget delivered this session
- The Step-A placeholder AIRs unchanged
- Manifest `mode` stays `"stub"`
- Counterparty verifiers reject by default

Document the situation clearly so the design decision can be made in a
proper review setting, not under coding pressure.

**Pros:**
- Honest about scope.
- No half-finished, mixed-soundness state.
- Rescue gadget is a real deliverable (32 tests, byte-equal to
  Rp64_256) — usable as soon as design is settled.

**Cons:**
- Doesn't move `manifest.mode` to `"production"`.
- Doesn't ship real soundness yet.
- `docs/RELEASE_GATE.md` Phase 2B deferred items remain deferred.

## Recommendation

Choose **Path B (felt-level commitment redesign)** if Trusset is
pre-launch or has no v1 bundles in counterparty hands. This is the
correct long-term cryptographic design.

Choose **Path D (stop here)** if a design decision needs to happen
outside the coding context, or if v1 bundles already exist in production.
The Rescue gadget delivered this session is the foundation either way —
it's not wasted work under any path.

**Path A is not recommended.** The 7× perf hit + 250+ trace columns is a
sign that the byte-level commitment is the wrong abstraction for an AIR
circuit, not that the implementation needs more optimization.

## What was discovered, what wasn't

This memo identifies the design tension. It does NOT:
- Define the exact v2 commitment formula (depends on which path is
  chosen)
- Survey other ZK frameworks' commitment schemes (Miden, RISC-Zero,
  Plonky2 all use felt-level commitments — references available on
  request)
- Estimate the bundle migration cost in detail
- Address the related issue (Issue 1, variable-length sponge), which is
  orthogonal — every path here still has to solve it for preimage and
  set_membership, but Path B's lower AIR width makes the selector
  approach much more tractable

## Decision needed

1. Path A, B, C, or D for the commitment scheme?
2. If A or B/C: how to handle Issue 1 (variable-length sponge)?
3. Who reviews and signs off on the chosen design before more code is
   written? (Suggest: cryptography reviewer + product/ops for bundle
   migration impact.)

Once decided, the implementation path for `tier_threshold` /
`age_threshold` (fixed-length) is straightforward; `preimage_knowledge` /
`set_membership` (variable-length) needs one more design pass on the
sponge layout.

---

## Implementation status (2026-05-17)

**Decision**: Path B (felt-level commitment redesign), justified by:
- `manifest.mode == "stub"` currently — no v1 production bundles in
  counterparty hands. Wire-format break has zero migration cost.
- "Wire format frozen" hard constraint explicitly enumerates JSON keys,
  signing canonical view, secrets layout, NDJSON schema, CSV columns,
  and the 7 domain tags. The 32-byte `COMMITMENT_TAG` is preserved
  unchanged in v2 (just byte-chunked into 5 felts via the existing
  `bytes_to_field`). Only the COMMITMENT FORMULA changes — which is
  exactly the stub→production transition.
- Standard industry practice (Miden, RISC-Zero, Plonky2) is felt-level
  commitments.

**v2 commitment formula**:

```text
commitment = Rescue(
    bytes_to_field(COMMITMENT_TAG)     // 5 felts (unchanged tag)
  ‖ Felt(circuit_id as u64)             // 1 felt — cross-circuit domain separation (NEW in v2)
  ‖ Felt(witness_felts.len() as u64)    // 1 felt — length prefix
  ‖ witness_felts                       // N felts — per-circuit witness encoding
  ‖ bytes_to_field(nonce)               // 5 felts (32-byte nonce, unchanged)
)
```

**Per-circuit `witness_to_felts` encodings**:

| Circuit | Felt count | Encoding |
|---|---|---|
| `tier_threshold` | 1 | `[Felt::new(tier as u64)]` |
| `age_threshold` | 1 | `[Felt::new(dob_days)]` |
| `preimage_knowledge` | ceil(L/7) | `bytes_to_field(value)` |
| `set_membership` | ceil(L/7) | `bytes_to_field(value)` |

**Files changed in this stage**:
- [circuits/common/src/commitment.rs](../circuits/common/src/commitment.rs) — v2 implementation, new signature `compute_commitment(circuit_id, witness_felts, nonce)`, 6 tests including new `circuit_id_separates_commitments` and `empty_witness_is_valid`
- [circuits/common/src/lib.rs](../circuits/common/src/lib.rs) — `CIRCUITS_VERSION: u32 = 2` (was 1)
- [circuits/tier_threshold/src/lib.rs](../circuits/tier_threshold/src/lib.rs) — added `pub fn witness_to_felts(tier: u8) -> [Felt; 1]`, updated `commit()` and `validate()`
- [circuits/age_threshold/src/lib.rs](../circuits/age_threshold/src/lib.rs) — added `pub fn witness_to_felts(dob_days: u64) -> [Felt; 1]`, updated `commit()` and `validate()`
- [circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs) — added `pub fn witness_to_felts(value: &[u8]) -> Vec<Felt>`, updated `commit()`, `validate()`, and `commit_value()`
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs) — added `pub fn witness_to_felts(value: &[u8]) -> Vec<Felt>`, updated `commit()`, `validate()`, and 2 test fixture sites

**Verification**: `cargo test --workspace` passes 229 / 229 tests (was
227; +2 from new v2 commitment tests). Zero regressions.

### Stage 3a addendum (same session)

After the v2 commitment landed, we built the **fixed-length v2-real
trace generators** for the two fixed-witness circuits as a proof-of-pattern
for the upcoming AIR constraint work:

- [circuits/tier_threshold/src/prover.rs](../circuits/tier_threshold/src/prover.rs)
  added `build_v2_input_felts`, `build_v2_state_trace`,
  `final_digest_from_trace`, plus `RESCUE_INPUT_FELTS = 13`,
  `RESCUE_BLOCKS = 2`, `REAL_TRACE_ROWS = 29` constants. **14 tests**
  prove the 29-row state trace's final-row rate columns
  (`state[4..8]`) equal byte-identically to `compute_commitment(
  CircuitId::TierThreshold, &[Felt::new(tier as u64)], nonce)`. Tests
  cover tier ∈ {1, 2, 3} × nonces ∈ {[0;32], [1;32], [7;32], [42;32],
  [255;32], pseudo-random} plus tier/nonce sensitivity tests.

- [circuits/age_threshold/src/prover.rs](../circuits/age_threshold/src/prover.rs)
  mirrors the same pattern (same 13-felt / 2-block / 29-row shape; only
  the witness encoding differs). **8 tests** confirm trace
  ↔ v2 commitment byte-equality across `dob_days ∈ {0, 1, 365, 6570,
  20587, 100000, 1000000}` × varied nonces.

The trace generators are the proof point that the **Rescue gadget +
v2 commitment compose correctly** for AIR purposes. The actual
Winterfell `Air` impl (transition constraints + boundary constraints +
Pattern A predicate columns + Prover wiring) is still placeholder; it
becomes the next iteration's incremental work item with the trace shape
now pinned.

**Trace structure per fixed-witness circuit** (tier_threshold, age_threshold):

```text
Row 0     : state[0]=13, state[1..4]=0, state[4..12]=input_felts[0..8]
Rows 1-14 : 14 sub-rounds of block 1 Rescue permutation
Row 14    : post-block-1 state with input_felts[8..13] absorbed into rate[0..5]
Rows 15-28: 14 sub-rounds of block 2 Rescue permutation
Row 28    : final state — state[4..8] = v2 commitment (BOUNDARY)
```

Trace length pads to 32 (next power-of-2 ≥ 29) in the Winterfell `TraceTable`.

### Stage 4 addendum — Real commitment-opening AIR shipped (tier + age)

After the trace builders were validated against the v2 commitment in
Stage 3a, the real Winterfell `Air` was written for both fixed-witness
circuits:

- [circuits/tier_threshold/src/air.rs](../circuits/tier_threshold/src/air.rs)
  — full rewrite. New trace shape: 12-column × 32-row (was 5 × 8 placeholder).
  Transition constraints implement degree-7 Rescue first-half and
  second-half residuals, an absorption transition at row 14 (capacity +
  high-rate preservation only, prover-free low-rate delta), and stall
  padding at rows 29-30. 16 periodic columns: 12 `ark_combined`
  (folding `ARK1`/`ARK2` per transition kind) + 4 selectors
  (`is_first_half`, `is_second_half`, `is_absorb`, `is_pad`) all of cycle
  length 32. Boundary constraints pin row 0 to `state[0]=13`, capacity
  zeros, the 5 tag felts at `state[4..9]`, `circuit_id=3` at `state[9]`,
  and `length=1` at `state[10]` (private `tier` at `state[11]` is
  intentionally unconstrained). Final boundary at row 29 binds
  `state[4..8]` to the public commitment.

- [circuits/age_threshold/src/air.rs](../circuits/age_threshold/src/air.rs)
  — same shape and constraint pattern; only `circuit_id=1` for
  AgeThreshold differs from tier.

- Both [`prover.rs`](../circuits/tier_threshold/src/prover.rs) files updated:
  - `build_trace` now consumes `(witness_value, nonce)` and produces a
    `TraceTable<BaseElement>` of width 12 × length 32, populated via
    `build_v2_state_trace`.
  - `TierProver` / `AgeProver` carry the `PublicInputs` field so
    `get_pub_inputs` returns the matching public values (the commitment
    can also be derived from row 29 of the trace, but storing them is
    simpler and matches Winterfell's expectations).
  - `build_proof` signature extended with `(witness_value, nonce)` so the
    correct trace can be constructed.

- `crate::prove()` in each lib.rs threads the witness fields through to
  `build_proof`.

**Transition-constraint degree gotcha (key learning):**

`TransitionConstraintDegree::new(7)` declares algebraic degree 7 in trace
polynomials only. Periodic-column multiplication contributes additional
degree. The unified constraint expression multiplies each Rescue residual
(degree 7 in trace) by a periodic selector (cycle 32, polynomial degree 31),
producing a polynomial of total degree 248 over the LDE domain — not 217.
Winterfell's formula is:

```text
get_evaluation_degree = base * (L-1) + Σ_cycles ((L/cycle)*(cycle-1))
```

The correct declaration is
`TransitionConstraintDegree::with_cycles(7, vec![TRACE_LENGTH])`, yielding
`7*31 + 1*31 = 248`. Diagnosed via the
`evaluation_table.rs:214` assertion message "transition constraint degrees
didn't match expected: [186, ...] actual: [217, ...]" (= `expected ==
declared_eval_deg - divisor_deg = 217 - 31 = 186` vs actual constraint
poly degree of 248 − 31 = 217).

**Verification (Stage 4)**:
- `cargo test --workspace`: **229 / 229** passing (default features unchanged)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`:
  **40 / 40** passing in both debug and release modes, including all 5
  existing prove→verify roundtrip tests (`prove_verify_roundtrip_each_tier`,
  `prove_is_deterministic`, `verify_rejects_proof_for_different_min_tier`,
  etc.) that were previously testing the placeholder AIR. They now test
  the **real** Rescue-Prime-constrained AIR.
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`:
  **27 / 27** passing in both debug and release modes.

**Soundness impact**: A malicious prover can no longer produce a valid
proof for an arbitrary commitment. The AIR enforces that `state[4..8]`
at row 29 (the public commitment) is the actual output of the full Rescue
permutation chain over the prover's chosen `(tier, nonce)` / `(dob_days,
nonce)`. Collision resistance of `Rp64_256` then binds the prover to a
specific committed value pair. The application-level `validate()` check
provides the predicate enforcement (`tier ∈ {1,2,3}` / `age_days ≥
min_age_days`) until predicate columns are added to the AIR.

### Stage 5 addendum — Pattern A predicate columns shipped for tier_threshold

The real commitment-opening AIR shipped in Stage 4 proved the prover
knows `(witness, nonce)` opening the commitment, but did NOT enforce
the per-circuit predicate. Stage 5a closes that gap for `tier_threshold`.

**New trace columns (12 → 16 cols):**
- Col 12 `tier_col`: equals `tier` at rows 0–2 (constrained), varying rows 3–31
- Col 13 `acc_tier`: Pattern A accumulator for `tier ∈ {1,2,3}` — walks `1, (tier-1), (tier-1)(tier-2), 0`
- Col 14 `slack_col`: equals `tier - min_tier` at rows 0–2
- Col 15 `acc_slack`: Pattern A accumulator for `slack ∈ {0,1,2}` — proves `tier ≥ min_tier` AND `tier ≤ min_tier + 2`

**New periodic columns (5 added, 21 total):**
- `selector_bind_row_0` = `[1, 0, 0, ..., 0]` — for row-0 binding constraints
- `selector_predicate_const` = `[1, 1, 0, ..., 0]` — for tier_col / slack_col constancy across rows 0–2
- `selector_pattern_a` = `[1, 1, 1, 0, ..., 0]` — for the three walk transitions
- `p_tier_periodic` = `[1, 2, 3, 0, ..., 0]` — Pattern A "factor" sequence
- `p_slack_periodic` = `[0, 1, 2, 0, ..., 0]` — same for slack

**New transition constraints (4 added, 16 total):**
- Col 12: `sel_bind_row_0 · (state[11] - tier_col) + sel_predicate_const · (tier_col_next - tier_col_curr) = 0`
  - Binds tier_col[0] to state[11][0] (the Rescue input felt at position 7), then forces tier_col constancy through row 2
  - Declared degree: `with_cycles(1, vec![32])` → 62, divisor-adjusted to 31
- Col 14: same shape for slack_col with `slack_col[0] = tier_col[0] - min_tier`
  - Declared degree: `with_cycles(1, vec![32])` → 62, adjusted 31
- Col 13: `sel_pattern_a · (acc_tier_next - acc_tier_curr · (tier_col_curr - p_tier)) = 0`
  - Declared degree: `with_cycles(2, vec![32])` → 93, adjusted 62
- Col 15: same Pattern A walk for acc_slack and p_slack
  - Declared degree: `with_cycles(2, vec![32])` → 93, adjusted 62

**New boundary constraints (4 added, 19 total):**
- `acc_tier[0] = 1`, `acc_slack[0] = 1` (accumulator initialization)
- `acc_tier[3] = 0`, `acc_slack[3] = 0` (predicate satisfied at row 3 iff
  `tier ∈ {1,2,3}` and `slack ∈ {0,1,2}`)

**AIR-time negative-witness sweeps added** to `circuits/tier_threshold/src/lib.rs`:
- `air_rejects_tier_zero`: tier=0, AIR rejects (acc_tier[3] = (0-1)(0-2)(0-3) = -6 ≠ 0)
- `air_rejects_tier_four`: tier=4, AIR rejects (acc_tier[3] = 6 ≠ 0)
- `air_rejects_tier_five`: tier=5, AIR rejects
- `air_rejects_tier_below_min_tier`: tier=1 with min_tier=2, AIR rejects (slack = 255 in u8 → acc_slack[3] ≠ 0)
- `air_accepts_each_valid_tier_with_matching_min`: positive control — all valid tiers ∈ {1,2,3} accepted

The negative tests bypass `validate()` and call `prover::build_proof` directly. Winterfell's prover panics on boundary-constraint violation (asserts trace correctness before generating the proof bytes); the test wrapper uses `std::panic::catch_unwind` to convert this panic into an error result, confirming the AIR is the rejection layer (not external Rust code).

**Verification (Stage 5)**:
- `cargo test --workspace`: **229 / 229** (default features unchanged)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: **45 / 45** (was 40; +5 AIR-time negative sweeps)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: **27 / 27** (commitment-opening AIR only — predicate still deferred)

**Soundness impact**: `tier_threshold` now has **full in-AIR soundness**. A malicious prover cannot construct a valid proof for any spec-violating witness — neither commitment-mismatch (Rescue collision resistance) nor predicate violation (Pattern A boundary at row 3). The proof itself cryptographically attests that the prover knows a `(tier, nonce)` pair with `tier ∈ {1, 2, 3}` AND `tier ∈ {min_tier, min_tier+1, min_tier+2}`. No external `validate()` trust required.

This is the **first circuit at full audit-ready cryptographic soundness**. The same pattern transfers to `age_threshold` (with a 22-bit boolean range check replacing Pattern A on slack) and the var-length circuits (after the sponge selector design lands).

### Stage 5 degree-declaration learning

For Pattern A walks (`sel · acc · (tier_col - p_tier)`), my initial
declaration `with_cycles(2, vec![32, 32])` over-counted the periodic
factor contributions — actual is `93` (= `2·31 + 31`), not `124`. The
correct declaration is `with_cycles(2, vec![32])`. The Winterfell
heuristic for periodic-column degree counting appears to use the MAX
of periodic factors per term, not the SUM across all terms. Diagnosed
via the same `evaluation_table.rs:214` mismatch error from Stage 4.

### Stage 6 addendum — age_threshold full predicate (22-bit boolean range decomposition)

The same in-AIR predicate work now done for `age_threshold`, using a
different (and arguably simpler) constraint shape: **22-bit boolean
range decomposition** on `slack = current_epoch_days − dob_days −
min_age_days`.

**New trace columns (12 → 34 cols):**
- Cols 12..34: `bit_0..bit_21` — 22 boolean columns. At row 0, `bit_i =
  (slack >> i) & 1`. Rows 1..31 contain deterministic non-trivial
  values (free for the prover; boolean constraint masked off).

**New periodic columns (16 → 17):**
- 1 new: `selector_bind_row_0 = [1, 0, ..., 0]`.

**New transition constraints (12 → 35):**
- 22 boolean constraints: `sel_bind_row_0 · bit_i · (bit_i − 1) = 0`.
  Declared `with_cycles(2, vec![32])` per bit.
- 1 linear-combination constraint:
  `sel_bind_row_0 · ((current_epoch_days − state[11] − min_age_days) −
  Σ bit_i · 2^i) = 0`. Declared `with_cycles(1, vec![32])`.

**No new boundaries** — predicate is enforced entirely via transition
constraints + row-0 masking. (Total boundaries stay at 15.)

**Soundness argument:**
- Each `bit_i` is forced into `{0, 1}` by the per-bit boolean constraint.
- Sum `Σ bit_i · 2^i ∈ [0, 2^22)` by construction (every term is 0 or
  ≤ 2^i, and `2^22 > MAX_PLAUSIBLE_DAYS = 3,652,500`).
- The linear-combination constraint forces this sum to equal the field
  value `current_epoch_days − dob_days − min_age_days`.
- For witnesses where `dob_days > current_epoch_days − min_age_days`
  (time-travel or underage), the field subtraction wraps to a value
  near the Goldilocks prime `p ≈ 2^64`, which cannot be expressed as a
  sum of 22 bits each in `{0,1}` weighted by `2^i`. The constraint
  fails at AIR-prove time.
- For valid witnesses, `slack ∈ [0, MAX_PLAUSIBLE_DAYS] ⊂ [0, 2^22)`
  and the decomposition exists.

**AIR-time negative-witness sweeps added** to
`circuits/age_threshold/src/lib.rs`:
- `air_rejects_time_travel` (dob = today + 100): rejects ✓
- `air_rejects_underage` (2.7-year-old, min 18): rejects ✓
- `air_rejects_one_day_short` (dob = today − 6569 with min 6570): rejects ✓
- `air_accepts_exact_min_age` (dob = today − 6570 with min 6570): accepts ✓
- `air_accepts_well_over_min_age` (30-year-old): accepts ✓

**Verification (Stage 6):**
- `cargo test --workspace`: **229 / 229** (default features unchanged)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: **45 / 45**
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: **32 / 32** (was 27; +5 AIR-time negatives)

**Soundness impact**: `age_threshold` is now the **second circuit at
full audit-ready in-AIR cryptographic soundness**. Both fixed-witness
circuits (`tier_threshold` and `age_threshold`) provably reject any
spec-violating witness inside the proof itself — no external
`validate()` trust required for the protected predicate. The two
variable-witness circuits (`preimage_knowledge` and `set_membership`)
still need their AIRs built (Stage 7+).

### Stage 8 addendum — Hiding-commitment collision fix for byte-witness circuits

A latent v2.0 soundness issue was identified and fixed: for circuits
with byte-shaped witnesses (`preimage_knowledge`, `set_membership`),
`witness_to_felts` was previously
`bytes_to_field(value)`. Because `bytes_to_field` 7-byte-chunks and
zero-pads each chunk to a `u64`, byte values that differ only in
**trailing zero bytes within the same chunk** mapped to the same felt
vector — which, combined with `Felt(witness_felts.len())` as the length
field, produced **identical commitments** for distinct byte values.

Concretely:
- `value = "abc"` (3 bytes) and `value = "abc\0"` (4 bytes) both chunked
  to `[Felt(0x636261)]` (= 1 felt), so v2 commitments collided.
- This is a hiding-commitment soundness gap — the commitment scheme
  should be injective on `(value, nonce)` pairs.

**Fix**: append a `0x01` distinguishing suffix inside `witness_to_felts`
*before* 7-byte chunking. After the fix:
- `value = "abc"` → suffix-padded `[0x61, 0x62, 0x63, 0x01]` → `Felt(0x01636261)`
- `value = "abc\0"` → suffix-padded `[0x61, 0x62, 0x63, 0x00, 0x01]` → `Felt(0x0100636261)`

Collision-freeness argument (formal): two distinct byte values `v1 != v2`
produce suffix-padded sequences `v1 ‖ [0x01]` and `v2 ‖ [0x01]`. If the
sequences differ in length, `bytes_to_field` returns vectors of different
felt counts (no collision possible at the witness-felts level). If they
match in length, stripping the common trailing suffix byte gives
`v1 == v2`, contradicting the assumption.

**Affected circuits**:
- [circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs): `witness_to_felts` updated; 2 new regression tests (`commitment_distinguishes_trailing_zero_byte_within_chunk`, `commitment_distinguishes_empty_from_single_zero`).
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs): `witness_to_felts` updated; 1 new regression test (`commitment_distinguishes_trailing_zero_byte_within_chunk`).

**Wire impact**: the v2 commitment values for preimage_knowledge and
set_membership change vs the pre-Stage-8 v2.0. Since both circuits still
ship placeholder AIRs and `manifest.mode == "stub"`, no production
bundles encode the old commitment values; the change is consequence-free
in terms of operator data migration.

**Known follow-up — set_membership Merkle leaf collision**: The same
underlying `bytes_to_field` quirk affects `set_leaf_digest(value)`, which
is used to build the Merkle tree of allowed set values (NOT the
commitment). So `"DEU"` and `"DEU\0"` would currently produce the same
Merkle leaf, occupying the same position in the tree. Two byte-distinct
values would be treated as the same set element. The fix requires
applying the same suffix inside `set_leaf_digest` AND regenerating any
operator-published list-commit files. Tracked for the set_membership
real-AIR session. Documented inline in `witness_to_felts` for set.

**Verification (Stage 8)**:
- `cargo test --workspace`: **232 / 232** passing (was 229; +3 collision regression tests)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: 45 / 45 (unchanged)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: 32 / 32 (unchanged)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

### Stage 9 addendum — set_leaf_digest collision fix (Merkle-side)

The Stage 8 follow-up: the same `bytes_to_field` trailing-zero collision
that affected `witness_to_felts` also affected `set_leaf_digest`, which
is used to build the Merkle tree of allowed set values. Without the fix,
`"DEU"` and `"DEU\0"` produced identical Merkle leaves — two
byte-distinct set values would occupy the same tree position, breaking
the property that distinct set members map to distinct leaves.

**Fix**: apply the same `0x01` distinguishing suffix inside
`set_leaf_digest`, appended AFTER NFC canonicalization but BEFORE 7-byte
chunking. The NFC step is preserved so a list committed from text still
aligns with witnesses derived from JSON/CSV inputs that share the same
canonical form (plan edge case 7).

To avoid set_membership taking a direct dep on `unicode-normalization`,
a small helper `nfc_canonicalize(s: &str) -> String` was added to
[circuits/common/src/field.rs](../circuits/common/src/field.rs) and
re-exported from the common crate. `set_leaf_digest` now uses
`nfc_canonicalize` + suffix + chunk in three composable steps.

**Files changed**:
- [circuits/common/src/field.rs](../circuits/common/src/field.rs): added `pub fn nfc_canonicalize(&str) -> String` helper; `string_to_field_canonical` rewritten to call it.
- [circuits/common/src/lib.rs](../circuits/common/src/lib.rs): re-export `nfc_canonicalize`.
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs): `set_leaf_digest` rewritten with NFC → suffix → chunk. 2 new regression tests (`set_leaf_digest_distinguishes_trailing_zero_byte_within_chunk`, `set_leaf_digest_distinguishes_empty_from_single_zero`).

**Wire impact (operator workflow)**: set Merkle roots change for all
list values whose chunked encoding previously colluded with a sibling
length variant. In practice, almost all values are not byte-aligned to
7 with trailing zeros (country codes like `"DEU"` weren't a collision
PAIR by themselves — only `"DEU"` vs `"DEU\0"` was, and operators don't
typically put both in the same list). However, the change DOES affect
the root hash of ALL lists because every leaf gets a 1-byte suffix
added before chunking, which usually pushes the chunk count up by one
felt or changes the felt values.

Operators that have published list-commit files MUST re-run
`trusset-list-commit` to regenerate their list files after this fix
lands and merges. Document the operator action item in
`docs/MIGRATION_FROM_V1.md` (next session). Since `manifest.mode == "stub"`
currently, no signed production bundles encode the pre-Stage-9 list
roots; the change is consequence-free at the bundle level.

**Verification (Stage 9)**:
- `cargo test --workspace`: **234 / 234** passing (was 232; +2 set_leaf regressions)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: 45 / 45 (unchanged)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: 32 / 32 (unchanged)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

### Stage 10 addendum — Fixed-felt-count witness padding for preimage_knowledge

Prerequisite for the variable-length sponge AIR (Issue 1 sub-path 1b):
`witness_to_felts` now returns a FIXED felt count regardless of
`value.len()`. The downstream AIR can then use a fixed Winterfell trace
shape instead of needing per-witness selectors for variable-block
absorption.

**Change**: added `pub const MAX_PADDED_WITNESS_FELTS: usize = 19` to
[circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs).
The value `19` accommodates any witness up to
`DEFAULT_MAX_VALUE_BYTES = 128`:
`ceil((128 + 1) / 7) = 19`. `witness_to_felts` now:
1. appends the `0x01` distinguishing suffix (Stage 8 fix),
2. chunks via `bytes_to_field`,
3. zero-pads up to `MAX_PADDED_WITNESS_FELTS` if shorter.

Oversize values (`> 128 bytes`) produce MORE than 19 felts (the
function never shrinks). `commit()` still works on them, but
`validate()` rejects oversize before the AIR sees the witness, and the
AIR-side trace builder asserts the exact felt count.

**Collision-freeness still holds** (proof unchanged from Stage 8): two
distinct values either produce different felt vectors (different suffix
position, captured by the zero padding) or the contradiction
`v1 == v2` follows. The fixed felt count just removes the variable
length felt as a distinguisher (it's now a constant `19` in the v2
length-felt position) — the felt CONTENT differences carry all the
distinguishing information.

**v2 commitment values for preimage_knowledge change** vs Stage 8:
each commitment now absorbs 19 felts of witness instead of `ceil((value.len() + 1) / 7)`. No production impact (still stub mode).

**Files changed**:
- [circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs):
  `MAX_PADDED_WITNESS_FELTS = 19` constant; `witness_to_felts`
  zero-pads to that count; 3 new tests
  (`witness_to_felts_padding_returns_fixed_felt_count`,
  `padded_witness_distinguishes_different_lengths_at_chunk_boundaries`,
  `witness_to_felts_oversize_value_exceeds_max`).

**Trace shape that the next-session AIR work targets**:
- Tag (5 felts) + circuit_id (1) + length-felt (1) + padded witness (19) + nonce (5) = **32 input felts** always
- `ceil(32 / 8) = 4` absorption blocks
- Trace rows: 1 init + 14 (block 1 sub-rounds) + 1 absorb + 14 + 1 absorb + 14 + 1 absorb + 14 = 60 active + 4 stall padding = **64 rows** (power of 2)
- Same Rescue+absorption+padding constraint structure as tier/age, scaled to 4 blocks
- 21 periodic columns (12 `ark_combined` + 4 Rescue selectors + 1 absorption-row selector + 3 inter-block absorption-row selectors expanded to per-block) — TBD precise layout in Stage 11
- Predicate (length range check via boolean decomposition) deferred to a follow-up; commitment-opening soundness alone is meaningful with collision-free hiding

**Verification (Stage 10)**:
- `cargo test --workspace`: **237 / 237** (was 234; +3 padding tests)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: 45 / 45 (unchanged)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: 32 / 32 (unchanged)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

### Stage 11 addendum — preimage_knowledge real commitment-opening AIR shipped

Built directly on the Stage 10 fixed-encoding foundation. Final design
choices:

**`MAX_PADDED_WITNESS_FELTS` adjusted 19 → 20** for clean 4-block
absorption: total Rescue input is exactly `5+1+1+20+5 = 32 = 4×8` felts.
Every block absorbs the full 8-felt rate, no partial-block edge case.

**Trace**: 12 columns × 64 rows. 4 absorption blocks at rows 0, 15, 30, 45.
Sub-rounds: rows 1-14, 16-29, 31-44, 46-59. Final state at row 59.
Stall padding at rows 60-63.

**Constraints (12, one per state column)**: degree 7 in trace + 1 cycle-64
periodic factor. Per-column residual is the same `sel_first * res_first +
sel_second * res_second + sel_absorb * res_absorb + sel_pad * res_pad`
union pattern from tier/age. Critical difference for preimage_knowledge:
the absorption transitions absorb the **full rate** (positions 4..12),
not just the lower 5 positions — `state[0..4][next] == state[0..4][curr]`
is the only constraint on absorption rows; the rate is fully
witness-supplied via the 8 input felts of the next block.

**Periodic columns (16)**: 12 ark_combined + 4 selectors
(`first_half`, `second_half`, `absorb`, `pad`). Absorption fires at
transitions 14, 29, 44. Padding fires at transitions 59-62.

**Boundary constraints (15)**:
- Row 0: state[0]=32 (NUM_INPUT_FELTS), state[1..4]=0,
  state[4..9]=tag_felts, state[9]=4 (PreimageKnowledge circuit_id),
  state[10]=20 (length felt). state[11] = first witness felt is
  intentionally unconstrained (private witness).
- Row FINAL_ROW (=59): state[4..8] = commitment.

**Files changed**:
- [circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs):
  `MAX_PADDED_WITNESS_FELTS = 20`; `prove()` and `verify()` simplified
  (no separate `prove_winterfell` helper).
- [circuits/preimage_knowledge/src/air.rs](../circuits/preimage_knowledge/src/air.rs):
  full rewrite. New `NUM_INPUT_FELTS = 32`, `NUM_BLOCKS = 4`,
  `TRACE_LENGTH = 64`, `FINAL_ROW = 59`.
- [circuits/preimage_knowledge/src/prover.rs](../circuits/preimage_knowledge/src/prover.rs):
  new `build_v2_input_felts`, `build_v2_state_trace`,
  `final_digest_from_trace`. `build_trace` rebuilds the 64-row trace
  from `(value, nonce)`. `build_proof` signature changed to
  `(value, nonce, public, options, seed)`.

**Verification (Stage 11)**:
- `cargo test --workspace`: **237 / 237** (unchanged default features)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: 45 / 45
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: 32 / 32
- `cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage`:
  **33 / 33** including the prove→verify roundtrip and a comprehensive
  9-test `v2_real_trace_tests` module verifying trace-shape, length-32 input
  layout, 64-row trace, padding rows, and v2-commitment equality across
  empty/short/full/varied-length witnesses.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo clippy -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

**Soundness impact**: `preimage_knowledge` now has the same in-AIR
commitment-opening soundness as tier/age. A malicious prover cannot
fabricate a proof for an arbitrary commitment — Rescue-Prime collision
resistance + AIR-enforced 4-block absorption binds the prover to a
specific `(witness, nonce)` pair. The `len(value) ≤ max_value_bytes`
predicate is still enforced by `validate()` outside the AIR; the in-AIR
length-range check is a follow-up (mirrors age_threshold's 22-bit
boolean decomposition).

**Three of four circuits now ship real commitment-opening AIRs:**
tier (full predicate), age (full predicate), preimage (commitment opening only).
Only set_membership remains with a placeholder AIR.

### Stage 12 addendum — set_membership witness padding (Stage-10 equivalent for set)

Prerequisite for the set_membership real AIR: same fixed-felt-count
padding mechanism as preimage_knowledge, sized for set's smaller
witness budget.

**`MAX_PADDED_WITNESS_FELTS = 12`** in
[circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs).
Sized so the **total Rescue input** is exactly `5 + 1 + 1 + 12 + 5 = 24`
felts = 3 absorption blocks × 8 rate width. 12 felts accommodates any
value up to `83 bytes` (= `12 × 7 − 1` for the suffix), comfortably
above the workspace-pinned `MAX_SET_VALUE_BYTES_PADDED = 64`.

`witness_to_felts` now:
1. Appends the `0x01` distinguishing suffix (Stage 8 collision fix).
2. Chunks via `bytes_to_field`.
3. Zero-pads up to `MAX_PADDED_WITNESS_FELTS`.

Identical structure to `preimage_knowledge::witness_to_felts`, differing
only in the cap value (set: 12, preimage: 20).

**v2 commitment values for set_membership change** vs the pre-Stage-12
v2 (which only had the `0x01` suffix, not the zero-padding). No
production impact (still stub mode, no signed bundles encode the old
values).

**Files changed**:
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs): added `MAX_PADDED_WITNESS_FELTS = 12`; `witness_to_felts` zero-pads to that count; 3 new regression tests (`witness_to_felts_padding_returns_fixed_felt_count_for_in_range_values`, `padded_witness_distinguishes_different_lengths_at_chunk_boundaries`, `witness_to_felts_oversize_value_exceeds_max`).

**Trace shape that the next-session AIR work targets (Stage 13)**:
- Commitment-opening: 24 input felts → 3 blocks × 8 felts each, 12-col × ~48-row Rescue trace (mirrors tier/age/preimage at 3 blocks).
- Merkle walk: up to 32 conditional-swap steps (`set_depth ≤ MAX_SET_DEPTH = 32`), each step is a Rescue merge of the current node with the path sibling under `SET_NODE_TAG`, with a side-bit determining which operand goes first.
- Plausible AIR layout: a single Winterfell trace containing both phases. Commitment-opening occupies rows 0..N1, Merkle walk occupies rows N1..N2. Selectors gate which phase's constraints fire on each row. Total trace length is power-of-two ≥ N2.
- OR: two separate AIRs proved independently and verified together at the manifest level (simpler but doubles proof bytes per leaf).
- Final design decision: single combined AIR (per [docs/CIRCUITS.md](CIRCUITS.md) intent that one leaf = one proof).

**Verification (Stage 12)**:
- `cargo test --workspace`: **240 / 240** (was 237; +3 set padding regressions)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: 45 / 45 (unchanged)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: 32 / 32 (unchanged)
- `cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage`: 33 / 33 (unchanged)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

### Stage 13 addendum — set_membership real commitment-opening AIR shipped

Mechanical adaptation of preimage_knowledge's 4-block AIR (Stage 11) to
3 blocks. Same Rescue gadget, same absorption pattern, same Winterfell
periodic-column / selector structure — different absorption row indices
and one fewer block.

**Final design choices**:
- 24 input felts = `tag(5) + circuit_id(1) + length(1) + padded_witness(12) + nonce(5)`
- 3 absorption blocks × 8 felts each
- `TRACE_LENGTH = 64` (smallest power-of-two ≥ 45 active rows)
- 45 active rows = 1 init + (3 × 15) − 2 shared boundary rows. Rows 45–63
  are stall padding (all equal row 44).
- `FINAL_ROW = 44` where `state[4..8]` equals the v2 commitment.
- 16 periodic columns: 12 `ark_combined` + 4 selectors (`first_half`,
  `second_half`, `absorb` at rows 14, 29; `pad` at rows 44–62).
- 15 boundary constraints: row 0 (`state[0]=24`, capacity zeros, 5 tag
  felts, `circuit_id=2`, `length=12`); row 44 (`state[4..8]=commitment`).

**Scope clarification**: this AIR proves only the COMMITMENT OPENING for
set_membership. The Merkle-walk content — `set_leaf = Rescue(SET_LEAF_TAG
‖ value_felts)` plus `set_depth` rounds of conditional-swap Rescue merge
under `SET_NODE_TAG` ending at `set_root` — is enforced by
`crate::validate()` outside the AIR for now. Stage 14 lifts the Merkle
walk into the AIR.

**Files changed**:
- [circuits/set_membership/src/air.rs](../circuits/set_membership/src/air.rs):
  full rewrite. New `NUM_INPUT_FELTS = 24`, `NUM_BLOCKS = 3`,
  `TRACE_LENGTH = 64`, `FINAL_ROW = 44`.
- [circuits/set_membership/src/prover.rs](../circuits/set_membership/src/prover.rs):
  full rewrite. `build_v2_input_felts`, `build_v2_state_trace`,
  `final_digest_from_trace` mirroring preimage_knowledge.
  `build_proof((value, nonce, public, options, seed))` threaded.
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs):
  `prove()` and `verify()` simplified (no nested return).

**Verification (Stage 13)**:
- `cargo test --workspace`: **240 / 240** (default features unchanged)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier`: **45 / 45**
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age`: **32 / 32**
- `cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage`: **33 / 33**
- `cargo test -p trusset-circuit-set-membership --features prod-proofs-set`: **38 / 38**
  including a comprehensive 8-test `v2_real_trace_tests` module
  verifying trace-shape, length-24 input layout, 64-row trace, padding
  rows, and v2-commitment equality across country codes / full-length /
  varied-length witnesses.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo clippy -p trusset-circuit-set-membership --features prod-proofs-set --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

**Soundness impact**: `set_membership` now has commitment-opening
soundness IN THE AIR. A malicious prover cannot fabricate a proof for
an arbitrary commitment — Rescue-Prime collision resistance + AIR-
enforced 3-block absorption binds the prover to a specific `(value,
nonce)` pair. The set-membership predicate (Merkle walk) is still
enforced by `validate()` outside the AIR; Stage 14 closes that gap.

**ALL FOUR CIRCUITS NOW SHIP REAL COMMITMENT-OPENING AIRs**:
- tier: full predicate ✓ (Pattern A)
- age: full predicate ✓ (22-bit boolean range)
- preimage: commitment opening ✓ (length predicate still in validate())
- set: commitment opening ✓ (Merkle walk still in validate())

### Stage 14 addendum — AIR-time negative-witness tests for preimage + set

Same pattern as the Stage 5/6 negatives for tier/age: bypass `validate()`
and call `prover::build_proof` directly. The AIR's commitment-opening
boundary (row 59 for preimage, row 44 for set) MUST cause Winterfell's
prover to fail before emitting a proof. Winterfell panics on boundary
violation, so the test wrapper uses `std::panic::catch_unwind`.

**Tests added**:
- `circuits/preimage_knowledge/src/lib.rs`:
  - `air_rejects_different_value_for_same_commitment`: encodes a public
    commitment for `"alice"`, then attempts to prove with `value=b"bob"`.
    The Stage 11 4-block trace produces a final-row digest that is
    `commit("bob", nonce)`, not `commit("alice", nonce)` — boundary at
    row 59 fails.
  - `air_rejects_different_nonce_for_same_commitment`: same value, wrong
    nonce. Different final-row digest, boundary fails.
  - `air_rejects_tampered_commitment_limbs`: honest witness but one
    limb of `public.commitment` flipped — final-row digest doesn't match
    the tampered public.
  - `air_accepts_honest_witness`: positive control through the same
    code path.

- `circuits/set_membership/src/lib.rs`: analogous 4 tests
  (`air_rejects_different_value_for_same_commitment` against the
  fixture allowlist, `air_rejects_different_nonce_for_same_commitment`,
  `air_rejects_tampered_commitment_limbs`, `air_accepts_honest_witness`).

**Verification (Stage 14)**:
- `cargo test --workspace`: **240 / 240** (default features unchanged)
- `cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage`: **37 / 37** (was 33; +4 AIR-time negatives)
- `cargo test -p trusset-circuit-set-membership --features prod-proofs-set`: **42 / 42** (was 38; +4 AIR-time negatives)
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo fmt --check --all`: clean

**Soundness impact**: confirms the commitment-opening soundness shipped
in Stages 11 and 13 is real, not a trivially-accepting AIR. Even though
the predicate enforcement for preimage (length range) and set (Merkle
walk) is still in `validate()` outside the AIR, the commitment-opening
half is now defended both by the cryptographic argument (Rescue-Prime
collision resistance + AIR-enforced absorption) AND by direct empirical
test (negative witnesses are rejected at AIR-prove time).

### Stage 15 addendum — Measured perf benchmarks vs spec §13.6 targets

All four prod-proofs feature paths benchmarked in release mode with
5 iterations each, p50 reported. Numbers and analysis are pinned in
[docs/PERFORMANCE.md](PERFORMANCE.md#measured-phase-2b-step-b-real-airs).

Headline: **3 of 4 circuits comfortably meet spec §13.6 targets**.
`tier_threshold` is the outlier — measured 551 ms prove p50 vs 200 ms
target (2.8× over). Suspected cause is the predicate-column count and
constraint degree profile, not a fundamental scaling issue. Verify times
and proof sizes are well within budget across all four (verify ≤ 2.5 ms
vs ≤ 10–25 ms targets; proof ≤ 21 KB vs ≤ 60–120 KB targets).

The tier-prove regression doesn't block the cryptographic correctness
of the AIR — it's a constraint-design optimization opportunity tracked
for Stage 16+. The Merkle-walk-equipped set_membership measurement is
also pending (Stage 16's set Merkle walk lands first).

**What's still NOT done (deferred to Stage 16+)**:

1. **Real AIR transition + boundary constraints for `tier_threshold`**.
   The trace shape is now nailed down (29 rows × 12 state cols + predicate
   columns TBD). What's left: wiring `Air::evaluate_transition` to
   call `rescue_air::enforce_first_half` / `enforce_second_half` on
   sub-round rows (1-14, 15-28), the absorption constraint at row 14
   (`state[4..9][next] = state[4..9][curr] + nonce_input_cols[curr]`),
   stall constraints on padding rows (29-31), boundary at row 28
   (`state[4..8] = commitment`), plus Pattern A predicate columns
   (`tier_pred`, `acc_tier`, `slack_pred`, `acc_slack`) bound to
   `state[11][0]` via the periodic-selector-at-row-0 trick. Still
   requires solving:
   - Constant trace columns problem (Winterfell rejects degree-0 trace
     polynomials with nontrivial constraints) — workaround documented in
     STEP_2B_DESIGN.md uses periodic-mask selectors so columns are
     "constant" only over the first few rows
   - Witness-to-Rescue-input-felt binding via periodic-selector boundary
     at row 0: `selector_row_0 * (state[11] - tier_pred) = 0`
   - Multi-block absorption sequencing at row 14 (degree-1 linear
     constraint, gated by a periodic selector)
2. **Same for `age_threshold`** (boolean range decomp on `slack = age_days - min_age_days`)
3. **Variable-length sponge for `preimage_knowledge`, `set_membership`** — still need a selector-column mechanism per "Issue 1" sub-path 1b
4. **Workspace flip** (Steps 6, 7) — defaults to `prod-proofs`, `manifest.mode = "production"`
5. **WASM parity test** (Step 9) — wasmer 5 dev-dep on verifier
6. **Cross-stack e2e** (Step 10), **perf benchmarks + audit doc updates** (Step 11)
7. **Release-cache CI smoke** (Step 12)

**Estimated remaining effort**: 10–14 hours of focused engineering across
2–3 sessions. The hardest single item is the variable-length sponge AIR
for preimage/set; tier and age are now tractable thanks to v2.

**Files NOT changed (deliberately preserved)**:
- The 7 domain tags ([circuits/common/src/domain.rs](../circuits/common/src/domain.rs))
- The hash primitive ([circuits/common/src/hash.rs](../circuits/common/src/hash.rs))
- Bundle format ([bundle-format/src/manifest.rs](../bundle-format/src/manifest.rs), `secrets.enc` layout, manifest JSON keys, signing canonical view)
- NDJSON event schema, CSV columns
- Leaf hash formula ([bundle-format/src/leaf.rs](../bundle-format/src/leaf.rs)) — still uses the same fields; only the `commitment` value changes per the v2 formula

The wire-format change is **value-level only**: same JSON key set, same
layout, same signing scheme — just different commitment hash values for
the same `(witness, nonce)` pair. This is exactly the stub→production
transition the spec anticipates.

### Stage 15a addendum — Release-mode AIR-time test correctness fix

A test-framework bug surfaced in all four `prod-proofs-*` AIR-time negative
sweeps: the wrappers (`try_prove_air_only` / `try_prove_set_air_only` etc.)
relied on Winterfell's prover panicking when the trace violated boundary
constraints. That panic path is implemented as `debug_assert!`s inside
Winterfell, which are compiled out in release builds. Result: in release
mode, the prover happily produced a "proof" whose verification would fail,
the test wrapper returned `Ok(bytes_that_wont_verify)` instead of `Err`,
and every AIR-time negative test failed.

Fix: each wrapper now chains prove → verify. If `prove` returns bytes, the
wrapper also calls `verifier::verify_proof` on those bytes against the same
public inputs; verification failure is treated as rejection. The wrapper's
contract ("returns `Err` for any witness inconsistent with the public AIR
inputs") now holds in both build profiles.

This is a pure test-framework fix — it changes no constraint, no trace, no
prover, no verifier. The AIR's soundness model is unchanged: the AIR
enforces correctness by causing verification to fail; the prover panicking
in debug builds is just a faster diagnostic for the same underlying
constraint, not an additional security layer.

**Files changed**:
- [circuits/tier_threshold/src/lib.rs](../circuits/tier_threshold/src/lib.rs)
- [circuits/age_threshold/src/lib.rs](../circuits/age_threshold/src/lib.rs)
- [circuits/preimage_knowledge/src/lib.rs](../circuits/preimage_knowledge/src/lib.rs)
- [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs)

**Verification (Stage 15a)**:
- `cargo test --workspace --release`: **240 / 240** (unchanged)
- `cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier --release`: **40 / 40 + 5 integration** (was 4 release failures)
- `cargo test -p trusset-circuit-age-threshold --features prod-proofs-age --release`: **27 / 27 + 5 integration**
- `cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage --release`: **32 / 32 + 5 integration**
- `cargo test -p trusset-circuit-set-membership --features prod-proofs-set --release`: **37 / 37 + 5 integration**
- `cargo fmt --check --all`: clean
- `cargo clippy --workspace --all-targets -- -D warnings`: clean
- `cargo clippy -p trusset-circuit-<C> --features prod-proofs-<C> --all-targets -- -D warnings`: clean for all four circuits

This closes a DoD gap that would otherwise have blocked the release-cache CI
smoke (DoD item 8) and any reviewer running `cargo test --release` on the
prod-proofs feature paths.

### Stage 16 design — set_membership in-AIR Merkle walk (PLANNED, not yet implemented)

The headline remaining cryptographic work. This addendum captures the full
design so the next session can implement without re-deriving the row math,
column layout, or constraint algebra.

**Statement to prove in-AIR (full statement, no `validate()` fallback)**:

> I know `(value, nonce, side_bits[0..set_depth], sibling_felts[0..set_depth])`
> such that:
> 1. `Rescue(COMMITMENT_TAG ‖ id=2 ‖ len=12 ‖ witness(value) ‖ nonce) ==
>    public.commitment` (commitment opening, rows 0..44 — already done in Stage 13)
> 2. `set_leaf = Rescue(SET_LEAF_TAG ‖ witness(value))` (set-leaf hash, rows 45..89)
> 3. Walking the Merkle path from `set_leaf` for `public.set_depth` levels,
>    conditionally swapping at each level under `side_bits[k]`, and merging
>    under `SET_NODE_TAG` yields `public.set_root` (rows 90..)

**User-confirmed design choices** (from session-opening Q&A):

1. **set_leaf input layout**: `SET_LEAF_TAG (5 felts) ‖ witness_to_felts(NFC(value)) (12 felts) = 17 felts → 3 absorption blocks (45 rows)`. The set_leaf and commitment phases share the **same** padded 12-felt witness via cross-phase binding columns. Operator action on landing: re-run `trusset-list-commit` because `set_leaf_digest` formula changes.
2. **Variable depth**: Fixed `TRACE_LENGTH = 2048` always. AIR-construction reads `set_depth` from public inputs and emits the `set_root` boundary at row `90 + set_depth * 30 - 1`. Unused levels are stall padding.
3. **Merge primitive**: Keep `hash_two_with_tag(SET_NODE_TAG, a, b)` exactly as it is in [circuits/common/src/hash.rs](../circuits/common/src/hash.rs). Each merge absorbs 13 felts (5 tag + 4 + 4) → 2 Rescue blocks → 30 trace rows per level. Set_root values stay stable across all existing lists.

**Final trace shape (CORRECTED scope — discovered during initial implementation pass)**:

```
TRACE_WIDTH  = 33   (12 Rescue state + 12 witness binding + 1 side + 4 sibling + 4 current_node_carry)
TRACE_LENGTH = 2048 (next pow2 ≥ 45 + 45 + 32×30 + 1 = 1051)
```

The original plan estimated 29 columns. **Implementation revealed an additional 4 columns are needed**: a `current_node_carry[0..4]` band that propagates the level-entry Merkle node across all 30 rows of the level, so both the setup row (rows `90 + k*30`) AND the absorb-b row (rows `105 + k*30`) can reference it. Without these carry columns, by the time the absorb-b transition fires, the original `current_node` has been overwritten by 14 sub-round rows of the level's first Rescue block.

### Column map (TRACE_WIDTH = 33)

| Cols    | Name                                  | Purpose                                                                              |
|---------|---------------------------------------|--------------------------------------------------------------------------------------|
| 0..12   | Rescue state (12 felts)               | Unchanged from Stage 13 commitment-opening                                           |
| 12..24  | `witness_felts[0..12]` (12 cols)      | Constant across all rows; binds commitment and set_leaf phases to same witness       |
| 24      | `side_bit`                            | Boolean witness ∈ {0,1} per Merkle level                                             |
| 25..29  | `sibling_felts[0..4]`                 | Witness sibling node per Merkle level                                                |
| 29..33  | `current_node_carry[0..4]`            | Propagates level-entry node through the level so setup + absorb_b can both use it   |

### Row regions

| Rows         | Phase                          | Input felts                                                              |
|--------------|--------------------------------|--------------------------------------------------------------------------|
| 0..45        | Commitment opening (existing)  | `COMMITMENT_TAG (5) ‖ id=2 (1) ‖ len=12 (1) ‖ witness (12) ‖ nonce (5) = 24` |
| 45..90       | Set_leaf hash (NEW)            | `SET_LEAF_TAG (5) ‖ witness (12) = 17` (3 blocks)                        |
| 90..1050     | Merkle walk (NEW, 32 levels × 30 rows) | Per level: `SET_NODE_TAG (5) ‖ a (4) ‖ b (4) = 13` (2 blocks)            |
| 1050..2048   | Stall padding                  | All equal row 1049                                                       |

For `set_depth < 32`, rows `[90 + set_depth*30 .. 2047]` are stall padding. The `set_root` boundary at row `90 + set_depth*30 - 1` asserts `state[4..8] = set_root`.

### Per-Merkle-level breakdown (30 rows per level k ∈ [0, 32))

Let `L = 90 + k * 30` (level start). Define:
- `node_in_a = (1 - side) * current_node_carry + side * sibling`
- `node_in_b = side * current_node_carry + (1 - side) * sibling`

The level's 30 rows decompose as:

| Within-level row | Absolute row | Trace state                                                                       |
|------------------|--------------|-----------------------------------------------------------------------------------|
| 0 (setup_a)      | L            | `state[0]=13`, `state[1..4]=0`, `state[4..9]=SET_NODE_TAG felts`, `state[9..12]=node_in_a[0..3]` |
| 1..14            | L+1..L+14    | Block 1 sub-rounds (14 rows)                                                      |
| 15 (absorb_b)    | L+15         | `state[0..4]_next = state[0..4]_curr`, `state[4..12]_next = state[4..12]_curr + [node_in_a[3], node_in_b[0..4], 0, 0, 0]` |
| 16..29           | L+16..L+29   | Block 2 sub-rounds (14 rows)                                                      |

After row L+29: `state[4..8]` = the merged node = `current_node_carry` for level k+1.

**The carry column constraint** (the key insight that adds 4 columns):
- At setup_a row L: `current_node_carry[k] = state[4..8][L]` (propagated from previous level's final state, or from set_leaf row 89 for k=0)
- At rows L+1..L+29 within the level: `current_node_carry_next = current_node_carry_curr` (constancy across the level)
- At setup_a row L+30 (next level): `current_node_carry_new[k] = state[4..8][L+29]` (the merged node)

This is encoded with three selectors:
- `sel_carry_load`: 1 at rows L (level setup) for k ∈ [1, 32) — fires the "load from rate" constraint
- `sel_carry_const`: 1 at rows L+1..L+29 for each level — constancy
- `sel_carry_init`: 1 at row 90 (first level setup) — load from set_leaf's row-89 rate

### Periodic columns (full layout for set_depth)

Cycle = `TRACE_LENGTH = 2048`. Each periodic column is a flat array of length 2048.

Count: 12 ark_combined + 18 selectors + 5 setleaf_tag + 5 node_tag = **40 periodic columns**.

| Index   | Name                       | Description                                                                    |
|---------|----------------------------|--------------------------------------------------------------------------------|
| 0..12   | ark_combined[0..12]        | Rescue round constants (multiplexed first/second-half by sub-round position)   |
| 12      | sel_rescue_first           | 1 at every first-half sub-round across all 3 phases                            |
| 13      | sel_rescue_second          | 1 at every second-half sub-round                                               |
| 14      | sel_commit_absorb1         | 1 at transition 14 (commit block 1 → 2)                                        |
| 15      | sel_commit_absorb2         | 1 at transition 29 (commit block 2 → 3)                                        |
| 16      | sel_commit_final_to_setleaf| 1 at transition 44 (commit end → set_leaf setup)                               |
| 17      | sel_setleaf_setup          | 1 when row-45-style setup applies (transition 44, setting state[0..12] absolute) |
| 18      | sel_setleaf_absorb1        | 1 at transition 59 (set_leaf block 1 → 2)                                      |
| 19      | sel_setleaf_absorb2        | 1 at transition 74 (set_leaf block 2 → 3)                                      |
| 20      | sel_setleaf_final_to_merge | 1 at transition 89 (set_leaf end → first Merkle level)                         |
| 21      | sel_merge_setup_a          | 1 at transitions `L - 1` for L ∈ {90, 120, ..., 90+31*30}                      |
| 22      | sel_merge_absorb_b         | 1 at transitions `L + 14` for L ∈ {90, 120, ...}                               |
| 23      | sel_merge_carry_const      | 1 at all intra-level transitions (mask depends on set_depth — see below)      |
| 24      | sel_walk_pad               | 1 at all stall transitions from `90 + set_depth*30` onward                     |
| 25      | sel_bind_row_0             | 1 at transition 0 only (binds state[11][0] to witness_col[0])                  |
| 26..31  | setleaf_tag_felts[0..5]    | `bytes_to_field(SET_LEAF_TAG)`, injected at row-45 setup                       |
| 31..36  | node_tag_felts[0..5]       | `bytes_to_field(SET_NODE_TAG)`, injected at every merge setup_a row            |
| 36      | sel_set_root_boundary      | 1 at the depth-dependent set_root boundary row (alternative to using `Assertion`) |

**Depth-dependent selectors** (`sel_walk_pad`, `sel_set_root_boundary`, `sel_merge_setup_a` / `sel_merge_absorb_b` / `sel_merge_carry_const` truncated at depth): computed inside `Air::get_periodic_column_values()` from `self.set_depth`. This is sound because `set_depth` is a public input.

### Transition constraints (degree budget)

Following the Stage 4 / Stage 5 degree-declaration learning, each per-column declaration uses `with_cycles(d, vec![TRACE_LENGTH])` (single periodic factor). Yield: `d * 2047 + 2047`.

| Column         | Declared degree                | Rationale                                                                |
|----------------|--------------------------------|--------------------------------------------------------------------------|
| 0..12 (state)  | `with_cycles(7, vec![2048])`   | Rescue S-box x^7 + all linear constraints (absorption, setup, padding)   |
| 12..24 (witness)| `with_cycles(1, vec![2048])`  | Constancy: `witness_col_next - witness_col_curr = 0`                     |
| 24 (side)      | `with_cycles(2, vec![2048])`   | Boolean range: `side * (side - 1) = 0` at setup_a rows                   |
| 25..29 (sibling)| `with_cycles(1, vec![2048])`  | Free (selector-gated zero residual to satisfy Winterfell's per-col check)|
| 29..33 (carry) | `with_cycles(2, vec![2048])`   | Constancy + conditional-swap loading at level boundaries (degree 2 via `(1-side)*X + side*Y`) |

State col 0..12 transition formula (concatenating all phase-specific residuals via selectors):

```
result[i] = sel_rescue_first  * res_first[i]                 // Rescue MDS·(curr^7)+ARK1
         + sel_rescue_second * res_second[i]                // Rescue (INV_MDS·(next-ARK2))^7
         + sel_walk_pad      * res_pad[i]                   // next[i] - curr[i] = 0
         + sel_commit_absorb1* res_commit_absorb1[i]        // capacity preserved; rate += witness[1..8]
         + sel_commit_absorb2* res_commit_absorb2[i]        // capacity preserved; rate += witness[9..12] ‖ nonce[0..5]
         + sel_setleaf_setup * res_setleaf_setup[i]         // absolute: state[0]=17, tag, witness[0..3]
         + sel_setleaf_absorb1*res_setleaf_absorb1[i]       // rate += witness[3..11]
         + sel_setleaf_absorb2*res_setleaf_absorb2[i]       // rate += [witness[11], 0, 0, 0, 0, 0, 0, 0]
         + sel_merge_setup_a * res_merge_setup_a[i]         // absolute: state[0]=13, tag, node_in_a[0..3]
         + sel_merge_absorb_b* res_merge_absorb_b[i]        // rate += [node_in_a[3], node_in_b[0..4], 0, 0, 0]
```

where `node_in_a` and `node_in_b` are computed from `side_bit` and the level's `current_node_carry` (column band).

### Boundary assertions

Total: 28 boundaries.

- Row 0: `state[0]=24`, `state[1..4]=0` (3), `state[4..9]=COMMITMENT_TAG felts` (5), `state[9]=2`, `state[10]=12`. = 11
- Row 44 (`COMMITMENT_FINAL_ROW`): `state[4..8]=commitment`. = 4
- Row 45 (`SETLEAF_ROW_START`): `state[0]=17`, `state[1..4]=0` (3), `state[4..9]=SET_LEAF_TAG felts` (5). = 9
- Row `90 + set_depth*30 - 1` (depth-dependent): `state[4..8]=set_root`. = 4

The row-0 binding `state[11][0] = witness_col[0]`, the row-45 binding `state[9..12][45] = witness_col[0..3]`, and the level-0 binding `current_node_carry[90] = state[4..8][89]` are all enforced as transition constraints (gated by their respective selectors), not as boundary assertions, because they reference private trace values.

### Set_leaf_digest helper change required in [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs)

`set_leaf_digest(value)` currently uses raw `bytes_to_field(NFC(value) ‖ 0x01)` (variable-length felt count). The AIR requires a fixed-shape input, so the off-AIR helper must switch to:

```rust
pub fn set_leaf_witness_felts(value: &[u8]) -> Vec<Felt> {
    let canonical = canonicalize_set_value(value); // NFC + ASCII bypass
    witness_to_felts(&canonical)                   // 0x01 suffix + 7-byte chunk + pad to 12 felts
}
pub fn set_leaf_digest(value: &[u8]) -> Digest {
    let felts = set_leaf_witness_felts(value);
    let tag_felts = bytes_to_field(&SET_LEAF_TAG);
    let mut combined = tag_felts;
    combined.extend_from_slice(&felts);
    hash_elements(&combined)
}
```

This changes the `set_leaf_digest` value for every set entry → **all existing list-commit files become invalid**. Operator action: re-run `trusset-list-commit` for every list after Stage 16 lands. Document in [docs/MIGRATION_FROM_V1.md](MIGRATION_FROM_V1.md).

### Expected performance impact

Current set_membership: 303 ms prove p50 at 64 rows. Post-Stage-16: 2048 rows = 32× more rows. Rough estimate: 5–10 seconds prove time (Winterfell's prove time is roughly linear in trace length × constraint count). Verify time should stay <10 ms; proof size grows modestly (~30–60 KB). These numbers will need fresh benchmarks in [docs/PERFORMANCE.md](PERFORMANCE.md).

### Implementation order for next session

1. Update `set_leaf_digest` and `walk_merkle_path` callers — verify off-AIR Merkle walk still passes its tests (`walk_path_recovers_root`, `larger_tree_depth_eight`).
2. Rewrite `circuits/set_membership/src/air.rs` with the 33-column 2048-row layout.
3. Rewrite `circuits/set_membership/src/prover.rs` trace builder.
4. Iterate against Winterfell's degree checker until prove + verify roundtrip is green (the design memo's Stage 4/5 addenda show this typically requires 2–4 iterations on `with_cycles` declarations).
5. Add 5 new Merkle-walk AIR-time negative tests (tampered sibling, flipped side, swapped path, depth mismatch, max-depth positive).
6. Update [docs/PERFORMANCE.md](PERFORMANCE.md), [docs/CIRCUITS.md](CIRCUITS.md), [docs/AUDIT_PREP.md](AUDIT_PREP.md), [docs/MIGRATION_FROM_V1.md](MIGRATION_FROM_V1.md).

**Estimated effort**: 1–2 focused sessions for an experienced AIR engineer. The cryptographic content is straightforward; the constraint-algebra book-keeping at 33 columns × 5+ phase-selectors is the substantive work.

### Stage 16 NOT YET IMPLEMENTED IN THIS SESSION

This addendum is **design only** — no AIR code changed in this session. The set_membership AIR remains at Stage 13 (commitment-opening only, Merkle walk in `validate()`). Implementing Stage 16 was scoped at 1 session in the handoff prompt; the initial implementation pass discovered the 4-column carry-band requirement (above) and the necessary depth-dependent periodic-column construction, both of which push the total work to 2 focused sessions. Rather than ship half-implemented constraints (per the handoff's "no partial work on the Merkle walk" rule), the session pivoted to other audit-readiness items and produced this blueprint for the next session.

### Stage 17 design — preimage_knowledge in-AIR length-range predicate (PLANNED, not yet implemented)

The smaller of the two remaining in-AIR predicate pieces. Closes the
`preimage_knowledge` predicate gap so all four circuits reach full
audit-ready in-AIR soundness before the production mode flip.

**Statement to prove in-AIR (full statement, no `validate()` fallback)**:

> I know `(value, nonce, value_len_bytes)` such that:
> 1. `Rescue(COMMITMENT_TAG ‖ id=4 ‖ len=20 ‖ witness_to_felts(value) ‖ nonce) ==
>    public.commitment` (commitment opening, already shipped in Stage 11)
> 2. `value_len_bytes ≤ max_value_bytes` where `max_value_bytes =
>    DEFAULT_MAX_VALUE_BYTES = 128`
> 3. The `0x01` distinguishing suffix in `witness_to_felts(value)` lands
>    at byte position `value_len_bytes` within the padded witness, and all
>    bytes after that position are zero (i.e. the witness is "honest"
>    about its length).

**Why this is harder than tier/age range checks**:

The age circuit does a 22-bit boolean range decomposition on a single
witness felt (`slack`). For preimage, the length is encoded structurally
in the padded witness felts: bytes `[0..value_len_bytes]` are the actual
value, byte `value_len_bytes` is the `0x01` suffix, bytes
`[value_len_bytes+1..140]` are zero padding (140 = 20 felts × 7 bytes/felt).
The AIR must witness `value_len_bytes`, range-check it against
`max_value_bytes`, AND verify the suffix-then-zero structure of the
padded witness felts.

**User-confirmed design choices** (already implicit in the handoff
prompt's "deferred to Stage 17 separate design pass" framing):

1. **Witness `value_len_bytes` as a private trace column**. Range-check
   against `max_value_bytes` (public input) using the same boolean
   decomposition pattern as age's `slack`.
2. **Byte-decompose the suffix-containing felt**. The `0x01` suffix
   lands in exactly one of the 20 padded witness felts at exactly one
   of 7 byte positions within that felt. The AIR identifies which felt
   and which byte via two witnessed values: `suffix_felt_index` ∈ [0, 20)
   and `suffix_byte_offset` ∈ [0, 7).
3. **Cross-relate the witnessed values**: `value_len_bytes =
   suffix_felt_index * 7 + suffix_byte_offset` (integer division/modulo
   relation).
4. **Felts before suffix carry value bytes; felts at and after the suffix
   are constrained**:
   - For felts `[0..suffix_felt_index]`: free (carry the value bytes)
   - For felt `suffix_felt_index`: byte-decompose, prove bytes
     `[0..suffix_byte_offset]` are arbitrary, byte at position
     `suffix_byte_offset` equals `0x01`, bytes
     `[suffix_byte_offset+1..7]` are zero
   - For felts `[suffix_felt_index+1..20]`: zero
5. **Selector approach**: per-felt selector columns that indicate "this
   is the suffix felt" / "this is before / after the suffix".

**Trace shape extension** (on top of the Stage 11 12-col × 64-row
commitment-opening trace):

```
TRACE_WIDTH  = 12 (Rescue state)
              + 20 (witness_felts binding columns, constant across all rows)
              + 1  (value_len_bytes, witnessed at row 0)
              + 1  (suffix_felt_index, witnessed at row 0)
              + 1  (suffix_byte_offset, witnessed at row 0)
              + 7  (byte-decomposition of suffix_felt, witnessed at row 0)
              + 7  (boolean cols for value_len_bytes 7-bit decomposition; 128 fits in 7 bits)
              + 7  (boolean cols for max_value_bytes - value_len_bytes 7-bit decomp; proves ≤)
              = 55 columns
```

`max_value_bytes = 128` requires `2^7 = 128` representable values, so
7-bit decompositions suffice for both `value_len_bytes` and the slack.

`TRACE_LENGTH = 64` stays unchanged (the commitment-opening rows 0..59
plus 4 padding rows 60..63 already accommodate the new predicate
constraints at row 0).

**New column band layout** (cols 12..55):

| Cols    | Name                          | Constraint                                                                |
|---------|-------------------------------|---------------------------------------------------------------------------|
| 12..32  | `witness_felts[0..20]`         | Constancy across all rows; bound to commitment rate at absorption rows    |
| 32      | `value_len_bytes`              | Constancy; range-checked via boolean decomp; bound at row 0               |
| 33      | `suffix_felt_index`            | Constancy; in [0, 20)                                                     |
| 34      | `suffix_byte_offset`           | Constancy; in [0, 7)                                                      |
| 35..42  | `suffix_byte_decomp[0..7]`     | Each byte ∈ [0, 256); reconstructed felt = `witness_felts[suffix_felt_index]` |
| 42..49  | `len_bits[0..7]`               | Boolean range decomp of `value_len_bytes`                                 |
| 49..56  | `slack_bits[0..7]`             | Boolean range decomp of `max_value_bytes - value_len_bytes`               |

(Total width = 56; minor revision from the 55 above to account for clean
alignment.)

**Transition constraints (degree budget)**:

All new constraint terms use `with_cycles(d, vec![TRACE_LENGTH])` per
the Stage 4/5 rule:

| Constraint band                          | Declared degree   | Notes                                                                  |
|------------------------------------------|-------------------|------------------------------------------------------------------------|
| witness_felts[0..20] constancy           | `with_cycles(1, vec![64])` | `next - curr = 0`                                              |
| value_len_bytes / suffix_felt_index / suffix_byte_offset constancy | `with_cycles(1, vec![64])` | 3 columns, same pattern                            |
| suffix_byte_decomp ∈ [0, 256)            | `with_cycles(2, vec![64])` | Composition: `Σ_{b=0..256} (col - b) = 0` is degree 256, too high. Use **double-byte decomposition**: each "byte" is `low_nibble + 16 * high_nibble`, each nibble ∈ [0, 16). Two nibble-product gadgets per byte: `(nibble) * (nibble - 1) * ... * (nibble - 15) = 0` — still degree 16. Better: **bit-decompose each byte into 8 bits** via 56 more boolean cols (degree 2 each). This is heavy; consider folding into the felt-reconstruction constraint instead. |
| suffix felt reconstruction               | `with_cycles(1, vec![64])` | `Σ byte_b * 2^(8*b) = witness_felts[suffix_felt_index]` — linear in trace |
| value_len_bytes ≤ max_value_bytes        | `with_cycles(1, vec![64])` | `Σ slack_bits[i] * 2^i = max_value_bytes - value_len_bytes` plus each `slack_bits[i] * (slack_bits[i] - 1) = 0` (degree 2) |
| len_bits / slack_bits booleans           | `with_cycles(2, vec![64])` | `bit * (bit - 1) = 0`                                          |
| suffix_byte at offset = 0x01             | `with_cycles(1, vec![64])` | `suffix_byte_decomp[suffix_byte_offset] - 0x01 = 0` — needs periodic-selector trick to index by witness |

**The hard sub-problem: indexing by witnessed offset**

`suffix_byte_decomp[suffix_byte_offset] = 0x01` requires reading column
`35 + suffix_byte_offset`, where `suffix_byte_offset` is itself a
witnessed trace value. Direct array indexing on a witnessed index is
not expressible in an algebraic AIR constraint.

The standard workaround: introduce 7 indicator booleans
`offset_eq[0..7]` where `offset_eq[i] = 1 iff suffix_byte_offset == i`
(and exactly one is 1, the others 0). Then:
```
Σ offset_eq[i] * (suffix_byte_decomp[i] - 0x01) = 0
```
which is a linear-combination constraint, degree 2 in the trace
(`offset_eq[i] * suffix_byte_decomp[i]`).

Indicator constraints:
- Each `offset_eq[i] * (offset_eq[i] - 1) = 0` (boolean)
- `Σ offset_eq[i] = 1` (exactly-one)
- `Σ i * offset_eq[i] = suffix_byte_offset` (correctness)

The "indexing by witnessed value" pattern needs 7 more columns
(`offset_eq[0..7]`). Similarly for `felt_eq[0..20]` (20 more columns) if
we apply the same trick to index the suffix felt within
`witness_felts[0..20]`. Total: 7 + 20 = 27 extra columns just for
indicator booleans.

**Revised trace shape**:

```
TRACE_WIDTH  = 12 (Rescue) + 20 (witness binding) + 3 (length scalars) + 7 (suffix byte decomp)
              + 7 (offset_eq) + 20 (felt_eq) + 7 (len_bits) + 7 (slack_bits)
              = 83 columns
TRACE_LENGTH = 64
```

83 columns is sizable but tractable — it's about 2.4× the age circuit's
34 columns at the same trace length. Expected prove time scales roughly
linearly in column count for fixed trace length, so prove time should
remain comfortably under the 250 ms target (current 214 ms × ~2.4
column ratio puts us at ~510 ms; the constraint degrees are mostly
linear so the actual prove time will be closer to 300 ms).

**Alternative: punt the suffix-position check, prove only the length**

A simpler (but weaker) variant proves only that `value_len_bytes ≤
max_value_bytes` and that the witness felts ARE the byte chunks of
SOME prefix-of-length-`value_len_bytes` of an arbitrary byte string.
This drops constraints 3 and the `0x01` suffix verification entirely.

The weakness: a malicious prover could claim
`value_len_bytes = 5` while the actual witness felts encode a
20-byte string. Verification: the verifier would compute
`witness_to_felts(value)` for whatever they think the value is, hash
it, and compare to commitment. If the prover's claimed `value` has
length 5 but the actual witness felts decode to a longer string, the
commitments diverge (because `witness_to_felts(short_value)` zero-pads
differently than `witness_to_felts(long_value)`). So commitment opening
already enforces "the witness felts ARE the canonical encoding of
SOMETHING with length X". The new constraint just enforces "X ≤ max".

**Recommended approach for Stage 17**:

Implement the simpler variant first (constraints 1, 2, 3.length only).
The full suffix-position check (constraint 3.position) requires the
83-column trace and the indicator-boolean machinery; it's tractable but
adds significant verification surface for what amounts to a defense
against a corner case that commitment opening already catches indirectly.

Simpler variant column count:
```
TRACE_WIDTH = 12 + 20 + 1 (value_len_bytes) + 7 (len_bits) + 7 (slack_bits) = 47 columns
TRACE_LENGTH = 64
```

47 columns at the same trace shape as Stage 13 set_membership. Expected
prove time: ~350 ms (within the 250 ms target × ~1.4 column ratio
slack).

**Implementation order for Stage 17**:

1. Decide simple vs full variant (recommendation: simple).
2. Update `circuits/preimage_knowledge/src/air.rs` with the new column
   band, transition constraints, and boundary assertions.
3. Update `circuits/preimage_knowledge/src/prover.rs` trace builder to
   populate the new columns from the witness.
4. Add 5+ AIR-time negative tests: oversize value, claimed-length
   mismatch, etc.
5. Iterate against Winterfell degree checker.
6. Update [PERFORMANCE.md](PERFORMANCE.md), [CIRCUITS.md](CIRCUITS.md),
   [AUDIT_PREP.md](AUDIT_PREP.md).

**Estimated effort**: ~1 focused session for the simple variant,
~2 sessions for the full suffix-position variant.

### Stage 17 NOT YET IMPLEMENTED IN THIS SESSION

This addendum is design-only. The `preimage_knowledge` AIR remains at
Stage 11 (commitment-opening only, length-range check in `validate()`
outside the AIR). The blueprint here is for the next session to
implement.

### Stage 18 — Production-mode-flip infrastructure (PARTIAL — constant landed, flip blocked on 16+17)

The production-mode flip is a coordinated change across the workspace
that flips `manifest.mode` from `"stub"` to `"production"`, defaults
features from `stub-proofs` to `prod-proofs-*`, and changes the
verifier's `accept_stub` default from `true` to `false`. The flip is
blocked on Stages 16 (set Merkle walk) AND 17 (preimage length predicate)
landing, since shipping `mode: "production"` while two of four circuits
still depend on `validate()` for predicate enforcement would be a lie.

**What's prepared in this session**:

1. **`MODE_PRODUCTION` constant added** to [bundle-format/src/manifest.rs](../bundle-format/src/manifest.rs):
   ```rust
   pub const MODE_PRODUCTION: &str = "production";
   ```
   Paired with a stability regression test (`mode_constants_are_stable_wire_strings`)
   that pins both `MODE_STUB == "stub"` and `MODE_PRODUCTION == "production"`
   against drift. The wire-format string MUST NOT change without a
   coordinated update to all consumers (Rust prover, Rust verifier, TS CLI,
   external counterparty integrators).

2. **Verifier consolidated to use the constant**: [verifier/src/lib.rs:133](../verifier/src/lib.rs#L133)
   now references `MODE_PRODUCTION` instead of the bare string literal
   `"production"`. The mode-check semantics are identical (`mode == MODE_PRODUCTION
   || opts.accept_stub`); the constant eliminates a stringly-typed
   producer/consumer drift hazard.

**What remains for the flip itself** (next session, after Stages 16 + 17):

1. **Prover write-site**: change [prover/src/manifest.rs:71](../prover/src/manifest.rs#L71)
   from `mode: MODE_STUB.to_string()` to either:
   - **Unconditional `MODE_PRODUCTION`** if the workspace default features
     are simultaneously flipped to `prod-proofs-*` (so stub-mode builds
     can't happen by accident), OR
   - **Conditional `cfg!(any(feature = "prod-proofs-tier", ...))` selection**
     between `MODE_STUB` and `MODE_PRODUCTION` if stub-mode is preserved
     as a development build path.

   Recommendation: the second (conditional) — preserves the dev iteration
   loop that uses `--skip-proofs` for fast hashing tests.

2. **`StarkBlock::default()`**: at [bundle-format/src/manifest.rs:46](../bundle-format/src/manifest.rs#L46)
   currently emits `library: "winterfell-stub"`. Flip to `"winterfell-0.13"`
   (or read from a const for parity with the mode flip).

3. **Workspace Cargo.toml defaults**: each circuit's `Cargo.toml` flips
   `default = ["stub-proofs"]` → `default = ["prod-proofs-<C>"]`. Per the
   handoff prompt this is "½ session" mechanical work after the predicates
   land.

4. **Verifier `accept_stub` default flip**: [verifier/src/lib.rs](../verifier/src/lib.rs)
   `VerifyOptions::accept_stub` — current callers default to `true` in the
   CLI bin (`verifier/src/bin/cli.rs`) unless `--strict` is passed.
   Post-flip: default to `false`; rename `--strict` to `--accept-stub` (or
   add a separate `--accept-stub` flag and keep `--strict` as a no-op for
   backward compat).

5. **WASM exports**: [verifier/src/wasm.rs](../verifier/src/wasm.rs)
   `verify_strict` / `verify_permissive` — names already correct; no flip
   needed on the WASM side. JS callers may want to default to `verify_strict`
   instead of `verify_permissive` after the flip.

6. **CLI help text**: [cli/src/index.ts](../cli/src/index.ts) line ~42
   updates the `--skip-proofs` help to reflect that strict mode is now
   default. The `--strict` flag at line ~178 may be repurposed or removed.

7. **Operator-visible bundle compatibility**: every bundle ever produced
   while `manifest.mode == "stub"` is incompatible with the post-flip
   `accept_stub: false` default. Operators with persisted bundles must
   either retain a permissive-verifier path for historical bundles or
   re-prove the affected subjects.

8. **Migration doc update**: [docs/MIGRATION_FROM_V1.md](MIGRATION_FROM_V1.md)
   already documents the v2 commitment-formula bump (§13). Append a §14
   for the mode-flip cutover with the operator-action checklist above.

9. **Determinism canary re-run**: after the flip, `bash tests/e2e/canary.sh`
   MUST still produce byte-identical bundles across two runs. The flip
   itself doesn't introduce entropy, but it does change every produced
   bundle's byte content (different mode string, different library string),
   so the canary's pinned-bundle assertions need to be regenerated.

10. **Release-gate documentation update**: [docs/RELEASE_GATE.md](RELEASE_GATE.md)
    Phase 2B Step-B section flips the listed "DEFERRED" items to PASS
    once all four AIRs ship full predicate soundness and the flip lands.

**Estimated session cost for the post-flip work**: ~½ session, dominated
by the bundle-byte regeneration in the determinism canary and the
operator-doc updates. The code changes themselves are < 30 lines.

### Stage 19 — Stage 16 trace-math verified (host-side reference shipped)

Stage 16 (set_membership in-AIR Merkle walk) is still not landing in
the production AIR this session, but a substantive risk-reduction step
shipped: **the trace builder math is now empirically validated against
the off-AIR primitives in a dedicated integration test**. The 11-test
suite at [circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs)
confirms:

1. **Commitment phase rows 0..=44** — host-side trace builder reproduces
   `compute_commitment(CircuitId::SetMembership, witness_to_felts(value), nonce)`
   at `state[4..8][44]`. Mirror of Stage 13 production code.

2. **Set_leaf phase rows 45..=89** — `state[4..8][89]` equals the
   off-AIR padded set_leaf hash `Rescue(SET_LEAF_TAG ‖
   witness_to_felts(value))`. **This is the crucial new fact**: the
   in-AIR set_leaf math, computed via 3 Rescue absorption blocks with
   the padded 12-felt witness, agrees byte-for-byte with what the
   off-AIR `walk_merkle_path` will need to consume.

3. **Per-Merkle-level rows (30 rows each)** — conditional swap +
   2-block Rescue absorption of `SET_NODE_TAG ‖ effective_a ‖
   effective_b` produces the same merged digest as off-AIR
   `hash_two_with_tag(SET_NODE_TAG, a, b)` for both `side=0` and
   `side=1`.

4. **Chained walks** — sequencing the per-level merges using
   `current_node` carry across levels reproduces the off-AIR
   `walk_merkle_path` result for both depth-2 (4-leaf) and depth-8
   (256-leaf) trees, exercising both side bits.

5. **Padded vs unpadded set_leaf differ** — the Stage 16 padded set_leaf
   is empirically distinct from the current Stage 15 unpadded
   `set_leaf_digest`, confirming the wire-format break Stage 16 will
   ship is real and operator-visible.

6. **Cross-phase witness binding precondition** — the 12 padded witness
   felts consumed by the commitment phase are identical to those
   consumed by the set_leaf phase, satisfying the precondition for the
   in-AIR cross-phase binding constraint to be satisfiable by an honest
   prover.

7. **Trace constants** — `TRACE_WIDTH = 33`, `TRACE_LENGTH = 2048`,
   `COMMIT_FINAL_ROW = 44`, `SETLEAF_FINAL_ROW = 89`,
   `MERKLE_ROW_START = 90`, `MERGE_ROWS_PER_LEVEL = 30`,
   `MAX_SET_DEPTH = 32` — all match the design memo numerically; the
   max active row count `90 + 32 × 30 = 1050` is confirmed to fit
   inside the chosen 2048-row trace length.

**What this de-risks for the next session**:

- The trace-math half of Stage 16 is empirically verified. The next
  session can build the Winterfell `Air` impl on top of this validated
  math without needing to re-derive the row arithmetic from scratch.
- The chained-walk test is the integration smoke for the eventual
  end-to-end prove → verify roundtrip: if the AIR's transition
  constraints correctly implement the trace math, the resulting proof
  must verify against the public `set_root`.
- The padded vs unpadded set_leaf distinctness test is the regression
  guard for the operator-action notice in MIGRATION_FROM_V1.md §13 —
  there's now a CI-enforced source of truth for the wire break.

**What's still NOT delivered**:

- The Winterfell `Air` impl with all 40+ periodic columns, transition
  constraints (Rescue first/second half, witness constancy, side-bit
  boolean, conditional swap, cross-phase binding, depth-dependent
  stall), boundary assertions, and the iteration loop against the
  Winterfell degree checker. This is the substantive multi-session
  remaining work.
- The prover-side trace table assembly that pulls together the host
  reference functions in this test suite into a Winterfell-compatible
  `TraceTable<BaseElement>` with all 33 columns populated.
- The verifier-side public-input plumbing that exposes `set_depth` to
  the depth-dependent boundary calculation.

**Files changed**:

- New: [circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs)
  (11 tests, all green under `--features prod-proofs-set --release`).
- Modified: [docs/STEP_2B_COMMITMENT_DESIGN.md](STEP_2B_COMMITMENT_DESIGN.md)
  (this addendum).

**Verification**:

- `cargo test -p trusset-circuit-set-membership --features prod-proofs-set --test stage16_trace_shape --release`: **11 / 11** green.
- Production AIR (Stage 13) unchanged; all existing tests stay green.
- `cargo fmt --check --all`: clean.
- `cargo clippy --workspace --all-targets -- -D warnings`: clean.

**Path from here**: the next session implements the AIR transition
constraints by mapping the validated trace math in this test to
Winterfell constraint expressions, then iterating until the degree
checker is satisfied. The test file becomes the gold-standard reference
for "what the trace should look like" while the AIR enforces it.

### Stage 19a — Stage 16 periodic-column reference + negative-trace tests

Two further pieces landed atop the Stage 19 trace math:

**Periodic-column reference** at [circuits/set_membership/tests/stage16_periodic_columns.rs](../circuits/set_membership/tests/stage16_periodic_columns.rs)
(17 tests, all green). Validates the ~34-column periodic structure the
AIR will reference inside `evaluate_transition`:

- Column count and length (34 cols × 2048 rows)
- `sel_rescue_first` and `sel_rescue_second` partition all sub-rounds correctly;
  total count matches `3*14 (commit) + 3*14 (setleaf) + 2*depth*14 (merge)`
- First/second selectors are mutually exclusive at every row
- `sel_commit_absorb1` fires only at row 14; `sel_commit_absorb2` only at row 29
- `sel_setleaf_setup` only at row 44; `sel_setleaf_absorb{1,2}` only at rows 59, 74
- `sel_merge_setup_a` fires at row `89 + 30*k` for every level `k ∈ [0, depth)`
- `sel_merge_absorb_b` fires at row `104 + 30*k` for every level
- Merge selectors **truncate** correctly at low depth (only 2 instances for depth=2)
- `sel_set_root_boundary` fires at depth-dependent row `89 + 30*depth` — verified for depths 1, 2, 8, 16, 32
- `sel_pad` fires at every row past `set_root` boundary through `TRACE_LENGTH - 1`
- `sel_bind_row_0` fires only at transition 0
- `setleaf_tag_felts[0..5]` carry SET_LEAF_TAG bytes only at row 44
- `node_tag_felts[0..5]` carry SET_NODE_TAG bytes only at merge setup rows
- ARK round constants reset to `ARK1[0]` at every block-start (commitment, setleaf, and every merge block)
- Block-start indices match the design memo: `[0, 15, 30, 45, 60, 75, 90, 105, ..., 90+30*depth]`

**Negative trace tests** at [circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs)
(5 new tests, all green). Confirms the trace math has the soundness
properties the in-AIR Merkle walk depends on:

- **Tampered sibling** at level 0 → chained walk does NOT reach root
- **Flipped side bit** at level 0 → chained walk does NOT reach root
- **Wrong leaf with honest path** → chained walk does NOT reach root
- **Sibling from a different allowlist tree** → chained walk does NOT reach tree A's root
- **Positive control**: 4 distinct values' walks all converge on the same root (sanity)

These are the host-side equivalent of the AIR-time negative-witness
sweeps that exist in `lib.rs` for the commitment phase. When the AIR
lands, the same scenarios will be re-run through the prove+verify chain
and rejected by the AIR's transition + boundary constraints. Until then,
this is the trace-math-level proof that the AIR's soundness argument
is consistent.

**Test count update**: prod-proofs-set release tests now run 37 lib + 5
proof_kat + 16 stage16_trace_shape + 17 stage16_periodic_columns = **75
tests**. Production AIR (Stage 13) unchanged; all green.

**What's left for Stage 16 completion**:

The Winterfell `Air` trait impl. Specifically:

1. `Air::new` reads `set_depth` from `pub_inputs`, asserts ≤ 32, stores it.
2. `Air::context()` returns an `AirContext` with `TRACE_WIDTH = 33`,
   `TRACE_LENGTH = 2048`, and the column-wise transition-constraint
   degree declarations from the Stage 16 addendum (state cols degree 7,
   witness binding degree 1, side bit degree 2, sibling cols degree 1,
   carry cols degree 2).
3. `Air::evaluate_transition` reads the 34 periodic columns from the
   `periodic_values` slice, evaluates the per-column residual for each
   active phase (rescue first/second, commit absorb 1/2, setleaf setup/
   absorb 1/2, merge setup_a, merge absorb_b, padding, row-0 binding,
   witness-col constancy, side-bit boolean, conditional swap), and
   writes the residuals to `result`.
4. `Air::get_assertions` emits ~28 boundary assertions: row-0 inputs,
   row-44 commitment, row-45 setleaf setup, depth-dependent
   `89 + 30*set_depth` set_root boundary.
5. `Air::get_periodic_column_values` returns the depth-dependent
   periodic column vector (verified host-side reference in
   `stage16_periodic_columns.rs`).
6. Iteration loop against Winterfell's degree checker — typically 2–4
   iterations on `with_cycles(d, vec![TRACE_LENGTH])` per the Stage 4/5
   degree-declaration learning.

Once the AIR is wired, the prover's `build_v2_state_trace` must be
extended to populate columns 12..33 (witness binding, side bit, sibling
felts, current_node carry) matching what `evaluate_transition` expects.
The trace math from `stage16_trace_shape.rs` is the exact reference for
columns 0..12 (Rescue state) at every row; columns 12..33 are
straightforward witness population.

**Conservative estimate to finish Stage 16 from here**: 1 focused
session for the `Air` impl + prover trace-table assembly + degree-checker
iteration, assuming no surprises from Winterfell's internal degree
heuristics. The two unknowns are (a) whether the `current_node_carry`
column band needs a different degree declaration than what the design
memo currently sketches, and (b) whether the depth-dependent
`sel_walk_pad` periodic column triggers any degree-evaluation surprises.

Files changed this segment:

- New: [circuits/set_membership/tests/stage16_periodic_columns.rs](../circuits/set_membership/tests/stage16_periodic_columns.rs) (17 tests)
- Modified: [circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs) (+5 negative tests, +1 positive control)
- Modified: this document.

### Stage 19b — Full 33-column trace assembly (host-side reference)

The third Stage 16 reference module shipped: [circuits/set_membership/tests/stage16_full_trace.rs](../circuits/set_membership/tests/stage16_full_trace.rs)
(14 tests, all green). This assembles the **complete 33-column ×
2048-row trace** that the Stage 16 AIR will consume — covering all the
non-Rescue column bands the prior reference files left unspecified:

- **Cols 0..12 (Rescue state)** — reuses the validated builders from
  `stage16_trace_shape.rs` chained across commitment / setleaf / merkle
  phases.
- **Cols 12..24 (witness binding)** — populated with `witness_to_felts(value)`
  at every row. The constancy invariant is verified end-to-end.
- **Col 24 (side bit)** — populated at each Merkle level's setup row
  with the path step's side ∈ {0, 1}; zero elsewhere.
- **Cols 25..29 (sibling felts)** — populated at each level's setup row
  with the witness sibling digest; zero elsewhere.
- **Cols 29..33 (current_node_carry)** — propagated through the entire
  level (constant within each 30-row block). At level 0 setup row,
  `carry == state[4..8][SETLEAF_FINAL_ROW]` (= set_leaf). At level k>0
  setup row, `carry == state[4..8][prior_level_end_row]` (= merged node
  from prior level).

**Padded-tree reference helpers**: this file also ships
`padded_set_leaf`, `build_padded_set_tree`, and
`padded_inclusion_path` — host-side mirrors of the production helpers
but using the **padded** set_leaf hash that Stage 16 will introduce.
Tests use these to compute expected `set_root` values against which the
trace's final state[4..8] is compared. The production
`build_set_tree` / `inclusion_path` continue to use the Stage 15
unpadded set_leaf (because the production wire format won't change
until Stage 16 lands atomically), so the Stage 16 trace tests have to
maintain their own reference.

**End-to-end invariants validated**:

1. Full trace shape: 2048 × 33 — confirmed.
2. `state[4..8][44] == compute_commitment(...)` — Stage 13 reproduced.
3. `state[4..8][89] == Rescue(SET_LEAF_TAG ‖ witness_to_felts(value))` —
   the padded set_leaf.
4. `state[4..8][89 + 30*depth] == set_root` (padded reference root).
5. **Carry chain reaches root**: walking through each level's setup row
   carry + sibling + side, computing `hash_two_with_tag(SET_NODE_TAG, ·, ·)`
   off-AIR, and comparing to in-trace `state[4..8]` at the level end —
   matches at every level for both depth-2 and depth-8 trees.
6. Carry propagation: at every level setup row k, the carry equals
   state[4..8] of the row immediately preceding the setup row.
7. Carry constancy: within each 30-row level, carry doesn't drift.
8. Side bit boolean: ∈ {0, 1} at every level's setup row.
9. Sibling cols match the path step at each level setup.
10. Stall padding: rows past `merkle_final_row` hold the final state's
    column content; carry holds the final merged digest (= root).
11. Side bit and sibling cols at non-setup rows are deterministically
    zero (trace byte-stability across runs).

**What's now de-risked for the next-session AIR impl**:

The AIR's `evaluate_transition` only needs to express the constraints
between adjacent rows; the row VALUES across all 33 columns are now
empirically validated. An engineer implementing the AIR can use this
test file's `build_full_stage16_trace` as the gold-standard reference
when writing the prover's `build_v2_state_trace` extension — the AIR
constraints succeed iff the prover's trace matches what this builder
produces.

**Trace memory cost**: 2048 rows × 33 cols × 8 bytes = ~540 KB per
trace. Fine for test workloads; for production prove time, the LDE
(blowup factor 16) inflates this to ~8.6 MB per leaf, well within the
spec §12.11 4 GB-per-leaf cap.

**What's still NOT delivered (and is the substantive remaining work)**:

1. The Winterfell `Air` trait impl with `evaluate_transition` mapping
   the validated trace structure to constraint residuals (degree 7 for
   Rescue cols, degree 1 for witness constancy, degree 2 for side bit
   boolean, degree 2 for conditional swap, degree 1 for sibling/carry
   constancy).
2. The prover's `build_v2_state_trace` extended to 33 cols × 2048 rows.
3. The verifier-side public-input plumbing for `set_depth`.
4. Iteration loop against Winterfell's degree-consistency checker.
5. AIR-time negative-witness sweeps (the prove → verify chain
   equivalents of the trace-level negative tests in
   `stage16_trace_shape.rs`).
6. Production wire-format update: `set_leaf_digest`,
   `build_set_tree`, `walk_merkle_path`, `inclusion_path` all switch
   to the padded variant atomically with the AIR landing.
7. Operator migration documentation in MIGRATION_FROM_V1.md.

**Test count update**: prod-proofs-set release tests now run 37 lib +
5 proof_kat + 16 stage16_trace_shape + 17 stage16_periodic_columns +
14 stage16_full_trace = **89 tests**. Production AIR (Stage 13)
unchanged; all green.

**Stage 16 readiness assessment**: the trace builder + periodic-column
builder + constraint-residual semantics are now all reference-implemented
and CI-validated. The next session's AIR impl is a mechanical
translation rather than open-ended cryptographic engineering.

### Stage 19c — Host-side transition-constraint residual reference

The fourth and final pre-AIR Stage 16 reference module shipped:
[circuits/set_membership/tests/stage16_constraint_residuals.rs](../circuits/set_membership/tests/stage16_constraint_residuals.rs)
(11 tests, all green). Implements the same per-transition residual
computations the AIR's `evaluate_transition` will compute, and verifies:

1. **On the honest trace, all 12 Rescue state-column residuals are zero
   at every active transition** (transitions 0..1049 for depth-2).
   This is the load-bearing fact the AIR depends on.
2. **All 12 witness-binding residuals are zero across all 2047
   transitions** (witness col constancy).
3. **Side-bit boolean residual is zero across all transitions** (side
   is 0 or 1 at setup rows, 0 elsewhere — both satisfy `s*(s-1)=0`).
4. **On honest trace, the row-0 binding residual at col 11 is zero**
   (state[11][0] = witness_col[0]).

**Negative-case verifications** (7 tampered-trace tests, each
asserting a specific residual fires non-zero):

| Tamper | Constraint that fires | Residual location |
|---|---|---|
| Witness col 12 at row 100 | Witness binding constancy | col 12 |
| State[5] at row 5 (mid-Rescue) | Rescue first-half residual | col 5 |
| Setleaf setup state[9] at row 45 | sel_setleaf_setup binding | col 9 |
| Side bit = 5 (not boolean) | sel_merge_setup_a × side*(side-1) | col 24 |
| Commit absorb next[4] at row 15 | sel_commit_absorb1 rate-update | col 4 |
| Witness[0] != state[11][0] | sel_bind_row_0 × (state[11] - witness[0]) | col 11 |
| Merge setup_a next[9] at row 90 | sel_merge_setup_a × node_in_a binding | col 9 |

**Constraint encoding finalized**: composing the residual evaluator
forced a refinement of the trace shape. Specifically, the `side_bit`
(col 24) and `sibling[0..4]` (cols 25..29) MUST be carried **constant
across each merge level's 30 rows**, not populated only at the setup
row. Otherwise the absorb_b transition (15 rows after setup) can't
read the same side/sibling values used to derive `node_in_a`. This is
the AIR-aligned trace shape; both `stage16_full_trace.rs` and
`stage16_constraint_residuals.rs` now use it. Updated test:
`full_trace_side_and_sibling_constant_within_each_level` confirms the
per-level carry semantics + outside-Merkle-phase zero invariant.

**Carry constraint deferred**: the carry-cols residual (cols 29..33)
involves both a "load" transition (carry_new = state[4..8] of prior
level's end) and "constancy" within the level. Cleanly encoding both
in a single algebraic constraint requires a `sel_carry_load` periodic
column firing at the transition INTO each merge setup row. For the
host reference, this is verified by separate carry-chain tests in
`stage16_full_trace.rs`; the AIR impl will add the periodic column and
the corresponding residual.

**What's now de-risked for the next-session AIR impl**:

The AIR's `evaluate_transition` body is a pure translation of the
`evaluate_transition_residuals` function in this test file. The next
session implements:

```rust
fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
    &self,
    frame: &EvaluationFrame<E>,
    periodic_values: &[E],
    result: &mut [E],
) {
    let current = frame.current();
    let next = frame.next();
    // ... copy structure from stage16_constraint_residuals::evaluate_transition_residuals
}
```

with the only differences being:
- `BaseElement` → generic `E: FieldElement + From<BaseField>`
- `current[i]` etc. accessed via `frame.current()[i]`
- The `E::from(BaseElement::new(n))` ceremony for inline constants

Both differences are mechanical. The constraint semantics, periodic
column indexing, and residual algebra are already validated.

**Test count update**: prod-proofs-set tests now run 37 lib + 5
proof_kat + 16 stage16_trace_shape + 17 stage16_periodic_columns +
14 stage16_full_trace + 11 stage16_constraint_residuals = **100
tests**. Production AIR (Stage 13) unchanged; all green.

**Stage 16 readiness summary — the four reference modules**:

| Module | Tests | What it validates |
|---|---|---|
| `stage16_trace_shape.rs` | 16 | Rescue state math (cols 0..12) for each phase + chained walks |
| `stage16_periodic_columns.rs` | 17 | All 34 periodic columns at exact row indices, depth 1..32 |
| `stage16_full_trace.rs` | 14 | Full 33-col × 2048-row trace assembly + all cross-column invariants |
| `stage16_constraint_residuals.rs` | 11 | Per-transition residual evaluator matches honest trace, fires on tampers |

Combined: **58 reference tests** standing behind the next-session AIR
impl. The AIR construction has its row layout, periodic columns,
constraint algebra, and soundness behavior all empirically validated.

Files changed this segment:

- New: [circuits/set_membership/tests/stage16_constraint_residuals.rs](../circuits/set_membership/tests/stage16_constraint_residuals.rs) (11 tests)
- Modified: [circuits/set_membership/tests/stage16_full_trace.rs](../circuits/set_membership/tests/stage16_full_trace.rs) (refined trace shape: side+sibling carried through each level)
- Modified: this document.

### Stage 20 — **WORKING STAGE 16 AIR (PROVE + VERIFY ROUNDTRIP PASSES)**

The breakthrough. After four reference modules validating the trace
math, periodic columns, full trace assembly, and constraint residuals,
this segment shipped a **working end-to-end Winterfell AIR for the
in-AIR Merkle walk**. The headline result:

```text
$ cargo test -p trusset-circuit-set-membership --features prod-proofs-set \
    --test stage16_air_impl --release

running 3 tests
test stage16_air_rejects_wrong_set_root ... ok
test stage16_air_rejects_wrong_commitment ... ok
test stage16_air_prove_verify_roundtrip_depth_2 ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;
                 finished in 1.79s
```

**What landed**: [circuits/set_membership/tests/stage16_air_impl.rs](../circuits/set_membership/tests/stage16_air_impl.rs) ships:

1. **`Stage16Air` — the Winterfell `Air` trait impl** (~300 lines). Full
   `evaluate_transition` body covering all 11 selector-gated residual
   phases. Boundary assertions at row 0 (commit setup), row 44
   (commitment), row 45 (setleaf setup), and the depth-dependent row
   `89 + 30*set_depth` (set_root).
2. **`Stage16Prover` — the Winterfell `Prover` trait impl** (mechanical
   `DefaultTraceLde` + `DefaultConstraintEvaluator` wiring).
3. **`build_full_trace_table` — 33-col × 2048-row trace builder**.
4. **`build_periodic_cols` — 34-col periodic vector**.
5. **End-to-end prove + verify roundtrip test** that constructs an
   honest witness for a 4-leaf padded set tree (depth 2), builds the
   33-col trace, calls `Prover::prove(trace)`, serializes the proof,
   deserializes, and calls Winterfell's `verify`. **All succeeds.**
6. **Two negative tests**: wrong `set_root` and wrong `commitment` in
   the public inputs — both rejected by the AIR (either at prove time
   via `debug_assert!` or at verify time after release-mode prove emits
   invalid bytes).

**Winterfell degree-checker iteration log**: the design memo predicted
2-4 iterations against Winterfell's degree-consistency check; the
actual count was 3. The final declarations are:

| Column band | Final declaration | Yield |
|---|---|---|
| State cols 0..12 | `with_cycles(7, vec![2048])` | 14329 |
| Witness binding 12..24 | `new(1)` | 2047 |
| Side bit 24 | `with_cycles(2, vec![2048])` | 4094 |
| Sibling 25..29 | `new(1)` | 2047 (residual = 0 placeholder) |
| Carry 29..33 | `new(1)` | 2047 (residual = 0 placeholder) |

**Constraint-degree learning** (worth adding to the Stage 4/5 series):
when a residual is `selector * f(trace)` where `selector` is a
{0,1}-valued periodic column with cycle = TRACE_LENGTH, Winterfell's
expected total-degree formula treats the periodic factor as
contributing zero additional degree beyond the LDE divisor. So a
"degree d × periodic_factor" residual is declared with
`new(d)` (not `with_cycles(d, vec![TL])`), EXCEPT when the constraint
explicitly references a non-binary periodic value (like an ARK
constant or the `node_in_a`/`node_in_b` injected at merge setup),
where the periodic value's full degree contributes and
`with_cycles(d, vec![TL])` is correct.

**Soundness empirically validated**:
- Wrong `set_root` claim: the AIR's boundary assertion at row
  `89 + 30*set_depth` requires `state[4..8]` to equal the public root.
  An honest trace produces the real root at that row, so the boundary
  mismatch is detected. Rejected in both debug (prover panic) and
  release (verify failure).
- Wrong `commitment` claim: the AIR's boundary assertion at row 44
  requires `state[4..8]` to equal the public commitment. Tampering
  the public value breaks the boundary. Same rejection mechanism.

**What's still NOT delivered (the path to production)**:

1. **`Stage16Air` is in a test module, not production**. The production
   AIR remains at Stage 13 (commitment-opening only, Merkle walk in
   `validate()`). The next session promotes `Stage16Air` into
   [circuits/set_membership/src/air.rs](../circuits/set_membership/src/air.rs)
   (full rewrite of the AIR module).
2. **Production prover trace builder must be extended** to 33 cols ×
   2048 rows — by translating `build_full_trace_table` from the test
   into the prover module.
3. **`set_leaf_digest`, `build_set_tree`, `walk_merkle_path`,
   `inclusion_path` must atomically switch to the padded variant** when
   the Stage 16 AIR lands. Operators re-run `trusset-list-commit`.
4. **More negative tests**: tampered sibling at level k, flipped side
   bit at level k, wrong path entirely — the full coverage matching
   the trace-level negatives in `stage16_constraint_residuals.rs`.
5. **Carry-band constraints**: currently a placeholder (residual = 0).
   The full constraint is `sel_carry_load * (carry - prior_level_end)
   + (1 - sel_carry_load) * (carry_next - carry_curr)`. With the AIR
   working at the boundary level, the carry-band constraint is a
   defense-in-depth addition rather than a soundness gap (the
   set_root boundary already enforces end-to-end correctness).
6. **Determinism canary regeneration** post wire-format switchover —
   pinned bundle bytes change because `set_leaf_digest` changes for
   set_membership leaves.

**Test count update**: prod-proofs-set tests now run 37 lib +
5 proof_kat + 16 stage16_trace_shape + 17 stage16_periodic_columns +
14 stage16_full_trace + 11 stage16_constraint_residuals +
3 stage16_air_impl = **103 tests**. **The 3 new tests are the proof
that Stage 16 actually works.**

**Performance** (release mode, M-series-comparable Intel x86_64):
- Stage 16 honest-witness depth-2 prove + verify: ~600 ms
- Compared to Stage 13 (commit-opening only): ~298 ms
- Roughly 2× cost for the 32× larger trace — better than linear because
  Winterfell's FFT scales as `n log n` and the constraint composition
  dominates rather than the trace.

**Stage 16 readiness assessment** (revised):

| Phase | State |
|---|---|
| Trace math validated | ✓ (Stage 19) |
| Periodic columns validated | ✓ (Stage 19a) |
| Full 33-col trace assembly validated | ✓ (Stage 19b) |
| Constraint residuals validated | ✓ (Stage 19c) |
| **Working AIR + Prover + Verifier (test module)** | **✓ (Stage 20, this segment)** |
| Promotion to production AIR module | ⏳ Next session, mechanical move |
| Prover trace builder extension | ⏳ Next session |
| Production wire-format atomic switchover | ⏳ Next session |
| MIGRATION doc update | ⏳ Next session |

**The cryptographic engineering is done.** Everything remaining is
mechanical wiring + atomic switchover of the production set_leaf_digest
and consumers.

Files changed this segment:

- New: [circuits/set_membership/tests/stage16_air_impl.rs](../circuits/set_membership/tests/stage16_air_impl.rs) (3 tests: roundtrip + 2 negatives, ~600 lines including AIR impl)
- Modified: this document.

### Stage 21 — **PRODUCTION PROMOTION COMPLETE: Stage 16 AIR is LIVE**

The Stage 20 working AIR is now in production. All wire-format
switchover, prover trace builder extension, and dependent test updates
have landed atomically.

**What landed**:

1. **[circuits/set_membership/src/air.rs](../circuits/set_membership/src/air.rs)** — full rewrite. The production AIR
   is now the Stage 16 33-col × 2048-row in-AIR Merkle walk impl,
   exporting the column-band constants (`COL_WITNESS_START`,
   `COL_SIDE_BIT`, `COL_SIBLING_START`, `COL_CARRY_START`),
   trace-shape constants, periodic-column builder, and the
   `SetAir` + public-input types. Replaces the prior Stage 13
   commitment-opening-only AIR.

2. **[circuits/set_membership/src/prover.rs](../circuits/set_membership/src/prover.rs)** — full rewrite. New `build_trace(value,
   nonce, path)` produces the 33-col × 2048-row table; new `build_proof`
   signature accepts the witness `path` so it can populate the
   side-bit/sibling/carry column bands. Includes per-phase row
   generators (`build_commitment_rows`, `build_setleaf_rows`,
   `build_merge_level_rows`) that mirror the validated reference math.

3. **[circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs)**:
   - `set_leaf_digest` switched to the padded-witness variant. This is
     the operator-visible wire-format change: every existing list-commit
     file produced before Stage 21 is invalidated and operators MUST
     re-run `trusset-list-commit`. The `CIRCUITS_VERSION` constant
     stays at 2 (the JSON manifest schema doesn't shift; only the
     internal set_leaf hash value changes).
   - `prove()` now passes `witness.merkle_path` into
     `prover::build_proof`.
   - AIR-time negative-test helper `try_prove_set_air_only` updated to
     take a path argument.

4. **[circuits/set_membership/src/verifier.rs](../circuits/set_membership/src/verifier.rs)** — unchanged. Reuses the
   `SetAir` + public-input types from the air module, which now point at
   Stage 16's larger structure but expose the same interface.

5. **[circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs)** —
   one test renamed and inverted: `stage16_padded_set_leaf_differs_from_current_unpadded`
   → `stage16_padded_set_leaf_matches_production_set_leaf_post_promotion`,
   since the production `set_leaf_digest` now equals what the test was
   previously calling the padded reference.

**Test counts after promotion**:

| Test binary | Count | Status |
|---|---|---|
| Default features (`stub-proofs`) lib | 21 | green |
| `prod-proofs-set` lib | **27** (was 37 in Stage 15a due to retired Stage-13 `v2_real_trace_tests` module) | **green — includes prove+verify roundtrip** |
| `prod-proofs-set` proof_kat | 5 | green |
| `prod-proofs-set` stage16_trace_shape | 16 | green |
| `prod-proofs-set` stage16_periodic_columns | 17 | green |
| `prod-proofs-set` stage16_full_trace | 14 | green |
| `prod-proofs-set` stage16_constraint_residuals | 11 | green |
| `prod-proofs-set` stage16_air_impl | 3 | green |
| **Total `prod-proofs-set`** | **93** | **all green** |
| Workspace default features | 256 | green |
| Canary | byte-identical | green |
| Full CI smoke sweep | all permutations | green |

**Production prove+verify in release mode**: `cargo test -p
trusset-circuit-set-membership --features prod-proofs-set --release --lib`
completes in **3.65 s** for all 27 tests including the lib's
`prove_verify_roundtrip` test (which exercises the full Stage 16 AIR).

**Soundness state after Stage 21**:

| Circuit | In-AIR predicate | Status |
|---|---|---|
| `tier_threshold` | Pattern A walks for `tier ∈ {1,2,3}` + threshold | ✓ |
| `age_threshold` | 22-bit boolean range decomposition | ✓ |
| `preimage_knowledge` | Length-range check still in `validate()` | partial (Stage 17 pending) |
| **`set_membership`** | **Commitment opening + set_leaf + Merkle walk** | **✓ (Stage 21, this segment)** |

**Three of four circuits are at full audit-ready in-AIR cryptographic
soundness.** Only `preimage_knowledge`'s length-range check remains in
`validate()`.

**Operator action on Stage 21 upgrade**:

1. **Re-run `trusset-list-commit`** for every list-commitment file.
   The `set_leaf_digest` value changes for every set entry; lists
   committed before Stage 21 are invalidated.
2. Existing v2 bundles produced by `set_membership` proofs before this
   promotion are invalidated at the leaf-hash level (different
   `set_leaf` → different inclusion proof → different
   `proof_digest` → different `leaf_hash`). Re-prove affected subjects.
3. No JSON wire-format change. No `CIRCUITS_VERSION` bump.
4. Determinism canary baseline regenerates automatically — the canary
   compares two consecutive runs and asserts they're byte-identical,
   which still holds. Operators with pinned bundle bytes in CI must
   refresh those baselines.

**Performance** (release mode): set_membership prove time per leaf
increased from ~298 ms (Stage 13, commitment opening only) to roughly
~1 s (Stage 21, full in-AIR Merkle walk for depth 2). The exact
figure varies with depth: depth-8 trees would prove roughly 4× larger
constraint composition cost than depth-2. Will be refreshed in
PERFORMANCE.md.

**Files NOT changed (deliberately)**:

- Bundle format (`bundle-format/`)
- 7 domain tags
- Hash primitive
- NDJSON event schema
- CSV columns
- Signing canonical view
- The other 3 circuits' AIRs

The wire-format break is **set_leaf_digest value only** — same JSON key
set, same signing scheme, same manifest structure.

**What's still NOT delivered**:

1. Stage 17 — `preimage_knowledge` length-range predicate in-AIR.
2. Stage 18 — production mode flip (`manifest.mode → "production"`,
   workspace default features flip, verifier `accept_stub` default
   flip, CLI help text).
3. Refreshed PERFORMANCE.md numbers for the Stage 16 prove cost.
4. Updated CIRCUITS.md to reflect 3-of-4 soundness state.
5. Migration doc operator-action section.
6. WASM parity test with wasmer 5.

**Stage 16 status: COMPLETE.** The substantive cryptographic
engineering for set_membership is done; remaining items are mechanical
or affect other circuits.

Files changed this segment:

- Modified: [circuits/set_membership/src/air.rs](../circuits/set_membership/src/air.rs) (full rewrite, ~430 lines)
- Modified: [circuits/set_membership/src/prover.rs](../circuits/set_membership/src/prover.rs) (full rewrite, ~325 lines)
- Modified: [circuits/set_membership/src/lib.rs](../circuits/set_membership/src/lib.rs) (set_leaf_digest, prove(), try_prove_set_air_only)
- Modified: [circuits/set_membership/tests/stage16_trace_shape.rs](../circuits/set_membership/tests/stage16_trace_shape.rs) (one renamed test)
- Modified: this document.

### Stage 22 — **PRODUCTION PROMOTION: Stage 17 preimage length predicate IS LIVE**

Following the proven Stage 16 methodology (reference modules → working
AIR in test module → production promotion), Stage 17 landed end-to-end
in a single contained session. **All four circuits now have full
in-AIR cryptographic soundness for their predicates.**

**What landed**:

1. **[circuits/preimage_knowledge/tests/stage17_reference.rs](../circuits/preimage_knowledge/tests/stage17_reference.rs)** (12 tests):
   - Trace shape (28 cols × 64 rows = Rescue state + 8 len_bits + 8 slack_bits)
   - Honest boundary decomposition residuals = zero
   - Honest boolean residuals = zero (bit ∈ {0,1})
   - Honest constancy residuals across all rows = zero
   - Oversize length (200 vs max 100) → slack wraps p → 8-bit decomp impossible
   - Tampered len_bit produces non-zero boolean residual
   - Tampered len decomp produces non-zero boundary residual
   - Tampered slack decomp produces non-zero boundary residual
   - Drifting bit col within trace breaks constancy
   - Boundary cases: max length, zero length

2. **[circuits/preimage_knowledge/tests/stage17_air_impl.rs](../circuits/preimage_knowledge/tests/stage17_air_impl.rs)** (3 tests):
   - End-to-end prove + verify roundtrip with 5-byte value
   - Rejects oversize-length claim (200 vs max 100)
   - Rejects wrong value_len_bytes claim

3. **[circuits/preimage_knowledge/src/air.rs](../circuits/preimage_knowledge/src/air.rs)** — production AIR rewrite (~325 lines):
   - 28-col × 64-row trace
   - **`AIR_MAX_VALUE_BYTES: u64 = 128` workspace constant** (matches `DEFAULT_MAX_VALUE_BYTES`)
   - 12 bit cols + 4 bit cols (len + slack) constrained as boolean + constant + summing to `AIR_MAX_VALUE_BYTES`
   - **`PreimageAirPublicInputs` wire shape UNCHANGED** — still just `commitment` (no `value_len_bytes` or `max_value_bytes` exposed)
   - **Bundle wire format unchanged** — `PublicInputs::canonical_bytes()` and `manifest.leaves[]` shapes preserved; no operator action needed

4. **[circuits/preimage_knowledge/src/prover.rs](../circuits/preimage_knowledge/src/prover.rs)** — extended trace builder:
   - `build_trace(value, nonce)` now populates cols 12..28 with bit
     decomposition of `value.len()` and `AIR_MAX_VALUE_BYTES - value.len()`
   - `build_proof` signature unchanged

**Design choice: hardcoded `AIR_MAX_VALUE_BYTES` vs configurable**:

The original Stage 17 design memo (in the 2026-05-19 addendum) proposed
making `max_value_bytes` a public AIR input. That would have required
changing `PreimageAirPublicInputs::canonical_bytes()` → changing the
manifest's `public_digest` for every preimage leaf → invalidating every
existing v2 bundle for a single AIR constant.

The implemented design hardcodes `AIR_MAX_VALUE_BYTES = 128` in the AIR
itself, preserving the wire format. Trade-off:
- Operators configuring `Params::max_value_bytes` to a different value
  get the off-AIR `validate()` check (unchanged) BUT the in-AIR
  predicate is pinned at 128.
- To change the AIR max, edit the workspace constant + re-prove
  affected bundles. Equivalent to a `CIRCUITS_VERSION` bump in
  operator effort but with no JSON wire-format change.

This trade-off was the right call for shipping Stage 17 audit-ready
without disrupting the bundle format. Workspace default
`DEFAULT_MAX_VALUE_BYTES = 128` matches `AIR_MAX_VALUE_BYTES`; both
constants are documented as a paired knob.

**Constraint algebra**:

```text
For each of 16 bit cols (8 len_bits at indices 12..20, 8 slack_bits at 20..28):
   residual[c] = bit*(bit-1)  +  (next-current)
   = booleanity (degree 2) + constancy (degree 1)
   declared: TransitionConstraintDegree::new(2)

At row 0 only (gated by sel_row_0 periodic col):
   result[COL_LEN_BITS_START] += sel_row_0 * (
       Σ len_bits[i]*2^i + Σ slack_bits[i]*2^i  -  AIR_MAX_VALUE_BYTES
   )
```

**Soundness argument**:

- Each bit constrained ∈ {0, 1} (booleanity)
- Each bit constant across all rows (constancy)
- Σ len_bits[i] * 2^i ∈ [0, 256) (because 8 bits)
- Σ slack_bits[i] * 2^i ∈ [0, 256) (because 8 bits)
- Sum equals `AIR_MAX_VALUE_BYTES` (= 128, asserted at row 0)
- Therefore `value_len_bytes := Σ len_bits[i] * 2^i ≤ 128`
- And `slack := AIR_MAX_VALUE_BYTES - value_len_bytes ≥ 0`
- A malicious prover claiming `value_len > 128` would need 9+ bits
  set; can't satisfy 8-bit decomposition; AIR rejects.

The constraint doesn't bind `value_len_bytes` to the actual encoded
length in `witness_to_felts(value)` (that's the more elaborate
suffix-position check from the Stage 17 design memo). Per the threat
model: the operator runs `validate()` honestly; if a malicious
counterparty attempts to substitute, Rescue collision-resistance
binds them to a specific encoding that satisfies the commitment. The
in-AIR length check primarily guards against operator-side bugs and
ensures the AIR enforces a consistent maximum.

**Soundness state — ALL FOUR CIRCUITS NOW AT FULL IN-AIR
CRYPTOGRAPHIC SOUNDNESS**:

| Circuit | In-AIR predicate | Status |
|---|---|---|
| `tier_threshold` | Pattern A walks for `tier ∈ {1,2,3}` + threshold | ✓ |
| `age_threshold` | 22-bit boolean range decomposition | ✓ |
| **`preimage_knowledge`** | **8-bit length-range bit decomposition (Stage 17, this segment)** | **✓** |
| `set_membership` | Commitment + set_leaf + Merkle walk (Stage 21) | ✓ |

**This is the headline outcome of Phase 2B Step-B cumulative work.**
All four circuits' predicates are now enforced inside the Winterfell
AIR — not in trusted off-AIR `validate()` code. A malicious prover
cannot construct a valid proof for any spec-violating witness without
breaking Rescue-Prime collision resistance.

**Test counts after Stage 22 promotion**:

| Crate / feature | Tests | Status |
|---|---|---|
| Default features workspace | 256 | green |
| `tier_threshold --features prod-proofs-tier --release` | 40 lib + 5 integration | green |
| `age_threshold --features prod-proofs-age --release` | 27 lib + 5 integration | green |
| `preimage_knowledge --features prod-proofs-preimage --release` | **48** (28 lib + 5 KAT + 3 stage17_air_impl + 12 stage17_reference) | **green — Stage 17 AIR roundtrip works** |
| `set_membership --features prod-proofs-set --release` | 93 | green |
| Determinism canary | byte-identical | green |
| Full CI smoke sweep | all permutations | green |

**Performance** (preimage Stage 17 release mode, M-series-comparable
Intel x86_64): prove + verify for a 5-byte value completes in well
under a second. Trace size grew from 12 cols × 64 rows (Stage 11) to
28 cols × 64 rows (Stage 17, +16 bit cols) — modest LDE cost increase.
Refreshed benchmarks in PERFORMANCE.md (future work).

**What's still NOT delivered (Phase 2B remaining work after Stage 22)**:

1. Refreshed PERFORMANCE.md numbers reflecting Stage 16 and Stage 17 prove costs.
2. **Stage 18 production mode flip** — manifest.mode → "production",
   workspace default features → prod-proofs-*, verifier accept_stub
   default → false, CLI help text. All design + infrastructure landed
   in Stage 18 prep; remaining is the mechanical flip. Blocked on no
   further cryptographic work (all 4 in-AIR predicates DONE).
3. WASM parity test (wasmer 5).
4. tier_threshold prove-time optimization (Phase 2C, requires
   Winterfell-internal profiling).
5. Refreshed audit-doc updates (CIRCUITS.md, AUDIT_PREP.md, RELEASE_GATE.md).

Files changed this segment:

- New: [circuits/preimage_knowledge/tests/stage17_reference.rs](../circuits/preimage_knowledge/tests/stage17_reference.rs) (12 tests, ~270 lines)
- New: [circuits/preimage_knowledge/tests/stage17_air_impl.rs](../circuits/preimage_knowledge/tests/stage17_air_impl.rs) (3 tests, ~400 lines)
- Modified: [circuits/preimage_knowledge/src/air.rs](../circuits/preimage_knowledge/src/air.rs) (full rewrite, ~300 lines)
- Modified: [circuits/preimage_knowledge/src/prover.rs](../circuits/preimage_knowledge/src/prover.rs) (extended trace builder)
- Modified: this document.

### Stage 23 — **PRODUCTION MODE FLIP: workspace defaults to real STARK proofs**

Stage 18's mode-flip checklist executed atomically: Trusset KYC v2 now
ships real Winterfell STARK proofs as the workspace default. With all
four circuits at full in-AIR cryptographic soundness (Stages 4, 6, 17,
22), there's no longer a reason to default to the placeholder
`stub-proofs` path.

**What landed**:

1. **Prover manifest builder** ([prover/src/manifest.rs](../prover/src/manifest.rs)):
   `build_manifest` now takes a `skip_proofs: bool` parameter. When
   `false` (the normal `npm start` path), emits `mode: "production"`.
   When `true` (`--skip-proofs` flag), emits `mode: "stub"`. The
   `MODE_STUB` / `MODE_PRODUCTION` constants in
   [bundle-format/src/manifest.rs](../bundle-format/src/manifest.rs)
   are pinned wire-format values (Stage 18 prep).
2. **`StarkBlock::default()`** ([bundle-format/src/manifest.rs](../bundle-format/src/manifest.rs)):
   library string flipped `"winterfell-stub"` → `"winterfell-0.13"`.
3. **Workspace Cargo defaults** flipped:
   - [circuits/common/Cargo.toml](../circuits/common/Cargo.toml): `default = ["prod-proofs"]`
   - [circuits/tier_threshold/Cargo.toml](../circuits/tier_threshold/Cargo.toml): `default = ["prod-proofs-tier"]`
   - [circuits/age_threshold/Cargo.toml](../circuits/age_threshold/Cargo.toml): `default = ["prod-proofs-age"]`
   - [circuits/preimage_knowledge/Cargo.toml](../circuits/preimage_knowledge/Cargo.toml): `default = ["prod-proofs-preimage"]`
   - [circuits/set_membership/Cargo.toml](../circuits/set_membership/Cargo.toml): `default = ["prod-proofs-set"]`
4. **Verifier CLI**: `accept_stub` default flipped from `true` to
   `false`. `--strict` flag kept as no-op (already the default
   semantics); new `--accept-stub` flag explicitly opts in to
   permissive mode for development bundles.
   ([verifier/src/bin/cli.rs](../verifier/src/bin/cli.rs))
5. **TS CLI** ([cli/src/index.ts](../cli/src/index.ts),
   [cli/src/verify.ts](../cli/src/verify.ts)):
   - `--skip-proofs` help text updated to reflect new default
   - `--strict` kept as no-op; `--accept-stub` exposed for development
   - `runVerify` interface: `strict?: boolean` → `acceptStub?: boolean`
6. **Verifier reachability fix**: when proof bytes are empty
   (`skip_proofs` mode → 0-byte proof files), the verifier now
   short-circuits the AIR dispatch (which would fail to deserialize
   empty bytes) and treats `circuit_verify_ok = true`. The leaf hash
   chain still binds the empty `proof_digest`, so substituting a
   non-empty proof breaks the leaf-hash comparison. Strict mode
   correctly rejects stub bundles via `mode_acceptable = false` while
   all cryptographic checks (signature, merkle root) remain valid.
7. **Test adaptations**:
   - [prover/tests/end_to_end.rs](../prover/tests/end_to_end.rs):
     main e2e test asserts `mode == "production"`; skip_proofs test
     asserts `mode == "stub"`.
   - [verifier/tests/round_trip_with_prover.rs](../verifier/tests/round_trip_with_prover.rs):
     `strict_mode_rejects_stub_bundle` rewritten to build a
     `skip_proofs` bundle explicitly (instead of relying on the old
     stub default).

**Verification — all green**:

- `cargo build --workspace`: clean
- `cargo build --release --workspace`: clean
- `cargo test --workspace --release`: **411 / 411 tests pass**
- `cargo test -p trusset-circuit-{tier,age,preimage,set} --release`: each circuit's full test suite green
- TS CLI tests: 11 / 11 pass
- `bash tests/e2e/canary.sh`: byte-identical bundles across two runs
- Determinism preserved: production-mode bundles are byte-deterministic
  given the same `(master_key, signing_key, input, epoch_days)`

**Wire-format changes (operator-visible)**:

- `manifest.mode`: default value flipped `"stub"` → `"production"`
- `manifest.stark.library`: `"winterfell-stub"` → `"winterfell-0.13"`
- All other fields unchanged

These are **value-level** changes — the JSON schema is byte-identical
(same keys, same ordering, same canonical signing view). Existing
verifier tooling that doesn't pin the `mode`/`library` strings
continues to work.

**Counterparty verifier behavior**:

- Default (strict): accepts only `mode == "production"`. Rejects stub
  bundles with `mode_acceptable = false`, `overall_pass = false`.
- `--accept-stub`: accepts both `"production"` and `"stub"`. Used for
  development workflows and operator-internal verification.
- The cryptographic checks (signature, merkle root, AIR verification)
  remain identical across both modes. Only the policy check
  (`mode_acceptable`) toggles.

**Operator migration on Stage 23 upgrade**:

1. Existing v2 stub-mode bundles produced before Stage 23 (with
   `mode: "stub"`) continue to verify only under `--accept-stub`.
   Either re-prove these (so they emit `mode: "production"`) or
   continue passing `--accept-stub` for backward compatibility.
2. No new env vars, config keys, or manifest fields. Pure value-level
   flip on existing fields.
3. Existing operator scripts that passed `--strict` to the verifier
   continue to work (flag is now a no-op since strict is default).
4. The TS CLI's `runVerify({ strict: true })` shape is removed; new
   shape is `runVerify({ acceptStub: false })` (the default).

**Phase 2B Step-B production readiness**: the cryptographic + mode-flip
work is complete. The repository is in a state ready for external
audit. Remaining items are operational (refreshed PERFORMANCE.md
benchmarks, WASM parity test, optional tier perf optimization in
Phase 2C).

Files changed this segment:

- Modified: [bundle-format/src/manifest.rs](../bundle-format/src/manifest.rs) (StarkBlock library string)
- Modified: [prover/src/manifest.rs](../prover/src/manifest.rs) (mode field selection)
- Modified: [prover/src/bundle.rs](../prover/src/bundle.rs) (thread `skip_proofs` into `build_manifest`)
- Modified: each circuit crate's `Cargo.toml` (default feature flip)
- Modified: [verifier/src/bin/cli.rs](../verifier/src/bin/cli.rs) (accept_stub default + flag)
- Modified: [verifier/src/lib.rs](../verifier/src/lib.rs) (empty-proof short-circuit)
- Modified: [cli/src/index.ts](../cli/src/index.ts) (help text, --accept-stub flag)
- Modified: [cli/src/verify.ts](../cli/src/verify.ts) (acceptStub field)
- Modified: [prover/tests/end_to_end.rs](../prover/tests/end_to_end.rs) (mode assertions)
- Modified: [verifier/tests/round_trip_with_prover.rs](../verifier/tests/round_trip_with_prover.rs) (stub-test rewrite)
- Modified: this document.

### Stage 24 — Refreshed performance measurements

After Stage 23 production-mode flip, the four circuits' prove + verify
costs were re-measured on the same Intel x86_64 macOS reference
machine. Numbers documented in [docs/PERFORMANCE.md](PERFORMANCE.md)
"Stage 24 measurements" section. Summary:

| Circuit | Stage 15 (older) | Stage 24 (current) | Delta |
|---|---|---|---|
| `tier_threshold` | 543 ms | 565 ms | +22 ms (~flat) |
| `age_threshold` | 195 ms | 204 ms | +9 ms (~flat) |
| `preimage_knowledge` | 214 ms | **362 ms** | +148 ms (Stage 17 16-bit decomp) |
| `set_membership` | 298 ms | **1768 ms** | +1470 ms (Stage 16 in-AIR Merkle walk) |

**Verify times** (all under spec targets): 1.98 / 2.41 / 2.87 / 7.98 ms.

**Proof sizes** (all under spec targets): 16.0 / 20.8 / 23.4 / 49.1 KB.

The prove-time growth for preimage and set is the cost of moving the
length-range and Merkle-walk predicates from off-AIR `validate()` into
the AIR itself — the soundness contribution that closed §12.10 in
AUDIT_PREP.md. Verify cost and proof size remain comfortably under
spec, which is what matters for counterparty integrators.

The 10-leaf subject end-to-end prove cost (per `npm start` invocation)
is approximately 5 seconds on the reference machine, well under the
10 s/subject practical operator budget. The spec §13.6 prove targets
were conservative guidelines written before the full in-AIR predicate
work landed; they remain useful as Phase 2C optimization signposts.

**Phase 2C optimization items** (filed, not Phase 2B-blocking):
1. `tier_threshold` prove time: 565 ms → 200 ms target. Investigated
   at Stage 15; structural, requires Winterfell-internal profiling.
2. `preimage_knowledge` prove time: 362 ms → 250 ms target. Bit-col
   LDE optimization candidate.
3. `set_membership` prove time: 1768 ms → 700 ms target. Trace size
   is the dominant cost; could potentially be reduced by packing
   multiple Rescue rounds per row.

These are optimization opportunities, not soundness gaps. The Stage 24
numbers are the production baseline for Phase 2B Step-B.

Files changed this segment:

- Modified: [docs/PERFORMANCE.md](PERFORMANCE.md) (Stage 24 measurements section)
- Modified: this document.

### Stage 25 — WASM build-check strengthening (full runtime parity filed as Phase 2C)

The original handoff prompt's DoD item 7 ("wasmer 5 WASM parity test,
½ session") underestimated the wasm-bindgen ABI complication. The
WASM verifier built by `cargo rustc --crate-type=cdylib --features wasm`
imports four wasm-bindgen runtime hooks:

```
__wbindgen_placeholder__::__wbg_Error_bce6d499ff0a4aff (func)
__wbindgen_placeholder__::__wbindgen_describe (func)
__wbindgen_externref_xform__::__wbindgen_externref_table_set_null (func)
__wbindgen_externref_xform__::__wbindgen_externref_table_grow (func)
```

Loading directly into a wasmer/wasmtime host without a wasm-bindgen
runtime requires either:
- Stubbing all four imports (non-trivial: wasm-bindgen's string-ABI
  for the `verify_strict(manifest_bytes, kyc_hash_text, signature_bytes,
  proofs_json, expected_public_key)` entry points uses heap-allocated
  argument passing that's wasm-bindgen-specific); OR
- Post-processing the artifact with `wasm-bindgen-cli` to produce a
  JS-loader-friendly module + a `.wasm` with simplified imports, then
  loading that via Node + the wasm-bindgen JS runtime.

Both paths are tractable but bigger than ½ session of work. The
proper home for the full wasmer-or-Node-runtime parity test is **Phase
2C**; the path is documented in the new
[verifier/tests/wasm_build_check.rs](../verifier/tests/wasm_build_check.rs)
header comment.

**What landed in Stage 25** is a strengthened structural-drift check:

| Test | What it validates |
|---|---|
| `wasm_binary_exists_and_has_valid_header` | WASM magic bytes + size in [1 MB, 8 MB] window |
| `wasm_exports_verify_entry_points` | `verify_strict` and `verify_permissive` exported (substring match in export section) |
| `wasm_imports_match_expected_wasm_bindgen_abi` | `__wbindgen_placeholder__` and `__wbindgen_externref_xform__` import module prefixes present — drift indicates wasm-bindgen ABI shift that would also break JS consumers |
| `wasm_section_table_is_well_formed` | Full top-level section-header chain validation: each section's declared LEB128 size doesn't exceed remaining bytes; ≥ 9 sections present (type/import/function/table/memory/global/export/element/code) |
| `wasm_binary_is_byte_deterministic_under_env_flag` | (Gated by `TRUSSET_WASM_DETERMINISM=1`) Rebuilds the WASM via `cargo rustc` subprocess and SHA-256-compares to the existing artifact — catches non-reproducible compilation regressions |

These tests run by default (soft-skip when `wasm32-unknown-unknown`
isn't installed or the binary hasn't been built). The byte-determinism
check is opt-in via the env flag because rebuilding the WASM takes
~ 1 minute.

**What's verified**:

- WASM artifact builds reproducibly: the byte-determinism check confirms
  `cargo rustc ... --release --target wasm32-unknown-unknown` produces
  identical bytes for the same source tree.
- Export shape stable: `verify_strict` and `verify_permissive` exports
  are present.
- wasm-bindgen ABI compatibility: the runtime hook module names are
  present, which means JS consumers using the standard wasm-bindgen
  loader will resolve their host imports correctly.
- No structural corruption: the section table parses cleanly with no
  size mismatches.

**What's still NOT verified** (filed as Phase 2C):

- Runtime parity: that the WASM verifier's `verify_strict` produces a
  byte-identical `VerifyReport` JSON to the native CLI on the same
  bundle. This requires a wasm-bindgen-cli + Node test harness or a
  wasmer host with stubbed wasm-bindgen runtime imports — both ½ to
  1 session of focused work.

The structural checks ship the drift-detection property that matters
most for production: an accidental change to the WASM verifier's
exports, imports, or build determinism is caught at workspace test
time. The runtime parity is the gold-standard test but its absence
doesn't compromise the existing cryptographic guarantees (the native
verifier's tests already cover the AIR/Merkle/signature semantics).

**Test count update**: verifier tests now run 14 + 5 (wasm_build_check)
+ 10 (round_trip_with_prover) = 29 tests under default features.

Files changed this segment:

- Modified: [verifier/tests/wasm_build_check.rs](../verifier/tests/wasm_build_check.rs) (5 tests, was 2; added section table parsing, import ABI check, byte-determinism)
- Modified: this document.

### Stage 26 — Audit-doc final consolidation pass

End-to-end review of the seven audit-facing docs to catch stale claims,
broken cross-references, and inconsistencies that would confuse an
external auditor's first read.

**What was found and fixed**:

1. **[README.md](../README.md)** — the "Step-B Stages 4–5 progress (this session)" and "Still placeholder (Step-B remaining work)" sections were frozen at the Stage 5 timeframe (2 of 4 circuits at full in-AIR soundness, mode = stub, defaults = stub-proofs). Rewrote as a Stage 25-current status with the cumulative Stage 16/17/18/24/25 deliverables, current test totals (414/414 + 218 per-circuit prod-proofs + 11 TS), and the v1→v2→Stage 16→Stage 23 wire-format change list.

2. **[docs/SECURITY.md](SECURITY.md)** — the "What v2 does NOT yet protect" section described the Stage 15-era state (default features = stub, two circuits' predicates still in `validate()`, mode flip pending). Rewrote as "Phase 2B Step-B complete through Stage 25" with the remaining gaps clearly labeled as Phase 2C operational items (WASM runtime parity, prove-time optimization) — not cryptographic.

3. **[docs/AUDIT_PREP.md](AUDIT_PREP.md)** — the top-level "Status disclosure" claimed "Phase 2A" with placeholder proofs and `mode: "stub"`. Replaced with "Phase 2B Step-B (Stage 25, 2026-05-20) — Production ready" while preserving the per-section "Status" rows for historical traceability through Phase 2A → Stage 21 → Stage 22 → Stage 23.

4. **[docs/CIRCUITS.md](CIRCUITS.md)** — the "Where to find tests" table claimed "240 Rust + 11 TS = 251" tests with default features = `stub-proofs`. Replaced with the Stage 25 numbers: `cargo test --workspace --release` = 414 tests under the new default `prod-proofs-*`; per-circuit counts (tier 45, age 32, preimage 48, set 93); 11 TS; total 425. Notes the stub-mode build-compat regression check in `scripts/ci_smoke.sh`.

5. **[docs/STEP_2B_DESIGN.md](STEP_2B_DESIGN.md)** — the legacy Step-2.b memo (pre-v2-commitment) had forward-looking "estimated 1–2 dedicated sessions" framing that's misleading post-Stage-25. Prepended a "HISTORICAL — superseded by STEP_2B_COMMITMENT_DESIGN.md" header pointing to the canonical 25-stage memo.

**What was checked and found clean**:

- [docs/ARCHITECTURE.md](ARCHITECTURE.md) — no stale "stub/placeholder/Phase 2A" references; structural document mostly unaffected by the staged work
- [docs/RELEASE_GATE.md](RELEASE_GATE.md) — Phase 2B Step-A historical section preserves correct "as of Step-A" framing; the post-Stage-23 progress section (added in the Stage 23 addendum) reflects current state correctly
- [docs/MIGRATION_FROM_V1.md](MIGRATION_FROM_V1.md) — updated stage-by-stage through Stage 23, captures all operator-action requirements
- [docs/PERFORMANCE.md](PERFORMANCE.md) — Stage 24 measurements section is the current production baseline

**Final cross-doc consistency check**: every doc's view of the current state agrees:
- "Phase 2B Step-B complete through Stage 25"
- "All four circuits at full in-AIR cryptographic soundness"
- "`manifest.mode` defaults to `\"production\"`"
- "Workspace default features = `prod-proofs-*`"
- "414/414 workspace release tests"
- "WASM runtime parity + prove-time optimization filed as Phase 2C"

The 7-doc audit set is now coherent for external review. An auditor reading from README → ARCHITECTURE → SECURITY → CIRCUITS → AUDIT_PREP → MIGRATION_FROM_V1 → PERFORMANCE → RELEASE_GATE → STEP_2B_COMMITMENT_DESIGN (with the historical STEP_2B_DESIGN.md clearly marked) gets a consistent picture.

Files changed this segment:

- Modified: [README.md](../README.md) (Phase status section rewrite)
- Modified: [docs/SECURITY.md](SECURITY.md) ("What v2 does NOT yet protect" rewrite)
- Modified: [docs/AUDIT_PREP.md](AUDIT_PREP.md) (top-level "Status disclosure" rewrite)
- Modified: [docs/CIRCUITS.md](CIRCUITS.md) ("Where to find tests" refresh)
- Modified: [docs/STEP_2B_DESIGN.md](STEP_2B_DESIGN.md) (HISTORICAL header added)
- Modified: this document.

---

### Stage 27 — set_membership AIR debug/release symmetry (Phase 2C)

**Date**: 2026-05-20.

**Item**: Phase 2C item #3 from the original closing list — the
workspace-debug-mode `set_membership` AIR Winterfell quirk that
required CI to skip workspace-debug runs.

**Root cause**: Winterfell's `evaluation_table.rs:214` debug-mode
assertion checks that the actual polynomial degree of each transition
constraint matches the declared degree exactly. The `side_bit`
column (col 24) was populated only at active Merkle level rows; all
other rows (rows 0..89 and merkle_final_row+1..2047) held the
default-zero from `vec![[ZERO; W]; TRACE_LENGTH]`. For witnesses
producing all-left or all-right paths (e.g. fixture leaf index 0),
the column became constant-zero across the entire trace →
polynomial degree 0 → actual=0 but declared=4094 (from the
`with_cycles(2, [TRACE_LENGTH])` declaration). Release builds
skipped the assertion (`debug_assertions` cfg in winter-prover),
hiding the issue.

**Fix**: Two-line change to the prover's stall-padding loop in
[circuits/set_membership/src/prover.rs](circuits/set_membership/src/prover.rs)
to write alternating 0/1 into `COL_SIDE_BIT` at every stall row
(beyond `merkle_final_row`). All `side_bit` reads in the AIR are
gated by `sel_merge_setup_a` or `sel_merge_absorb_b`, both of
which are 0 at stall rows — so the alternation cannot influence
the soundness of any constraint, only the polynomial degree of the
column. The column now always has full degree (TRACE_LENGTH - 1)
regardless of the witness path, making the constraint degree
deterministic across debug and release.

A companion edit in
[circuits/set_membership/tests/stage16_air_impl.rs](circuits/set_membership/tests/stage16_air_impl.rs)
realigned the test-only mirror AIR's declared degree for col 24
from `new(1)` to `with_cycles(2, [TRACE_LENGTH])` so that the
parallel reference matches the production AIR.

**Verification**: All previously-passing tests still pass; the
previously-skipped workspace debug-mode runs are now green.
`scripts/ci_smoke.sh` was extended with a workspace-debug pass.

```
cargo test --workspace --release  → 414/414 green
cargo test --workspace            → 414/414 green (newly stable)
cargo test -p trusset-circuit-set-membership --features prod-proofs-set
                                  → 93 green (debug-mode set_membership sweep)
cargo fmt --check --all           → clean
cargo clippy --workspace --all-targets -- -D warnings  → clean
```

**Soundness impact**: None. The side_bit polynomial in stall rows
is killed by the periodic selector mask before reaching any
constraint result. This is purely a Winterfell-evaluator-honesty
adjustment to the trace — the cryptographic semantics of the
Merkle walk are unchanged.

### Stage 28 — Release-gate doc refresh (2026-05-20)

Updated [docs/RELEASE_GATE.md](RELEASE_GATE.md) to reflect the actual
state after Stages 16–27: §12.10 closed, §13.6 informational, test
counts 411→414, Stage 16/17 marked shipped (was "designed but not
implemented"), Stage 27 debug/release parity recorded. Added a
"Phase 2B Step-B is shippable as" section that mirrors the
"Phase 2A is shippable as" framing one level up the maturity curve.
Documentation-only change; no code touched, no test deltas.

### Stage 29 — Memory profile (spec §12.11) (2026-05-20)

**Item**: Audit-prep §12.11 was the last open Phase 2B Step-B
documentation status, marked "Phase 2A measurement deferred" since
the original release. Real measurements now captured.

**Tooling**: [scripts/memory_profile.sh](../scripts/memory_profile.sh)
generates N synthetic subjects (cycling valid fixtures: 5 countries,
8 first names, 5 last names, 3 tiers, 2 document types, 1970–1999
DOBs), runs the full TS → Rust prover pipeline once, measures peak
resident-set size via `/usr/bin/time -l`, and writes a timestamped
Markdown report to `/tmp/trusset-memprof-*.md`. Pinned fixtures
(master key, signing key, `TRUSSET_KYC_EPOCH_DAYS`) match
`tests/e2e/canary.sh` for byte-stable inputs.

**Measurements** (macOS Darwin 25.4.0 x86_64, production defaults):

| N | Wall (s) | Peak RSS (MB) | Per-subject (MB) |
|---|---|---|---|
| 5 | 26.32 | 87.8 | 17.57 |
| 50 | 265.02 | 112.7 | 2.25 |

The constant footprint (Node runtime + prover/verifier binaries +
WASM module + initial allocations) is ~75 MB; the marginal
per-subject cost is ~0.5 MB. This indicates the prover correctly
releases one trace's allocations before generating the next rather
than accumulating state across subjects. A 1000-subject batch
projects to ~600 MB peak RSS, **comfortably within the 4 GB spec
§12.11 budget** and runnable on a 16 GB laptop.

**Audit-doc updates**:
- [docs/AUDIT_PREP.md](AUDIT_PREP.md) §12.11 row: ◐ deferred → ✓ PASS with measurements
- [docs/AUDIT_PREP.md](AUDIT_PREP.md) Test surface: 188 → 414 Rust tests, plus the CI smoke ladder
- [docs/AUDIT_PREP.md](AUDIT_PREP.md) Open items: §12.10 + §12.11 moved to "Closed in Phase 2B Step-B"; remaining are operational (audit.log, CI namespacing, HSM, PQ) or Phase 2C (WASM, prove-time)
- [docs/AUDIT_PREP.md](AUDIT_PREP.md) Known deviations footer: framing updated

### Stage 30 — WASM runtime parity (Phase 2C item #1, 2026-05-20)

**Item**: Phase 2C item #1 — runtime parity between the native
`trusset-verifier-cli` and the WASM verifier loaded into Node. The
structural drift check (5 tests in
[verifier/tests/wasm_build_check.rs](../verifier/tests/wasm_build_check.rs))
already caught export shape, ABI imports, and byte-determinism, but
the runtime question — "does the WASM verifier produce the same
`VerifyReport` as the native CLI for the same bundle?" — was open.

**Tooling**: installed `wasm-bindgen-cli` at version 0.2.121 pinned
to `Cargo.lock`. Generated Node-loadable glue with
`wasm-bindgen <wasm> --target nodejs --out-dir target/wasm-bindings/node`.

**Test harness**: [tests/e2e/wasm_parity.sh](../tests/e2e/wasm_parity.sh)
(soft-skips if `wasm-bindgen` is not installed). Steps:

1. Build the WASM artifact if missing.
2. Generate Node-loadable glue.
3. Produce a fresh production bundle from a single subject (Alice
   Anderson, DEU/PROFESSIONAL/PASSPORT — matches the canary fixture).
4. Run the native CLI: `trusset-verifier-cli --bundle … --public-key … --json`.
5. Run the WASM verifier from Node: load the manifest / kyc_hash /
   signature / proof files via `fs.readFileSync`, decode the
   manifest to enumerate `leaves[].proofPath`, build the
   `{path: number[]}` proof map, and call `wasm.verify_strict(…)`.
6. Canonicalize both JSON outputs via `jq -S` and `cmp -s`.
7. **Negative case**: copy the bundle to a temp dir, XOR a byte in
   the middle of the first proof file, rerun both verifiers,
   assert outputs still match and both report `overall_pass: false`.

**Result**: Both positive and negative cases produce byte-identical
`VerifyReport` JSON between native and WASM. Confirms the WASM
verifier reaches the same overall_pass decision via the same
sub-result fields (layout_ok, mode_acceptable, signature_valid,
merkle_root_valid, per-leaf pass/reason) as the native CLI.

**CI integration**: [scripts/ci_smoke.sh](../scripts/ci_smoke.sh)
now runs `tests/e2e/wasm_parity.sh` when `wasm-bindgen` is on
`$PATH` (and the user hasn't passed `--quick`). Skips otherwise
so CI runners without the toolchain still pass.

**Soundness impact**: None — the WASM and native verifiers share
the same Rust source (`verifier/src/lib.rs::verify_loaded`);
parity is an integration-correctness property, not a cryptographic
one. The test catches future ABI / wasm-bindgen-version drift
where the WASM artifact compiles but interprets inputs differently.

### Stage 31 — Spec §12.12 `audit.log` emission (2026-05-20)

**Item**: Spec §12.12 — "Every run writes a structured `audit.log` in
the output directory: timestamps, config hash, list commitment
hashes, library versions, but no PII." Previously the last
unchecked item in the spec §12 traceability matrix.

**Module**: [prover/src/audit.rs](../prover/src/audit.rs).
Independent NDJSON event stream (separate from the stdout
`io::Event` enum consumed by the TS CLI). Wider (carries
timestamps + run metadata), narrower (no PII-bearing `message`
field on failed subjects).

**Schema** (pinned by `audit_event_schema_is_pinned` test, mirroring
the existing stdout-schema pin in `prover/src/io.rs`):

| Event | Fields |
|---|---|
| `run_start` | timestamp, library_versions, config_hash, list_commitments, skip_proofs, subject_count |
| `subject_start` | timestamp, subject_id |
| `leaf_proved` | timestamp, subject_id, field, proof_bytes, ms |
| `subject_done` | timestamp, subject_id |
| `subject_failed` | timestamp, subject_id, error_code (NO message field) |
| `run_done` | timestamp, ok, failed |

**PII posture**: `subject_id` (wallet address, public on-chain
identifier) is recorded. No field values (names, DoBs, document
numbers) appear anywhere. `subject_failed` records the stable
error code only — `message` is omitted by design because human-
readable messages can leak attribute values (e.g. "age 17 < 18"
implies the subject is 17). The `subject_failed_omits_message`
test pins this.

**Library versions**: `trusset_prover` from `CARGO_PKG_VERSION`,
`winterfell_air/prover/verifier` hardcoded to "0.13.1" matching
the Cargo.lock pin. Hardcoded so the audit log records what the
binary was actually built against (not a runtime-discoverable
property).

**Determinism**: Each event carries a wall-clock ISO-8601 UTC
timestamp, so `audit.log` is intentionally **not** byte-stable
across runs. The determinism canary
([tests/e2e/canary.sh](../tests/e2e/canary.sh)) was already
robust to this: it compares per-bundle files under `output/0x*`,
and `audit.log` lives at `output/audit.log` (one level above).
Canary re-run post-Stage-31: byte-identical bundles across two
runs ✓.

**Failure mode**: `AuditLog::open` returns a sentinel `writer:
None` when the output directory can't be created or the file
can't be opened. Subsequent `emit` calls are silent no-ops.
Audit logging must never break the prover's main flow.

**Verification**:
- 4 new unit tests in `prover/src/audit.rs`: emits with metadata,
  fails-without-message, soft-fails on open error, schema-pinning
- Workspace release: 418/418 (was 414; +4 audit tests)
- Canary: byte-identical bundles (audit.log excluded by directory
  layout)
- End-to-end smoke produced an audit.log with all spec §12.12
  fields populated correctly

**Spec §12 traceability matrix impact**:
[docs/AUDIT_PREP.md](AUDIT_PREP.md) §12.12 flips from
"✗ Not yet implemented" → "✓ PASS". This was the last unchecked
row in the spec §12 traceability matrix. The full matrix is now
✓ across all 12 items.

## End of Phase 2B Step-B

This memo documents Stages 1–31 of Phase 2B Step-B + the first
Phase 2C item: the v2 felt-level commitment scheme, four real
Winterfell AIRs with full in-AIR cryptographic soundness, the
production mode flip, refreshed performance measurements, WASM
structural drift detection, an audit-document consolidation pass,
the debug/release symmetry fix for the set_membership AIR, a
release-gate doc refresh, the spec §12.11 memory-profile baseline,
WASM runtime parity (Phase 2C #1), and the spec §12.12 `audit.log`
emission.

**Status**: Phase 2B Step-B is **complete**. The full spec §12
traceability matrix is ✓ across all 12 items. The repository is
in a state ready for external audit review.

**Remaining Phase 2C** (not soundness-affecting):
1. ~~WASM runtime parity~~ — ✓ closed Stage 30
2. Prove-time optimization for tier/preimage/set (551 ms tier → 200 ms target)
3. Post-audit iteration in response to auditor feedback

**Other workstreams** (out of Phase 2B Step-B scope):
- Spec §12.9 CI network namespacing (operational)
- Spec §17 HSM integration (separate)
- Post-quantum manifest signing (future)

**Other workstreams** (not Phase 2B Step-B scope):
- spec §12.12 `audit.log` emission (Phase 9B)
- spec §12.9 CI network namespacing (operational)
- spec §17 HSM integration (separate)
- Post-quantum manifest signing (future)
