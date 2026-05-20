# Step 2.b — Real AIR constraint design (HISTORICAL)

> **⚠️ This document is HISTORICAL — superseded by
> [STEP_2B_COMMITMENT_DESIGN.md](STEP_2B_COMMITMENT_DESIGN.md).**
>
> Written at the start of Phase 2B Step-B planning, this memo
> captured the design exploration that led to the v2 commitment
> scheme and the per-circuit AIR work. The current canonical
> design memo is [STEP_2B_COMMITMENT_DESIGN.md](STEP_2B_COMMITMENT_DESIGN.md),
> which documents Stages 1–25 of the actual implementation work
> (the v2 commitment scheme, all four circuits' production AIRs,
> the Stage 23 mode flip, and the Stage 24/25 baselines).
>
> Phase 2B Step-B is now **complete** (2026-05-20):
> - All four circuits ship full in-AIR cryptographic soundness
> - `manifest.mode` defaults to `"production"`
> - 414/414 workspace release tests pass
>
> The historical content below is preserved as a record of the
> early design exploration. The "estimated remaining effort" and
> forward-looking sections were written when Phase 2B Step-B was
> projected at "1–2 dedicated sessions" — the actual work spanned
> 25 stages across many more sessions, with substantial Winterfell
> degree-checker iteration and design refinements not anticipated
> at the time this memo was written.

This document scopes the next Phase 2B work item: replacing the
placeholder AIRs with real constraints that enforce the formal
predicates in [docs/CIRCUITS.md](CIRCUITS.md).

It exists because the naive arithmetization attempted in Phase 2B
Step-A hit a fundamental Winterfell design constraint that's worth
recording before the next session starts.

## What Step-A delivered

- All four circuit crates have working Winterfell `Air` / `Prover` /
  `Verifier` plumbing behind their `prod-proofs-<circuit>` feature.
- Trace shape is a 4–9 column × 8 row "increment-by-1 ballast" — the
  constraints prove "I know felts equal to public-input limbs", which
  is soundness-meaningless but exercises every other part of the
  STARK pipeline (Fiat-Shamir, FRI, Merkle authentication, OOD-frame
  composition).
- KAT + negative-witness sweeps validate the integration. Determinism
  contract holds (two prove calls produce byte-identical proofs).
- Workspace-pinned `STARK_OPTIONS` empirically reaches 100 conjectured
  bits via Winterfell's `AcceptableOptions::MinConjecturedSecurity(100)`.

What's NOT delivered: any cryptographically meaningful constraint.
The prover can produce a valid proof for any `tier`, any `dob_days`,
any `value`, etc. — bound only to the public inputs declared at
prove time, not to the committed witness.

## The Winterfell degree-consistency check

The first attempt at real constraints introduced witness columns
(`tier`, `slack`) as constant private values and tried degree-3
transition constraints `(tier-1)(tier-2)(tier-3) = 0` and
`slack(slack-1)(slack-2) = 0`. This failed at
[winter-prover/src/constraints/evaluation_table.rs:214](https://docs.rs/winter-prover/0.13.1/src/winter_prover/constraints/evaluation_table.rs.html#L214)
with:

```text
assertion `left == right` failed: transition constraint degrees didn't match
expected: [0, 0, 0, 0, 0, 0, 0, 14, 14, 0]
actual:   [0, 0, 0, 0, 0, 0, 0,  0,  0, 0]
```

**Why:** Winterfell asserts `actual_constraint_polynomial_degree ==
declared_degree × trace_column_polynomial_degree`. A constant column
has polynomial degree 0; a degree-3 constraint over a constant column
produces a degree-0 polynomial, which mismatches Winterfell's expected
degree-14 polynomial slot.

**The lesson:** Predicate constraints over private *constant* witness
columns cannot be expressed naively. Any of three patterns will work:

## Three valid arithmetization patterns

### Pattern A — Product accumulator

Walk the predicate's factors multiplicatively across rows. A column
`acc` starts at 1; each row multiplies by a different factor; boundary
constraint at the final row asserts `acc = 0`.

For `tier ∈ {1, 2, 3}`:

```text
Row 0:  acc = 1                          (boundary)
Row 1:  acc = 1 * (tier - 1)
Row 2:  acc = row1 * (tier - 2)
Row 3:  acc = row2 * (tier - 3)
Row 4+: acc unchanged                    (or stays 0)
Row L-1: acc = 0                         (boundary)
```

Transition: `next.acc = current.acc * (tier - some_value_at_row_k)`.
The `some_value_at_row_k` lives in a **periodic column**
(Winterfell-native concept) carrying `[1, 1, 2, 3, ...]`.

**Pros:** Degree 2 constraint (acc × periodic), naturally evolves so
trace polynomial is non-trivial. Each factor consumed in a separate
row → no degree-3 expression needed.
**Cons:** Adds a periodic column per predicate. Three of them for the
tier check; for age_threshold's range check, the periodic table grows
to ~22 rows of `2^k` values, which forces `L ≥ 32`.

### Pattern B — Periodic-column lookup

A periodic column carries `[1, 2, 3, 0, 0, ...]`. The constraint
`(tier - p[k])` is degree 1 in the trace variable for each row, and
the prover is forced to "match" the tier against exactly one of the
periodic values at one row. Combined with a boolean column indicating
which row matched, this enforces tier ∈ {set}.

**Pros:** Each constraint stays degree ≤ 2.
**Cons:** Boolean-indicator column needs its own range check.
Verifier-side periodic column setup adds boilerplate.

### Pattern C — Lagrange interpolation gadget

Express the predicate via a polynomial that's identically zero on the
"valid value" set. For `tier ∈ {1, 2, 3}`: the polynomial
`(x-1)(x-2)(x-3)` is zero exactly at those three values. Use this as
the AIR's reduction target but reformulate as a sequence of
two-multiplications: prover witnesses `m1 = (tier-1)(tier-2)`, then
constraint `m1 * (tier-3) = 0`. Each constraint is degree 2.

**Pros:** Cleanest mathematically; matches what the formal predicate
says verbatim.
**Cons:** Witness `m1` is a constant column — same Winterfell
degree-mismatch issue unless `m1` is forced to evolve. Workaround:
encode `m1` across two rows of the trace (`m1_row0`, `m1_row1`) so
the column has degree 1 in the trace variable.

## Rescue commitment opening (the bigger half)

All three patterns above address only the *predicate* side. The
*commitment* side requires proving:

```text
Rescue(COMMITMENT_TAG ‖ u32_le(witness_len) ‖ witness ‖ nonce) == commitment
```

The Rescue-Prime permutation has 7 rounds; each round has S-box `x⁷`,
MDS layer (12×12 matrix over Goldilocks), and 24 round constants. A
single absorption block is 12 columns × ~14 rows (2 rounds per row
pair). Encoding this is several hundred lines of careful
transition-constraint code plus a one-time KAT against
`winter_crypto::hashers::Rp64_256::merge()` to validate the round
constants byte-for-byte.

This is the workspace-shared gadget. It belongs in
`circuits/common/src/rescue_air.rs` and gets reused by all four
circuits. **Implementing it correctly is the largest single
engineering item in all of Phase 2B.**

## Recommended Step 2.b execution order

For a focused session, in order of decreasing leverage:

1. **Rescue-Prime AIR module in `circuits/common`** with a KAT against
   `Rp64_256::merge()`. Soundness-meaningful on its own; unblocks all
   four circuits.
2. **`preimage_knowledge` first** — only needs the Rescue gadget plus
   a one-line length range check. Smallest possible circuit using the
   real Rescue AIR.
3. **`tier_threshold`** — Rescue gadget + Pattern A product accumulator.
4. **`age_threshold`** — Rescue gadget + boolean-decomposition range
   check on `slack = age_days - min_age_days` over ~22 bits.
5. **`set_membership`** — Rescue gadget × `set_depth` rounds of
   conditional-swap Merkle merge. Highest column count.

Each step ships with a frozen-bytes KAT and the existing per-circuit
neg-witness sweep. After step 5, Steps 6/7/8/10 of the Phase 2B plan
become a single PR: flip workspace defaults, flip `manifest.mode`,
re-run canary, run cross-stack e2e.

## Acceptance bar for each circuit

- `cargo test -p trusset-circuit-<name> --features prod-proofs-<name>`
  green.
- KAT file `tests/kat/<circuit>.json` with frozen `proof_sha256_hex`.
- Negative witness sweep proves predicate violation is rejected at
  AIR-prove time (not at validate-time).
- Determinism contract: two prove calls byte-identical.
- Canary `tests/e2e/canary.sh` green when only that circuit is moved
  to `prod-proofs-<circuit>` (i.e., partial rollout works).

## Estimated effort

- Rescue gadget + KAT: 1 full focused session (3–4 hours of iteration
  against KAT bytes).
- Per-circuit constraint body: 1–2 hours each, dropping after the
  first one as the patterns stabilize.
- Workspace flip (Steps 6/7/8/10): 30 minutes once all four circuits
  ship real constraints.

Total: 1–2 dedicated sessions to land Phase 2B Step-B (real AIRs)
through to production-mode flip.
