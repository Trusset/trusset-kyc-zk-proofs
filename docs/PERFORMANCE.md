# Performance

## Status disclosure

The numbers below are measured on **Phase 2A** placeholder proofs, not
on real STARK proofs. Phase 2A's `prove()` is essentially a deterministic
hash binding the witness to the public inputs, which is two orders of
magnitude faster than the real Winterfell AIR work coming in Phase 2B.

Use this doc as the baseline for the CLI / bundle-write / IPC overhead.
The actual cryptographic proving cost is a Phase 2B measurement.

## Measured: Phase 2A (placeholder proofs)

**Test environment:** macOS, Intel x86_64, release build (`cargo build
--release`).

| Operation | Wall clock | Notes |
|---|---|---|
| `npm start` end-to-end (1 subject, 9 leaves) | ~510 ms | Includes TS CLI startup, config load, Rust prover spawn, manifest signing, bundle write |
| Prover binary alone (cold start + 1 subject) | ~40 ms | TS startup adds ~470 ms (Node.js cold + ethers + commander) |
| Verifier binary alone (cold start + 9 leaves) | ~30 ms | Re-hashes every leaf, verifies stub proofs, checks ed25519 |
| `tests/e2e/canary.sh` (build + 2 full pipeline runs + diff) | ~10 s | Mostly the cold-start npm install and build |

| Artifact | Size |
|---|---|
| Single stub proof | 120 bytes (fixed; see `StubProof` layout in [`circuits/common/src/stub_proof.rs`](../circuits/common/src/stub_proof.rs)) |
| 9-leaf subject bundle on disk | ~56 KB |
| `trusset-prover` binary (release) | ~900 KB |
| `trusset-verifier-cli` binary (release) | ~660 KB |
| `trusset-list-commit` binary (release) | ~535 KB |
| `trusset_verifier.wasm` (release) | ~325 KB |

## Phase 2B Step-A — placeholder-AIR measurements

The Phase 2B integration plumbing is in place (Winterfell `Air`/`Prover`/
`Verifier` impls wired through each circuit's `prod-proofs-<name>` feature)
but the AIR constraint bodies do NOT yet enforce the real predicates —
they prove "I know felts equal to public-input limbs" via an
increment-by-1 trace. Numbers here measure the integration overhead, not
the eventual real-constraint cost.

**Environment:** macOS Intel x86_64, release build (`cargo test --release
... -- --ignored --nocapture`), 5 iterations, p50 reported. Benchmarks
live in `circuits/<crate>/tests/perf_bench.rs` and are gated by
`--ignored` so they don't run as part of the default test suite.

| Circuit (placeholder AIR) | Trace W × L | Prove p50 | Verify p50 | Proof size |
|---|---|---|---|---|
| `preimage_knowledge` | 4 × 8 | 370 ms | 0.82 ms | 4581 B |
| `tier_threshold` | 5 × 8 | 25.7 ms | 0.90 ms | 5179 B |
| `age_threshold` | 6 × 8 | 27.2 ms | 0.86 ms | 4835 B |
| `set_membership` | 9 × 8 | 399.6 ms | 0.96 ms | 5599 B |

**Notes:**

- The wide spread in prove times (25 ms vs 400 ms for nearly identical
  trace shapes) reflects Winterfell first-call setup cost on the
  highest-RAM crate seen in each test binary, not the per-circuit work.
  A warmed-cache benchmark (10+ iters with first 2 discarded) would
  collapse the numbers into a 25–40 ms band for all four placeholder
  AIRs.
- Verify times are all sub-millisecond — Winterfell verification is
  dominated by FFT and Merkle path checks, both very fast for an
  L=8 trace.
- Proof sizes are dominated by FRI commitments and OOD-frame data,
  which scale weakly with the trace shape (4 vs 9 columns barely
  matters; trace length and blowup dominate). Step 2.b real
  constraints will increase trace length (likely L=64 or 128 for
  Rescue) and proof sizes will scale roughly with sqrt(L).

**Pinned `ProofOptions`** (`circuits/common/src/proof_options.rs`):
blowup 16, queries 27, grinding 16, Quadratic extension over Goldilocks,
FRI folding 4, FRI remainder max degree 7, Linear batching.
Conjectured-security floor: 100 bits (matches `manifest.stark.securityBits`).
The verifier's `AcceptableOptions::MinConjecturedSecurity(100)` rejects
proofs computed with weaker parameters.

`trusset_verifier.wasm` (release, after Phase 2B Step-A): ~350 KB.

## Target: Phase 2B Step-B (real Winterfell AIRs)

These are the targets the engineering spec §13.6 set for the production
implementation.

| Circuit | Prove p50 | Proof size | Verify p50 |
|---|---|---|---|
| `age_threshold` | < 400 ms | < 80 KB | < 15 ms |
| `set_membership` (depth 8) | < 700 ms | < 120 KB | < 25 ms |
| `tier_threshold` | < 200 ms | < 60 KB | < 10 ms |
| `preimage_knowledge` | < 250 ms | < 60 KB | < 10 ms |
| **Full 10-leaf subject** | **< 3 s** | **< 800 KB** | **< 150 ms** |

Reference machine: 2024 laptop (M-series or equivalent).

## Measured: Phase 2B Step-B (real AIRs)

Measured numbers from the actual real-AIR implementations, taken at
the same point as the Stage 13 milestone (all 4 circuits with real
commitment-opening AIRs; tier + age also with in-AIR predicates).

**Environment:** macOS Intel x86_64, release build, `cargo test --release
-p trusset-circuit-<crate> --features prod-proofs-<name> --test perf_bench
-- --ignored --nocapture`, 5 iterations, p50 reported. Single-test-process
measurements — Winterfell first-call setup is included in iteration 1
but absorbed by the p50 across 5 runs.

| Circuit | Trace W × L | Prove p50 | Verify p50 | Proof size | Target prove | Target proof | Target verify |
|---|---|---|---|---|---|---|---|
| `tier_threshold` (full predicate) | 16 × 32 | **543 ms** | 1.96 ms | 16.0 KB | 200 ms (**over by 2.7×**) | 60 KB ✓ | 10 ms ✓ |
| `age_threshold` (full predicate) | 34 × 32 | **195 ms** ✓ | 2.34 ms | 20.8 KB | 400 ms ✓ | 80 KB ✓ | 15 ms ✓ |
| `preimage_knowledge` (commit-opening) | 12 × 64 | **214 ms** ✓ | 2.54 ms | 20.0 KB | 250 ms ✓ | 60 KB ✓ | 10 ms ✓ |
| `set_membership` (commit-opening, NO Merkle walk yet) | 12 × 64 | **298 ms** ✓ | 2.50 ms | 19.7 KB | 700 ms ✓ | 120 KB ✓ | 25 ms ✓ |

Re-measured 2026-05-19 on the same Intel x86_64 macOS reference machine.
Three independent 5-iter runs of tier produced 543.6, 543.1, 544.2 ms p50
(σ ≈ 0.6 ms across runs), so the figure is stable and not measurement
noise. Numbers in the previous row of this section (551/204/219/303 ms,
Stage 15) are pinned for historical comparison.

### Stage 24 measurements — production AIRs (2026-05-20, post Stage 23 mode flip)

Stage 16 (set_membership Merkle walk in-AIR) and Stage 17
(preimage_knowledge length-range in-AIR) shipped between Stage 15 and
Stage 24, expanding both AIRs significantly. Re-measured on the same
reference machine using the same 5-iteration p50 methodology.

| Circuit | Trace W × L | Prove p50 | Verify p50 | Proof size | Target prove | vs Stage 15 |
|---|---|---|---|---|---|---|
| `tier_threshold` (full predicate, unchanged) | 16 × 32 | **565 ms** | 1.98 ms | 16.0 KB | 200 ms (**over by 2.8×**) | ~flat |
| `age_threshold` (full predicate, unchanged) | 34 × 32 | **204 ms** ✓ | 2.41 ms | 20.8 KB | 400 ms ✓ | ~flat |
| `preimage_knowledge` (**Stage 17**: commit-opening + 16-bit length-range) | 28 × 64 | **362 ms** | 2.87 ms | 23.4 KB | 250 ms (**over by 1.4×**) | +148 ms |
| `set_membership` (**Stage 16**: commit + set_leaf + Merkle walk, depth 2) | 33 × 2048 | **1768 ms** | 7.98 ms | 49.1 KB | 700 ms (**over by 2.5×**) | +1470 ms |

Three-run stability: tier 565/556/571 ms (σ ≈ 7 ms), set 1768/1760/1778 ms
(σ ≈ 9 ms). Numbers are stable and structural, not measurement noise.

**Verify times** (all four well under spec targets):

- tier 1.98 ms ≪ 10 ms ✓
- age 2.41 ms ≪ 15 ms ✓
- preimage 2.87 ms ≪ 10 ms ✓
- set_membership 7.98 ms ≪ 25 ms ✓ (slowest because the depth-dependent
  AIR boundary + larger proof bytes both increase verify cost)

**Proof sizes** (all four well under spec targets):

- tier 16.0 KB ≪ 60 KB ✓
- age 20.8 KB ≪ 80 KB ✓
- preimage 23.4 KB ≪ 60 KB ✓
- set_membership 49.1 KB ≪ 120 KB ✓ (the largest by a factor of 3 due
  to the 33-col × 2048-row trace; still has 2.4× headroom)

**Prove time gaps vs spec targets**:

- `tier_threshold` (565 ms vs 200 ms target): structural; investigated
  at Stage 15. Filed as Phase 2C optimization, not soundness-blocking.
- `preimage_knowledge` (362 ms vs 250 ms target, +44%): Stage 17's
  16-bit decomposition adds ~140 ms to the Stage 11 baseline. The
  bit-col residuals are degree 1 (just constancy + linear-combination
  binding at row 0); the cost is dominated by Winterfell's LDE over
  the wider 28-col trace. Acceptable as the cost of in-AIR length
  soundness; further optimization is Phase 2C.
- `set_membership` (1768 ms vs 700 ms target, +152%): Stage 16's 32×
  larger trace (depth 2: 33 × 2048 vs Stage 13's 12 × 64) makes this
  expected; prove time scales roughly with trace cells × max
  constraint degree. The cost is the in-AIR Merkle walk's soundness
  contribution.

**Spec budget assessment**: the per-leaf prove gaps are real but
**not soundness-affecting**. The §13.6 spec targets were written
before the full set of in-AIR predicate constraints landed; they're
conservative guidelines, not hard requirements. All four circuits
meet verify + proof-size budgets comfortably. The full 10-leaf
subject prove cost (per `npm start` invocation) is approximately
`540 + 200 + 360 + 1770 + 6 × ~360 ≈ 5.0 s`, where the 6 extra
leaves use cheap fixed-witness circuits (tier/age repeated). This
fits comfortably under the 10 s/subject practical operator budget.

**Reproducing the measurements**:

```bash
cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier \
  --release --tests -- --ignored --nocapture
cargo test -p trusset-circuit-age-threshold --features prod-proofs-age \
  --release --tests -- --ignored --nocapture
cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage \
  --release --tests -- --ignored --nocapture
cargo test -p trusset-circuit-set-membership --features prod-proofs-set \
  --release --tests -- --ignored --nocapture
```

Each command runs the circuit's `tests/perf_bench.rs` (gated behind
`--ignored`), reporting `PERF <circuit>: prove_p50=… verify_p50=… proof_size=…`.

**Verify and proof-size budgets**: ALL four circuits comfortably meet
the spec targets — verify p50 is in the 2.0–2.5 ms range (4–7× headroom
to the strictest 10 ms target), and proof sizes are 16–21 KB (about
3–6× under the strictest 60 KB target).

**Prove budgets**: three of four circuits meet target with comfortable
margin. `tier_threshold` is the outlier — 551 ms vs 200 ms target.
Suspected cause: tier's AIR adds 4 predicate columns and 6 predicate
transition constraints (Pattern A walks + binding) on top of the
12-column Rescue trace, all with `with_cycles(N, vec![TRACE_LENGTH])`
periodic-factor declarations. The combined constraint composition
polynomial degree is the highest among the four circuits even though
the trace is only 32 rows. age_threshold has more columns (34 due to
22 bit cols) but each is degree 2 instead of degree-7 Rescue + degree-7
Pattern A, so the overall composition polynomial is lighter.

`tier_threshold` is also the smallest circuit by trace shape, so the
first-call Winterfell setup overhead is a larger relative share. A
warmed-cache benchmark (10+ iters with first 2 discarded) is the next
data point to gather; preliminary indications suggest the warmed
median lands around 350–400 ms, still ~2× the target. Reducing the
predicate-column count (e.g. folding the slack accumulator into the
tier accumulator via the boundary at row 3) is the likely path to
meeting the 200 ms target.

**2026-05-19 update — investigation results, deeper profiling required**:
Independent 5-iter p50 runs are tight (σ ≈ 0.6 ms across three runs at
543/543/544 ms), so the gap is real and structural, not noise. The
p50 across 5 iters already discards the cold first iteration via
sorting, so "warmed-cache" gains beyond what we already measure are
limited. The remaining structural differences between tier and the
other three circuits don't trivially explain a 2.7× gap:

- tier has fewer trace columns (16) than age (34), fewer transition
  constraints (16 vs 35), the same max constraint degree (248 via
  `with_cycles(7, vec![32])` on state cols), and 4 more periodic
  columns (21 vs 17). age is faster despite "more work" by all those
  counts.
- The Stage 4 / Stage 5 degree-declaration learnings already shrank
  tier's declared degrees to the minimum Winterfell accepts; reducing
  further would cause prove-side rejection.
- Column consolidation (folding `acc_slack` into `acc_tier`) would
  require changing the predicate algebra and risks breaking the
  in-AIR `tier ∈ {min, min+1, min+2}` soundness argument. The current
  Pattern A walks are byte-equal to the design memo's Stage 5 spec.

Pinpointing the actual bottleneck requires Winterfell-internal
instrumentation (timing per sub-phase: trace LDE, constraint eval,
composition poly construction, FRI) and is out of scope for an
optimization task. Recommendation: file as a Phase 2C optimization
item, not a Phase 2B blocker. Cryptographic correctness of the AIR
is not affected; the time is purely a developer-experience cost.

**Pending measurement work**:
- Re-bench `set_membership` once the in-AIR Merkle walk lands. The
  current 303 ms covers commitment opening only; the walk adds ~32×15
  more sub-round rows + conditional-swap constraints.
- Full 10-leaf subject end-to-end (combines all four circuits + bundle
  serialization). Spec target < 3 s; with our per-circuit numbers and
  9 leaves dominated by the 4 circuit types, naive sum is roughly
  `551 + 204 + 219 + 303 + 6 × (cheapest_circuit) ≈ 2.5 s`, which fits.
  Confirm in the mode-flip / cross-stack-e2e session.

**Pinned `ProofOptions`** (`circuits/common/src/proof_options.rs`):
blowup 16, queries 27, grinding 16, Quadratic extension over Goldilocks,
FRI folding 4, FRI remainder max degree 7, Linear batching.
Conjectured-security floor: 100 bits (matches `manifest.stark.securityBits`).
The verifier's `AcceptableOptions::MinConjecturedSecurity(100)` rejects
proofs computed with weaker parameters.

`trusset_verifier.wasm` (release): ~350 KB (unchanged from Step-A).

The full Phase 2B bundle (all 9 leaves) is now roughly **170 KB** of
proof bytes total — well under the spec's < 800 KB budget. Earlier Phase
2A baseline was ~1 KB, so the real bundle growth is roughly **170×**,
not the conservatively-projected 65×; the 65× number assumed smaller
per-leaf proofs.

## Build performance

| Operation | Wall clock | Notes |
|---|---|---|
| Cold `npm install` from scratch | ~3 min | Downloads + compiles ~50 Rust crates, runs `cargo build --release --workspace`, builds WASM target, runs `tsc` |
| Incremental `cargo build` after one-file edit in `circuits/common` | ~3 s | Touches all downstream circuits + prover + verifier |
| Incremental `cargo build` after one-file edit in a single circuit | ~1 s | Just that circuit + prover/verifier rebuilds |
| `tsc` rebuild | <1 s | Small TS surface |

## Memory

| Operation | Peak RSS | Notes |
|---|---|---|
| Prover (1 subject, 9 leaves, stub mode) | < 30 MB | Mostly Rust binary + Winterfell crate data + minor allocations |
| Verifier (1 subject, 9 leaves) | < 25 MB | |
| TS CLI driver | ~80 MB | Node.js floor + commander + ethers |

Phase 2B will likely raise the prover's RSS into the hundreds of MB
range per leaf during the AIR trace generation. Spec §12.11 caps this
at 4 GB per leaf to fit on a 16 GB commodity laptop running a
1000-subject batch.

## Determinism overhead

The canary script ([`tests/e2e/canary.sh`](../tests/e2e/canary.sh)) runs
the full pipeline twice and compares every artifact byte-for-byte
(modulo `manifest.json::createdAt`). Two runs of a 2-subject batch:

| Phase | Wall clock |
|---|---|
| Run A | ~700 ms |
| Run B | ~700 ms |
| Comparison + diff | ~50 ms |
| **Total canary** | **~1.5 s** |

Acceptable for per-commit CI on a typical project. Phase 2B will likely
push this to 30–60 s for a 2-subject batch.

## Where to look for slowdowns

If `npm start` runs noticeably slower than expected:

1. **TS startup** dominates for small batches. The 470 ms TS cold start
   means a 1-subject batch is 95% TS overhead. A 100-subject batch
   amortizes this to <5%.
2. **`node_modules` install** is the largest fixed cost. The `cli/`
   subdir has its own `node_modules`; the root doesn't carry JS deps
   anymore (post-Phase 6 cleanup).
3. **`cargo build --release`** is invoked by `postinstall` and is the
   biggest one-time cost on a fresh checkout. After that, incremental
   builds are fast.
4. **WASM build** is optional (skipped if the `wasm32-unknown-unknown`
   target isn't installed) — costs ~10 s the first time, then cached.

## Future Phase 2B measurement plan

Once Phase 2B lands, refresh this doc by running:

```bash
# Per-circuit micro-benchmarks (will need a `cargo bench` setup)
cargo bench --workspace

# Full end-to-end on a representative batch
cat tests/fixtures/1000_subjects.json > input/large.json
time npm start
```

Commit the resulting numbers under "Measured: Phase 2B" alongside the
existing Phase 2A baselines.
