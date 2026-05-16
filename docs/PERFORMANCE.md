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

## Target: Phase 2B (real Winterfell AIRs)

These are the targets the engineering spec §13.6 set for the production
implementation. They will replace the table above once Phase 2B lands.

| Circuit | Prove p50 | Proof size | Verify p50 |
|---|---|---|---|
| `age_threshold` | < 400 ms | < 80 KB | < 15 ms |
| `set_membership` (depth 8) | < 700 ms | < 120 KB | < 25 ms |
| `tier_threshold` | < 200 ms | < 60 KB | < 10 ms |
| `preimage_knowledge` | < 250 ms | < 60 KB | < 10 ms |
| **Full 10-leaf subject** | **< 3 s** | **< 800 KB** | **< 150 ms** |

Reference machine: 2024 laptop (M-series or equivalent).

The Phase 2B bundle size will jump roughly **65×** per subject
(from ~1 KB of total proof bytes to ~600 KB). The dispatch / signing /
bundle-write overhead stays the same; only the proof bytes balloon.

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
