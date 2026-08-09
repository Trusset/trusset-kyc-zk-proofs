# Performance

All numbers below are measured on the reference machine described under
"Hardware", with the v2.1.0 code as shipped. Nothing here is projected or
extrapolated; every figure has a reproduction command next to it.

## Hardware

| Component | Value |
|---|---|
| CPU | Apple M5 Pro, 18 cores |
| Memory | 24 GB |
| OS | macOS 26.5.2 (Darwin 25.5.0, arm64) |
| Rust | 1.91.0 (pinned in `rust-toolchain.toml`) |
| Node | v20.16.0 |
| Build | `cargo build --release --workspace` |

Earlier releases were benchmarked on an Intel x86_64 macOS machine. Those
tables are not comparable to these and have been removed rather than left
to look like a regression or an improvement.

## Per-circuit proving and verification

Methodology: `tests/perf_bench.rs` in each circuit crate, 5 iterations,
p50 reported. Gated behind `--ignored` so it stays out of the default
test suite.

| Circuit | Trace W x L | Prove p50 | Verify p50 | Proof size |
|---|---|---|---|---|
| `age_threshold` | 34 x 32 | 198 ms | 2.37 ms | 20.8 KB |
| `preimage_knowledge` | 28 x 64 | 349 ms | 2.78 ms | 23.4 KB |
| `tier_threshold` | 16 x 32 | 550 ms | 1.89 ms | 16.0 KB |
| `set_membership` | 33 x 2048 | 1348 ms | 7.49 ms | 49.1 KB |

Reproduce:

```bash
cargo test -p trusset-circuit-age-threshold --features prod-proofs-age --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-set-membership --features prod-proofs-set --release --test perf_bench -- --ignored --nocapture
```

`set_membership` is the most expensive circuit by a wide margin: its
trace is 2048 rows because the Merkle walk runs in-AIR at 30 rows per
level. Since v2.1.0 that walk also carries the binding constraints that
make it prove membership of the committed value (see
[CIRCUITS.md](CIRCUITS.md)); the constraints are degree 1 and did not
measurably change prove time.

`tier_threshold` remains the outlier relative to its trace size - 550 ms
for a 16 x 32 trace, against 198 ms for age's larger 34 x 32. The cause
is the constraint composition degree, not the trace shape, and it is a
developer-experience cost rather than a soundness one. Tracked in
[FUTURE_WORK.md](FUTURE_WORK.md).

## Full pipeline

Measured on the shipped `config.example.json`, which produces 9 leaves per
subject: 5 proving leaves (1 age, 3 set_membership, 1 tier) and 4
`commitment_only` leaves.

| Operation | Wall clock |
|---|---|
| `npm start` end-to-end, 1 subject, 9 leaves | 4.83 s |
| Verifier, 9 leaves, 5 STARK proofs | 68 ms |
| `tests/e2e/canary.sh` (build check + 2 runs + byte diff) | ~25 s |

The 4.83 s is dominated by the three `set_membership` proofs at roughly
1.35 s each. Node.js startup and bundle writing are under 500 ms of the
total.

## Artifact sizes

| Artifact | Size |
|---|---|
| 9-leaf subject bundle on disk | 224 KB |
| Proof bytes in that bundle | 200 KB |
| `commitment_only` proof file | 0 bytes (sentinel) |
| `trusset-prover` (release) | 2.7 MB |
| `trusset-verifier-cli` (release) | 2.5 MB |
| `trusset-list-commit` (release) | 523 KB |
| `trusset_verifier_bg.wasm` (release, wasm-bindgen nodejs) | 2.3 MB |

The WASM artifact grew with the v2.1 granular exports
(`proof_digest_hex`, `public_digest_hex`, `leaf_hash_hex`,
`merkle_root_hex`, `merkle_root_hex_v`, `manifest_signing_bytes`,
`verify_manifest_signature`, `verify_leaf_stark`, `verify_leaf_stark_v`,
`verify_with_anchors`) plus the frozen circuitsVersion 2 AIR retained for
verifying existing bundles. Rebuild it with
[`scripts/rebuild-wasm.sh`](../scripts/rebuild-wasm.sh).

Choosing `commitment_only` for the four identity fields in
`config.example.json` removes roughly 95 KB of proof bytes per subject
compared with proving them under `preimage_knowledge`, and removes about
1.4 s of prove time.

## Proof parameters

Pinned once in
[`circuits/common/src/proof_options.rs`](../circuits/common/src/proof_options.rs)
and shared by all four circuits: blowup 16, 27 FRI queries, 16 grinding
bits, quadratic extension over Goldilocks, FRI folding 4, FRI remainder
max degree 7, Linear batching.

`conjectured_security_bits()` evaluates the Winterfell estimate as the
minimum of three independent terms rather than their sum:

```text
query soundness : 27 * log2(16) + 16          = 124 bits
field soundness : 2 * 64 - log2(2048 * 16)    = 113 bits
hash collision  : Rp64_256                    = 128 bits
                                          min = 113 bits
```

The field term is evaluated against `MAX_WORKSPACE_TRACE_LENGTH` (2048,
the `set_membership` trace), so it is the worst case across the workspace.
113 conjectured bits clears the published `STARK_SECURITY_BITS` floor of
100 that `manifest.stark.securityBits` advertises and that every circuit's
verifier enforces through `AcceptableOptions::MinConjecturedSecurity`.

The floor is checked twice: a `const` assertion at compile time, and a
startup check in the prover that exits with `E_WEAK_PROOF_OPTIONS` before
any proving work begins.

## Memory

| Operation | Peak RSS |
|---|---|
| Prover, 1 subject, 9 leaves | ~250 MB |
| Verifier, 9 leaves | ~60 MB |
| TS CLI driver | ~80 MB |

Measure with [`scripts/memory_profile.sh`](../scripts/memory_profile.sh).
Peak RSS is driven by the `set_membership` trace (33 x 2048 felts plus
its LDE), so it scales with the largest single leaf rather than with the
leaf count.

## Where to look for slowdowns

1. **`set_membership` count.** Each one costs about 1.35 s. A config with
   three of them (the shipped example) spends 4 s of its 4.8 s there.
   Fields that do not need allowlist membership should not use it.
2. **`commitment_only` vs `preimage_knowledge`.** The former is free; the
   latter costs 349 ms and 23 KB per leaf while proving only that the
   operator knows an opening of its own commitment (see
   [CIRCUITS.md](CIRCUITS.md) for what that does and does not establish).
3. **TS startup** dominates small batches. A 1-subject run is mostly
   Node.js cold start plus commander and ethers; a 100-subject batch
   amortizes it away.
4. **`cargo build --release`** runs from `postinstall` on a fresh
   checkout. Subsequent incremental builds are a few seconds.
