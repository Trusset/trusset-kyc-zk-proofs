# v2.1.0 release gate

Every gate below was run on the reference machine at the v2.1.0 working
tree. Commands and their observed results are recorded verbatim so an
auditor can re-run them.

## Environment

| Component | Value |
|---|---|
| CPU | Apple M5 Pro, 18 cores |
| Memory | 24 GB |
| OS | macOS 26.5.2 (Darwin 25.5.0, arm64) |
| Rust | 1.91.0 (pinned in `rust-toolchain.toml`) |
| Node | v20.16.0 |
| wasm-bindgen | 0.2.121 (pinned to `Cargo.lock`) |
| wasm target | `wasm32-unknown-unknown` installed |

Cross-platform CI (Linux, Windows) remains out of scope, unchanged from
the v2.0.0 gate.

## Verdict

**ALL GATE STEPS PASS.**

## Static analysis

| Step | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all --check` | clean |
| 2 | `cargo check --workspace --all-targets` | clean |
| 3 | `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| 4 | `cargo build --release --workspace` | ok |
| 5 | `cargo build --release --target wasm32-unknown-unknown -p trusset-verifier --features wasm` | ok |
| 6 | `cd cli && npx tsc --noEmit` | clean |
| 7 | `cd cli && npx tsc` | ok |

## Unit and integration tests

| Step | Command | Result |
|---|---|---|
| 8 | `cargo test --workspace` | **465 passed, 0 failed** |
| 9 | `cd cli && npm test` | **12 passed, 0 failed** |

The Rust count rose from 435 at the start of this pass to 465 with the
v2.1 additions:

| New suite | Tests | Covers |
|---|---|---|
| `bundle-format/src/merkle.rs` (added cases) | 9 | v2 padding and arity, leaf counts 1/2/3/5/7/8/9, second-preimage, pad-leaf separation, v1-vs-v2 divergence, version dispatch |
| `bundle-format/tests/v200_backward_compat.rs` | 5 | v2.0.0 manifest parses, defaults to Merkle v1, re-serializes byte-identically, signing view unchanged, recorded root recomputes |
| `prover/tests/v21_features.rs` | 11 | commitment_only sentinel and root participation, manifest schema additions, multi-instance predicates, subject-key wrapping, re-key, determinism, entropy guard |
| `verifier/tests/v21_anchors_and_policy.rs` | 13 | root anchor, signature anchor, both, neither, wrong root, case-insensitivity, paramsHash lockstep, empty-proof policy, merkleVersion dispatch, version acceptance |
| `circuits/set_membership` (added case) | 1 | forged non-member grafted onto a member walk: v2 AIR accepts, v3 AIR rejects |
| `circuits/common/src/proof_options.rs` (added case) | 1 | conjectured security pinned at 113 bits, floor holds |
| `prover/src/entropy.rs` | 3 | guard refuses under determinism, draws otherwise, env-var name pinned |

## Cross-language KAT

`tests/kat/params_hash.json` now carries **18 vectors** covering all four
circuits plus `commitment_only`, and both TS-side resolution paths that
were previously unexercised:

| Added coverage | Why it matters |
|---|---|
| `minTier` as a string (`RETAIL`, `PROFESSIONAL`, `ELIGIBLE_COUNTERPARTY`) | `resolveTier` in the TS CLI was never checked against Rust |
| `minAgeYears` (18, 21) | The TS `years * 365` conversion was never checked against Rust |
| `commitment_only` params shape | New mode |
| A third list id | Multi-list configs |

Vectors carrying `resolvedParams` feed the unresolved form to TS and the
resolved form to Rust; both must reach the same `expected` value, which is
what makes the resolution logic cross-language-covered rather than
self-consistent.

Verified by `prover/tests/params_hash_kat.rs` and
`cli/src/__tests__/paramsHash.test.ts`, both green.

## Determinism

| Step | Command | Result |
|---|---|---|
| 10 | `bash tests/e2e/canary.sh` | pass, all bundles byte-identical across two runs |
| 11 | Entropy guard under `TRUSSET_KYC_DETERMINISTIC=1` | fails with `E_DETERMINISM_VIOLATION` |

The canary compares `kycHash.hex`, `manifest.sig`, `secrets.enc`, every
`proofs/*.bin`, and the batched CSV byte-for-byte, and `manifest.json`
with `createdAt` stripped. It passes under the new KDF chain: the
per-subject key is HKDF-derived in deterministic mode, so wrapping did not
disturb reproducibility.

Note on the guard: earlier documentation described a custom `getrandom`
hook registered in `prover/Cargo.toml`. No such hook existed in the code.
[`prover/src/entropy.rs`](../prover/src/entropy.rs) is its replacement and
is the only path to OS entropy in the prover.

## WASM parity

| Step | Command | Result |
|---|---|---|
| 12 | `bash tests/e2e/wasm_parity.sh` | pass |

Native and WASM `VerifyReport` JSON match byte-for-byte after canonical
key sort, on both a valid bundle and a single-byte-tampered one, with both
reaching `overall_pass = false` in the negative case.

The script now rebuilds the WASM artifact unconditionally. It previously
skipped the build when a file existed at the target path, which during
this pass produced a green-looking comparison against a stale artifact
from an earlier checkout. That is precisely the failure the gate exists to
catch, so the staleness path was removed.

## End-to-end matrix

`bash tests/e2e/v21_matrix.sh` runs eight scenarios plus an atomicity
check, each from a clean `input/` and `output/`: **84 assertions, 0
failures.**

| Scenario | Assertions |
|---|---|
| 1. JSON input, single subject, all fields, default config | exit 0; layout; kycHash agreement; both anchors; version 2.1.0; merkleVersion 2; production mode; one index CSV; CSV header unchanged |
| 2. CSV input with BOM, multiple subjects | exit 0; two bundles; layout each; both anchors |
| 3. Mixed JSON and CSV in `input/` | exit 0; both formats produced bundles |
| 4. Validation-stage AND prover-stage failures | exit 2; `failures.csv` header; 2 validation rows; 3 prover rows; `E_AGE_BELOW_MIN`, `E_LIST_MEMBER_MISSING`, `E_TIER_NONE` each recorded; only the survivor produced a bundle; survivor verifies |
| 5. All subjects failing | exit 1; no bundles in `output/`; no `.tmp/` left behind |
| 6. `--raw`, `--skip-proofs`, `--json` | valid JSON from `hash --json` and `show --json`; `--raw` drops the index column; `--skip-proofs` marks `mode: stub` with only zero-byte proofs; strict verify rejects it (exit 2); `--accept-stub` accepts it (exit 0); root anchor also rejects it; `verify --json` reports the anchor used; unreadable bundle exits 66 |
| 7. Odd leaf counts 1, 3, 5, 7, 9 | exact leaf count per config; layout; both anchors, each count |
| 8. Multi-instance predicates (age 18 and 21) | exit 0; two age leaves; params 6570 and 7665; distinct paramsHash values; params-derived leaf name; every leaf name filesystem-safe |
| 9. Atomicity | SIGKILL mid-batch leaves no partial bundle visible in `output/` |

Exit-code contract confirmed throughout: 0 pass, 1 batch-aborting, 2
partial or verify-fail, 64 usage error, 66 unreadable bundle.

## Backward compatibility with v2.0.0

| Check | Result |
|---|---|
| A real v2.0.0 manifest parses under the v2.1 schema | pass |
| It re-serializes byte-identically | pass |
| Its signing view contains no v2.1 keys | pass |
| Its recorded root recomputes under Merkle v1 | pass |
| The shipped v2.0.0 bundle verifies end-to-end under the v2.1 verifier | `overall_pass: true`, 9/9 leaves, root-anchored |

The last line exercises both retained compatibility paths at once: Merkle
v1 (no `merkleVersion` field) and the frozen circuitsVersion 2
`set_membership` AIR.

## Backend compatibility

The gate that matters most. Driven against the real
`trusser-issuer-backend` modules, not a reimplementation.

| Check | Result |
|---|---|
| Every generated `manifest.json` through the real validator and vendored WASM | **280 assertions, 0 failures** across 20 bundles |
| Every generated `kyc_hashes_<timestamp>.csv` row through the real `/customers/api/identity/verify` validation | **27 assertions, 0 failures** |
| The backend's own unit suite | **701 passed, 0 failed** |
| `/manifest/inspect` on a v2.1 multi-instance bundle | `ok: true`, `signature: "verified"`, passthrough prefill intact |
| Issuer app proof-upload keying (`.bin` basename equals `fieldName`) | holds, including `dateOfBirth@7665d.bin` |

Per-bundle the backend independently recomputes `publicDigest`,
`proofDigest`, `leafHash`, and the Merkle root, verifies the ed25519
signature, and runs every STARK proof. All additive manifest fields are
tolerated.

Backend changes required and left uncommitted are listed in the final
report; they are additive and total 9 files.

## Performance

Measured, not projected. Full tables in [PERFORMANCE.md](PERFORMANCE.md).

| Circuit | Prove p50 | Verify p50 | Proof size |
|---|---|---|---|
| `age_threshold` | 198 ms | 2.37 ms | 20.8 KB |
| `preimage_knowledge` | 349 ms | 2.78 ms | 23.4 KB |
| `tier_threshold` | 550 ms | 1.89 ms | 16.0 KB |
| `set_membership` | 1348 ms | 7.49 ms | 49.1 KB |

Full pipeline, 1 subject and 9 leaves: 4.83 s. Verifier over the same
bundle: 68 ms. Bundle on disk: 224 KB.

Conjectured security of the pinned `ProofOptions`: **113 bits**, against
the published floor of 100. Asserted at compile time and again at prover
startup (`E_WEAK_PROOF_OPTIONS`).

## Acceptance criteria

| # | Criterion | Status |
|---|---|---|
| 1 | All static gates clean | PASS |
| 2 | All unit, integration, and KAT tests green | PASS (465 Rust + 12 TS) |
| 3 | Determinism canary byte-identical | PASS |
| 4 | Native and WASM verifiers agree byte-for-byte | PASS |
| 5 | Eight end-to-end scenarios plus atomicity | PASS (84 assertions) |
| 6 | v2.0.0 bundles still verify | PASS |
| 7 | Generated artifacts accepted by the real issuer backend | PASS (280 + 27 assertions, 701 backend tests) |
| 8 | Documentation updated to match behavior | PASS |
