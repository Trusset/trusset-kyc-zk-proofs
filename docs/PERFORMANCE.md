# Performance

Every number below was measured on the machine described under "Hardware".
The "v3.1" section is the v3.1.0 code; the sections after it are the v3.0.0
measurements, which v3.1 does not change (the circuits are the same). Nothing is projected or extrapolated, and
each figure has a reproduction command next to it.

## Hardware

| Component | Value |
|---|---|
| CPU | Apple M5 Pro, 18 cores |
| Memory | 24 GB |
| OS | macOS 26.6.1 (Darwin 25.6.0, arm64) |
| Rust | 1.91.0 (pinned in `rust-toolchain.toml`) |
| Node | v20.16.0 |
| Build | `cargo build --release --workspace` |

**These are Rosetta 2 numbers, not native arm64 numbers.** The host is arm64,
but the installed Rust toolchain's host triple is `x86_64-apple-darwin`, so
every binary here is a Mach-O x86_64 executable running under translation:

```console
$ rustc -vV | grep host
host: x86_64-apple-darwin
$ file target/release/trusset-prover
target/release/trusset-prover: Mach-O 64-bit executable x86_64
```

A native `aarch64-apple-darwin` toolchain will be faster, likely
substantially, and these figures are therefore an upper bound on prove time
for this hardware rather than a measurement of it. Earlier releases published
the same table describing the machine as arm64 without noting the translation;
that was wrong and is corrected here. Check your own host triple before
comparing.

## v3.1: a typical bundle

The 3.1.0 template that `npm run init -- --chain-id ... --hub ... --attester ...`
writes (`config.example.v3.1.json`): 10 leaves for an EEA resident, 9 for anyone
else (the `EEA_RESIDENT` leaf is optional). Proving leaves: 4 `set_membership`
(EEA, residency allowlist, nationality, document issuer), 1 `age_threshold`,
1 `tier_threshold`; 4 `commitment_only`. Release build, same host and Rosetta
caveat as below.

| Operation | Time |
|---|---|
| Prove one subject, 10 leaves (sum of leaf times, from `audit.log`) | 5.27 s (`set_membership` 1.2 to 1.4 s each, age 67 ms, tier 149 ms) |
| Prove one subject, 9 leaves (non-EEA) | 4.70 s |
| `npm run issue`, 2 subjects, end to end including Node start and key-file unlock | 10 s |
| Header, 10 disclosures, and `attestation.json` per subject | under 5 ms |
| Native whole-bundle verify with header (`trusset-verifier-cli`, process wall clock) | 0.05 s |
| Native single-leaf disclosure verify (process wall clock) | 0.01 to 0.02 s |
| WASM in Node, whole bundle with header, 6 STARKs (`verify_with_header`, p50 of 7) | 387 ms |
| WASM in Node, `verify_disclosure`, p50 of 9 | `set_membership` 81 ms, `age_threshold` 32 ms, `tier_threshold` 26 ms, `commitment_only` 0.7 ms |
| Key-file unlock (scrypt N = 2^17, r = 8, Node) | 0.17 s |

| Artifact (10-leaf subject) | Size |
|---|---|
| Bundle on disk | 332 KB, of which proofs 248 KB |
| `manifest.json` | 19.2 KB |
| `header.json` / `header.sig` | 378 B / 64 B |
| One disclosure (`disclosures/country.json`) | 2.8 KB, plus its 50 KB proof |
| `attestation.json` | 544 B |

```bash
cargo test -p trusset-verifier --release --test v31_vectors
node --test tests/wasm/
```

## Per-circuit proving and verification

Methodology: `tests/perf_bench.rs` in each circuit crate, 5 iterations, p50
reported. Gated behind `--ignored` so it stays out of the default suite.

| Circuit | Trace W x L | Prove p50 | Verify p50 | Proof size |
|---|---|---|---|---|
| `age_threshold` | 34 x 32 | 206 ms | 2.52 ms | 20.8 KB |
| `preimage_knowledge` | 28 x 64 | 351 ms | 2.78 ms | 23.4 KB |
| `tier_threshold` | 16 x 32 | 539 ms | 1.93 ms | 16.0 KB |
| `set_membership` | 33 x 2048 | 1361 ms | 7.57 ms | 49.1 KB |

```bash
cargo test -p trusset-circuit-age-threshold --features prod-proofs-age --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-preimage-knowledge --features prod-proofs-preimage --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-tier-threshold --features prod-proofs-tier --release --test perf_bench -- --ignored --nocapture
cargo test -p trusset-circuit-set-membership --features prod-proofs-set --release --test perf_bench -- --ignored --nocapture
```

v3 changed nothing inside the circuits: the AIRs, the commitment scheme, and
`CIRCUITS_VERSION` are all as they were at v2.1.0. These figures differ from
the v2.1.0 table only by measurement noise and by the Rosetta caveat above,
which applied to those numbers too and was not stated.

`set_membership` is the most expensive circuit by a wide margin: its trace is
2048 rows because the Merkle walk runs in-AIR at 30 rows per level.

`tier_threshold` remains the outlier relative to its trace size, 539 ms for a
16 x 32 trace, against 206 ms for age's larger 34 x 32. The cause is the
constraint composition degree, not the trace shape. Tracked in
[FUTURE_WORK.md](FUTURE_WORK.md).

## Full pipeline

Measured on the shipped `config.example.json`, which produces 9 leaves per
subject: 5 proving leaves (1 age, 3 `set_membership`, 1 tier) and 4
`commitment_only` leaves.

| Operation | Wall clock |
|---|---|
| `npm start`, 1 subject, 9 leaves | 4.16 s (p50 of 5; first run 4.41 s) |
| `npm start -- --dry-run`, 1 subject | 0.12 s |
| Verifier, 9 leaves, 5 STARKs | 0.04 s |
| `trusset-archive build`, 1 subject | 0.01 s |
| Verify from an archive, 1 subject | 0.05 s |
| `tests/e2e/canary.sh` (build check, 2 runs, byte diff) | ~24 s |
| `tests/e2e/v3_matrix.sh` (80 assertions, 5 full batches) | ~5 min |

The 4.16 s is dominated by the three `set_membership` proofs. Per-leaf times
for one run, from `output/audit.log`:

| Leaf | Circuit | Prove |
|---|---|---|
| `documentIssuingCountry` | `set_membership` | 1522 ms |
| `country` | `set_membership` | 1118 ms |
| `nationality` | `set_membership` | 1102 ms |
| `investorType` | `tier_threshold` | 247 ms |
| `dateOfBirth` | `age_threshold` | 37 ms |
| `firstName`, `lastName`, `documentType`, `documentNumber` | `commitment_only` | 0 ms |

The three `set_membership` leaves account for 3.74 s of the 4.16 s. Per-leaf
figures vary more than the isolated benchmarks above because they share a warm
process; the isolated p50s are the ones to plan capacity against.

### `--skip-proofs` and `--dry-run` are now fast

Through v2.1, `--skip-proofs` ran the full STARK and then discarded the bytes,
so it cost the same as a real run while producing nothing. It now runs each
circuit's `validate()` instead, predicates are still enforced, an under-age
subject still fails, and skips proving:

| | v2.1 | v3.0 |
|---|---|---|
| Dry run, 11-row batch, 7 provable subjects | 33.3 s | 0.77 s |
| Dry run, 1 subject |, | 0.12 s |

The stub bundles produced are byte-identical to what v2.1 produced: the leaf
hash always bound the digest of the empty proof, so the discarded STARK never
affected the output.

## Artifact sizes

Measured on one 9-leaf subject under `config.example.json`.

| Artifact | Size |
|---|---|
| Bundle on disk | 228 KB |
| Proof bytes in that bundle | 196 KB |
| `manifest.json` (v3, with claim descriptors) | 17.1 KB |
| `manifest.json` (v2.0, same 9 leaves, no descriptors) | 7.9 KB |
| `secrets.enc` | 1.4 KB |
| `commitment_only` proof file | 0 bytes (sentinel) |
| Archive, 1 subject | 269 KB (275,418 bytes) |
| Archive, 3 subjects with 10 leaves each | 978 KB (1,001,058 bytes) |
| `trusset-prover` (release) | 2.8 MB |
| `trusset-verifier-cli` (release) | 2.9 MB |
| `trusset-archive` (release) | 939 KB |
| `trusset-registry` (release) | 934 KB |
| `trusset-list-commit` (release) | 522 KB |
| `trusset_verifier.wasm` (release, `--features wasm`) | 2.6 MB (2,761,619 bytes) |

### What v3 added to the size

The manifest grew from 7.9 KB to 17.1 KB for the same nine leaves: roughly
1 KB per leaf of claim descriptor, validity interval, list-version reference,
and binding digest, plus the issuer and toolchain blocks. That is the cost of
a leaf saying what it asserts and who warrants it rather than only that a
threshold was met. It is 7% of a bundle that is 92% proof bytes.

An archive is modestly larger than the bundles it contains: proof bytes are
base64 inside it, which costs a third, offset by `secrets.enc` being excluded
by default. A 3-subject, 30-leaf archive carrying two list versions, three
root anchors, and two revocations is 978 KB against 840 KB of bundle
directories.

The WASM artifact grew from 2.3 MB to 2.6 MB with the v3 exports
(`verify_as_of`, `binding_digest_hex`, `leaf_hash_hex_bound`) and the
registry types they need. Rebuild it with
[`scripts/rebuild-wasm.sh`](../scripts/rebuild-wasm.sh).

Choosing `commitment_only` for the four identity fields removes roughly 95 KB
of proof bytes and 1.4 s of prove time per subject compared with proving them
under `preimage_knowledge`.

## Proof parameters

Pinned once in
[`circuits/common/src/proof_options.rs`](../circuits/common/src/proof_options.rs)
and shared by all four circuits: blowup 16, 27 FRI queries, 16 grinding bits,
quadratic extension over Goldilocks, FRI folding 4, FRI remainder max degree 7,
Linear batching. Unchanged in v3.

`conjectured_security_bits()` evaluates the Winterfell estimate as the minimum
of three independent terms rather than their sum:

```text
query soundness : 27 * log2(16) + 16          = 124 bits
field soundness : 2 * 64 - log2(2048 * 16)    = 113 bits
hash collision  : Rp64_256                    = 128 bits
                                          min = 113 bits
```

The field term is evaluated against `MAX_WORKSPACE_TRACE_LENGTH` (2048, the
`set_membership` trace), so it is the worst case across the workspace. 113
conjectured bits clears the published `STARK_SECURITY_BITS` floor of 100 that
`manifest.stark.securityBits` advertises and that every circuit's verifier
enforces through `AcceptableOptions::MinConjecturedSecurity`.

The floor is checked twice: a `const` assertion at compile time, and a startup
check in the prover that exits with `E_WEAK_PROOF_OPTIONS` before any proving
begins.

## Memory

| Operation | Peak RSS |
|---|---|
| `trusset-prover`, 1 subject, 9 leaves | 72 MB |
| `trusset-verifier-cli`, 9 leaves | 8 MB |
| Node CLI driver | ~72 MB |

```bash
/usr/bin/time -l target/release/trusset-verifier-cli --bundle output/<wallet> --public-key <hex>
```

Peak prover RSS is driven by the `set_membership` trace (33 x 2048 felts plus
its LDE), so it scales with the largest single leaf rather than with the leaf
count. Subjects are processed one at a time, so a 10,000-subject batch has the
same peak as a 1-subject batch.

## Build

There are no prebuilt binaries. A cold `npm install` compiles 130 crates from
`Cargo.lock`; subsequent builds are incremental and take a few seconds. Every
bundle records the SHA-256 of the prover binary that produced it
(`manifest.toolchain.proverSha256`), which is what lets a bundle be traced to
a build rather than to "some version of the tool".

Distributing signed prebuilt binaries would cut cold start from minutes to
seconds, the binaries link only `libSystem` and `libiconv`, so they are as
portable as native binaries get, but it would put a network fetch in the
install path of a tool that otherwise makes no outbound calls. That trade is
recorded in [FUTURE_WORK.md](FUTURE_WORK.md) rather than taken.

## Where to look for slowdowns

1. **`set_membership` count.** Each one costs about 1.1-1.5 s. A config with
   three of them spends 3.7 s of its 4.2 s there. Fields that do not need
   allowlist membership should not use it.
2. **`commitment_only` vs `preimage_knowledge`.** The former is free; the
   latter costs 351 ms and 23 KB per leaf while proving only that the operator
   knows an opening of its own commitment (see [CIRCUITS.md](CIRCUITS.md) for
   what that does and does not establish).
3. **Multi-instance predicates.** Two age thresholds on one field are two
   leaves and two proofs. They are cheap for `age_threshold` and expensive for
   `set_membership`.
4. **TS startup** dominates small batches. A 1-subject run is mostly Node cold
   start plus commander and ethers; a 100-subject batch amortizes it away.
5. **Check before you prove.** `npm start -- --dry-run` costs 0.12 s per
   subject and catches everything the prover would reject, so a batch with
   bad rows is found in seconds rather than after minutes of proving.
