# v3.0.0 release gate

Every gate below was run on the reference machine at the v3.0.0 working tree.
Commands and their observed results are recorded verbatim so an auditor can
re-run them.

## Environment

| Component | Value |
|---|---|
| CPU | Apple M5 Pro, 18 cores |
| Memory | 24 GB |
| OS | macOS 26.6.1 (Darwin 25.6.0, arm64) |
| Rust | 1.91.0 (pinned in `rust-toolchain.toml`) |
| Rust host triple | `x86_64-apple-darwin` — binaries run under Rosetta 2 |
| Node | v20.16.0 |
| wasm-bindgen | 0.2.121 (pinned to `Cargo.lock`) |
| wasm target | `wasm32-unknown-unknown` installed |

The host-triple row is new and matters: the machine is arm64 but the installed
toolchain builds x86_64, so every timing in
[PERFORMANCE.md](PERFORMANCE.md) is a translated-execution figure. Earlier
gates recorded the same machine as arm64 without noting this.

Cross-platform CI (Linux, Windows) remains out of scope, unchanged from the
v2.1.0 gate.

## Gates

### 1. Formatting and lint

```bash
cargo fmt --check --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p trusset-verifier --features wasm --target wasm32-unknown-unknown --lib -- -D warnings
```

Result: clean, no warnings. The MSRV declared in `Cargo.toml` moved from 1.75
to 1.82, which is what clippy's `incompatible_msrv` lint required once v3
started using `Option::is_none_or`. The 1.75 figure had not been accurate for
some time — `rust-toolchain.toml` pins 1.91.

### 2. Rust test suite

```bash
cargo test --workspace --release
```

Result: **565 passed, 0 failed** across 48 test binaries.

New in v3:

| Suite | Tests | Covers |
|---|---|---|
| `bundle-format` unit (`claims`, `registry`, `archive`) | 55 | Binding digest, registry invariants, lapse/void semantics, archive integrity |
| `prover/tests/v3_guards.rs` | 18 | Issuer requirement, descriptor and validity validation, list-version cross-checks, failure-message content, dry-run completeness, stub-mode predicate enforcement |
| `verifier/tests/v3_temporal.rs` | 17 | Rotation regression, as-of block resolution, unresolvable-as-of, lapse/void, descriptor binding into the root |
| `verifier/tests/v3_archive.rs` | 7 | Archive round-trip with the bundle directory deleted, tamper rejection, digest stability |

The v2.0.0 backward-compatibility suite
(`bundle-format/tests/v200_backward_compat.rs`) is unchanged and still passes
against the real v2.0.0 fixture, which is the gate that says existing bundles
keep verifying.

### 3. TypeScript test suite

```bash
cd cli && npm test
```

Result: **17 passed, 0 failed.**

Four assertions changed. Three were message-text expectations that moved with
the rewritten failure messages. The fourth,
`investorType falls back to default when invalid`, asserted behaviour v3
deliberately removes: an unrecognised tier is now a quarantined row rather
than a silent substitution. It is replaced by
`an unrecognised investorType quarantines the row instead of coercing it` and
`a blank investorType takes the configured default`, which pin both halves of
the new rule.

### 4. Determinism canary

```bash
bash tests/e2e/canary.sh
```

Result: **PASS.** Two runs in clean working directories produce byte-identical
`kycHash.hex`, `manifest.sig`, `secrets.enc`, and every `proofs/*.bin`;
`manifest.json` differs only in `createdAt`.

The canary's second fixture subject moved from `RETAIL` to
`ELIGIBLE_COUNTERPARTY` because `config.example.json` now asserts
`minTier: PROFESSIONAL`. `minTier: RETAIL` is vacuous over the provable
domain — the circuit already refuses `NONE` — so shipping it as the example
taught operators to write a predicate that asserts nothing.

### 5. v2.1 wire compatibility

```bash
bash tests/e2e/v21_matrix.sh
```

Result: **84 passed, 0 failed.** Each case forces `manifest.version` back to
`2.1.0`, and the bundles that come out are the v2.1 shape: no issuer, no
descriptors, no validity, and the v2 leaf-hash preimage.

### 6. v3 end to end

```bash
bash tests/e2e/v3_matrix.sh
```

Result: **80 passed, 0 failed.** From an empty directory: `init`, a dry run
over a batch with failures at both stages, a real batch covering every circuit
and both leaf modes with two predicate instances on one field, verification
against both anchors, a list rotation followed by re-verification, validity
windows, an as-of block query, lapse and voidance, an archive verified on a
clean directory, a determinism comparison, and the unpinned-epoch refusal.

Two harness defects were found and fixed while bringing this up, both worth
recording because they are the class of bug that makes a suite report success
it has not earned:

- **A `set -o pipefail` + SIGPIPE race.** `printf '%s' "$out" | grep -q PATTERN`
  reports failure when grep matches *early*: grep exits, the pipe closes, and
  printf dies with 141, which pipefail surfaces as the pipeline's status. It
  fired only on the longest output in the suite. Substring assertions now use
  bash pattern matching and never a pipe.
- **The same pattern in `scripts/build.sh`**, where
  `rustup target list --installed | grep -q wasm32` deciding wrongly would
  have silently skipped the WASM build.

### 7. WASM runtime parity

```bash
bash tests/e2e/wasm_parity.sh
```

Result: **PASS.** The native `trusset-verifier-cli` and the WASM verifier
loaded into Node produce byte-identical `VerifyReport` JSON, on a clean bundle
and on one with a flipped proof byte.

Both sides are pinned to the same evaluation instant for the comparison. The
native CLI defaults to the system clock; the pre-v3 WASM exports have no clock
and evaluate at the bundle's own `epochDays`, which reproduces their v2
semantics. The gate exists to catch verification-logic drift, not a
disagreement about the date.

### 8. WASM build and export contract

```bash
cargo rustc --release --target wasm32-unknown-unknown -p trusset-verifier \
    --features wasm --lib --crate-type=cdylib
bash scripts/rebuild-wasm.sh
```

Result: builds clean at 2,761,619 bytes. `scripts/rebuild-wasm.sh` asserts
every export the issuer backend depends on is present. The required list gains
three v3 entries — `verify_as_of`, `binding_digest_hex`,
`leaf_hash_hex_bound` — and keeps all eight pre-v3 entries, so a backend that
has not been updated keeps working.

**Counterparties running their own verifier must re-vendor.** A verifier that
re-serializes the typed manifest struct to recompute the signing view will
drop fields it does not know about and compute the wrong bytes.

### 9. Security review

Run over the v3 surface before the gate. Three findings, all fixed and
regression-tested; the results below are from after the fixes.

| Check | Result |
|---|---|
| `unsafe` code | None. `unsafe_code = "forbid"` at the workspace level |
| `unwrap` / `expect` / `panic!` in new library code | None outside `#[cfg(test)]` |
| Key material reaching stdout, stderr, `audit.log`, or `failures.csv` | None. Keys are never interpolated into any output |
| Witness values reaching `audit.log` or `failures.csv` | None. Failure messages name the leaf and the asserted threshold only |
| Key file permissions | `.trusset/keys.env` is written 0600 and chmod'd 0600 |
| Archive embedding `secrets.enc` | Off unless `--include-secrets` is passed |
| `cargo` dependency surface | 130 crates, all pinned in `Cargo.lock` |
| `npm audit --omit=dev` | **0 vulnerabilities** |

**Finding 1 — path traversal via `proofPath` (fixed).** A manifest is
untrusted input, and `proofPath` was the one field in it that reached the
filesystem: the verifier's loader and the archive builder both joined it onto
a directory without validation. A manifest carrying
`proofPath: "../../../etc/passwd"` would have made a verifier read an
arbitrary file. Impact was limited — the contents only ever feed a digest
comparison that then fails — but whether the read succeeds is observable and
the path appears in error output, which is an arbitrary-file-read primitive by
any reasonable reading. This predates v3.

Fixed with `is_safe_proof_path` in `bundle-format`, enforced at all three read
points: the verifier's disk loader, the archive builder, and the archive's own
structure check. It requires a plain `proofs/<name>` entry — no separators, no
parent references, no leading dot, no NUL — which is exactly what the prover
writes, so no real bundle is affected. Regression test:
`a_traversing_proof_path_is_refused_rather_than_followed`.

**Finding 2 — `ethers` dependency (removed).** Fifteen npm advisories, one
high (`ws`, uninitialized memory disclosure), all transitive under `ethers@5`,
which was present for exactly two functions. None was reachable — the tool
opens no sockets — but a tool whose security model is "no outbound network
calls" should not ship a WebSocket client, and it would have appeared in every
downstream supply-chain scan.

Replaced with `@noble/hashes` plus a fifteen-line EIP-55 implementation. The
CLI's runtime dependency count went from roughly twenty packages to four, and
`npm audit` from fifteen advisories to zero. Verified by differential testing
against `ethers` over 20,012 inputs with zero divergence, and by confirming
bundle output is byte-identical across the swap — `kycHash`, every proof byte,
and `secrets.enc` unchanged, with only `toolchain.proverSha256` moving because
the prover binary was rebuilt. That is the field doing its job.

**Finding 3 — unchecked arithmetic (hardened).** Two spots where an
underflow was unreachable but not locally evident: closing a superseded list
version's window (`effective_from - 1`, guarded by an earlier ordering check)
and computing `basisAsOf` from an offset. A wrap in the first would have set a
superseded version's window to end at `u64::MAX`, leaving it authoritative
forever. Both now check explicitly and return a named error. Regression test:
`a_first_version_on_epoch_day_zero_is_allowed`.

### 10. Performance

Measured, not projected. See [PERFORMANCE.md](PERFORMANCE.md) for the full
tables and reproduction commands. Headlines:

| | v2.1.0 | v3.0.0 |
|---|---|---|
| `npm start`, 1 subject, 9 leaves | 4.83 s | 4.16 s |
| Verify, 9 leaves | 68 ms | 40 ms |
| Dry run, 11-row batch | 33.3 s | 0.77 s |
| Bundle on disk | 224 KB | 228 KB |
| `manifest.json` | 7.9 KB | 17.1 KB |
| `trusset_verifier.wasm` | 2.3 MB | 2.6 MB |

The circuits are unchanged, so the prove-time difference is noise plus a
warmer process. The dry-run figure is a real change: `--skip-proofs` used to
run the full STARK and discard it.

### 11. Documentation

README rewritten around the operator's path — what the tool is, a five-command
quick start, then reference. Every command in it was executed against the
shipped binaries rather than transcribed.

## What this gate does not cover

- **Cross-platform.** macOS only, and x86_64-under-Rosetta at that.
- **Native arm64 timings.** Every figure is an upper bound for this hardware.
- **Chain integration.** There is none, by design. As-of queries resolve
  against the operator's signed root history, and the anchors it contains are
  recorded by the operator rather than read from a chain. An anchor that
  misstates which block a root was published at is a signed misstatement by
  the operator, not something this tool can detect.
- **Formal zero knowledge.** Unchanged from v2.1: proofs carry no blinding.
  See [FUTURE_WORK.md](FUTURE_WORK.md).
- **HSM key custody.** The master and signing keys arrive via environment
  variables. `npm run init` writes them to `.trusset/keys.env` at mode 0600,
  which is better than the previous "paste two `openssl` invocations into your
  shell history" and is still not an HSM.
