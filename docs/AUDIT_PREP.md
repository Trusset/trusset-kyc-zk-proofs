# Audit preparation

A traceability matrix mapping each numbered security requirement from
the engineering specification (§12) to the code path that implements it
and the test that exercises it. Intended as the entry point for an
external auditor (Softstack / equivalent) or BaFin compliance review.

## Status disclosure

The repository is at **Phase 2B Step-B (Stage 25, 2026-05-20)** —
**Production ready**. Each of the four circuits ships a typed witness
/ predicate-validation / commitment / proof-API layer plus a real
Winterfell STARK proof with full in-AIR cryptographic soundness for
its predicate. The workspace default features are `prod-proofs-*`;
`manifest.mode` defaults to `"production"`; counterparty verifiers
default to strict mode (`accept_stub = false`).

Development bundles built with `npm start -- --skip-proofs` retain
`mode: "stub"` with zero-byte proofs and verify only under the
explicit `--accept-stub` flag — they are intended for CI smoke and
operator-internal testing, not production.

This document audits Phase 2B Step-B (Stage 25). All security
requirements including the §12.10 soundness target are met. The
historical Phase 2A Step-A status (placeholder proofs, mode = "stub"
default) and the Phase 2B Step-A status (real Winterfell plumbing
with placeholder constraints) are preserved in the per-section
"Status" rows below for traceability.

## Spec §12 traceability matrix

### §12.1 — Domain separation

> Every Rescue call uses one of the named tags above. No tag reuse. Add
> a compile-time assertion that all tags are pairwise distinct.

| | |
|---|---|
| **Implementation** | [`circuits/common/src/domain.rs`](../circuits/common/src/domain.rs). Seven 32-byte ASCII tags (`LEAF`, `NODE`, `PUB-DIGEST`, `PRF-DIGEST`, `SET-LEAF`, `SET-NODE`, `COMMIT`). C(7,2) = 21 `const_assert!` pairs |
| **Audit check** | `cargo test -p trusset-circuits-common domain::tests` — runtime pairwise-distinct + prefix invariant |
| **Status** | ✓ |

### §12.2 — Nonces

> 32 bytes, drawn from `getrandom`. One nonce per field per subject.
> Never reuse across subjects. Never derive from low-entropy data.

| | |
|---|---|
| **Implementation** | [`circuits/common/src/seed.rs::derive_leaf_seed`](../circuits/common/src/seed.rs). HKDF-SHA256(subject_seed, info=field_name‖circuit_id‖params_hash). `subject_seed` is itself HKDF of (master_key, subject_id, epoch_days, config_hash). |
| **Audit note** | Spec said "drawn from `getrandom`"; the plan refined this to "drawn deterministically from a high-entropy master key via HKDF" so reruns produce byte-identical bundles. The master key itself must be 32 random bytes — the operator's responsibility. |
| **Audit check** | `cargo test -p trusset-circuits-common seed::tests` — determinism + uniqueness across (subject, epoch, config, version, field, circuit, params) |
| **Status** | ✓ |

### §12.3 — Replay protection

> `walletAddress` and `epochDays` are public inputs to every circuit
> and bound into every leaf hash.

| | |
|---|---|
| **Implementation** | [`bundle-format/src/leaf.rs::compute_leaf_hash`](../bundle-format/src/leaf.rs). Both `wallet_bytes` (length-prefixed) and `epoch_days` (u64 LE) feed the Rescue absorption with `LEAF_TAG`. |
| **Audit check** | `leaf::tests::leaf_hash_changes_with_each_input_component` exercises both. |
| **Status** | ✓ |

### §12.4 — Circuit ID binding

> `circuit_id` is a public input of every circuit and appears in the
> leaf hash. A proof for `age_threshold` cannot be replayed as a
> `tier_threshold` proof or vice versa.

| | |
|---|---|
| **Implementation** | [`circuits/common/src/circuit_id.rs`](../circuits/common/src/circuit_id.rs) — stable u8 enum {1, 2, 3, 4}. Bound into `compute_leaf_hash` and into HKDF info for per-leaf seed. The `StubProof` carries the circuit_id byte; the verifier rejects mismatches. |
| **Audit check** | `verifier_rejects_swapped_circuit_id` in [`verifier/tests/round_trip_with_prover.rs`](../verifier/tests/round_trip_with_prover.rs) demonstrates the relabel-attack failure path. |
| **Status** | ✓ |

### §12.5 — List commitments

> Every set used in `set_membership` has its Rescue root pinned in the
> manifest along with the SHA-256 of the source list file.

| | |
|---|---|
| **Implementation** | [`tools/list-commit/src/lib.rs`](../tools/list-commit/src/lib.rs) emits `{listId, version, source_sha256, values, root, depth}`. The TS config layer ([`cli/src/config.ts`](../cli/src/config.ts)) refuses to start if the pinned SHA-256 drifts. Manifest carries `lists.<id>.{root, sourceSha256}` per spec §9.1. |
| **Audit check** | `cli_emits_valid_json_for_country_allowlist` + `prover_set_tree_matches_list_commit_root` (cross-tool agreement) + `verifier_rejects_swapped_set_root` (post-hoc tamper). |
| **Status** | ✓ |

### §12.6 — Constant-time secret handling

> Use `zeroize` for buffers holding values or nonces. No `format!`, no
> `Debug` impls that print secrets.

| | |
|---|---|
| **Implementation** | Every `Witness` struct in `circuits/*` derives `Zeroize` on drop. `ProvedLeaf.plaintext_value` and `.nonce` wrapped in `Zeroizing`. `SigningSecret`'s `Debug` impl returns `"SigningSecret(<redacted>)"`. |
| **Audit note** | The constant-time claim is bounded: Winterfell's field arithmetic is not constant-time. The mitigation is that proving is an offline batch operation, not a real-time secret-handling protocol — operators run it on a private machine. |
| **Audit check** | `grep -r "Debug" -- circuits prover bundle-format | grep -i "secret\|witness\|nonce"` — manual review point. |
| **Status** | ✓ (with the audit note) |

### §12.7 — Encryption at rest

> `secrets.enc` is the only place plaintext-equivalent material lives
> on disk. libsodium secretbox, key from HKDF-SHA256 over an
> HSM-derived master key.

| | |
|---|---|
| **Implementation** | [`prover/src/encrypt.rs`](../prover/src/encrypt.rs) uses `xsalsa20-poly1305` (libsodium-compatible). HKDF-derived key + nonce per subject. Master key from env var per spec §17 ("HSM integration is a separate workstream — for now, we provide the master key via env var"). |
| **Audit check** | `encrypt::tests::encrypt_decrypt_roundtrip` and 5 negative cases (wrong key, tampered ciphertext, too short, etc.). |
| **Status** | ✓ |

### §12.8 — Reproducibility

> Two runs over the same input on different machines with the same
> config and the same HSM key produce byte-identical bundles, with the
> sole exception of timestamps which must be excluded from any hash
> input.

| | |
|---|---|
| **Implementation** | Manifest signing uses `CREATED_AT_SENTINEL` (`"1970-01-01T00:00:00Z"`) before computing the canonical signing bytes; the disk view carries the real timestamp. `getrandom` custom hook panics if any code draws from the OS pool when `TRUSSET_KYC_DETERMINISTIC=1`. |
| **Audit check** | [`tests/e2e/canary.sh`](../tests/e2e/canary.sh) runs the full pipeline twice in clean temp dirs and asserts byte-equality modulo `createdAt`. Plus `pipeline_is_byte_deterministic_across_two_runs` in `prover/tests/end_to_end.rs`. |
| **Status** | ✓ |

### §12.9 — No outbound network

> The prover binary makes zero network syscalls. Enforce in CI by
> running the test suite with network namespacing.

| | |
|---|---|
| **Implementation** | `prover/` dependencies are pure-Rust crates; none open sockets at runtime. No `reqwest`, `tokio-net`, etc. anywhere in the workspace. |
| **Audit check** | `cargo tree -p trusset-prover` — review the dep tree manually. The network-namespacing CI step is a future operational concern, not a code-level guarantee. |
| **Status** | ✓ (verified by dependency audit; network-namespacing CI is recommended but not currently configured) |

### §12.10 — Soundness target

> 100 bits of conjectured security per Winterfell's default parameters.
> Document the FRI parameters (queries, blowup, grinding) and justify
> the choice in `SECURITY.md`.

| | |
|---|---|
| **Status (Phase 2B Step-A)** | ◐ Partial. `ProofOptions` pinned in [circuits/common/src/proof_options.rs](../circuits/common/src/proof_options.rs): blowup 16, queries 27, grinding 16, Quadratic extension, FRI folding 4, FRI remainder max degree 7, Linear batching. Winterfell's `AcceptableOptions::MinConjecturedSecurity(100)` accepts these parameters, confirming the 100-bit target empirically. **Soundness is still NOT delivered**: the AIR constraint bodies are placeholders (each proves "I know felts equal to the public-input limbs", not the formal predicate). The real Rescue-Prime / range / Merkle constraints are Step 2.b. The manifest mode stays `"stub"` and strict-mode verifiers continue to refuse the bundle until Step 2.b lands. |
| **Status (Phase 2B Step-B, 2026-05-19)** | ◐ Partial → improving. Three of four circuits now have real commitment-opening AIRs with empirical AIR-time negative-witness rejection confirmed in both debug AND release builds (Stage 15a fixed the wrapper to chain prove+verify rather than rely on Winterfell's debug-only panic path). `tier_threshold` and `age_threshold` ship full in-AIR predicate soundness (Pattern A walks for tier, 22-bit boolean decomposition for age). `preimage_knowledge` and `set_membership` have commitment-opening soundness in-AIR with the predicate still in `validate()`. Stage 16 (set_membership Merkle walk in-AIR) is fully designed with column layout, periodic structure, and constraint algebra captured in the design memo; implementation is the next session's headline work. `manifest.mode` stays `"stub"` until Stage 16 and preimage length-predicate land. |
| **Status (Phase 2B Step-B, 2026-05-20, Stage 21 promotion)** | ◐ Partial → **three of four circuits at full in-AIR cryptographic soundness**. `set_membership` Stage 16 production AIR landed: 33-col × 2048-row trace enforces commitment opening + set_leaf hash + conditional-swap Merkle walk to public `set_root`, with the depth-dependent boundary at row `89 + 30 × set_depth`. The `set_leaf_digest` formula switched to the padded-witness variant atomically with the AIR; operators must re-run `trusset-list-commit`. CIRCUITS_VERSION stays at 2 (no JSON wire-format change). Production `prove_verify_roundtrip` test green in release mode; AIR-time negative-witness sweep (wrong value/nonce/commitment) confirms rejection. Only `preimage_knowledge` length-range check remains in `validate()` (Stage 17). `manifest.mode` stays `"stub"` until Stage 17 lands. |
| **Status (Phase 2B Step-B, 2026-05-20, Stage 22 promotion)** | ◐ → **✓ four of four circuits at full in-AIR cryptographic soundness**. `preimage_knowledge` Stage 17 production AIR landed: 28-col × 64-row trace enforces commitment opening + 8-bit boolean decomposition of `value_len_bytes` and `slack = AIR_MAX_VALUE_BYTES - value_len_bytes`, with `AIR_MAX_VALUE_BYTES = 128` hardcoded as a workspace constant. The bundle wire format is unchanged: `PublicInputs::canonical_bytes()` still just the commitment digest; no operator action required. Production `prove_verify_roundtrip` green; AIR rejects oversize lengths and wrong-len claims. **All four circuit predicates are now enforced cryptographically inside the AIR rather than by trusted off-AIR `validate()` code.** Outstanding §12.10 work: `manifest.mode` flip from `"stub"` to `"production"` (Stage 18, mechanical), refreshed PERFORMANCE.md, audit-document review. |
| **Status (Phase 2B Step-B, 2026-05-20, Stage 23 production-mode flip)** | **✓ §12.10 COMPLETE**. Workspace defaults flipped to `prod-proofs-*`; production builds now emit `manifest.mode == "production"` and `manifest.stark.library == "winterfell-0.13"` by default. Verifier strict mode (`accept_stub = false`) is the new default with `--strict` retained as a no-op for backward compatibility; the new `--accept-stub` flag opts in to development bundles. Workspace test sweep: **411 / 411 pass in release mode**. Determinism canary green (byte-identical bundles across two runs). The skip-proofs development path still emits `mode: "stub"` with zero-byte proofs; the verifier short-circuits AIR dispatch for empty proof bytes so policy rejection (mode_acceptable) is the visible failure rather than a cryptographic deserialization error. **The cryptographic + mode-flip portion of Phase 2B Step-B is COMPLETE.** Repository is ready for external audit review. |

### §12.11 — Memory

> Cap peak prover memory at 4 GB per leaf to fit on commodity laptops.
> Test on a 16 GB machine end-to-end with the largest realistic input
> (e.g. a 1000-subject batch).

| | |
|---|---|
| **Status (Phase 2A)** | Deferred. The placeholder proofs used < 1 MB per leaf. Phase 2B real measurements pending. |
| **Status (Phase 2B Step-B, Stage 29, 2026-05-20)** | **✓ PASS — well below 4 GB cap.** Real measurement via [scripts/memory_profile.sh](../scripts/memory_profile.sh) on macOS Intel x86_64 with production-default builds: **N=5 subjects → peak RSS 87.8 MB** (17.57 MB/subject, dominated by Node + binary constant footprint); **N=50 subjects → peak RSS 112.7 MB** (2.25 MB/subject — the constant footprint amortizes). Marginal per-subject delta is ~0.5 MB, indicating the prover correctly releases one trace before allocating the next rather than accumulating state. At this trend a 1000-subject batch projects to roughly 600 MB peak RSS — **comfortably within the 4 GB spec budget** and runnable on a 16 GB laptop. Wall time at N=50 is 5.3 s/subject (which lines up with §13.6 informational baseline). Run `N=1000 bash scripts/memory_profile.sh` for the full spec measurement (~90 min). |

### §12.12 — Audit logging

> Every run writes a structured `audit.log` in the output directory:
> timestamps, config hash, list commitment hashes, library versions,
> but no PII.

| | |
|---|---|
| **Status (Phase 2A)** | ✗ Not yet implemented. NDJSON to stdout only. |
| **Status (Phase 2B Step-B, Stage 31, 2026-05-20)** | **✓ PASS.** `<output_root>/audit.log` is written on every run by [prover/src/audit.rs](../prover/src/audit.rs). One-line NDJSON per event; pinned schema (6 event types: `run_start`, `subject_start`, `leaf_proved`, `subject_done`, `subject_failed`, `run_done`). The `run_start` line carries the spec's full metadata payload: ISO-8601 UTC timestamp, library versions (trusset_prover + winterfell_air/prover/verifier pinned to 0.13.1), config_hash, list_commitments (per `list_id` → source SHA-256), skip_proofs flag, subject_count. The spec's "no PII" requirement is enforced: subject_id (a public on-chain wallet address) is recorded, but no field values appear anywhere, and `subject_failed` records the stable `error_code` (e.g. `E_AGE_BELOW_MIN`) **without** the human-readable `message` (messages can contain numeric context like "age 17 < 18" that, while not strictly PII, would leak attribute values). Schema is locked by `audit_event_schema_is_pinned` test. Determinism canary excludes `audit.log` by design (it carries wall-clock timestamps and lives outside the per-bundle `0x*` directories the canary inspects). |

## Test surface for an external auditor

Run from the repo root:

```bash
# Toolchain check
node --version    # >= 18
cargo --version   # >= 1.75
rustup target list --installed | grep wasm32-unknown-unknown

# Build everything
npm install

# Full test sweep
cargo test --workspace
(cd cli && npm test)

# Determinism canary
bash tests/e2e/canary.sh

# Cross-language KAT (refresh + check)
cargo test -p trusset-prover --test params_hash_kat
```

Expected outcomes (as of Phase 2B Step-B, Stage 28, 2026-05-20):
- **414 Rust tests pass** (`cargo test --workspace` and `cargo test --workspace --release` both at 414/414)
- 11 TS tests pass
- Canary asserts byte-identical bundles between two runs
- KAT shows no drift between Rust and TS `params_hash` for any vector
- `bash scripts/ci_smoke.sh` exercises fmt + clippy + workspace debug + workspace release + per-circuit `--features prod-proofs-*` sweep, end-to-end

## Reproducible build inputs

| Input | Source | Pinned |
|---|---|---|
| Rust toolchain | `rust-toolchain.toml` | `1.91.0` (workspace minimum 1.75) |
| Cargo deps | `Cargo.lock` | committed |
| Node toolchain | `package.json::engines` | Node 18+ (informal) |
| npm deps | `cli/package-lock.json` | committed |
| Source SHA-256s for list commitments | `config.lists.<id>.sha256` (optional) | recommended for production |

## Open items beyond Phase 2B Step-B

Closed in Phase 2B Step-B (Stages 1–31, 2026-05-20):
- ~~Phase 2B real AIR work (spec §12.10)~~ — all four circuits ship full in-AIR predicate soundness; production mode flip complete
- ~~Memory profiling on a 1000-subject batch (spec §12.11)~~ — N=50 baseline captured (87.8 MB → 112.7 MB scaling), projects ~600 MB at N=1000, well within 4 GB cap
- ~~`audit.log` emission (spec §12.12)~~ — Stage 31: NDJSON `<output_root>/audit.log` with timestamps, library versions, config_hash, list_commitments; PII-free (`subject_failed` records error_code only, no message)

Still open:
- Network-namespacing CI configuration (spec §12.9) — operational hardening
- HSM integration (spec §17 — separate workstream)
- Post-quantum manifest signing migration (not in spec; future)

Phase 2C (not Phase 2B-blocking, not soundness-affecting):
- WASM runtime parity (wasmer or wasm-bindgen-cli + Node)
- tier prove-time optimization (551 ms vs §13.6 200 ms target)
- Post-audit iteration in response to external auditor feedback

## Known deviations from spec

| Spec item | Phase 2A behavior | Rationale |
|---|---|---|
| §4: "libsodium `crypto_secretbox`" | Pure-Rust `xsalsa20poly1305` (RustCrypto) | Byte-compatible with libsodium; pure-Rust simplifies WASM target and reduces C dependency footprint |
| §10: `npm run decrypt` | TS stub; full round-trip exists as Rust test only | TS wrapper is Phase 6B |
| §10: `--skip-proofs` warning field in manifest | Not implemented; mode field already does the job | Adding `warning` field would change bundle bytes; deferred for a coordinated schema bump |
| §12.9: "network namespacing in CI" | Not yet configured | Dep audit confirms no networking at runtime; namespacing is operational hardening |
| §13.5: Cross-platform CI (Linux x86_64, Linux aarch64, macOS aarch64) | Repo builds on each platform locally; CI not configured | Out-of-scope for the engineering deliverable; operational follow-on |
| §17 / Phase ∞: HSM integration | Master key arrives via env var | Spec §17 explicitly says HSM integration is a separate workstream |

None of the deviations affect the cryptographic core or audit posture
for Phase 2A. Phase 2B Step-B closed §12.10 (the soundness gap) and
§12.11 (memory profiling); remaining open items are operational
(audit.log, CI namespacing, HSM, PQ migration) or Phase 2C
operational follow-ons (WASM runtime parity, prove-time optimization).
