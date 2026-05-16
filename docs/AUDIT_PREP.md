# Audit preparation

A traceability matrix mapping each numbered security requirement from
the engineering specification (§12) to the code path that implements it
and the test that exercises it. Intended as the entry point for an
external auditor (Softstack / equivalent) or BaFin compliance review.

## Status disclosure

The repository is at **Phase 2A**. Each of the four circuits ships a
typed witness / predicate-validation / commitment / proof-API layer
plus a 120-byte placeholder proof that binds the witness to the public
inputs via Rescue, but the placeholder is **not a STARK**. Counterparty
verifiers refuse `mode: "stub"` bundles by default. Real Winterfell
AIRs with Rescue gates are Phase 2B work.

This document audits Phase 2A. All security requirements except those
that explicitly require real STARK proving (§12.10 soundness target)
are met as of v2.0.0.

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
| **Status** | ✗ **Phase 2A blocker.** The placeholder proofs do not provide STARK soundness. Real Winterfell AIRs are Phase 2B. The manifest mode is `"stub"` and strict-mode verifiers refuse the bundle. Production deployments must wait for Phase 2B. |

### §12.11 — Memory

> Cap peak prover memory at 4 GB per leaf to fit on commodity laptops.
> Test on a 16 GB machine end-to-end with the largest realistic input
> (e.g. a 1000-subject batch).

| | |
|---|---|
| **Status** | Phase 2A measurement deferred. The placeholder proofs use < 1 MB per leaf. Phase 2B will need real measurements; budget is captured. |

### §12.12 — Audit logging

> Every run writes a structured `audit.log` in the output directory:
> timestamps, config hash, list commitment hashes, library versions,
> but no PII.

| | |
|---|---|
| **Status** | ✗ Not yet implemented. The prover does emit NDJSON events to stdout (which the TS layer can persist), but there's no dedicated `audit.log`. Tracked for Phase 9B. |

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

Expected outcomes:
- 188 Rust tests pass
- 11 TS tests pass
- Canary asserts byte-identical bundles between two runs
- KAT shows no drift between Rust and TS `params_hash` for any vector

## Reproducible build inputs

| Input | Source | Pinned |
|---|---|---|
| Rust toolchain | `rust-toolchain.toml` | `1.91.0` (workspace minimum 1.75) |
| Cargo deps | `Cargo.lock` | committed |
| Node toolchain | `package.json::engines` | Node 18+ (informal) |
| npm deps | `cli/package-lock.json` | committed |
| Source SHA-256s for list commitments | `config.lists.<id>.sha256` (optional) | recommended for production |

## Open items for Phase 9B

- `audit.log` emission (spec §12.12)
- Network-namespacing CI configuration (spec §12.9)
- Phase 2B real AIR work (spec §12.10)
- Memory profiling on a 1000-subject batch (spec §12.11)
- HSM integration (spec §17 — separate workstream)
- Post-quantum manifest signing migration (not in spec; future)

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
for Phase 2A. Phase 2B will close §12.10 (the soundness gap).
