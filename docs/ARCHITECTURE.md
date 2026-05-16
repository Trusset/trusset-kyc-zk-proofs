# Architecture

A hybrid TypeScript + Rust workspace. TS owns the operator-facing CLI
and input/output orchestration. Rust owns all cryptography, proof
generation, and proof verification. The seam is a JSON-over-stdin/stdout
protocol between the TS CLI and the `trusset-prover` binary.

## Crate map

```
trusset-kyc-hashing/
├── circuits/                 # Cargo workspace member; one crate per circuit
│   ├── common/               # Shared crypto primitives, domain tags, seed derivation
│   ├── preimage_knowledge/
│   ├── tier_threshold/
│   ├── age_threshold/
│   └── set_membership/
│
├── bundle-format/            # Manifest schema, leaf/merkle, ed25519 verify
│                             # WASM-compatible (no std::fs). Consumed by both
│                             # prover and verifier.
│
├── prover/                   # `trusset-prover` binary + library
│   ├── src/main.rs           # stdin → NDJSON events on stdout
│   ├── src/job.rs            # Job spec schema
│   ├── src/dispatch.rs       # Per-leaf circuit routing
│   ├── src/encrypt.rs        # xsalsa20-poly1305 for secrets.enc
│   ├── src/sign.rs           # ed25519 signing helpers
│   └── src/bundle.rs         # Atomic per-subject directory writer
│
├── verifier/                 # `trusset-verifier-cli` binary + library + WASM cdylib
│   ├── src/lib.rs            # verify_bundle(path, opts) -> VerifyReport
│   ├── src/bundle.rs         # Disk loader
│   ├── src/wasm.rs           # wasm-bindgen entry points (gated by `wasm` feature)
│   └── src/bin/cli.rs        # CLI wrapper for the TS layer
│
├── tools/list-commit/        # `trusset-list-commit` binary
│                             # Builds list_commitments JSON from plain text source
│
├── cli/                      # TypeScript CLI (the operator-facing entry point)
│   ├── src/index.ts          # Commander wiring
│   ├── src/config.ts         # v2 config validator with v1 fallbacks
│   ├── src/recordValidation.ts  # Non-throwing per-record validation
│   ├── src/jobSpec.ts        # Build prover stdin JSON
│   ├── src/paramsHash.ts     # TS replica of each circuit's Params::hash
│   ├── src/spawnProver.ts    # child_process bridge with NDJSON event stream
│   ├── src/bundleWriter.ts   # Batched index CSV + failures.csv
│   ├── src/verify.ts         # Wraps trusset-verifier-cli binary
│   └── src/__tests__/        # node:test unit tests
│
├── config/                   # Operator configuration
│   ├── config.example.json
│   └── list_commitments/     # Pre-committed set-membership lists
│
├── tests/
│   ├── e2e/canary.sh         # Determinism canary
│   └── kat/                  # Cross-language Known-Answer Test fixtures
│
└── docs/                     # This directory
```

## Data flow — `npm start`

```
┌─────────────────┐
│ /input/*.json   │     1. Read records (BOM-safe CSV, JSON array or object)
│ /input/*.csv    │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│ cli/src/recordValidation.ts │  2. Non-throwing per-row validation
│                             │     (wallet checksum, country, expiry bounds)
└────────┬────────────────────┘
         │
         ├─→ ValidationFailures ──→  output/failures.csv (stage=validation)
         │
         ▼
┌─────────────────────────────┐
│ cli/src/jobSpec.ts          │  3. Translate config + valid records into the
│                             │     Rust prover's stdin protocol
└────────┬────────────────────┘
         │
         ▼ stdin JSON
┌─────────────────────────────┐
│ trusset-prover (Rust)       │  4. For each subject:
│   - derive subject_seed     │       a. HKDF-SHA256(master_key, …)
│   - for each leaf:          │       b. derive leaf_seed (= nonce)
│       - prove()             │       c. each circuit's prove(witness, public)
│       - leaf_hash()         │       d. spec §7 leaf hash binding
│   - sort + merkle_root()    │       e. Rescue Merkle root → kycHash
│   - build + sign manifest   │       f. ed25519 over canonical signing view
│   - encrypt secrets.enc     │       g. xsalsa20-poly1305 (HKDF-derived key)
│   - atomic bundle write     │       h. .tmp/<wallet> → rename to <wallet>
└────────┬────────────────────┘
         │ NDJSON events
         ▼
┌─────────────────────────────┐
│ cli/src/spawnProver.ts      │  5. Parse {event: start | subject_start |
│                             │           leaf_proved | subject_done |
│                             │           subject_failed | done}
└────────┬────────────────────┘
         │
         ├─→ Subject failures ──→  output/failures.csv (stage=prover)
         │
         ▼
┌─────────────────────────────┐
│ cli/src/bundleWriter.ts     │  6. Build v1-compatible batched index CSV
│                             │     from successful bundles' kycHash.hex
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│ /output/<wallet>/...        │  Final per-subject artifacts
│ /output/kyc_hashes_*.csv    │  v1-style batched summary
│ /output/failures.csv        │  if any row failed (either stage)
└─────────────────────────────┘
```

Exit codes: 0 all passed, 2 partial (≥1 success + ≥1 failure), 1
batch-aborted (no successes).

## Data flow — `npm run verify -- <wallet>`

```
┌─────────────────────────────┐
│ cli/src/verify.ts           │  1. spawn trusset-verifier-cli
│   --bundle path             │     --bundle output/<wallet>
│   --public-key <hex>        │     --public-key <op pinned key>
│   [--strict]                │     [--strict]
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│ trusset-verifier-cli        │  2. load_bundle: read manifest, sig,
│                             │     kycHash.hex, every proofs/*.bin
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│ verifier::verify_loaded     │  3. Run every check independently:
│                             │       a. layout_ok
│                             │       b. mode_acceptable (vs --strict)
│                             │       c. kycHash.hex matches manifest
│                             │       d. signature_valid (sentinel view)
│                             │       e. per-leaf: proofDigest, circuit
│                             │          verify, leafHash recompute
│                             │       f. merkle root recompute
└────────┬────────────────────┘
         │
         ▼ JSON VerifyReport
┌─────────────────────────────┐
│ cli/src/verify.ts           │  4. Pretty-print per-leaf table or
│   formatHumanReport()       │     emit JSON if --json
└─────────────────────────────┘
```

Exit codes: 0 pass, 2 fail (signature or proof check), 66 unreadable.

## Library choices

| Choice | Why |
|---|---|
| **Winterfell** (`winter-math`, `winter-crypto` 0.13) | Production-grade STARK lib used by Polygon Miden. Pure Rust, no trusted setup, post-quantum-friendly. Active maintenance |
| **Goldilocks field** (`p = 2^64 − 2^32 + 1`) | Single-word arithmetic on 64-bit CPUs; STARK-friendly modulus; matches Winterfell's optimization target |
| **Rescue-Prime 64/256** | STARK-friendly hash, ships with Winterfell. Same primitive inside and outside the AIR keeps the audit surface tight |
| **ed25519-dalek 2.x** | Standard, well-audited. Deterministic RFC 8032 signatures so bundles are byte-stable across runs |
| **xsalsa20-poly1305** (RustCrypto) | Wire-compatible with libsodium `crypto_secretbox`. Pure Rust, no C dependency, WASM-friendly |
| **HKDF-SHA256** | RFC 5869, the standard KDF. Used for both per-subject and per-leaf seed derivation |
| **`serde_json` (default features)** | `BTreeMap`-backed `Map` gives sorted JSON keys automatically — no `preserve_order` anywhere in the workspace, no manual canonicalization needed |
| **Hand-rolled CLI parsers** in Rust binaries | Both `trusset-prover` and `trusset-verifier-cli` use `std::env::args` directly. Avoids `clap`'s 40+ transitive deps and keeps each binary < 350 KB |
| **Commander.js in TS** | Used in v1; preserved to keep the CLI verb surface identical |
| **node:test** | Node 18+ built-in test runner. Zero dev-dep cost for the TS unit tests |

Explicitly avoided: Plonky3 (different field/security trade-off), Halo2
(KZG trusted setup), Groth16 (per-circuit trusted setup), RISC Zero
(non-Rescue hash), Cairo (different toolchain entirely).

## TS ↔ Rust IPC contract

**Stdin: single Job JSON object, then EOF.**

```json
{
  "version": "2.0.0",
  "deterministic": true,
  "epoch_days": 20587,
  "output_root": "/abs/path/output",
  "config_hash": "0x<64-hex>",
  "skip_proofs": false,
  "subjects": [
    {
      "subject_id": "0xAbCd...",
      "passthrough": { "country": "DEU", "investorType": "PROFESSIONAL",
                       "softExpiryDays": 365, "hardExpiryDays": 730 },
      "leaves": [
        {
          "field": "dateOfBirth",
          "circuit": "age_threshold",
          "value": "1985-04-12",
          "public": { "min_age_days": 6570 },
          "params_hash": "0x<64-hex>"
        },
        ...
      ]
    }
  ],
  "list_commitments": {
    "country_allowlist": {
      "values": ["DEU", "FRA", ...],
      "source_sha256": "0x..."
    }
  }
}
```

**Stdout: newline-delimited JSON events.**

```
{"event":"start","subjects":10}
{"event":"subject_start","subject_id":"0xAbCd..."}
{"event":"leaf_proved","subject_id":"...","field":"dateOfBirth","proof_bytes":120,"ms":1}
{"event":"subject_done","subject_id":"...","bundle_path":"output/0xAbCd..."}
{"event":"subject_failed","subject_id":"...","error_code":"E_AGE_BELOW_MIN","message":"..."}
{"event":"done","ok":9,"failed":1}
```

**Stderr.** Unstructured logs and panics, prefixed by the TS layer with
`[prover]`.

**Env vars** the TS layer forwards under canonical names regardless of
what the operator's config calls them:
- `TRUSSET_KYC_MASTER_KEY` — 32-byte hex
- `TRUSSET_KYC_SIGNING_KEY` — 32-byte hex
- `RUST_BACKTRACE=0` — pinned to keep stderr concise

## Determinism boundary

The full pipeline is deterministic given:
- Same `/input` records
- Same `TRUSSET_KYC_MASTER_KEY` and `TRUSSET_KYC_SIGNING_KEY`
- Same `config.json` (modulo cosmetic fields stripped from `config_hash`)
- Pinned `security.epochDaysSource` (not `utc_today`)

Two such runs produce byte-identical bundles modulo
`manifest.json::createdAt`. [`tests/e2e/canary.sh`](../tests/e2e/canary.sh)
is the operational check.

What about `getrandom`? The prover binary opts into a custom
`getrandom` hook (Cargo feature `["custom"]`) that panics on any OS
entropy draw when `TRUSSET_KYC_DETERMINISTIC=1` is set. CI runs with
this flag — any code path that accidentally introduces nondeterminism
aborts loudly rather than silently producing a different bundle.

## Atomicity

The prover writes each bundle into `output/.tmp/<wallet>/` and renames
to `output/<wallet>/` only after the manifest is signed. A crashed
proof leaves nothing visible in `output/`. Implementation:
[`prover/src/bundle.rs`](../prover/src/bundle.rs).

Caveat: the parent `.tmp/` directory persists across runs as an empty
shell. Harmless but a known cosmetic. Flagged for cleanup in a future
phase.

## Build flow

`scripts/build.sh` (driven by `npm install` postinstall and
`npm run build`):

1. Check `cargo` is on PATH. Fatal with a clear message if not.
2. `cargo build --release --workspace` — produces native binaries:
   `target/release/trusset-prover`, `trusset-verifier-cli`,
   `trusset-list-commit`.
3. If `wasm32-unknown-unknown` target is installed:
   `cargo build --release --target wasm32-unknown-unknown -p trusset-verifier --features wasm`
   — produces `target/wasm32-unknown-unknown/release/trusset_verifier.wasm`
   (≈325 KB).
4. `cd cli && npm install --ignore-scripts && tsc` — produces
   `cli/dist/*.js`.

The Rust workspace pins the toolchain via `rust-toolchain.toml`; the TS
side targets ES2020 + CommonJS via `cli/tsconfig.json`.
