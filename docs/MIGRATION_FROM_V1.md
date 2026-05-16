# Migrating from v1

v2.0.0 is breaking on internals but preserves the v1 CLI surface and the
batched index CSV consumed by the Trusset uploader. Tier-1 banks running
v1 in production should be able to switch with config + env-var changes
only — no upstream pipeline edits required.

The eleven things you need to know.

## 1. v1 keccak hashes are not interoperable with v2

A v1 `kycHash` (32-byte keccak Merkle root over `keccak256(abiEncode(field,
value))` leaves) **cannot** be re-derived from v2 outputs. The two
algorithms hash different things — v2 binds each leaf to a STARK proof,
v1 did not. Re-running a subject through v2 produces a fresh `kycHash`
that is unrelated to whatever v1 produced.

Operators with v1 hashes already published on-chain keep using v1 of the
tool to re-verify them. New subjects go through v2.

## 2. CLI verbs preserved; one alias removed

| v1 | v2 |
|---|---|
| `npm start` | `npm start` (unchanged) |
| `npm start -- --raw` | `npm start -- --raw` (unchanged) |
| `npm run decrypt` | `npm run decrypt` (semantics change — see §3) |
| `npm run decrypt` alias `verify` | **removed**. `npm run verify -- <wallet>` is now the counterparty bundle verifier |
| `npm run show` | `npm run show` (output format extended) |
| — | `npm start -- --skip-proofs` (new) |

If any of your scripts call `npm run verify`, double-check what behavior
you actually wanted. v1 `verify` was an alias for `decrypt` (re-hash and
compare); v2 `verify` is the counterparty path that validates a bundle
against a pinned public key.

## 3. `npm run decrypt` semantics changed

In v1, `decrypt` read input records that had a `kycHash` column and
re-keccak-hashed them to confirm the column matched. v2 redefines it
(per spec §10) as a full round-trip via the encrypted secrets blob:
decrypt `secrets.enc`, re-prove every leaf, recompute the Merkle root,
and compare to `kycHash.hex`. This is the operator's self-audit path.

v2 `decrypt` is currently a stub in the TypeScript CLI (the Rust
integration test already exercises the round-trip end-to-end). Wiring it
into the TS layer is tracked as Phase 6B.

## 4. New required env vars

```bash
export TRUSSET_KYC_MASTER_KEY=$(openssl rand -hex 32)   # 32-byte hex
export TRUSSET_KYC_SIGNING_KEY=$(openssl rand -hex 32)  # 32-byte hex
```

Both are required. Missing → fatal before any I/O. Names can be
overridden via `config.security.masterKeyEnv` and
`config.manifest.signingKeyEnv`.

The master key derives all per-subject and per-leaf nonces via
HKDF-SHA256. The signing key feeds ed25519. Lose either and you cannot
reproduce bundles byte-for-byte; lose the master key and you cannot
decrypt previously-written `secrets.enc` files.

## 5. New required toolchain

- Rust 1.75 or newer
- The `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- Node.js 18 or newer

The `postinstall` script builds the Rust workspace, the WASM verifier, and
the TS CLI. Cold install takes a few minutes; incremental rebuilds are
fast.

## 6. New required config sections

| Section | Required? | Behavior if absent |
|---|---|---|
| `mapping` | required (v1) | unchanged |
| `output` | required (v1) | unchanged |
| `security` | required (v1) | `masterKeyEnv` / `epochDaysSource` / `deterministic` default if missing |
| `predicates` | optional | spec §5 defaults applied per field; the prover refuses to start if a field has no circuit assigned |
| `tiers` | optional | defaults to `{ NONE:0, RETAIL:1, PROFESSIONAL:2, ELIGIBLE_COUNTERPARTY:3 }` |
| `lists` | required if any `set_membership` predicate is configured | fatal otherwise |
| `manifest` | optional | `signingKeyEnv` defaults to `TRUSSET_KYC_SIGNING_KEY` |

The presence of v1's `security.hashAlgorithm` field is honored for
readability but is otherwise ignored — v2 always uses Rescue-Prime over
the Goldilocks field. You'll see one warning per run.

## 7. Output shape change: bundles + batched CSV

v1 emitted only `/output/kyc_hashes_<timestamp>.csv`. v2 emits **both**:

- A per-subject directory: `/output/<wallet>/{manifest.json, manifest.sig,
  kycHash.hex, proofs/<field>.bin, secrets.enc}`
- The v1-style batched index CSV with identical columns
  (`walletAddress, country, investorType, softExpiryDays,
  hardExpiryDays, kycHash`)

Set `output.emitIndexCsv: false` in `config.json` to suppress the CSV if
your Trusset uploader has been updated to walk per-subject bundles.

## 8. `kycHash` column semantics

In v1 the column held a keccak Merkle root over field-level keccak
leaves. In v2 it holds the Rescue-Prime Merkle root over the per-leaf
STARK-bound leaf hashes (spec §7–§8). The Trusset upload API that
consumed v1 hex roots continues to work without changes — the column
format is unchanged (0x-prefixed 64-char hex). What's different is what
the hex commits to.

## 9. Stub mode (`--skip-proofs`)

For CI smoke runs or iteration speed during Phase 2B AIR development:

```bash
npm start -- --skip-proofs
```

Emits zero-byte `proofs/*.bin` files. The manifest's `mode` stays
`"stub"`. Counterparty verifiers reject these bundles by default
(strict mode); operators wanting to test against them must explicitly
opt in via `--strict` toggled off (the verifier's default).

## 10. Determinism guarantee

With `security.deterministic: true` (the default) and a pinned
`epochDaysSource` (`fixed:<n>` or `env:<VAR>` instead of `utc_today`),
two runs over the same input on the same master + signing keys produce
byte-identical bundles for every artifact except `manifest.json`'s
`createdAt` field. The signing payload uses a sentinel timestamp, so
`manifest.sig` is also byte-identical.

The repo ships [`tests/e2e/canary.sh`](../tests/e2e/canary.sh) that runs
the full pipeline twice and asserts byte-equality. Run it after any
upgrade.

## 11. Failure semantics

v1 threw on the first invalid record, aborting the whole batch. v2
isolates failures into two stages:

- **Validation failures** (bad wallet, missing country, expiry overflow)
  are caught in TypeScript before the prover spawns. Each bad row is
  appended to `output/failures.csv` with `stage=validation`.
- **Prover failures** (under-age, country not in allowlist, tier=NONE)
  are isolated per-subject. The rest of the batch continues. Each bad
  row is appended to the same `failures.csv` with `stage=prover`.

Exit codes: 0 (everything succeeded), 2 (at least one subject succeeded
AND at least one failed — partial), 1 (no successes, batch-aborting).
Update your CI checks accordingly.

## 12. Lost `secrets.enc` is unrecoverable

There is no key escrow. Lose `secrets.enc` for a subject and you cannot
re-prove their leaves, cannot run the `decrypt` self-audit, and cannot
serve a counterparty's "show me the proof for field X" request. The
bank's only option is to re-run KYC for that subject from the original
data sources.

Back up `secrets.enc` files the same way you back up any other
operator-private data.

## Quick reference: equivalent v1 / v2 commands

| Task | v1 | v2 |
|---|---|---|
| Hash a batch | `npm start` | `npm start` |
| Hash without index column | `npm start -- --raw` | `npm start -- --raw` |
| Show config | `npm run show` | `npm run show` |
| Self-audit | `npm run decrypt` (re-keccak vs `kycHash` column) | `npm run decrypt` (decrypt secrets, re-prove, compare) |
| Counterparty verify | — | `npm run verify -- <wallet> --public-key <hex>` |
| Iteration speed | — | `npm start -- --skip-proofs` |
