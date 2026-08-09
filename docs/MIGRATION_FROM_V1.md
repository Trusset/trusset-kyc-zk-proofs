# Migrating from v1

v2.0.0 is breaking on internals but preserves the v1 CLI surface and the
batched index CSV consumed by the Trusset uploader. Tier-1 banks running
v1 in production should be able to switch with config + env-var changes
only - no upstream pipeline edits required.

The eleven things you need to know.

## 1. v1 keccak hashes are not interoperable with v2

A v1 `kycHash` (32-byte keccak Merkle root over `keccak256(abiEncode(field,
value))` leaves) **cannot** be re-derived from v2 outputs. The two
algorithms hash different things - v2 binds each leaf to a STARK proof,
v1 did not. Re-running a subject through v2 produces a fresh `kycHash`
that is unrelated to whatever v1 produced.

Operators with v1 hashes already published on-chain keep using v1 of the
tool to re-verify them. New subjects go through v2.

## 2. CLI verbs preserved; one alias removed

| v1 | v2 |
|---|---|
| `npm start` | `npm start` (unchanged) |
| `npm start -- --raw` | `npm start -- --raw` (unchanged) |
| `npm run decrypt` | `npm run decrypt` (semantics change - see §3) |
| `npm run decrypt` alias `verify` | **removed**. `npm run verify -- <wallet>` is now the counterparty bundle verifier |
| `npm run show` | `npm run show` (output format extended) |
| - | `npm start -- --skip-proofs` (new) |

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
readability but is otherwise ignored - v2 always uses Rescue-Prime over
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
STARK-bound leaf hashes (spec §7-§8). The Trusset upload API that
consumed v1 hex roots continues to work without changes - the column
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
AND at least one failed - partial), 1 (no successes, batch-aborting).
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
| Counterparty verify | - | `npm run verify -- <wallet> --public-key <hex>` |
| Iteration speed | - | `npm start -- --skip-proofs` |

## 13. v2 commitment-formula bump (CIRCUITS_VERSION 1 → 2)

Phase 2B Step-B replaces the byte-level v1 commitment with a felt-level
Rescue commitment over a domain-separated input vector (`COMMITMENT_TAG ‖
circuit_id ‖ length ‖ padded_witness ‖ nonce`). Every commitment value
for every leaf in every circuit changes - bundles produced by v1 cannot
be verified by v2 binaries and vice versa.

Operator actions on upgrade:

- **Re-run `trusset-list-commit`** for every list-commitment file (e.g.
  `country_allowlist.json`, `document_types.json`). The
  `set_leaf_digest` formula incorporated a `0x01` collision-prevention
  suffix in Stage 9, then a fixed-felt-count padding change in Stage 12.
  Any list-commit JSON produced before Stage 12 is byte-incompatible
  with v2 prover/verifier binaries.
- **Discard all v2-pre-Stage-12 bundles**. The CIRCUITS_VERSION bump
  invalidates them at the manifest level.
- **Stage 16 (SHIPPED 2026-05-20)** changed `set_leaf_digest` to use
  the padded witness (12 felts) so the off-AIR and in-AIR set_leaf
  values agree. The `set_membership` AIR now enforces the full
  Merkle-walk predicate in-AIR (commitment opening + set_leaf hash +
  conditional-swap Merkle walk to set_root). Operator action: re-run
  `trusset-list-commit` for every list-commitment file. Existing v2
  bundles with `set_membership` proofs are invalidated at the leaf
  level (different `set_leaf` → different inclusion proof → different
  `proof_digest` → different `leaf_hash`) and must be re-proven.
  CIRCUITS_VERSION stays at 2 (no JSON wire-format change; only the
  internal `set_leaf` hash value shifts).
- **Stage 17 (SHIPPED 2026-05-20)** added in-AIR length-range
  enforcement to `preimage_knowledge`. The AIR now enforces
  `value_len_bytes + slack = AIR_MAX_VALUE_BYTES (= 128)` via 8-bit
  boolean decomposition. **No operator action required**: bundle wire
  format is unchanged (PublicInputs canonical bytes still just the
  commitment digest), existing v2 bundles validate as before, and
  CIRCUITS_VERSION stays at 2. The off-AIR `Params::max_value_bytes`
  may still be configured per-operator for the `validate()` check,
  but the AIR enforces `≤ 128`. To change the AIR's max length,
  modify `AIR_MAX_VALUE_BYTES` in
  [circuits/preimage_knowledge/src/air.rs](../circuits/preimage_knowledge/src/air.rs)
  and re-prove affected bundles.

## 14. Production mode flip (Stage 23, SHIPPED 2026-05-20)

The workspace default flipped from stub-proofs to real Winterfell
STARK proofs. Operator-visible changes:

- **`manifest.mode`**: default value flipped from `"stub"` to
  `"production"`. With `--skip-proofs` the operator can still
  produce stub bundles (mode stays `"stub"`).
- **`manifest.stark.library`**: flipped from `"winterfell-stub"` to
  `"winterfell-0.13"`.
- **Verifier default**: strict mode (`accept_stub = false`) is now
  the default. The `--strict` flag is kept as a no-op; the new
  `--accept-stub` flag opts in to accepting stub bundles.

**Operator actions**:

1. Existing v2 bundles produced before Stage 23 carry
   `mode: "stub"` and will be rejected by post-Stage-23 verifiers
   in strict mode (the default). Either re-prove them
   (`npm start` regenerates with `mode: "production"`) or run the
   verifier with `--accept-stub` for backward compatibility.
2. The TS CLI `verify <wallet>` command no longer accepts stub
   bundles by default. Pass `--accept-stub` to retain the old
   permissive behavior, e.g. for development bundles produced with
   `--skip-proofs`.
3. The Rust verifier CLI `trusset-verifier-cli` no longer accepts
   stub bundles by default. The `--strict` flag remains a no-op for
   backward compatibility with existing operator scripts.
4. No new env vars, no config-schema changes, no
   `CIRCUITS_VERSION` bump. Pure value-level flip on the existing
   `mode` and `library` fields.
5. Prove time per leaf increased from ~120 bytes (stub) to ~16-30 KB
   of real STARK bytes per leaf. Per-leaf prove time scales with the
   circuit (tier ~540 ms, age ~200 ms, preimage ~250 ms, set ~1 s
   depth-2; rough release-mode numbers). The canary's two-run
   determinism guarantee is preserved.

Equivalent prove commands across versions:

| Phase 2A (stub) | Phase 2B post-Stage-23 (production) |
|---|---|
| `npm start` (mode=stub) | `npm start` (mode=production) |
| - | `npm start -- --skip-proofs` (mode=stub for development) |
| `npm run verify -- <wallet>` (accepts stub) | `npm run verify -- <wallet>` (rejects stub by default) |
| `npm run verify -- <wallet> --strict` (rejects stub) | `npm run verify -- <wallet>` (same, default) |
| - | `npm run verify -- <wallet> --accept-stub` (development) |

Stub-mode bundles (`manifest.mode == "stub"`) produced during Phase 2B
Step-A or Step-B development are not signed for production and can be
discarded freely.

## 15. v2.0 to v2.1: root computation, key wrapping, and schema additions

v2.1.0 changes how `kycHash` is computed, how per-subject key material is
derived, and what `manifest.json` records. Existing bundles keep
verifying; new issuance produces different roots for the same input.

### What changes a `kycHash` value

Two independent changes make a v2.1 bundle's root differ from what v2.0
would have produced for the same subject and inputs:

1. **`merkleVersion: 2`.** The subject tree pads to a power of two with a
   domain-separated padding leaf and binds the leaf count and arity into
   a root wrap, replacing v1's last-node duplication. See
   [CIRCUITS.md](CIRCUITS.md) for the construction and the three
   ambiguities it removes.
2. **`CIRCUITS_VERSION` 2 to 3.** The `set_membership` AIR gained the
   Merkle-walk carry binding, and `circuits_version` is folded into every
   per-subject HKDF info string, so every commitment and therefore every
   leaf hash changes.

**Existing bundles are unaffected.** A manifest with no `merkleVersion`
field means version 1, and the v1 computation is retained; a manifest with
`circuitsVersion: 2` is verified against the frozen pre-v2.1
`set_membership` AIR. Both selections are automatic.

**Re-registering on chain is per-subject and optional.** An operator who
re-issues a subject under v2.1 gets a new `kycHash` and must publish it;
one who does not re-issue keeps the old root, which keeps verifying. There
is no flag day.

### Key derivation: `secretsKdfVersion` 1 to 2

Nonces no longer derive from the master key. Each subject gets an
independent `subject_key`; the master key wraps it inside `secrets.enc`
and derives nothing else. Under `security.deterministic: true` the subject
key is itself HKDF-derived so runs stay byte-identical; under
`deterministic: false` it is drawn from OS entropy. The full chain and the
honest limits of the wrapping under deterministic mode are in
[SECURITY.md](SECURITY.md).

`secrets.enc` gains a leading version byte and a wrapped-key block. v1
blobs still decrypt: the path is selected by `manifest.secretsKdfVersion`.

New in v2.1, rotating the master key no longer requires re-proving:

```bash
TRUSSET_KYC_MASTER_KEY=<old-hex> \
TRUSSET_KYC_NEW_MASTER_KEY=<new-hex> \
  trusset-prover --rekey-subject output/0xWALLET
```

Only `secrets.enc` is rewritten. The manifest, its signature, `kycHash`,
and every proof file are untouched. v1 bundles must be re-proved to move
to a new master key.

### `config_hash` now varies with the config

Before v2.1, `canonicalConfigHash` passed a key array as
`JSON.stringify`'s replacer. An array replacer filters keys at every
nesting depth, so the serialized payload was a constant and `config_hash`
was the same value for every possible config: the documented HKDF binding
never held, and changing `predicates` did not re-key anything. v2.1
serializes with sorted keys at every depth, so the hash now genuinely
tracks the config.

For operators this means: **editing `config.json` now changes every
subject's derived key material**, as the documentation always claimed it
would. Bundles issued before v2.1 carry `secretsKdfVersion: 1` and the
legacy constant, and decrypt unchanged.

`manifest.json` now records `configHash`, so decryption and re-keying no
longer depend on out-of-band knowledge of the config that produced a
bundle.

### Manifest schema additions (all optional)

| Field | Level | Meaning |
|---|---|---|
| `merkleVersion` | top | Root construction; absent means 1 |
| `configHash` | top | The config hash folded into the KDF chain |
| `disclosure` | leaf | `plaintext`, `predicate`, or `commitment_only` |
| `params` | leaf | Resolved predicate parameters, e.g. `{"minAgeDays": 6570}` |

Every addition is optional-with-omission. A v2.0.0 manifest parses,
re-serializes byte-identically, and keeps its signature valid under v2.1
code - enforced by `v200_manifest_reserializes_byte_identically` against a
real v2.0.0 fixture. The verify path accepts both `2.0.0` and `2.1.0`.

**Counterparties running their own verifier must rebuild it.** A verifier
that re-serializes the typed manifest struct to recompute the signing view
will drop fields it does not know about and compute the wrong bytes. For
the Trusset issuer backend this means re-vendoring the WASM via
[`scripts/rebuild-wasm.sh`](../scripts/rebuild-wasm.sh) and widening its
`manifestVersions` and `circuitsVersions` anchors.

### Verification: anchors are now explicit

`npm run verify` previously required `--public-key`. It now accepts either
anchor and requires at least one:

| Situation | Command |
|---|---|
| The root is known from chain | `npm run verify -- <wallet> --root 0x<64-hex>` |
| Offline bundle, root not known | `npm run verify -- <wallet> --public-key <hex>` |
| Both | pass both flags; both are checked |
| Neither | usage error, exit 64 |

Exit codes are unchanged: 0 pass, 2 fail, 66 unreadable bundle.
`VerifyReport` gains `anchor`, `root_anchor_valid`, and
`manifest_version`; consumers parsing that JSON should tolerate the new
keys.

### New predicate capabilities

- A field may carry **several predicate instances**. Write an array:
  `"dateOfBirth": [{"circuit":"age_threshold","params":{"minAgeYears":18}},
  {"circuit":"age_threshold","params":{"minAgeYears":21}}]`. The first
  instance keeps the bare field name; later ones get a deterministic
  params-derived suffix (`dateOfBirth@7665d`) that is filesystem-safe and
  becomes the `.bin` basename.
- `"circuit": "commitment_only"` produces a hiding commitment and a leaf
  hash with no STARK. `config.example.json` now uses it for `firstName`,
  `lastName`, `documentType`, and `documentNumber`. **Existing
  `config.json` files are untouched** - the default for a field that
  already specifies `preimage_knowledge` is unchanged.

### Behavior fixes worth knowing about

- `--no-deterministic` previously parsed but did nothing. It now flows
  into the job spec and stamps `"deterministic": false` into the manifest.
- `--isolate` was dead and has been removed.
- A record missing a value for a configured predicate field used to abort
  the entire batch. It is now quarantined into `failures.csv` like any
  other bad row.
- A prover that died before emitting any event used to produce exit 0. It
  now reports the failure.
- The `leaf_proved` NDJSON event was declared on both sides but never
  emitted. It is now emitted with real `proof_bytes` and `ms`, to stdout
  and to `audit.log`.

Equivalent commands across versions:

| v2.0 | v2.1 |
|---|---|
| `npm run verify -- <wallet> --public-key <hex>` | same, or `--root 0x<hex>` |
| (no equivalent) | `trusset-prover --rekey-subject output/0xWALLET` |
| single predicate per field | array of predicate instances per field |
| `preimage_knowledge` for identity fields | `commitment_only` in the example config |
