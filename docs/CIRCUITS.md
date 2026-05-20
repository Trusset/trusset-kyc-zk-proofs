# Circuit specifications

Each of the four circuits is a self-contained Cargo crate under
`circuits/`. The Rust API surface is identical across all four
(`Witness`, `PublicInputs`, `Params`, `commit`, `validate`, `prove`,
`verify`), which means the prover binary dispatches each leaf without
knowing the specific circuit — only the circuit ID byte.

## Phase status disclosure (Phase 2B Step-B, 2026-05-20, Stage 23 complete)

**Trusset KYC v2 ships real Winterfell STARK proofs by default.** All
four circuits are at full in-AIR cryptographic soundness, the workspace
default features flipped to `prod-proofs-*`, and `manifest.mode` now
defaults to `"production"`. Counterparty verifiers default to strict
mode (`accept_stub = false`).

| Circuit | AIR state | Predicate state |
|---|---|---|
| `tier_threshold` | Real commitment-opening AIR (16-col × 32-row, 2-block Rescue) | **Full in-AIR predicate** (Pattern A walks for `tier ∈ {1,2,3}` and `slack ∈ {0,1,2}`) |
| `age_threshold` | Real commitment-opening AIR (34-col × 32-row, 2-block Rescue) | **Full in-AIR predicate** (22-bit boolean range decomposition on `slack = age_days − min_age_days`) |
| `preimage_knowledge` | **Real commitment-opening + 8-bit length-range AIR (28-col × 64-row, 4-block Rescue + 16-col bit decomposition)** (Stage 22, shipped 2026-05-20) | **Full in-AIR predicate** — `value_len_bytes + slack = AIR_MAX_VALUE_BYTES = 128`, enforced by 16-bit boolean decomposition at row 0 |
| `set_membership` | **Real commitment opening + set_leaf hash + conditional-swap Merkle walk AIR (33-col × 2048-row, 7 Rescue blocks for commit/setleaf + 2 blocks per Merkle level)** (Stage 21, shipped 2026-05-20) | **Full in-AIR predicate** — Merkle walk reaches `set_root` at the depth-dependent boundary row |

**Development path**: `npm start -- --skip-proofs` emits zero-byte
proof files and `manifest.mode == "stub"`. These bundles verify only
under `--accept-stub` (verifier development flag). The cryptographic
chain (signature, merkle root, leaf hash) remains intact in stub mode;
only the AIR proof bytes are zeroed.

**AIR-time negative-witness sweep coverage** confirms the AIRs reject
spec-violating witnesses (not just `validate()` doing the work): each
circuit has 4–5 negative tests that bypass `validate()`, call
`prover::build_proof` directly, then chain `verifier::verify_proof` (the
prove → verify chain rejects in both debug AND release builds —
Winterfell's debug-only `debug_assert!` is no longer the sole signal).

## Cross-circuit invariants

| Invariant | Where enforced |
|---|---|
| Witness value is bound to public commitment via `Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(circuit_id) ‖ Felt(witness_felts.len()) ‖ witness_felts ‖ bytes_to_field(nonce))` (v2, felt-level — see `docs/STEP_2B_COMMITMENT_DESIGN.md`) | `circuits/common/src/commitment.rs::compute_commitment` |
| Per-leaf nonce is HKDF-derived (32 bytes) | `circuits/common/src/seed.rs::derive_leaf_seed` |
| Witness value is auto-zeroed on drop | `Zeroize` impl on each `Witness` |
| `params_hash` is SHA-256 over canonical params encoding | each circuit's `Params::hash()` |
| Cross-language params_hash agreement (TS ↔ Rust) | [`tests/kat/params_hash.json`](../tests/kat/params_hash.json) + `prover/tests/params_hash_kat.rs` + `cli/src/__tests__/paramsHash.test.ts` |

## Circuit 1 — `preimage_knowledge`

**Crate:** [`circuits/preimage_knowledge`](../circuits/preimage_knowledge/src/lib.rs)
**Circuit ID:** 4

**Statement.** I know `(value, nonce)` such that the v2 commitment opens:
`Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(4) ‖ Felt(witness_to_felts(value).len()) ‖ witness_to_felts(value) ‖ bytes_to_field(nonce)) == commitment`
where `witness_to_felts(value) = bytes_to_field(value)`.

The catch-all leaf type for identity-binding fields where there is no
meaningful predicate to disclose: `firstName`, `lastName`,
`documentNumber`. Its ZK value is non-malleability plus the uniform
"every leaf is a STARK" manifest property.

**Private witness:**
- `value: Vec<u8>` — variable-length UTF-8 (NFC-normalized upstream)
- `nonce: [u8; 32]` — HKDF-derived

**Public inputs:** `commitment: Digest`

**Params:**
- `max_value_bytes: usize` (default 128). Values longer than this are
  rejected with `ValidateError::ValueTooLong`.

**Phase 2B AIR (`--features prod-proofs-preimage`)**:
1. ✓ Rescue commitment opens correctly over `witness_to_felts(value) ‖ nonce`
   (shipped Stage 11; 12-col × 64-row trace, 4 Rescue blocks; in-AIR
   absorption constraints bind each block's rate update to the witness).
2. ✗ `len(value) ≤ max_value_bytes` range check — still enforced by
   `validate()` outside the AIR. In-AIR length-range predicate is a
   Stage 17 design item (needs byte-decomposition of the witness felt
   carrying the `0x01` suffix; the suffix can land in any of 7 byte
   positions across up to 3 felts, so the constraint structure is
   non-trivial — see [STEP_2B_COMMITMENT_DESIGN.md](STEP_2B_COMMITMENT_DESIGN.md)
   for the design sketch).

## Circuit 2 — `tier_threshold`

**Crate:** [`circuits/tier_threshold`](../circuits/tier_threshold/src/lib.rs)
**Circuit ID:** 3

**Statement.** I know `(tier, nonce)` such that the v2 commitment opens:
`Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(3) ‖ Felt(1) ‖ [Felt(tier as u64)] ‖ bytes_to_field(nonce)) == commitment`,
`tier ∈ {RETAIL=1, PROFESSIONAL=2, ELIGIBLE_COUNTERPARTY=3}`,
and `tier ≥ min_tier`.

`NONE=0` is rejected at witness construction with `E_TIER_NONE`.
Operators wanting "no tier claim" semantics should remove the predicate
from `config.predicates` entirely.

**Private witness:**
- `tier: u8` ∈ `{1, 2, 3}` (NONE=0 rejected)
- `nonce: [u8; 32]`

**Public inputs:**
- `commitment: Digest`
- `min_tier: u8`

**Params:**
- `min_tier: u8` (must equal `PublicInputs::min_tier` — drift is
  rejected by `validate`)

**Phase 2B AIR (`--features prod-proofs-tier`)**:
1. ✓ Rescue commitment opens correctly (shipped Stage 4; 12-col × 32-row
   trace, 2 Rescue blocks).
2. ✓ `(tier − 1)(tier − 2)(tier − 3) = 0` enforces `tier ∈ {1,2,3}`
   (shipped Stage 5 as Pattern A accumulator walk over 3 transitions —
   `acc_tier_next = acc_tier_curr · (tier_col_curr − p_tier_periodic)`
   with `p_tier_periodic = [1, 2, 3, 0, ...]` and boundary `acc_tier[3] = 0`).
3. ✓ `tier − min_tier = slack` with `slack ∈ {0, 1, 2}` enforces the
   threshold (shipped Stage 5 as parallel Pattern A walk on `slack_col`).
4. ✓ All four predicate columns (`tier_col`, `acc_tier`, `slack_col`,
   `acc_slack`) are bound to `state[11][0]` via periodic-selector-at-row-0
   binding so the prover cannot use an arbitrary value disconnected from
   the commitment.

**Soundness state**: `tier_threshold` is at full audit-ready in-AIR
cryptographic soundness. A malicious prover cannot construct a valid
proof for any spec-violating witness (commitment mismatch caught by
Rescue collision resistance; predicate violation caught by Pattern A
boundary at row 3).

## Circuit 3 — `age_threshold`

**Crate:** [`circuits/age_threshold`](../circuits/age_threshold/src/lib.rs)
**Circuit ID:** 1

**Statement.** I know `(dob_days, nonce)` such that the v2 commitment opens:
`Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(1) ‖ Felt(1) ‖ [Felt(dob_days)] ‖ bytes_to_field(nonce)) == commitment`,
`current_epoch_days ≥ dob_days` (no time travel),
and `current_epoch_days − dob_days ≥ min_age_days`.

Operating on days rather than seconds keeps the range-check cost low
(~22 bits for plausible date ranges vs. ~37 bits for second precision).

**Private witness:**
- `dob_days: u64` — days since Unix epoch
- `nonce: [u8; 32]`

**Public inputs:**
- `commitment: Digest`
- `min_age_days: u64`
- `current_epoch_days: u64` — supplied by the operator at proving time
  per `config.security.epochDaysSource`, recorded in the manifest so
  counterparties can enforce a max staleness window

**Params:**
- `min_age_days: u64` (must equal `PublicInputs::min_age_days`)

**Phase 2B AIR (`--features prod-proofs-age`)**:
1. ✓ Rescue commitment opens correctly (shipped Stage 4; 34-col × 32-row
   trace, 2 Rescue blocks).
2. ✓ Subtraction folded into the boundary check at row 0:
   `slack = current_epoch_days − dob_days − min_age_days` (the AIR
   directly asserts the linear combination at the row-0 binding step).
3. ✓ 22-bit boolean range decomposition on `slack` proves `slack ≥ 0`
   (shipped Stage 6). 22 boolean columns (cols 12..34) each constrained
   `bit · (bit - 1) = 0` at the row-0 binding selector; one
   linear-combination constraint `slack = Σ bit_i · 2^i` ties the
   decomposition to the binding. Time travel (`dob_days > current_epoch_days`)
   and underage (`age_days < min_age_days`) both wrap field subtraction
   past `2^22`, causing the linear constraint to fail.

**Soundness state**: `age_threshold` is at full audit-ready in-AIR
cryptographic soundness. Range bound `MAX_PLAUSIBLE_DAYS = 3,652,500`
(year 9999) fits comfortably inside the 22-bit window.

## Circuit 4 — `set_membership`

**Crate:** [`circuits/set_membership`](../circuits/set_membership/src/lib.rs)
**Circuit ID:** 2

**Statement.** I know `(value, nonce, merkle_path)` such that the v2 commitment opens:
`Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(2) ‖ Felt(witness_to_felts(value).len()) ‖ witness_to_felts(value) ‖ bytes_to_field(nonce)) == commitment`
where `witness_to_felts(value) = bytes_to_field(value)`
and walking the Merkle path from
`Rescue(SET_LEAF_TAG ‖ value_canonical)` upward through the witnessed
siblings under `SET_NODE_TAG` merges yields `set_root`.

The set tree uses distinct domain tags (`SET_LEAF`, `SET_NODE`) from
the main per-subject leaf tree (`LEAF`, `NODE`) so a set leaf can never
collide with a subject leaf.

**Private witness:**
- `value: Vec<u8>` — UTF-8 (NFC-normalized)
- `nonce: [u8; 32]`
- `merkle_path: Vec<PathStep>` — sibling digests + side bits, length
  `set_depth`

**Public inputs:**
- `commitment: Digest`
- `set_root: Digest`
- `set_depth: u8` ≤ `MAX_SET_DEPTH` (32)

**Params:**
- `list_id: String` — identifier referencing
  `config.lists.<list_id>` in the operator config. Folded into
  `params_hash`.

**Set commitment generation.**
[`trusset-list-commit`](../tools/list-commit/src/lib.rs) reads a plain
text source file, NFC-normalizes each entry, builds the Rescue Merkle
tree (padding to the next power of two by duplicating the last leaf),
and emits a JSON file containing the canonical values, root, depth,
and SHA-256 of the source. The operator pins
`config.lists.<id>.sha256` and the prover refuses to start if the
on-disk file's hash drifts.

**Phase 2B AIR (`--features prod-proofs-set`)**:
1. ✓ Rescue commitment opens correctly over `(witness_to_felts(value), nonce)`
   (shipped Stage 13; 12-col × 64-row trace, 3 Rescue blocks).
2. ✗ `Rescue(SET_LEAF_TAG ‖ value_felts) == leaf` — Stage 16 design,
   not yet implemented. Will share the same padded witness via cross-phase
   binding columns; trace extends to rows 45..89.
3. ✗ Conditional-swap Merkle walk — Stage 16 design, not yet implemented.
   33-col × 2048-row trace with 4 `current_node_carry` columns that
   propagate the level-entry node through each level's 30 trace rows
   (15 rows × 2 Rescue blocks per `hash_two_with_tag` merge). Side-bit
   ∈ {0,1} per level witnessed in col 24; sibling felts in cols 25..29.
4. ✗ `set_root` boundary at row `90 + set_depth × 30 − 1` — Stage 16
   design, not yet implemented.

**Soundness state**: commitment-opening soundness in-AIR; set membership
predicate still in `validate()`. A malicious prover cannot fabricate a
proof for an arbitrary commitment, but the Merkle-side check still
relies on the `validate()` predicate (which is Phase 2B Step-A's
trust-the-prover-binary assumption). Stage 16 closes this gap fully.
See [docs/STEP_2B_COMMITMENT_DESIGN.md](STEP_2B_COMMITMENT_DESIGN.md)
Stage 16 addendum for the full implementation blueprint.

## Leaf hash construction (spec §7)

Every leaf — regardless of which circuit produced its proof — is folded
into a uniform leaf hash:

```
public_digest = Rescue(PUBLIC_DIGEST_TAG ‖ canonical(public_inputs))
proof_digest  = Rescue(PROOF_DIGEST_TAG  ‖ proof_bytes)

leaf_hash = Rescue(
  LEAF_TAG
  ‖ u32_le(len(field_name)) ‖ field_name_bytes
  ‖ circuit_id (u8)
  ‖ u32_le(len(wallet_bytes)) ‖ wallet_bytes
  ‖ u64_le(epoch_days)
  ‖ commitment (32 bytes BE-per-limb)
  ‖ public_digest (32 bytes BE-per-limb)
  ‖ proof_digest (32 bytes BE-per-limb)
)
```

Implementation: [`bundle-format/src/leaf.rs`](../bundle-format/src/leaf.rs).

Why this exact order: lex sorting of the leaf hash bytes is then a
proxy for sorting `(field_name, circuit_id, …)` so two callers
processing the same subject get the same Merkle tree shape.

## Merkle root construction (spec §8)

Implementation: [`bundle-format/src/merkle.rs`](../bundle-format/src/merkle.rs).

1. Sort the `[Digest; n]` leaves by their big-endian byte representation.
2. Pair adjacent leaves; within each pair, the smaller hash goes first.
3. Merge with `Rescue(NODE_TAG ‖ a ‖ b)`.
4. On odd-length layers, duplicate the last node before pairing.
5. Repeat until one root remains.

This preserves the v1 sorted-leaf Merkle convention: a verifier can
re-pair without tracking which side was originally left, so per-leaf
inclusion proofs are just the chain of siblings (no left/right bits).

## Determinism boundary

Everything above is deterministic given:
- The same input record set
- The same `TRUSSET_KYC_MASTER_KEY` (drives nonces)
- The same `TRUSSET_KYC_SIGNING_KEY` (drives manifest signatures)
- A pinned `config.security.epochDaysSource` (not `utc_today`)

Two such runs produce byte-identical bundles modulo the
`manifest.json::createdAt` wall-clock timestamp. See
[`tests/e2e/canary.sh`](../tests/e2e/canary.sh) for the operational
test.

## Where to find tests

Counts as of Stage 25 (2026-05-20), `cargo test --workspace --release`
under default features (post-Stage-23 = `prod-proofs-*` per circuit):

| Test surface | Count | Notes |
|---|---|---|
| `cargo test --workspace --release` | **414** | Default features now include the real Winterfell AIRs; all four circuits' lib tests + integration tests exercise prove + verify roundtrips |
| `cargo test -p trusset-circuit-tier-threshold --release` | 45 | lib + integration; includes Pattern A predicate negative-witness sweep |
| `cargo test -p trusset-circuit-age-threshold --release` | 32 | lib + integration; includes 22-bit boolean range negative-witness sweep |
| `cargo test -p trusset-circuit-preimage-knowledge --release` | 48 | lib + integration + Stage 17 reference modules (12) + Stage 17 AIR roundtrip (3) |
| `cargo test -p trusset-circuit-set-membership --release` | 93 | lib + integration + Stage 16 reference modules (16+17+14+11) + Stage 16 AIR roundtrip (3) |
| `cli` TypeScript | 11 | record validation, params_hash KAT, JSON shape |
| **Total Rust release + TS** | **425** | Default features green; no stub mode unless `--features stub-proofs --no-default-features` |

Stub-mode path (`--features stub-proofs --no-default-features`) is
preserved for development bundles via `npm start -- --skip-proofs`;
the smoke script ([scripts/ci_smoke.sh](../scripts/ci_smoke.sh))
includes a build-compat regression check for it.

With `prod-proofs-{tier,age,preimage,set}` enabled per circle, additional
release-mode tests run: tier 40+5, age 27+5, preimage 32+5, set 37+5 —
all green in both debug AND release builds (Stage 15a's prove+verify
chain in the test wrapper closes the prior release-only false-positive).

Full feature-permutation sweep:

```bash
bash scripts/ci_smoke.sh           # full back-to-back sweep
bash scripts/ci_smoke.sh --quick   # default-features only
```
