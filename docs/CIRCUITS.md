# Circuit specifications

Each of the four circuits is a self-contained Cargo crate under
`circuits/`. The Rust API surface is identical across all four
(`Witness`, `PublicInputs`, `Params`, `commit`, `validate`, `prove`,
`verify`), which means the prover binary dispatches each leaf without
knowing the specific circuit — only the circuit ID byte.

## Phase 2A status disclosure

All four circuits currently ship a **placeholder proving path** that
produces a 120-byte `StubProof` binding the witness commitment to the
public-inputs digest through Rescue. This is sufficient infrastructure
to exercise the prover binary, manifest builder, verifier, and TS CLI
end-to-end, but the bytes are **not a STARK**. Counterparty verifiers
refuse `mode: "stub"` manifests by default. Phase 2B replaces the
placeholder with real Winterfell AIRs — each circuit's `prove.rs`
documents the constraints the AIR must enforce.

## Cross-circuit invariants

| Invariant | Where enforced |
|---|---|
| Witness value is bound to public commitment via `Rescue(COMMITMENT_TAG ‖ u32_len ‖ value ‖ nonce)` | `circuits/common/src/commitment.rs::compute_commitment` |
| Per-leaf nonce is HKDF-derived (32 bytes) | `circuits/common/src/seed.rs::derive_leaf_seed` |
| Witness value is auto-zeroed on drop | `Zeroize` impl on each `Witness` |
| `params_hash` is SHA-256 over canonical params encoding | each circuit's `Params::hash()` |
| Cross-language params_hash agreement (TS ↔ Rust) | [`tests/kat/params_hash.json`](../tests/kat/params_hash.json) + `prover/tests/params_hash_kat.rs` + `cli/src/__tests__/paramsHash.test.ts` |

## Circuit 1 — `preimage_knowledge`

**Crate:** [`circuits/preimage_knowledge`](../circuits/preimage_knowledge/src/lib.rs)
**Circuit ID:** 4

**Statement.** I know `(value, nonce)` such that
`Rescue(COMMITMENT_TAG ‖ u32_le(value.len()) ‖ value ‖ nonce) == commitment`.

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

**Phase 2B AIR (TODO):**
1. Rescue permutation trace over `(value_padded ‖ nonce)` equals
   `commitment`.
2. `len(value) ≤ max_value_bytes` (range check via boolean
   decomposition).

## Circuit 2 — `tier_threshold`

**Crate:** [`circuits/tier_threshold`](../circuits/tier_threshold/src/lib.rs)
**Circuit ID:** 3

**Statement.** I know `(tier, nonce)` such that
`Rescue(COMMITMENT_TAG ‖ u32_le(1) ‖ tier ‖ nonce) == commitment`,
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

**Phase 2B AIR (TODO):**
1. `(tier − 1)(tier − 2)(tier − 3) = 0` enforces `tier ∈ {1,2,3}`
   (boolean decomposition product gadget).
2. `tier − min_tier = slack` with `slack ∈ {0, 1, 2}` enforces the
   threshold (another product gadget).
3. Rescue commitment opens correctly.

## Circuit 3 — `age_threshold`

**Crate:** [`circuits/age_threshold`](../circuits/age_threshold/src/lib.rs)
**Circuit ID:** 1

**Statement.** I know `(dob_days, nonce)` such that
`Rescue(COMMITMENT_TAG ‖ u32_le(8) ‖ dob_days_le ‖ nonce) == commitment`,
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

**Phase 2B AIR (TODO):**
1. Rescue commitment opens correctly over `(dob_days, nonce)`.
2. Subtraction trace: `current_epoch_days − dob_days = age_days`.
3. Range check on `slack = age_days − min_age_days` proves `slack ≥ 0`
   (boolean decomposition over ~22 bits — `MAX_PLAUSIBLE_DAYS` is
   3,652,500, roughly year 9999).

## Circuit 4 — `set_membership`

**Crate:** [`circuits/set_membership`](../circuits/set_membership/src/lib.rs)
**Circuit ID:** 2

**Statement.** I know `(value, nonce, merkle_path)` such that
`Rescue(COMMITMENT_TAG ‖ u32_le(value.len()) ‖ value ‖ nonce) == commitment`
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

**Phase 2B AIR (TODO):**
1. Rescue commitment opens correctly over `(value_padded, nonce)`.
2. `Rescue(SET_LEAF_TAG ‖ value_felts) == leaf` (first leaf hash).
3. For each of `set_depth` rounds: `parent = Rescue(SET_NODE_TAG ‖ a ‖ b)`
   with `(a, b) = side ? (sibling, node) : (node, sibling)` (conditional
   swap).
4. After `set_depth` rounds, the resulting node equals `set_root`.

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

| Crate | Test counts |
|---|---|
| `circuits/common` | 51 — domain-tag distinctness, NFC, hash determinism, commitment construction, stub-proof framing, hex roundtrip |
| `circuits/preimage_knowledge` | 11 |
| `circuits/tier_threshold` | 13 |
| `circuits/age_threshold` | 13 |
| `circuits/set_membership` | 15 |
| `bundle-format` | 18 — leaf hash, sorted Merkle, manifest sentinel signing, ed25519 verify |
| `tools/list-commit` (lib + integration) | 18 — NFC dedupe, source-SHA-256, cross-tool root agreement with prover |
| `prover` (lib) | 30 — errors, NDJSON IO, signing helpers, secretbox encrypt/decrypt, job parsing, dispatch, manifest builder |
| `prover` (integration) | 6 — full pipeline, determinism canary, skip-proofs roundtrip, three predicate-failure paths |
| `prover` (KAT) | 1 — cross-language params_hash bridge |
| `verifier` (lib) | 2 — wallet decode |
| `verifier` (integration) | 10 — happy + 7 tamper scenarios + 2 list-swap |
| `cli` (TypeScript) | 11 — record validation outcomes, params_hash matches KAT |
| **Total** | **199** (188 Rust + 11 TS) |
