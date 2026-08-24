# Circuit specifications

Each of the four circuits is a self-contained Cargo crate under
`circuits/`. The Rust API surface is identical across all four
(`Witness`, `PublicInputs`, `Params`, `commit`, `validate`, `prove`,
`verify`), which means the prover binary dispatches each leaf without
knowing the specific circuit - only the circuit ID byte.

## Status disclosure (v2.1.0)

**Trusset KYC v2.1 ships real Winterfell STARK proofs by default.** The
workspace default features are `prod-proofs-*` and `manifest.mode`
defaults to `"production"`. Counterparty verifiers default to strict mode
(`accept_stub = false`).

| Circuit | AIR state | Predicate state |
|---|---|---|
| `tier_threshold` | Real commitment-opening AIR (16-col x 32-row, 2-block Rescue) | **Full in-AIR predicate** (Pattern A walks for `tier in {1,2,3}` and `slack in {0,1,2}`) |
| `age_threshold` | Real commitment-opening AIR (34-col x 32-row, 2-block Rescue) | **Full in-AIR predicate** (22-bit boolean range decomposition on `slack = age_days - min_age_days`) |
| `preimage_knowledge` | Real commitment-opening AIR (28-col x 64-row, 4-block Rescue + 16 bit columns) | **Commitment opening only.** The 16-bit length decomposition is present but does not constrain the witness - see the circuit section below |
| `set_membership` | Real commitment opening + set_leaf hash + conditional-swap Merkle walk with carry binding (33-col x 2048-row) | **Full in-AIR predicate** since circuitsVersion 3 |

**Leaf modes.** A leaf is produced in one of two modes, recorded in
`manifest.leaves[].disclosure`:

| Mode | Proof file | What is proved |
|---|---|---|
| Predicate leaf (`predicate` or `plaintext`) | Real STARK bytes | The circuit's statement below |
| `commitment_only` | Zero-length sentinel | Nothing in-circuit. The hiding commitment and the leaf hash are computed and enter the Merkle root exactly as for any other leaf |

`commitment_only` exists because `preimage_knowledge` proves nothing a
counterparty can act on (see below). It removes the proving cost and the
proof bytes while preserving the binding that actually matters: the value
is committed, and that commitment is in `kycHash`.

**Development path**: `npm start -- --skip-proofs` emits zero-byte proof
files for every leaf and `manifest.mode == "stub"`. These verify only
under `--accept-stub`. A production-mode bundle carrying an empty proof on
a predicate leaf is rejected outright, so stub and `commitment_only`
cannot be confused.

## Cross-circuit invariants

| Invariant | Where enforced |
|---|---|
| Witness value is bound to public commitment via `Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(circuit_id) ‖ Felt(witness_felts.len()) ‖ witness_felts ‖ bytes_to_field(nonce))` (v2, felt-level - see `docs/STEP_2B_COMMITMENT_DESIGN.md`) | `circuits/common/src/commitment.rs::compute_commitment` |
| Per-leaf nonce is HKDF-derived (32 bytes) | `circuits/common/src/seed.rs::derive_leaf_seed` |
| Witness value is auto-zeroed on drop | `Zeroize` impl on each `Witness` |
| `params_hash` is SHA-256 over canonical params encoding | each circuit's `Params::hash()` |
| Cross-language params_hash agreement (TS ↔ Rust) | [`tests/kat/params_hash.json`](../tests/kat/params_hash.json) + `prover/tests/params_hash_kat.rs` + `cli/src/__tests__/paramsHash.test.ts` |

## Circuit 1 - `preimage_knowledge`

**Crate:** [`circuits/preimage_knowledge`](../circuits/preimage_knowledge/src/lib.rs)
**Circuit ID:** 4

**Statement, formally.** The AIR establishes exactly:

> There exist felts `w[0..20]` and `n[0..5]` such that
> `Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(4) ‖ Felt(20) ‖ w ‖ n) == commitment`,
> and there exist 16 boolean values `b[0..16]` whose weighted sums satisfy
> `sum(len_bits) + sum(slack_bits) = 128`.

**What that does and does not establish.** It establishes that the prover
knows an opening of the public commitment under the correct tag, circuit
id, and length prefix. It does **not** establish:

- **Canonical encoding.** Nothing binds the absorbed felts to
  `witness_to_felts(value)`. The `0x01` suffix, the 7-byte chunking, and
  the zero padding are prover-side conventions with no AIR counterpart.
  Contrast `set_membership`, which does bind its witness columns.
- **A length bound.** The 16 bit columns are constant and boolean, and
  nothing ties them to the witness. `len_bits = 0, slack_bits = 128`
  satisfies the row-0 constraint for any value whatsoever. The real
  `len(value) <= max_value_bytes` check lives off-AIR in `validate()`,
  which is prover-side. The trace builder's own comment concedes it
  "reads `value.len()` directly - the prover is trusted to use the actual
  byte length".

**Therefore:** a counterparty learns that the operator knows an opening of
a commitment the operator itself generated. That is not a claim about the
subject. The circuit's residual value is non-malleability of the
commitment within the bundle, which `commitment_only` provides for free.

**Private witness:**
- `value: Vec<u8>` - variable-length UTF-8 (NFC-normalized upstream)
- `nonce: [u8; 32]` - derived from the per-subject key

**Public inputs:** `commitment: Digest`

**Params:**
- `max_value_bytes: usize` (default 128). Enforced by `validate()`, not
  by the AIR.

**Recommended use.** `config.example.json` maps `firstName`, `lastName`,
`documentType`, and `documentNumber` to `commitment_only` rather than to
this circuit. An operator config that already uses `preimage_knowledge`
keeps working unchanged; the default was not altered for existing
deployments.

## Mode - `commitment_only`

**Statement, formally.** None. No STARK is produced.

The leaf computes the same hiding commitment any other leaf would:

```text
commitment = Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(4)
                    ‖ Felt(witness_to_felts(value).len())
                    ‖ witness_to_felts(value) ‖ bytes_to_field(nonce))
```

and the same `publicDigest` shape as `preimage_knowledge`
(`Rescue(PUBLIC_DIGEST_TAG ‖ commitment_be32)`), then the same leaf hash,
and it takes its place in the Merkle tree indistinguishably from a
predicate leaf.

**On-disk representation.** `proofs/<leaf>.bin` is present and
**zero-length**. The file exists so the bundle layout stays uniform for
every consumer that enumerates `proofPath`; the manifest records
`disclosure: "commitment_only"`, and the leaf hash binds
`proofDigest = Rescue(PROOF_DIGEST_TAG ‖ [])`. The verifier accepts an
empty proof only for this mode or for a `mode: "stub"` bundle, and
rejects it anywhere else.

The zero-length sentinel was chosen over omitting the file because the
issuer backend tolerates a leaf whose bytes are absent from a request
(it falls back to the signed `proofDigest`) but the frontend enumerates
`*.bin` files when assembling an upload; a present-but-empty file keeps
both paths working without special cases.

**Manifest circuit identity.** `commitment_only` leaves record
`circuit: "preimage_knowledge"` and `circuitId: 4`. Consumers that
validate circuit names against a fixed set - the Trusset issuer backend
does - would reject an unknown name. The mode is carried by `disclosure`.

## Circuit 2 - `tier_threshold`

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
- `min_tier: u8` (must equal `PublicInputs::min_tier` - drift is
  rejected by `validate`)

**Phase 2B AIR (`--features prod-proofs-tier`)**:
1. ✓ Rescue commitment opens correctly (shipped Stage 4; 12-col × 32-row
   trace, 2 Rescue blocks).
2. ✓ `(tier − 1)(tier − 2)(tier − 3) = 0` enforces `tier ∈ {1,2,3}`
   (shipped Stage 5 as Pattern A accumulator walk over 3 transitions -
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

## Circuit 3 - `age_threshold`

**Crate:** [`circuits/age_threshold`](../circuits/age_threshold/src/lib.rs)
**Circuit ID:** 1

**Statement.** I know `(dob_days, nonce)` such that the v2 commitment opens:
`Rescue(bytes_to_field(COMMITMENT_TAG) ‖ Felt(1) ‖ Felt(1) ‖ [Felt(dob_days)] ‖ bytes_to_field(nonce)) == commitment`,
`current_epoch_days ≥ dob_days` (no time travel),
and `current_epoch_days − dob_days ≥ min_age_days`.

Operating on days rather than seconds keeps the range-check cost low
(~22 bits for plausible date ranges vs. ~37 bits for second precision).

**Private witness:**
- `dob_days: u64` - days since Unix epoch
- `nonce: [u8; 32]`

**Public inputs:**
- `commitment: Digest`
- `min_age_days: u64`
- `current_epoch_days: u64` - supplied by the operator at proving time
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

## Circuit 4 - `set_membership`

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
- `value: Vec<u8>` - UTF-8 (NFC-normalized)
- `nonce: [u8; 32]`
- `merkle_path: Vec<PathStep>` - sibling digests + side bits, length
  `set_depth`

**Public inputs:**
- `commitment: Digest`
- `set_root: Digest`
- `set_depth: u8` ≤ `MAX_SET_DEPTH` (32)

**Params:**
- `list_id: String` - identifier referencing
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

**In-AIR statement, formally (circuitsVersion 3).** The AIR establishes:

> There exist `(w, n, side_bits[0..d], siblings[0..d])` such that
> 1. `Rescue(COMMITMENT_TAG ‖ Felt(2) ‖ Felt(12) ‖ w ‖ n) == commitment`
>    (rows 0..44),
> 2. `set_leaf = Rescue(SET_LEAF_TAG ‖ w)` over the **same** `w`, bound
>    across both phases by the witness columns 12..24 (rows 45..89),
> 3. starting from `carry[0] = set_leaf`, for each level k the merge
>    `Rescue(SET_NODE_TAG ‖ a ‖ b)` under the conditional swap on
>    `side_bits[k]` yields `carry[k+1]`, and
> 4. `carry[d] == set_root` at row `90 + 30d - 1`.

Step 3's carry chain is what makes this a membership proof. Before
circuitsVersion 3 the carry and sibling columns were unconstrained
placeholders, so the walk started from an arbitrary witnessed value
rather than from the committed value's `set_leaf`. Because the allowlist
and its whole tree are public, a prover could commit to a **non-member**
and replay any real member's path: every merge constraint and the
`set_root` boundary still passed. The circuit proved "some valid path
exists in this public tree", not "the committed value is in it".

The v3 constraints, in
[`circuits/set_membership/src/air.rs`](../circuits/set_membership/src/air.rs):

```text
result[COL_CARRY_START + c] =
      sel_merge_setup_a * (next[carry + c] - current[4 + c])
    + sel_level_const   * (next[carry + c] - current[carry + c])
result[COL_SIBLING_START + c] =
      sel_level_const   * (next[sib + c]   - current[sib + c])
result[COL_SIDE_BIT] =
      sel_merge_setup_a * side * (side - 1)
    + sel_level_const   * (next[side] - current[side])
```

At each merge setup the incoming carry must equal the previous row's
`state[4..8]`, which is the `set_leaf` digest at level 0 and level k-1's
merged output afterwards. Within a level, side, sibling, and carry are
constant, so the `setup_a` and `absorb_b` halves consume the same
witnessed sibling.

`v3_rejects_nonmember_grafted_onto_member_walk_while_v2_accepts` in
[`circuits/set_membership/src/lib.rs`](../circuits/set_membership/src/lib.rs)
builds that exact forgery - a non-member commitment spliced onto a real
member's walk - and asserts the frozen v2 AIR accepts it while v3 rejects
it. It is both the regression test for the fix and the demonstration that
the gap was real.

**Verifying older bundles.** Bundles with `manifest.circuitsVersion == 2`
were proved under the pre-v2.1 constraint set and are verified against the
frozen copy in
[`circuits/set_membership/src/air_v2.rs`](../circuits/set_membership/src/air_v2.rs),
selected automatically by the verifier. Those proofs carry the weaker
property described above; re-issue the subject under v2.1 to upgrade it.

## Leaf hash construction (spec §7)

Every leaf, regardless of which circuit produced its proof and of
whether it carries a proof at all, is folded into a uniform leaf hash:

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

Two constructions exist, selected by `manifest.merkleVersion`.

**Version 2 (absent field means version 1; v2 is the v2.1.0 default):**

```text
1. Sort the [Digest; n] leaves by their big-endian byte representation.
2. Pad the sorted layer to next_power_of_two().max(2) with
   pad = Rescue(MERKLE_PAD_TAG ‖ leaf_count_le8).
3. Pair adjacent nodes; within a pair the smaller hash goes first;
   merge with Rescue(NODE_TAG ‖ a ‖ b). No layer is ever odd.
4. root = Rescue(MERKLE_ROOT_TAG ‖ inner_root ‖ leaf_count_le8 ‖ arity_u8)
```

**Version 1 (pre-v2.1 bundles, retained for verification):** identical
through step 3 except that an odd layer duplicates its last node
(`hash_two(x, x)`) instead of padding, there is no root wrap, and a
single-leaf tree returns the leaf itself as the root.

The v2 changes exist to remove three structural ambiguities:

| v1 weakness | v2 fix |
|---|---|
| A leaf set and the same set plus a duplicate of its largest leaf produce the same root | Power-of-two padding; no node is ever hashed with itself |
| The root commits to neither leaf count nor arity, so structurally different trees are indistinguishable from the root | Both bound into the root wrap |
| A one-leaf root is a bare `LEAF_TAG` digest, so a leaf is directly interpretable as a root | The wrap makes leaf and root digests disjoint |

Padding leaves are domain-separated from real leaves, so a padding node
can never be presented as a member. The sort key is the leaf hash's
32-byte serialization, not the field name, so the tree is a function of
the leaf multiset alone; `compute_root` returns `sorted_indices` and the
prover reorders `manifest.leaves[]` to match.

Coverage in [`bundle-format/src/merkle.rs`](../bundle-format/src/merkle.rs)
spans 1, 2, 3, 5, 7, 8, and 9 leaves, cross-count distinctness,
second-preimage resistance, padding-leaf separation, and a test that
reproduces the v1 duplication collision and asserts v2 does not have it.

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
release-mode tests run: tier 40+5, age 27+5, preimage 32+5, set 37+5 -
all green in both debug AND release builds (Stage 15a's prove+verify
chain in the test wrapper closes the prior release-only false-positive).

Full feature-permutation sweep:

```bash
bash scripts/ci_smoke.sh           # full back-to-back sweep
bash scripts/ci_smoke.sh --quick   # default-features only
```

## What v3 added, and what it did not

v3 changed **nothing inside any circuit**. The four AIRs, the felt-level
commitment scheme, the leaf-hash construction for a v2 leaf, the Merkle
construction, and `CIRCUITS_VERSION` (3) are all exactly as they were at
v2.1.0. A v2 bundle's leaf hashes, root, and signature are unchanged under v3
tooling, which is enforced by
[`bundle-format/tests/v200_backward_compat.rs`](../bundle-format/tests/v200_backward_compat.rs)
against a real v2.0.0 fixture.

What changed is what each leaf records about the statement it is making.

### The binding digest

A v3 leaf carries a `binding` block — a claim descriptor, a validity interval,
and for `set_membership` a list-version reference — hashed into

```text
binding_digest = Rescue(TRUSSET-KYC-V3:LEAF-BIND ‖ canonical_json(binding))
```

and appended to the leaf-hash preimage:

```text
leaf_hash = Rescue(
              LEAF_TAG
              ‖ len_le(field_name) ‖ field_name_bytes
              ‖ circuit_id u8
              ‖ len_le(wallet_bytes) ‖ wallet_bytes
              ‖ epoch_days_le8
              ‖ commitment_be32
              ‖ public_digest_be32
              ‖ proof_digest_be32
              [‖ binding_digest_be32]     v3 only
            )
```

The digest is appended only when the block is present, so a leaf without one
hashes over exactly the v2 preimage. Whether a given leaf has one is read from
the manifest, so there is no ambiguity about which preimage to reconstruct.

Editing a descriptor therefore changes the leaf hash, the Merkle root, and the
signature. A descriptor that could be swapped freely would be decoration, not
evidence.

### Claim descriptors

```text
descriptor.legalBasis     framework, reference, assertion
descriptor.issuingParty   name, identifierScheme, identifier, jurisdiction
descriptor.evidenceClass  one of six
descriptor.evidenceRef    optional operator-side case reference
```

`evidenceClass` is a labelled taxonomy, not a scale: `SELF_ATTESTED`,
`DOCUMENTARY`, `THIRD_PARTY_RELIANCE`, `AUTHORITATIVE_SOURCE`,
`CRYPTOGRAPHIC`, `PHYSICAL_PRESENCE`. Nothing in the codebase compares two of
them and no predicate accepts an evidence-class threshold — deliberately, so
it does not become another anonymous integer like `minTier: 2` was.

`issuingParty` defaults to the bundle issuer. A different party is for
reliance arrangements, where another regulated firm did the verification.

### Validity intervals

```text
validity.from        first epochDay the claim is asserted for, inclusive
validity.until       last epochDay, inclusive; absent means open-ended
validity.basisAsOf   the epochDay the underlying evidence was examined
```

`basisAsOf` is not `from`. A passport checked in January and used for a March
issuance has January in `basisAsOf` and March in `from`; the gap is the
staleness a reviewer wants to see, so it is recorded rather than assumed zero.

None of this is proved in any circuit. A validity interval is a signed
assertion by the issuer about the window over which it stands behind a claim,
exactly as `softExpiryDays` always was — the difference is that it is bound
into the root, it names a real date rather than a day count from an unstated
origin, and something evaluates it.

### The tier ordering, stated

`tier_threshold` proves `tier ≥ min_tier` by constraining `tier - min_tier`
to `{0, 1, 2}` inside the AIR, with `NONE = 0` rejected at witness
construction. The ordering is a property of the circuit, not configurable
metadata, and v3 does not change it.

The tiers are the MiFID II client-categorisation set, which v3 says out loud
in the descriptor rather than leaving `minTier: 2` to be guessed at. The
ordering is sound for the predicate the circuit proves — a sophistication
floor — with three limits worth stating so a reviewer does not have to derive
them:

- A per-se professional and one who opted up under Annex II §II.1 are both
  `2` and carry materially different protections.
- Elective ECP status is instrument- and service-specific, not a global
  property of a client.
- On a protection-owed axis the ordering inverts: `RETAIL` carries the most.

Record the per-se/elective distinction in `descriptor.legalBasis.reference`
where it matters.

`minTier: RETAIL` asserts nothing: the circuit already refuses to prove
`NONE`, so it is true of every provable tier.
