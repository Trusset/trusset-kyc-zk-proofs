# Security model

This document describes what `trusset-kyc-hashing` v2 protects against,
what it assumes, and how the cryptographic primitives compose. It is the
primary reference for compliance reviewers and external auditors.

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Rainbow-table recovery of low-entropy fields (DOB, country, tier) given a Merkle inclusion proof | Per-leaf hiding commitment `Rescue(COMMITMENT_TAG ‖ circuit_id ‖ len ‖ value ‖ nonce)` with a 32-byte nonce derived from the per-subject key |
| Master-key compromise recovering every nonce ever issued | Nonces derive from an independent per-subject key that the master key only wraps (`secretsKdfVersion: 2`). Recovery needs both the master key and that subject's `secrets.enc`. Under `deterministic: true` the subject key is still master-derived - see "Determinism and the wrapping boundary" |
| Counterparty observing partial disclosure inferring undisclosed fields | Domain-separated leaf tags (`LEAF`, `NODE`) plus circuit ID byte in every leaf hash - siblings reveal nothing about the disclosed field |
| Cross-subject replay (proof for Alice replayed as proof for Bob) | `walletAddress_bytes` bound into every leaf hash (spec §7) |
| Cross-epoch replay (proof generated at time T verified as fresh at T+N) | `epochDays` bound into every leaf hash; operators choose `utc_today` / `fixed:<n>` / `env:<VAR>` per `security.epochDaysSource`. Counterparties enforce their own staleness window |
| Cross-circuit replay (proof for `age_threshold` re-presented as `tier_threshold`) | `CircuitId` u8 (1=age, 2=set, 3=tier, 4=preimage) bound into the leaf hash and into the commitment |
| Structural ambiguity in the subject Merkle tree (two different leaf sets yielding one root) | v2 construction pads to a power of two with a domain-separated padding leaf and binds leaf count and arity into the root wrap. Replaces v1's last-node duplication |
| A non-member value proved as an allowlist member | `set_membership` circuitsVersion 3 binds the Merkle-walk carry chain to the committed value's `set_leaf` digest. See "Allowlist membership soundness" |
| Predicate parameters silently differing from what a bundle claims | Every leaf records its resolved `params`; the verifier recomputes `paramsHash` from them and rejects a mismatch |
| Tampered list-commitments file post-prove | `config.lists.<id>.sha256` pinning, plus the prover cross-checks the committed file's declared root and depth against its own recomputation and refuses to start on drift |
| Tampered proof or manifest after signing | ed25519 signature over the canonical-JSON view of the manifest; the verifier reconstructs and re-checks. Independently, the on-chain root anchors the same bytes |
| Stub bundle relabeled as production | The `mode` field is inside the signing payload, so relabeling invalidates the signature. A production-mode bundle carrying an empty proof on a proving leaf is rejected outright |
| Lost or stolen `secrets.enc` decryption attempt without the master key | XSalsa20-Poly1305 with an HKDF-derived wrapping key; the payload key itself is wrapped, so offline brute force requires the 256-bit master key |
| Non-deterministic output (operator cannot reproduce a bundle to satisfy an audit) | Under `deterministic: true` all key material flows from `TRUSSET_KYC_MASTER_KEY` via HKDF, and `TRUSSET_KYC_DETERMINISTIC=1` makes any OS-entropy draw fail with `E_DETERMINISM_VIOLATION` |
| Proof parameters silently weakened below the advertised level | `conjectured_security_bits()` is asserted against `STARK_SECURITY_BITS` at compile time and again at prover startup (`E_WEAK_PROOF_OPTIONS`) |

### Out of scope

| Threat | Why not |
|---|---|
| Compromise of the operator's machine while the master key is loaded in memory | Tool-level mitigations (`Zeroize` on secret buffers) reduce the window, but a kernel-level adversary defeats any user-space defense. Use HSM-backed secret loading at the OS layer |
| Side-channel attacks against the Goldilocks field arithmetic | Winterfell's implementation is not constant-time; acceptable for STARK proving, which is not a real-time secret-handling operation |
| Quantum attacks on ed25519 manifest signing | ed25519 is pre-quantum. The Rescue-Prime STARK layer is post-quantum-friendly, the manifest signature is not. Root-anchored verification avoids the signature entirely when the root is known from chain |
| Formal zero-knowledge of the proof bytes | Winterfell 0.13 adds no blinding columns and proofs are deterministic in the witness. Hiding rests on the commitment nonce. See [FUTURE_WORK.md](FUTURE_WORK.md) |
| Adversary with arbitrary write access to `/output` after the prover finishes | The verifier catches tampered bytes but not deletion. Standard filesystem ACLs apply |
| KYC data ingestion (`/input` is trusted) | The tool assumes records come from a vetted source. Bad input produces validation failures, not silent acceptance |

## What the zk layer does and does not hide

The zk layer protects a field only if that field's value is not also
published outside it. Two fields in the default pipeline are published
outside it, because the issuer backend requires them: `country` is stored
on the customer record and drives transfer-rule evaluation, and
`investorType` becomes a uint8 argument to the on-chain `verifyIdentity`
call. Both appear in cleartext in the batch index CSV and in the signed
`manifest.passthrough` block.

Every leaf therefore records a `disclosure` class, so a reader of the
bundle can tell what a given proof is actually worth:

| Field | Circuit | Disclosure | What a counterparty learns |
|---|---|---|---|
| `country` | `set_membership` | `plaintext` | The exact value, from the batch CSV and `passthrough`. The proof adds integrity, not privacy |
| `investorType` | `tier_threshold` | `plaintext` | The exact value, same sources. The proof adds integrity, not privacy |
| `nationality` | `set_membership` | `predicate` | Only that it is in the committed allowlist |
| `documentIssuingCountry` | `set_membership` | `predicate` | Only that it is in the committed allowlist |
| `dateOfBirth` | `age_threshold` | `predicate` | Only that the age is at or above the recorded threshold |
| `firstName` | `commitment_only` | `commitment_only` | Only that a commitment exists and is in the root |
| `lastName` | `commitment_only` | `commitment_only` | Same |
| `documentNumber` | `commitment_only` | `commitment_only` | Same |
| `documentType` | `commitment_only` | `commitment_only` | Same |

The `country` and `investorType` rows are the honest statement of a real
limitation: **for those two fields the zero-knowledge property provides no
privacy benefit in the default Trusset pipeline**, because the plaintext
travels alongside the proof by design. Their circuits are retained because
they still bind the disclosed value cryptographically into `kycHash`, so a
counterparty can detect a CSV row that disagrees with the bundle. An
operator who does not feed the Trusset issuer backend, and therefore does
not need the plaintext, can drop those fields from `mapping` and keep only
the predicate leaves.

`softExpiryDays` and `hardExpiryDays` are passthrough only. They are never
witnessed by any circuit and are not covered by any proof, only by the
manifest signature.

## Cryptographic primitives

| Layer | Primitive | Source | Rationale |
|---|---|---|---|
| Finite field | Goldilocks (`p = 2^64 − 2^32 + 1`) | [`winter-math` 0.13.1](https://crates.io/crates/winter-math) | Native 64-bit arithmetic; STARK-friendly modulus |
| Hash | Rescue-Prime 64/256 | [`winter-crypto` 0.13.1](https://crates.io/crates/winter-crypto) | Same primitive inside and outside circuits, so one audit surface |
| STARK | Winterfell AIR | [`winterfell`](https://github.com/facebook/winterfell) | Production-grade (Polygon Miden), no trusted setup, post-quantum-friendly |
| Manifest signature | ed25519 (RFC 8032) | [`ed25519-dalek` 2.x](https://crates.io/crates/ed25519-dalek) | Deterministic, well-audited |
| Secrets encryption | XSalsa20-Poly1305 (libsodium secretbox) | [`xsalsa20poly1305` 0.9](https://crates.io/crates/xsalsa20poly1305) | Bit-compatible with libsodium; auditors can decrypt with either toolchain |
| Key derivation | HKDF-SHA256 | [`hkdf` 0.12](https://crates.io/crates/hkdf) + [`sha2` 0.10](https://crates.io/crates/sha2) | RFC 5869 |
| Canonical UTF-8 | Unicode NFC | [`unicode-normalization` 0.1](https://crates.io/crates/unicode-normalization) | Prevents `"café"` composed vs decomposed producing different proofs |

All nine 32-byte domain tags are pairwise distinct at compile time via
`static_assertions::const_assert!`:

- `TRUSSET-KYC-V2:LEAF` - subject Merkle leaf
- `TRUSSET-KYC-V2:NODE` - subject tree inner node
- `TRUSSET-KYC-V2:PUB-DIGEST` - Rescue hash of canonical public inputs
- `TRUSSET-KYC-V2:PRF-DIGEST` - Rescue hash of proof bytes
- `TRUSSET-KYC-V2:SET-LEAF` - set-membership leaf
- `TRUSSET-KYC-V2:SET-NODE` - set-membership inner node
- `TRUSSET-KYC-V2:COMMIT` - hiding commitment for `(value, nonce)`
- `TRUSSET-KYC-V2:MERKLE-PAD` - v2 padding leaf
- `TRUSSET-KYC-V2:MERKLE-ROOT` - v2 root wrap

Adding a tenth tag requires extending the `const_assert!`/`const_ne(...)`
matrix in [`circuits/common/src/domain.rs`](../circuits/common/src/domain.rs)
by nine entries. The compiler refuses to build a workspace where any two
tags are equal.

## Key derivation chain (secretsKdfVersion 2)

```
TRUSSET_KYC_MASTER_KEY (32 bytes, operator-supplied via env var)
│
│   The master key is a KEY-WRAPPING KEY. It does not derive nonces.
│
├─→ deterministic: true
│   HKDF-SHA256(salt="trusset-kyc-v2/subject-key",
│               info=subject_id ‖ epoch_days_le8 ‖ config_hash ‖ circuits_version_le4)
│   → subject_key (32 bytes, Zeroizing<>)
│
├─→ deterministic: false
│   subject_key ← OS entropy via prover/src/entropy.rs
│   (panics if TRUSSET_KYC_DETERMINISTIC=1 is set)
│
├─→ HKDF-SHA256(salt="trusset-kyc-v2/wrap-key",   info=ctx) → wrap_key
└─→ HKDF-SHA256(salt="trusset-kyc-v2/wrap-nonce", info=ctx) → wrap_nonce
        secrets.enc = version_byte(2)
                    ‖ wrap_nonce(24) ‖ secretbox(wrap_key, subject_key)(48)
                    ‖ data_nonce(24) ‖ secretbox(subject_key, secrets_json)

subject_key
│
├─→ HKDF-SHA256(salt="trusset-kyc-v2/subject",
│               info=subject_id ‖ epoch_days_le8 ‖ config_hash ‖ circuits_version_le4)
│   → subject_seed (32 bytes, Zeroizing<>)
│   │
│   └─→ HKDF-SHA256(salt="trusset-kyc-v2/leaf",
│                   info=leaf_name ‖ circuit_id ‖ params_hash)
│       → leaf_seed (32 bytes), used verbatim as the hiding-commitment nonce
│
└─→ HKDF-SHA256(salt="trusset-kyc-v2/data-nonce", info=ctx) → data_nonce

ctx = subject_id ‖ epoch_days_le8 ‖ config_hash ‖ kdf_version_le4
```

`config_hash` is SHA-256 over a canonicalized projection of the config
that excludes cosmetic fields (`output.format`, `output.includeIndex`,
`security.clearInputAfterProcessing`). Serialization sorts object keys at
every depth, so source-text key order does not affect it, and changing
`predicates` does re-key every subject.

Before v2.1 this function passed a key array as `JSON.stringify`'s
replacer. An array replacer filters keys at every nesting level, which
collapsed the payload to a constant: `config_hash` was the same value for
every possible config and the documented binding never held. Bundles
issued before v2.1 therefore carry `secretsKdfVersion: 1` and the legacy
constant; the decrypt path selects on that field and keeps working.

`circuits_version` is `3` as of v2.1.0, a compile-time constant in
[`circuits/common/src/lib.rs`](../circuits/common/src/lib.rs). Bumping it
invalidates every subject's seed simultaneously and is the right move when
changing leaf encoding, AIR constraints, or serialization.

### Determinism and the wrapping boundary

Under `security.deterministic: true` the subject key is HKDF-derived from
the master key, so an adversary holding only the master key can
reconstruct it without the bundle. The wrapping still helps - it removes
the nonce chain from anything that leaks without `secrets.enc` - but it
does not by itself defeat a master-key compromise.

**The wrapping benefit fully materializes only under `deterministic:
false`,** where the subject key comes from OS entropy and exists nowhere
except inside that subject's wrapped blob. For production issuance where
reproducibility is not an audit requirement, run with
`--no-deterministic` and back up `secrets.enc`. Determinism remains the
default because the audit and canary workflows depend on it.

### Per-subject re-key

Rotating the master key does not require re-proving:

```bash
TRUSSET_KYC_MASTER_KEY=<old-hex> \
TRUSSET_KYC_NEW_MASTER_KEY=<new-hex> \
  trusset-prover --rekey-subject output/0xWALLET
```

This unwraps the subject key under the old master key and re-wraps it
under the new one, rewriting `secrets.enc` in place. `manifest.json`,
`manifest.sig`, `kycHash.hex`, and every `proofs/<leaf>.bin` are
untouched, so the signature stays valid and the on-chain root still
matches - `secrets.enc` sits outside the signing payload by design. Only
bundles with `secretsKdfVersion: 2` support this; v1 bundles must be
re-proved to move to a new master key.

## Allowlist membership soundness

`set_membership` proves, in-AIR: the commitment opens to a witness, that
same witness hashes to a `set_leaf` digest, and a conditional-swap Merkle
walk from that digest reaches the public `set_root`.

Before circuitsVersion 3 the walk's carry and sibling columns were
unconstrained placeholders. Because the allowlist and its whole tree are
public, a prover could commit to a **non-member** value and witness any
real member's path: every merge constraint and the `set_root` boundary
passed. The circuit proved "some valid path exists in this public tree",
not "the committed value is in it". Membership was enforced only
off-AIR at prove time, by the operator the proof is meant to convince a
counterparty about.

circuitsVersion 3 adds the binding constraints: at every merge setup
transition the incoming carry must equal the previous row's `state[4..8]`
(the `set_leaf` digest for level 0, level k-1's merged output for level
k), and side, sibling, and carry are constant within each level. The
regression test
`v3_rejects_nonmember_grafted_onto_member_walk_while_v2_accepts` in
[`circuits/set_membership/src/lib.rs`](../circuits/set_membership/src/lib.rs)
constructs exactly that forgery and asserts the frozen v2 AIR accepts it
while the v3 AIR rejects it.

Bundles issued before v2.1 carry `circuitsVersion: 2` and are verified
against the frozen v2 AIR in
[`circuits/set_membership/src/air_v2.rs`](../circuits/set_membership/src/air_v2.rs),
so they keep verifying. **Their `set_membership` proofs carry the weaker
property described above.** Operators who need the stronger guarantee for
existing subjects must re-issue them under v2.1.

## Allowlist rotation

An allowlist changes when a jurisdiction is added or a sanctions list
updates. The procedure:

1. Edit `config/list_commitments/<id>.source.txt`. One entry per line,
   `#` for comments.
2. Regenerate the commitment:

```bash
cargo run --release -p trusset-list-commit -- \
  --list-id country_allowlist \
  --source config/list_commitments/country_allowlist.source.txt \
  --output config/list_commitments/country_allowlist.json
```

3. The new file carries a new `root` and a new `sourceSha256`. If
   `config.lists.<id>.sha256` is pinned, update it to the new file hash.
   The prover independently recomputes the root from the values and
   refuses to run if the file's declared root or depth disagrees, so a
   forgotten regeneration fails loudly instead of being ignored.
4. New bundles record the new root and `sourceSha256` in
   `manifest.lists.<id>` and in each `set_membership` leaf's `params`.
5. Update the counterparty's approved-root policy. For the Trusset issuer
   backend that is `approvedLists.<id>` in `config/zkTrustAnchors.js`;
   editing it changes `POLICY_VERSION`, which invalidates cached
   verification verdicts (they re-verify, they do not fail).

**Existing bundles keep verifying.** A bundle asserts membership in the
list whose root it recorded, and that statement stays true. What a
counterparty decides about an old root is policy, not cryptography: a
verifier that only accepts the current root will reject bundles issued
against the previous one, which is usually the intent for a sanctions
update. Rotating a list does not invalidate `kycHash` and does not
require re-proving unless the counterparty's policy demands the new root.

## Replay protection (spec §12.3 / §12.4)

Every leaf hash binds:

```
leaf_hash = Rescue(
  LEAF_TAG
  ‖ len(leaf_name) ‖ leaf_name_bytes
  ‖ circuit_id (u8)
  ‖ len(wallet_bytes) ‖ wallet_bytes
  ‖ epoch_days (u64 LE)
  ‖ commitment (32 bytes)
  ‖ public_digest (32 bytes)
  ‖ proof_digest (32 bytes)
)
```

A proof generated for `(leaf=dateOfBirth, wallet=0xA, epoch=20587,
circuit=age_threshold)` cannot be presented under any other tuple: the
leaf hash, the Merkle root, and the manifest signature all change.

For multi-instance predicates the leaf name carries the instance suffix
(`dateOfBirth@7665d`), so the 18-year and 21-year assertions over the same
field are distinct leaves with distinct nonces, commitments, and hashes.

## Subject Merkle tree (merkleVersion 2)

```
1. Sort leaf hashes by their 32-byte big-endian representation.
2. Pad the sorted layer to the next power of two (minimum 2) with
   pad = Rescue(MERKLE_PAD_TAG ‖ leaf_count_le8).
3. Pair adjacent nodes, smaller first, merge with Rescue(NODE_TAG ‖ a ‖ b).
   No layer is ever odd, so no node is ever duplicated.
4. root = Rescue(MERKLE_ROOT_TAG ‖ inner_root ‖ leaf_count_le8 ‖ arity_u8)
```

This fixes three structural weaknesses in v1:

- **Last-node duplication.** v1 promoted an odd layer's final node by
  hashing it with itself, so a leaf set and the same set plus a second
  copy of its largest leaf produced the identical root. The regression
  test `v1_duplicate_last_leaf_ambiguity_exists_and_v2_removes_it`
  demonstrates the collision on v1 and its absence on v2.
- **No count or arity binding.** v1 roots committed to neither, so two
  structurally different trees could not be told apart from the root.
- **Single-leaf root equal to the leaf.** A v1 one-leaf tree returned the
  leaf digest itself as the root, making a `LEAF_TAG` digest directly
  interpretable as a root. The v2 wrap makes them distinct.

Padding leaves are domain-separated from real leaves, so a padding node
can never be presented as a member.

Existing bundles carry no `merkleVersion` field, which means version 1;
the v1 computation is retained and selected automatically. See
[MIGRATION_FROM_V1.md](MIGRATION_FROM_V1.md).

## Verification anchors

A bundle is only meaningful relative to something that says who issued it.
The verifier accepts two anchors and requires at least one:

- **`--root 0x<64-hex>`** - the `kycHash` the caller read from chain. The
  on-chain root already authenticates the bundle, so no key pinning is
  needed. This is the right anchor for any counterparty that can read the
  chain.
- **`--public-key <hex>`** - the operator's ed25519 key, pinned out of
  band. This is for offline bundles whose root is not independently
  known.

Supplying both checks both. Supplying neither is a usage error (exit 64),
not a silent pass: a bundle verified against no anchor proves only
internal self-consistency, which an adversary who rewrote the whole bundle
can also produce. `VerifyReport.anchor` records which was used.

## `secrets.enc` and recovery

The encrypted secrets blob carries the plaintext value of each witnessed
field, the 32-byte commitment nonce, and the circuit name.

Decryption requires the master key, plus `subject_id`, `epoch_days`, and
`config_hash` - all readable from `manifest.json`, which now records
`configHash` directly rather than requiring out-of-band knowledge of it.

### Recovery procedure

1. If only `manifest.json` is corrupted: re-run `npm start` against the
   original `/input` records. With `deterministic: true` and a pinned
   `epochDaysSource` the new bundle is byte-identical modulo `createdAt`.
2. If `secrets.enc` is corrupted but the input records are intact: same
   as above.
3. If `secrets.enc` is lost AND the input records are gone: there is no
   recovery under `deterministic: true` only if the master key is also
   gone; the bundle can otherwise be regenerated. Under `deterministic:
   false` the subject key existed only in that blob, so the values are
   unrecoverable and the subject must be re-run from the originating
   sources.

Back up `secrets.enc` like any other operator-private artifact. Under
non-deterministic issuance it is the only copy of the subject key.

## Timestamp exclusion (spec §12.8)

The manifest carries the real wall-clock `createdAt`, but the ed25519
signature is computed over a canonical view with `createdAt` overwritten
to `"1970-01-01T00:00:00Z"`. The verifier performs the same overwrite
before checking. Two runs at different times differ only in that field;
`manifest.sig` is byte-identical.

[`tests/e2e/canary.sh`](../tests/e2e/canary.sh) runs the two-run
comparison and asserts byte-equality modulo `createdAt`.

## Determinism enforcement (spec §12.8)

[`prover/src/entropy.rs`](../prover/src/entropy.rs) is the only path to OS
entropy in the prover. It refuses to draw when
`TRUSSET_KYC_DETERMINISTIC=1` is set, returning
`E_DETERMINISM_VIOLATION`. The CLI exports that variable for the child
process whenever `security.deterministic` is true, so a deterministic run
that reaches for randomness fails loudly instead of producing a bundle
that cannot be reproduced.

`--no-deterministic` opts out: the per-subject key is drawn from OS
entropy, `TRUSSET_KYC_DETERMINISTIC` is not exported, and
`"deterministic": false` is stamped into the manifest so a downstream
verifier can tell which mode produced the bundle.

Earlier documentation described a custom `getrandom` hook registered in
`prover/Cargo.toml`. No such hook existed in the code; the guarded
entropy module is its replacement and is exercised by tests.

## Schema evolution and the counterparty WASM

Every v2.1 manifest addition is optional-with-omission, so a v2.0.0
manifest parses, re-serializes byte-identically, and keeps its signature
valid under v2.1 code. This is enforced by
`v200_manifest_reserializes_byte_identically` in
[`bundle-format/tests/v200_backward_compat.rs`](../bundle-format/tests/v200_backward_compat.rs)
against a real v2.0.0 fixture.

This matters beyond convenience: the Trusset issuer backend verifies
bundles through a vendored WASM build of this repo's verifier, which
recomputes the signing view by re-serializing the typed struct. Any signed
field the vendored artifact does not know about would be silently dropped
there, and every production signature would fail. Adding a field to the
signed manifest therefore requires re-vendoring the backend's WASM via
[`scripts/rebuild-wasm.sh`](../scripts/rebuild-wasm.sh) as part of the same
change.

## What v2.1 does NOT yet protect

- **Formal zero knowledge.** Proofs carry no blinding and are
  deterministic in the witness; hiding rests on the commitment nonce.
  See [FUTURE_WORK.md](FUTURE_WORK.md).
- **Post-quantum manifest signing.** ed25519 is pre-quantum. Root-anchored
  verification sidesteps it when the root is known from chain.
- **HSM integration.** The master key arrives via env var. HSM backing is
  the spec §17 workstream; the API surface stays the same.
- **`preimage_knowledge` semantics.** What that circuit does and does not
  establish is documented in [CIRCUITS.md](CIRCUITS.md); it is the reason
  `commitment_only` exists.

**Development bundles** (`npm start -- --skip-proofs`) emit
`manifest.mode == "stub"` with zero-byte proof files. Counterparty
verifiers reject them by default; `--accept-stub` opts in. A
production-mode bundle with an empty proof on a proving leaf is rejected
outright, so the two cannot be confused.
