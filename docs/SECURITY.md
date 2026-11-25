# Security model

This document describes what `trusset-kyc-hashing` v3.1 protects against, what
it assumes, and how the cryptographic primitives compose. It is the primary
reference for compliance reviewers and external auditors.

v3.1 binds every bundle to one IdentityHub attestation through a signed header,
removes clear-text personal values from bundles, gives every leaf an inclusion
path so a holder can disclose one leaf at a time, names the hub predicate each
leaf proves, and keeps the operator key in an encrypted key file or the macOS
keychain. It changes nothing inside the circuits, and it does not make proofs
zero-knowledge: read "What a proof reveals" before deciding who may see a
proof.

v3 recorded who is responsible for a bundle's assertions, what legal test each
predicate stands for, how long each claim holds, which list version a proof
used, and what was true at a past moment. Those sections are unchanged.

## v3.1 at a glance

| Property | How |
|---|---|
| A bundle matches only its own hub attestation | The signed header names root, wallet, epochDays, attester, chainId, hub, keyId, merkleVersion and leafCount. `verify --rpc-url` reads the hub and compares |
| No clear-text personal value in a bundle | `country` and `investorType` are predicate leaves; `passthrough` holds only `softExpiryDays` and `hardExpiryDays`; the prover refuses anything else (`E_PASSTHROUGH_REFUSED`) |
| One leaf can be checked on its own | Merkle v3 inclusion path, signed header, `verify_disclosure` |
| A leaf cannot be relabelled | `binding.predicate` is inside the binding digest, so inside the leaf hash and the root |
| A disclosure cannot pick a weaker circuit | Its circuits version is fixed by the signed header version (3.1.0 means 3), never read from the disclosure |
| One spelling per document | 3.1.0 manifests and disclosures must equal their typed form (no unknown keys, no nulls); every digest is lowercase canonical hex; proof bytes must be the canonical serialization of the proof |
| Operator key at rest | scrypt (N = 2^17, r = 8, p = 1) and ChaCha20-Poly1305, or the macOS keychain; environment variables for CI only |
| Revocation | The hub's `revoke`, `suspend` and `erase` are the authority; `config/registry/revocations.json` is the operator's own record |

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Rainbow-table recovery of low-entropy fields (DOB, country, tier) from a commitment or a Merkle inclusion path (not from a predicate proof, see "What a proof reveals") | Per-leaf hiding commitment `Rescue(COMMITMENT_TAG ‖ circuit_id ‖ len ‖ value ‖ nonce)` with a 32-byte nonce derived from the per-subject key |
| Master-key compromise recovering every nonce ever issued | Nonces derive from an independent per-subject key that the master key only wraps (`secretsKdfVersion: 2`). Recovery needs both the master key and that subject's `secrets.enc`. Under `deterministic: true` the subject key is still master-derived - see "Determinism and the wrapping boundary" |
| Counterparty shown one leaf inferring the undisclosed fields | Inclusion-path siblings are leaf hashes and inner nodes over salted commitments, with domain-separated tags (`LEAF`, `NODE`) and the circuit id in every leaf hash, so they reveal nothing about the other fields. The disclosed leaf's own proof does reveal its value ("What a proof reveals") |
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
| Non-deterministic output (operator cannot reproduce a bundle to satisfy an audit) | Under `deterministic: true` all key material flows from `TRUSSET_KYC_MASTER_KEY` via HKDF, and `TRUSSET_KYC_DETERMINISTIC=1` makes any OS-entropy draw fail with `E_DETERMINISM_VIOLATION`. Since v3, `epochDaysSource: "utc_today"` is refused outside an explicit development flag: it is the other way a bundle becomes unreproducible, and it was the shipped default through v2.1 |
| A bundle whose assertions nobody is accountable for | v3 manifests record `issuer`: the institution's name, identifier scheme and value, supervising jurisdiction, signing-key id, and public key |
| A threshold with no stated meaning (`minTier: 2`) | Every v3 leaf carries a claim descriptor naming the legal basis, the warranting party, and the evidence class, hashed into the leaf and therefore into `kycHash` |
| A list root whose contents nobody retained | The signed append-only list registry keeps every version that was ever authoritative, with its values; each leaf records the version it used |
| A claim that stopped being true, or was never true | Separate signed revocation records distinguish `lapsed` from `void_ab_initio`. Neither edits the bundle, both are surfaced by the verifier |
| Silent substitution of a compliance-relevant input | An `investorType` or expiry value that is present but unrecognised quarantines the row instead of taking the configured default. Through v2.1 a mistyped tier was silently recorded as the default and signed |
| A witness value leaking through a failure report | Prover failure messages name the leaf and the asserted threshold, never the subject's value. `output/failures.csv` travels; through v2.1 it recorded lines like `value 'BRA' not in list` |
| A manifest whose `proofPath` escapes the bundle directory | `proofPath` is the only manifest field that reaches the filesystem, and a manifest is untrusted input. Every read path, the verifier's loader, the archive builder, and the archive's own structure check, requires a plain `proofs/<name>` entry with no separators, parent references, or leading dot, so a hand-written manifest cannot make a verifier read outside the bundle |
| Proof parameters silently weakened below the advertised level | `conjectured_security_bits()` is asserted against `STARK_SECURITY_BITS` at compile time and again at prover startup (`E_WEAK_PROOF_OPTIONS`) |

### Out of scope

| Threat | Why not |
|---|---|
| Compromise of the operator's machine while the master key is loaded in memory | Tool-level mitigations (`Zeroize` on secret buffers) reduce the window, but a kernel-level adversary defeats any user-space defense. Use HSM-backed secret loading at the OS layer |
| Side-channel attacks against the Goldilocks field arithmetic | Winterfell's implementation is not constant-time; acceptable for STARK proving, which is not a real-time secret-handling operation |
| Quantum attacks on ed25519 manifest signing | ed25519 is pre-quantum. The Rescue-Prime STARK layer is post-quantum-friendly, the manifest signature is not. Root-anchored verification avoids the signature entirely when the root is known from chain |
| Hiding the witness from whoever holds a predicate proof | Winterfell 0.13 has no zero-knowledge mode. A predicate proof discloses its value; see "What a proof reveals". Hiding rests on the commitment nonce and on who is given a proof |
| Adversary with arbitrary write access to `/output` after the prover finishes | The verifier catches tampered bytes but not deletion. Standard filesystem ACLs apply |
| KYC data ingestion (`/input` is trusted) | The tool assumes records come from a vetted source. Bad input produces validation failures, not silent acceptance |

## What a proof reveals

**Winterfell 0.13 has no zero-knowledge option.** Checked in the 0.13.1
sources: `ProofOptions::new` takes no hiding flag, the prover draws no
randomness, and trace and constraint commitments are unsalted Merkle trees.
Enabling hiding would need new AIRs with randomized trace rows (for
`age_threshold` and `tier_threshold` that means editing their `air.rs`), so
v3.1 does not enable it and there is no circuitsVersion 4. Proof bytes are a
deterministic function of the witness and the nonce.

A proof carries every trace column evaluated at an out-of-domain point `z` and
at `z * g` (the OOD frame), the full trace rows at 27 queried positions of the
low-degree extension with their Merkle paths, the composition polynomial at the
same points, and the FRI layers. Anyone can recompute `z` by replaying the
public transcript, as the verifier does. What that discloses, per circuit:

| Circuit | Revealed to anyone holding the proof | How |
|---|---|---|
| `set_membership` | **The committed value** (the country code of an `EEA_RESIDENT` or `RESIDENCY_ON_FILE` leaf) | Witness columns 12..24 are constant over all rows, so their OOD values are the witness field elements in the clear. No transcript replay needed. `circuits/set_membership/tests/proof_disclosure.rs` reads `DEU` out of the EEA vector proof |
| `age_threshold` | **The exact date of birth** | Rows 1..31 of the 22 slack-bit columns hold a fixed public pattern, so row 0 is the only unknown in each column polynomial and one OOD value solves it. The bits give `currentEpochDays - dob - minAgeDays`. `circuits/age_threshold/tests/proof_disclosure.rs` recovers the date from the proof alone |
| `tier_threshold` | The exact tier | The tier column holds the tier on rows 0..2 and a public pattern after; same method. For an `INVESTOR_CLASS` leaf the tier equals the attested class, so nothing beyond the attestation leaks; for an `ACCREDITED` leaf with a fixed floor it does |
| `preimage_knowledge` | Treat the value as revealed | The length bits are constant columns; the 64-row Rescue columns are nearly determined by the revealed evaluations. Not used by the shipped configs |
| `commitment_only` | Nothing beyond the commitment | No proof is produced. The commitment is Rescue over the value and a 32-byte per-leaf nonce, which is not in the bundle |

So a predicate leaf proves its predicate *and* hands its value to whoever gets
its proof. In practice:

- Give a predicate proof only to a party entitled to the value. The issuer
  backend already holds the values; a bank relying on a holder's disclosure
  learns the value of each leaf it is shown, not of the others.
- What goes on chain is unaffected: the hub stores the root, the class, the
  predicate bits and the dates. Proofs never go on chain, and the root links
  to nothing once the issuer deletes the bundle secrets.
- Names and document numbers are `commitment_only` and stay hidden.
- Two bundles for the same subject, date, and key produce identical proof
  bytes, so a holder of both can tell whether a value changed. Under
  `security.deterministic: false` the nonces, and with them the proofs,
  differ per issuance.

Commitments keep their 32-byte nonce. Hiding proofs are tracked in
[FUTURE_WORK.md](FUTURE_WORK.md).

## What the root authenticates, and what the signatures do

A verifier anchored only on the on-chain root (`--root`) checks the leaf set:
every leaf's commitment, public inputs, proof, binding block, predicate, and
so the investor class and the predicate bits. It does not check the manifest
signature or the header signature, so it does not authenticate the `chain`
block, the header, or the expiry days in `passthrough`. Anchor on the operator
key as well (or use `verify --rpc-url`, which takes the key and the root from
the hub) before relying on those. A backend that builds the attest calldata
from `attestation_from_manifest` should verify the bundle under the attester's
key first.

## Disclosure in a 3.1.0 bundle

| Field | Leaf | Predicate | In clear text anywhere |
|---|---|---|---|
| `country` | `set_membership` on `eea` (optional) | `EEA_RESIDENT` | No. Revealed by its proof (above) |
| `country@country_allowlist` | `set_membership` on `country_allowlist` | `RESIDENCY_ON_FILE` | No. Revealed by its proof |
| `nationality` | `set_membership` | `CITIZENSHIP_ON_FILE` | No. Revealed by its proof |
| `documentIssuingCountry` | `set_membership` | none | No. Revealed by its proof |
| `dateOfBirth` | `age_threshold` | `ADULT` | No. Revealed by its proof |
| `investorType` | `tier_threshold`, `minTier` = the subject's class | `INVESTOR_CLASS` | The class is the attestation's `investorClass`, on chain by design |
| `firstName`, `lastName`, `documentType`, `documentNumber` | `commitment_only` | none | No |

The batch index CSV of a 3.1.0 run has no `country` column. `softExpiryDays`
and `hardExpiryDays` remain passthrough settings, covered by the manifest
signature only.

Bundles before 3.1.0 carry `country` and `investorType` in clear text in
`passthrough` and in the index CSV, and mark those leaves `plaintext`.

## Operator keys

The operator key signs manifests, headers, and registry records. With it sits
the master key that wraps each subject's key in `secrets.enc`.

| `security.keyStore` | Storage |
|---|---|
| `{ "type": "file", "path": ".trusset/operator.key" }` | Both keys in one file, encrypted with ChaCha20-Poly1305 under a key derived from a passphrase with scrypt (N = 2^17, r = 8, p = 1, 32-byte salt). The format, public key, and KDF parameters are the AEAD's associated data, so editing any of them fails decryption. Mode 0600. Passphrases under 12 characters are refused |
| `{ "type": "keychain" }` | The macOS keychain, service `trusset-kyc-operator`. Written through `security -i` on stdin, so the secret is never in a process argument list |
| absent | `TRUSSET_KYC_SIGNING_KEY` and `TRUSSET_KYC_MASTER_KEY`. For CI only |

The passphrase is read from the terminal without echo, or from
`TRUSSET_KYC_KEY_PASSPHRASE` for one unattended command. The CLI hands the
decrypted keys to the Rust binaries on the first line of their stdin
(`TRUSSET_KYC_KEYS_STDIN=1`), never through the environment or a file.
`npm run key -- create | encrypt | show` creates a key, moves existing keys
into a store, and prints the public key, the hub `keyId`, and the
`setAttesterProfile` calldata.

**Rotation.** Publishing a new key with `setAttesterProfile` makes the hub
assign the next `keyId` and keep the old one at `operatorKeyAt(attester,
oldKeyId)`. Headers name their `keyId`, so roots issued under an older key keep
verifying against the key that signed them.

## Revocation

The hub is the authority: `revoke`, `suspend`, and `erase` by the attester end
reliance on an attestation for every on-chain reader, and `verify --rpc-url`
reports the hub status. `config/registry/revocations.json` remains the
operator's signed record of lapses and voidances, used for as-of answers from
an archive. It does not change what the hub says; record a revocation in both.

## Format strictness in 3.1.0

- Manifests and disclosures must equal their own typed form: an unknown key
  anywhere, or an explicit null, is refused.
- `publicInputs` and `params` have a fixed key set per circuit, `proofPath` is
  `proofs/<fieldName>.bin`, and `disclosure` is `predicate` or
  `commitment_only`.
- Every digest is `0x` + 64 lowercase hex of a canonical field element.
- `publicDigest` is recomputed from `publicInputs`, and an age leaf's
  `currentEpochDays` must equal the batch date.
- `params` must agree with `publicInputs` for every manifest version. Before
  this check a root-anchored bundle could carry `params` and a matching
  `paramsHash` for a threshold its proof was not made for.
- `proofDigest` packs bytes into field elements with zero padding and no
  length prefix, and Winterfell ignores bytes after a proof, so a proof with a
  trailing zero byte has the same digest and verifies as the same proof. 3.1.0
  requires proof bytes to be exactly the serialization of the proof they
  decode to.
- Merkle v3, the `chain` block, and `binding.predicate` are valid only in a
  3.1.0 manifest, so a 3.1.0 manifest relabelled as 3.0.0 fails.
- The header signature is checked with strict ed25519 (weak keys and
  non-canonical signatures refused).

`verifier/tests/v31_tamper_matrix.rs` mutates disclosures, headers, paths,
proofs, and manifests from a fixed seed (`TRUSSET_FUZZ_ITERS` scales it) and
requires every mutation to be refused or to leave the meaning unchanged.

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
| Address checksums (TS) | keccak-256 | [`@noble/hashes` 1.x](https://www.npmjs.com/package/@noble/hashes) | Audited, zero-dependency. EIP-55 itself is fifteen lines in `cli/src/address.ts`, pinned against the vectors published in the EIP |

### Dependency surface

The CLI has three runtime dependencies: `@noble/hashes`, `commander`, and the
two `csv-*` parsers. `npm audit` reports zero advisories.

Through v3.0.0-rc this list also carried `ethers`, used for exactly two
functions, `isAddress` and `getAddress`. It brought roughly twenty transitive
packages including a WebSocket client and an ENS normalizer, and produced
fifteen advisories, one of them high severity (`ws`, uninitialized memory
disclosure). None was reachable, the tool opens no sockets, but a tool whose
security model is "no outbound network calls, ever" has no business shipping a
WebSocket library, and every downstream security review would have had to
reason about it.

The replacement was differential-tested against `ethers` over 20,012 inputs
(random addresses in lowercase, uppercase, checksummed, and single-case-flipped
forms, plus malformed input and the EIP-55 vectors) with zero divergence, and
bundle output was confirmed byte-identical before and after the swap. That
check matters because the 20-byte address is hashed into every leaf: a
divergence would have changed every root the tool has ever produced.

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

An allowlist changes when a jurisdiction is added or a sanctions list updates.

### What was wrong before v3

`trusset-list-commit --output` wrote over the previous file. A
`set_membership` proof records the Merkle root of the list it was proved
against, so once a list had been rotated, nothing on disk mapped an old root
back to the values it committed to. The bundles kept verifying, that part of
this document was always accurate, but a reader holding one could establish
only "member of the set with root `0x9078…`" and never what that set was.
`config.json`, which named the list files, is `.gitignore`d, so the
configuration that produced a bundle was not retained either.

`paramsHash` does not distinguish versions: `set::Params::hash()` covers the
`listId` string alone, so it is identical across every version a list has ever
had. The distinguishing value has always been `setRoot`, which is bound into
`publicDigest`, the leaf hash, and `kycHash`.

### The procedure now

1. Edit `config/list_commitments/<id>.source.txt`. One entry per line, `#` for
   comments.
2. Record a new authoritative version:

```bash
npm run list-version -- \
  --list-id country_allowlist \
  --source config/list_commitments/country_allowlist.source.txt \
  --effective-date 2026-09-01 \
  --note "Sanctions review 2026-Q3"
```

This appends to `config/registry/lists/country_allowlist.json` and signs it
with the manifest signing key. The previous version's window closes on the day
before the new one opens; its values, root, and content hash stay in the file
forever. The writer refuses to remove or reorder a version, to record a version
whose values are unchanged (two versions sharing a root could not be told apart
by a proof), or to open one before the current version started.

3. New bundles resolve the version authoritative on the batch as-of date and
   record it in each `set_membership` leaf's `binding.listVersion`, alongside
   its root and content hash. The prover cross-checks both against its own
   recomputation and refuses to proceed on a mismatch.
4. Update the counterparty's approved-root policy. For the Trusset issuer
   backend that is `approvedLists.<id>` in `config/zkTrustAnchors.js`; editing
   it changes `POLICY_VERSION`, which invalidates cached verification verdicts
   (they re-verify, they do not fail).

**Existing bundles keep verifying, and now they also stay interpretable.** A
verifier holding the registry, or an archive, which carries it, resolves an
old proof's `setRoot` back to the version it used and the values that version
contained:

```
list     country_allowlist v1 (resolved, 17 entries)
```

Verification resolves the version from the leaf, never from current config.
Rotating a list does not invalidate `kycHash` and does not require re-proving.

## Claim descriptors and what a leaf asserts

Through v2.1 a leaf asserted a numeric threshold and nothing else. `minAgeDays:
6570` recorded a day count; it did not record which legal test that count
stands for, who warrants it, what the underlying value was checked against, or
how long the assertion holds. Nothing in the repository named a regulatory
framework, the tiers `NONE / RETAIL / PROFESSIONAL / ELIGIBLE_COUNTERPARTY`
are the MiFID II client-categorisation set and were nowhere declared as such.

Every v3 leaf carries:

```
binding.descriptor.legalBasis     framework, reference, assertion
binding.descriptor.issuingParty   who warrants this specific claim
binding.descriptor.evidenceClass  how the value was verified
binding.validity                  from, until, basisAsOf
binding.listVersion               which list version, for set_membership
```

hashed together into `bindingDigest = Rescue(LEAF-BIND ‖ canonical_json(binding))`
and appended to the leaf-hash preimage. Changing a descriptor changes the leaf
hash, the Merkle root, and the signature. A leaf carrying no binding block
hashes over exactly the v2 preimage, which is what keeps existing bundles
valid.

The evidence classes are `SELF_ATTESTED`, `DOCUMENTARY`,
`THIRD_PARTY_RELIANCE`, `AUTHORITATIVE_SOURCE`, `CRYPTOGRAPHIC`, and
`PHYSICAL_PRESENCE`. They are a labelled taxonomy, not a scale: nothing
compares two of them, and no predicate accepts an evidence-class threshold.
`THIRD_PARTY_RELIANCE` in particular carries whatever assurance the
relied-upon firm applied, which this tool cannot observe.

### The tier ordering

`tier_threshold` proves `tier ≥ min_tier` by constraining `tier - min_tier` to
`{0,1,2}` inside the AIR. The ordering is therefore a property of the circuit,
not configurable metadata, and v3 does not change it.

It is sound for the predicate the circuit proves, a sophistication floor -
and matches how the categories escalate in practice. Its limits, stated so a
reviewer does not have to infer them: a per-se professional and a professional
who opted up under Annex II §II.1 are both `2` here and carry materially
different protections; elective ECP status is instrument- and
service-specific rather than a global property of a client; and on a
protection-owed axis the ordering inverts, since `RETAIL` carries the most.
Record the per-se/elective distinction in `descriptor.legalBasis.reference`
where it matters.

`minTier: RETAIL` is vacuous over the provable domain: the circuit already
refuses `NONE`, so "at least RETAIL" is true of every tier it can prove.

## Validity, lapse, and voidance

`softExpiryDays` and `hardExpiryDays` are passthrough integers. No circuit
witnesses them, no verifier evaluates them, and nothing records what date they
count from. They were never an expiry model and are retained only for the
issuer backend that consumes them.

The model is per-leaf validity intervals: `from`, optional `until`, and
`basisAsOf`, the date the underlying evidence was examined, which is not the
date the claim starts. The gap between them is the staleness a reviewer wants
to see, so it is recorded rather than assumed to be zero.

Ending a claim is a separate signed record in
`config/registry/revocations.json`, never an edit to the bundle:

| | `lapsed` | `void_ab_initio` |
|---|---|---|
| Means | The claim was true and stopped being true | The claim was never true |
| Carries `effectiveFrom` | Required | Rejected: naming a date would imply it held before then |
| Reliance before that date | Stands | In question |
| Bundle still verifies | Yes | **Yes** |
| `temporal.entitled` | False from the date on | False at every instant |

A voided bundle keeps verifying deliberately. The proof is a true record of
what the operator asserted; destroying it to express that the assertion was
wrong would destroy the evidence of the misstatement.

## As-of verification and the root history

This tool has no chain access and v3 does not add any. `--root` has always been
a hex string the caller supplies.

An as-of query resolves against `config/registry/root_history.json`, a signed
append-only record of which root was published, at which block height, at which
block timestamp:

```bash
npm run anchor -- --bundle output/0xWALLET \
  --chain-id 1 --block 8000100 --block-time 1787529600
```

`trusset-verifier-cli --as-of-block N --chain-id C` finds the latest anchor at
or below that height and reports whether it is this bundle's root. An anchor is
never rewritten: recording the same publication twice is a no-op, and recording
a *different* root at the same height is refused.

When nothing resolves, no history supplied, or nothing published at or before
that height, entitlement is reported as **NO**, with a note distinguishing
"unknown" from "false". An entitlement question is never answered YES from
absent evidence.

## Archives

`npm run archive` writes one integrity-checked file containing the bundles, the
list registries their proofs depend on including superseded versions, the root
history, the revocation log, and the issuer identity. Its `digest` covers every
field except its own `createdAt`, so two archives of the same content compare
equal and any modification is refused at parse time.

Verification from an archive needs the file and a verifier binary: no config,
no registry, no output tree, no network, no chain. `secrets.enc` is excluded
unless `--include-secrets` is passed, because an archive is usually handed to a
counterparty and the witness blob is operator-private even though encrypted.

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

Through v2.1 the operator's ed25519 public key was never written anywhere: the
README documented `--public-key <hex>` and no command emitted that hex, so the
offline path could not be run by anyone who had not read the test suite. It is
now printed by `npm run init` and `npm run show`, and recorded in
`manifest.issuer.publicKey`. Recording it in the manifest does not make the
signature self-authenticating, an adversary who rewrites the manifest rewrites
that field too, but it tells a counterparty which key to obtain out of band,
and the verifier reports when a caller-supplied key disagrees with the one the
bundle names.

`overall_pass` and `temporal.entitled` answer different questions and are kept
apart on purpose. The first is cryptography. The second adds the root that was
on chain at the queried instant, each leaf's validity window, and any
revocation. Exit codes: 0 verified and entitled, 2 verification failed, 3
verified but not entitled.

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

## What v3.1 does NOT yet protect

- **Zero knowledge.** Proofs carry no blinding and disclose the values of
  predicate leaves (see "What a proof reveals").
- **Post-quantum manifest signing.** ed25519 is pre-quantum. Root-anchored
  verification sidesteps it when the root is known from chain.
- **HSM integration.** Keys live in an encrypted file or the macOS keychain
  and are decrypted into the CLI process for a run. HSM signing is the spec
  §17 workstream.
- **`preimage_knowledge` semantics.** What that circuit does and does not
  establish is documented in [CIRCUITS.md](CIRCUITS.md); it is the reason
  `commitment_only` exists.

**Development bundles** (`npm start -- --skip-proofs`) emit
`manifest.mode == "stub"` with zero-byte proof files. Counterparty
verifiers reject them by default; `--accept-stub` opts in. A
production-mode bundle with an empty proof on a proving leaf is rejected
outright, so the two cannot be confused.
