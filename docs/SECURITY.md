# Security model

This document describes what `trusset-kyc-hashing` v2 protects against,
what it assumes, and how the cryptographic primitives compose. It is the
primary reference for compliance reviewers and external auditors.

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Rainbow-table recovery of low-entropy fields (DOB, country, tier) given a Merkle inclusion proof | Per-leaf hiding commitment `Rescue(COMMITMENT_TAG ‖ u32_len ‖ value ‖ nonce)` with 32-byte nonce from HKDF |
| Counterparty observing partial disclosure inferring undisclosed fields | Domain-separated leaf tags (`LEAF`, `NODE`) plus circuit ID byte in every leaf hash — siblings reveal nothing about the disclosed field |
| Cross-subject replay (proof for Alice replayed as proof for Bob) | `walletAddress_bytes` bound into every leaf hash (spec §7) |
| Cross-epoch replay (proof generated at time T verified as fresh at T+N) | `epochDays` bound into every leaf hash; operators choose `utc_today` / `fixed:<n>` / `env:<VAR>` per `security.epochDaysSource` |
| Cross-circuit replay (proof for `age_threshold` re-presented as `tier_threshold`) | `CircuitId` u8 (1=age, 2=set, 3=tier, 4=preimage) bound into the leaf hash and the per-leaf Fiat-Shamir seed |
| Tampered list-commitments file post-prove | `config.lists.<id>.sha256` pinned; the prover refuses to start if the on-disk file's hash drifts |
| Tampered proof or manifest after signing | ed25519 signature over canonical-JSON view of the manifest; the verifier reconstructs and re-checks |
| Stub bundle relabeled as production | The `mode` field is inside the signing payload — relabeling invalidates the signature |
| Lost / stolen `secrets.enc` decryption attempt without the master key | xsalsa20-poly1305 with HKDF-derived per-subject key; offline brute force requires the 256-bit master key |
| Non-deterministic output (operator can't reproduce a bundle to satisfy an audit) | All randomness flows from `TRUSSET_KYC_MASTER_KEY` via HKDF; `TRUSSET_KYC_DETERMINISTIC=1` panics on any OS-entropy draw |

### Out of scope

| Threat | Why not |
|---|---|
| Compromise of the operator's machine while the master key is loaded in memory | Tool-level mitigations (`Zeroize` on secret buffers) reduce the window, but a kernel-level adversary defeats any user-space defense. Use HSM-backed secret loading at the OS layer |
| Side-channel attacks against the Goldilocks field arithmetic | Winterfell's implementation is not constant-time; this is acceptable for STARK proving, which is not a real-time secret-handling operation |
| Quantum attacks on ed25519 manifest signing | ed25519 is pre-quantum. The Rescue-Prime STARK layer is post-quantum-friendly, but the manifest signature is not. Operators should sign manifests with a post-quantum scheme (Dilithium) once standards stabilize — issue tracked, not blocking v2.0.0 |
| Adversary with arbitrary write access to `/output` after the prover finishes | The verifier catches tampered bytes, but doesn't catch e.g. a bundle being deleted. Standard filesystem ACLs apply |
| KYC data ingestion (`/input` is trusted) | The tool assumes records come from a vetted source. Bad input produces validation failures, not silent acceptance |

## Cryptographic primitives

| Layer | Primitive | Source | Rationale |
|---|---|---|---|
| Finite field | Goldilocks (`p = 2^64 − 2^32 + 1`) | [`winter-math` 0.13.1](https://crates.io/crates/winter-math) | Native 64-bit arithmetic; STARK-friendly modulus |
| Hash | Rescue-Prime 64/256 | [`winter-crypto` 0.13.1](https://crates.io/crates/winter-crypto) | Same primitive inside and outside circuits → smaller audit surface |
| STARK | Winterfell AIR | [`winterfell`](https://github.com/facebook/winterfell) | Production-grade (Polygon Miden), no trusted setup, post-quantum |
| Manifest signature | ed25519 (RFC 8032) | [`ed25519-dalek` 2.x](https://crates.io/crates/ed25519-dalek) | Deterministic, well-audited |
| Secrets encryption | xsalsa20-poly1305 (libsodium secretbox) | [`xsalsa20poly1305` 0.9](https://crates.io/crates/xsalsa20poly1305) | Bit-compatible with libsodium; auditors can decrypt with either toolchain |
| Key derivation | HKDF-SHA256 | [`hkdf` 0.12](https://crates.io/crates/hkdf) + [`sha2` 0.10](https://crates.io/crates/sha2) | RFC 5869 |
| Canonical UTF-8 | Unicode NFC | [`unicode-normalization` 0.1](https://crates.io/crates/unicode-normalization) | Prevents `"café"` (composed) vs `"cafe´"` (decomposed) from producing different proofs |

All seven 32-byte domain tags are pairwise distinct at compile time via
`static_assertions::const_assert!`:

- `TRUSSET-KYC-V2:LEAF` — main per-subject Merkle leaf
- `TRUSSET-KYC-V2:NODE` — main tree inner node
- `TRUSSET-KYC-V2:PUB-DIGEST` — Rescue hash of canonical public inputs
- `TRUSSET-KYC-V2:PRF-DIGEST` — Rescue hash of proof bytes
- `TRUSSET-KYC-V2:SET-LEAF` — set-membership leaf
- `TRUSSET-KYC-V2:SET-NODE` — set-membership inner node
- `TRUSSET-KYC-V2:COMMIT` — hiding commitment for `(value, nonce)`

Adding an eighth tag requires extending the
`const_assert!`/`const_ne(...)` matrix in
[`circuits/common/src/domain.rs`](../circuits/common/src/domain.rs) by
seven entries — the compiler refuses to build a workspace where any two
tags are equal.

## Key derivation chain

```
TRUSSET_KYC_MASTER_KEY (32 bytes, operator-supplied via env var)
│
├─→ HKDF-SHA256(salt="trusset-kyc-v2/subject",
│               info=subject_id ‖ epoch_days_le8 ‖ config_hash ‖ circuits_version)
│   → subject_seed (32 bytes, Zeroizing<>)
│   │
│   ├─→ HKDF-SHA256(salt="trusset-kyc-v2/leaf",
│   │               info=field_name ‖ circuit_id ‖ params_hash)
│   │   → leaf_seed (32 bytes, also the hiding-commitment nonce)
│   │
│   └─→ used as the IKM for any auxiliary RNG inside the AIR prover
│
├─→ HKDF-SHA256(salt="trusset-kyc-v2/secretbox-key",
│               info=subject_id ‖ epoch_days_le8 ‖ config_hash ‖ kdf_version)
│   → secretbox_key (32 bytes, used by xsalsa20-poly1305)
│
└─→ HKDF-SHA256(salt="trusset-kyc-v2/secretbox-nonce",
                info=subject_id ‖ epoch_days_le8 ‖ config_hash ‖ kdf_version)
    → secretbox_nonce (24 bytes, also deterministic — XSalsa20-Poly1305 is safe
                       under nonce reuse only if the key+nonce pair never repeats
                       with different plaintext, which the info string structurally
                       prevents)
```

`config_hash` is SHA-256 over a canonicalized projection of the config
that excludes cosmetic fields (`output.format`, `output.includeIndex`,
`security.clearInputAfterProcessing`). This means reformatting a CSV vs
JSON output doesn't invalidate the determinism cache; changing
`predicates` does.

`circuits_version` (currently `1`) is a compile-time constant in
[`circuits/common/src/lib.rs`](../circuits/common/src/lib.rs). Bumping it
invalidates every subject's seed simultaneously and is the right move
when changing leaf encoding, AIR layout, or serialization.

## Replay protection (spec §12.3 / §12.4)

Every leaf hash binds:

```
leaf_hash = Rescue(
  LEAF_TAG
  ‖ len(field_name) ‖ field_name_bytes
  ‖ circuit_id (u8)
  ‖ len(wallet_bytes) ‖ wallet_bytes
  ‖ epoch_days (u64 LE)
  ‖ commitment (32 bytes)
  ‖ public_digest (32 bytes)
  ‖ proof_digest (32 bytes)
)
```

This binding means a proof generated for `(field=dateOfBirth,
wallet=0xA, epoch=20587, circuit=age_threshold)` cannot be presented
under any other tuple — the leaf hash, the merkle root, and the
manifest signature all change.

## `secrets.enc` and recovery

The encrypted secrets blob carries:
- the plaintext value of each witnessed field
- the 32-byte nonce used in the hiding commitment
- the circuit name (for cross-reference)

Decryption requires:
- `TRUSSET_KYC_MASTER_KEY` (the same value that produced the bundle)
- `subject_id`, `epoch_days`, `config_hash` (all read from `manifest.json`)
- `kdf_version` (constant for v2.0.0; bumping invalidates old bundles)

If any of these drift — operator rotated the master key, edited
`config.json` cosmetic fields in a way that affects `config_hash`,
moved to a future `kdf_version` — the file cannot be decrypted.

### Recovery procedure

1. If only `manifest.json` is corrupted: re-run `npm start` against the
   original `/input` records. With `deterministic: true` and pinned
   `epochDaysSource`, the new bundle is byte-identical (modulo the
   wall-clock `createdAt` field).
2. If `secrets.enc` is corrupted but the input records are intact: same
   as above.
3. If `secrets.enc` is lost AND the input records are gone: there is no
   recovery. The bank must re-run KYC for the subject from the
   originating data sources.

Back up `secrets.enc` files like any other operator-private artifact.

## Timestamp exclusion (spec §12.8)

The manifest carries the real wall-clock `createdAt` ISO 8601 timestamp,
but the ed25519 signature is computed over a canonical view of the
manifest with `createdAt` overwritten to `"1970-01-01T00:00:00Z"` (the
sentinel). The verifier reconstructs the signing view by performing the
same overwrite before checking. This means:

- Two runs at different times produce bundles that differ only in the
  `manifest.json` `createdAt` field. `manifest.sig` is byte-identical.
- An adversary cannot replay a manifest at a later timestamp without
  re-signing (the `createdAt` change after signing would not match the
  sentinel anymore).
- Compliance teams diffing two bundles for an audit see the timestamp
  drift and ignore it; everything else is bit-stable.

[`tests/e2e/canary.sh`](../tests/e2e/canary.sh) runs this two-run
comparison and asserts byte-equality modulo `createdAt`.

## Determinism enforcement (spec §12.8)

`prover/Cargo.toml` enables `getrandom = { features = ["custom"] }` and
registers a custom `getrandom` hook that, when
`TRUSSET_KYC_DETERMINISTIC=1`, panics if any code attempts to draw from
the OS entropy pool. CI runs with this flag set, so any code path that
accidentally introduces nondeterminism aborts loudly rather than
producing a subtly-different bundle.

`--no-deterministic` opts out (permits OS randomness in nonces) and
stamps `"deterministic": false` into the manifest so a downstream
verifier can tell which mode produced the bundle.

## What v2 does NOT yet protect

These are Phase 2B / future work, tracked but not blocking v2.0.0
release as Phase 2A:

- **Real STARK proving**: Phase 2A produces structured 120-byte
  placeholder proofs that bind witness to public inputs via Rescue but
  do NOT carry actual STARK security. The manifest carries
  `mode: "stub"` and counterparty verifiers refuse the bundle by
  default. Real Winterfell AIRs with Rescue gates are Phase 2B.
- **Post-quantum manifest signing**: ed25519 is pre-quantum. Switch to
  Dilithium once NIST PQC signature standards stabilize.
- **HSM integration**: master key currently arrives via env var. HSM
  backing is the spec §17 / Phase ∞ workstream — the API surface stays
  the same.
