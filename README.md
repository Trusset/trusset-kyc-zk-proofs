<div align="center">

![Batch verification tool](/assets/kyc-hashing-merkle-root-hero.png)

# Trusset KYC zk-Proof Tool

**Generate per-leaf zk-STARK KYC proofs for on-chain identity attestation.**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Rust](https://img.shields.io/badge/Rust-1.75%2B-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![zk-STARK](https://img.shields.io/badge/zk--STARK-Winterfell-7E57C2)](https://github.com/facebook/winterfell)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

[Quick Start](#quick-start) · [Usage](#usage) · [Configuration](#configuration) · [Security](#security)

</div>

---

## How it works

Each KYC field is bound to a per-leaf zk-STARK that proves a predicate or knowledge claim about its private value. Leaves are committed via a hiding Rescue-Prime commitment with a fresh per-leaf nonce, then sorted lexicographically and merged pairwise into a Rescue-Prime Merkle root. That root is the `kycHash` published to the Trusset network.

What changes from v1: each leaf carries a STARK proof instead of an unprotected `keccak256(fieldName, value)`. Banks can selectively disclose predicates ("over 18", "country in allowlist", "investor tier at least Professional") without revealing the underlying values, and low-entropy fields like `dateOfBirth` are no longer rainbow-table vulnerable to anyone holding a Merkle inclusion proof.

The tool runs entirely on the operator's machine: all proving is local, the master key never leaves the host, and `secrets.enc` is the only place plaintext-equivalent witness material lives on disk.

## Quick Start

Requirements: Node.js 18+, Rust 1.75+ with the `wasm32-unknown-unknown` target installed.

```bash
git clone https://github.com/Trusset/trusset-kyc-zk-proofs
cd trusset-kyc-hashing
npm install                              # builds Rust workspace + WASM verifier + TS CLI
cp config.example.json config.json
export TRUSSET_KYC_MASTER_KEY=$(openssl rand -hex 32)
export TRUSSET_KYC_SIGNING_KEY=$(openssl rand -hex 32)
```

The first install compiles ~50 Rust crates; subsequent builds are incremental.

## Usage

**Hash KYC data:**

```bash
npm start                       # Read /input, prove every subject, write bundles + index CSV
npm start -- --raw              # Omit the index column from the batched CSV
npm start -- --skip-proofs      # Emit zero-byte proof files (CI smoke mode)
npm start -- --no-deterministic # Draw per-subject keys from OS entropy
```

**Verify a bundle as a counterparty:**

```bash
npm run verify -- 0xAbCdEf... --root 0x<64-hex-kycHash-read-from-chain>
```

```bash
npm run verify -- 0xAbCdEf... --public-key <64-hex-of-operator-ed25519-pubkey>
```

The first form is for anyone who can read `kycHash` from chain: the
published root already authenticates the bundle, so no key needs pinning.
The second is for offline bundles whose root is not independently known.
Pass both to check both. Passing neither is a usage error, not a silent
pass.

**Inspect resolved configuration:**

```bash
npm run show
```

Every command supports `--json` for machine-readable output.

## Input / Output

| Direction | Details |
|-----------|---------|
| **Input** | Place `.json` or `.csv` files in `/input` |
| **Output (per subject)** | `/output/<wallet>/{manifest.json, manifest.sig, kycHash.hex, proofs/<field>.bin, secrets.enc}` |
| **Output (batch index)** | `/output/kyc_hashes_<timestamp>.csv` - v1-compatible row-per-subject summary for legacy uploaders |
| **Output (failures)** | `/output/failures.csv` - only created when at least one subject failed |
| **Cleanup** | `/input` cleared after processing (configurable) |

Two failure stages are recorded: rows that fail TS-side validation (bad wallet, missing country) are quarantined before the prover spawns; rows that fail in the prover (under-age, country not in allowlist, tier=NONE) are isolated per-subject and the rest of the batch continues.

## Configuration

`config.json` extends v1 additively. The example shipped at `config.example.json`:

```json
{
  "mapping": {
    "fields": ["firstName", "lastName", "dateOfBirth", "nationality",
               "documentType", "documentNumber", "documentIssuingCountry"],
    "walletAddressField": "walletAddress",
    "countryField": "country",
    "investorTypeField": "investorType",
    "softExpiryDaysField": "softExpiryDays",
    "hardExpiryDaysField": "hardExpiryDays"
  },
  "predicates": {
    "dateOfBirth":  { "circuit": "age_threshold",      "params": { "minAgeYears": 18 } },
    "country":      { "circuit": "set_membership",     "params": { "list": "country_allowlist" } },
    "nationality":  { "circuit": "set_membership",     "params": { "list": "country_allowlist" } },
    "investorType": { "circuit": "tier_threshold",     "params": { "minTier": "RETAIL" } },
    "firstName":    { "circuit": "commitment_only",    "params": { "maxValueBytes": 128 } }
  },
  "tiers": { "NONE": 0, "RETAIL": 1, "PROFESSIONAL": 2, "ELIGIBLE_COUNTERPARTY": 3 },
  "lists": {
    "country_allowlist": {
      "path": "config/list_commitments/country_allowlist.json"
    }
  },
  "security": {
    "clearInputAfterProcessing": true,
    "masterKeyEnv": "TRUSSET_KYC_MASTER_KEY",
    "epochDaysSource": "utc_today",
    "deterministic": true
  },
  "manifest": { "signingKeyEnv": "TRUSSET_KYC_SIGNING_KEY" }
}
```

`predicates` maps each hashed field to its circuit and params. Spec defaults apply if a field is omitted. `set_membership` lists must reference a commitment file built by `trusset-list-commit` (see `docs/CIRCUITS.md`). `epochDaysSource` may be `utc_today`, `fixed:<n>`, or `env:<VAR>` - pin it for byte-stable reruns.

A field may also carry **several predicate instances** by giving an array. Each becomes its own leaf with its own params hash:

```json
"dateOfBirth": [
  { "circuit": "age_threshold", "params": { "minAgeYears": 18 } },
  { "circuit": "age_threshold", "params": { "minAgeYears": 21 } }
]
```

The first instance keeps the bare field name; later ones get a deterministic params-derived suffix (`dateOfBirth@7665d`). `commitment_only` produces a hiding commitment and a leaf hash with no STARK, for identity fields where there is no predicate worth proving - see `docs/CIRCUITS.md` for why that is the right default for names and document numbers.

## Input Format Example

**JSON:**

```json
[
  {
    "walletAddress": "0xabcdef0123456789abcdef0123456789abcdef01",
    "country": "DEU",
    "investorType": "PROFESSIONAL",
    "firstName": "Alice",
    "lastName": "Anderson",
    "dateOfBirth": "1985-04-12",
    "nationality": "DEU",
    "documentType": "PASSPORT",
    "documentNumber": "P12345678",
    "documentIssuingCountry": "DEU"
  }
]
```

**CSV:**

```csv
walletAddress,country,investorType,firstName,lastName,dateOfBirth,nationality,documentType,documentNumber,documentIssuingCountry
0xabcdef0123456789abcdef0123456789abcdef01,DEU,PROFESSIONAL,Alice,Anderson,1985-04-12,DEU,PASSPORT,P12345678,DEU
```

## Output Format Example

```
output/
├── 0xAbCd.../
│   ├── kycHash.hex              # 0x-prefixed Rescue Merkle root
│   ├── manifest.json            # signed bundle manifest
│   ├── manifest.sig             # ed25519 signature (sibling)
│   ├── proofs/
│   │   ├── dateOfBirth.bin      # zk-STARK proof binding to commitment
│   │   ├── firstName.bin        # zero-length for commitment_only leaves
│   │   └── ...
│   └── secrets.enc              # xsalsa20-poly1305 encrypted witness blob
└── kyc_hashes_<timestamp>.csv   # batched index for the Trusset uploader
```

The batched CSV preserves the v1 row schema:

```csv
walletAddress,country,investorType,softExpiryDays,hardExpiryDays,kycHash,index
0xAbCd...,DEU,PROFESSIONAL,365,730,0x9f1c...,1
```

Each row maps directly to the `/customers/api/identity/verify` request body in the Trusset issuer backend.

Note that `country` and `investorType` travel in cleartext here because the backend needs them for storage and for on-chain transfer rules. The zk layer binds those values but does not hide them in this pipeline; each manifest leaf records a `disclosure` class saying so. See the disclosure table in [docs/SECURITY.md](docs/SECURITY.md).

## Security

> All operations run entirely on your local machine. The master key never leaves the host.

| Feature | Details |
|---------|---------|
| **Local only** | No outbound network calls during proving |
| **Auto cleanup** | Input cleared after processing |
| **Hiding commitments** | Per-leaf 32-byte nonces derived from an independent per-subject key |
| **Key wrapping** | The master key wraps each subject key inside `secrets.enc` and derives nothing else, so one compromise no longer recovers every nonce ever issued |
| **Domain separation** | Nine 32-byte tags (`LEAF`, `NODE`, `PUB-DIGEST`, `PRF-DIGEST`, `SET-LEAF`, `SET-NODE`, `COMMIT`, `MERKLE-PAD`, `MERKLE-ROOT`) enforce non-collision across primitives |
| **Manifest signing** | ed25519 over a sentinel-`createdAt` canonical view - byte-identical signatures across runs |
| **Root anchoring** | A counterparty can verify against the on-chain `kycHash` instead of pinning the operator key |
| **Encrypted at rest** | `secrets.enc` is xsalsa20-poly1305 (libsodium-compatible), payload key wrapped under the master key |
| **Determinism** | Pinned `epochDaysSource` + fixed master key → byte-identical bundles across runs |
| **Cryptographic stack** | Goldilocks field, Rescue-Prime hash, Winterfell STARK, all PQ-friendly |

Detailed security model: see [docs/SECURITY.md](docs/SECURITY.md).

## Additional Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - crate map, data flow, bundle artifact contract
- [docs/CIRCUITS.md](docs/CIRCUITS.md) - formal predicate statements per circuit and leaf mode
- [docs/SECURITY.md](docs/SECURITY.md) - threat model, key hierarchy, per-field disclosure, allowlist rotation
- [docs/MIGRATION_FROM_V1.md](docs/MIGRATION_FROM_V1.md) - v1 upgrade path and the v2.0 to v2.1 changes
- [docs/AUDIT_PREP.md](docs/AUDIT_PREP.md) - spec §12 traceability matrix
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - measured prove/verify times and artifact sizes, with hardware
- [docs/RELEASE_GATE.md](docs/RELEASE_GATE.md) - v2.1.0 release-gate results
- [docs/FUTURE_WORK.md](docs/FUTURE_WORK.md) - deliberately deferred design directions

---

<div align="center">

Built by [Trusset](https://trusset.org) · [Report an Issue](https://trusset.org/contact)

</div>
