<div align="center">

![Batch verification tool](/assets/kyc-hashing-merkle-root-hero.png)

# Trusset KYC zk-Proof Tool

**Generate per-leaf zk-STARK KYC proofs for on-chain identity attestation.**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Rust](https://img.shields.io/badge/Rust-1.82%2B-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![zk-STARK](https://img.shields.io/badge/zk--STARK-Winterfell-7E57C2)](https://github.com/facebook/winterfell)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

[Quick Start](#quick-start) · [Usage](#usage) · [Configuration](#configuration) · [Security](#security)

</div>

---

## How it works

Each KYC field is bound to a per-leaf zk-STARK that proves a predicate or knowledge claim about its private value. Leaves are committed via a hiding Rescue-Prime commitment with a fresh per-leaf nonce, then sorted lexicographically and merged pairwise into a Rescue-Prime Merkle root. That root is the `kycHash` published to the Trusset network.

Banks can selectively disclose predicates ("over 18", "country in allowlist", "investor tier at least Professional") without revealing the underlying values, and low-entropy fields like `dateOfBirth` are not rainbow-table vulnerable to anyone holding a Merkle inclusion proof.

Every leaf also records what it is asserting: the legal basis, the party that warrants it, the class of evidence the value was checked against, and the window over which the claim holds. That block is hashed into the leaf, so it cannot be edited without invalidating the root — a threshold with no stated meaning is not evidence anyone can act on years later.

The tool runs entirely on the operator's machine: all proving is local, the master key never leaves the host, and `secrets.enc` is the only place plaintext-equivalent witness material lives on disk. There is no network access at any point, including for verification.

**What v3 exists for.** The tool proved what is true now and had no reliable way to prove what was true then. Every entitlement question in securities is a question about a past block. v3 pins the batch date so a bundle can be reproduced, keeps every superseded allowlist version so an old proof still means something, records who is responsible for each assertion, distinguishes a claim that lapsed from one that was never valid, and answers "was this subject entitled at block N" from the operator's own signed records rather than from a chain lookup nobody can make years later. See [docs/MIGRATION_V2_TO_V3.md](docs/MIGRATION_V2_TO_V3.md).

## Quick Start

Requirements: Node.js 18+ and Rust 1.82+. `rust-toolchain.toml` pins 1.91 and
declares the `wasm32-unknown-unknown` target, so rustup installs both on the
first `cargo` invocation.

```bash
git clone https://github.com/Trusset/trusset-kyc-zk-proofs
cd trusset-kyc-zk-proofs
npm install                              # builds the Rust workspace, the WASM verifier, and the TS CLI
npm run init -- --issuer-name "Example Bank AG" --issuer-scheme LEI \
                --issuer-identifier 529900T8BM49AURSDO55 --issuer-jurisdiction DE
set -a && . ./.trusset/keys.env && set +a
```

`init` generates both keys, writes a `config.json` with the batch date pinned
and starting claim descriptors filled in, records version 1 of every allowlist
it finds, checks the environment, and prints your operator public key. Run it
with no flags for an interactive prompt. It reports exactly what is missing and
what to run; nothing it finds already is overwritten without `--force`.

The first install compiles ~130 Rust crates and takes a few minutes; subsequent
builds are incremental. There are no prebuilt binaries — everything is built
from source, and each bundle records the SHA-256 of the prover that produced it.

## Usage

**Check a batch before proving anything:**

```bash
npm start -- --dry-run          # Validate every row and report every problem at once; writes nothing
```

**Hash KYC data:**

```bash
npm start                       # Read /input, prove every subject, write bundles + index CSV
npm start -- --raw              # Omit the index column from the batched CSV
npm start -- --skip-proofs      # Skip proving; predicates are still enforced (CI smoke mode)
npm start -- --no-deterministic # Draw per-subject keys from OS entropy
```

**Verify a bundle as a counterparty:**

```bash
npm run verify -- 0xAbCdEf... --root 0x<64-hex-kycHash-read-from-chain>
```

```bash
npm run verify -- 0xAbCdEf... --public-key <64-hex-of-operator-ed25519-pubkey>
```

The first form is for anyone who can read `kycHash` from chain: the published
root already authenticates the bundle, so no key needs pinning. The second is
for offline bundles whose root is not independently known. `npm run show`
prints your public key. Pass both to check both. Passing neither is a usage
error, not a silent pass.

**Ask what was true then, not what is true now:**

```bash
npm run verify -- 0xAbCdEf... --public-key <hex> --as-of-block 8000100 --chain-id 1
npm run verify -- 0xAbCdEf... --public-key <hex> --as-of-date 2026-09-15
```

Verification answers two separate questions. `Verifies` is cryptography: does
this bundle hold together and was it signed by that key. `Entitled` adds the
root that was on chain at the instant you asked about, each leaf's validity
window, and any revocation the operator has since signed. A bundle whose claims
were later declared void still verifies — the proof is a true record of what
was asserted — and reports `Entitled: NO`.

**Record what the tool cannot see:**

```bash
npm run list-version -- --list-id country_allowlist --source <file>   # rotate an allowlist
npm run anchor -- --bundle output/0xAbCd... --chain-id 1 --block N --block-time T
npm run revoke -- --bundle output/0xAbCd... --effect lapsed --effective-date 2026-10-01 --reason DOC_EXPIRED
npm run archive -- --output batch.tka --all output                   # one self-contained file
```

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
| **Registries** | `config/registry/{lists/<id>.json, root_history.json, revocations.json}` plus a detached `.sig` for each - append-only, never rewritten |
| **Archive** | `<name>.tka` - one self-contained file that verifies without this machine |
| **Output (batch index)** | `/output/kyc_hashes_<timestamp>.csv` - v1-compatible row-per-subject summary for legacy uploaders |
| **Output (failures)** | `/output/failures.csv` - only created when at least one subject failed |
| **Cleanup** | `/input` cleared after processing (configurable) |

Two failure stages are recorded: rows that fail TS-side validation (bad wallet, missing country) are quarantined before the prover spawns; rows that fail in the prover (under-age, country not in allowlist, tier=NONE) are isolated per-subject and the rest of the batch continues.

## Configuration

`npm run init` writes a complete `config.json`; the shipped
`config.example.json` is the same shape. The parts worth understanding:

```json
{
  "predicates": {
    "investorType": {
      "circuit": "tier_threshold",
      "params": { "minTier": "PROFESSIONAL" },
      "descriptor": {
        "legalBasis": {
          "framework": "MiFID_II",
          "reference": "Annex II Section I - professional clients",
          "assertion": "Subject is categorised at or above professional client"
        },
        "evidenceClass": "DOCUMENTARY"
      },
      "validity": { "days": 730 }
    }
  },
  "claims": {
    "defaults": {
      "issuingParty": "self",
      "evidenceClass": "DOCUMENTARY",
      "validity": { "days": 365, "basisAsOfOffsetDays": 0 }
    }
  },
  "security": {
    "epochDaysSource": "fixed:20689",
    "registryDir": "config/registry",
    "deterministic": true
  },
  "manifest": {
    "version": "3.0.0",
    "signingKeyEnv": "TRUSSET_KYC_SIGNING_KEY",
    "issuer": {
      "name": "Example Bank AG",
      "identifierScheme": "LEI",
      "identifier": "529900T8BM49AURSDO55",
      "jurisdiction": "DE",
      "keyId": "issuing-2026-08"
    }
  }
}
```

**`descriptor`** says what a threshold stands for. Without it, `minTier: 2` is
an anonymous integer that no reader can act on years later. `legalBasis` names
the rule, `evidenceClass` says how the value was verified, and `issuingParty`
(default `"self"`) names who warrants the claim — a different party when
another regulated firm verified it under a reliance arrangement. Evidence
classes: `SELF_ATTESTED`, `DOCUMENTARY`, `THIRD_PARTY_RELIANCE`,
`AUTHORITATIVE_SOURCE`, `CRYPTOGRAPHIC`, `PHYSICAL_PRESENCE`.

**`validity`** says how long the claim is asserted for: `{"days": N}`,
`{"until": "YYYY-MM-DD"}`, or `{"openEnded": true}`. `basisAsOfOffsetDays`
records when the evidence was examined, which is not when the claim starts; an
`evidenceDate` column in the input overrides it per subject.

**`epochDaysSource`** is the batch as-of date, and it must be pinned:
`fixed:<n>` or `env:<VAR>`. `utc_today` is refused outside
`--dev-unpinned-epoch`, because every per-subject key and every commitment
derives from that number and a bundle proved against a wall-clock epoch cannot
be reproduced the next day.

**`manifest.issuer`** is the party legally responsible for the assertions.
Required for version 3.0.0. Set `manifest.version` to `"2.1.0"` to keep
producing the previous bundle shape while you migrate.

**`lists`** may be left empty: allowlists resolve from the signed registry
under `security.registryDir`, which retains every version that was ever
authoritative. A bare `path` to a `trusset-list-commit` file still works but
warns, because superseded versions of such a file are not kept and an old
proof's root cannot then be resolved back to the set it committed to.

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
| **Determinism** | `epochDaysSource` must be pinned; with a fixed master key two runs are byte-identical. An unpinned wall-clock epoch is refused outside an explicit development flag |
| **Responsibility** | Every manifest records the issuing institution, its identifier and jurisdiction, the signing key id, and the SHA-256 of the prover binary that produced it |
| **Claim descriptors** | Every leaf records the legal basis it is asserted under, the party that warrants it, the evidence class the value was verified against, and the window over which it holds |
| **List history** | Allowlist versions are append-only and signed; a proof resolves to the version it used, not to whatever the config says today |
| **Revocation** | Lapse and voidance are separate signed records. A revoked bundle keeps verifying — the proof is a true record of what was asserted — and reports as not entitled |
| **Archives** | One integrity-checked file carries the bundles, the list versions they depend on, the root history, and the revocations. It verifies with no access to the operator |
| **Cryptographic stack** | Goldilocks field, Rescue-Prime hash, Winterfell STARK, all PQ-friendly |

Detailed security model: see [docs/SECURITY.md](docs/SECURITY.md).

## Additional Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - crate map, data flow, bundle artifact contract
- [docs/CIRCUITS.md](docs/CIRCUITS.md) - formal predicate statements per circuit and leaf mode
- [docs/SECURITY.md](docs/SECURITY.md) - threat model, key hierarchy, per-field disclosure, allowlist rotation
- [docs/MIGRATION_V2_TO_V3.md](docs/MIGRATION_V2_TO_V3.md) - what changes for an operator who already has bundles in the field
- [docs/MIGRATION_FROM_V1.md](docs/MIGRATION_FROM_V1.md) - v1 upgrade path and the v2.0 to v2.1 changes
- [docs/AUDIT_PREP.md](docs/AUDIT_PREP.md) - spec §12 traceability matrix
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - measured prove/verify times and artifact sizes, with hardware
- [docs/RELEASE_GATE.md](docs/RELEASE_GATE.md) - v2.1.0 release-gate results
- [docs/FUTURE_WORK.md](docs/FUTURE_WORK.md) - deliberately deferred design directions

---

<div align="center">

Built by [Trusset](https://trusset.org) · [Report an Issue](https://trusset.org/contact)

</div>
