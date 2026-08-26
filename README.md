<div align="center">

![Batch verification tool](/assets/kyc-hashing-merkle-root-hero.png)

# Trusset KYC zk-Proof Tool

**Turn a batch of KYC records into per-subject zk-STARK proofs you can publish on chain — and still explain to a regulator five years later.**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Rust](https://img.shields.io/badge/Rust-1.82%2B-DEA584?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![zk-STARK](https://img.shields.io/badge/zk--STARK-Winterfell-7E57C2)](https://github.com/facebook/winterfell)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)

[Quick start](#quick-start) · [Commands](#commands) · [Configuration](#configuration) · [How it works](#how-it-works) · [Security](#security) · [Docs](#documentation)

</div>

---

## What this is

You give it KYC records. It gives you, per subject:

- a **`kycHash`** — one 32-byte Merkle root to publish on chain,
- a **bundle** of zk-STARK proofs backing that root, one per field,
- a **signed manifest** saying who asserted what, under which rule, on what evidence, and for how long.

A counterparty can then check "is this person over 18 / in an approved
jurisdiction / a professional client" without ever seeing their date of birth,
nationality, or documents.

Everything runs on your machine. No network calls, no service to operate, no
key ever leaves the host.

**Two questions it answers, kept apart on purpose:**

| Question | Answer |
|---|---|
| Does this bundle hold together, and did you sign it? | `Verifies: PASS/FAIL` — pure cryptography |
| Could this subject rely on it *at block N*, two years ago? | `Entitled: YES/NO` — adds the root live then, each claim's validity window, and any revocation since |

That second one is what v3 is for. Entitlement questions in securities are
always about a past moment, and a proof that only tells you about today is not
much use in a dispute. See [what changed in v3](#what-changed-in-v3).

---

## Quick start

**You need:** Node.js 18+ and Rust 1.82+. That's it — `rust-toolchain.toml`
pins the exact toolchain and target, so rustup fetches what it needs on the
first build.

```bash
git clone https://github.com/Trusset/trusset-kyc-zk-proofs
cd trusset-kyc-zk-proofs
npm install
```

First build compiles ~130 Rust crates and takes a few minutes. After that it's
incremental.

```bash
npm run init
```

Asks four questions about your institution, then does the rest: generates both
keys, writes a working `config.json`, records version 1 of your allowlists,
checks your environment, and prints your public key. Add `--non-interactive`
with the flags below to script it:

```bash
npm run init -- --issuer-name "Example Bank AG" --issuer-scheme LEI \
                --issuer-identifier 529900T8BM49AURSDO55 \
                --issuer-jurisdiction DE --non-interactive
```

Load your keys, drop records in `input/`, and go:

```bash
set -a && . ./.trusset/keys.env && set +a   # do this in every new shell

cp your-records.json input/
npm start -- --dry-run                      # check everything first, writes nothing
npm start                                   # prove for real
```

Verify what you just made:

```bash
npm run show                                # prints your operator public key
npm run verify -- 0xYourSubject --public-key <that key>
```

**That's the whole loop.** Everything below is reference.

> **One thing worth knowing up front:** `init` pins the batch date into
> `config.json` as `epochDaysSource: "fixed:<today>"`. Leave it pinned. Every
> per-subject key and commitment derives from that number, so a bundle proved
> against a moving clock can't be reproduced tomorrow — which is exactly what
> an auditor will ask you to do. The tool refuses to run unpinned unless you
> pass `--dev-unpinned-epoch`.

---

## Commands

Every command takes `--json` for machine-readable output. Every failure names
the field, the subject, and the fix.

### Daily use

```bash
npm start -- --dry-run     # validate the whole batch, report every problem at once
npm start                  # prove /input, write bundles + index CSV to /output
npm run verify -- <wallet> --public-key <hex>
npm run show               # resolved config, descriptors, list versions, your public key
```

| Flag on `npm start` | What it does |
|---|---|
| `--dry-run` | Validates everything, writes nothing, needs no keys. ~0.1 s per subject |
| `--raw` | Omit the index column from the batched CSV |
| `--skip-proofs` | Skip STARK generation; predicates are still enforced. For CI |
| `--no-deterministic` | Draw per-subject keys from OS entropy instead of the master key |
| `--dev-unpinned-epoch` | Allow a wall-clock batch date. Development only — bundles are permanently marked unreproducible |

### Verifying

```bash
# Anyone who can read kycHash from chain — the root authenticates the bundle
npm run verify -- <wallet> --root 0x<64-hex>

# Offline bundles — pin the operator key instead
npm run verify -- <wallet> --public-key <64-hex>

# What was true at a past block, or on a past day
npm run verify -- <wallet> --public-key <hex> --as-of-block 8000100 --chain-id 1
npm run verify -- <wallet> --public-key <hex> --as-of-date 2026-09-15

# Straight from an archive, on a machine that has nothing else
npm run verify -- <wallet> --public-key <hex> --archive batch.tka
```

Passing neither anchor is a usage error, not a silent pass. Pass both to check
both.

| Exit code | Meaning |
|---|---|
| `0` | Verifies, and entitled at the instant asked about |
| `2` | Verification failed — cryptographic mismatch or policy rejection |
| `3` | Verifies, but not entitled then (lapsed, void, outside its window, or a different root at that block) |
| `64` | Usage error |
| `66` | Bundle or archive unreadable |

### Keeping the record straight

These three write to append-only, signed registries under `config/registry/`.
Nothing there is ever edited or removed — that's the point.

```bash
# An allowlist changed. The old version keeps its values forever.
npm run list-version -- --list-id country_allowlist \
    --source config/list_commitments/country_allowlist.source.txt \
    --effective-date 2026-09-01 --note "Sanctions review 2026-Q3"

# You published a root. Record where, so as-of checks work without a chain lookup.
npm run anchor -- --bundle output/0xAbCd... \
    --chain-id 1 --block 8000100 --block-time 1787529600

# A claim stopped being true...
npm run revoke -- --bundle output/0xAbCd... --leaf investorType \
    --effect lapsed --effective-date 2026-10-01 --reason PERIODIC_REVIEW_OVERDUE

# ...or was never true. Not the same thing, and the tool won't let you conflate them.
npm run revoke -- --bundle output/0xAbCd... \
    --effect void_ab_initio --reason FRAUDULENT_ONBOARDING
```

### Archiving

```bash
npm run archive -- --output 2026Q3.tka --all output    # build
npm run archive -- --inspect 2026Q3.tka                # read one back
```

One file containing the bundles, every list version their proofs used, the
root history, the revocations, and your issuer identity. It verifies on a bare
machine with no config, no registry, and no network. Store it wherever you
keep things you might have to produce in five years.

---

## Input format

Drop `.json` or `.csv` files in `input/`. Both shapes are the same fields.

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
    "documentIssuingCountry": "DEU",
    "softExpiryDays": 365,
    "hardExpiryDays": 730,
    "evidenceDate": "2026-08-01"
  }
]
```

```csv
walletAddress,country,investorType,firstName,lastName,dateOfBirth,nationality,documentType,documentNumber,documentIssuingCountry
0xabcdef0123456789abcdef0123456789abcdef01,DEU,PROFESSIONAL,Alice,Anderson,1985-04-12,DEU,PASSPORT,P12345678,DEU
```

`evidenceDate` is optional and says when you examined this subject's documents
— usually not the day you ran the batch. `softExpiryDays` and `hardExpiryDays`
are passthrough for the issuer backend; the real expiry model is
[`validity`](#validity--how-long-the-claim-holds) in your config.

**A blank column takes the configured default. A column with something the
tool can't read fails the row.** A typo'd `PROFESSIONAL_INVESTOR` is a
quarantined row, not a silent downgrade to `RETAIL`.

---

## Output

```
output/
├── 0xAbCd.../
│   ├── kycHash.hex          # the root you publish
│   ├── manifest.json        # what was asserted, by whom, on what evidence
│   ├── manifest.sig         # ed25519 over a canonical view of the manifest
│   ├── proofs/*.bin         # one STARK per proving leaf; 0 bytes for commitment-only
│   └── secrets.enc          # encrypted witnesses — operator-private, never ship it
├── kyc_hashes_<ts>.csv      # row per subject, for the uploader
├── failures.csv             # only when something failed
└── audit.log                # per-run event log, no PII

config/registry/             # append-only, each with a detached .sig
├── lists/<id>.json          # every allowlist version ever authoritative
├── root_history.json        # which root you published, at which block
└── revocations.json         # lapses and voidances
```

Failures land in two stages. Bad input (malformed wallet, unreadable tier) is
quarantined before the prover starts. Predicate failures (under age, not in
the allowlist) fail that subject and let the rest of the batch through. Both
end up in `failures.csv` with a stage column.

Failure messages name the leaf and the fix, and never echo the subject's
value — `failures.csv` travels, and `nationality` is exactly what the proof
exists to keep private.

---

## Configuration

`npm run init` writes a complete `config.json`. Four parts are worth
understanding.

### `predicates` — what to prove about each field

```json
"investorType": {
  "circuit": "tier_threshold",
  "params": { "minTier": "PROFESSIONAL" },
  "descriptor": {
    "legalBasis": {
      "framework": "MiFID_II",
      "reference": "Annex II Section I — professional clients",
      "assertion": "Subject is categorised at or above professional client"
    },
    "evidenceClass": "DOCUMENTARY"
  },
  "validity": { "days": 730 }
}
```

Five circuits:

| Circuit | Proves | Use for |
|---|---|---|
| `age_threshold` | value is at least N days old, as of the batch date | `dateOfBirth` |
| `set_membership` | value is in a committed allowlist | `country`, `nationality` |
| `tier_threshold` | value is at or above a tier floor | `investorType` |
| `preimage_knowledge` | you know an opening of the commitment | rarely what you want |
| `commitment_only` | a hiding commitment, no STARK | names, document numbers |

`commitment_only` is the right default for identity fields: there is no
predicate worth proving about a surname, and it costs zero prove time and zero
proof bytes. [docs/CIRCUITS.md](docs/CIRCUITS.md) explains why
`preimage_knowledge` usually isn't what you want.

One field can carry **several predicates** — each becomes its own leaf:

```json
"dateOfBirth": [
  { "circuit": "age_threshold", "params": { "minAgeYears": 18 }, "descriptor": {...}, "validity": {...} },
  { "circuit": "age_threshold", "params": { "minAgeYears": 21 }, "descriptor": {...}, "validity": {...} }
]
```

The first keeps the bare field name; later ones get a stable suffix
(`dateOfBirth@7665d`).

### `descriptor` — what the threshold *means*

Required. Without it a leaf says `minTier: 2` and nothing else, which is not
something a reader can act on years later.

- **`legalBasis`** — `framework` (e.g. `MiFID_II`, `AMLD5`, `REG_D`,
  `NATIONAL`), `reference` (the provision), `assertion` (one line, your words).
- **`evidenceClass`** — how you checked. One of `SELF_ATTESTED`,
  `DOCUMENTARY`, `THIRD_PARTY_RELIANCE`, `AUTHORITATIVE_SOURCE`,
  `CRYPTOGRAPHIC`, `PHYSICAL_PRESENCE`.
- **`issuingParty`** — defaults to `"self"`. Name a different firm when they
  did the verification under a reliance arrangement.

Put shared values in `claims.defaults` and override per predicate.

The descriptor is **hashed into the leaf**, so editing it changes the root and
breaks the signature. It's evidence, not a comment.

### `validity` — how long the claim holds

```json
"validity": { "days": 365 }                  // window from the batch date
"validity": { "until": "2027-12-31" }        // fixed end
"validity": { "openEnded": true }            // only a revocation can end it
```

`basisAsOfOffsetDays` (or the per-subject `evidenceDate` column) records when
you examined the evidence — deliberately separate from when the claim starts,
because the gap between them is the staleness a reviewer wants to see.

### `security` and `manifest`

```json
"security": {
  "epochDaysSource": "fixed:20689",     // or "env:TRUSSET_KYC_EPOCH_DAYS". Pin it.
  "registryDir": "config/registry",
  "deterministic": true
},
"manifest": {
  "version": "3.0.0",                   // "2.1.0" keeps the old bundle shape
  "issuer": { "name": "...", "identifierScheme": "LEI", "identifier": "...",
              "jurisdiction": "DE", "keyId": "issuing-2026-08" }
}
```

`manifest.issuer` is who is legally responsible. Required for v3 bundles.

Allowlists resolve from the signed registry, so `lists` can be left empty. A
bare `path` to a `trusset-list-commit` file still works but warns: superseded
versions of a plain file aren't kept, and an old proof's root then can't be
traced back to the set it committed to.

---

## How it works

Each field becomes a **leaf**. Its value is committed with a hiding
Rescue-Prime commitment and a fresh per-leaf nonce, a STARK proves the
predicate about that commitment, and the leaf hash binds:

```
leaf_hash = Rescue( LEAF_TAG ‖ field ‖ circuit_id ‖ wallet ‖ epochDays
                    ‖ commitment ‖ public_digest ‖ proof_digest
                    [‖ binding_digest] )     ← the claim descriptor + validity
```

Leaves are sorted, padded to a power of two, and merged into a Rescue-Prime
Merkle root. That root is your `kycHash`.

Because the wallet, the batch date, the circuit id, and the descriptor are all
inside the leaf hash, a proof can't be replayed for another subject, another
date, another predicate, or another stated meaning. Any of those changes the
root, which breaks the signature and the on-chain anchor.

Key material flows one way:

```
TRUSSET_KYC_MASTER_KEY  →  wraps a per-subject key inside secrets.enc
                        →  per-subject seed  →  per-leaf nonce
TRUSSET_KYC_SIGNING_KEY →  ed25519 over the manifest and the registries
```

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the crate map and full data
flow. [docs/CIRCUITS.md](docs/CIRCUITS.md) has the formal statement each
circuit proves.

---

## What changed in v3

If you already run v2, read
[docs/MIGRATION_V2_TO_V3.md](docs/MIGRATION_V2_TO_V3.md). **Your existing
bundles keep verifying, unchanged** — enforced by tests against a real v2.0.0
fixture, not just intended.

The short version of what was wrong and what fixes it:

| Before | Now |
|---|---|
| Default batch date was the wall clock, so a bundle couldn't be reproduced the next day | Pinned dates required; `utc_today` refused outside a dev flag |
| Rotating an allowlist overwrote it — old proofs' roots had no retrievable meaning | Append-only signed registry; every version keeps its values, and each leaf records which one it used |
| A leaf said `minAgeDays: 6570` and nothing about what rule that was | Legal basis, warranting party, evidence class, and validity, hashed into the leaf |
| No bundle said who issued it | `manifest.issuer`, plus the SHA-256 of the prover binary that built it |
| No way to ask what was true at a past block | `--as-of-block` / `--as-of-date`, resolved from your own signed root history |
| No way to say a claim ended, or was never valid | Separate signed records; `lapsed` and `void_ab_initio` are distinct and can't be conflated |
| A typo'd `investorType` was silently rewritten to the default and signed | The row is quarantined |
| `--skip-proofs` proved everything and threw it away | Actually skips proving; 33 s → 0.8 s on a test batch |
| The README told you to verify with `--public-key <hex>` and nothing printed that hex | `init` and `show` both print it; it's in the manifest too |

---

## Security

Everything runs locally. No outbound network calls, at any point, including
verification.

| | |
|---|---|
| **Hiding commitments** | 32-byte per-leaf nonces from an independent per-subject key — low-entropy fields like `dateOfBirth` aren't rainbow-tableable from an inclusion proof |
| **Key wrapping** | The master key only wraps the per-subject key inside `secrets.enc`; one compromise doesn't recover every nonce ever issued |
| **Domain separation** | Ten 32-byte tags, pairwise-distinct at compile time |
| **Replay protection** | Wallet, batch date, circuit id, and descriptor all inside the leaf hash |
| **Signed manifests** | ed25519 over a canonical view with a sentinel timestamp, so signatures are byte-identical across runs |
| **Root anchoring** | Verify against the on-chain `kycHash` with no key pinning at all |
| **Encrypted at rest** | `secrets.enc` is XSalsa20-Poly1305, libsodium-compatible, payload key wrapped under the master key |
| **Determinism** | Pinned date + fixed master key ⇒ byte-identical reruns. Any OS-entropy draw during a deterministic run aborts |
| **Append-only records** | List versions, root anchors, and revocations are signed and never rewritten |
| **Post-quantum-friendly** | Goldilocks field, Rescue-Prime hash, Winterfell STARK. The ed25519 manifest signature is not PQ — root-anchored verification sidesteps it |

**Look after two things:** `.trusset/keys.env` (mode 0600, never commit it —
lose it and you can't reproduce or decrypt anything) and your `secrets.enc`
files (the only copy of witness material under non-deterministic issuance).

Full threat model, key hierarchy, and per-field disclosure table:
[docs/SECURITY.md](docs/SECURITY.md).

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `epochDaysSource is "utc_today"` refusal | Working as intended. Pin it: `"fixed:<today>"`. `init` does this for you |
| `TRUSSET_KYC_MASTER_KEY is not set` | `set -a && . ./.trusset/keys.env && set +a` — needed in each new shell |
| `manifest.issuer: missing` | v3 bundles record who's responsible. Run `npm run init`, or set `manifest.version` to `"2.1.0"` |
| `predicates.X.descriptor is missing` | Every predicate needs a legal basis and evidence class. `init` writes starting values to edit |
| `list "X" ... has no source` | `npm run list-version -- --list-id X --source <file>` |
| `E_LIST_MEMBER_MISSING` | The subject's value isn't in the allowlist. Add it and record a new version, or exclude the subject |
| `Entitled: NO` but `Verifies: PASS` | The proof is fine; the claim lapsed, was voided, or is outside its validity window. The per-leaf status says which |
| `cargo not found` | Install Rust from [rustup.rs](https://rustup.rs). There are no prebuilt binaries |

`npm start -- --dry-run` reports every problem in a batch at once, so you
rarely need to fix these one at a time.

---

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crate map, data flow, artifact contract |
| [CIRCUITS.md](docs/CIRCUITS.md) | What each circuit actually proves, and the v3 leaf binding |
| [SECURITY.md](docs/SECURITY.md) | Threat model, key hierarchy, disclosure table, allowlist rotation |
| [MIGRATION_V2_TO_V3.md](docs/MIGRATION_V2_TO_V3.md) | Upgrading with bundles already in the field |
| [MIGRATION_FROM_V1.md](docs/MIGRATION_FROM_V1.md) | The v1 → v2 path |
| [PERFORMANCE.md](docs/PERFORMANCE.md) | Measured times and sizes, with the hardware caveats stated |
| [RELEASE_GATE.md](docs/RELEASE_GATE.md) | v3.0.0 gate results, verbatim |
| [AUDIT_PREP.md](docs/AUDIT_PREP.md) | Spec §12 traceability matrix |
| [FUTURE_WORK.md](docs/FUTURE_WORK.md) | What was deliberately left out, and why |

### Contributing

```bash
bash scripts/ci_smoke.sh            # fmt, clippy, tests, and all four e2e suites
bash scripts/ci_smoke.sh --quick    # fmt, clippy, tests only
```

---

<div align="center">

Built by [Trusset](https://trusset.org) · [Report an issue](https://trusset.org/contact)

</div>
