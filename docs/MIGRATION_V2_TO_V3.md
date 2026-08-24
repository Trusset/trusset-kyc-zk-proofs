# Migrating from v2 to v3

v3 changes what a bundle *says*, not how it is proved. The circuits, the
commitment scheme, the Merkle construction, and `CIRCUITS_VERSION` are all
unchanged at 3. What changes is that a bundle now records who is responsible
for its assertions, what legal test each predicate stands for, how long each
claim is asserted for, and which version of which list a set-membership proof
was made against — and that the operator keeps an append-only record of the
things a proof depends on but does not contain.

**Every bundle you have already issued keeps verifying, unchanged, under v3
tooling.** That is enforced by tests, not by intention; see §7.

---

## 1. What problem this release exists to fix

v2 proved what is true now and gave you no reliable way to prove what was true
then. Concretely, before v3:

| Question a counterparty or regulator asks | v2 answer |
|---|---|
| Reproduce this bundle so I can check it | Impossible one day later, under the shipped default `epochDaysSource: "utc_today"` |
| What set was `setRoot: 0x9078…` a commitment to? | Unrecoverable once the list file was regenerated |
| Which institution asserts this? | Not recorded anywhere in the bundle |
| Under what rule is "minAgeDays: 6570" asserted? | Not recorded |
| Was this subject entitled at block N? | No way to ask |
| This claim turned out to be false — how do I say so? | No mechanism; editing the manifest breaks its signature |

Every one of those is a question about evidence rather than about
cryptography, which is why none of them needed a circuit change to fix.

---

## 2. Manifest version 3.0.0

`manifest.version` becomes `3.0.0`. The verify path accepts `2.0.0`, `2.1.0`,
and `3.0.0`.

New top-level fields, all optional-with-omission so a v2 manifest still
re-serializes byte-identically:

| Field | Meaning |
|---|---|
| `issuer` | The party legally responsible: name, identifier scheme and value, jurisdiction, key id, and the ed25519 public key the signature should be checked against |
| `toolchain` | `proverVersion` and the SHA-256 of the prover binary that actually ran, so a bundle can be traced to a build years later |
| `epochDaysSource` | The expression that produced `epochDays`, e.g. `fixed:20689` |
| `asOfDate` | `epochDays` rendered `YYYY-MM-DD`, because auditors read dates |
| `unpinnedEpoch` | Present and `true` only on a development bundle built with `--dev-unpinned-epoch`. Such a bundle cannot be reproduced and says so for the rest of its life |

New per-leaf fields:

| Field | Meaning |
|---|---|
| `binding.descriptor` | `legalBasis` (framework, reference, assertion), `issuingParty`, `evidenceClass`, optional `evidenceRef` |
| `binding.validity` | `from`, optional `until`, and `basisAsOf` — all `epochDays` |
| `binding.listVersion` | For `set_membership`: which list, which version, its root and content hash |
| `bindingDigest` | `Rescue(LEAF-BIND ‖ canonical_json(binding))`, appended to the leaf-hash preimage |

**A v3 bundle's `kycHash` differs from what v2 would have produced for the same
subject and inputs**, because the binding digest is inside the leaf hash. A
leaf carrying no binding block hashes over exactly the v2 preimage, which is
what keeps existing bundles valid.

### Keeping the v2 shape while you migrate

Set `manifest.version` to `"2.1.0"` in `config.json`. The run then produces
exactly the bundle it always did: no issuer, no descriptors, no validity, and
the v2 leaf-hash preimage. Nothing else in your configuration needs to change.
Use this if you have downstream consumers that must be updated first.

---

## 3. `utc_today` is now refused

This is the change most likely to stop an existing pipeline, and it is
deliberate.

`epochDays` is folded into every per-subject key, every commitment nonce, and
every leaf hash. Under `utc_today` that number is whatever day the batch
happened to run, so the bundle cannot be regenerated tomorrow. `docs/SECURITY.md`
promised that a bundle could be re-derived from the original records; under the
shipped default it could not, and that promise is the one an audit actually
tests.

```
security.epochDaysSource is "utc_today", which resolves to whatever day this
batch happens to run.
  Today that is 2026-08-24 (epoch day 20689).
  Every per-subject key, commitment nonce, and leaf hash derives from that
  number, so a bundle proved this way cannot be reproduced tomorrow and cannot
  satisfy an audit that asks you to.
  Fix: set "epochDaysSource": "fixed:20689" in config.json ...
```

**What to do:** pin the batch as-of date.

- `"epochDaysSource": "fixed:<n>"` — one date for all runs of a batch. `npm run init` writes today's value.
- `"epochDaysSource": "env:TRUSSET_KYC_EPOCH_DAYS"` — supply it per run, which is what a scheduled pipeline usually wants.

`--dev-unpinned-epoch` restores the old behaviour for development. It prints a
banner, and the bundle carries `unpinnedEpoch: true` permanently. Verification
reports it. Do not issue evidence this way.

The refusal is enforced in both layers: the TypeScript config resolver and the
prover itself, so a hand-written job spec cannot route around it.

---

## 4. Lists move into an append-only registry

### What was wrong

A `set_membership` proof records the Merkle root of the list it was proved
against. `trusset-list-commit` wrote its output over the previous file, so once
you rotated a list, nothing on disk mapped an old root back to the values it
committed to. A bundle from two rotations ago asserted membership in a set
nobody could name.

The claim in `docs/SECURITY.md` that "existing bundles keep verifying" was
true and is still true. What was missing was any way to say *what they assert*.

### What replaces it

`config/registry/lists/<listId>.json`, append-only and signed with the same key
that signs manifests. Every version keeps its values, its root, its content
hash, and the `epochDays` window over which it was authoritative. Superseded
versions are never removed; the writer refuses to modify or reorder them.

```bash
npm run list-version -- \
  --list-id country_allowlist \
  --source config/list_commitments/country_allowlist.source.txt \
  --effective-date 2026-09-01 \
  --note "Sanctions review 2026-Q3"
```

```
country_allowlist: recorded version 2 effective 2026-09-01 (17 entries)
  root         0x10dc9ba7716ba43a5469ba13159413407a46d9bd1a1e34afa1bc0abd221dd67a
  contentHash  0xc1aba62b30e7f7489a0428d2a50daf87060836530636b9a64111bb85c7e778ac
  supersedes   version 1 (its window closed on 2026-08-31)
```

Each leaf records the version it used, so verification resolves the list from
the leaf and never from current config. A bundle proved against version 1 keeps
resolving to version 1 and its 17 original values after any number of
rotations.

`trusset-list-commit` still exists and still works. `config.lists.<id>.path`
still resolves. A v3 run using a bare list file warns that superseded versions
are not retained, and refuses to build an archive that would depend on one.

**Migration:** run `npm run list-version` once per list to record version 1
from your current source file. `npm run init` does this automatically for every
`config/list_commitments/*.source.txt` it finds.

---

## 5. Claim descriptors are required

Every predicate now needs a `descriptor` and a `validity` block. A run with
`manifest.version: "3.0.0"` and a predicate missing either one fails with the
config path, the problem, and the fix.

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

`claims.defaults` supplies `issuingParty`, `evidenceClass`, and `validity` for
every predicate that does not override them.

### Evidence classes

Six values, ordered roughly by assurance but **not** a comparable scale:
nothing in the codebase compares two of them, and no predicate accepts an
evidence-class threshold.

| Value | Meaning |
|---|---|
| `SELF_ATTESTED` | Subject asserted it; not independently checked |
| `DOCUMENTARY` | Verified against a document copy, not the physical or chip original |
| `THIRD_PARTY_RELIANCE` | Verified by another regulated firm under a reliance arrangement; `issuingParty` names them |
| `AUTHORITATIVE_SOURCE` | Verified against an issuer or registry you queried |
| `CRYPTOGRAPHIC` | Verified by a cryptographic check on an issued credential |
| `PHYSICAL_PRESENCE` | Subject and original documents present, or equivalent remote assurance |

### `issuingParty`

Defaults to `"self"`, meaning the bundle issuer warrants the claim. A named
party is for reliance arrangements, where another regulated firm did the
verification and you are passing on their assurance. The issuer still signs;
the descriptor records who stands behind the specific claim.

### A note on `investorType`

The tiers `NONE / RETAIL / PROFESSIONAL / ELIGIBLE_COUNTERPARTY` are the MiFID
II client-categorisation set. v3 says so in the descriptor rather than leaving
`minTier: 2` as an anonymous integer.

The ordering itself is unchanged and is **not** configurable metadata: it is
compiled into the `tier_threshold` AIR, which constrains `tier - min_tier` to
`{0,1,2}`. It is sound for the predicate the circuit actually proves — "at
least as sophisticated as" — and that reading matches how the categories
escalate in practice. It does not capture that a per-se professional and an
elective professional carry different protections, or that on a
protection-owed axis the ordering inverts. Record the per-se/elective
distinction in `descriptor.legalBasis.reference` if it matters to you.

Note also that `minTier: RETAIL` — the v2 example default — is vacuous: the
circuit already refuses to prove `NONE`, so "at least RETAIL" is true of every
provable tier. `config.example.json` now uses `PROFESSIONAL`.

---

## 6. Validity, lapse, and voidance

### Validity intervals

Each leaf records `from`, optional `until`, and `basisAsOf`. `basisAsOf` is
when the evidence was examined, which is not when the claim starts: a passport
checked in January and used for a March issuance has January in `basisAsOf` and
March in `from`, and the gap is exactly the staleness a reviewer wants to see.

Set it per subject with an `evidenceDate` column in the input
(`mapping.evidenceDateField`), or per predicate with
`validity.basisAsOfOffsetDays`.

`softExpiryDays` and `hardExpiryDays` are unchanged, still passthrough, and
still not covered by any proof. They were never an expiry *model* — nothing in
this repository evaluated them, and nothing recorded what date they counted
from. Validity intervals are the model; the two passthrough integers remain for
the issuer backend that consumes them.

### Lapse versus voidance

A signed manifest cannot be edited, so ending a claim is a separate signed
record rather than a field on the leaf. The distinction matters legally and the
tool refuses to blur it:

| | `lapsed` | `void_ab_initio` |
|---|---|---|
| Means | The claim was true and stopped being true | The claim was never true |
| Requires `--effective-date` | Yes — it is the whole content of the record | No, and passing one is rejected |
| Reliance before that date | Stands | Is in question |
| Reliance at any other date | Stands before, fails from the date on | Fails, at every instant |
| Bundle still verifies | Yes | **Yes** |

The last row is deliberate. A voided bundle keeps verifying because the proof
is a true record of what the operator asserted; destroying it to express that
the assertion was wrong would destroy the evidence of the misstatement.
`overall_pass` stays true and `temporal.entitled` goes false.

```bash
npm run revoke -- --bundle output/0xWALLET --leaf investorType \
  --effect lapsed --effective-date 2026-10-01 --reason PERIODIC_REVIEW_OVERDUE

npm run revoke -- --bundle output/0xWALLET \
  --effect void_ab_initio --reason FRAUDULENT_ONBOARDING
```

---

## 7. Verification: two questions, kept apart

`VerifyReport` gains `issuer`, `temporal`, and a per-leaf `claim`. The existing
fields are unchanged, so a consumer that reads `overall_pass` and `leaves[]`
keeps working.

| Question | Field | Answers |
|---|---|---|
| Does the bundle verify? | `overall_pass` | Pure cryptography. A bundle whose claims were later voided still passes |
| Could the subject rely on it at instant X? | `temporal.entitled` | Adds the root on chain then, the validity windows, and any revocation |

Exit codes: `0` verified and entitled, `2` verification failed, `3` verified
but not entitled, `64` usage, `66` unreadable.

### As-of verification

```bash
npm run verify -- 0xWALLET --public-key <hex> --as-of-block 8000100 --chain-id 1
npm run verify -- 0xWALLET --public-key <hex> --as-of-date 2026-09-15
npm run verify -- 0xWALLET --public-key <hex> --now 2027-09-01
```

**There is no chain access in this tool, and v3 does not add any.** An as-of
block query resolves against `config/registry/root_history.json`, a signed
append-only record of which root you published, at which block, at which
timestamp:

```bash
npm run anchor -- --bundle output/0xWALLET \
  --chain-id 1 --block 8000100 --block-time 1787529600
```

Record an anchor whenever you publish a root. Without one, an as-of block query
reports `Entitled: NO` with a note saying the answer is unknown rather than
false — an entitlement question is never answered YES from absent evidence.

### v2 bundles under a v3 verifier

They verify exactly as before. `issuer` is `null`, every leaf's `claim` is
`null`, and `temporal.notes` says so:

> no leaf carries a claim descriptor or validity interval: this is a pre-v3
> bundle, so what each predicate stands for and how long it was asserted are
> not recorded.

Enforced by `bundle-format/tests/v200_backward_compat.rs` against a real
v2.0.0 fixture, and by `v3_manifest_version_is_accepted` /
`unsupported_manifest_version_is_rejected` in the verifier suite.

**Counterparties running their own verifier must rebuild it.** A verifier that
re-serializes the typed manifest struct to recompute the signing view will drop
fields it does not know about and compute the wrong bytes. For the Trusset
issuer backend that means re-vendoring the WASM via
[`scripts/rebuild-wasm.sh`](../scripts/rebuild-wasm.sh) and widening its
accepted `manifestVersions`.

---

## 8. Archives

`npm run archive` produces one integrity-checked file containing the bundles,
the list registries their proofs depend on (every version, including
superseded), the root history, the revocation log, and the issuer identity.

```bash
npm run archive -- --output nordbank-2026Q3.tka --all output
trusset-verifier-cli --archive nordbank-2026Q3.tka --public-key <hex>
```

Verification from the archive needs the file and a verifier binary. No config,
no registry, no output tree, no network, no chain. The archive's `digest`
covers everything except its own `createdAt`, so two archives of the same
content compare equal and any modification is refused at parse time.

`secrets.enc` is **not** included unless you pass `--include-secrets`: an
archive is usually handed to a counterparty, and the witness blob is
operator-private even though it is encrypted.

---

## 9. Operator workflow changes

### `npm run init`

Replaces the manual setup. Generates both keys with Node's CSPRNG — `openssl`
is no longer needed, and never had a security reason to be — writes them to
`.trusset/keys.env` at mode 0600, adds that path to `.gitignore`, writes a v3
`config.json` with the epoch pinned to today and starting descriptors filled
in, records version 1 of every list it finds, validates the environment, and
prints your ed25519 public key.

That last item closes a real gap: v2's README documented
`npm run verify -- <wallet> --public-key <hex>` and the tool emitted that hex
nowhere. `npm run show` also prints it.

### `npm start -- --dry-run`

Validates an entire batch and reports every problem at once — input parsing,
TypeScript validation, config resolution, and the prover's own witness and
predicate checks — writing nothing and requiring no key material. Problems are
grouped by subject, and each names the field, the subject, and the fix.

### Silent value substitution is now a failure

v2's `resolveInvestorType` and `resolveExpiryDays` returned the configured
default for any value they did not recognise. A row declaring
`investorType: "PROFESSIONAL_INVESTOR"` (a typo) was silently recorded as
`RETAIL`, signed, and committed into `kycHash`, with no warning and no failure
row — a signed bundle asserting a tier the operator never declared, in a
context where retail and professional are different regulatory regimes.

Blank still means "use the configured default". A value that is present and
unusable is now a quarantined row:

```
0x2222…  (input row 5)
  [input] investorType  E_INPUT
      field "investorType" is "PROFESSIONAL_INVESTOR", which is not a recognised
      investor type. Fix: use one of NONE, RETAIL, PROFESSIONAL,
      ELIGIBLE_COUNTERPARTY, or leave the column blank to take the configured
      default (RETAIL).
```

**Check your inputs before upgrading.** Rows that v2 silently coerced will now
be rejected. That is the point, but it will change your batch outcomes.

### Failure messages

Prover failures now name the leaf and never echo the witness value:

```
✘  0x7777…  [E_LIST_MEMBER_MISSING] leaf "nationality" (set_membership): this
   subject's value is not a member of list 'country_allowlist' (17 entries, root
   0x90785a7ea7). Fix: add the value to the list source and run
   `npm run list-version -- --list-id country_allowlist`, or exclude the subject.
```

v2 wrote `value 'BRA' not in list 'country_allowlist'` into
`output/failures.csv`, disclosing the exact attribute the `nationality`
predicate exists to keep private, in a file that travels. The leaf name and the
wallet locate the input row without disclosing it.

### `--skip-proofs` is now fast

It ran the full STARK and then discarded the bytes, so it cost the same as a
real run. It now runs each circuit's `validate()` instead — predicates are
still enforced, an under-age subject still fails — and skips proving. On the
reference batch the dry run went from 33.3 s to 0.77 s. Stub bundles are
byte-identical to what v2 produced.

---

## 10. New error codes

`E_ISSUER_MISSING`, `E_DESCRIPTOR_MISSING`, `E_DESCRIPTOR_INVALID`,
`E_VALIDITY_INVALID`, `E_LIST_VERSION_MISMATCH`, `E_UNPINNED_EPOCH`. Existing
codes are unchanged.

---

## 11. Toolchain

`rust-version` in `Cargo.toml` moves from 1.75 to **1.82**. The declared 1.75
had not been accurate for some time — `rust-toolchain.toml` pins 1.91 — and
v3 uses `Option::is_none_or`, stable since 1.82. Node stays at 18+.

No prebuilt binaries. Everything is still built from source, which is why
`manifest.toolchain.proverSha256` records the digest of the binary that
actually ran: it is what lets a bundle be traced to a build rather than to
"some version of the tool".

---

## 12. Upgrade checklist

1. `npm run build`
2. `npm run init` — or, on an existing tree, add `manifest.issuer` and
   `claims.defaults` to `config.json` by hand and run `npm run list-version`
   once per list.
3. Pin `security.epochDaysSource`.
4. Add a `descriptor` and `validity` to every predicate.
5. `npm start -- --dry-run` and read what it says about rows v2 used to coerce.
6. Issue. `npm run anchor` after each publish.
7. `npm run archive` per batch, and store the archive where you store
   everything else you would have to produce years later.
8. Existing bundles: leave them alone. They verify. Re-issue only if you need
   the claims they assert to carry descriptors.
