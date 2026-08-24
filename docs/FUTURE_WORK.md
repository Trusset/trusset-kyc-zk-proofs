# Future work

Design directions that are deliberately out of scope for v3.0.0, with the
reasoning and the migration cost each would carry. Nothing here is a
defect; these are the choices a later major version has to make.

## Single per-subject AIR verifying the Merkle root in-circuit

**What it is.** Instead of one STARK per leaf plus an out-of-circuit
Rescue Merkle root, one AIR per subject that takes every field's witness,
computes every commitment, computes every leaf hash, walks the whole
subject tree, and asserts the root equals a public input. The bundle
collapses to a single proof and a single public root.

**Why it is the right long-term design.** It removes the entire manifest
layer from the verifier's trust model. Today a counterparty must parse
`manifest.json`, trust that the recorded `leafHash` values are the ones
the proofs bind, recompute the tree itself, and check an ed25519
signature or an on-chain root to know the manifest was not rewritten. In
the collapsed design the proof itself establishes "these committed values
hash into this root", so the manifest becomes a convenience index rather
than a load-bearing artifact, and both `manifest.sig` and the per-leaf
file layout drop out of the verification path entirely.

**Why not now.** It changes the artifact contract the issuer backend
consumes. `services/customers/proofVerificationService.js` drives a
per-leaf check ladder: `publicDigest` recomputation, `proofDigest`
matching against uploaded bytes, `leafHash` recomputation, sorted-pair
root recomputation, then per-leaf STARK verification against a claim
slot. Every one of those steps assumes per-leaf proofs. The backend also
attests individual claims on chain (`CustomerProof` rows keyed by
`claimType`), which requires being able to present one field's proof
without the others. A single per-subject proof cannot do selective
disclosure at all without recursion or a separate opening protocol.

**Migration cost.** New AIR (large: Rescue sponge per field plus the full
tree walk, likely 10-50x the current `set_membership` trace), a new
manifest major version, a rewritten backend check ladder, a re-vendored
WASM with different exports, and re-proving every subject. Selective
disclosure needs solving first or the feature regresses.

## On-demand disclosure-time proving

**What it is.** Move proving out of batch issuance. The operator stores
commitments and witnesses; a proof is generated when a specific
counterparty asks a specific question, bound to that counterparty and
that moment.

**Why it is attractive.** It fixes the freshness problem structurally.
Today `epochDays` is baked into the leaf hash at issuance and the backend
enforces a staleness window (`defaultMaxStalenessDays: 400`) because a
proof issued a year ago still verifies. It also fixes predicate rigidity
at the root: a counterparty needing "over 21" gets a proof for over 21,
rather than the operator having to have predicted that threshold at
issuance. Multi-instance predicates are a partial answer that
still requires predicting the set of thresholds in advance.

**Why not now.** Issuance-time proving is what makes the tool an offline
batch utility with no service to run. On-demand proving means a live
signing service holding master key material, with an availability and
authentication story the current threat model does not have. It also
inverts the trust direction: the operator becomes an online participant
in every verification rather than a one-time issuer.

**Migration cost.** A long-lived service, key custody at runtime (HSM
becomes mandatory rather than recommended), a request protocol with
replay protection, and a rewrite of the counterparty integration. The
`kycHash` on-chain anchor keeps working, so this can be additive rather
than a replacement.

## Recursion, proof aggregation, and the proving-stack question

**What it is.** Wrap the per-leaf proofs in a recursive verifier so one
succinct proof attests to all of them, or aggregate across subjects so a
batch has a single proof.

**Why it matters here.** Bundle size is 196 KB of proof bytes for 9
leaves and prove time is 4.2 s per subject, dominated by three
`set_membership` proofs at roughly 1.2 s each. Aggregation compresses both, and
it is also the precondition for the single per-subject AIR above becoming
practical with selective disclosure.

**The stack question that follows.** Winterfell 0.13 has no recursion
support and no in-circuit STARK verifier. Getting recursion means moving
the proving stack, and the realistic candidates are Plonky3 (recursion,
active development, Goldilocks-friendly, but a different AIR authoring
model) or Miden VM (a real recursive verifier, but reframes the circuits
as VM programs rather than hand-written AIRs). Winterfell 0.13 also lacks
zero-knowledge blinding entirely, which is the other reason a stack move
eventually becomes necessary - see the note below.

**Migration cost.** Full rewrite of all four circuits, a new proof
serialization, a new WASM verifier, re-proving every subject, and a fresh
security review of the new stack's parameters. This is a major-version
project, not an increment.

## Zero-knowledge blinding

The proofs this tool produces are sound but not zero-knowledge in the
formal sense. Winterfell 0.13 does not add randomized blinding columns to
the trace, and `derive_prover_seed` in
[`circuits/common/src/seed.rs`](../circuits/common/src/seed.rs) is
currently unused: every circuit's `prove()` passes a zero seed that the
prover discards, so proof bytes are a deterministic function of the
witness.

What actually hides the field values is the hiding commitment: the
witness is only ever exposed as `Rescue(COMMITMENT_TAG || circuit_id ||
len || witness || nonce)` with a 32-byte nonce, and the AIR proves
statements about that commitment. An adversary who guesses a candidate
value cannot confirm it without the nonce.

The gap is that determinism makes proof bytes a stable fingerprint of the
`(witness, nonce)` pair. Two bundles for the same subject at the same
epoch under the same key produce byte-identical proofs, which is exactly
what the determinism canary asserts and what auditors want. It also means
a counterparty holding two bundles can tell whether a field changed
between them without learning its value. Under `security.deterministic:
false` the per-subject key is fresh, so the nonces and therefore the proof
bytes differ between issuances and this linkability goes away.

Closing the gap properly needs blinding in the proving stack, which loops
back to the stack question above.

## Prebuilt binaries

**What it is.** Publishing signed `trusset-prover`, `trusset-verifier-cli`,
`trusset-registry`, and `trusset-archive` builds so `npm install` does not
compile 130 crates on a fresh checkout.

**Why it is attractive.** Cold start drops from minutes to seconds, which is
most of the distance between "clone" and "first bundle" for an operator who
does not already have Rust. The binaries are unusually easy to ship: they link
only `libSystem` and `libiconv` on macOS and would be fully static under musl
on Linux, so five targets (macOS arm64/x86_64, Linux x86_64/aarch64-musl,
Windows x86_64) at three binaries each is about 30 MB raw and 10 MB
compressed.

**Why not now.** It puts a network fetch into the install path of a tool whose
security model says it makes no outbound calls, and it turns "did you build
this?" into "do you trust the release channel?". Checking binaries into git
avoids the fetch but bloats the repository permanently and gives the operator
no better assurance. Either way the artifacts need signing, checksum pinning,
and a provenance record, and the decision belongs to whoever runs the release
process rather than to the code.

**What v3 did instead.** Every bundle records
`manifest.toolchain.proverSha256`, the digest of the binary that actually ran.
That is the half of the problem that matters for evidence — tracing a bundle
to a build — and it is worth having whether or not binaries are ever
published.

## Per-field evidence dates

`validity.basisAsOf` is per subject: the `evidenceDate` column applies to every
leaf of a row. In practice a bank often examined a passport in January and
verified source of wealth in March, and the two claims have different
staleness. Expressing that needs a per-field evidence date in the input
schema, which is a wider input format rather than a deeper one, and was left
out of v3 to keep the CSV shape recognisable.

## Completing the `tier_threshold` prove-time investigation

`tier_threshold` proves in 550 ms for a 16 x 32 trace while
`age_threshold` proves in 198 ms for a larger 34 x 32 trace. Column
count, transition-constraint count, and declared degrees do not explain
the gap; the suspect is the constraint composition polynomial degree
driven by the degree-7 Rescue rounds combined with the Pattern A
accumulator walks. Pinpointing it needs Winterfell-internal timing per
sub-phase (trace LDE, constraint evaluation, composition polynomial
construction, FRI). Purely a developer-experience cost - correctness and
soundness are unaffected.
