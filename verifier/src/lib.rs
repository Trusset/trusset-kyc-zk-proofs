//! `trusset-verifier` — counterparty verification path.
//!
//! Given a bundle directory produced by `trusset-prover` and an out-of-band
//! pinned ed25519 public key, `verify_bundle` returns a structured
//! `VerifyReport` covering every check spec §10's `npm run verify`
//! semantics requires:
//!
//!   1. Manifest JSON parses against the schema.
//!   2. Bundle filesystem layout is intact (manifest.json, manifest.sig,
//!      kycHash.hex, proofs/*.bin all present).
//!   3. `mode` field is acceptable (rejected when `mode == "stub"` unless
//!      `accept_stub = true`).
//!   4. `kycHash.hex` matches `manifest.kycHash`.
//!   5. ed25519 signature over the *signing view* of the manifest (with
//!      `createdAt` overwritten to the sentinel) verifies under the pinned
//!      public key.
//!   6. Each leaf's:
//!        - `commitment` is referenced by `publicInputs.commitment`
//!        - on-disk proof file's SHA-3-style Rescue `proofDigest` matches
//!        - circuit's native `verify()` accepts the proof against the
//!          reconstructed `PublicInputs`
//!        - `leafHash` equals `compute_leaf_hash(...)` recomputed from
//!          field name, circuit id, wallet, epochDays, commitment, public
//!          digest, proof digest
//!   7. Rescue Merkle root re-derived from the (sorted) leaf hashes equals
//!      `manifest.kycHash`.
//!
//! WASM entry points live in `wasm.rs` behind the `wasm` cargo feature.

pub mod bundle;
pub mod v31;

#[cfg(feature = "wasm")]
pub mod wasm;

use std::path::Path;

use serde::Serialize;
use trusset_bundle_format::claims::compute_binding_digest;
use trusset_bundle_format::leaf::{compute_leaf_hash_bound, compute_proof_digest};
use trusset_bundle_format::manifest::{
    canonical_signing_bytes, is_v31, Manifest, ACCEPTED_MANIFEST_VERSIONS,
    DISCLOSURE_COMMITMENT_ONLY, MODE_PRODUCTION, MODE_STUB,
};
use trusset_bundle_format::merkle::compute_root_versioned;
use trusset_bundle_format::registry::{ClaimStatus, ListRegistry, RevocationLog, RootHistory};
use trusset_bundle_format::sign;
use trusset_circuits_common::{bytes32_to_hex, digest_to_hex, hex_to_digest, CircuitId, Digest};

/// Anchor the verification is rooted in. At least one must be supplied:
/// a bundle verified against neither anchor proves nothing about who
/// issued it.
#[derive(Debug, Clone, Default)]
pub struct VerifyAnchors {
    /// 32-byte ed25519 public key pinned out-of-band (e.g. published on the
    /// operator's website, hardcoded in the consumer's config). Use for
    /// offline bundles where the root is not independently known.
    pub expected_public_key: Option<[u8; sign::PUBLIC_KEY_LEN]>,
    /// `kycHash` read from chain by the caller. When supplied the on-chain
    /// root authenticates the bundle and no out-of-band key pinning is
    /// required.
    pub expected_root: Option<String>,
}

impl VerifyAnchors {
    pub fn is_empty(&self) -> bool {
        self.expected_public_key.is_none() && self.expected_root.is_none()
    }

    /// Human-readable description used in `VerifyReport.anchor`.
    pub fn label(&self) -> &'static str {
        match (
            self.expected_public_key.is_some(),
            self.expected_root.is_some(),
        ) {
            (true, true) => ANCHOR_BOTH,
            (true, false) => ANCHOR_PUBLIC_KEY,
            (false, true) => ANCHOR_ROOT,
            (false, false) => ANCHOR_NONE,
        }
    }
}

pub const ANCHOR_PUBLIC_KEY: &str = "public_key";
pub const ANCHOR_ROOT: &str = "root";
pub const ANCHOR_BOTH: &str = "public_key+root";
pub const ANCHOR_NONE: &str = "none";

/// The instant a verification asks about.
///
/// Every entitlement question in securities is about a past moment, not about
/// now. `AsOf::Now` answers "is this claim usable today"; the other two answer
/// "was it usable then", which is what a dispute two years later actually
/// turns on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsOf {
    /// Evaluate against the verifier's current clock.
    Now,
    /// Evaluate against the state at a block height on a chain, resolved
    /// through the operator's signed root history.
    Block { chain_id: u64, height: u64 },
    /// Evaluate against a calendar day, expressed as `epochDays`.
    Date { epoch_days: u64 },
}

/// Registries a verifier can consult. All optional: a bundle still verifies
/// cryptographically without them, it just cannot be interpreted as fully.
#[derive(Debug, Clone, Default)]
pub struct TemporalContext {
    pub root_history: Option<RootHistory>,
    pub revocations: Option<RevocationLog>,
    pub list_registries: std::collections::BTreeMap<String, ListRegistry>,
}

/// Options for `verify_bundle`.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Trust anchors. At least one is required.
    pub anchors: VerifyAnchors,
    /// If `false`, manifests with `mode != "production"` are rejected. If
    /// `true`, `mode == "stub"` is tolerated (mirrors the
    /// `TRUSSET_KYC_ALLOW_STUB=1` env var on the prover side).
    pub accept_stub: bool,
    /// The instant to evaluate validity and revocations against.
    pub as_of: AsOf,
    /// Registries backing an as-of query.
    pub context: TemporalContext,
    /// The verifier's current `epochDays`. Supplied by the caller rather than
    /// read from a clock inside the library so WASM and native agree and so
    /// tests can pin it.
    pub now_epoch_days: u64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            anchors: VerifyAnchors::default(),
            accept_stub: false,
            as_of: AsOf::Now,
            context: TemporalContext::default(),
            now_epoch_days: 0,
        }
    }
}

/// Result of `verify_bundle`. All checks are run even if earlier ones fail,
/// so the caller gets a full report instead of failing at the first
/// problem.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub wallet_address: String,
    pub kyc_hash: String,
    pub leaf_count: usize,
    pub layout_ok: bool,
    pub mode_acceptable: bool,
    pub kyc_hash_file_matches: bool,
    pub signature_valid: bool,
    pub merkle_root_valid: bool,
    pub leaves: Vec<LeafReport>,
    /// Which anchor(s) the caller supplied: `public_key`, `root`,
    /// `public_key+root`, or `none`. A report with `none` never passes.
    pub anchor: String,
    /// `true` when a caller-supplied root was checked and matched
    /// `manifest.kycHash`. `false` when no root anchor was supplied.
    pub root_anchor_valid: bool,
    /// Manifest version as read from the bundle, for callers that branch
    /// on it (`2.0.0`, `2.1.0`, or `3.0.0`).
    pub manifest_version: String,
    /// `true` iff every applicable check above passed and every leaf in
    /// `leaves` has `pass == true`.
    ///
    /// This is a statement about cryptography only. A bundle whose claims have
    /// since been declared void still passes here — the proof is a true record
    /// of what was asserted. Whether the claim may be relied on is
    /// `temporal.entitled`.
    pub overall_pass: bool,
    /// v3: who issued the bundle, read from the manifest. Absent on v2
    /// bundles, which record no issuer at all.
    pub issuer: Option<IssuerReport>,
    /// v3: the as-of evaluation.
    pub temporal: TemporalReport,
    /// v3.1: the signed header and the attestation the bundle supports.
    /// `null` for earlier versions.
    pub header: Option<v31::HeaderReport>,
}

/// The responsible party, surfaced from the manifest so a report is readable
/// without opening the bundle.
#[derive(Debug, Clone, Serialize)]
pub struct IssuerReport {
    pub name: String,
    pub identifier_scheme: String,
    pub identifier: String,
    pub jurisdiction: String,
    pub key_id: String,
    /// The key the manifest claims signed it. Cross-checked against the
    /// caller-pinned key when one was supplied; a mismatch is reported rather
    /// than silently preferring either.
    pub public_key: String,
    /// `true` when a caller-supplied `--public-key` differs from the key the
    /// manifest names. The signature check still governs; this flags that the
    /// bundle is claiming a different signer than the caller expected.
    pub public_key_disagrees_with_anchor: bool,
}

/// The outcome of evaluating a bundle at a particular instant.
#[derive(Debug, Clone, Serialize)]
pub struct TemporalReport {
    /// `now`, `block`, or `date`.
    pub as_of: String,
    pub as_of_epoch_days: u64,
    pub as_of_date: String,
    pub as_of_chain_id: Option<u64>,
    pub as_of_block: Option<u64>,
    /// The root the operator's signed history says was live at that block.
    pub resolved_root: Option<String>,
    /// Whether that historical root is this bundle's root. `None` when no
    /// as-of block was requested or no history was supplied.
    pub resolved_root_matches: Option<bool>,
    pub root_history_available: bool,
    pub revocations_available: bool,
    /// `true` when the bundle verifies cryptographically, its root was the one
    /// live at the queried instant (where that was checkable), and every leaf
    /// was effective then. This, not `overall_pass`, is the answer to "could
    /// this subject transact at that moment".
    pub entitled: bool,
    /// Everything the verifier could not establish, stated rather than
    /// silently omitted.
    pub notes: Vec<String>,
    /// v3: whether the bundle was produced against an unpinned wall-clock
    /// epoch and therefore cannot be reproduced.
    pub unpinned_epoch: bool,
    /// The manifest's own `asOfDate`, when it has one.
    pub manifest_as_of_date: Option<String>,
    pub epoch_days_source: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeafReport {
    pub field: String,
    pub circuit: String,
    pub pass: bool,
    /// Short human-readable reason for the failure if `pass == false`.
    pub reason: Option<String>,
    /// v3 claim descriptor and its status at the queried instant. Absent on
    /// leaves carrying no binding block.
    pub claim: Option<ClaimReport>,
}

/// What a leaf asserts and whether it may be relied on at the queried instant.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimReport {
    /// `effective`, `lapsed`, `void_ab_initio`, or `outside_validity`.
    pub status: String,
    pub detail: Option<String>,
    pub legal_basis: String,
    pub legal_reference: String,
    pub assertion: String,
    pub evidence_class: String,
    pub issuing_party: String,
    pub issuing_party_identifier: String,
    pub validity_from: u64,
    pub validity_from_date: String,
    pub validity_until: Option<u64>,
    pub validity_until_date: Option<String>,
    pub basis_as_of: u64,
    pub basis_as_of_date: String,
    /// For `set_membership` leaves: which list version the proof was made
    /// against, and whether the archive or registry could resolve it back to
    /// the values it committed to.
    pub list_id: Option<String>,
    pub list_version: Option<u32>,
    pub list_resolved: Option<bool>,
    pub list_entry_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Bundle directory missing or unreadable.
    Io(String),
    /// manifest.json failed to parse against the schema.
    ManifestParse(String),
    /// A digest field in the manifest is not 64-char hex.
    BadHex(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Io(s) => write!(f, "io: {}", s),
            VerifyError::ManifestParse(s) => write!(f, "manifest parse: {}", s),
            VerifyError::BadHex(s) => write!(f, "bad hex: {}", s),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        VerifyError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for VerifyError {
    fn from(e: serde_json::Error) -> Self {
        VerifyError::ManifestParse(e.to_string())
    }
}

/// Verify a bundle directory.
pub fn verify_bundle(
    bundle_path: &Path,
    opts: &VerifyOptions,
) -> Result<VerifyReport, VerifyError> {
    let loaded = bundle::load_bundle(bundle_path)?;
    Ok(verify_loaded(&loaded, opts))
}

/// Verify a bundle that has already been read into memory (used by both
/// the disk-driven entrypoint and the WASM bindings).
pub fn verify_loaded(loaded: &bundle::LoadedBundle, opts: &VerifyOptions) -> VerifyReport {
    let manifest = &loaded.manifest;

    // Merkle v3, the chain block, and leaf predicates exist only in 3.1.0. A
    // manifest relabelled to an earlier version must not slip past the 3.1.0
    // checks while keeping 3.1.0 structure.
    let v31_fields_only_in_v31 = is_v31(&manifest.version)
        || (manifest.merkle_version != Some(trusset_bundle_format::merkle::MERKLE_VERSION_V3)
            && manifest.chain.is_none()
            && manifest
                .leaves
                .iter()
                .all(|l| l.binding.as_ref().is_none_or(|b| b.predicate.is_none())));
    let version_acceptable =
        ACCEPTED_MANIFEST_VERSIONS.contains(&manifest.version.as_str()) && v31_fields_only_in_v31;
    let header = if is_v31(&manifest.version) {
        Some(v31::check_header(
            manifest,
            loaded.header_bytes.as_deref(),
            loaded.header_sig.as_deref(),
            opts.anchors.expected_public_key.as_ref(),
        ))
    } else {
        None
    };
    let layout_ok =
        loaded.layout_ok && version_acceptable && header.as_ref().is_none_or(|h| h.present);
    let mode_acceptable = manifest.mode == MODE_PRODUCTION || opts.accept_stub;
    let kyc_hash_file_matches = loaded.kyc_hash_file_text.trim() == manifest.kyc_hash;

    // Signature: recompute the canonical signing view of the manifest.
    // Only meaningful when the caller pinned a public key; a root-anchored
    // verification leaves this false and relies on `root_anchor_valid`.
    let signature_valid = match opts.anchors.expected_public_key {
        Some(pk) => match (canonical_signing_bytes(manifest), loaded.signature.as_ref()) {
            (Ok(payload), Some(sig)) if sig.len() == sign::SIGNATURE_LEN => {
                let mut sig_arr = [0u8; sign::SIGNATURE_LEN];
                sig_arr.copy_from_slice(sig);
                sign::verify(&pk, &payload, &sig_arr)
            }
            _ => false,
        },
        None => false,
    };

    // Root anchor: the caller-supplied on-chain root must equal the
    // manifest's own root. Combined with the recomputed Merkle root below
    // this binds the whole bundle to the chain without any key pinning.
    let root_anchor_valid = match opts.anchors.expected_root.as_deref() {
        Some(root) => root.trim().eq_ignore_ascii_case(&manifest.kyc_hash),
        None => false,
    };

    // Resolve the instant this verification is about before walking leaves,
    // so each leaf's claim status can be evaluated against it.
    let mut notes: Vec<String> = Vec::new();
    let resolution = resolve_as_of(manifest, opts, &mut notes);

    let as_of_epoch_days = resolution.epoch_days;
    let empty_log = RevocationLog::new();
    let revocations = opts.context.revocations.as_ref().unwrap_or(&empty_log);

    // Walk each leaf.
    let mut leaf_hashes: Vec<Digest> = Vec::with_capacity(manifest.leaves.len());
    let mut leaves = Vec::with_capacity(manifest.leaves.len());
    for entry in &manifest.leaves {
        let report = verify_leaf(
            manifest,
            entry,
            loaded,
            revocations,
            &opts.context.list_registries,
            as_of_epoch_days,
        );
        if let Some(hash) = report.0 {
            leaf_hashes.push(hash);
        }
        leaves.push(report.1);
    }

    // Merkle root: only meaningful if every leaf produced a hash. The
    // construction is selected by `manifest.merkleVersion` (absent = v1).
    let merkle_root_valid =
        if leaf_hashes.len() == manifest.leaves.len() && !manifest.leaves.is_empty() {
            match compute_root_versioned(&leaf_hashes, manifest.effective_merkle_version()) {
                Some((root, _)) => digest_to_hex(&root) == manifest.kyc_hash,
                None => false,
            }
        } else {
            false
        };

    // At least one anchor is required. Each supplied anchor must hold.
    let anchors_ok = !opts.anchors.is_empty()
        && (opts.anchors.expected_public_key.is_none() || signature_valid)
        && (opts.anchors.expected_root.is_none() || root_anchor_valid);

    // v3.1: the header must agree with the manifest, the attestation must be
    // derivable, and under a pinned key the header signature must hold.
    let header_ok = header.as_ref().is_none_or(|h| {
        h.present
            && h.consistent
            && h.attestation.is_some()
            && (opts.anchors.expected_public_key.is_none() || h.signature_valid)
    });

    let overall_pass = layout_ok
        && mode_acceptable
        && kyc_hash_file_matches
        && anchors_ok
        && merkle_root_valid
        && header_ok
        && leaves.iter().all(|l| l.pass);

    let resolved_root_matches = resolution
        .resolved_root
        .as_ref()
        .map(|r| r.eq_ignore_ascii_case(&manifest.kyc_hash));

    if resolved_root_matches == Some(false) {
        notes.push(format!(
            "at the queried instant the operator's signed root history records {} for this subject, which is not this bundle's root. This bundle was not the live issuance then.",
            resolution.resolved_root.clone().unwrap_or_default()
        ));
    }
    if opts.context.revocations.is_none() {
        notes.push(
            "no revocation log was supplied, so claim statuses reflect only what this bundle asserts. A lapse or voidance declared elsewhere would not be visible here."
                .to_string(),
        );
    }
    if manifest.unpinned_epoch == Some(true) {
        notes.push(
            "this bundle was produced against an unpinned wall-clock epoch and cannot be reproduced. It is a development artifact, not evidence."
                .to_string(),
        );
    }
    if manifest.leaves.iter().all(|l| l.binding.is_none()) && !manifest.leaves.is_empty() {
        notes.push(
            "no leaf carries a claim descriptor or validity interval: this is a pre-v3 bundle, so what each predicate stands for and how long it was asserted are not recorded."
                .to_string(),
        );
    }

    let all_claims_effective = leaves
        .iter()
        .all(|l| l.claim.as_ref().is_none_or(|c| c.status == "effective"));

    // An as-of question that could not be resolved is answered NO, never YES.
    // "Was this subject entitled at block N" has three possible answers — yes,
    // no, and I cannot tell — and only the first may be reported as
    // entitlement. Falling through to YES because no anchor was found would
    // assert entitlement precisely where the evidence is absent.
    let entitled = overall_pass
        && !resolution.unresolved
        && resolved_root_matches != Some(false)
        && all_claims_effective;

    let issuer = manifest.issuer.as_ref().map(|i| IssuerReport {
        name: i.party.name.clone(),
        identifier_scheme: i.party.identifier_scheme.clone(),
        identifier: i.party.identifier.clone(),
        jurisdiction: i.party.jurisdiction.clone(),
        key_id: i.key_id.clone(),
        public_key: i.public_key.clone(),
        public_key_disagrees_with_anchor: match opts.anchors.expected_public_key {
            Some(pk) => !i
                .public_key
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(bytes32_to_hex(&pk).trim_start_matches("0x")),
            None => false,
        },
    });
    if issuer
        .as_ref()
        .is_some_and(|i| i.public_key_disagrees_with_anchor)
    {
        notes.push(
            "the manifest names a different public key than the one supplied as an anchor. The signature check governs; this bundle claims a signer you did not expect."
                .to_string(),
        );
    }

    VerifyReport {
        wallet_address: manifest.wallet_address.clone(),
        kyc_hash: manifest.kyc_hash.clone(),
        leaf_count: manifest.leaves.len(),
        layout_ok,
        mode_acceptable,
        kyc_hash_file_matches,
        signature_valid,
        merkle_root_valid,
        leaves,
        anchor: opts.anchors.label().to_string(),
        root_anchor_valid,
        manifest_version: manifest.version.clone(),
        overall_pass,
        issuer,
        temporal: TemporalReport {
            as_of: resolution.label,
            as_of_epoch_days: resolution.epoch_days,
            as_of_date: epoch_days_to_iso_date(resolution.epoch_days),
            as_of_chain_id: resolution.chain_id,
            as_of_block: resolution.block,
            resolved_root: resolution.resolved_root,
            resolved_root_matches,
            root_history_available: opts.context.root_history.is_some(),
            revocations_available: opts.context.revocations.is_some(),
            entitled,
            notes,
            unpinned_epoch: manifest.unpinned_epoch == Some(true),
            manifest_as_of_date: manifest.as_of_date.clone(),
            epoch_days_source: manifest.epoch_days_source.clone(),
        },
        header,
    }
}

/// The instant a verification resolved to, and whether it could be resolved
/// at all.
struct AsOfResolution {
    epoch_days: u64,
    label: String,
    chain_id: Option<u64>,
    block: Option<u64>,
    resolved_root: Option<String>,
    /// True when an as-of block was asked for and no root could be established
    /// for it — either because no history was supplied, or because the subject
    /// had nothing published at or before that height.
    unresolved: bool,
}

/// Work out which instant to evaluate against, and which root was live then.
fn resolve_as_of(
    manifest: &Manifest,
    opts: &VerifyOptions,
    notes: &mut Vec<String>,
) -> AsOfResolution {
    match &opts.as_of {
        AsOf::Now => {
            let days = if opts.now_epoch_days > 0 {
                opts.now_epoch_days
            } else {
                // A caller that supplied no clock is asking about the bundle's
                // own as-of date rather than about today. Saying so beats
                // silently evaluating against epoch day zero.
                notes.push(
                    "no current date was supplied, so validity was evaluated against the \
                     bundle's own epochDays rather than against today."
                        .to_string(),
                );
                manifest.epoch_days
            };
            AsOfResolution {
                epoch_days: days,
                label: "now".to_string(),
                chain_id: None,
                block: None,
                resolved_root: None,
                unresolved: false,
            }
        }
        AsOf::Date { epoch_days } => AsOfResolution {
            epoch_days: *epoch_days,
            label: "date".to_string(),
            chain_id: None,
            block: None,
            resolved_root: None,
            unresolved: false,
        },
        AsOf::Block { chain_id, height } => {
            let Some(history) = opts.context.root_history.as_ref() else {
                notes.push(format!(
                    "an as-of check at block {} on chain {} was requested, but no root history \
                     was supplied, so it could not be established what was on chain then. \
                     Entitlement is reported as NO because it is unknown, not because it is \
                     false. Point --registry at the operator's signed registry, or verify from \
                     an archive, which carries it.",
                    height, chain_id
                ));
                return AsOfResolution {
                    epoch_days: manifest.epoch_days,
                    label: "block".to_string(),
                    chain_id: Some(*chain_id),
                    block: Some(*height),
                    resolved_root: None,
                    unresolved: true,
                };
            };
            match history.resolve_at_block(&manifest.wallet_address, *chain_id, *height) {
                Some(anchor) => AsOfResolution {
                    epoch_days: anchor.block_timestamp / 86_400,
                    label: "block".to_string(),
                    chain_id: Some(*chain_id),
                    block: Some(*height),
                    resolved_root: Some(anchor.kyc_hash.clone()),
                    unresolved: false,
                },
                None => {
                    notes.push(format!(
                        "the root history records no publication for {} at or before block {} on \
                         chain {}: this subject had no root on chain then, so nothing was \
                         entitled at that moment.",
                        manifest.wallet_address, height, chain_id
                    ));
                    AsOfResolution {
                        epoch_days: manifest.epoch_days,
                        label: "block".to_string(),
                        chain_id: Some(*chain_id),
                        block: Some(*height),
                        resolved_root: None,
                        unresolved: true,
                    }
                }
            }
        }
    }
}

/// `epochDays` as `YYYY-MM-DD`. Duplicated from the prover rather than shared,
/// because the verifier crate compiles to WASM and must not depend on the
/// prover.
fn epoch_days_to_iso_date(epoch_days: u64) -> String {
    let z = epoch_days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Verify a single leaf against its manifest entry and the loaded bundle.
/// Returns `(Some(reconstructed_leaf_hash), report)` on success or
/// `(None, report)` if anything went wrong.
fn verify_leaf(
    manifest: &Manifest,
    entry: &trusset_bundle_format::manifest::LeafEntry,
    loaded: &bundle::LoadedBundle,
    revocations: &RevocationLog,
    list_registries: &std::collections::BTreeMap<String, ListRegistry>,
    as_of_epoch_days: u64,
) -> (Option<Digest>, LeafReport) {
    let mut report = LeafReport {
        field: entry.field_name.clone(),
        circuit: entry.circuit.clone(),
        pass: false,
        reason: None,
        claim: build_claim_report(
            manifest,
            entry,
            revocations,
            list_registries,
            as_of_epoch_days,
        ),
    };

    // The binding digest must be reproducible from the descriptor the manifest
    // records. Without this check a bundle could carry a descriptor that says
    // one thing while the leaf hash — and therefore the root — commits to
    // another.
    let binding_digest = match (entry.binding.as_ref(), entry.binding_digest.as_deref()) {
        (None, None) => None,
        (Some(b), Some(recorded)) => match compute_binding_digest(b) {
            Ok(d) => {
                if !digest_to_hex(&d).eq_ignore_ascii_case(recorded) {
                    report.reason = Some(format!(
                        "bindingDigest mismatch: manifest {} vs recomputed {}",
                        recorded,
                        digest_to_hex(&d)
                    ));
                    return (None, report);
                }
                Some(d)
            }
            Err(e) => {
                report.reason = Some(format!("claim descriptor is not canonicalizable: {}", e));
                return (None, report);
            }
        },
        (Some(_), None) => {
            report.reason = Some(
                "leaf carries a claim descriptor but no bindingDigest, so the descriptor is not \
                 bound into the root and could be swapped freely"
                    .to_string(),
            );
            return (None, report);
        }
        (None, Some(_)) => {
            report.reason = Some(
                "leaf carries a bindingDigest with no descriptor to reproduce it from".to_string(),
            );
            return (None, report);
        }
    };

    // A leaf's declared list version must be the list the proof actually used.
    if let Some(binding) = entry.binding.as_ref() {
        if let Some(lv) = binding.list_version.as_ref() {
            let public_root = entry
                .public_inputs
                .get("setRoot")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if !lv.root.eq_ignore_ascii_case(public_root) {
                report.reason = Some(format!(
                    "declared list version {} of '{}' has root {} but the proof was made against \
                     {}",
                    lv.version, lv.list_id, lv.root, public_root
                ));
                return (None, report);
            }
        }
        if !binding.validity.is_well_formed() {
            report.reason = Some(
                "validity interval is not well formed: `until` precedes `from`, or the evidence \
                 post-dates the window it supports"
                    .to_string(),
            );
            return (None, report);
        }
    }

    // Decode the commitment.
    let commitment = match hex_to_digest(&entry.commitment) {
        Ok(d) => d,
        Err(_) => {
            report.reason = Some("invalid commitment hex".to_string());
            return (None, report);
        }
    };
    let manifest_public_digest = match hex_to_digest(&entry.public_digest) {
        Ok(d) => d,
        Err(_) => {
            report.reason = Some("invalid public_digest hex".to_string());
            return (None, report);
        }
    };

    // Locate the proof file.
    let proof_bytes = match loaded.proofs.get(&entry.proof_path) {
        Some(b) => b,
        None => {
            report.reason = Some(format!("missing proof file: {}", entry.proof_path));
            return (None, report);
        }
    };

    // proofDigest must match.
    let recomputed_proof_digest = compute_proof_digest(proof_bytes);
    if digest_to_hex(&recomputed_proof_digest) != entry.proof_digest {
        report.reason = Some("proof digest mismatch".to_string());
        return (None, report);
    }

    // Dispatch to the circuit's native verify(), using the public inputs
    // reconstructed from the manifest entry.
    let circuit_id = match CircuitId::from_str(&entry.circuit) {
        Some(id) => id,
        None => {
            report.reason = Some(format!("unknown circuit: {}", entry.circuit));
            return (None, report);
        }
    };

    // Sanity: the entry's `circuitId` byte must match the parsed name.
    if entry.circuit_id != circuit_id.as_u8() {
        report.reason = Some(format!(
            "circuit_id byte ({}) disagrees with circuit name ({})",
            entry.circuit_id, entry.circuit
        ));
        return (None, report);
    }

    // `params` and `publicInputs` must agree before `paramsHash` is checked:
    // `params` are not in the leaf hash, so without this a root-anchored
    // bundle could carry `params` (and a matching `paramsHash`) for a
    // threshold its proof was never made for.
    if let Err(reason) = v31::check_params_consistency(entry) {
        report.reason = Some(reason);
        return (None, report);
    }

    // `paramsHash` must be reproducible from the recorded parameters, so
    // a counterparty reads the asserted thresholds from the bundle rather
    // than trusting a config file it does not have.
    if let Err(reason) = check_params_hash(entry, circuit_id) {
        report.reason = Some(reason);
        return (None, report);
    }

    if is_v31(&manifest.version) {
        if let Err(reason) = v31::check_proof_canonical(proof_bytes) {
            report.reason = Some(reason);
            return (None, report);
        }
        if let Err(reason) = v31::check_leaf_v31(
            entry,
            circuit_id,
            manifest.epoch_days,
            proof_bytes.is_empty(),
            manifest.mode == MODE_STUB,
        ) {
            report.reason = Some(reason);
            return (None, report);
        }
    }

    // Zero-byte proofs are legitimate in exactly two cases: the
    // operator-facing `--skip-proofs` mode (manifest.mode == "stub"), and
    // `commitment_only` leaves, which carry a hiding commitment and no
    // STARK by design. A production-mode bundle with an empty proof on a
    // proving leaf is rejected here rather than silently passing.
    let circuit_verify_ok = if proof_bytes.is_empty() {
        let commitment_only = entry.disclosure.as_deref() == Some(DISCLOSURE_COMMITMENT_ONLY);
        if !commitment_only && manifest.mode != MODE_STUB {
            report.reason = Some("empty proof on a proving leaf in a non-stub bundle".to_string());
            return (None, report);
        }
        true
    } else {
        match dispatch_verify(
            circuit_id,
            &commitment,
            &entry.public_inputs,
            proof_bytes,
            manifest.circuits_version,
        ) {
            Ok(()) => true,
            Err(reason) => {
                report.reason = Some(reason);
                return (None, report);
            }
        }
    };

    // Recompute leaf hash and compare.
    let wallet_bytes = match decode_wallet(&manifest.wallet_address) {
        Some(b) => b,
        None => {
            report.reason = Some("manifest.walletAddress is not 0x + 40 hex".to_string());
            return (None, report);
        }
    };
    let recomputed_leaf = compute_leaf_hash_bound(
        &entry.field_name,
        circuit_id,
        &wallet_bytes,
        manifest.epoch_days,
        &commitment,
        &manifest_public_digest,
        &recomputed_proof_digest,
        binding_digest.as_ref(),
    );
    if digest_to_hex(&recomputed_leaf) != entry.leaf_hash {
        report.reason = Some("leaf hash mismatch".to_string());
        return (None, report);
    }

    report.pass = circuit_verify_ok;
    (Some(recomputed_leaf), report)
}

/// Render the claim descriptor and resolve its status at the queried instant.
fn build_claim_report(
    manifest: &Manifest,
    entry: &trusset_bundle_format::manifest::LeafEntry,
    revocations: &RevocationLog,
    list_registries: &std::collections::BTreeMap<String, ListRegistry>,
    as_of_epoch_days: u64,
) -> Option<ClaimReport> {
    let binding = entry.binding.as_ref()?;
    let status = revocations.status_at(
        &manifest.wallet_address,
        &manifest.kyc_hash,
        &entry.field_name,
        Some(&binding.validity),
        as_of_epoch_days,
    );

    let detail = match &status {
        ClaimStatus::Effective => None,
        ClaimStatus::Lapsed { effective_from } => Some(format!(
            "the operator declared this claim lapsed from {} ({}). Reliance strictly before that date stands; reliance on or after it does not.",
            epoch_days_to_iso_date(*effective_from),
            effective_from
        )),
        ClaimStatus::Void => Some(
            "the operator declared this claim void from the start: it was never true, and every reliance on it at any date is in question. The proof still verifies — it is a true record of what was asserted."
                .to_string(),
        ),
        ClaimStatus::OutsideValidity { from, until } => Some(format!(
            "the claim was asserted for {} .. {} and the query is outside that window. Nothing went wrong; the claim simply was not asserted for this date.",
            epoch_days_to_iso_date(*from),
            until
                .map(epoch_days_to_iso_date)
                .unwrap_or_else(|| "open-ended".to_string())
        )),
    };

    // Resolving a list version back to the values it committed to is what
    // turns `setRoot: 0x9078…` into a statement a reader can act on.
    let (list_id, list_version, list_resolved, list_entry_count) =
        match binding.list_version.as_ref() {
            Some(lv) => {
                let resolved = list_registries
                    .get(&lv.list_id)
                    .and_then(|r| r.resolve_root(&lv.root));
                (
                    Some(lv.list_id.clone()),
                    Some(lv.version),
                    Some(resolved.is_some()),
                    resolved.map(|v| v.values.len()),
                )
            }
            None => (None, None, None, None),
        };

    Some(ClaimReport {
        status: status.label().to_string(),
        detail,
        legal_basis: binding.descriptor.legal_basis.framework.clone(),
        legal_reference: binding.descriptor.legal_basis.reference.clone(),
        assertion: binding.descriptor.legal_basis.assertion.clone(),
        evidence_class: binding.descriptor.evidence_class.as_str().to_string(),
        issuing_party: binding.descriptor.issuing_party.name.clone(),
        issuing_party_identifier: format!(
            "{}:{}",
            binding.descriptor.issuing_party.identifier_scheme,
            binding.descriptor.issuing_party.identifier
        ),
        validity_from: binding.validity.from,
        validity_from_date: epoch_days_to_iso_date(binding.validity.from),
        validity_until: binding.validity.until,
        validity_until_date: binding.validity.until.map(epoch_days_to_iso_date),
        basis_as_of: binding.validity.basis_as_of,
        basis_as_of_date: epoch_days_to_iso_date(binding.validity.basis_as_of),
        list_id,
        list_version,
        list_resolved,
        list_entry_count,
    })
}

fn decode_wallet(addr: &str) -> Option<[u8; 20]> {
    let stripped = addr.strip_prefix("0x")?;
    if stripped.len() != 40 || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Recompute `paramsHash` from the leaf's recorded parameters and compare
/// it to the signed value. v2.1 leaves carry `params`; v2.0 leaves are
/// checked against the values already present in `publicInputs`, which are
/// bound into `publicDigest` and therefore into the root.
fn check_params_hash(
    entry: &trusset_bundle_format::manifest::LeafEntry,
    circuit_id: CircuitId,
) -> Result<(), String> {
    use trusset_circuit_age_threshold as age;
    use trusset_circuit_preimage_knowledge as preimage;
    use trusset_circuit_set_membership as set;
    use trusset_circuit_tier_threshold as tier;

    let params = entry.params.as_ref();
    let pick_u64 = |key: &str| -> Option<u64> {
        params
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_u64())
            .or_else(|| entry.public_inputs.get(key).and_then(|v| v.as_u64()))
    };
    let pick_str = |key: &str| -> Option<String> {
        params
            .and_then(|p| p.get(key))
            .and_then(|v| v.as_str())
            .or_else(|| entry.public_inputs.get(key).and_then(|v| v.as_str()))
            .map(|s| s.to_string())
    };

    let expected = match circuit_id {
        CircuitId::AgeThreshold => {
            let min_age_days = pick_u64("minAgeDays")
                .ok_or_else(|| "age_threshold leaf has no minAgeDays".to_string())?;
            age::Params { min_age_days }.hash()
        }
        CircuitId::TierThreshold => {
            let min_tier: u8 = pick_u64("minTier")
                .ok_or_else(|| "tier_threshold leaf has no minTier".to_string())?
                .try_into()
                .map_err(|_| "minTier out of u8 range".to_string())?;
            tier::Params { min_tier }.hash()
        }
        CircuitId::SetMembership => {
            let list_id = pick_str("listId")
                .ok_or_else(|| "set_membership leaf has no listId".to_string())?;
            set::Params { list_id }.hash()
        }
        CircuitId::PreimageKnowledge => {
            // v2.0 leaves record no parameters at all for this circuit, so
            // the hash is only checkable when the v2.1 `params` block is
            // present.
            match params
                .and_then(|p| p.get("maxValueBytes"))
                .and_then(|v| v.as_u64())
            {
                Some(max_value_bytes) => preimage::Params {
                    max_value_bytes: max_value_bytes as usize,
                }
                .hash(),
                None => return Ok(()),
            }
        }
    };

    let expected_hex = bytes32_to_hex(&expected);
    if expected_hex.eq_ignore_ascii_case(&entry.params_hash) {
        Ok(())
    } else {
        Err(format!(
            "paramsHash mismatch: manifest {} vs recomputed {}",
            entry.params_hash, expected_hex
        ))
    }
}

/// Public wrapper over `check_params_hash` for the v3.1 disclosure path.
pub fn check_params_hash_public(
    entry: &trusset_bundle_format::manifest::LeafEntry,
    circuit_id: CircuitId,
) -> Result<(), String> {
    check_params_hash(entry, circuit_id)
}

/// Public wrapper over `dispatch_verify` for the WASM granular exports,
/// which drive their own per-leaf check ladder.
pub fn dispatch_verify_public(
    circuit_id: CircuitId,
    commitment: &Digest,
    public_inputs: &serde_json::Value,
    proof_bytes: &[u8],
    circuits_version: u32,
) -> Result<(), String> {
    dispatch_verify(
        circuit_id,
        commitment,
        public_inputs,
        proof_bytes,
        circuits_version,
    )
}

fn dispatch_verify(
    circuit_id: CircuitId,
    commitment: &Digest,
    public_inputs: &serde_json::Value,
    proof_bytes: &[u8],
    circuits_version: u32,
) -> Result<(), String> {
    use trusset_circuit_age_threshold as age;
    use trusset_circuit_preimage_knowledge as preimage;
    use trusset_circuit_set_membership as set;
    use trusset_circuit_tier_threshold as tier;

    match circuit_id {
        CircuitId::PreimageKnowledge => {
            let public = preimage::PublicInputs {
                commitment: *commitment,
            };
            preimage::verify(proof_bytes, &public)
                .map_err(|e| format!("preimage_knowledge: {:?}", e))
        }
        CircuitId::TierThreshold => {
            let min_tier = pub_u64(public_inputs, "minTier")?
                .try_into()
                .map_err(|_| "minTier out of u8 range".to_string())?;
            let public = tier::PublicInputs {
                commitment: *commitment,
                min_tier,
            };
            tier::verify(proof_bytes, &public).map_err(|e| format!("tier_threshold: {:?}", e))
        }
        CircuitId::AgeThreshold => {
            let min_age_days = pub_u64(public_inputs, "minAgeDays")?;
            let current_epoch_days = pub_u64(public_inputs, "currentEpochDays")?;
            let public = age::PublicInputs {
                commitment: *commitment,
                min_age_days,
                current_epoch_days,
            };
            age::verify(proof_bytes, &public).map_err(|e| format!("age_threshold: {:?}", e))
        }
        CircuitId::SetMembership => {
            let set_root_hex = public_inputs
                .get("setRoot")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "set_membership.publicInputs.setRoot missing".to_string())?;
            let set_root = hex_to_digest(set_root_hex)
                .map_err(|_| "setRoot is not a valid digest hex".to_string())?;
            let set_depth = pub_u64(public_inputs, "setDepth")?
                .try_into()
                .map_err(|_| "setDepth out of u8 range".to_string())?;
            let public = set::PublicInputs {
                commitment: *commitment,
                set_root,
                set_depth,
            };
            // circuitsVersion 2 bundles were proved under the frozen AIR
            // that predates the Merkle-walk carry binding; they verify
            // against that constraint set. Version 3 and later use the
            // current AIR.
            if circuits_version <= SET_MEMBERSHIP_AIR_V2_CIRCUITS_VERSION {
                set::verify_v2(proof_bytes, &public)
                    .map_err(|e| format!("set_membership (circuitsVersion 2 AIR): {:?}", e))
            } else {
                set::verify(proof_bytes, &public).map_err(|e| format!("set_membership: {:?}", e))
            }
        }
    }
}

/// Highest `circuitsVersion` whose `set_membership` proofs were generated
/// under the frozen pre-v2.1 AIR.
pub const SET_MEMBERSHIP_AIR_V2_CIRCUITS_VERSION: u32 = 2;

fn pub_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("publicInputs.{} missing or not a u64", field))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_wallet_accepts_valid_eip55_form() {
        let bytes = decode_wallet("0xAbCdEf0123456789AbCdEf0123456789AbCdEf01").unwrap();
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes[19], 0x01);
    }

    #[test]
    fn decode_wallet_rejects_bad_input() {
        assert!(decode_wallet("not-an-address").is_none());
        assert!(decode_wallet("0xZZ").is_none());
        assert!(decode_wallet("0x123").is_none());
    }

    /// Pin every JSON field name produced by `VerifyReport` serialization.
    ///
    /// **Why this test is load-bearing**: the Rust verifier emits a JSON
    /// report consumed by the TS CLI at [cli/src/verify.ts](../../cli/src/verify.ts).
    /// The TS side has its own `VerifyReport` interface declaration with
    /// hand-written field names. There is no shared schema between the
    /// two — drift on either side is silent.
    ///
    /// Failure of this test means: an engineer renamed a `VerifyReport` /
    /// `LeafReport` field in `lib.rs` without updating [cli/src/verify.ts](../../cli/src/verify.ts).
    /// To fix: either revert the Rust rename or apply the matching rename
    /// to the TS interface declaration AND to all TS call sites (look for
    /// `report.<old_name>` references in `cli/src/verify.ts`).
    ///
    /// The fields enumerated here MUST match `cli/src/verify.ts`'s
    /// `VerifyReport` and `LeafReport` interfaces verbatim.
    #[test]
    fn verify_report_json_field_names_are_pinned() {
        let report = VerifyReport {
            wallet_address: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
            kyc_hash: "0x9f1c".to_string(),
            leaf_count: 1,
            layout_ok: true,
            mode_acceptable: true,
            kyc_hash_file_matches: true,
            signature_valid: true,
            merkle_root_valid: true,
            leaves: vec![LeafReport {
                field: "firstName".to_string(),
                circuit: "preimage_knowledge".to_string(),
                pass: true,
                reason: None,
                claim: None,
            }],
            anchor: ANCHOR_PUBLIC_KEY.to_string(),
            root_anchor_valid: false,
            manifest_version: "3.0.0".to_string(),
            overall_pass: true,
            issuer: None,
            temporal: TemporalReport {
                as_of: "now".to_string(),
                as_of_epoch_days: 20700,
                as_of_date: "2026-08-24".to_string(),
                as_of_chain_id: None,
                as_of_block: None,
                resolved_root: None,
                resolved_root_matches: None,
                root_history_available: false,
                revocations_available: false,
                entitled: true,
                notes: vec![],
                unpinned_epoch: false,
                manifest_as_of_date: None,
                epoch_days_source: None,
            },
            header: None,
        };

        let json = serde_json::to_value(&report).unwrap();
        let obj = json
            .as_object()
            .expect("VerifyReport serializes to JSON object");

        // Every wire-name expected by cli/src/verify.ts MUST be present.
        let expected_top_level = [
            "wallet_address",
            "kyc_hash",
            "leaf_count",
            "layout_ok",
            "mode_acceptable",
            "kyc_hash_file_matches",
            "signature_valid",
            "merkle_root_valid",
            "leaves",
            "anchor",
            "root_anchor_valid",
            "manifest_version",
            "overall_pass",
            // v3 additions. `issuer` is null on pre-v3 bundles but always
            // present as a key; `temporal` is always present.
            "issuer",
            "temporal",
            // v3.1. `header` is null before 3.1.0 but always present as a key.
            "header",
        ];
        for name in &expected_top_level {
            assert!(
                obj.contains_key(*name),
                "VerifyReport JSON is missing wire field {:?} (TS CLI in cli/src/verify.ts expects this)",
                name
            );
        }
        // No surprise extra fields — adding a field to the Rust struct
        // requires deliberately updating the TS interface AND this test.
        assert_eq!(
            obj.len(),
            expected_top_level.len(),
            "VerifyReport has {} JSON fields but {} are pinned in the wire-format test. \
             Add the new field to cli/src/verify.ts:VerifyReport AND to expected_top_level here.",
            obj.len(),
            expected_top_level.len()
        );

        // LeafReport schema check.
        let leaves = obj.get("leaves").unwrap().as_array().unwrap();
        let leaf = leaves[0].as_object().unwrap();
        let expected_leaf = ["field", "circuit", "pass", "reason", "claim"];
        for name in &expected_leaf {
            assert!(
                leaf.contains_key(*name),
                "LeafReport JSON is missing wire field {:?}",
                name
            );
        }
        assert_eq!(
            leaf.len(),
            expected_leaf.len(),
            "LeafReport has {} JSON fields but {} are pinned",
            leaf.len(),
            expected_leaf.len()
        );

        // Type assertions on a handful of representative fields — catches
        // a serde attribute change that flips bool to {true,false} string,
        // or usize → i64 → string surprises.
        assert!(obj["wallet_address"].is_string());
        assert!(obj["leaf_count"].is_number());
        assert!(obj["layout_ok"].is_boolean());
        assert!(obj["overall_pass"].is_boolean());
        assert!(obj["leaves"].is_array());
        assert!(leaf["pass"].is_boolean());
        assert!(leaf["reason"].is_null()); // None serializes to null
    }
}
