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

#[cfg(feature = "wasm")]
pub mod wasm;

use std::path::Path;

use serde::Serialize;
use trusset_bundle_format::leaf::{compute_leaf_hash, compute_proof_digest};
use trusset_bundle_format::manifest::{
    canonical_signing_bytes, Manifest, ACCEPTED_MANIFEST_VERSIONS, DISCLOSURE_COMMITMENT_ONLY,
    MODE_PRODUCTION, MODE_STUB,
};
use trusset_bundle_format::merkle::compute_root_versioned;
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

/// Options for `verify_bundle`.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Trust anchors. At least one is required.
    pub anchors: VerifyAnchors,
    /// If `false`, manifests with `mode != "production"` are rejected. If
    /// `true`, `mode == "stub"` is tolerated (mirrors the
    /// `TRUSSET_KYC_ALLOW_STUB=1` env var on the prover side).
    pub accept_stub: bool,
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
    /// on it (`2.0.0` or `2.1.0`).
    pub manifest_version: String,
    /// `true` iff every applicable check above passed and every leaf in
    /// `leaves` has `pass == true`.
    pub overall_pass: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LeafReport {
    pub field: String,
    pub circuit: String,
    pub pass: bool,
    /// Short human-readable reason for the failure if `pass == false`.
    pub reason: Option<String>,
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

    let version_acceptable = ACCEPTED_MANIFEST_VERSIONS.contains(&manifest.version.as_str());
    let layout_ok = loaded.layout_ok && version_acceptable;
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

    // Walk each leaf.
    let mut leaf_hashes: Vec<Digest> = Vec::with_capacity(manifest.leaves.len());
    let mut leaves = Vec::with_capacity(manifest.leaves.len());
    for entry in &manifest.leaves {
        let report = verify_leaf(manifest, entry, loaded);
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

    let overall_pass = layout_ok
        && mode_acceptable
        && kyc_hash_file_matches
        && anchors_ok
        && merkle_root_valid
        && leaves.iter().all(|l| l.pass);

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
    }
}

/// Verify a single leaf against its manifest entry and the loaded bundle.
/// Returns `(Some(reconstructed_leaf_hash), report)` on success or
/// `(None, report)` if anything went wrong.
fn verify_leaf(
    manifest: &Manifest,
    entry: &trusset_bundle_format::manifest::LeafEntry,
    loaded: &bundle::LoadedBundle,
) -> (Option<Digest>, LeafReport) {
    let mut report = LeafReport {
        field: entry.field_name.clone(),
        circuit: entry.circuit.clone(),
        pass: false,
        reason: None,
    };

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

    // `paramsHash` must be reproducible from the recorded parameters, so
    // a counterparty reads the asserted thresholds from the bundle rather
    // than trusting a config file it does not have.
    if let Err(reason) = check_params_hash(entry, circuit_id) {
        report.reason = Some(reason);
        return (None, report);
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
    let recomputed_leaf = compute_leaf_hash(
        &entry.field_name,
        circuit_id,
        &wallet_bytes,
        manifest.epoch_days,
        &commitment,
        &manifest_public_digest,
        &recomputed_proof_digest,
    );
    if digest_to_hex(&recomputed_leaf) != entry.leaf_hash {
        report.reason = Some("leaf hash mismatch".to_string());
        return (None, report);
    }

    report.pass = circuit_verify_ok;
    (Some(recomputed_leaf), report)
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
            }],
            anchor: ANCHOR_PUBLIC_KEY.to_string(),
            root_anchor_valid: false,
            manifest_version: "2.1.0".to_string(),
            overall_pass: true,
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
        let expected_leaf = ["field", "circuit", "pass", "reason"];
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
