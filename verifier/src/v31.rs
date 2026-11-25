//! v3.1 verification: the signed header, the stricter per-leaf checks, and
//! single-leaf disclosures.
//!
//! A 3.1.0 leaf is held to more than an earlier leaf, because a disclosure
//! shows it without the signed manifest around it:
//!
//! - `publicDigest` is recomputed from `publicInputs`, not taken as written.
//! - `params` must agree with `publicInputs`, so `paramsHash` cannot describe
//!   a threshold the proof was not made for.
//! - An `age_threshold` leaf's `currentEpochDays` must be the batch date.
//! - The leaf must carry a binding block, and its predicate must be one its
//!   circuit and parameters establish.
//! - An empty proof is accepted only on a `commitment_only` leaf with no
//!   predicate.
//!
//! The circuits version of a disclosure is fixed by its signed header
//! version, never read from unsigned input.

use serde::Serialize;
use trusset_bundle_format::attestation::AttestationFile;
use trusset_bundle_format::claims::compute_binding_digest;
use trusset_bundle_format::disclosure::Disclosure;
use trusset_bundle_format::header::{
    address_to_hex, parse_address, parse_digest_strict, parse_signature_hex, DisclosureHeader,
    HEADER_CIRCUITS_VERSION,
};
use trusset_bundle_format::leaf::{compute_leaf_hash_bound, compute_proof_digest};
use trusset_bundle_format::manifest::{LeafEntry, Manifest, DISCLOSURE_COMMITMENT_ONLY};
use trusset_bundle_format::merkle::{root_from_path_v3, MERKLE_VERSION_V3};
use trusset_bundle_format::predicates::{
    bit_of, check_leaf_predicate, PredicateEvidence, INVESTOR_CLASS,
};
use trusset_bundle_format::sign;
use trusset_circuits_common::{digest_to_hex, hex_to_digest, CircuitId, Digest};

/// Recompute `publicDigest` from a leaf's `publicInputs`, reconstructing the
/// typed circuit public inputs exactly as the prover does.
pub fn public_digest_from_json(
    circuit: CircuitId,
    value: &serde_json::Value,
) -> Result<Digest, String> {
    use trusset_circuit_age_threshold as age;
    use trusset_circuit_preimage_knowledge as preimage;
    use trusset_circuit_set_membership as set;
    use trusset_circuit_tier_threshold as tier;

    let digest = |key: &str| -> Result<Digest, String> {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| hex_to_digest(s).ok())
            .ok_or_else(|| format!("publicInputs.{} missing or not a digest", key))
    };
    let num = |key: &str| -> Result<u64, String> {
        value
            .get(key)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("publicInputs.{} missing or not a u64", key))
    };
    let commitment = digest("commitment")?;
    Ok(match circuit {
        CircuitId::PreimageKnowledge => preimage::PublicInputs { commitment }.digest(),
        CircuitId::TierThreshold => tier::PublicInputs {
            commitment,
            min_tier: num("minTier")?
                .try_into()
                .map_err(|_| "minTier out of u8 range".to_string())?,
        }
        .digest(),
        CircuitId::AgeThreshold => age::PublicInputs {
            commitment,
            min_age_days: num("minAgeDays")?,
            current_epoch_days: num("currentEpochDays")?,
        }
        .digest(),
        CircuitId::SetMembership => set::PublicInputs {
            commitment,
            set_root: digest("setRoot")?,
            set_depth: num("setDepth")?
                .try_into()
                .map_err(|_| "setDepth out of u8 range".to_string())?,
        }
        .digest(),
    })
}

/// Every key both `params` and `publicInputs` carry must agree. Applied to
/// every manifest version: a genuine bundle always agrees, and a leaf whose
/// `params` claim a threshold its proof was not made for is a forgery
/// whichever version it says it is.
pub fn check_params_consistency(entry: &LeafEntry) -> Result<(), String> {
    let Some(params) = entry.params.as_ref() else {
        return Ok(());
    };
    for key in ["minAgeDays", "minTier", "listId"] {
        if let (Some(p), Some(q)) = (params.get(key), entry.public_inputs.get(key)) {
            if p != q {
                return Err(format!(
                    "params.{} ({}) disagrees with publicInputs.{} ({}), which the proof binds",
                    key, p, key, q
                ));
            }
        }
    }
    Ok(())
}

/// A 3.1.0 leaf carries exactly the keys the prover writes, so nothing in it
/// is unbound: `publicInputs` and `params` have a fixed key set per circuit,
/// `proofPath` is `proofs/<fieldName>.bin`, and `disclosure` is `predicate` or
/// `commitment_only`.
pub fn check_leaf_shape_v31(entry: &LeafEntry, circuit: CircuitId) -> Result<(), String> {
    let commitment_only = entry.disclosure.as_deref() == Some(DISCLOSURE_COMMITMENT_ONLY);
    match entry.disclosure.as_deref() {
        Some("predicate") | Some(DISCLOSURE_COMMITMENT_ONLY) => {}
        other => {
            return Err(format!(
                "a 3.1.0 leaf's disclosure is predicate or commitment_only, not {:?}",
                other
            ))
        }
    }
    if commitment_only && circuit != CircuitId::PreimageKnowledge {
        return Err("a commitment_only leaf records the preimage_knowledge circuit".to_string());
    }
    let (public_keys, param_keys): (&[&str], &[&str]) = match circuit {
        CircuitId::AgeThreshold => (
            &["commitment", "currentEpochDays", "minAgeDays"],
            &["minAgeDays"],
        ),
        CircuitId::TierThreshold => (&["commitment", "minTier"], &["minTier"]),
        CircuitId::SetMembership => (
            &["commitment", "listId", "setDepth", "setRoot"],
            &["listId"],
        ),
        CircuitId::PreimageKnowledge => (&["commitment"], &["maxValueBytes"]),
    };
    let exact = |what: &str, v: Option<&serde_json::Value>, keys: &[&str]| -> Result<(), String> {
        let obj = v
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("{} must be an object", what))?;
        let mut have: Vec<&str> = obj.keys().map(String::as_str).collect();
        have.sort_unstable();
        if have != keys {
            return Err(format!(
                "{} keys are {:?}, a 3.1.0 leaf has {:?}",
                what, have, keys
            ));
        }
        Ok(())
    };
    exact("publicInputs", Some(&entry.public_inputs), public_keys)?;
    exact("params", entry.params.as_ref(), param_keys)?;

    // One spelling per value: every digest is 0x + 64 lowercase hex, and the
    // Rescue digests are canonical field elements.
    let lower32 = |s: &str| {
        s.len() == 66
            && s.starts_with("0x")
            && s[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut digests: Vec<(&str, Option<&str>)> = vec![
        ("commitment", Some(entry.commitment.as_str())),
        ("publicDigest", Some(entry.public_digest.as_str())),
        ("proofDigest", Some(entry.proof_digest.as_str())),
        ("leafHash", Some(entry.leaf_hash.as_str())),
        ("bindingDigest", entry.binding_digest.as_deref()),
        (
            "publicInputs.commitment",
            entry
                .public_inputs
                .get("commitment")
                .and_then(|v| v.as_str()),
        ),
    ];
    if circuit == CircuitId::SetMembership {
        digests.push((
            "publicInputs.setRoot",
            entry.public_inputs.get("setRoot").and_then(|v| v.as_str()),
        ));
    }
    for (name, value) in digests {
        match value {
            Some(v) if parse_digest_strict(v).is_some() => {}
            _ => return Err(format!("{} is not a canonical lowercase digest", name)),
        }
    }
    if !lower32(&entry.params_hash) {
        return Err("paramsHash is not 0x + 64 lowercase hex".to_string());
    }
    if let Some(lv) = entry.binding.as_ref().and_then(|b| b.list_version.as_ref()) {
        if parse_digest_strict(&lv.root).is_none() || !lower32(&lv.content_hash) {
            return Err("listVersion root or contentHash is not lowercase hex".to_string());
        }
    }
    if entry.proof_path != format!("proofs/{}.bin", entry.field_name) {
        return Err(format!(
            "proofPath is {}, a 3.1.0 leaf's is proofs/{}.bin",
            entry.proof_path, entry.field_name
        ));
    }
    Ok(())
}

/// The 3.1.0 checks on one leaf, on top of the checks every version gets.
/// `epoch_days` is the batch date from the manifest or the signed header.
/// `stub_bundle` is true only for a whole bundle in `mode: "stub"` (built with
/// `--skip-proofs`), whose proving leaves carry empty proofs by design and
/// which verifies only under `--accept-stub`. A disclosure is never a stub.
pub fn check_leaf_v31(
    entry: &LeafEntry,
    circuit: CircuitId,
    epoch_days: u64,
    proof_is_empty: bool,
    stub_bundle: bool,
) -> Result<(), String> {
    let binding = entry
        .binding
        .as_ref()
        .ok_or("a 3.1.0 leaf must carry a binding block")?;
    check_leaf_shape_v31(entry, circuit)?;
    let recomputed = public_digest_from_json(circuit, &entry.public_inputs)?;
    if digest_to_hex(&recomputed) != entry.public_digest.to_ascii_lowercase() {
        return Err(format!(
            "publicDigest {} is not the digest of publicInputs ({})",
            entry.public_digest,
            digest_to_hex(&recomputed)
        ));
    }
    if circuit == CircuitId::AgeThreshold {
        let current = entry
            .public_inputs
            .get("currentEpochDays")
            .and_then(|v| v.as_u64());
        if current != Some(epoch_days) {
            return Err(format!(
                "age proof is for epoch day {:?}, the bundle is dated {}",
                current, epoch_days
            ));
        }
    }
    if circuit == CircuitId::SetMembership {
        let lv = binding
            .list_version
            .as_ref()
            .ok_or("a 3.1.0 set_membership leaf must record its list version")?;
        let pub_list = entry.public_inputs.get("listId").and_then(|v| v.as_str());
        if pub_list != Some(lv.list_id.as_str()) {
            return Err(format!(
                "listVersion names list '{}' but publicInputs.listId is {:?}",
                lv.list_id, pub_list
            ));
        }
    }
    let commitment_only = entry.disclosure.as_deref() == Some(DISCLOSURE_COMMITMENT_ONLY);
    if let Some(name) = binding.predicate.as_deref() {
        let ev = PredicateEvidence {
            circuit: Some(circuit),
            commitment_only,
            min_age_days: entry
                .public_inputs
                .get("minAgeDays")
                .and_then(|v| v.as_u64()),
            min_tier: entry.public_inputs.get("minTier").and_then(|v| v.as_u64()),
            list_id: binding.list_version.as_ref().map(|lv| lv.list_id.as_str()),
        };
        check_leaf_predicate(name, &ev)?;
    }
    if proof_is_empty && !stub_bundle && !(commitment_only && binding.predicate.is_none()) {
        return Err(
            "empty proof: only a commitment_only leaf with no predicate may carry none".to_string(),
        );
    }
    if !proof_is_empty && commitment_only {
        return Err("a commitment_only leaf must carry an empty proof".to_string());
    }
    Ok(())
}

/// A non-empty 3.1.0 proof must be exactly the serialization of the proof it
/// decodes to. See `trusset_circuits_common::proof_bytes`.
pub fn check_proof_canonical(proof_bytes: &[u8]) -> Result<(), String> {
    if proof_bytes.is_empty() || trusset_circuits_common::is_canonical_proof_bytes(proof_bytes) {
        Ok(())
    } else {
        Err("proof bytes are not the canonical serialization of the proof".to_string())
    }
}

/// Whether the header in a 3.1.0 bundle is present, signed, and says what
/// the manifest says.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderReport {
    pub present: bool,
    /// Checked only when the caller pinned a public key. `false` otherwise.
    pub signature_valid: bool,
    /// Root, wallet, epoch, chain block, Merkle version, and leaf count all
    /// match the manifest.
    pub consistent: bool,
    pub reason: Option<String>,
    pub attester: Option<String>,
    pub chain_id: Option<u64>,
    pub hub: Option<String>,
    pub key_id: Option<u32>,
    /// The attestation this bundle supports, derived from the manifest. What
    /// the hub should hold for this subject under this attester.
    pub attestation: Option<AttestationFile>,
}

/// Check a 3.1.0 bundle's header against its manifest.
pub fn check_header(
    manifest: &Manifest,
    header_bytes: Option<&[u8]>,
    header_sig: Option<&[u8]>,
    public_key: Option<&[u8; 32]>,
) -> HeaderReport {
    let mut report = HeaderReport {
        present: header_bytes.is_some() && header_sig.is_some(),
        signature_valid: false,
        consistent: false,
        reason: None,
        attester: None,
        chain_id: None,
        hub: None,
        key_id: None,
        attestation: None,
    };
    match AttestationFile::from_manifest(manifest) {
        Ok(a) => report.attestation = Some(a),
        Err(e) => report.reason = Some(e),
    }
    let (Some(bytes), Some(sig)) = (header_bytes, header_sig) else {
        report.reason = Some("a 3.1.0 bundle must carry header.json and header.sig".to_string());
        return report;
    };
    let header: DisclosureHeader = match serde_json::from_slice(bytes) {
        Ok(h) => h,
        Err(e) => {
            report.reason = Some(format!("header.json: {}", e));
            return report;
        }
    };
    let parsed = match header.parse() {
        Ok(p) => p,
        Err(e) => {
            report.reason = Some(e);
            return report;
        }
    };
    report.attester = Some(address_to_hex(&parsed.attester));
    report.chain_id = Some(parsed.chain_id);
    report.hub = Some(address_to_hex(&parsed.hub));
    report.key_id = Some(parsed.key_id);

    if let Some(pk) = public_key {
        report.signature_valid = sig.len() == sign::SIGNATURE_LEN && {
            let mut s = [0u8; sign::SIGNATURE_LEN];
            s.copy_from_slice(sig);
            sign::verify_strict(pk, &parsed.signing_bytes(), &s)
        };
    }

    let mismatch = header_mismatch(manifest, &header, &parsed);
    report.consistent = mismatch.is_none();
    if mismatch.is_some() && report.reason.is_none() {
        report.reason = mismatch;
    }
    report
}

fn header_mismatch(
    manifest: &Manifest,
    header: &DisclosureHeader,
    parsed: &trusset_bundle_format::header::ParsedHeader,
) -> Option<String> {
    if !header.root.eq_ignore_ascii_case(&manifest.kyc_hash) {
        return Some("header root is not the manifest's kycHash".to_string());
    }
    if parse_address(&manifest.wallet_address) != Some(parsed.wallet) {
        return Some("header wallet is not the manifest's walletAddress".to_string());
    }
    if parsed.epoch_days != manifest.epoch_days {
        return Some("header epochDays is not the manifest's epochDays".to_string());
    }
    if manifest.effective_merkle_version() != MERKLE_VERSION_V3 {
        return Some("a 3.1.0 manifest must use merkleVersion 3".to_string());
    }
    if parsed.leaf_count as usize != manifest.leaves.len() {
        return Some("header leafCount is not the manifest's leaf count".to_string());
    }
    let Some(chain) = manifest.chain.as_ref() else {
        return Some("a 3.1.0 manifest must carry a chain block".to_string());
    };
    if parse_address(&chain.attester) != Some(parsed.attester)
        || parse_address(&chain.hub) != Some(parsed.hub)
        || chain.chain_id != parsed.chain_id
        || chain.key_id != parsed.key_id
    {
        return Some(
            "header attester, chainId, hub or keyId differs from the manifest".to_string(),
        );
    }
    if manifest.circuits_version != HEADER_CIRCUITS_VERSION {
        return Some(format!(
            "a 3.1.0 manifest must use circuitsVersion {}",
            HEADER_CIRCUITS_VERSION
        ));
    }
    let class_leaves = manifest
        .leaves
        .iter()
        .filter(|l| l.binding.as_ref().and_then(|b| b.predicate.as_deref()) == Some(INVESTOR_CLASS))
        .count();
    if class_leaves != 1 {
        return Some(format!(
            "a 3.1.0 bundle needs exactly one INVESTOR_CLASS leaf, found {}",
            class_leaves
        ));
    }
    None
}

/// The outcome of checking one disclosed leaf.
#[derive(Debug, Clone, Serialize)]
pub struct DisclosureReport {
    /// Every check below passed.
    pub ok: bool,
    /// The first check that failed, in the order listed below.
    pub reason: Option<String>,
    pub parsed: bool,
    pub header_signature_valid: bool,
    /// `true` when no expected wallet was supplied.
    pub wallet_matches: bool,
    pub leaf_valid: bool,
    pub leaf_hash_valid: bool,
    pub inclusion_valid: bool,
    /// `true` for a `commitment_only` leaf, which has no STARK to check.
    pub stark_valid: bool,
    /// `verified` or `none` (commitment_only).
    pub stark: String,
    pub field: Option<String>,
    pub circuit: Option<String>,
    pub predicate: Option<String>,
    pub predicate_bit: Option<u8>,
    /// For an `INVESTOR_CLASS` leaf: the class it proves.
    pub investor_class: Option<u8>,
    pub public_inputs: Option<serde_json::Value>,
    pub params_hash: Option<String>,
    pub list_id: Option<String>,
    pub list_version: Option<u32>,
    pub validity_from: Option<u64>,
    pub validity_until: Option<u64>,
    pub basis_as_of: Option<u64>,
    pub header: Option<DisclosureHeader>,
}

impl DisclosureReport {
    fn empty() -> Self {
        DisclosureReport {
            ok: false,
            reason: None,
            parsed: false,
            header_signature_valid: false,
            wallet_matches: false,
            leaf_valid: false,
            leaf_hash_valid: false,
            inclusion_valid: false,
            stark_valid: false,
            stark: "none".to_string(),
            field: None,
            circuit: None,
            predicate: None,
            predicate_bit: None,
            investor_class: None,
            public_inputs: None,
            params_hash: None,
            list_id: None,
            list_version: None,
            validity_from: None,
            validity_until: None,
            basis_as_of: None,
            header: None,
        }
    }

    fn fail(&mut self, reason: impl Into<String>) {
        if self.reason.is_none() {
            self.reason = Some(reason.into());
        }
    }
}

/// Check one disclosed leaf: the header signature under `public_key`, the
/// wallet the caller expects (pass `None` to skip), the leaf's own checks,
/// its hash under the header's wallet and epoch, its inclusion path to the
/// header root, and its STARK.
pub fn verify_disclosure(
    disclosure_bytes: &[u8],
    proof_bytes: &[u8],
    public_key: &[u8; 32],
    expected_wallet: Option<&str>,
) -> DisclosureReport {
    let mut r = DisclosureReport::empty();
    let d = match Disclosure::parse(disclosure_bytes) {
        Ok(d) => d,
        Err(e) => {
            r.fail(e);
            return r;
        }
    };
    r.parsed = true;
    r.header = Some(d.header.clone());
    let header = match d.header.parse() {
        Ok(h) => h,
        Err(e) => {
            r.fail(e);
            return r;
        }
    };
    let leaf = &d.leaf;
    r.field = Some(leaf.field_name.clone());
    r.circuit = Some(leaf.circuit.clone());
    r.public_inputs = Some(leaf.public_inputs.clone());
    r.params_hash = Some(leaf.params_hash.clone());
    if let Some(b) = leaf.binding.as_ref() {
        r.predicate = b.predicate.clone();
        r.predicate_bit = b.predicate.as_deref().and_then(bit_of);
        r.list_id = b.list_version.as_ref().map(|lv| lv.list_id.clone());
        r.list_version = b.list_version.as_ref().map(|lv| lv.version);
        r.validity_from = Some(b.validity.from);
        r.validity_until = b.validity.until;
        r.basis_as_of = Some(b.validity.basis_as_of);
        if b.predicate.as_deref() == Some(INVESTOR_CLASS) {
            r.investor_class = leaf
                .public_inputs
                .get("minTier")
                .and_then(|v| v.as_u64())
                .and_then(|t| u8::try_from(t).ok());
        }
    }

    r.header_signature_valid = match parse_signature_hex(&d.header_signature) {
        Some(sig) => sign::verify_strict(public_key, &header.signing_bytes(), &sig),
        None => false,
    };
    if !r.header_signature_valid {
        r.fail("header signature does not verify under the operator key");
    }

    r.wallet_matches = match expected_wallet {
        None => true,
        Some(w) => parse_address(w.trim()) == Some(header.wallet),
    };
    if !r.wallet_matches {
        r.fail("the header names a different wallet than the one expected");
    }

    let circuit = match CircuitId::from_str(&leaf.circuit) {
        Some(c) if c.as_u8() == leaf.circuit_id => Some(c),
        _ => {
            r.fail("circuit name and circuitId disagree or are unknown");
            None
        }
    };

    let proof_digest = compute_proof_digest(proof_bytes);
    let leaf_ok = (|| -> Result<(Digest, Digest, Option<Digest>), String> {
        let circuit = circuit.ok_or("unknown circuit")?;
        if digest_to_hex(&proof_digest) != leaf.proof_digest.to_ascii_lowercase() {
            return Err("proof bytes do not match proofDigest".to_string());
        }
        let commitment =
            parse_digest_strict(&leaf.commitment).ok_or("commitment is not a canonical digest")?;
        if leaf
            .public_inputs
            .get("commitment")
            .and_then(|v| v.as_str())
            != Some(leaf.commitment.as_str())
        {
            return Err("publicInputs.commitment is not the leaf commitment".to_string());
        }
        let public_digest = parse_digest_strict(&leaf.public_digest)
            .ok_or("publicDigest is not a canonical digest")?;
        let binding = leaf
            .binding
            .as_ref()
            .ok_or("a 3.1.0 leaf must carry a binding block")?;
        let binding_digest =
            compute_binding_digest(binding).map_err(|e| format!("binding: {}", e))?;
        if Some(digest_to_hex(&binding_digest).as_str()) != leaf.binding_digest.as_deref() {
            return Err("bindingDigest is not the digest of the binding block".to_string());
        }
        if !binding.validity.is_well_formed() {
            return Err("validity interval is not well formed".to_string());
        }
        if let Some(lv) = binding.list_version.as_ref() {
            let set_root = leaf.public_inputs.get("setRoot").and_then(|v| v.as_str());
            if !set_root.is_some_and(|s| s.eq_ignore_ascii_case(&lv.root)) {
                return Err("listVersion root is not the proof's setRoot".to_string());
            }
        }
        check_proof_canonical(proof_bytes)?;
        check_params_consistency(leaf)?;
        crate::check_params_hash_public(leaf, circuit)?;
        check_leaf_v31(
            leaf,
            circuit,
            header.epoch_days,
            proof_bytes.is_empty(),
            false,
        )?;
        Ok((commitment, public_digest, Some(binding_digest)))
    })();
    let (commitment, public_digest, binding_digest) = match leaf_ok {
        Ok(v) => {
            r.leaf_valid = true;
            v
        }
        Err(e) => {
            r.fail(e);
            return finish(r);
        }
    };
    let circuit = circuit.expect("leaf_ok implies a circuit");

    let leaf_hash = compute_leaf_hash_bound(
        &leaf.field_name,
        circuit,
        &header.wallet,
        header.epoch_days,
        &commitment,
        &public_digest,
        &proof_digest,
        binding_digest.as_ref(),
    );
    r.leaf_hash_valid = digest_to_hex(&leaf_hash) == leaf.leaf_hash.to_ascii_lowercase();
    if !r.leaf_hash_valid {
        r.fail("leaf hash does not match its fields under the header's wallet and epoch");
    }

    let path: Vec<Digest> = d
        .path
        .iter()
        .filter_map(|s| parse_digest_strict(s))
        .collect();
    r.inclusion_valid =
        root_from_path_v3(&leaf_hash, &path, u64::from(header.leaf_count)) == Some(header.root);
    if !r.inclusion_valid {
        r.fail("inclusion path does not lead to the header root");
    }

    if proof_bytes.is_empty() {
        r.stark_valid = true;
        r.stark = "none".to_string();
    } else {
        match crate::dispatch_verify_public(
            circuit,
            &commitment,
            &leaf.public_inputs,
            proof_bytes,
            HEADER_CIRCUITS_VERSION,
        ) {
            Ok(()) => {
                r.stark_valid = true;
                r.stark = "verified".to_string();
            }
            Err(e) => r.fail(format!("STARK: {}", e)),
        }
    }
    finish(r)
}

fn finish(mut r: DisclosureReport) -> DisclosureReport {
    r.ok = r.reason.is_none()
        && r.parsed
        && r.header_signature_valid
        && r.wallet_matches
        && r.leaf_valid
        && r.leaf_hash_valid
        && r.inclusion_valid
        && r.stark_valid;
    r
}
