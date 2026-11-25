//! WASM bindings (`cargo build --features wasm --target wasm32-unknown-unknown`).
//!
//! Two families of exports:
//!
//! **Whole-bundle verification** — `verify_strict` rejects
//! `mode != "production"`, `verify_permissive` accepts stub mode, and
//! `verify_with_anchors` takes an explicit anchor pair so a caller holding
//! only the on-chain root can verify without pinning an operator key. All
//! three take the manifest bytes, kycHash text, signature bytes, a
//! `{path: [byte, ...]}` proof map, and return the `VerifyReport` as JSON.
//!
//! **Granular primitives** — `proof_digest_hex`, `public_digest_hex`,
//! `leaf_hash_hex`, `merkle_root_hex`, `merkle_root_hex_v`,
//! `manifest_signing_bytes`, `verify_manifest_signature`, and
//! `verify_leaf_stark`. The Trusset issuer backend drives its own check
//! ladder through these, recomputing each bound value independently rather
//! than trusting a single pass/fail verdict. Their signatures are a wire
//! contract with `services/customers/zk-verifier/index.js`; see
//! `scripts/rebuild-wasm.sh` for the re-vendoring procedure.
//!
//! **v3.1**: `verify_disclosure` checks one disclosed leaf on its own;
//! `verify_with_header` verifies a whole 3.1.0 bundle including its signed
//! header; `header_signing_bytes`, `verify_header_signature`,
//! `merkle_root_from_path_hex`, and `attestation_from_manifest` expose the
//! pieces for a backend that runs its own ladder.

use crate::bundle::{loaded_from_parts, loaded_from_parts_with_header};
use crate::{verify_loaded, AsOf, TemporalContext, VerifyAnchors, VerifyOptions};
use std::collections::BTreeMap;
use trusset_bundle_format::claims::{compute_binding_digest, LeafBinding};
use trusset_bundle_format::leaf::{
    compute_leaf_hash, compute_leaf_hash_bound, compute_proof_digest,
};
use trusset_bundle_format::manifest::{canonical_signing_bytes, Manifest};
use trusset_bundle_format::merkle::{compute_root_versioned, MERKLE_VERSION_V1};
use trusset_bundle_format::registry::{ListRegistry, RevocationLog, RootHistory};
use trusset_bundle_format::sign;
use trusset_circuits_common::{digest_to_hex, hex_to_digest, CircuitId, Digest};
use wasm_bindgen::prelude::*;

// =====================================================================
// Whole-bundle verification
// =====================================================================

#[wasm_bindgen]
pub fn verify_strict(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
) -> Result<String, JsError> {
    let anchors = VerifyAnchors {
        expected_public_key: Some(parse_public_key(expected_public_key)?),
        expected_root: None,
    };
    do_verify(
        manifest_bytes,
        kyc_hash_text,
        signature_bytes,
        proofs_json,
        anchors,
        false,
    )
}

#[wasm_bindgen]
pub fn verify_permissive(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
) -> Result<String, JsError> {
    let anchors = VerifyAnchors {
        expected_public_key: Some(parse_public_key(expected_public_key)?),
        expected_root: None,
    };
    do_verify(
        manifest_bytes,
        kyc_hash_text,
        signature_bytes,
        proofs_json,
        anchors,
        true,
    )
}

/// Verify against an explicit anchor pair. Pass an empty `public_key` to
/// verify root-anchored only, or an empty `root` to verify signature-only.
/// Supplying neither is a usage error.
#[wasm_bindgen]
pub fn verify_with_anchors(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
    expected_root: &str,
    accept_stub: bool,
) -> Result<String, JsError> {
    let expected_public_key = if expected_public_key.is_empty() {
        None
    } else {
        Some(parse_public_key(expected_public_key)?)
    };
    let expected_root = if expected_root.trim().is_empty() {
        None
    } else {
        Some(expected_root.trim().to_ascii_lowercase())
    };
    let anchors = VerifyAnchors {
        expected_public_key,
        expected_root,
    };
    if anchors.is_empty() {
        return Err(JsError::new(
            "at least one anchor is required: expected_public_key or expected_root",
        ));
    }
    do_verify(
        manifest_bytes,
        kyc_hash_text,
        signature_bytes,
        proofs_json,
        anchors,
        accept_stub,
    )
}

fn parse_public_key(bytes: &[u8]) -> Result<[u8; 32], JsError> {
    if bytes.len() != 32 {
        return Err(JsError::new("expected_public_key must be exactly 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(bytes);
    Ok(pk)
}

fn do_verify(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    anchors: VerifyAnchors,
    accept_stub: bool,
) -> Result<String, JsError> {
    // proofs_json is `{ "proofs/firstName.bin": [byte, ...], ... }`. The JS
    // layer decodes to plain number arrays before calling, which is correct
    // because it already holds the original Uint8Array from readFileSync
    // and keeps a base64 dependency out of the WASM bundle.
    let raw: BTreeMap<String, Vec<u8>> = serde_json::from_str(proofs_json)
        .map_err(|e| JsError::new(&format!("proofs_json parse: {}", e)))?;

    let loaded = loaded_from_parts(
        manifest_bytes,
        kyc_hash_text,
        Some(signature_bytes.to_vec()),
        raw,
    )
    .map_err(|e| JsError::new(&format!("load: {}", e)))?;

    // The pre-v3 exports have no clock and no registries, so they evaluate at
    // the bundle's own as-of date. That reproduces their v2 semantics exactly:
    // a verification with no temporal question asked, where every leaf's
    // validity window necessarily covers the date the bundle was issued.
    // Stating it as an explicit `Date` rather than letting `Now` fall back to
    // a sentinel keeps the report honest about which instant was evaluated.
    let opts = VerifyOptions {
        anchors,
        accept_stub,
        as_of: AsOf::Date {
            epoch_days: loaded.manifest.epoch_days,
        },
        context: TemporalContext::default(),
        now_epoch_days: loaded.manifest.epoch_days,
    };

    let report = verify_loaded(&loaded, &opts);
    serde_json::to_string(&report).map_err(|e| JsError::new(&format!("report serialize: {}", e)))
}

// =====================================================================
// v3 temporal verification
// =====================================================================

/// Registries a caller passes alongside a bundle so an as-of question can be
/// answered. All three are optional; the report names what was missing rather
/// than assuming absence means "nothing to report".
#[derive(serde::Deserialize, Default)]
struct WasmContext {
    #[serde(default)]
    root_history: Option<RootHistory>,
    #[serde(default)]
    revocations: Option<RevocationLog>,
    #[serde(default)]
    list_registries: BTreeMap<String, ListRegistry>,
}

/// Verify with an explicit instant and the registries needed to resolve it.
///
/// `as_of_kind` is `"now"`, `"date"`, or `"block"`. For `"date"`,
/// `as_of_value` is an `epochDays` count; for `"block"` it is a block height
/// and `chain_id` selects the chain. `now_epoch_days` is the caller's current
/// date, supplied rather than read from a clock so the WASM and native paths
/// agree.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_as_of(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
    expected_root: &str,
    accept_stub: bool,
    as_of_kind: &str,
    as_of_value: u64,
    chain_id: u64,
    now_epoch_days: u64,
    context_json: &str,
) -> Result<String, JsError> {
    let raw: BTreeMap<String, Vec<u8>> = serde_json::from_str(proofs_json)
        .map_err(|e| JsError::new(&format!("proofs_json parse: {}", e)))?;
    let loaded = loaded_from_parts(
        manifest_bytes,
        kyc_hash_text,
        Some(signature_bytes.to_vec()),
        raw,
    )
    .map_err(|e| JsError::new(&format!("load: {}", e)))?;

    let anchors = VerifyAnchors {
        expected_public_key: if expected_public_key.is_empty() {
            None
        } else {
            Some(parse_public_key(expected_public_key)?)
        },
        expected_root: if expected_root.is_empty() {
            None
        } else {
            Some(expected_root.to_string())
        },
    };

    let as_of = match as_of_kind {
        "now" => AsOf::Now,
        "date" => AsOf::Date {
            epoch_days: as_of_value,
        },
        "block" => AsOf::Block {
            chain_id,
            height: as_of_value,
        },
        other => {
            return Err(JsError::new(&format!(
                "as_of_kind must be now, date, or block; got {}",
                other
            )))
        }
    };

    let ctx: WasmContext = if context_json.trim().is_empty() {
        WasmContext::default()
    } else {
        serde_json::from_str(context_json)
            .map_err(|e| JsError::new(&format!("context parse: {}", e)))?
    };

    let opts = VerifyOptions {
        anchors,
        accept_stub,
        as_of,
        context: TemporalContext {
            root_history: ctx.root_history,
            revocations: ctx.revocations,
            list_registries: ctx.list_registries,
        },
        now_epoch_days,
    };

    let report = verify_loaded(&loaded, &opts);
    serde_json::to_string(&report).map_err(|e| JsError::new(&format!("report serialize: {}", e)))
}

/// `bindingDigest = Rescue(LEAF-BIND ‖ canonical_json(binding))`, so a
/// backend running its own check ladder can recompute it rather than trusting
/// the value the manifest carries.
#[wasm_bindgen]
pub fn binding_digest_hex(binding_json: &str) -> Result<String, JsError> {
    let binding: LeafBinding = serde_json::from_str(binding_json)
        .map_err(|e| JsError::new(&format!("binding parse: {}", e)))?;
    let digest = compute_binding_digest(&binding)
        .map_err(|e| JsError::new(&format!("binding canonicalize: {}", e)))?;
    Ok(digest_to_hex(&digest))
}

/// `leaf_hash` including a v3 binding digest. Pass an empty `binding_hex` to
/// reproduce the v2 preimage, which is what a pre-v3 leaf hashes over.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn leaf_hash_hex_bound(
    field_name: &str,
    circuit_id: u8,
    wallet_address: &str,
    epoch_days: u64,
    commitment_hex: &str,
    public_digest_hex_in: &str,
    proof_digest_hex_in: &str,
    binding_hex: &str,
) -> Result<String, JsError> {
    let circuit = CircuitId::try_from(circuit_id)
        .map_err(|b| JsError::new(&format!("unknown circuitId {}", b)))?;
    let wallet = decode_wallet(wallet_address)
        .ok_or_else(|| JsError::new("walletAddress must be 0x + 40 hex"))?;
    let commitment = parse_digest(commitment_hex, "commitment")?;
    let public_digest = parse_digest(public_digest_hex_in, "publicDigest")?;
    let proof_digest = parse_digest(proof_digest_hex_in, "proofDigest")?;
    let binding = if binding_hex.trim().is_empty() {
        None
    } else {
        Some(parse_digest(binding_hex, "bindingDigest")?)
    };
    Ok(digest_to_hex(&compute_leaf_hash_bound(
        field_name,
        circuit,
        &wallet,
        epoch_days,
        &commitment,
        &public_digest,
        &proof_digest,
        binding.as_ref(),
    )))
}

// =====================================================================
// Granular primitives (issuer-backend check ladder)
// =====================================================================

/// `proof_digest = Rescue(PROOF_DIGEST_TAG ‖ proof_bytes)`.
#[wasm_bindgen]
pub fn proof_digest_hex(proof_bytes: &[u8]) -> String {
    digest_to_hex(&compute_proof_digest(proof_bytes))
}

/// Recompute `publicDigest` from a leaf's `publicInputs`, reconstructing
/// the typed circuit public inputs exactly as the prover does.
#[wasm_bindgen]
pub fn public_digest_hex(circuit_id: u8, public_inputs_json: &str) -> Result<String, JsError> {
    let value: serde_json::Value = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("publicInputs parse: {}", e)))?;
    let circuit = CircuitId::try_from(circuit_id)
        .map_err(|b| JsError::new(&format!("unknown circuitId {}", b)))?;
    let digest =
        crate::v31::public_digest_from_json(circuit, &value).map_err(|e| JsError::new(&e))?;
    Ok(digest_to_hex(&digest))
}

/// Recompute a leaf hash from its bound components.
#[wasm_bindgen]
pub fn leaf_hash_hex(
    field_name: &str,
    circuit_id: u8,
    wallet_address: &str,
    epoch_days: u64,
    commitment_hex: &str,
    public_digest_hex: &str,
    proof_digest_hex: &str,
) -> Result<String, JsError> {
    let circuit = CircuitId::try_from(circuit_id)
        .map_err(|b| JsError::new(&format!("unknown circuitId {}", b)))?;
    let wallet = decode_wallet(wallet_address)
        .ok_or_else(|| JsError::new("walletAddress must be 0x + 40 hex"))?;
    let leaf = compute_leaf_hash(
        field_name,
        circuit,
        &wallet,
        epoch_days,
        &parse_digest(commitment_hex, "commitment")?,
        &parse_digest(public_digest_hex, "publicDigest")?,
        &parse_digest(proof_digest_hex, "proofDigest")?,
    );
    Ok(digest_to_hex(&leaf))
}

/// Sorted-pair Rescue Merkle root over leaf hashes, v1 convention. Kept at
/// this name and behavior for callers that predate `merkleVersion`.
#[wasm_bindgen]
pub fn merkle_root_hex(leaf_hashes_json: &str) -> Result<String, JsError> {
    merkle_root_hex_v(leaf_hashes_json, MERKLE_VERSION_V1)
}

/// Merkle root under an explicit construction version. Pass
/// `manifest.merkleVersion` (absent means 1).
#[wasm_bindgen]
pub fn merkle_root_hex_v(leaf_hashes_json: &str, merkle_version: u32) -> Result<String, JsError> {
    let hexes: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| JsError::new(&format!("leafHashes parse: {}", e)))?;
    if hexes.is_empty() {
        return Err(JsError::new("leafHashes must be a non-empty array"));
    }
    let mut leaves: Vec<Digest> = Vec::with_capacity(hexes.len());
    for h in &hexes {
        leaves.push(parse_digest(h, "leafHash")?);
    }
    let (root, _) = compute_root_versioned(&leaves, merkle_version)
        .ok_or_else(|| JsError::new(&format!("unsupported merkleVersion {}", merkle_version)))?;
    Ok(digest_to_hex(&root))
}

/// Canonical ed25519 signing view of a manifest (sorted keys, pretty JSON,
/// `createdAt` set to the sentinel).
#[wasm_bindgen]
pub fn manifest_signing_bytes(manifest_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| JsError::new(&format!("manifest parse: {}", e)))?;
    canonical_signing_bytes(&manifest)
        .map_err(|e| JsError::new(&format!("canonical serialize: {}", e)))
}

/// Verify a manifest's ed25519 signature under a registered operator key.
/// Returns `false` rather than throwing on any length or decode problem so
/// a malformed signature is a clean policy reject.
#[wasm_bindgen]
pub fn verify_manifest_signature(
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> bool {
    if signature.len() != sign::SIGNATURE_LEN || public_key.len() != sign::PUBLIC_KEY_LEN {
        return false;
    }
    let Ok(manifest) = serde_json::from_slice::<Manifest>(manifest_bytes) else {
        return false;
    };
    let Ok(payload) = canonical_signing_bytes(&manifest) else {
        return false;
    };
    let mut sig = [0u8; sign::SIGNATURE_LEN];
    sig.copy_from_slice(signature);
    let mut pk = [0u8; sign::PUBLIC_KEY_LEN];
    pk.copy_from_slice(public_key);
    sign::verify(&pk, &payload, &sig)
}

/// Verify a single leaf's STARK proof. Returns `{"ok":bool,"reason":str|null}`
/// as JSON; only malformed inputs throw. `circuits_version` selects the
/// `set_membership` constraint set (2 = frozen pre-v2.1 AIR).
#[wasm_bindgen]
pub fn verify_leaf_stark(
    circuit_id: u8,
    commitment_hex: &str,
    public_inputs_json: &str,
    proof_bytes: &[u8],
) -> Result<String, JsError> {
    verify_leaf_stark_v(
        circuit_id,
        commitment_hex,
        public_inputs_json,
        proof_bytes,
        trusset_circuits_common::CIRCUITS_VERSION,
    )
}

/// `verify_leaf_stark` with an explicit `manifest.circuitsVersion`.
#[wasm_bindgen]
pub fn verify_leaf_stark_v(
    circuit_id: u8,
    commitment_hex: &str,
    public_inputs_json: &str,
    proof_bytes: &[u8],
    circuits_version: u32,
) -> Result<String, JsError> {
    let circuit = CircuitId::try_from(circuit_id)
        .map_err(|b| JsError::new(&format!("unknown circuitId {}", b)))?;
    let commitment = parse_digest(commitment_hex, "commitment")?;
    let public_inputs: serde_json::Value = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("publicInputs parse: {}", e)))?;

    let verdict = match crate::dispatch_verify_public(
        circuit,
        &commitment,
        &public_inputs,
        proof_bytes,
        circuits_version,
    ) {
        Ok(()) => serde_json::json!({ "ok": true, "reason": serde_json::Value::Null }),
        Err(reason) => serde_json::json!({ "ok": false, "reason": reason }),
    };
    serde_json::to_string(&verdict).map_err(|e| JsError::new(&format!("verdict serialize: {}", e)))
}

// =====================================================================
// v3.1: disclosures, headers, inclusion paths, attestations
// =====================================================================

/// Check one disclosed leaf on its own. `disclosure_json` is the content of
/// `disclosures/<leaf>.json`, `proof_bytes` the matching `proofs/<leaf>.bin`,
/// `operator_public_key` the attester's 32-byte ed25519 key (for example
/// `operatorKeyAt(attester, keyId)` read from the hub), and `expected_wallet`
/// the wallet the caller is checking, or `""` to skip that comparison.
///
/// Returns the `DisclosureReport` as JSON; `ok` is the verdict. Throws only
/// when the key is not 32 bytes.
#[wasm_bindgen]
pub fn verify_disclosure(
    disclosure_json: &[u8],
    proof_bytes: &[u8],
    operator_public_key: &[u8],
    expected_wallet: &str,
) -> Result<String, JsError> {
    let pk = parse_public_key(operator_public_key)?;
    let wallet = if expected_wallet.trim().is_empty() {
        None
    } else {
        Some(expected_wallet)
    };
    let report = crate::v31::verify_disclosure(disclosure_json, proof_bytes, &pk, wallet);
    serde_json::to_string(&report).map_err(|e| JsError::new(&format!("report serialize: {}", e)))
}

/// Verify a whole 3.1.0 bundle, including its signed header. Same anchors as
/// `verify_with_anchors`; `header_json` and `header_sig` are `header.json`
/// and `header.sig`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify_with_header(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    header_json: &[u8],
    header_sig: &[u8],
    expected_public_key: &[u8],
    expected_root: &str,
    accept_stub: bool,
) -> Result<String, JsError> {
    let raw: BTreeMap<String, Vec<u8>> = serde_json::from_str(proofs_json)
        .map_err(|e| JsError::new(&format!("proofs_json parse: {}", e)))?;
    let loaded = loaded_from_parts_with_header(
        manifest_bytes,
        kyc_hash_text,
        Some(signature_bytes.to_vec()),
        raw,
        Some(header_json.to_vec()),
        Some(header_sig.to_vec()),
    )
    .map_err(|e| JsError::new(&format!("load: {}", e)))?;
    let anchors = VerifyAnchors {
        expected_public_key: if expected_public_key.is_empty() {
            None
        } else {
            Some(parse_public_key(expected_public_key)?)
        },
        expected_root: if expected_root.trim().is_empty() {
            None
        } else {
            Some(expected_root.trim().to_ascii_lowercase())
        },
    };
    if anchors.is_empty() {
        return Err(JsError::new(
            "at least one anchor is required: expected_public_key or expected_root",
        ));
    }
    let opts = VerifyOptions {
        anchors,
        accept_stub,
        as_of: AsOf::Date {
            epoch_days: loaded.manifest.epoch_days,
        },
        context: TemporalContext::default(),
        now_epoch_days: loaded.manifest.epoch_days,
    };
    let report = verify_loaded(&loaded, &opts);
    serde_json::to_string(&report).map_err(|e| JsError::new(&format!("report serialize: {}", e)))
}

/// The 155 bytes the operator key signs for a v3.1 header.
#[wasm_bindgen]
pub fn header_signing_bytes(header_json: &[u8]) -> Result<Vec<u8>, JsError> {
    let header: trusset_bundle_format::header::DisclosureHeader =
        serde_json::from_slice(header_json)
            .map_err(|e| JsError::new(&format!("header parse: {}", e)))?;
    header
        .signing_bytes()
        .map(|b| b.to_vec())
        .map_err(|e| JsError::new(&e))
}

/// Check a v3.1 header signature (strict ed25519). `false` on any malformed
/// input rather than a throw.
#[wasm_bindgen]
pub fn verify_header_signature(header_json: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != sign::SIGNATURE_LEN || public_key.len() != sign::PUBLIC_KEY_LEN {
        return false;
    }
    let Ok(header) =
        serde_json::from_slice::<trusset_bundle_format::header::DisclosureHeader>(header_json)
    else {
        return false;
    };
    let Ok(bytes) = header.signing_bytes() else {
        return false;
    };
    let mut sig = [0u8; sign::SIGNATURE_LEN];
    sig.copy_from_slice(signature);
    let mut pk = [0u8; sign::PUBLIC_KEY_LEN];
    pk.copy_from_slice(public_key);
    sign::verify_strict(&pk, &bytes, &sig)
}

/// Rebuild a Merkle v3 root from one leaf hash and its inclusion path
/// (`["0x…", …]`, leaf level first).
#[wasm_bindgen]
pub fn merkle_root_from_path_hex(
    leaf_hash_hex: &str,
    path_json: &str,
    leaf_count: u32,
) -> Result<String, JsError> {
    let leaf = parse_digest(leaf_hash_hex, "leafHash")?;
    let hexes: Vec<String> =
        serde_json::from_str(path_json).map_err(|e| JsError::new(&format!("path parse: {}", e)))?;
    let mut path = Vec::with_capacity(hexes.len());
    for h in &hexes {
        path.push(parse_digest(h, "path sibling")?);
    }
    let root =
        trusset_bundle_format::merkle::root_from_path_v3(&leaf, &path, u64::from(leaf_count))
            .ok_or_else(|| JsError::new("path length does not match leafCount"))?;
    Ok(digest_to_hex(&root))
}

/// `attestation.json` derived from a 3.1.0 manifest. A backend builds the
/// attest calldata from this, computed from the verified manifest, rather
/// than from an uploaded file it would have to trust.
#[wasm_bindgen]
pub fn attestation_from_manifest(manifest_bytes: &[u8]) -> Result<String, JsError> {
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| JsError::new(&format!("manifest parse: {}", e)))?;
    let a = trusset_bundle_format::attestation::AttestationFile::from_manifest(&manifest)
        .map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&a).map_err(|e| JsError::new(&format!("serialize: {}", e)))
}

// =====================================================================
// Helpers
// =====================================================================

fn parse_digest(hex: &str, label: &str) -> Result<Digest, JsError> {
    hex_to_digest(hex).map_err(|_| JsError::new(&format!("{} is not 0x + 64 hex", label)))
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
