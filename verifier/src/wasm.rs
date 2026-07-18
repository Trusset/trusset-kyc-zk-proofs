//! WASM bindings (`cargo build --features wasm --target wasm32-unknown-unknown`).
//!
//! Two entry points:
//!   - `verify_strict(...)`     — rejects `mode != "production"`
//!   - `verify_permissive(...)` — accepts stub mode
//!
//! Both take the same inputs: the manifest bytes, kycHash text, signature
//! bytes, an array of `{ path, bytes }` proof tuples, and the 32-byte
//! expected public key. They return the `VerifyReport` as a JSON string —
//! the JS layer parses it and renders a per-leaf table.

use crate::bundle::loaded_from_parts;
use crate::{verify_loaded, VerifyOptions};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn verify_strict(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
) -> Result<String, JsError> {
    do_verify(
        manifest_bytes,
        kyc_hash_text,
        signature_bytes,
        proofs_json,
        expected_public_key,
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
    do_verify(
        manifest_bytes,
        kyc_hash_text,
        signature_bytes,
        proofs_json,
        expected_public_key,
        true,
    )
}

fn do_verify(
    manifest_bytes: &[u8],
    kyc_hash_text: &str,
    signature_bytes: &[u8],
    proofs_json: &str,
    expected_public_key: &[u8],
    accept_stub: bool,
) -> Result<String, JsError> {
    if expected_public_key.len() != 32 {
        return Err(JsError::new("expected_public_key must be exactly 32 bytes"));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(expected_public_key);

    // proofs_json is `{ "proofs/firstName.bin": "<base64 or hex>", ... }`.
    // To keep the binding minimal (no base64 dep in the WASM bundle), we
    // expect the values to be already-decoded byte arrays. The JS layer
    // does the decoding before calling — which is correct because it has
    // the original Uint8Array from fs.readFileSync.
    //
    // Concretely, the JS shape is:
    //   { "proofs/firstName.bin": Uint8Array(120), ... }
    // and we serialize it as a JSON object where each value is an array of
    // numbers. The wasm-bindgen JS shim handles this conversion.
    let raw: BTreeMap<String, Vec<u8>> = serde_json::from_str(proofs_json)
        .map_err(|e| JsError::new(&format!("proofs_json parse: {}", e)))?;

    let loaded = loaded_from_parts(
        manifest_bytes,
        kyc_hash_text,
        Some(signature_bytes.to_vec()),
        raw,
    )
    .map_err(|e| JsError::new(&format!("load: {}", e)))?;

    let opts = VerifyOptions {
        expected_public_key: pk,
        accept_stub,
    };

    let report = verify_loaded(&loaded, &opts);
    serde_json::to_string(&report).map_err(|e| JsError::new(&format!("report serialize: {}", e)))
}

// ===========================================================================
// Granular verification primitives.
//
// The whole-bundle `verify_strict`/`verify_permissive` entry points above run
// every check (including all STARK proofs) before returning, and require every
// leaf's proof to be present. Server-side callers that want (a) cheap → expensive
// check ordering with the expensive STARK verification LAST, and (b) proofs only
// for the leaves actually being claimed, compose the primitives below instead.
//
// Every crypto operation stays in Rust/WASM so the on-chain-bound byte formats
// (canonical manifest signing view, Rescue digests, leaf-hash layout, sorted
// Merkle root) can never drift from the prover. See the corresponding
// `trusset-bundle-format` / `trusset-circuits-common` functions each wraps.
// ===========================================================================

use crate::{dispatch_public_digest, dispatch_verify};
use trusset_bundle_format::leaf::{compute_leaf_hash, compute_proof_digest};
use trusset_bundle_format::manifest::{canonical_signing_bytes, Manifest};
use trusset_bundle_format::merkle::compute_root;
use trusset_bundle_format::sign;
use trusset_circuits_common::{digest_to_hex, hex_to_digest, CircuitId, Digest};

fn parse_manifest(manifest_bytes: &[u8]) -> Result<Manifest, JsError> {
    serde_json::from_slice(manifest_bytes)
        .map_err(|e| JsError::new(&format!("manifest parse: {}", e)))
}

fn parse_circuit(circuit_id: u8) -> Result<CircuitId, JsError> {
    CircuitId::try_from(circuit_id)
        .map_err(|_| JsError::new(&format!("unknown circuit id: {}", circuit_id)))
}

fn digest_arg(label: &str, hex: &str) -> Result<Digest, JsError> {
    hex_to_digest(hex).map_err(|_| JsError::new(&format!("{} is not a 32-byte hex digest", label)))
}

/// Canonical ed25519 *signing view* of a manifest: sorted-key pretty JSON with
/// `createdAt` overwritten to the sentinel. Exposed for inspection / tests; the
/// signature check itself is `verify_manifest_signature`.
#[wasm_bindgen]
pub fn manifest_signing_bytes(manifest_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    let manifest = parse_manifest(manifest_bytes)?;
    canonical_signing_bytes(&manifest)
        .map_err(|e| JsError::new(&format!("canonical signing bytes: {}", e)))
}

/// Verify the manifest's ed25519 signature under `expected_public_key` (32 bytes)
/// over the canonical signing view. Returns `false` on any decode/length error
/// rather than throwing, so a malformed signature is a clean policy reject.
#[wasm_bindgen]
pub fn verify_manifest_signature(
    manifest_bytes: &[u8],
    signature: &[u8],
    expected_public_key: &[u8],
) -> Result<bool, JsError> {
    let manifest = parse_manifest(manifest_bytes)?;
    let payload = canonical_signing_bytes(&manifest)
        .map_err(|e| JsError::new(&format!("canonical signing bytes: {}", e)))?;
    if expected_public_key.len() != sign::PUBLIC_KEY_LEN || signature.len() != sign::SIGNATURE_LEN {
        return Ok(false);
    }
    let mut pk = [0u8; sign::PUBLIC_KEY_LEN];
    pk.copy_from_slice(expected_public_key);
    let mut sig = [0u8; sign::SIGNATURE_LEN];
    sig.copy_from_slice(signature);
    Ok(sign::verify(&pk, &payload, &sig))
}

/// `proof_digest = Rescue(PROOF_DIGEST_TAG ‖ proof_bytes)`, hex.
#[wasm_bindgen]
pub fn proof_digest_hex(proof_bytes: &[u8]) -> String {
    digest_to_hex(&compute_proof_digest(proof_bytes))
}

/// `public_digest` recomputed from the manifest's `publicInputs` JSON for a
/// circuit. Reconstructs the typed `PublicInputs` and returns `.digest()` — the
/// exact value the prover writes to `leaves[].publicDigest`.
#[wasm_bindgen]
pub fn public_digest_hex(circuit_id: u8, public_inputs_json: &str) -> Result<String, JsError> {
    let circuit = parse_circuit(circuit_id)?;
    let public_inputs: serde_json::Value = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("publicInputs parse: {}", e)))?;
    dispatch_public_digest(circuit, &public_inputs)
        .map(|d| digest_to_hex(&d))
        .map_err(|e| JsError::new(&e))
}

/// `leaf_hash = Rescue(LEAF_TAG ‖ fieldName ‖ circuitId ‖ wallet ‖ epochDays ‖
/// commitment ‖ public_digest ‖ proof_digest)`, hex. `wallet_hex` is `0x` + 40
/// hex chars; the three digest args are 32-byte hex.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn leaf_hash_hex(
    field_name: &str,
    circuit_id: u8,
    wallet_hex: &str,
    epoch_days: u64,
    commitment_hex: &str,
    public_digest_hex: &str,
    proof_digest_hex: &str,
) -> Result<String, JsError> {
    let circuit = parse_circuit(circuit_id)?;
    let wallet_bytes = decode_wallet(wallet_hex)
        .ok_or_else(|| JsError::new("wallet_hex must be 0x + 40 hex chars"))?;
    let commitment = digest_arg("commitment", commitment_hex)?;
    let public_digest = digest_arg("public_digest", public_digest_hex)?;
    let proof_digest = digest_arg("proof_digest", proof_digest_hex)?;
    let leaf = compute_leaf_hash(
        field_name,
        circuit,
        &wallet_bytes,
        epoch_days,
        &commitment,
        &public_digest,
        &proof_digest,
    );
    Ok(digest_to_hex(&leaf))
}

/// Sorted-pair Rescue Merkle root over the given leaf hashes (v1 convention).
/// Input is a JSON array of 32-byte hex strings; returns the root hex.
#[wasm_bindgen]
pub fn merkle_root_hex(leaf_hashes_json: &str) -> Result<String, JsError> {
    let hexes: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| JsError::new(&format!("leaf hashes parse: {}", e)))?;
    if hexes.is_empty() {
        return Err(JsError::new("cannot compute a Merkle root over zero leaves"));
    }
    let mut leaves = Vec::with_capacity(hexes.len());
    for (i, h) in hexes.iter().enumerate() {
        leaves.push(digest_arg(&format!("leaf[{}]", i), h)?);
    }
    let (root, _) = compute_root(&leaves);
    Ok(digest_to_hex(&root))
}

/// Verify a single leaf's STARK proof against the reconstructed public inputs.
/// This is the expensive step (tens of ms); callers run it LAST and only for
/// claimed leaves. Returns `{"ok":bool,"reason":string|null}` as JSON so a
/// proof rejection is data, not an exception (only malformed *inputs* throw).
#[wasm_bindgen]
pub fn verify_leaf_stark(
    circuit_id: u8,
    commitment_hex: &str,
    public_inputs_json: &str,
    proof_bytes: &[u8],
) -> Result<String, JsError> {
    let circuit = parse_circuit(circuit_id)?;
    let commitment = digest_arg("commitment", commitment_hex)?;
    let public_inputs: serde_json::Value = serde_json::from_str(public_inputs_json)
        .map_err(|e| JsError::new(&format!("publicInputs parse: {}", e)))?;
    let (ok, reason) = match dispatch_verify(circuit, &commitment, &public_inputs, proof_bytes) {
        Ok(()) => (true, serde_json::Value::Null),
        Err(e) => (false, serde_json::Value::String(e)),
    };
    Ok(serde_json::json!({ "ok": ok, "reason": reason }).to_string())
}

fn decode_wallet(addr: &str) -> Option<[u8; 20]> {
    let stripped = addr.strip_prefix("0x").or(Some(addr))?;
    if stripped.len() != 40 || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}
