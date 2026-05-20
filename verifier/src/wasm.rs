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
