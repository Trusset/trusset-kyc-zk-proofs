//! Disk loader for a `trusset-prover` bundle directory.

use crate::VerifyError;
use std::collections::BTreeMap;
use std::path::Path;
use trusset_bundle_format::manifest::{is_safe_proof_path, Manifest};

/// All files from a bundle, materialized in memory.
#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub manifest: Manifest,
    pub kyc_hash_file_text: String,
    pub signature: Option<Vec<u8>>,
    /// Keyed by `manifest.leaves[].proofPath` (e.g. `"proofs/firstName.bin"`).
    pub proofs: BTreeMap<String, Vec<u8>>,
    /// True if every file referenced by the manifest is present and readable.
    pub layout_ok: bool,
    /// v3.1: `header.json` and `header.sig`, when the bundle has them.
    pub header_bytes: Option<Vec<u8>>,
    pub header_sig: Option<Vec<u8>>,
    /// True when `manifest.json` is exactly its own typed form: no key the
    /// schema does not know, no explicit null. Required of 3.1.0 manifests.
    pub manifest_exact: bool,
}

fn manifest_is_exact(bytes: &[u8], manifest: &Manifest) -> bool {
    match (
        serde_json::from_slice::<serde_json::Value>(bytes),
        serde_json::to_value(manifest),
    ) {
        (Ok(raw), Ok(typed)) => raw == typed,
        _ => false,
    }
}

pub fn load_bundle(path: &Path) -> Result<LoadedBundle, VerifyError> {
    let manifest_bytes = std::fs::read(path.join("manifest.json"))
        .map_err(|e| VerifyError::Io(format!("manifest.json: {}", e)))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    let manifest_exact = manifest_is_exact(&manifest_bytes, &manifest);

    let kyc_hash_file_text = std::fs::read_to_string(path.join("kycHash.hex")).unwrap_or_default();

    let signature = std::fs::read(path.join("manifest.sig")).ok();

    let mut proofs = BTreeMap::new();
    let mut layout_ok = !kyc_hash_file_text.is_empty() && signature.is_some();
    for leaf in &manifest.leaves {
        // The manifest is untrusted input and `proofPath` is the only field
        // in it that reaches the filesystem. Reject anything that is not a
        // plain `proofs/<name>` before joining, so a hand-written manifest
        // cannot make the verifier read outside the bundle directory.
        if !is_safe_proof_path(&leaf.proof_path) {
            layout_ok = false;
            continue;
        }
        let proof_full_path = path.join(&leaf.proof_path);
        match std::fs::read(&proof_full_path) {
            Ok(b) => {
                proofs.insert(leaf.proof_path.clone(), b);
            }
            Err(_) => {
                layout_ok = false;
            }
        }
    }

    let header_bytes = std::fs::read(path.join("header.json")).ok();
    let header_sig = std::fs::read(path.join("header.sig")).ok();

    Ok(LoadedBundle {
        manifest,
        kyc_hash_file_text,
        signature,
        proofs,
        layout_ok,
        header_bytes,
        header_sig,
        manifest_exact,
    })
}

/// Construct a `LoadedBundle` from in-memory bytes — used by WASM bindings
/// where the JS layer reads files and passes them through.
pub fn loaded_from_parts(
    manifest_bytes: &[u8],
    kyc_hash_file_text: &str,
    signature: Option<Vec<u8>>,
    proofs: BTreeMap<String, Vec<u8>>,
) -> Result<LoadedBundle, VerifyError> {
    let manifest: Manifest = serde_json::from_slice(manifest_bytes)?;
    let manifest_exact = manifest_is_exact(manifest_bytes, &manifest);
    let layout_ok = !kyc_hash_file_text.is_empty()
        && signature.is_some()
        && manifest
            .leaves
            .iter()
            .all(|l| is_safe_proof_path(&l.proof_path) && proofs.contains_key(&l.proof_path));
    Ok(LoadedBundle {
        manifest,
        kyc_hash_file_text: kyc_hash_file_text.to_string(),
        signature,
        proofs,
        layout_ok,
        header_bytes: None,
        header_sig: None,
        manifest_exact,
    })
}

/// `loaded_from_parts` plus a v3.1 header and its signature.
pub fn loaded_from_parts_with_header(
    manifest_bytes: &[u8],
    kyc_hash_file_text: &str,
    signature: Option<Vec<u8>>,
    proofs: BTreeMap<String, Vec<u8>>,
    header_bytes: Option<Vec<u8>>,
    header_sig: Option<Vec<u8>>,
) -> Result<LoadedBundle, VerifyError> {
    let mut loaded = loaded_from_parts(manifest_bytes, kyc_hash_file_text, signature, proofs)?;
    loaded.header_bytes = header_bytes;
    loaded.header_sig = header_sig;
    Ok(loaded)
}
