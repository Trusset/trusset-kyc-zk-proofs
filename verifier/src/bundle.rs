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
}

pub fn load_bundle(path: &Path) -> Result<LoadedBundle, VerifyError> {
    let manifest_bytes = std::fs::read(path.join("manifest.json"))
        .map_err(|e| VerifyError::Io(format!("manifest.json: {}", e)))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

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

    Ok(LoadedBundle {
        manifest,
        kyc_hash_file_text,
        signature,
        proofs,
        layout_ok,
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
    })
}
