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
use trusset_bundle_format::manifest::{canonical_signing_bytes, Manifest};
use trusset_bundle_format::merkle::compute_root;
use trusset_bundle_format::sign;
use trusset_circuits_common::{digest_to_hex, hex_to_digest, CircuitId, Digest};

/// Options for `verify_bundle`.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// 32-byte ed25519 public key pinned out-of-band (e.g. published on the
    /// operator's website, hardcoded in the consumer's config).
    pub expected_public_key: [u8; sign::PUBLIC_KEY_LEN],
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
    /// `true` iff every check above passed and every leaf in `leaves` has
    /// `pass == true`.
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

    let layout_ok = loaded.layout_ok;
    let mode_acceptable = manifest.mode == "production" || opts.accept_stub;
    let kyc_hash_file_matches = loaded.kyc_hash_file_text.trim() == manifest.kyc_hash;

    // Signature: recompute the canonical signing view of the manifest.
    let sig_bytes_result = canonical_signing_bytes(manifest);
    let signature_valid = match (sig_bytes_result, loaded.signature.as_ref()) {
        (Ok(payload), Some(sig)) if sig.len() == sign::SIGNATURE_LEN => {
            let mut sig_arr = [0u8; sign::SIGNATURE_LEN];
            sig_arr.copy_from_slice(sig);
            sign::verify(&opts.expected_public_key, &payload, &sig_arr)
        }
        _ => false,
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

    // Merkle root: only meaningful if every leaf produced a hash.
    let merkle_root_valid = if leaf_hashes.len() == manifest.leaves.len()
        && !manifest.leaves.is_empty()
    {
        let (root, _) = compute_root(&leaf_hashes);
        digest_to_hex(&root) == manifest.kyc_hash
    } else {
        false
    };

    let overall_pass = layout_ok
        && mode_acceptable
        && kyc_hash_file_matches
        && signature_valid
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
            entry.circuit_id,
            entry.circuit
        ));
        return (None, report);
    }

    let circuit_verify_ok =
        match dispatch_verify(circuit_id, &commitment, &entry.public_inputs, proof_bytes) {
            Ok(()) => true,
            Err(reason) => {
                report.reason = Some(reason);
                return (None, report);
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

fn dispatch_verify(
    circuit_id: CircuitId,
    commitment: &Digest,
    public_inputs: &serde_json::Value,
    proof_bytes: &[u8],
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
            set::verify(proof_bytes, &public).map_err(|e| format!("set_membership: {:?}", e))
        }
    }
}

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
}
