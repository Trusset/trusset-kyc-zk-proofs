//! Manifest schema, sentinel-signing helper, and canonical JSON
//! serialization.
//!
//! The signing-side and verifier-side derivations of the canonical bytes
//! MUST agree to the byte. Putting both helpers here keeps that property
//! self-evident.
//!
//! Two manifest views:
//!
//! 1. **Signing view** — `createdAt = CREATED_AT_SENTINEL`. The ed25519
//!    signer hashes this. The verifier reconstructs it by overwriting the
//!    disk manifest's `createdAt` with the sentinel before checking the
//!    signature.
//! 2. **Disk view** — `createdAt` = real ISO 8601 timestamp at write time.
//!    Identical to the signing view in every other field.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Sentinel placed in `createdAt` during signing so the signature is
/// independent of wall-clock time (plan §"Determinism").
pub const CREATED_AT_SENTINEL: &str = "1970-01-01T00:00:00Z";

pub const MANIFEST_VERSION: &str = "2.0.0";

/// Phase 2A marker. Phase 2B flips this to `"production"` for real STARK
/// proofs. Verifiers refuse stub manifests by default (`verify_strict`).
pub const MODE_STUB: &str = "stub";

/// Stable version of the `secrets.enc` KDF chain. Folded into the encrypt
/// info string in `prover/src/encrypt.rs` and serialized into the manifest
/// so a future key rotation can decrypt old bundles.
pub const SECRETS_KDF_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StarkBlock {
    pub library: String,
    #[serde(rename = "libraryVersion")]
    pub library_version: String,
    pub field: String,
    pub hash: String,
    #[serde(rename = "securityBits")]
    pub security_bits: u32,
}

impl Default for StarkBlock {
    fn default() -> Self {
        Self {
            library: "winterfell-stub".to_string(),
            library_version: "0.13".to_string(),
            field: "goldilocks".to_string(),
            hash: "rescue-prime".to_string(),
            security_bits: 100,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LeafEntry {
    #[serde(rename = "fieldName")]
    pub field_name: String,
    pub circuit: String,
    #[serde(rename = "circuitId")]
    pub circuit_id: u8,
    pub commitment: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: serde_json::Value,
    #[serde(rename = "publicDigest")]
    pub public_digest: String,
    #[serde(rename = "proofPath")]
    pub proof_path: String,
    #[serde(rename = "proofDigest")]
    pub proof_digest: String,
    #[serde(rename = "paramsHash")]
    pub params_hash: String,
    #[serde(rename = "leafHash")]
    pub leaf_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub root: String,
    #[serde(
        rename = "sourceSha256",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub mode: String,
    #[serde(rename = "walletAddress")]
    pub wallet_address: String,
    #[serde(rename = "kycHash")]
    pub kyc_hash: String,
    #[serde(rename = "epochDays")]
    pub epoch_days: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub deterministic: bool,
    #[serde(rename = "circuitsVersion")]
    pub circuits_version: u32,
    pub stark: StarkBlock,
    pub leaves: Vec<LeafEntry>,
    #[serde(default)]
    pub passthrough: serde_json::Value,
    #[serde(default)]
    pub lists: BTreeMap<String, ListEntry>,
    #[serde(rename = "secretsKdfVersion")]
    pub secrets_kdf_version: u32,
}

/// Serialize the manifest to canonical bytes used as the ed25519 signing
/// payload: sorted keys, two-space indent, Unix newlines, `createdAt` set
/// to the sentinel.
pub fn canonical_signing_bytes(manifest: &Manifest) -> serde_json::Result<Vec<u8>> {
    let mut for_signing = manifest.clone();
    for_signing.created_at = CREATED_AT_SENTINEL.to_string();
    canonical_bytes(&for_signing)
}

/// Serialize the manifest to canonical bytes for the on-disk
/// `manifest.json`. Same layout as the signing view, but with the real
/// timestamp.
pub fn canonical_disk_bytes(manifest: &Manifest) -> serde_json::Result<Vec<u8>> {
    canonical_bytes(manifest)
}

fn canonical_bytes(manifest: &Manifest) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(manifest)?;
    // `serde_json::Map` uses `BTreeMap` by default (no `preserve_order`
    // feature anywhere in the workspace), so keys are auto-sorted.
    let mut out = serde_json::to_vec_pretty(&value)?;
    // Strip carriage returns just in case the host adds them.
    out.retain(|b| *b != b'\r');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            version: MANIFEST_VERSION.to_string(),
            mode: MODE_STUB.to_string(),
            wallet_address: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
            kyc_hash: "0x9f1c".to_string(),
            epoch_days: 20587,
            created_at: "2026-05-14T09:12:33Z".to_string(),
            deterministic: true,
            circuits_version: 1,
            stark: StarkBlock::default(),
            leaves: vec![],
            passthrough: serde_json::json!({}),
            lists: BTreeMap::new(),
            secrets_kdf_version: SECRETS_KDF_VERSION,
        }
    }

    #[test]
    fn signing_bytes_use_sentinel() {
        let m = sample_manifest();
        let s = canonical_signing_bytes(&m).unwrap();
        assert!(String::from_utf8(s)
            .unwrap()
            .contains(r#""createdAt": "1970-01-01T00:00:00Z""#));
    }

    #[test]
    fn signing_bytes_dont_depend_on_real_timestamp() {
        let mut a = sample_manifest();
        let mut b = a.clone();
        a.created_at = "2026-05-14T09:12:33Z".to_string();
        b.created_at = "2099-12-31T23:59:59Z".to_string();
        assert_eq!(
            canonical_signing_bytes(&a).unwrap(),
            canonical_signing_bytes(&b).unwrap()
        );
    }

    #[test]
    fn disk_bytes_use_real_timestamp() {
        let m = sample_manifest();
        let s = canonical_disk_bytes(&m).unwrap();
        assert!(String::from_utf8(s)
            .unwrap()
            .contains(r#""createdAt": "2026-05-14T09:12:33Z""#));
    }

    #[test]
    fn roundtrip_through_serde() {
        let m = sample_manifest();
        let bytes = canonical_disk_bytes(&m).unwrap();
        let parsed: Manifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(m, parsed);
    }
}
