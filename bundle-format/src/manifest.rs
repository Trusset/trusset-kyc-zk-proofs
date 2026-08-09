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

pub const MANIFEST_VERSION: &str = "2.1.0";

/// Prior manifest version still accepted on the verify path. Bundles
/// produced by v2.0.0 tooling parse into the same struct (every v2.1
/// field is optional-with-omission) and re-serialize byte-identically,
/// so their signatures stay valid under v2.1 verifiers.
pub const MANIFEST_VERSION_V200: &str = "2.0.0";

/// Manifest versions the verify path accepts.
pub const ACCEPTED_MANIFEST_VERSIONS: [&str; 2] = [MANIFEST_VERSION_V200, MANIFEST_VERSION];

/// Per-leaf disclosure classes (v2.1, optional field `disclosure`).
/// `plaintext`: the field's value is also disclosed outside the zk layer
/// (batch index CSV and manifest passthrough) - the proof does not hide it
/// in the default pipeline. `predicate`: only the predicate outcome is
/// meaningful to a counterparty. `commitment_only`: hiding commitment and
/// leaf hash only, no STARK; the proof file is a zero-length sentinel.
pub const DISCLOSURE_PLAINTEXT: &str = "plaintext";
pub const DISCLOSURE_PREDICATE: &str = "predicate";
pub const DISCLOSURE_COMMITMENT_ONLY: &str = "commitment_only";

/// Phase 2A marker. Phase 2B flips this to `MODE_PRODUCTION` for real
/// STARK proofs. Verifiers refuse stub manifests by default
/// (`verify_strict`).
pub const MODE_STUB: &str = "stub";

/// Phase 2B production marker. Emitted by the prover when the workspace is
/// built with the per-circuit `prod-proofs-*` features enabled AND the
/// real AIR predicates for ALL four circuits are in place. Once flipped,
/// strict verifiers accept bundles carrying this mode value; permissive
/// verifiers continue to accept both modes for diagnostic / development
/// flows. See [docs/STEP_2B_COMMITMENT_DESIGN.md](../../docs/STEP_2B_COMMITMENT_DESIGN.md)
/// for the operator-visible flip checklist.
pub const MODE_PRODUCTION: &str = "production";

/// Stable version of the `secrets.enc` KDF chain. Folded into the encrypt
/// info string in `prover/src/encrypt.rs` and serialized into the manifest
/// so a future key rotation can decrypt old bundles.
/// Version 2 (v2.1.0) introduces the wrapped per-subject key layout; the
/// version 1 direct-derivation path is retained for decrypting existing
/// bundles.
pub const SECRETS_KDF_VERSION: u32 = 2;

/// The v2.0.0 `secrets.enc` KDF chain (subject material derived directly
/// from the master key). Selected by `manifest.secretsKdfVersion == 1` on
/// the decrypt path.
pub const SECRETS_KDF_VERSION_V1: u32 = 1;

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
            // Stage 18 mode-flip: real Winterfell 0.13.x AIR is now
            // wired through all four circuits' prod-proofs feature
            // paths. The `library` string reflects that reality. With
            // `--skip-proofs` the bundle still carries this string
            // (the stub flag affects the `mode` field, not the
            // library declaration).
            library: "winterfell-0.13".to_string(),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
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
    #[serde(
        rename = "merkleVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub merkle_version: Option<u32>,
    #[serde(
        rename = "configHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub config_hash: Option<String>,
}

impl Manifest {
    /// The Merkle construction this manifest's `kycHash` was computed
    /// with. Absent means the v1 construction (pre-v2.1 bundles).
    #[must_use]
    pub fn effective_merkle_version(&self) -> u32 {
        self.merkle_version
            .unwrap_or(crate::merkle::MERKLE_VERSION_V1)
    }
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
            merkle_version: Some(crate::merkle::MERKLE_VERSION_V2),
            config_hash: None,
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

    /// v2.0.0 manifests carry none of the v2.1 optional fields. They must
    /// re-serialize byte-identically so their ed25519 signatures stay
    /// valid under v2.1 tooling - absent options must never appear as
    /// JSON keys.
    #[test]
    fn absent_v21_fields_are_omitted_from_canonical_bytes() {
        let mut m = sample_manifest();
        m.version = MANIFEST_VERSION_V200.to_string();
        m.merkle_version = None;
        m.config_hash = None;
        let text = String::from_utf8(canonical_disk_bytes(&m).unwrap()).unwrap();
        assert!(!text.contains("merkleVersion"));
        assert!(!text.contains("configHash"));
        assert!(!text.contains("disclosure"));
        let parsed: Manifest = serde_json::from_slice(text.as_bytes()).unwrap();
        assert_eq!(
            canonical_signing_bytes(&m).unwrap(),
            canonical_signing_bytes(&parsed).unwrap()
        );
    }

    #[test]
    fn accepted_versions_cover_both_wire_versions() {
        assert!(ACCEPTED_MANIFEST_VERSIONS.contains(&"2.0.0"));
        assert!(ACCEPTED_MANIFEST_VERSIONS.contains(&"2.1.0"));
        assert_eq!(MANIFEST_VERSION, "2.1.0");
    }

    /// Wire-format constants for `manifest.mode`. These strings are
    /// observed by counterparty verifiers across the workspace boundary
    /// and across language boundaries (the TS CLI also pattern-matches
    /// on these literals via the verifier binary's JSON output). They
    /// MUST NOT drift without a coordinated update to all consumers.
    #[test]
    fn mode_constants_are_stable_wire_strings() {
        assert_eq!(MODE_STUB, "stub");
        assert_eq!(MODE_PRODUCTION, "production");
        assert_ne!(MODE_STUB, MODE_PRODUCTION);
    }
}
