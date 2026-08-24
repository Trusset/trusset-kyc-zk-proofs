//! v3 archive container: everything needed to verify a batch, in one file.
//!
//! A bundle directory verifies offline today, but only against what a
//! verifier already knows. It cannot tell you what `setRoot: 0x9078…` was a
//! commitment to, which key signed it, which root was on chain at a given
//! block, or whether the operator has since declared the claim void. Those
//! live in the operator's working tree and nowhere else, so a bundle handed to
//! a third party is verifiable but not interpretable.
//!
//! An archive carries the bundles plus the registries they depend on and the
//! issuer identity that signed them. Verification from an archive needs the
//! file and a verifier binary — no access to the operator's machine, no
//! network, no chain.
//!
//! The container is JSON so a reviewer can open it without this tool. Proof
//! bytes and signatures are base64; everything else is readable. The
//! `digest` covers every field except `createdAt` and `digest` itself, so two
//! archives of the same content compare equal regardless of when they were
//! written.

use crate::claims::ValidityInterval;
use crate::manifest::{IssuerBlock, Manifest, ToolchainBlock};
use crate::registry::{
    canonical_document_bytes, ClaimStatus, ListRegistry, RegistryError, RevocationLog, RootHistory,
};
use base64ct::{Base64, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const ARCHIVE_VERSION: &str = "3.0.0";

/// One subject's bundle, materialized inside the container.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ArchivedSubject {
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    /// The manifest as structured JSON rather than opaque bytes, so the
    /// archive stays readable. `manifestSha256` pins the on-disk bytes it came
    /// from; the archive builder refuses to write a subject whose manifest
    /// does not re-serialize to those exact bytes.
    pub manifest: Manifest,
    #[serde(rename = "manifestSha256")]
    pub manifest_sha256: String,
    #[serde(rename = "manifestSig")]
    pub manifest_sig: String,
    #[serde(rename = "kycHashHex")]
    pub kyc_hash_hex: String,
    /// Keyed by `manifest.leaves[].proofPath`, base64 of the proof bytes.
    pub proofs: BTreeMap<String, String>,
    /// Present only when the operator archived witness material. Omitted by
    /// default: an archive is usually handed to a counterparty, and
    /// `secrets.enc` is operator-private even though it is encrypted.
    #[serde(
        rename = "secretsEnc",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secrets_enc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    #[serde(rename = "archiveVersion")]
    pub archive_version: String,
    /// Operator-chosen label for the batch, e.g. `2026-Q3-onboarding`.
    #[serde(rename = "archiveId")]
    pub archive_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub issuer: IssuerBlock,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<ToolchainBlock>,
    pub subjects: Vec<ArchivedSubject>,
    /// Every list registry any archived leaf depends on, in full, including
    /// superseded versions.
    #[serde(rename = "listRegistries", default)]
    pub list_registries: BTreeMap<String, ListRegistry>,
    #[serde(rename = "listRegistrySignatures", default)]
    pub list_registry_signatures: BTreeMap<String, String>,
    #[serde(rename = "rootHistory")]
    pub root_history: RootHistory,
    #[serde(
        rename = "rootHistorySignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub root_history_signature: Option<String>,
    pub revocations: RevocationLog,
    #[serde(
        rename = "revocationsSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocations_signature: Option<String>,
    /// SHA-256 over the canonical bytes of every field except `createdAt` and
    /// `digest`.
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    UnsupportedVersion(String),
    DigestMismatch { recorded: String, computed: String },
    SubjectNotFound(String),
    MissingProof { subject: String, path: String },
    BadBase64 { subject: String, path: String },
    ManifestBytesDiverge(String),
    Registry(RegistryError),
    Malformed(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::UnsupportedVersion(v) => write!(
                f,
                "archive format {} is not readable by this build (expected {})",
                v, ARCHIVE_VERSION
            ),
            ArchiveError::DigestMismatch { recorded, computed } => write!(
                f,
                "archive integrity check failed: recorded digest {} but the contents hash to {}. \
                 The file has been modified since it was written.",
                recorded, computed
            ),
            ArchiveError::SubjectNotFound(s) => {
                write!(f, "archive contains no subject {}", s)
            }
            ArchiveError::MissingProof { subject, path } => write!(
                f,
                "subject {}: archive is missing proof {} referenced by its manifest",
                subject, path
            ),
            ArchiveError::BadBase64 { subject, path } => {
                write!(f, "subject {}: {} is not valid base64", subject, path)
            }
            ArchiveError::ManifestBytesDiverge(s) => write!(
                f,
                "subject {}: manifest does not re-serialize to the bytes its SHA-256 records. \
                 The manifest was hand-edited after signing.",
                s
            ),
            ArchiveError::Registry(e) => write!(f, "{}", e),
            ArchiveError::Malformed(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<RegistryError> for ArchiveError {
    fn from(e: RegistryError) -> Self {
        ArchiveError::Registry(e)
    }
}

pub fn encode_b64(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

pub fn decode_b64(text: &str) -> Option<Vec<u8>> {
    Base64::decode_vec(text).ok()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for b in out {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    format!("0x{}", s)
}

/// Compute the integrity digest of an archive: SHA-256 over canonical JSON
/// with `createdAt` and `digest` removed.
pub fn compute_archive_digest(archive: &Archive) -> Result<String, ArchiveError> {
    let mut value = serde_json::to_value(archive)
        .map_err(|e| ArchiveError::Malformed(format!("serialize archive: {}", e)))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("digest");
        obj.remove("createdAt");
    }
    let bytes = serde_json::to_vec(&value)
        .map_err(|e| ArchiveError::Malformed(format!("canonical bytes: {}", e)))?;
    Ok(sha256_hex(&bytes))
}

/// Serialize an archive for writing, stamping the digest first.
pub fn finalize(mut archive: Archive) -> Result<(Archive, Vec<u8>), ArchiveError> {
    archive.digest = String::new();
    archive.digest = compute_archive_digest(&archive)?;
    let bytes = serde_json::to_vec_pretty(&archive)
        .map_err(|e| ArchiveError::Malformed(format!("serialize archive: {}", e)))?;
    Ok((archive, bytes))
}

impl Archive {
    /// Parse and integrity-check. Every read path goes through here: an
    /// archive that fails its own digest is refused before any of its contents
    /// are believed.
    pub fn parse(bytes: &[u8]) -> Result<Self, ArchiveError> {
        let archive: Archive = serde_json::from_slice(bytes)
            .map_err(|e| ArchiveError::Malformed(format!("archive parse: {}", e)))?;
        if archive.archive_version != ARCHIVE_VERSION {
            return Err(ArchiveError::UnsupportedVersion(
                archive.archive_version.clone(),
            ));
        }
        let recorded = archive.digest.clone();
        let mut probe = archive.clone();
        probe.digest = String::new();
        let computed = compute_archive_digest(&probe)?;
        if !recorded.eq_ignore_ascii_case(&computed) {
            return Err(ArchiveError::DigestMismatch { recorded, computed });
        }
        archive.validate_structure()?;
        Ok(archive)
    }

    /// Structural checks that do not need a key: registries well formed, every
    /// manifest re-serializing to the bytes it claims, every referenced proof
    /// present and decodable.
    pub fn validate_structure(&self) -> Result<(), ArchiveError> {
        for reg in self.list_registries.values() {
            reg.validate()?;
        }
        self.root_history.validate()?;
        self.revocations.validate()?;

        for s in &self.subjects {
            let disk = crate::manifest::canonical_disk_bytes(&s.manifest)
                .map_err(|e| ArchiveError::Malformed(format!("manifest re-serialize: {}", e)))?;
            if sha256_hex(&disk) != s.manifest_sha256.to_ascii_lowercase() {
                return Err(ArchiveError::ManifestBytesDiverge(s.subject_id.clone()));
            }
            for leaf in &s.manifest.leaves {
                let Some(b64) = s.proofs.get(&leaf.proof_path) else {
                    return Err(ArchiveError::MissingProof {
                        subject: s.subject_id.clone(),
                        path: leaf.proof_path.clone(),
                    });
                };
                if decode_b64(b64).is_none() {
                    return Err(ArchiveError::BadBase64 {
                        subject: s.subject_id.clone(),
                        path: leaf.proof_path.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn subject(&self, subject_id: &str) -> Option<&ArchivedSubject> {
        self.subjects
            .iter()
            .find(|s| s.subject_id.eq_ignore_ascii_case(subject_id))
    }

    /// Decoded proof bytes for one subject, keyed by `proofPath`.
    pub fn proofs_for(&self, subject_id: &str) -> Result<BTreeMap<String, Vec<u8>>, ArchiveError> {
        let s = self
            .subject(subject_id)
            .ok_or_else(|| ArchiveError::SubjectNotFound(subject_id.to_string()))?;
        let mut out = BTreeMap::new();
        for (path, b64) in &s.proofs {
            let bytes = decode_b64(b64).ok_or_else(|| ArchiveError::BadBase64 {
                subject: subject_id.to_string(),
                path: path.clone(),
            })?;
            out.insert(path.clone(), bytes);
        }
        Ok(out)
    }

    pub fn signature_for(&self, subject_id: &str) -> Result<Vec<u8>, ArchiveError> {
        let s = self
            .subject(subject_id)
            .ok_or_else(|| ArchiveError::SubjectNotFound(subject_id.to_string()))?;
        decode_b64(&s.manifest_sig).ok_or_else(|| ArchiveError::BadBase64 {
            subject: subject_id.to_string(),
            path: "manifest.sig".to_string(),
        })
    }

    /// Resolve a leaf's list version from the archived registries. Returns the
    /// values the proof's `setRoot` was a commitment to.
    #[must_use]
    pub fn resolve_list_values(&self, list_id: &str, root: &str) -> Option<&Vec<String>> {
        self.list_registries
            .get(list_id)
            .and_then(|r| r.resolve_root(root))
            .map(|v| &v.values)
    }

    /// Status of one leaf at one instant, resolved entirely from the archive.
    #[must_use]
    pub fn claim_status(
        &self,
        subject_id: &str,
        kyc_hash: &str,
        leaf_name: &str,
        validity: Option<&ValidityInterval>,
        at_epoch_days: u64,
    ) -> ClaimStatus {
        self.revocations
            .status_at(subject_id, kyc_hash, leaf_name, validity, at_epoch_days)
    }

    /// Detached signatures inside the archive cover the same canonical bytes
    /// the standalone registry files do, so an archived registry verifies
    /// under the issuer key exactly as the on-disk one does.
    pub fn verify_registry_signatures(
        &self,
        public_key: &[u8; crate::sign::PUBLIC_KEY_LEN],
    ) -> Result<(), ArchiveError> {
        for (id, reg) in &self.list_registries {
            let sig = self
                .list_registry_signatures
                .get(id)
                .and_then(|s| decode_b64(s));
            crate::registry::verify_document(reg, sig.as_deref(), public_key).map_err(|_| {
                ArchiveError::Registry(RegistryError::Malformed(format!(
                    "list registry '{}' signature does not verify under the issuer key",
                    id
                )))
            })?;
        }
        if !self.root_history.entries.is_empty() {
            let sig = self
                .root_history_signature
                .as_ref()
                .and_then(|s| decode_b64(s));
            crate::registry::verify_document(&self.root_history, sig.as_deref(), public_key)
                .map_err(|_| {
                    ArchiveError::Registry(RegistryError::Malformed(
                        "root history signature does not verify under the issuer key".to_string(),
                    ))
                })?;
        }
        if !self.revocations.entries.is_empty() {
            let sig = self
                .revocations_signature
                .as_ref()
                .and_then(|s| decode_b64(s));
            crate::registry::verify_document(&self.revocations, sig.as_deref(), public_key)
                .map_err(|_| {
                    ArchiveError::Registry(RegistryError::Malformed(
                        "revocation log signature does not verify under the issuer key".to_string(),
                    ))
                })?;
        }
        Ok(())
    }
}

/// Canonical bytes of a registry document, re-exported so the archive builder
/// and the on-disk registry writer sign identical bytes.
pub use crate::registry::canonical_document_bytes as registry_signing_bytes;

/// Convenience for callers that hold a document and want its signing bytes.
pub fn document_signing_bytes<T: Serialize>(doc: &T) -> Result<Vec<u8>, ArchiveError> {
    canonical_document_bytes(doc)
        .map_err(|e| ArchiveError::Malformed(format!("canonical bytes: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::PartyRef;
    use crate::manifest::{canonical_disk_bytes, StarkBlock, SECRETS_KDF_VERSION};

    fn issuer() -> IssuerBlock {
        IssuerBlock {
            party: PartyRef {
                name: "Example Bank AG".to_string(),
                identifier_scheme: "LEI".to_string(),
                identifier: "529900T8BM49AURSDO55".to_string(),
                jurisdiction: "DE".to_string(),
            },
            public_key: format!("0x{}", "ab".repeat(32)),
            key_id: "key-1".to_string(),
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            version: crate::manifest::MANIFEST_VERSION.to_string(),
            mode: crate::manifest::MODE_PRODUCTION.to_string(),
            wallet_address: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
            kyc_hash: format!("0x{}", "cd".repeat(32)),
            epoch_days: 20700,
            created_at: "2026-08-24T00:00:00Z".to_string(),
            deterministic: true,
            circuits_version: 3,
            stark: StarkBlock::default(),
            leaves: vec![],
            passthrough: serde_json::json!({}),
            lists: BTreeMap::new(),
            secrets_kdf_version: SECRETS_KDF_VERSION,
            merkle_version: Some(crate::merkle::MERKLE_VERSION_V2),
            config_hash: None,
            epoch_days_source: Some("fixed:20700".to_string()),
            as_of_date: Some("2026-08-24".to_string()),
            unpinned_epoch: None,
            issuer: Some(issuer()),
            toolchain: None,
        }
    }

    fn archive() -> Archive {
        let m = manifest();
        let disk = canonical_disk_bytes(&m).unwrap();
        Archive {
            archive_version: ARCHIVE_VERSION.to_string(),
            archive_id: "test-batch".to_string(),
            created_at: "2026-08-24T12:00:00Z".to_string(),
            issuer: issuer(),
            toolchain: None,
            subjects: vec![ArchivedSubject {
                subject_id: m.wallet_address.clone(),
                manifest_sha256: sha256_hex(&disk),
                manifest: m,
                manifest_sig: encode_b64(&[7u8; 64]),
                kyc_hash_hex: format!("0x{}", "cd".repeat(32)),
                proofs: BTreeMap::new(),
                secrets_enc: None,
            }],
            list_registries: BTreeMap::new(),
            list_registry_signatures: BTreeMap::new(),
            root_history: RootHistory::new(),
            root_history_signature: None,
            revocations: RevocationLog::new(),
            revocations_signature: None,
            digest: String::new(),
        }
    }

    #[test]
    fn finalize_then_parse_round_trips() {
        let (_, bytes) = finalize(archive()).unwrap();
        let parsed = Archive::parse(&bytes).unwrap();
        assert_eq!(parsed.archive_id, "test-batch");
        assert_eq!(parsed.subjects.len(), 1);
    }

    #[test]
    fn a_modified_archive_fails_its_digest() {
        let (_, bytes) = finalize(archive()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["subjects"][0]["kycHashHex"] = serde_json::json!("0xdeadbeef");
        let tampered = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            Archive::parse(&tampered),
            Err(ArchiveError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn the_digest_ignores_created_at_so_identical_content_compares_equal() {
        let (a, _) = finalize(archive()).unwrap();
        let mut later = archive();
        later.created_at = "2099-01-01T00:00:00Z".to_string();
        let (b, _) = finalize(later).unwrap();
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn the_digest_covers_the_registries() {
        let (a, _) = finalize(archive()).unwrap();
        let mut with_revocation = archive();
        with_revocation
            .revocations
            .entries
            .push(crate::registry::RevocationRecord {
                subject: "0xAAA".to_string(),
                kyc_hash: "0xroot".to_string(),
                leaf_name: None,
                effect: crate::registry::RevocationEffect::VoidAbInitio,
                effective_from: None,
                declared_at: 21000,
                reason_code: "TEST".to_string(),
                note: None,
                issuer_key_id: "key-1".to_string(),
                recorded_at: "2026-01-01T00:00:00Z".to_string(),
            });
        let (b, _) = finalize(with_revocation).unwrap();
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn a_hand_edited_manifest_is_refused_at_parse() {
        let mut a = archive();
        a.subjects[0].manifest_sha256 = format!("0x{}", "00".repeat(32));
        let (_, bytes) = finalize(a).unwrap();
        assert!(matches!(
            Archive::parse(&bytes),
            Err(ArchiveError::ManifestBytesDiverge(_))
        ));
    }

    #[test]
    fn a_missing_proof_is_refused_at_parse() {
        let mut a = archive();
        a.subjects[0]
            .manifest
            .leaves
            .push(crate::manifest::LeafEntry {
                field_name: "firstName".to_string(),
                circuit: "preimage_knowledge".to_string(),
                circuit_id: 4,
                commitment: format!("0x{}", "11".repeat(32)),
                public_inputs: serde_json::json!({}),
                public_digest: format!("0x{}", "22".repeat(32)),
                proof_path: "proofs/firstName.bin".to_string(),
                proof_digest: format!("0x{}", "33".repeat(32)),
                params_hash: format!("0x{}", "44".repeat(32)),
                leaf_hash: format!("0x{}", "55".repeat(32)),
                disclosure: None,
                params: None,
                binding: None,
                binding_digest: None,
            });
        let disk = canonical_disk_bytes(&a.subjects[0].manifest).unwrap();
        a.subjects[0].manifest_sha256 = sha256_hex(&disk);
        let (_, bytes) = finalize(a).unwrap();
        assert!(matches!(
            Archive::parse(&bytes),
            Err(ArchiveError::MissingProof { .. })
        ));
    }

    #[test]
    fn base64_round_trips_proof_bytes() {
        let raw: Vec<u8> = (0u8..=255).collect();
        let encoded = encode_b64(&raw);
        assert_eq!(decode_b64(&encoded).unwrap(), raw);
        assert!(decode_b64("not base64!!!").is_none());
    }

    #[test]
    fn unsupported_archive_versions_are_refused() {
        let mut a = archive();
        a.archive_version = "9.9.9".to_string();
        let (_, bytes) = finalize(a).unwrap();
        assert!(matches!(
            Archive::parse(&bytes),
            Err(ArchiveError::UnsupportedVersion(_))
        ));
    }
}
