//! Filesystem side of the v3 registries: read, append, sign, verify.
//!
//! The registries are append-only by construction, not by convention. Every
//! writer here refuses to modify or remove an existing record: a list version
//! can only be added after the current one, an anchor cannot replace an anchor
//! at the same height, and a revocation is only ever pushed. The alternative —
//! letting an operator rewrite history in the file that establishes what was
//! true when — would defeat the point of keeping it.
//!
//! Layout under the registry root (default `config/registry`):
//!
//! ```text
//! config/registry/
//!   lists/<listId>.json        ListRegistry, every version ever authoritative
//!   lists/<listId>.json.sig    detached ed25519 over its canonical bytes
//!   root_history.json          RootHistory
//!   root_history.json.sig
//!   revocations.json           RevocationLog
//!   revocations.json.sig
//! ```

use crate::errors::{ErrorCode, ProverError, Result};
use crate::sign::SigningSecret;
use std::fs;
use std::path::{Path, PathBuf};
use trusset_bundle_format::registry::{
    canonical_document_bytes, list_content_hash, ListRegistry, ListVersionRecord, RevocationLog,
    RevocationRecord, RootAnchor, RootHistory, REGISTRY_SCHEMA_VERSION,
};

pub const DEFAULT_REGISTRY_DIR: &str = "config/registry";

#[derive(Debug, Clone)]
pub struct RegistryPaths {
    pub root: PathBuf,
}

impl RegistryPaths {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn lists_dir(&self) -> PathBuf {
        self.root.join("lists")
    }

    #[must_use]
    pub fn list_file(&self, list_id: &str) -> PathBuf {
        self.lists_dir().join(format!("{}.json", list_id))
    }

    #[must_use]
    pub fn root_history_file(&self) -> PathBuf {
        self.root.join("root_history.json")
    }

    #[must_use]
    pub fn revocations_file(&self) -> PathBuf {
        self.root.join("revocations.json")
    }
}

fn sig_path(doc: &Path) -> PathBuf {
    let mut s = doc.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Write a registry document plus its detached signature over the canonical
/// bytes an archive and a verifier both reconstruct.
pub fn write_signed<T: serde::Serialize>(
    path: &Path,
    doc: &T,
    signing_key: &SigningSecret,
) -> Result<()> {
    let canonical = canonical_document_bytes(doc)
        .map_err(|e| ProverError::new(ErrorCode::Io, format!("canonical bytes: {}", e)))?;
    let signature = signing_key.sign(&canonical);
    // The readable copy is pretty-printed; the signature covers the canonical
    // compact form, which both the verifier and the archive recompute from
    // the parsed document rather than from these bytes.
    let pretty = serde_json::to_vec_pretty(doc)
        .map_err(|e| ProverError::new(ErrorCode::Io, format!("serialize: {}", e)))?;
    write_atomic(path, &pretty)?;
    write_atomic(&sig_path(path), signature.as_slice())?;
    Ok(())
}

pub fn read_signature(path: &Path) -> Option<Vec<u8>> {
    fs::read(sig_path(path)).ok()
}

// ============================== list registry ==============================

pub fn load_list_registry(paths: &RegistryPaths, list_id: &str) -> Result<Option<ListRegistry>> {
    let path = paths.list_file(list_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let reg: ListRegistry = serde_json::from_slice(&bytes).map_err(|e| {
        ProverError::new(
            ErrorCode::Config,
            format!("{}: not a readable list registry: {}", path.display(), e),
        )
    })?;
    reg.validate()
        .map_err(|e| ProverError::new(ErrorCode::Config, format!("{}: {}", path.display(), e)))?;
    if reg.list_id != list_id {
        return Err(ProverError::new(
            ErrorCode::Config,
            format!(
                "{} declares listId '{}' but was loaded as '{}'",
                path.display(),
                reg.list_id,
                list_id
            ),
        ));
    }
    Ok(Some(reg))
}

#[derive(Debug)]
pub struct AppendedVersion {
    pub version: u32,
    pub root: String,
    pub content_hash: String,
    pub superseded: Option<u32>,
}

/// Append a new authoritative version of a list.
///
/// Refuses when the values are unchanged: a rotation that changes nothing
/// would put two versions with the same root in the registry, and a verifier
/// resolving a proof's root back to a version would then have two answers.
#[allow(clippy::too_many_arguments)]
pub fn append_list_version(
    paths: &RegistryPaths,
    list_id: &str,
    values: Vec<String>,
    root: String,
    depth: u8,
    source_sha256: String,
    effective_from: u64,
    generator: String,
    recorded_at: String,
    note: Option<String>,
    signing_key: &SigningSecret,
) -> Result<AppendedVersion> {
    let mut registry =
        load_list_registry(paths, list_id)?.unwrap_or_else(|| ListRegistry::new(list_id));

    let content_hash = list_content_hash(&values);
    let mut superseded = None;

    if let Some(current) = registry.versions.last() {
        if current.content_hash.eq_ignore_ascii_case(&content_hash) {
            return Err(ProverError::new(
                ErrorCode::Config,
                format!(
                    "list '{}' version {} already has exactly these values. Nothing to record: \
                     a rotation must change the set, or two versions would share a root and a \
                     proof could not be resolved back to one of them.",
                    list_id, current.version
                ),
            ));
        }
        if effective_from <= current.effective_from {
            return Err(ProverError::new(
                ErrorCode::Config,
                format!(
                    "list '{}' version {} became effective on epoch day {}; a new version cannot \
                     start on or before that day. Pass a later --effective-from.",
                    list_id, current.version, current.effective_from
                ),
            ));
        }
        superseded = Some(current.version);
    }

    let next_version = registry.versions.len() as u32 + 1;
    if let Some(current) = registry.versions.last_mut() {
        // The outgoing version stops being authoritative the day before the
        // new one starts, so the two windows abut with no gap and no overlap.
        current.effective_until = Some(effective_from - 1);
    }

    registry.versions.push(ListVersionRecord {
        version: next_version,
        values,
        root: root.clone(),
        depth,
        content_hash: content_hash.clone(),
        source_sha256,
        effective_from,
        effective_until: None,
        generator,
        recorded_at,
        note,
    });

    registry.validate().map_err(|e| {
        ProverError::new(
            ErrorCode::Config,
            format!("refusing to write an invalid registry: {}", e),
        )
    })?;
    write_signed(&paths.list_file(list_id), &registry, signing_key)?;

    Ok(AppendedVersion {
        version: next_version,
        root,
        content_hash,
        superseded,
    })
}

// =============================== root history ===============================

pub fn load_root_history(paths: &RegistryPaths) -> Result<RootHistory> {
    let path = paths.root_history_file();
    if !path.exists() {
        return Ok(RootHistory::new());
    }
    let bytes = fs::read(&path)?;
    let history: RootHistory = serde_json::from_slice(&bytes).map_err(|e| {
        ProverError::new(
            ErrorCode::Config,
            format!("{}: not a readable root history: {}", path.display(), e),
        )
    })?;
    history
        .validate()
        .map_err(|e| ProverError::new(ErrorCode::Config, format!("{}: {}", path.display(), e)))?;
    Ok(history)
}

/// Record that a subject's `kycHash` was published to a chain at a block.
///
/// This is what makes an offline as-of check possible: without it, "which root
/// was live at block N" has no answer that does not involve an archive node.
pub fn append_root_anchor(
    paths: &RegistryPaths,
    anchor: RootAnchor,
    signing_key: &SigningSecret,
) -> Result<()> {
    let mut history = load_root_history(paths)?;

    for existing in &history.entries {
        if existing.subject.eq_ignore_ascii_case(&anchor.subject)
            && existing.chain_id == anchor.chain_id
            && existing.block_height == anchor.block_height
        {
            if existing.kyc_hash.eq_ignore_ascii_case(&anchor.kyc_hash) {
                // Recording the same publication twice is a no-op, not an
                // error: an operator re-running the anchor step after an
                // interruption should not have to reason about it.
                return Ok(());
            }
            return Err(ProverError::new(
                ErrorCode::Config,
                format!(
                    "root history already records a different root for {} at block {} on chain \
                     {}. An anchor is never rewritten; if the earlier entry was wrong, record \
                     the correction as a new anchor at the block where the correct root was \
                     published.",
                    anchor.subject, anchor.block_height, anchor.chain_id
                ),
            ));
        }
    }

    history.entries.push(anchor);
    history.entries.sort_by(|a, b| {
        a.subject
            .to_ascii_lowercase()
            .cmp(&b.subject.to_ascii_lowercase())
            .then(a.chain_id.cmp(&b.chain_id))
            .then(a.block_height.cmp(&b.block_height))
    });
    history
        .validate()
        .map_err(|e| ProverError::new(ErrorCode::Config, format!("{}", e)))?;
    write_signed(&paths.root_history_file(), &history, signing_key)?;
    Ok(())
}

// =============================== revocations ===============================

pub fn load_revocations(paths: &RegistryPaths) -> Result<RevocationLog> {
    let path = paths.revocations_file();
    if !path.exists() {
        return Ok(RevocationLog::new());
    }
    let bytes = fs::read(&path)?;
    let log: RevocationLog = serde_json::from_slice(&bytes).map_err(|e| {
        ProverError::new(
            ErrorCode::Config,
            format!("{}: not a readable revocation log: {}", path.display(), e),
        )
    })?;
    log.validate()
        .map_err(|e| ProverError::new(ErrorCode::Config, format!("{}: {}", path.display(), e)))?;
    Ok(log)
}

pub fn append_revocation(
    paths: &RegistryPaths,
    record: RevocationRecord,
    signing_key: &SigningSecret,
) -> Result<()> {
    record
        .validate()
        .map_err(|e| ProverError::new(ErrorCode::Input, format!("{}", e)))?;
    let mut log = load_revocations(paths)?;
    if log.entries.contains(&record) {
        return Ok(());
    }
    log.entries.push(record);
    log.schema_version = REGISTRY_SCHEMA_VERSION;
    write_signed(&paths.revocations_file(), &log, signing_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusset_bundle_format::registry::RevocationEffect;

    fn key() -> SigningSecret {
        SigningSecret::from_hex(&"42".repeat(32)).unwrap()
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn append(paths: &RegistryPaths, values: &[&str], from: u64) -> Result<AppendedVersion> {
        let values: Vec<String> = values.iter().map(|s| s.to_string()).collect();
        append_list_version(
            paths,
            "country_allowlist",
            values,
            format!("0x{:0>64}", from),
            2,
            format!("0x{:0>64}", from + 1),
            from,
            "test".to_string(),
            "2026-01-01T00:00:00Z".to_string(),
            None,
            &key(),
        )
    }

    #[test]
    fn first_append_creates_version_one() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        let a = append(&paths, &["DEU", "FRA"], 20000).unwrap();
        assert_eq!(a.version, 1);
        assert_eq!(a.superseded, None);
        let reg = load_list_registry(&paths, "country_allowlist")
            .unwrap()
            .unwrap();
        assert_eq!(reg.versions.len(), 1);
        assert!(reg.versions[0].effective_until.is_none());
    }

    #[test]
    fn rotation_closes_the_previous_window_and_keeps_its_values() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append(&paths, &["DEU", "FRA"], 20000).unwrap();
        let b = append(&paths, &["DEU", "FRA", "ESP"], 20700).unwrap();
        assert_eq!(b.version, 2);
        assert_eq!(b.superseded, Some(1));

        let reg = load_list_registry(&paths, "country_allowlist")
            .unwrap()
            .unwrap();
        assert_eq!(reg.versions.len(), 2);
        assert_eq!(reg.versions[0].effective_until, Some(20699));
        assert_eq!(
            reg.versions[0].values,
            vec!["DEU", "FRA"],
            "the superseded version must keep its own values"
        );
        assert_eq!(reg.resolve_at(20500).unwrap().version, 1);
        assert_eq!(reg.resolve_at(20700).unwrap().version, 2);
    }

    #[test]
    fn rotation_with_unchanged_values_is_refused() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append(&paths, &["DEU", "FRA"], 20000).unwrap();
        let err = append(&paths, &["DEU", "FRA"], 20700).unwrap_err();
        assert!(err.message.contains("already has exactly these values"));
    }

    #[test]
    fn rotation_backwards_in_time_is_refused() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append(&paths, &["DEU", "FRA"], 20700).unwrap();
        let err = append(&paths, &["DEU", "FRA", "ESP"], 20000).unwrap_err();
        assert!(err.message.contains("cannot start on or before"));
    }

    #[test]
    fn a_written_registry_verifies_under_the_signing_key() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append(&paths, &["DEU", "FRA"], 20000).unwrap();
        let reg = load_list_registry(&paths, "country_allowlist")
            .unwrap()
            .unwrap();
        let sig = read_signature(&paths.list_file("country_allowlist")).unwrap();
        assert_eq!(
            trusset_bundle_format::registry::verify_document(&reg, Some(&sig), &key().public_key()),
            Ok(())
        );
    }

    #[test]
    fn a_tampered_registry_fails_its_signature() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append(&paths, &["DEU", "FRA"], 20000).unwrap();
        let mut reg = load_list_registry(&paths, "country_allowlist")
            .unwrap()
            .unwrap();
        reg.versions[0].values.push("SMUGGLED".to_string());
        let sig = read_signature(&paths.list_file("country_allowlist")).unwrap();
        assert!(trusset_bundle_format::registry::verify_document(
            &reg,
            Some(&sig),
            &key().public_key()
        )
        .is_err());
    }

    fn anchor(block: u64, root: &str) -> RootAnchor {
        RootAnchor {
            subject: "0xAAA".to_string(),
            kyc_hash: root.to_string(),
            epoch_days: 20700,
            chain_id: 1,
            block_height: block,
            block_timestamp: 1_700_000_000 + block,
            tx_hash: None,
            manifest_sha256: format!("0x{}", "11".repeat(32)),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn anchors_accumulate_and_resolve_by_block() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append_root_anchor(&paths, anchor(1000, "0xaaaa"), &key()).unwrap();
        append_root_anchor(&paths, anchor(2000, "0xbbbb"), &key()).unwrap();
        let h = load_root_history(&paths).unwrap();
        assert_eq!(h.entries.len(), 2);
        assert_eq!(
            h.resolve_at_block("0xAAA", 1, 1500).unwrap().kyc_hash,
            "0xaaaa"
        );
    }

    #[test]
    fn re_recording_the_same_anchor_is_a_no_op() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append_root_anchor(&paths, anchor(1000, "0xaaaa"), &key()).unwrap();
        append_root_anchor(&paths, anchor(1000, "0xaaaa"), &key()).unwrap();
        assert_eq!(load_root_history(&paths).unwrap().entries.len(), 1);
    }

    #[test]
    fn rewriting_an_anchor_with_a_different_root_is_refused() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        append_root_anchor(&paths, anchor(1000, "0xaaaa"), &key()).unwrap();
        let err = append_root_anchor(&paths, anchor(1000, "0xcccc"), &key()).unwrap_err();
        assert!(err.message.contains("never rewritten"));
    }

    #[test]
    fn revocations_append_and_reject_the_malformed() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        let good = RevocationRecord {
            subject: "0xAAA".to_string(),
            kyc_hash: "0xroot".to_string(),
            leaf_name: Some("investorType".to_string()),
            effect: RevocationEffect::Lapsed,
            effective_from: Some(20900),
            declared_at: 21000,
            reason_code: "PERIODIC_REVIEW_OVERDUE".to_string(),
            note: None,
            issuer_key_id: "key-1".to_string(),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        };
        append_revocation(&paths, good.clone(), &key()).unwrap();
        assert_eq!(load_revocations(&paths).unwrap().entries.len(), 1);
        append_revocation(&paths, good, &key()).unwrap();
        assert_eq!(
            load_revocations(&paths).unwrap().entries.len(),
            1,
            "an identical revocation must not be appended twice"
        );

        let bad = RevocationRecord {
            subject: "0xAAA".to_string(),
            kyc_hash: "0xroot".to_string(),
            leaf_name: None,
            effect: RevocationEffect::VoidAbInitio,
            effective_from: Some(20900),
            declared_at: 21000,
            reason_code: "X".to_string(),
            note: None,
            issuer_key_id: "key-1".to_string(),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(append_revocation(&paths, bad, &key()).is_err());
    }

    #[test]
    fn loading_from_an_empty_registry_root_yields_empty_documents() {
        let dir = tmp();
        let paths = RegistryPaths::new(dir.path());
        assert!(load_list_registry(&paths, "nope").unwrap().is_none());
        assert!(load_root_history(&paths).unwrap().entries.is_empty());
        assert!(load_revocations(&paths).unwrap().entries.is_empty());
    }
}
