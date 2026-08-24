//! v3 append-only registries: list versions, root history, and revocations.
//!
//! Three problems these solve, none of which v2 addressed:
//!
//! 1. **A list root has no preimage.** A v2 bundle records
//!    `setRoot: 0x9078…` and nothing that says what set that root stands for.
//!    Regenerating a list overwrites the only copy of its values.
//!    [`ListRegistry`] keeps every version that was ever authoritative, with
//!    its values, its root, and the window over which it applied.
//!
//! 2. **`kycHash` on chain has no history.** Verifying "was this subject
//!    entitled at block N" needs the root that was published at block N, not
//!    the one published today. [`RootHistory`] records each publish with its
//!    block height and timestamp, so an as-of check resolves offline.
//!
//! 3. **A signed manifest cannot be edited.** Ending a claim, or declaring it
//!    was never true, must not rewrite the artifact that asserted it — the
//!    original assertion is the evidence of what the operator said.
//!    [`RevocationLog`] carries those declarations as separate records.
//!
//! All three are plain data here. Signing lives in the prover (which holds the
//! key); verification uses [`crate::sign::verify`] over
//! [`canonical_document_bytes`].

use crate::sign;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const REGISTRY_SCHEMA_VERSION: u32 = 1;

/// Canonical bytes of any registry document: compact JSON with keys sorted at
/// every depth. Detached signatures cover exactly these bytes.
pub fn canonical_document_bytes<T: Serialize>(doc: &T) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(doc)?;
    serde_json::to_vec(&value)
}

/// SHA-256 over the NFC-canonical values of a list, newline-joined, as
/// `0x`-prefixed hex.
///
/// Distinct from `sourceSha256`, which hashes the source file verbatim and so
/// changes when a comment is edited. `contentHash` changes only when the set
/// changes, which is what an auditor comparing two versions actually wants.
pub fn list_content_hash(values: &[String]) -> String {
    let mut h = Sha256::new();
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(v.as_bytes());
    }
    format!("0x{}", hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ============================== list registry ==============================

/// One version of a list, retained forever.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListVersionRecord {
    pub version: u32,
    /// The values themselves. This is the field that makes an old `setRoot`
    /// interpretable years later.
    pub values: Vec<String>,
    pub root: String,
    pub depth: u8,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    #[serde(rename = "sourceSha256")]
    pub source_sha256: String,
    /// First `epochDays` on which this version was authoritative, inclusive.
    #[serde(rename = "effectiveFrom")]
    pub effective_from: u64,
    /// Last `epochDays` on which it was authoritative, inclusive. `None` on
    /// the current version only.
    #[serde(
        rename = "effectiveUntil",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_until: Option<u64>,
    pub generator: String,
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
    /// Free-text reason for the rotation, e.g. the sanctions update that
    /// prompted it. Not interpreted; retained for the audit trail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListRegistry {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "listId")]
    pub list_id: String,
    /// Ascending by `version`, contiguous from 1. Never rewritten, never
    /// truncated.
    pub versions: Vec<ListVersionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    Empty(String),
    SchemaVersion { found: u32, expected: u32 },
    NonContiguousVersion { expected: u32, found: u32 },
    OverlappingRange { version: u32 },
    OpenRangeNotLast { version: u32 },
    ContentHashMismatch { version: u32 },
    ListIdMismatch { expected: String, found: String },
    DuplicateAnchor { subject: String, block: u64 },
    VoidWithEffectiveFrom,
    LapseWithoutEffectiveFrom,
    SignatureInvalid,
    Malformed(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Empty(what) => write!(f, "{} is empty", what),
            RegistryError::SchemaVersion { found, expected } => write!(
                f,
                "registry schemaVersion {} is not supported (this build reads {})",
                found, expected
            ),
            RegistryError::NonContiguousVersion { expected, found } => write!(
                f,
                "list versions must be contiguous from 1: expected version {}, found {}",
                expected, found
            ),
            RegistryError::OverlappingRange { version } => write!(
                f,
                "list version {} overlaps the previous version's authoritative window",
                version
            ),
            RegistryError::OpenRangeNotLast { version } => write!(
                f,
                "list version {} has no effectiveUntil but is not the current version",
                version
            ),
            RegistryError::ContentHashMismatch { version } => write!(
                f,
                "list version {}: contentHash does not match its recorded values",
                version
            ),
            RegistryError::ListIdMismatch { expected, found } => write!(
                f,
                "list registry declares listId '{}' but was loaded as '{}'",
                found, expected
            ),
            RegistryError::DuplicateAnchor { subject, block } => write!(
                f,
                "root history has two entries for subject {} at block {}",
                subject, block
            ),
            RegistryError::VoidWithEffectiveFrom => f.write_str(
                "a void_ab_initio revocation must not carry effectiveFrom: it voids the claim from \
                 the beginning, and naming a date would imply the claim held before it",
            ),
            RegistryError::LapseWithoutEffectiveFrom => {
                f.write_str("a lapsed revocation requires effectiveFrom: the date the claim ended")
            }
            RegistryError::SignatureInvalid => {
                f.write_str("registry signature does not verify under the supplied public key")
            }
            RegistryError::Malformed(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for RegistryError {}

impl ListRegistry {
    #[must_use]
    pub fn new(list_id: &str) -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            list_id: list_id.to_string(),
            versions: Vec::new(),
        }
    }

    /// Structural checks: contiguous versions from 1, non-overlapping windows
    /// in ascending order, only the last version open-ended, and every
    /// `contentHash` reproducible from its own values.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::SchemaVersion {
                found: self.schema_version,
                expected: REGISTRY_SCHEMA_VERSION,
            });
        }
        if self.versions.is_empty() {
            return Err(RegistryError::Empty(format!(
                "list registry '{}'",
                self.list_id
            )));
        }
        let last_index = self.versions.len() - 1;
        let mut previous_until: Option<u64> = None;
        for (i, v) in self.versions.iter().enumerate() {
            let expected = (i as u32) + 1;
            if v.version != expected {
                return Err(RegistryError::NonContiguousVersion {
                    expected,
                    found: v.version,
                });
            }
            if list_content_hash(&v.values) != v.content_hash.to_ascii_lowercase() {
                return Err(RegistryError::ContentHashMismatch { version: v.version });
            }
            if let Some(prev) = previous_until {
                if v.effective_from <= prev {
                    return Err(RegistryError::OverlappingRange { version: v.version });
                }
            }
            match v.effective_until {
                Some(u) => {
                    if u < v.effective_from {
                        return Err(RegistryError::Malformed(format!(
                            "list version {}: effectiveUntil {} precedes effectiveFrom {}",
                            v.version, u, v.effective_from
                        )));
                    }
                    previous_until = Some(u);
                }
                None => {
                    if i != last_index {
                        return Err(RegistryError::OpenRangeNotLast { version: v.version });
                    }
                }
            }
        }
        Ok(())
    }

    /// The version authoritative on `epoch_days`.
    #[must_use]
    pub fn resolve_at(&self, epoch_days: u64) -> Option<&ListVersionRecord> {
        self.versions.iter().find(|v| {
            epoch_days >= v.effective_from && v.effective_until.is_none_or(|u| epoch_days <= u)
        })
    }

    #[must_use]
    pub fn resolve_version(&self, version: u32) -> Option<&ListVersionRecord> {
        self.versions.iter().find(|v| v.version == version)
    }

    /// The version whose Merkle root matches. This is how a verifier gets from
    /// a proof's `setRoot` back to the list's contents.
    #[must_use]
    pub fn resolve_root(&self, root: &str) -> Option<&ListVersionRecord> {
        self.versions
            .iter()
            .find(|v| v.root.eq_ignore_ascii_case(root))
    }

    #[must_use]
    pub fn current(&self) -> Option<&ListVersionRecord> {
        self.versions.last()
    }
}

// =============================== root history ===============================

/// One publication of a subject's `kycHash` to a chain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RootAnchor {
    pub subject: String,
    #[serde(rename = "kycHash")]
    pub kyc_hash: String,
    /// The `epochDays` of the bundle whose root this is.
    #[serde(rename = "epochDays")]
    pub epoch_days: u64,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    #[serde(rename = "blockHeight")]
    pub block_height: u64,
    /// Unix seconds of that block. Lets an as-of query be phrased as a date
    /// rather than a height, which is how entitlement questions are usually
    /// asked.
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: u64,
    #[serde(rename = "txHash", default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// SHA-256 of the `manifest.json` this root came from, so an anchor can be
    /// tied to a specific bundle rather than just to a hex string.
    #[serde(rename = "manifestSha256")]
    pub manifest_sha256: String,
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RootHistory {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub entries: Vec<RootAnchor>,
}

impl Default for RootHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl RootHistory {
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::SchemaVersion {
                found: self.schema_version,
                expected: REGISTRY_SCHEMA_VERSION,
            });
        }
        for (i, a) in self.entries.iter().enumerate() {
            for b in self.entries.iter().skip(i + 1) {
                if a.subject.eq_ignore_ascii_case(&b.subject)
                    && a.chain_id == b.chain_id
                    && a.block_height == b.block_height
                {
                    return Err(RegistryError::DuplicateAnchor {
                        subject: a.subject.clone(),
                        block: a.block_height,
                    });
                }
            }
        }
        Ok(())
    }

    /// The root that was authoritative for `subject` at `block` on `chain_id`:
    /// the latest anchor at or below that height. `None` means nothing had been
    /// published for that subject yet, which is a meaningful answer — the
    /// subject was not entitled at that block.
    #[must_use]
    pub fn resolve_at_block(
        &self,
        subject: &str,
        chain_id: u64,
        block: u64,
    ) -> Option<&RootAnchor> {
        self.entries
            .iter()
            .filter(|a| {
                a.subject.eq_ignore_ascii_case(subject)
                    && a.chain_id == chain_id
                    && a.block_height <= block
            })
            .max_by_key(|a| a.block_height)
    }

    /// Same, resolved by wall-clock instant instead of height.
    #[must_use]
    pub fn resolve_at_timestamp(
        &self,
        subject: &str,
        chain_id: u64,
        timestamp: u64,
    ) -> Option<&RootAnchor> {
        self.entries
            .iter()
            .filter(|a| {
                a.subject.eq_ignore_ascii_case(subject)
                    && a.chain_id == chain_id
                    && a.block_timestamp <= timestamp
            })
            .max_by_key(|a| a.block_timestamp)
    }

    #[must_use]
    pub fn for_subject(&self, subject: &str) -> Vec<&RootAnchor> {
        let mut v: Vec<&RootAnchor> = self
            .entries
            .iter()
            .filter(|a| a.subject.eq_ignore_ascii_case(subject))
            .collect();
        v.sort_by_key(|a| a.block_height);
        v
    }
}

// =============================== revocations ===============================

/// The two legally distinct ways a claim stops being usable.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationEffect {
    /// The claim was true and stopped being true on `effectiveFrom`.
    /// Everything that relied on it strictly before that date stands.
    #[serde(rename = "lapsed")]
    Lapsed,
    /// The claim was never true. Every reliance on it, at any date, is in
    /// question. Carries no `effectiveFrom`: naming one would imply the claim
    /// held before it.
    #[serde(rename = "void_ab_initio")]
    VoidAbInitio,
}

impl RevocationEffect {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationEffect::Lapsed => "lapsed",
            RevocationEffect::VoidAbInitio => "void_ab_initio",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevocationRecord {
    pub subject: String,
    /// The root of the bundle being revoked. A revocation is always about a
    /// specific issuance, never about a subject in the abstract.
    #[serde(rename = "kycHash")]
    pub kyc_hash: String,
    /// The leaf this applies to. `None` revokes every leaf in the bundle.
    #[serde(rename = "leafName", default, skip_serializing_if = "Option::is_none")]
    pub leaf_name: Option<String>,
    pub effect: RevocationEffect,
    /// For `lapsed`: the first `epochDays` on which the claim no longer holds.
    /// Must be absent for `void_ab_initio`.
    #[serde(
        rename = "effectiveFrom",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_from: Option<u64>,
    /// When the operator made this declaration, which is not the same as when
    /// the claim ended. A lapse discovered late has `declaredAt` well after
    /// `effectiveFrom`, and that gap is itself audit-relevant.
    #[serde(rename = "declaredAt")]
    pub declared_at: u64,
    #[serde(rename = "reasonCode")]
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "issuerKeyId")]
    pub issuer_key_id: String,
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
}

impl RevocationRecord {
    pub fn validate(&self) -> Result<(), RegistryError> {
        match self.effect {
            RevocationEffect::VoidAbInitio if self.effective_from.is_some() => {
                Err(RegistryError::VoidWithEffectiveFrom)
            }
            RevocationEffect::Lapsed if self.effective_from.is_none() => {
                Err(RegistryError::LapseWithoutEffectiveFrom)
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    fn applies_to(&self, subject: &str, kyc_hash: &str, leaf_name: &str) -> bool {
        self.subject.eq_ignore_ascii_case(subject)
            && self.kyc_hash.eq_ignore_ascii_case(kyc_hash)
            && match &self.leaf_name {
                Some(l) => l == leaf_name,
                None => true,
            }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RevocationLog {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub entries: Vec<RevocationRecord>,
}

impl Default for RevocationLog {
    fn default() -> Self {
        Self::new()
    }
}

/// What a claim is worth at a given moment.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Asserted and not revoked, and the query instant falls inside the
    /// leaf's validity interval.
    Effective,
    /// Inside the validity interval, but a lapse took effect at or before the
    /// query instant.
    Lapsed { effective_from: u64 },
    /// Declared never to have been true. Applies at every instant, including
    /// instants before the declaration.
    Void,
    /// Not revoked, but the query instant falls outside the leaf's own
    /// validity interval. Distinct from `Lapsed`: nothing went wrong, the
    /// claim simply was not asserted for that date.
    OutsideValidity { from: u64, until: Option<u64> },
}

impl ClaimStatus {
    /// True only for `Effective`. Every other status means a counterparty must
    /// not rely on the claim at the queried instant.
    #[must_use]
    pub fn is_effective(&self) -> bool {
        matches!(self, ClaimStatus::Effective)
    }

    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            ClaimStatus::Effective => "effective",
            ClaimStatus::Lapsed { .. } => "lapsed",
            ClaimStatus::Void => "void_ab_initio",
            ClaimStatus::OutsideValidity { .. } => "outside_validity",
        }
    }
}

impl RevocationLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != REGISTRY_SCHEMA_VERSION {
            return Err(RegistryError::SchemaVersion {
                found: self.schema_version,
                expected: REGISTRY_SCHEMA_VERSION,
            });
        }
        for e in &self.entries {
            e.validate()?;
        }
        Ok(())
    }

    /// Status of one leaf at one instant.
    ///
    /// Voidance wins over everything: it is a statement that the claim was
    /// never true, so it cannot be outranked by a later lapse or by the query
    /// instant falling inside the validity window.
    #[must_use]
    pub fn status_at(
        &self,
        subject: &str,
        kyc_hash: &str,
        leaf_name: &str,
        validity: Option<&crate::claims::ValidityInterval>,
        at_epoch_days: u64,
    ) -> ClaimStatus {
        for e in &self.entries {
            if e.effect == RevocationEffect::VoidAbInitio
                && e.applies_to(subject, kyc_hash, leaf_name)
            {
                return ClaimStatus::Void;
            }
        }

        let lapse = self
            .entries
            .iter()
            .filter(|e| {
                e.effect == RevocationEffect::Lapsed
                    && e.applies_to(subject, kyc_hash, leaf_name)
                    && e.effective_from.is_some_and(|f| at_epoch_days >= f)
            })
            .filter_map(|e| e.effective_from)
            .min();
        if let Some(effective_from) = lapse {
            return ClaimStatus::Lapsed { effective_from };
        }

        if let Some(v) = validity {
            if !v.covers(at_epoch_days) {
                return ClaimStatus::OutsideValidity {
                    from: v.from,
                    until: v.until,
                };
            }
        }
        ClaimStatus::Effective
    }

    /// Every record touching a subject, for reporting.
    #[must_use]
    pub fn for_subject(&self, subject: &str, kyc_hash: &str) -> Vec<&RevocationRecord> {
        self.entries
            .iter()
            .filter(|e| {
                e.subject.eq_ignore_ascii_case(subject) && e.kyc_hash.eq_ignore_ascii_case(kyc_hash)
            })
            .collect()
    }
}

// ============================ signature helpers ============================

/// A registry document plus its detached signature.
#[derive(Debug, Clone)]
pub struct SignedDocument<T> {
    pub document: T,
    pub signature: Option<Vec<u8>>,
}

/// Verify a detached signature over a registry document's canonical bytes.
pub fn verify_document<T: Serialize>(
    document: &T,
    signature: Option<&[u8]>,
    public_key: &[u8; sign::PUBLIC_KEY_LEN],
) -> Result<(), RegistryError> {
    let bytes = canonical_document_bytes(document)
        .map_err(|e| RegistryError::Malformed(format!("canonical bytes: {}", e)))?;
    let Some(sig) = signature else {
        return Err(RegistryError::SignatureInvalid);
    };
    if sig.len() != sign::SIGNATURE_LEN {
        return Err(RegistryError::SignatureInvalid);
    }
    let mut arr = [0u8; sign::SIGNATURE_LEN];
    arr.copy_from_slice(sig);
    if sign::verify(public_key, &bytes, &arr) {
        Ok(())
    } else {
        Err(RegistryError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::ValidityInterval;

    fn version(n: u32, from: u64, until: Option<u64>, values: &[&str]) -> ListVersionRecord {
        let values: Vec<String> = values.iter().map(|s| s.to_string()).collect();
        ListVersionRecord {
            version: n,
            content_hash: list_content_hash(&values),
            values,
            root: format!("0x{:0>64}", n),
            depth: 2,
            source_sha256: format!("0x{:0>64}", n + 100),
            effective_from: from,
            effective_until: until,
            generator: "test".to_string(),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
            note: None,
        }
    }

    fn two_version_registry() -> ListRegistry {
        ListRegistry {
            schema_version: REGISTRY_SCHEMA_VERSION,
            list_id: "country_allowlist".to_string(),
            versions: vec![
                version(1, 20000, Some(20699), &["DEU", "FRA"]),
                version(2, 20700, None, &["DEU", "FRA", "ESP"]),
            ],
        }
    }

    #[test]
    fn resolves_the_version_authoritative_on_a_date() {
        let r = two_version_registry();
        assert_eq!(r.resolve_at(20500).unwrap().version, 1);
        assert_eq!(r.resolve_at(20699).unwrap().version, 1);
        assert_eq!(r.resolve_at(20700).unwrap().version, 2);
        assert_eq!(r.resolve_at(99999).unwrap().version, 2);
        assert!(r.resolve_at(19999).is_none());
    }

    #[test]
    fn resolves_a_version_from_its_root() {
        let r = two_version_registry();
        let v1_root = r.resolve_version(1).unwrap().root.clone();
        assert_eq!(r.resolve_root(&v1_root).unwrap().version, 1);
        assert_eq!(
            r.resolve_root(&v1_root.to_uppercase()).unwrap().version,
            1,
            "root lookup must be case-insensitive"
        );
        assert!(r.resolve_root("0xdeadbeef").is_none());
    }

    #[test]
    fn superseded_versions_keep_their_values() {
        let r = two_version_registry();
        assert_eq!(r.resolve_version(1).unwrap().values, vec!["DEU", "FRA"]);
        assert_eq!(
            r.resolve_version(2).unwrap().values,
            vec!["DEU", "FRA", "ESP"]
        );
    }

    #[test]
    fn validate_accepts_a_well_formed_registry() {
        assert_eq!(two_version_registry().validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_a_gap_in_version_numbers() {
        let mut r = two_version_registry();
        r.versions[1].version = 3;
        assert_eq!(
            r.validate(),
            Err(RegistryError::NonContiguousVersion {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn validate_rejects_overlapping_windows() {
        let mut r = two_version_registry();
        r.versions[1].effective_from = 20699;
        assert_eq!(
            r.validate(),
            Err(RegistryError::OverlappingRange { version: 2 })
        );
    }

    #[test]
    fn validate_rejects_a_superseded_version_left_open_ended() {
        let mut r = two_version_registry();
        r.versions[0].effective_until = None;
        assert_eq!(
            r.validate(),
            Err(RegistryError::OpenRangeNotLast { version: 1 })
        );
    }

    #[test]
    fn validate_rejects_values_that_do_not_match_their_content_hash() {
        let mut r = two_version_registry();
        r.versions[0].values.push("SMUGGLED".to_string());
        assert_eq!(
            r.validate(),
            Err(RegistryError::ContentHashMismatch { version: 1 })
        );
    }

    #[test]
    fn content_hash_ignores_ordering_only_when_values_actually_match() {
        let a = list_content_hash(&["DEU".to_string(), "FRA".to_string()]);
        let b = list_content_hash(&["FRA".to_string(), "DEU".to_string()]);
        assert_ne!(a, b, "order is part of the committed content");
        let c = list_content_hash(&["DEU".to_string(), "FRA".to_string()]);
        assert_eq!(a, c);
    }

    fn anchor(subject: &str, block: u64, ts: u64, root: &str) -> RootAnchor {
        RootAnchor {
            subject: subject.to_string(),
            kyc_hash: root.to_string(),
            epoch_days: ts / 86_400,
            chain_id: 1,
            block_height: block,
            block_timestamp: ts,
            tx_hash: None,
            manifest_sha256: format!("0x{}", "11".repeat(32)),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn history() -> RootHistory {
        RootHistory {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![
                anchor("0xAAA", 1000, 1_700_000_000, "0xaaaa"),
                anchor("0xAAA", 2000, 1_720_000_000, "0xbbbb"),
                anchor("0xBBB", 1500, 1_710_000_000, "0xcccc"),
            ],
        }
    }

    #[test]
    fn resolves_the_root_that_was_live_at_a_block() {
        let h = history();
        assert!(h.resolve_at_block("0xAAA", 1, 999).is_none());
        assert_eq!(
            h.resolve_at_block("0xAAA", 1, 1000).unwrap().kyc_hash,
            "0xaaaa"
        );
        assert_eq!(
            h.resolve_at_block("0xAAA", 1, 1999).unwrap().kyc_hash,
            "0xaaaa",
            "a block before the re-issue must resolve to the older root"
        );
        assert_eq!(
            h.resolve_at_block("0xAAA", 1, 5000).unwrap().kyc_hash,
            "0xbbbb"
        );
    }

    #[test]
    fn root_resolution_is_scoped_to_subject_and_chain() {
        let h = history();
        assert_eq!(
            h.resolve_at_block("0xBBB", 1, 5000).unwrap().kyc_hash,
            "0xcccc"
        );
        assert!(h.resolve_at_block("0xAAA", 137, 5000).is_none());
    }

    #[test]
    fn resolves_by_timestamp_as_well_as_height() {
        let h = history();
        assert_eq!(
            h.resolve_at_timestamp("0xAAA", 1, 1_710_000_000)
                .unwrap()
                .kyc_hash,
            "0xaaaa"
        );
        assert_eq!(
            h.resolve_at_timestamp("0xAAA", 1, 1_730_000_000)
                .unwrap()
                .kyc_hash,
            "0xbbbb"
        );
    }

    #[test]
    fn history_validate_rejects_two_anchors_at_one_height() {
        let mut h = history();
        h.entries
            .push(anchor("0xAAA", 1000, 1_700_000_001, "0xdddd"));
        assert!(matches!(
            h.validate(),
            Err(RegistryError::DuplicateAnchor { .. })
        ));
    }

    fn revocation(
        effect: RevocationEffect,
        effective_from: Option<u64>,
        leaf: Option<&str>,
    ) -> RevocationRecord {
        RevocationRecord {
            subject: "0xAAA".to_string(),
            kyc_hash: "0xroot".to_string(),
            leaf_name: leaf.map(|s| s.to_string()),
            effect,
            effective_from,
            declared_at: 21000,
            reason_code: "TEST".to_string(),
            note: None,
            issuer_key_id: "key-1".to_string(),
            recorded_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn validity() -> ValidityInterval {
        ValidityInterval {
            from: 20700,
            until: Some(21065),
            basis_as_of: 20690,
        }
    }

    #[test]
    fn a_lapse_leaves_everything_before_it_standing() {
        let log = RevocationLog {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![revocation(
                RevocationEffect::Lapsed,
                Some(20900),
                Some("investorType"),
            )],
        };
        let v = validity();
        assert!(log
            .status_at("0xAAA", "0xroot", "investorType", Some(&v), 20899)
            .is_effective());
        assert_eq!(
            log.status_at("0xAAA", "0xroot", "investorType", Some(&v), 20900),
            ClaimStatus::Lapsed {
                effective_from: 20900
            }
        );
    }

    #[test]
    fn a_voidance_reaches_back_before_its_own_declaration() {
        let log = RevocationLog {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![revocation(
                RevocationEffect::VoidAbInitio,
                None,
                Some("investorType"),
            )],
        };
        let v = validity();
        for at in [20700, 20800, 21065, 21100] {
            assert_eq!(
                log.status_at("0xAAA", "0xroot", "investorType", Some(&v), at),
                ClaimStatus::Void,
                "void_ab_initio must apply at every instant, including {}",
                at
            );
        }
    }

    #[test]
    fn voidance_outranks_a_later_lapse_on_the_same_leaf() {
        let log = RevocationLog {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![
                revocation(RevocationEffect::Lapsed, Some(20900), Some("investorType")),
                revocation(RevocationEffect::VoidAbInitio, None, Some("investorType")),
            ],
        };
        assert_eq!(
            log.status_at("0xAAA", "0xroot", "investorType", Some(&validity()), 20800),
            ClaimStatus::Void
        );
    }

    #[test]
    fn a_subject_wide_revocation_covers_every_leaf() {
        let log = RevocationLog {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![revocation(RevocationEffect::VoidAbInitio, None, None)],
        };
        for leaf in ["investorType", "dateOfBirth", "country"] {
            assert_eq!(
                log.status_at("0xAAA", "0xroot", leaf, Some(&validity()), 20800),
                ClaimStatus::Void
            );
        }
    }

    #[test]
    fn revocations_are_scoped_to_the_issuance_they_name() {
        let log = RevocationLog {
            schema_version: REGISTRY_SCHEMA_VERSION,
            entries: vec![revocation(RevocationEffect::VoidAbInitio, None, None)],
        };
        assert!(log
            .status_at(
                "0xAAA",
                "0xdifferentroot",
                "country",
                Some(&validity()),
                20800
            )
            .is_effective());
        assert!(log
            .status_at("0xBBB", "0xroot", "country", Some(&validity()), 20800)
            .is_effective());
    }

    #[test]
    fn outside_validity_is_not_the_same_answer_as_lapsed() {
        let log = RevocationLog::new();
        let v = validity();
        assert_eq!(
            log.status_at("0xAAA", "0xroot", "country", Some(&v), 21066),
            ClaimStatus::OutsideValidity {
                from: 20700,
                until: Some(21065)
            }
        );
        assert_eq!(
            log.status_at("0xAAA", "0xroot", "country", Some(&v), 20699),
            ClaimStatus::OutsideValidity {
                from: 20700,
                until: Some(21065)
            }
        );
    }

    #[test]
    fn revocation_validate_enforces_the_lapse_void_distinction() {
        assert_eq!(
            revocation(RevocationEffect::VoidAbInitio, Some(20900), None).validate(),
            Err(RegistryError::VoidWithEffectiveFrom)
        );
        assert_eq!(
            revocation(RevocationEffect::Lapsed, None, None).validate(),
            Err(RegistryError::LapseWithoutEffectiveFrom)
        );
        assert_eq!(
            revocation(RevocationEffect::Lapsed, Some(20900), None).validate(),
            Ok(())
        );
        assert_eq!(
            revocation(RevocationEffect::VoidAbInitio, None, None).validate(),
            Ok(())
        );
    }

    #[test]
    fn canonical_document_bytes_sort_keys() {
        let bytes = canonical_document_bytes(&two_version_registry()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.find("\"listId\"").unwrap() < text.find("\"schemaVersion\"").unwrap());
    }

    #[test]
    fn effect_wire_strings_are_stable() {
        assert_eq!(RevocationEffect::Lapsed.as_str(), "lapsed");
        assert_eq!(RevocationEffect::VoidAbInitio.as_str(), "void_ab_initio");
        assert_eq!(
            serde_json::to_string(&RevocationEffect::VoidAbInitio).unwrap(),
            "\"void_ab_initio\""
        );
    }
}
