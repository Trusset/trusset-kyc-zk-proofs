//! Job spec: the JSON read from stdin (plan §"TS ↔ Rust Integration").

use crate::errors::{ErrorCode, ProverError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trusset_bundle_format::claims::{ClaimDescriptor, ListVersionRef, ValidityInterval};
use trusset_bundle_format::header::parse_address;
use trusset_bundle_format::manifest::{is_v31, is_v3_family, ChainBinding, IssuerBlock};
use trusset_bundle_format::predicates::{is_leaf_predicate, INVESTOR_CLASS};

/// The passthrough keys a 3.1.0 subject may carry. Both are settings, not
/// personal values.
pub const V31_PASSTHROUGH_KEYS: [&str; 2] = ["softExpiryDays", "hardExpiryDays"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub version: String,
    #[serde(default = "default_deterministic")]
    pub deterministic: bool,
    pub epoch_days: u64,
    pub output_root: String,
    /// 0x-prefixed 64-char hex of SHA-256 over canonical config. Folded into
    /// the per-subject seed derivation so two different configs never produce
    /// the same bundle bytes.
    pub config_hash: String,
    /// When true, emit zero-byte proof files and skip per-circuit `prove()`.
    /// Manifest mode stays `"stub"`; the verifier rejects these in strict
    /// mode (plan §"Resolved edge cases" item 3).
    ///
    /// Use case: CI smoke runs or iteration speed during Phase 2B AIR work.
    /// In Phase 2A this flag is largely cosmetic — the prover already emits
    /// stub proofs — but it lets us shave the per-leaf hash cost.
    #[serde(default)]
    pub skip_proofs: bool,
    pub subjects: Vec<JobSubject>,
    #[serde(default)]
    pub list_commitments: BTreeMap<String, ListCommitment>,
    /// v3: the expression that produced `epoch_days`, recorded verbatim in the
    /// manifest so a reader knows how the as-of date was chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_days_source: Option<String>,
    /// v3: set when the operator ran with an unpinned wall-clock epoch behind
    /// the development flag. Stamped into the manifest so such a bundle is
    /// identifiable as non-reproducible for the rest of its life.
    #[serde(default)]
    pub unpinned_epoch: bool,
    /// v3: the party legally responsible for the assertions. Required for
    /// manifest version 3.0.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerBlock>,
    /// v3: validate every leaf of every subject and report all failures
    /// without writing any bundle.
    #[serde(default)]
    pub dry_run: bool,
    /// v3.1: the attester, chain, hub, and hub key id the bundles are issued
    /// under. Required for a 3.1.0 job that writes bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainBinding>,
}

fn default_deterministic() -> bool {
    true
}

/// A `Job` with every optional field at its wire default. Exists so callers
/// constructing a job in code — tests, and the archive round-trip harness —
/// name only the fields they care about, and so adding a field to the wire
/// schema does not mechanically break every construction site.
impl Default for Job {
    fn default() -> Self {
        Self {
            version: trusset_bundle_format::manifest::MANIFEST_VERSION.to_string(),
            deterministic: true,
            epoch_days: 0,
            output_root: String::new(),
            config_hash: String::new(),
            skip_proofs: false,
            subjects: Vec::new(),
            list_commitments: BTreeMap::new(),
            epoch_days_source: None,
            unpinned_epoch: false,
            issuer: None,
            dry_run: false,
            chain: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSubject {
    /// EIP-55 wallet address (0x-prefixed, 42 chars).
    pub subject_id: String,
    /// Verbatim passthrough block written into `manifest.passthrough`.
    #[serde(default)]
    pub passthrough: serde_json::Value,
    pub leaves: Vec<JobLeaf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobLeaf {
    pub field: String,
    pub circuit: String,
    /// Witness value. JSON-typed so the prover can accept string, number, or
    /// date forms depending on the circuit (see `dispatch::prove_leaf`).
    pub value: serde_json::Value,
    /// Circuit-specific parameters relevant to public inputs
    /// (e.g. `min_age_days`, `min_tier`, `list_id`). Schema enforced per
    /// circuit at dispatch time.
    #[serde(default)]
    pub public: serde_json::Value,
    /// 0x-prefixed 64-char hex of SHA-256 over canonical params.
    pub params_hash: String,
    /// v2.1 per-leaf disclosure class (`plaintext` | `predicate` |
    /// `commitment_only`). Absent falls back to a per-circuit default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<String>,
    /// v2.1 resolved public parameter values recorded in
    /// `manifest.leaves[].params`. Absent falls back to a value derived
    /// from `public` / the circuit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// v3 claim descriptor: legal basis, warranting party, evidence class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<ClaimDescriptor>,
    /// v3 validity interval for this leaf's assertion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<ValidityInterval>,
    /// v3 list-version reference, for `set_membership` leaves. The prover
    /// cross-checks `root` against its own recomputation from the values it
    /// was given, so a descriptor pointing at the wrong version fails the run
    /// rather than being recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<ListVersionRef>,
    /// v3.1 predicate this leaf proves, from the hub's predicate table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListCommitment {
    /// Raw allowlist values, NFC-normalized strings. The prover recomputes
    /// the Rescue Merkle root from these.
    pub values: Vec<String>,
    /// SHA-256 of the source file (for `manifest.lists`).
    #[serde(default)]
    pub source_sha256: String,
    /// Root declared by the committed list-commitment file. The CLI cannot
    /// recompute a Rescue root, so the prover cross-checks this against its
    /// own recomputation and refuses to proceed on a mismatch - a stale
    /// committed file would otherwise be silently ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_root: Option<String>,
    /// Depth declared by the same file, cross-checked alongside the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_depth: Option<u8>,
    /// v3 registry version this list resolved to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// v3 SHA-256 over the canonical values, cross-checked by the prover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

impl Job {
    pub fn parse_from_slice(bytes: &[u8]) -> Result<Self> {
        let job: Job = serde_json::from_slice(bytes)?;
        job.validate()?;
        Ok(job)
    }

    pub fn validate(&self) -> Result<()> {
        if !trusset_bundle_format::manifest::ACCEPTED_JOB_VERSIONS.contains(&self.version.as_str())
        {
            return Err(ProverError::input(format!(
                "unsupported job version: {} (this build accepts {})",
                self.version,
                trusset_bundle_format::manifest::ACCEPTED_JOB_VERSIONS.join(", ")
            )));
        }
        // A dry run writes no manifest, so it has nothing to record an issuer
        // into. Requiring one here would make the check an operator runs
        // before they have finished configuring depend on the configuration
        // being finished.
        if is_v3_family(&self.version) && self.issuer.is_none() && !self.dry_run {
            return Err(ProverError::new(
                ErrorCode::IssuerMissing,
                format!(
                    "a version {} job requires an issuer block: the bundle records who is legally \
                     responsible for its assertions. Run `npm run init` to configure \
                     `manifest.issuer` in config.json.",
                    self.version
                ),
            ));
        }
        if is_v31(&self.version) {
            match self.chain.as_ref() {
                Some(c) => validate_chain(c)?,
                None if self.dry_run => {}
                None => {
                    return Err(ProverError::new(
                        ErrorCode::ChainInvalid,
                        "a version 3.1.0 job requires a chain block (attester, chainId, hub, \
                         keyId): every bundle is bound to one on-chain attestation. Set `chain` \
                         in config.json.",
                    ))
                }
            }
        }
        if self.subjects.is_empty() {
            return Err(ProverError::input("job has no subjects"));
        }
        validate_hex32("config_hash", &self.config_hash)?;
        for (i, s) in self.subjects.iter().enumerate() {
            s.validate().map_err(|e| {
                ProverError::input(format!("subject[{}] ({}): {}", i, s.subject_id, e.message))
            })?;
            if is_v31(&self.version) {
                s.validate_v31().map_err(|e| {
                    ProverError::new(
                        e.code,
                        format!("subject[{}] ({}): {}", i, s.subject_id, e.message),
                    )
                })?;
            }
        }
        Ok(())
    }
}

/// A chain block must name a real attester and hub on a real chain, under a
/// key id the hub can have assigned.
pub fn validate_chain(c: &ChainBinding) -> Result<()> {
    let bad = |what: &str| ProverError::new(ErrorCode::ChainInvalid, format!("chain.{}", what));
    for (name, value) in [("attester", &c.attester), ("hub", &c.hub)] {
        match parse_address(value) {
            Some(a) if a != [0u8; 20] => {}
            Some(_) => return Err(bad(&format!("{} is the zero address", name))),
            None => return Err(bad(&format!("{} is not 0x + 40 hex", name))),
        }
    }
    if c.chain_id == 0 {
        return Err(bad("chainId must be positive"));
    }
    if c.key_id == 0 {
        return Err(bad(
            "keyId must be at least 1: the hub numbers an attester's operator keys from 1",
        ));
    }
    Ok(())
}

impl JobSubject {
    pub fn validate(&self) -> Result<()> {
        if !is_eip55_like(&self.subject_id) {
            return Err(ProverError::input(format!(
                "subject_id is not a 0x-prefixed 40-hex address: {}",
                self.subject_id
            )));
        }
        if self.leaves.is_empty() {
            return Err(ProverError::input("subject has no leaves"));
        }
        for (i, l) in self.leaves.iter().enumerate() {
            l.validate().map_err(|e| {
                ProverError::input(format!("leaf[{}] ({}): {}", i, l.field, e.message))
            })?;
        }
        Ok(())
    }

    /// The 3.1.0 rules: no personal value in clear text, every leaf bound to a
    /// descriptor, known predicates only, and exactly one leaf behind the
    /// investor class.
    pub fn validate_v31(&self) -> Result<()> {
        match &self.passthrough {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    if !V31_PASSTHROUGH_KEYS.contains(&k.as_str()) {
                        return Err(ProverError::new(
                            ErrorCode::PassthroughRefused,
                            format!(
                                "passthrough.{} is not allowed in a 3.1.0 bundle: only {} may \
                                 travel in clear text. Prove the value as a leaf instead.",
                                k,
                                V31_PASSTHROUGH_KEYS.join(" and ")
                            ),
                        ));
                    }
                    if v.as_u64().is_none() {
                        return Err(ProverError::new(
                            ErrorCode::PassthroughRefused,
                            format!("passthrough.{} must be a whole number of days", k),
                        ));
                    }
                }
            }
            serde_json::Value::Null => {}
            _ => {
                return Err(ProverError::new(
                    ErrorCode::PassthroughRefused,
                    "passthrough must be an object",
                ))
            }
        }
        let mut class_leaves = 0usize;
        for l in &self.leaves {
            if l.descriptor.is_none() || l.validity.is_none() {
                return Err(ProverError::new(
                    ErrorCode::DescriptorMissing,
                    format!(
                        "leaf {} has no claim descriptor and validity; every 3.1.0 leaf carries both",
                        l.field
                    ),
                ));
            }
            if let Some(p) = l.predicate.as_deref() {
                if !is_leaf_predicate(p) {
                    return Err(ProverError::new(
                        ErrorCode::PredicateInvalid,
                        format!(
                            "leaf {} names predicate {}, which no leaf may claim",
                            l.field, p
                        ),
                    ));
                }
                if p == INVESTOR_CLASS {
                    class_leaves += 1;
                }
            }
        }
        if class_leaves != 1 {
            return Err(ProverError::new(
                ErrorCode::PredicateInvalid,
                format!(
                    "a 3.1.0 subject needs exactly one INVESTOR_CLASS leaf (a tier_threshold leaf \
                     whose minTier is the attested class), found {}",
                    class_leaves
                ),
            ));
        }
        Ok(())
    }

    /// 20-byte raw form of the wallet address, used in leaf hash bindings.
    pub fn wallet_bytes(&self) -> Result<[u8; 20]> {
        let hex_part = self.subject_id.trim_start_matches("0x");
        let decoded = hex::decode(hex_part.to_ascii_lowercase()).map_err(|_| {
            ProverError::input(format!("subject_id is not hex: {}", self.subject_id))
        })?;
        if decoded.len() != 20 {
            return Err(ProverError::input(format!(
                "subject_id must decode to 20 bytes, got {}",
                decoded.len()
            )));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&decoded);
        Ok(out)
    }
}

impl JobLeaf {
    pub fn validate(&self) -> Result<()> {
        if self.field.is_empty() {
            return Err(ProverError::input("field name empty"));
        }
        // params_hash is validated for shape here; circuit-specific checks
        // happen in dispatch.
        validate_hex32("params_hash", &self.params_hash)?;
        Ok(())
    }

    pub fn params_hash_bytes(&self) -> Result<[u8; 32]> {
        let h = self.params_hash.trim_start_matches("0x");
        let v = hex::decode(h).map_err(|_| {
            ProverError::input(format!("params_hash not hex: {}", self.params_hash))
        })?;
        if v.len() != 32 {
            return Err(ProverError::input("params_hash must be 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

fn is_eip55_like(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_hex32(field: &str, hex: &str) -> Result<()> {
    let h = hex.trim_start_matches("0x");
    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ProverError::new(
            ErrorCode::Input,
            format!("{} must be 0x-prefixed 64-char hex", field),
        ));
    }
    Ok(())
}

pub fn parse_config_hash(hex: &str) -> Result<[u8; 32]> {
    let h = hex.trim_start_matches("0x");
    let v = hex::decode(h).map_err(|_| ProverError::input("config_hash not hex"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_job_json() -> &'static str {
        r#"{
            "version": "2.0.0",
            "epoch_days": 20587,
            "output_root": "/tmp/out",
            "config_hash": "0xababababababababababababababababababababababababababababababab",
            "subjects": [
                {
                    "subject_id": "0x0000000000000000000000000000000000000001",
                    "leaves": [
                        {
                            "field": "firstName",
                            "circuit": "preimage_knowledge",
                            "value": "Alice",
                            "params_hash": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                        }
                    ]
                }
            ]
        }"#
    }

    fn pad_hex(short: &str, len: usize) -> String {
        let h = short.trim_start_matches("0x");
        let padded = format!("{:0>1$}", h, len);
        format!("0x{}", padded)
    }

    #[test]
    fn parses_minimal_job() {
        // The literal in `minimal_job_json` happens to be 62 hex chars
        // (handy for readability). Replace with a properly-padded version.
        let json = minimal_job_json().replace(
            "0xababababababababababababababababababababababababababababababab",
            &pad_hex("ab", 64),
        );
        let job = Job::parse_from_slice(json.as_bytes()).unwrap();
        assert_eq!(job.version, "2.0.0");
        assert_eq!(job.subjects.len(), 1);
        assert!(job.deterministic, "deterministic defaults to true");
    }

    #[test]
    fn rejects_unsupported_version() {
        let bad = r#"{
            "version": "1.0.0",
            "epoch_days": 0,
            "output_root": "/tmp",
            "config_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "subjects": [{"subject_id": "0x0000000000000000000000000000000000000001",
                          "leaves": [{"field": "f", "circuit": "preimage_knowledge", "value": "x",
                                      "params_hash": "0x0000000000000000000000000000000000000000000000000000000000000000"}]}]
        }"#;
        let err = Job::parse_from_slice(bad.as_bytes()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Input);
    }

    #[test]
    fn rejects_empty_subjects() {
        let bad = r#"{
            "version": "2.0.0",
            "epoch_days": 0,
            "output_root": "/tmp",
            "config_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "subjects": []
        }"#;
        let err = Job::parse_from_slice(bad.as_bytes()).unwrap_err();
        assert_eq!(err.code, ErrorCode::Input);
        assert!(err.message.contains("no subjects"));
    }

    #[test]
    fn rejects_malformed_wallet() {
        let bad = r#"{
            "version": "2.0.0",
            "epoch_days": 0,
            "output_root": "/tmp",
            "config_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "subjects": [{"subject_id": "not-an-address",
                          "leaves": [{"field": "f", "circuit": "preimage_knowledge", "value": "x",
                                      "params_hash": "0x0000000000000000000000000000000000000000000000000000000000000000"}]}]
        }"#;
        let err = Job::parse_from_slice(bad.as_bytes()).unwrap_err();
        assert!(err.message.contains("not a 0x-prefixed 40-hex address"));
    }

    #[test]
    fn wallet_bytes_decodes_to_20() {
        let s = JobSubject {
            subject_id: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
            passthrough: serde_json::Value::Null,
            leaves: vec![],
        };
        let bytes = s.wallet_bytes().unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0xab);
        assert_eq!(bytes[19], 0x01);
    }

    /// Pin every JSON field name on the Job / JobSubject / JobLeaf /
    /// ListCommitment wire schema. These are consumed by the TS CLI on
    /// the stdin side ([cli/src/jobSpec.ts](../../cli/src/jobSpec.ts)
    /// `JobLeaf` / `JobSubject` / `Job` interfaces).
    ///
    /// **Why this test is load-bearing**: the TS CLI builds the Job JSON
    /// independently from these interfaces. There is no shared schema —
    /// drift is silent.
    ///
    /// Failure of this test means: an engineer renamed a Job-related
    /// field in `job.rs` without updating `cli/src/jobSpec.ts`. To fix:
    /// either revert the Rust rename or apply the matching rename to
    /// the TS interface declarations AND every TS call site building a
    /// Job (look for `cli/src/buildJob.ts`).
    #[test]
    fn job_json_field_names_are_pinned() {
        let job = Job {
            version: "2.0.0".to_string(),
            deterministic: true,
            epoch_days: 20587,
            output_root: "/tmp/out".to_string(),
            config_hash: "0x".to_string() + &"a".repeat(64),
            skip_proofs: false,
            epoch_days_source: Some("fixed:20587".to_string()),
            unpinned_epoch: false,
            issuer: None,
            dry_run: false,
            chain: None,
            subjects: vec![JobSubject {
                subject_id: "0x0000000000000000000000000000000000000001".to_string(),
                passthrough: serde_json::json!({"k": "v"}),
                leaves: vec![JobLeaf {
                    field: "firstName".to_string(),
                    circuit: "preimage_knowledge".to_string(),
                    value: serde_json::json!("Alice"),
                    public: serde_json::json!({}),
                    params_hash: "0x".to_string() + &"c".repeat(64),
                    disclosure: None,
                    params: None,
                    descriptor: None,
                    validity: None,
                    list_version: None,
                    predicate: None,
                }],
            }],
            list_commitments: BTreeMap::from([(
                "country_allowlist".to_string(),
                ListCommitment {
                    values: vec!["DEU".to_string()],
                    source_sha256: "0x".to_string() + &"d".repeat(64),
                    declared_root: None,
                    declared_depth: None,
                    version: None,
                    content_hash: None,
                },
            )]),
        };

        let json = serde_json::to_value(&job).unwrap();
        let obj = json.as_object().unwrap();

        let expected_job_fields = [
            "version",
            "deterministic",
            "epoch_days",
            "output_root",
            "config_hash",
            "skip_proofs",
            "subjects",
            "list_commitments",
            // v3. `epoch_days_source` and `dry_run`/`unpinned_epoch` are
            // always present on the wire; `issuer` is optional-with-omission
            // and absent here.
            "epoch_days_source",
            "unpinned_epoch",
            "dry_run",
        ];
        for name in &expected_job_fields {
            assert!(
                obj.contains_key(*name),
                "Job JSON is missing wire field {:?} (cli/src/jobSpec.ts expects this)",
                name
            );
        }
        assert_eq!(
            obj.len(),
            expected_job_fields.len(),
            "Job has {} JSON fields but {} are pinned. \
             Add the new field to cli/src/jobSpec.ts:Job AND to expected_job_fields here.",
            obj.len(),
            expected_job_fields.len()
        );

        // JobSubject
        let subject = obj["subjects"].as_array().unwrap()[0].as_object().unwrap();
        let expected_subject_fields = ["subject_id", "passthrough", "leaves"];
        for name in &expected_subject_fields {
            assert!(
                subject.contains_key(*name),
                "JobSubject JSON is missing field {:?}",
                name
            );
        }
        assert_eq!(subject.len(), expected_subject_fields.len());

        // JobLeaf. `disclosure` and `params` are optional-with-omission,
        // so they are absent here (both None); the pinned required set is
        // the five always-present fields.
        let leaf = subject["leaves"].as_array().unwrap()[0]
            .as_object()
            .unwrap();
        let expected_leaf_fields = ["field", "circuit", "value", "public", "params_hash"];
        for name in &expected_leaf_fields {
            assert!(
                leaf.contains_key(*name),
                "JobLeaf JSON is missing field {:?}",
                name
            );
        }
        assert_eq!(leaf.len(), expected_leaf_fields.len());

        // ListCommitment
        let lc = obj["list_commitments"].as_object().unwrap()["country_allowlist"]
            .as_object()
            .unwrap();
        let expected_lc_fields = ["values", "source_sha256"];
        for name in &expected_lc_fields {
            assert!(
                lc.contains_key(*name),
                "ListCommitment JSON is missing field {:?}",
                name
            );
        }
        assert_eq!(lc.len(), expected_lc_fields.len());
    }
}
