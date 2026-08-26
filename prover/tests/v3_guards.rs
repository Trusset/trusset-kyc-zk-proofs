//! v3 prover guards: the refusals that keep an unusable bundle from being
//! written at all.
//!
//! Each of these is something v2 either permitted silently or did not express.
//! They are tested here rather than only through the CLI because the CLI is
//! not the only way a job reaches the prover — the issuer backend and the e2e
//! harness both construct one directly.

use std::collections::BTreeMap;
use trusset_bundle_format::claims::{
    ClaimDescriptor, EvidenceClass, LegalBasis, ListVersionRef, PartyRef, ValidityInterval,
};
use trusset_bundle_format::manifest::IssuerBlock;
use trusset_bundle_format::registry::list_content_hash;
use trusset_prover::{
    bundle::{build_subject_bundle, check_list_commitments, dry_run_subject},
    errors::ErrorCode,
    job::{Job, JobLeaf, JobSubject, ListCommitment},
    sign::SigningSecret,
};

const EPOCH: u64 = 20689;
const WALLET: &str = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01";

fn master_key() -> [u8; 32] {
    [7u8; 32]
}

fn signing() -> SigningSecret {
    SigningSecret::from_hex(&"42".repeat(32)).unwrap()
}

fn config_hash() -> [u8; 32] {
    [0xcd; 32]
}

fn hex32(bytes: [u8; 32]) -> String {
    let mut s = String::from("0x");
    for b in bytes.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn party() -> PartyRef {
    PartyRef {
        name: "Example Bank AG".into(),
        identifier_scheme: "LEI".into(),
        identifier: "529900T8BM49AURSDO55".into(),
        jurisdiction: "DE".into(),
    }
}

fn issuer() -> IssuerBlock {
    IssuerBlock {
        party: party(),
        public_key: hex32(signing().public_key()),
        key_id: "issuing-2026-08".into(),
    }
}

fn descriptor() -> ClaimDescriptor {
    ClaimDescriptor {
        legal_basis: LegalBasis {
            framework: "MiFID_II".into(),
            reference: "Annex II Section I".into(),
            assertion: "Subject is categorised at or above professional client".into(),
        },
        issuing_party: party(),
        evidence_class: EvidenceClass::Documentary,
        evidence_ref: None,
    }
}

fn validity() -> ValidityInterval {
    ValidityInterval {
        from: EPOCH,
        until: Some(EPOCH + 364),
        basis_as_of: EPOCH - 5,
    }
}

fn tier_leaf() -> JobLeaf {
    JobLeaf {
        field: "investorType".into(),
        circuit: "tier_threshold".into(),
        value: serde_json::json!("PROFESSIONAL"),
        public: serde_json::json!({"min_tier": 2u64}),
        params_hash: hex32(trusset_circuit_tier_threshold::Params { min_tier: 2 }.hash()),
        disclosure: None,
        params: Some(serde_json::json!({"minTier": 2u64})),
        descriptor: Some(descriptor()),
        validity: Some(validity()),
        list_version: None,
    }
}

fn job_with(leaves: Vec<JobLeaf>, output_root: &str) -> Job {
    Job {
        version: "3.0.0".into(),
        deterministic: true,
        epoch_days: EPOCH,
        output_root: output_root.into(),
        config_hash: hex32(config_hash()),
        skip_proofs: true,
        epoch_days_source: Some(format!("fixed:{}", EPOCH)),
        unpinned_epoch: false,
        issuer: Some(issuer()),
        dry_run: false,
        subjects: vec![JobSubject {
            subject_id: WALLET.into(),
            passthrough: serde_json::json!({}),
            leaves,
        }],
        list_commitments: BTreeMap::new(),
    }
}

fn build(job: &Job) -> trusset_prover::errors::Result<trusset_prover::bundle::BundleReport> {
    build_subject_bundle(
        job,
        &job.subjects[0],
        &master_key(),
        &signing(),
        &config_hash(),
        "2026-08-24T09:12:33Z",
    )
}

// =====================================================================
// Issuer
// =====================================================================

#[test]
fn a_v3_job_without_an_issuer_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = job_with(vec![tier_leaf()], tmp.path().to_str().unwrap());
    job.issuer = None;
    let err = job.validate().unwrap_err();
    assert_eq!(err.code, ErrorCode::IssuerMissing);
    assert!(err.message.contains("legally responsible"));
}

/// A dry run writes no manifest, so it has nothing to record an issuer into.
/// Requiring one would make the check an operator runs *before* finishing
/// configuration depend on the configuration being finished.
#[test]
fn a_dry_run_does_not_require_an_issuer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = job_with(vec![tier_leaf()], tmp.path().to_str().unwrap());
    job.issuer = None;
    job.dry_run = true;
    assert!(job.validate().is_ok());
}

#[test]
fn a_v2_job_still_needs_no_issuer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = job_with(vec![tier_leaf()], tmp.path().to_str().unwrap());
    job.version = "2.1.0".into();
    job.issuer = None;
    assert!(job.validate().is_ok());
}

// =====================================================================
// Descriptors and validity
// =====================================================================

#[test]
fn a_validity_interval_without_a_descriptor_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = tier_leaf();
    leaf.descriptor = None;
    let job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::DescriptorMissing);
    assert!(err.message.contains("investorType"), "{}", err.message);
}

#[test]
fn a_descriptor_without_a_validity_interval_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = tier_leaf();
    leaf.validity = None;
    let job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::ValidityInvalid);
}

#[test]
fn an_empty_legal_basis_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = tier_leaf();
    leaf.descriptor.as_mut().unwrap().legal_basis.assertion = "   ".into();
    let job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::DescriptorInvalid);
    assert!(err.message.contains("assertion"), "{}", err.message);
}

/// Evidence cannot post-date the window it supports, and a window cannot end
/// before it starts.
#[test]
fn a_malformed_validity_interval_is_refused() {
    let tmp = tempfile::tempdir().unwrap();

    let mut inverted = tier_leaf();
    inverted.validity = Some(ValidityInterval {
        from: EPOCH,
        until: Some(EPOCH - 1),
        basis_as_of: EPOCH,
    });
    let err = build(&job_with(vec![inverted], tmp.path().to_str().unwrap())).unwrap_err();
    assert_eq!(err.code, ErrorCode::ValidityInvalid);

    let mut future_evidence = tier_leaf();
    future_evidence.validity = Some(ValidityInterval {
        from: EPOCH,
        until: Some(EPOCH + 10),
        basis_as_of: EPOCH + 1,
    });
    let err = build(&job_with(
        vec![future_evidence],
        tmp.path().to_str().unwrap(),
    ))
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::ValidityInvalid);
    assert!(err.message.contains("post-date"), "{}", err.message);
}

// =====================================================================
// List versions
// =====================================================================

fn list_values() -> Vec<String> {
    ["DEU", "FRA", "USA", "GBR"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn set_leaf(version_ref: ListVersionRef) -> JobLeaf {
    JobLeaf {
        field: "nationality".into(),
        circuit: "set_membership".into(),
        value: serde_json::json!("GBR"),
        public: serde_json::json!({"list_id": "country_allowlist"}),
        params_hash: hex32(
            trusset_circuit_set_membership::Params {
                list_id: "country_allowlist".into(),
            }
            .hash(),
        ),
        disclosure: None,
        params: Some(serde_json::json!({"listId": "country_allowlist"})),
        descriptor: Some(descriptor()),
        validity: Some(validity()),
        list_version: Some(version_ref),
    }
}

fn job_with_list(version_ref: ListVersionRef, output_root: &str) -> Job {
    let mut job = job_with(vec![set_leaf(version_ref)], output_root);
    let values = list_values();
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    job.list_commitments.insert(
        "country_allowlist".into(),
        ListCommitment {
            values: list_values(),
            source_sha256: hex32([0xaa; 32]),
            declared_root: Some(trusset_circuits_common::digest_to_hex(&root)),
            declared_depth: Some(depth),
            version: Some(1),
            content_hash: Some(list_content_hash(&list_values())),
        },
    );
    job
}

fn correct_version_ref() -> ListVersionRef {
    let values = list_values();
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, _, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    ListVersionRef {
        list_id: "country_allowlist".into(),
        version: 1,
        root: trusset_circuits_common::digest_to_hex(&root),
        content_hash: list_content_hash(&list_values()),
    }
}

#[test]
fn a_correct_list_version_reference_proves() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_list(correct_version_ref(), tmp.path().to_str().unwrap());
    assert!(build(&job).is_ok());
}

/// A descriptor claiming one list version while the proof uses another would
/// let a bundle assert membership in a set it was never checked against.
#[test]
fn a_list_version_whose_root_disagrees_with_the_values_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut version_ref = correct_version_ref();
    version_ref.root = format!("0x{}", "ee".repeat(32));
    let job = job_with_list(version_ref, tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::ListVersionMismatch);
    assert!(err.message.contains("recompute"), "{}", err.message);
}

#[test]
fn a_list_version_whose_content_hash_disagrees_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let mut version_ref = correct_version_ref();
    version_ref.content_hash = format!("0x{}", "ee".repeat(32));
    let job = job_with_list(version_ref, tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::ListVersionMismatch);
}

#[test]
fn a_set_membership_leaf_with_a_descriptor_must_name_its_list_version() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = set_leaf(correct_version_ref());
    leaf.list_version = None;
    let mut job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    let values = list_values();
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    job.list_commitments.insert(
        "country_allowlist".into(),
        ListCommitment {
            values: list_values(),
            source_sha256: hex32([0xaa; 32]),
            declared_root: Some(trusset_circuits_common::digest_to_hex(&root)),
            declared_depth: Some(depth),
            version: Some(1),
            content_hash: Some(list_content_hash(&list_values())),
        },
    );
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::DescriptorMissing);
    assert!(err.message.contains("list version"), "{}", err.message);
}

/// A stale registry is a property of the batch, not of one subject, so it is
/// caught once before any subject is processed.
#[test]
fn a_batch_level_content_hash_mismatch_is_caught_before_any_subject() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = job_with_list(correct_version_ref(), tmp.path().to_str().unwrap());
    job.list_commitments
        .get_mut("country_allowlist")
        .unwrap()
        .content_hash = Some(format!("0x{}", "ee".repeat(32)));
    let err = check_list_commitments(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::ListVersionMismatch);
}

// =====================================================================
// Failure reporting
// =====================================================================

/// Prover failures must name the leaf. On a subject with three
/// `set_membership` leaves, "not in list" without a leaf name is unactionable.
#[test]
fn a_failure_names_the_leaf_it_came_from() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = tier_leaf();
    leaf.value = serde_json::json!("RETAIL");
    let job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::TierBelowMin);
    assert!(
        err.message
            .starts_with("leaf \"investorType\" (tier_threshold):"),
        "{}",
        err.message
    );
}

/// Failure messages reach `output/failures.csv`, which travels. The asserted
/// threshold is public — it is in the manifest — but the subject's own value
/// is exactly what the predicate exists to keep private.
#[test]
fn a_failure_does_not_echo_the_subjects_value() {
    let tmp = tempfile::tempdir().unwrap();
    let mut version_ref = correct_version_ref();
    version_ref.version = 1;
    let mut job = job_with_list(version_ref, tmp.path().to_str().unwrap());
    job.subjects[0].leaves[0].value = serde_json::json!("BRA");
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::ListMemberMissing);
    assert!(
        !err.message.contains("BRA"),
        "the failing value leaked into the message: {}",
        err.message
    );
    assert!(err.message.contains("country_allowlist"));
    assert!(err.message.contains("nationality"));
}

// =====================================================================
// Dry run
// =====================================================================

/// A dry run reports every problem on a subject, not just the first. Stopping
/// at the first turns one review pass into as many passes as there are broken
/// leaves.
#[test]
fn a_dry_run_reports_every_failing_leaf_on_a_subject() {
    let tmp = tempfile::tempdir().unwrap();
    let mut under_age = JobLeaf {
        field: "dateOfBirth".into(),
        circuit: "age_threshold".into(),
        value: serde_json::json!("2015-06-01"),
        public: serde_json::json!({"min_age_days": 6570u64}),
        params_hash: hex32(trusset_circuit_age_threshold::Params { min_age_days: 6570 }.hash()),
        disclosure: None,
        params: Some(serde_json::json!({"minAgeDays": 6570u64})),
        descriptor: Some(descriptor()),
        validity: Some(validity()),
        list_version: None,
    };
    let mut also_under_age = under_age.clone();
    also_under_age.field = "dateOfBirth@7665d".into();
    also_under_age.public = serde_json::json!({"min_age_days": 7665u64});
    also_under_age.params_hash =
        hex32(trusset_circuit_age_threshold::Params { min_age_days: 7665 }.hash());

    let mut below_tier = tier_leaf();
    below_tier.value = serde_json::json!("RETAIL");

    under_age.disclosure = None;
    let job = job_with(
        vec![under_age, also_under_age, below_tier],
        tmp.path().to_str().unwrap(),
    );

    let problems = dry_run_subject(&job, &job.subjects[0]);
    assert_eq!(
        problems.len(),
        3,
        "expected one problem per failing leaf, got {:?}",
        problems.iter().map(|p| &p.message).collect::<Vec<_>>()
    );
    let leaves: Vec<&str> = problems.iter().filter_map(|p| p.leaf.as_deref()).collect();
    assert!(leaves.contains(&"dateOfBirth"));
    assert!(leaves.contains(&"dateOfBirth@7665d"));
    assert!(leaves.contains(&"investorType"));
}

#[test]
fn a_dry_run_on_a_clean_subject_reports_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_list(correct_version_ref(), tmp.path().to_str().unwrap());
    assert!(dry_run_subject(&job, &job.subjects[0]).is_empty());
}

// =====================================================================
// Stub mode
// =====================================================================

/// `--skip-proofs` skips proving but still enforces predicates. Before v3 it
/// ran the full STARK and discarded the bytes, so it cost the same as a real
/// run; the fix must not have turned it into a mode that accepts anything.
#[test]
fn stub_mode_still_enforces_predicates() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaf = tier_leaf();
    leaf.value = serde_json::json!("RETAIL");
    let mut job = job_with(vec![leaf], tmp.path().to_str().unwrap());
    job.skip_proofs = true;
    let err = build(&job).unwrap_err();
    assert_eq!(err.code, ErrorCode::TierBelowMin);
}

#[test]
fn stub_mode_emits_zero_byte_proofs() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = job_with(vec![tier_leaf()], tmp.path().to_str().unwrap());
    job.skip_proofs = true;
    let report = build(&job).unwrap();
    let proof = report.bundle_path.join("proofs").join("investorType.bin");
    assert_eq!(std::fs::metadata(proof).unwrap().len(), 0);
}
