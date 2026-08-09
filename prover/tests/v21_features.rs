//! v2.1 feature tests: wrapped per-subject keys and the re-key path,
//! `commitment_only` leaves, multi-instance predicates over one field, and
//! the entropy guard.
//!
//! These cover the behavior added in the v2.1 remediation pass that the
//! pre-existing `end_to_end.rs` does not reach.

use std::collections::BTreeMap;
use trusset_bundle_format::manifest::{
    Manifest, DISCLOSURE_COMMITMENT_ONLY, DISCLOSURE_PLAINTEXT, DISCLOSURE_PREDICATE,
    SECRETS_KDF_VERSION,
};
use trusset_bundle_format::merkle::MERKLE_VERSION_V2;
use trusset_prover::{
    bundle::build_subject_bundle,
    encrypt::decrypt_secrets,
    entropy::{fill_random_guarded, DETERMINISM_ENV},
    errors::ErrorCode,
    job::{Job, JobLeaf, JobSubject},
    rekey::rekey_bundle,
    sign::SigningSecret,
};

fn master_key() -> [u8; 32] {
    let mut m = [0u8; 32];
    for (i, b) in m.iter_mut().enumerate() {
        *b = i as u8;
    }
    m
}

fn signing_key_hex() -> &'static str {
    "4242424242424242424242424242424242424242424242424242424242424242"
}

fn config_hash() -> [u8; 32] {
    [0xcd; 32]
}

fn now_iso() -> &'static str {
    "2026-05-14T09:12:33Z"
}

fn hex32(bytes: [u8; 32]) -> String {
    let mut s = String::from("0x");
    for b in bytes.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn age_params_hash(min_age_days: u64) -> String {
    hex32(trusset_circuit_age_threshold::Params { min_age_days }.hash())
}

fn preimage_params_hash(max_value_bytes: usize) -> String {
    hex32(trusset_circuit_preimage_knowledge::Params { max_value_bytes }.hash())
}

fn wallet() -> &'static str {
    "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
}

/// One age leaf plus one commitment-only leaf: enough for a valid bundle
/// while keeping prove time low.
fn base_leaves() -> Vec<JobLeaf> {
    vec![
        JobLeaf {
            field: "dateOfBirth".into(),
            circuit: "age_threshold".into(),
            value: serde_json::json!("1985-04-12"),
            public: serde_json::json!({"min_age_days": 6570u64}),
            params_hash: age_params_hash(6570),
            disclosure: Some(DISCLOSURE_PREDICATE.to_string()),
            params: Some(serde_json::json!({"minAgeDays": 6570u64})),
        },
        JobLeaf {
            field: "firstName".into(),
            circuit: "preimage_knowledge".into(),
            value: serde_json::json!("Alice"),
            public: serde_json::json!({}),
            params_hash: preimage_params_hash(128),
            disclosure: Some(DISCLOSURE_COMMITMENT_ONLY.to_string()),
            params: Some(serde_json::json!({"maxValueBytes": 128u64})),
        },
    ]
}

fn job_with_leaves(output_root: &str, leaves: Vec<JobLeaf>, deterministic: bool) -> Job {
    Job {
        version: "2.1.0".into(),
        deterministic,
        epoch_days: 20587,
        output_root: output_root.to_string(),
        config_hash: hex32(config_hash()),
        skip_proofs: false,
        subjects: vec![JobSubject {
            subject_id: wallet().to_string(),
            passthrough: serde_json::json!({"country": "DEU"}),
            leaves,
        }],
        list_commitments: BTreeMap::new(),
    }
}

fn build(job: &Job) -> trusset_prover::bundle::BundleReport {
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    build_subject_bundle(
        job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap()
}

fn read_manifest(dir: &std::path::Path) -> Manifest {
    let bytes = std::fs::read(dir.join("manifest.json")).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// =====================================================================
// commitment_only leaves
// =====================================================================

#[test]
fn commitment_only_leaf_writes_zero_length_sentinel_and_joins_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_leaves(tmp.path().to_str().unwrap(), base_leaves(), true);
    let report = build(&job);
    let manifest = read_manifest(&report.bundle_path);

    let leaf = manifest
        .leaves
        .iter()
        .find(|l| l.field_name == "firstName")
        .expect("commitment_only leaf present");
    assert_eq!(
        leaf.disclosure.as_deref(),
        Some(DISCLOSURE_COMMITMENT_ONLY),
        "commitment_only leaves must be labeled"
    );
    // The circuit identity stays preimage_knowledge so consumers that
    // validate circuit names against a fixed set still accept the bundle.
    assert_eq!(leaf.circuit, "preimage_knowledge");
    assert_eq!(leaf.circuit_id, 4);

    let proof = std::fs::read(report.bundle_path.join(&leaf.proof_path)).unwrap();
    assert!(
        proof.is_empty(),
        "commitment_only proof must be a zero-length sentinel, got {} bytes",
        proof.len()
    );

    // The leaf still participates in the Merkle root exactly like any other.
    assert_eq!(manifest.leaves.len(), 2);
    assert!(manifest
        .leaves
        .iter()
        .any(|l| l.field_name == "firstName" && !l.leaf_hash.is_empty()));
}

#[test]
fn commitment_only_commitment_differs_per_subject_key() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let job_a = job_with_leaves(tmp_a.path().to_str().unwrap(), base_leaves(), true);
    let mut job_b = job_with_leaves(tmp_b.path().to_str().unwrap(), base_leaves(), true);
    job_b.subjects[0].subject_id = "0x00000000000000000000000000000000000000ff".to_string();

    let a = read_manifest(&build(&job_a).bundle_path);
    let b = read_manifest(&build(&job_b).bundle_path);
    let ca = &a
        .leaves
        .iter()
        .find(|l| l.field_name == "firstName")
        .unwrap()
        .commitment;
    let cb = &b
        .leaves
        .iter()
        .find(|l| l.field_name == "firstName")
        .unwrap()
        .commitment;
    assert_ne!(
        ca, cb,
        "same value under different subjects must not share a commitment"
    );
}

// =====================================================================
// Manifest schema additions
// =====================================================================

#[test]
fn manifest_records_v21_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_leaves(tmp.path().to_str().unwrap(), base_leaves(), true);
    let manifest = read_manifest(&build(&job).bundle_path);

    assert_eq!(manifest.version, "2.1.0");
    assert_eq!(manifest.merkle_version, Some(MERKLE_VERSION_V2));
    assert_eq!(manifest.secrets_kdf_version, SECRETS_KDF_VERSION);
    assert_eq!(
        manifest.config_hash.as_deref(),
        Some(hex32(config_hash()).as_str())
    );
    for leaf in &manifest.leaves {
        assert!(
            leaf.disclosure.is_some(),
            "{} has no disclosure",
            leaf.field_name
        );
        assert!(leaf.params.is_some(), "{} has no params", leaf.field_name);
    }
}

#[test]
fn plaintext_disclosure_is_carried_through_to_the_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaves = base_leaves();
    leaves[0].disclosure = Some(DISCLOSURE_PLAINTEXT.to_string());
    let job = job_with_leaves(tmp.path().to_str().unwrap(), leaves, true);
    let manifest = read_manifest(&build(&job).bundle_path);
    let leaf = manifest
        .leaves
        .iter()
        .find(|l| l.field_name == "dateOfBirth")
        .unwrap();
    assert_eq!(leaf.disclosure.as_deref(), Some(DISCLOSURE_PLAINTEXT));
}

// =====================================================================
// Multi-instance predicates over one field
// =====================================================================

#[test]
fn two_age_thresholds_over_one_field_produce_two_distinct_leaves() {
    let tmp = tempfile::tempdir().unwrap();
    let mut leaves = base_leaves();
    // A second age instance at 21 years, named with the params-derived
    // suffix the CLI generates.
    leaves.push(JobLeaf {
        field: "dateOfBirth@7665d".into(),
        circuit: "age_threshold".into(),
        value: serde_json::json!("1985-04-12"),
        public: serde_json::json!({"min_age_days": 7665u64}),
        params_hash: age_params_hash(7665),
        disclosure: Some(DISCLOSURE_PREDICATE.to_string()),
        params: Some(serde_json::json!({"minAgeDays": 7665u64})),
    });
    let job = job_with_leaves(tmp.path().to_str().unwrap(), leaves, true);
    let report = build(&job);
    let manifest = read_manifest(&report.bundle_path);

    let at18 = manifest
        .leaves
        .iter()
        .find(|l| l.field_name == "dateOfBirth")
        .unwrap();
    let at21 = manifest
        .leaves
        .iter()
        .find(|l| l.field_name == "dateOfBirth@7665d")
        .unwrap();

    assert_ne!(
        at18.params_hash, at21.params_hash,
        "params hashes must differ"
    );
    assert_ne!(
        at18.commitment, at21.commitment,
        "per-leaf nonces must differ"
    );
    assert_ne!(at18.leaf_hash, at21.leaf_hash);
    assert_eq!(at18.public_inputs["minAgeDays"], 6570);
    assert_eq!(at21.public_inputs["minAgeDays"], 7665);

    // Both proof files exist under filesystem-safe names.
    for leaf in [at18, at21] {
        let p = report.bundle_path.join(&leaf.proof_path);
        assert!(p.exists(), "missing proof file {}", leaf.proof_path);
    }
}

// =====================================================================
// Per-subject key wrapping and re-key
// =====================================================================

#[test]
fn secrets_decrypt_under_the_wrapped_subject_key() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_leaves(tmp.path().to_str().unwrap(), base_leaves(), true);
    let report = build(&job);
    let manifest = read_manifest(&report.bundle_path);

    let blob = std::fs::read(report.bundle_path.join("secrets.enc")).unwrap();
    assert_eq!(
        blob[0], SECRETS_KDF_VERSION as u8,
        "v2 blob must start with its version byte"
    );
    let pt = decrypt_secrets(
        &master_key(),
        manifest.wallet_address.as_bytes(),
        manifest.epoch_days,
        &config_hash(),
        manifest.secrets_kdf_version,
        &blob,
    )
    .unwrap();
    let entries: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&pt).unwrap();
    assert_eq!(entries["firstName"]["value"], serde_json::json!("Alice"));
}

#[test]
fn rekey_rotates_the_master_key_without_touching_proofs_or_root() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_leaves(tmp.path().to_str().unwrap(), base_leaves(), true);
    let report = build(&job);
    let dir = report.bundle_path.clone();

    let manifest_before = std::fs::read(dir.join("manifest.json")).unwrap();
    let sig_before = std::fs::read(dir.join("manifest.sig")).unwrap();
    let root_before = std::fs::read(dir.join("kycHash.hex")).unwrap();
    let proof_before = std::fs::read(dir.join("proofs/dateOfBirth.bin")).unwrap();

    let mut new_master = master_key();
    new_master[0] ^= 0xff;
    rekey_bundle(&dir, &master_key(), &new_master).unwrap();

    // Everything the signature and the chain cover is untouched.
    assert_eq!(
        std::fs::read(dir.join("manifest.json")).unwrap(),
        manifest_before
    );
    assert_eq!(std::fs::read(dir.join("manifest.sig")).unwrap(), sig_before);
    assert_eq!(std::fs::read(dir.join("kycHash.hex")).unwrap(), root_before);
    assert_eq!(
        std::fs::read(dir.join("proofs/dateOfBirth.bin")).unwrap(),
        proof_before
    );

    let manifest = read_manifest(&dir);
    let blob = std::fs::read(dir.join("secrets.enc")).unwrap();

    // The old master key can no longer read the blob; the new one can.
    assert!(decrypt_secrets(
        &master_key(),
        manifest.wallet_address.as_bytes(),
        manifest.epoch_days,
        &config_hash(),
        manifest.secrets_kdf_version,
        &blob,
    )
    .is_err());

    let pt = decrypt_secrets(
        &new_master,
        manifest.wallet_address.as_bytes(),
        manifest.epoch_days,
        &config_hash(),
        manifest.secrets_kdf_version,
        &blob,
    )
    .unwrap();
    let entries: BTreeMap<String, serde_json::Value> = serde_json::from_slice(&pt).unwrap();
    assert_eq!(entries["firstName"]["value"], serde_json::json!("Alice"));
}

#[test]
fn rekey_leaves_no_temporary_file_behind() {
    let tmp = tempfile::tempdir().unwrap();
    let job = job_with_leaves(tmp.path().to_str().unwrap(), base_leaves(), true);
    let dir = build(&job).bundle_path;
    let mut new_master = master_key();
    new_master[1] ^= 0x0f;
    rekey_bundle(&dir, &master_key(), &new_master).unwrap();
    assert!(!dir.join("secrets.enc.tmp").exists());
}

// =====================================================================
// Determinism and the entropy guard
// =====================================================================

#[test]
fn deterministic_runs_stay_byte_identical_under_the_new_kdf() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let job_a = job_with_leaves(tmp_a.path().to_str().unwrap(), base_leaves(), true);
    let job_b = job_with_leaves(tmp_b.path().to_str().unwrap(), base_leaves(), true);

    let a = build(&job_a).bundle_path;
    let b = build(&job_b).bundle_path;

    for name in [
        "kycHash.hex",
        "manifest.json",
        "manifest.sig",
        "secrets.enc",
    ] {
        assert_eq!(
            std::fs::read(a.join(name)).unwrap(),
            std::fs::read(b.join(name)).unwrap(),
            "{} differs between two deterministic runs",
            name
        );
    }
    for name in ["proofs/dateOfBirth.bin", "proofs/firstName.bin"] {
        assert_eq!(
            std::fs::read(a.join(name)).unwrap(),
            std::fs::read(b.join(name)).unwrap(),
            "{} differs between two deterministic runs",
            name
        );
    }
}

#[test]
fn non_deterministic_runs_draw_fresh_subject_keys() {
    // Two runs with identical inputs but `deterministic: false` must
    // produce different commitments: the subject key comes from OS
    // entropy rather than from the master key.
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let job_a = job_with_leaves(tmp_a.path().to_str().unwrap(), base_leaves(), false);
    let job_b = job_with_leaves(tmp_b.path().to_str().unwrap(), base_leaves(), false);

    let a = read_manifest(&build(&job_a).bundle_path);
    let b = read_manifest(&build(&job_b).bundle_path);
    assert_ne!(
        a.kyc_hash, b.kyc_hash,
        "non-deterministic runs must not reproduce the same root"
    );
    assert!(!a.deterministic && !b.deterministic);
}

#[test]
fn entropy_guard_rejects_draws_when_determinism_is_pinned() {
    // Driven through the pure guard rather than the env var: the harness
    // runs cases in parallel and `std::env` is process-global.
    let mut buf = [0u8; 32];
    let err = fill_random_guarded(true, &mut buf).unwrap_err();
    assert_eq!(err.code, ErrorCode::DeterminismViolation);
    assert_eq!(DETERMINISM_ENV, "TRUSSET_KYC_DETERMINISTIC");
}
