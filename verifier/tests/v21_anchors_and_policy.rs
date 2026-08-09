//! v2.1 verifier tests: root-anchored verification, the anchor
//! requirement, `paramsHash` lockstep, the empty-proof policy, and
//! `merkleVersion` dispatch.

use std::collections::BTreeMap;
use trusset_bundle_format::manifest::{
    canonical_signing_bytes, Manifest, DISCLOSURE_COMMITMENT_ONLY, DISCLOSURE_PREDICATE,
};
use trusset_prover::{
    bundle::build_subject_bundle,
    job::{Job, JobLeaf, JobSubject},
    sign::SigningSecret,
};
use trusset_verifier::{verify_bundle, VerifyAnchors, VerifyOptions};

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

fn fixture_job(output_root: &str) -> Job {
    Job {
        version: "2.1.0".into(),
        deterministic: true,
        epoch_days: 20587,
        output_root: output_root.to_string(),
        config_hash: hex32(config_hash()),
        skip_proofs: false,
        subjects: vec![JobSubject {
            subject_id: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".into(),
            passthrough: serde_json::json!({}),
            leaves: vec![
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
            ],
        }],
        list_commitments: BTreeMap::new(),
    }
}

/// Build a bundle and return `(dir, public_key, root_hex)`.
fn build_bundle(tmp: &tempfile::TempDir) -> (std::path::PathBuf, [u8; 32], String) {
    let job = fixture_job(tmp.path().to_str().unwrap());
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let pk = signing.public_key();
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        "2026-05-14T09:12:33Z",
    )
    .unwrap();
    let root = report.kyc_hash_hex.clone();
    (report.bundle_path, pk, root)
}

fn key_only(pk: [u8; 32]) -> VerifyOptions {
    VerifyOptions {
        anchors: VerifyAnchors {
            expected_public_key: Some(pk),
            expected_root: None,
        },
        accept_stub: false,
    }
}

fn root_only(root: &str) -> VerifyOptions {
    VerifyOptions {
        anchors: VerifyAnchors {
            expected_public_key: None,
            expected_root: Some(root.to_string()),
        },
        accept_stub: false,
    }
}

fn rewrite_manifest(dir: &std::path::Path, m: &Manifest) {
    let bytes = trusset_bundle_format::manifest::canonical_disk_bytes(m).unwrap();
    std::fs::write(dir.join("manifest.json"), &bytes).unwrap();
}

fn resign(dir: &std::path::Path, m: &Manifest) {
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let payload = canonical_signing_bytes(m).unwrap();
    std::fs::write(dir.join("manifest.sig"), signing.sign(&payload)).unwrap();
}

// =====================================================================
// Anchors
// =====================================================================

#[test]
fn root_anchor_alone_verifies_without_a_public_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, _pk, root) = build_bundle(&tmp);
    let report = verify_bundle(&dir, &root_only(&root)).unwrap();
    assert!(
        report.overall_pass,
        "root-anchored verify must pass: {:?}",
        report
    );
    assert_eq!(report.anchor, "root");
    assert!(report.root_anchor_valid);
    assert!(
        !report.signature_valid,
        "no key supplied, so no signature check"
    );
}

#[test]
fn signature_anchor_alone_verifies_without_a_root() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);
    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(report.overall_pass);
    assert_eq!(report.anchor, "public_key");
    assert!(report.signature_valid);
    assert!(!report.root_anchor_valid);
}

#[test]
fn both_anchors_agree_on_the_same_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, root) = build_bundle(&tmp);
    let by_key = verify_bundle(&dir, &key_only(pk)).unwrap();
    let by_root = verify_bundle(&dir, &root_only(&root)).unwrap();
    let both = verify_bundle(
        &dir,
        &VerifyOptions {
            anchors: VerifyAnchors {
                expected_public_key: Some(pk),
                expected_root: Some(root.clone()),
            },
            accept_stub: false,
        },
    )
    .unwrap();

    assert!(by_key.overall_pass && by_root.overall_pass && both.overall_pass);
    assert_eq!(by_key.kyc_hash, by_root.kyc_hash);
    assert_eq!(by_key.merkle_root_valid, by_root.merkle_root_valid);
    assert_eq!(both.anchor, "public_key+root");
}

#[test]
fn no_anchor_never_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, _pk, _root) = build_bundle(&tmp);
    let report = verify_bundle(
        &dir,
        &VerifyOptions {
            anchors: VerifyAnchors::default(),
            accept_stub: false,
        },
    )
    .unwrap();
    assert!(
        !report.overall_pass,
        "a bundle verified against no anchor proves nothing and must not pass"
    );
    assert_eq!(report.anchor, "none");
}

#[test]
fn wrong_root_fails_even_though_the_bundle_is_internally_consistent() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, _pk, _root) = build_bundle(&tmp);
    let other = format!("0x{}", "11".repeat(32));
    let report = verify_bundle(&dir, &root_only(&other)).unwrap();
    assert!(!report.overall_pass);
    assert!(!report.root_anchor_valid);
    // The bundle's own chain is still intact - only the anchor disagrees.
    assert!(report.merkle_root_valid);
}

#[test]
fn root_anchor_is_case_insensitive() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, _pk, root) = build_bundle(&tmp);
    let upper = format!("0x{}", root.trim_start_matches("0x").to_uppercase());
    let report = verify_bundle(&dir, &root_only(&upper)).unwrap();
    assert!(report.overall_pass);
}

// =====================================================================
// paramsHash lockstep
// =====================================================================

#[test]
fn tampered_params_hash_fails_the_leaf() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let leaf = manifest
        .leaves
        .iter_mut()
        .find(|l| l.field_name == "dateOfBirth")
        .unwrap();
    leaf.params_hash = format!("0x{}", "ab".repeat(32));
    // Re-sign so the signature is not what fails: the params check is.
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(
        report.signature_valid,
        "re-signed bundle keeps a valid signature"
    );
    assert!(!report.overall_pass);
    let leaf_report = report
        .leaves
        .iter()
        .find(|l| l.field == "dateOfBirth")
        .unwrap();
    assert!(!leaf_report.pass);
    assert!(leaf_report
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("paramsHash mismatch"));
}

#[test]
fn params_that_disagree_with_the_asserted_threshold_fail() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let leaf = manifest
        .leaves
        .iter_mut()
        .find(|l| l.field_name == "dateOfBirth")
        .unwrap();
    // Claim a stricter threshold than the paramsHash commits to.
    leaf.params = Some(serde_json::json!({"minAgeDays": 7665u64}));
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(
        !report.overall_pass,
        "a re-labeled threshold must not verify"
    );
}

// =====================================================================
// Empty-proof policy
// =====================================================================

#[test]
fn commitment_only_leaf_is_accepted_with_an_empty_proof() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);
    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    let leaf = report
        .leaves
        .iter()
        .find(|l| l.field == "firstName")
        .unwrap();
    assert!(
        leaf.pass,
        "commitment_only leaf must verify: {:?}",
        leaf.reason
    );
    assert!(report.overall_pass);
}

#[test]
fn empty_proof_on_a_proving_leaf_is_rejected_in_production_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    // Strip the age proof to zero bytes and rewrite the manifest so the
    // proofDigest and leafHash match the empty file: the bundle is then
    // internally consistent and correctly signed, and only the policy
    // check stands between it and a pass.
    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    let empty_digest = trusset_circuits_common::digest_to_hex(
        &trusset_bundle_format::leaf::compute_proof_digest(&[]),
    );
    {
        let leaf = manifest
            .leaves
            .iter_mut()
            .find(|l| l.field_name == "dateOfBirth")
            .unwrap();
        std::fs::write(dir.join(&leaf.proof_path), []).unwrap();
        leaf.proof_digest = empty_digest.clone();
        let commitment = trusset_circuits_common::hex_to_digest(&leaf.commitment).unwrap();
        let public_digest = trusset_circuits_common::hex_to_digest(&leaf.public_digest).unwrap();
        let proof_digest = trusset_circuits_common::hex_to_digest(&empty_digest).unwrap();
        let wallet = {
            let s = manifest.wallet_address.trim_start_matches("0x").to_string();
            let mut out = [0u8; 20];
            for i in 0..20 {
                out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
            }
            out
        };
        let recomputed = trusset_bundle_format::leaf::compute_leaf_hash(
            &leaf.field_name,
            trusset_circuits_common::CircuitId::AgeThreshold,
            &wallet,
            manifest.epoch_days,
            &commitment,
            &public_digest,
            &proof_digest,
        );
        leaf.leaf_hash = trusset_circuits_common::digest_to_hex(&recomputed);
    }
    // Recompute the root over the edited leaf set and re-sign.
    let leaf_hashes: Vec<_> = manifest
        .leaves
        .iter()
        .map(|l| trusset_circuits_common::hex_to_digest(&l.leaf_hash).unwrap())
        .collect();
    let (root, _) = trusset_bundle_format::merkle::compute_root_v2(&leaf_hashes);
    manifest.kyc_hash = trusset_circuits_common::digest_to_hex(&root);
    std::fs::write(dir.join("kycHash.hex"), manifest.kyc_hash.as_bytes()).unwrap();
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    // The forged bundle is signed correctly and its kycHash.hex matches,
    // so the signature and layout checks pass: the empty-proof policy is
    // the only thing standing between it and acceptance. (The Merkle check
    // reports false as a consequence of the rejected leaf, not as an
    // independent finding - a failed leaf contributes no hash.)
    assert!(
        report.signature_valid && report.kyc_hash_file_matches && report.layout_ok,
        "signature and layout must be intact: {:?}",
        report
    );
    let leaf = report
        .leaves
        .iter()
        .find(|l| l.field == "dateOfBirth")
        .unwrap();
    assert!(
        !leaf.pass,
        "a production-mode proving leaf with an empty proof must be rejected"
    );
    assert!(leaf
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("empty proof"));
    assert!(!report.overall_pass);
}

// =====================================================================
// merkleVersion dispatch
// =====================================================================

#[test]
fn manifest_declaring_the_wrong_merkle_version_fails_the_root_check() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    manifest.merkle_version = Some(1);
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(
        !report.merkle_root_valid,
        "a v2 root must not re-derive under the v1 construction"
    );
    assert!(!report.overall_pass);
}

#[test]
fn unknown_merkle_version_is_rejected_rather_than_assumed() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    manifest.merkle_version = Some(99);
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(!report.merkle_root_valid);
    assert!(!report.overall_pass);
}

// =====================================================================
// Version acceptance
// =====================================================================

#[test]
fn unsupported_manifest_version_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (dir, pk, _root) = build_bundle(&tmp);

    let mut manifest: Manifest =
        serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
    manifest.version = "3.0.0".into();
    rewrite_manifest(&dir, &manifest);
    resign(&dir, &manifest);

    let report = verify_bundle(&dir, &key_only(pk)).unwrap();
    assert!(!report.layout_ok);
    assert!(!report.overall_pass);
    assert_eq!(report.manifest_version, "3.0.0");
}
