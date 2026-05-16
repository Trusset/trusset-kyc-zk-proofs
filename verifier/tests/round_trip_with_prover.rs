//! End-to-end verifier ↔ prover round-trip.
//!
//! For each scenario, build a bundle with `trusset-prover::bundle::build_subject_bundle`,
//! then run `trusset-verifier::verify_bundle` against the resulting
//! directory and assert the expected pass/fail outcome.

use std::collections::BTreeMap;
use std::path::Path;
use trusset_prover::{
    bundle::build_subject_bundle,
    job::{Job, JobLeaf, JobSubject, ListCommitment},
    sign::SigningSecret,
};
use trusset_verifier::{verify_bundle, VerifyOptions};

fn master_key() -> [u8; 32] {
    let mut m = [0u8; 32];
    for (i, b) in m.iter_mut().enumerate() {
        *b = i as u8;
    }
    m
}
fn signing_hex() -> &'static str {
    "4242424242424242424242424242424242424242424242424242424242424242"
}
fn config_hash() -> [u8; 32] {
    [0xcd; 32]
}
fn now_iso() -> &'static str {
    "2026-05-14T09:12:33Z"
}

fn pad_hex64(short: &str) -> String {
    format!("0x{:0>1$}", short.trim_start_matches("0x"), 64)
}

fn fixture_job(out: &str) -> Job {
    let leaves = vec![
        JobLeaf {
            field: "firstName".into(),
            circuit: "preimage_knowledge".into(),
            value: serde_json::json!("Alice"),
            public: serde_json::json!({}),
            params_hash: pad_hex64("aa"),
        },
        JobLeaf {
            field: "dateOfBirth".into(),
            circuit: "age_threshold".into(),
            value: serde_json::json!("1985-04-12"),
            public: serde_json::json!({"min_age_days": 6570u64}),
            params_hash: pad_hex64("bb"),
        },
        JobLeaf {
            field: "investorType".into(),
            circuit: "tier_threshold".into(),
            value: serde_json::json!("PROFESSIONAL"),
            public: serde_json::json!({"min_tier": 1u64}),
            params_hash: pad_hex64("cc"),
        },
        JobLeaf {
            field: "country".into(),
            circuit: "set_membership".into(),
            value: serde_json::json!("DEU"),
            public: serde_json::json!({"list_id": "country_allowlist"}),
            params_hash: pad_hex64("dd"),
        },
    ];
    let subject = JobSubject {
        subject_id: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
        passthrough: serde_json::json!({"country": "DEU"}),
        leaves,
    };
    let mut lists = BTreeMap::new();
    lists.insert(
        "country_allowlist".to_string(),
        ListCommitment {
            values: vec!["DEU".into(), "FRA".into(), "USA".into(), "GBR".into()],
            source_sha256: "fixture-hash".into(),
        },
    );
    Job {
        version: "2.0.0".into(),
        deterministic: true,
        epoch_days: 20587,
        output_root: out.to_string(),
        config_hash: format!("0x{}", hex::encode(config_hash())),
        skip_proofs: false,
        subjects: vec![subject],
        list_commitments: lists,
    }
}

fn build_and_get_path(tmp: &tempfile::TempDir) -> (std::path::PathBuf, [u8; 32]) {
    let signing = SigningSecret::from_hex(signing_hex()).unwrap();
    let pk = signing.public_key();
    let job = fixture_job(tmp.path().to_str().unwrap());
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap();
    (report.bundle_path, pk)
}

#[test]
fn verifier_accepts_a_real_bundle_in_permissive_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);
    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(report.overall_pass, "report: {:#?}", report);
    assert!(report.signature_valid);
    assert!(report.merkle_root_valid);
    assert!(report.kyc_hash_file_matches);
    assert_eq!(report.leaf_count, 4);
    for leaf in &report.leaves {
        assert!(leaf.pass, "leaf failed: {:#?}", leaf);
    }
}

#[test]
fn strict_mode_rejects_stub_bundle() {
    // Phase 2A always emits mode="stub". Strict mode must refuse it.
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);
    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: false,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    assert!(!report.mode_acceptable);
    // All the cryptographic checks still pass — only the policy check fails.
    assert!(report.signature_valid);
    assert!(report.merkle_root_valid);
}

#[test]
fn verifier_rejects_wrong_public_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, _pk) = build_and_get_path(&tmp);
    let mut bad = [0u8; 32];
    bad[0] = 0xff;
    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: bad,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    assert!(!report.signature_valid);
}

#[test]
fn verifier_rejects_tampered_proof_byte() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);

    // Flip one byte of one proof file.
    let proof_path = bundle_path.join("proofs").join("firstName.bin");
    let mut proof_bytes = std::fs::read(&proof_path).unwrap();
    proof_bytes[20] ^= 0x01; // somewhere in the proof body
    std::fs::write(&proof_path, &proof_bytes).unwrap();

    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    // The proofDigest field in the manifest no longer matches the
    // recomputed digest, so the firstName leaf fails. The other three
    // leaves should still pass.
    let firstname = report
        .leaves
        .iter()
        .find(|l| l.field == "firstName")
        .unwrap();
    assert!(!firstname.pass);
    let three_others = report
        .leaves
        .iter()
        .filter(|l| l.field != "firstName")
        .count();
    let three_others_passing = report
        .leaves
        .iter()
        .filter(|l| l.field != "firstName" && l.pass)
        .count();
    assert_eq!(three_others, 3);
    assert_eq!(three_others_passing, 3);
}

#[test]
fn verifier_rejects_tampered_manifest_field() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);

    // Tamper with the manifest's kycHash so the signing payload changes.
    let manifest_path = bundle_path.join("manifest.json");
    let original = std::fs::read_to_string(&manifest_path).unwrap();
    let tampered = original.replacen(
        r#""kycHash": "0x"#,
        r#""kycHash": "0xff"#,
        1,
    );
    assert_ne!(original, tampered, "tamper edit must replace something");
    std::fs::write(&manifest_path, tampered).unwrap();

    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    // The signature was over the original `kycHash`, so it no longer verifies.
    assert!(!report.signature_valid);
}

#[test]
fn verifier_rejects_missing_kyc_hash_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);
    std::fs::remove_file(bundle_path.join("kycHash.hex")).unwrap();
    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    assert!(!report.layout_ok);
}

#[test]
fn verifier_rejects_swapped_circuit_id() {
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);

    // Flip the preimage_knowledge leaf's circuitId byte from 4 to 3.
    // `"circuitId": 4` is unique in the manifest (only preimage has id 4),
    // so a single global replace is safe and unambiguous.
    let manifest_path = bundle_path.join("manifest.json");
    let original = std::fs::read_to_string(&manifest_path).unwrap();
    let text = original.replace(r#""circuitId": 4"#, r#""circuitId": 3"#);
    assert_ne!(original, text, "expected exactly one occurrence of circuitId: 4");
    std::fs::write(&manifest_path, text).unwrap();

    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    // Two possible failure modes — signature check (manifest is hashed
    // wholesale) or the per-leaf consistency check. Either way overall fails.
}

#[test]
fn verifier_rejects_swapped_set_root() {
    // The list-swap attack: a malicious operator could try to prove a
    // subject is in list X but claim the proof was against list Y in the
    // manifest. Defense: the leaf hash binds the public inputs (including
    // setRoot) into a chain that ends at the signed kycHash. Swapping the
    // setRoot post-hoc in the manifest invalidates both the leaf hash
    // (via publicDigest) and the manifest signature.

    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);

    let manifest_path = bundle_path.join("manifest.json");
    let original = std::fs::read_to_string(&manifest_path).unwrap();
    // Find the setRoot value in the country leaf and corrupt one nibble.
    // The first `"setRoot": "0x..."` line corresponds to the country leaf.
    let line_marker = r#""setRoot": "0x"#;
    let idx = original
        .find(line_marker)
        .expect("manifest should contain a setRoot field");
    // Flip a byte two characters after the 0x prefix.
    let mut bytes = original.into_bytes();
    let target = idx + line_marker.len() + 2;
    bytes[target] = if bytes[target] == b'0' { b'1' } else { b'0' };
    std::fs::write(&manifest_path, &bytes).unwrap();

    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    // The signature is over the manifest with the original setRoot, so
    // flipping it breaks the signature check first.
    assert!(!report.signature_valid);
    // And the country leaf's publicDigest no longer matches what the
    // verifier recomputes from the (tampered) setRoot.
    let country_leaf = report
        .leaves
        .iter()
        .find(|l| l.field == "country")
        .unwrap();
    assert!(!country_leaf.pass);
}

#[test]
fn verifier_rejects_list_root_swap_via_public_digest_drift() {
    // A subtler attack: instead of swapping the setRoot bytes in place,
    // an attacker tries to claim a different list_id with a matching root.
    // The leaf hash binds the publicDigest, and publicDigest hashes the
    // canonical public-inputs bytes (which include setRoot, setDepth, and
    // commitment). So any drift between the public_inputs JSON and what
    // the verifier reconstructs into PublicInputs fails the leaf check.
    let tmp = tempfile::tempdir().unwrap();
    let (bundle_path, pk) = build_and_get_path(&tmp);

    let manifest_path = bundle_path.join("manifest.json");
    let original = std::fs::read_to_string(&manifest_path).unwrap();
    // Replace setDepth: 2 with setDepth: 3 (one byte) inside the country leaf.
    let text = original.replace(r#""setDepth": 2"#, r#""setDepth": 3"#);
    assert_ne!(original, text, "no setDepth field found to swap");
    std::fs::write(&manifest_path, text).unwrap();

    let report = verify_bundle(
        &bundle_path,
        &VerifyOptions {
            expected_public_key: pk,
            accept_stub: true,
        },
    )
    .unwrap();
    assert!(!report.overall_pass);
    assert!(!report.signature_valid);
}

#[test]
fn verifier_handles_missing_bundle_directory() {
    let opts = VerifyOptions {
        expected_public_key: [0u8; 32],
        accept_stub: true,
    };
    let result = verify_bundle(Path::new("/tmp/this/does/not/exist"), &opts);
    assert!(result.is_err());
}
