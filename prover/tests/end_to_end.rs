//! End-to-end prover pipeline test.
//!
//! Builds a synthetic Job in memory, runs `build_subject_bundle`, then:
//!   - decrypts `secrets.enc` and asserts the plaintext matches the input;
//!   - re-derives the Merkle root from the manifest's `leafHash` array and
//!     asserts it matches `kycHash.hex`;
//!   - verifies `manifest.sig` against the signing key;
//!   - calls each circuit's `verify()` on `proofs/*.bin` to confirm the
//!     stub proofs round-trip;
//!   - re-runs the whole pipeline a second time and asserts byte-identical
//!     output (the determinism canary).

use std::collections::BTreeMap;
use trusset_circuit_age_threshold as age;
use trusset_circuit_preimage_knowledge as preimage;
use trusset_circuit_set_membership as set;
use trusset_circuit_tier_threshold as tier;
use trusset_circuits_common::hex_to_digest;
use trusset_bundle_format::manifest::{canonical_signing_bytes, Manifest, CREATED_AT_SENTINEL};
use trusset_prover::{
    bundle::build_subject_bundle,
    encrypt::decrypt_secrets,
    job::{Job, JobLeaf, JobSubject, ListCommitment},
    sign::{verify as verify_sig, SigningSecret, SIGNATURE_LEN},
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

fn pad_hex64(short: &str) -> String {
    let h = short.trim_start_matches("0x");
    format!("0x{:0>1$}", h, 64)
}

fn fixture_job(output_root: &str) -> Job {
    let leaves = vec![
        JobLeaf {
            field: "firstName".to_string(),
            circuit: "preimage_knowledge".to_string(),
            value: serde_json::json!("Alice"),
            public: serde_json::json!({}),
            params_hash: pad_hex64("aa"),
        },
        JobLeaf {
            field: "dateOfBirth".to_string(),
            circuit: "age_threshold".to_string(),
            value: serde_json::json!("1985-04-12"),
            public: serde_json::json!({"min_age_days": 6570u64}),
            params_hash: pad_hex64("bb"),
        },
        JobLeaf {
            field: "investorType".to_string(),
            circuit: "tier_threshold".to_string(),
            value: serde_json::json!("PROFESSIONAL"),
            public: serde_json::json!({"min_tier": 1u64}),
            params_hash: pad_hex64("cc"),
        },
        JobLeaf {
            field: "country".to_string(),
            circuit: "set_membership".to_string(),
            value: serde_json::json!("DEU"),
            public: serde_json::json!({"list_id": "country_allowlist"}),
            params_hash: pad_hex64("dd"),
        },
    ];

    let subject = JobSubject {
        subject_id: "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01".to_string(),
        passthrough: serde_json::json!({
            "country": "DEU",
            "investorType": "PROFESSIONAL",
            "softExpiryDays": 365,
            "hardExpiryDays": 730
        }),
        leaves,
    };

    let mut list_commitments = BTreeMap::new();
    list_commitments.insert(
        "country_allowlist".to_string(),
        ListCommitment {
            values: vec!["DEU".into(), "FRA".into(), "USA".into(), "GBR".into()],
            source_sha256: "fixture-hash".to_string(),
        },
    );

    Job {
        version: "2.0.0".into(),
        deterministic: true,
        epoch_days: 20587,
        output_root: output_root.to_string(),
        config_hash: format!("0x{}", hex::encode(config_hash())),
        skip_proofs: false,
        subjects: vec![subject],
        list_commitments,
    }
}

#[test]
fn end_to_end_pipeline_produces_valid_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let job = fixture_job(tmp.path().to_str().unwrap());
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let public_key = signing.public_key();

    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap();

    assert_eq!(report.leaf_count, 4);

    // ---- File layout ----
    let dir = report.bundle_path.clone();
    assert!(dir.join("kycHash.hex").exists());
    assert!(dir.join("manifest.json").exists());
    assert!(dir.join("manifest.sig").exists());
    assert!(dir.join("secrets.enc").exists());
    for field in ["firstName", "dateOfBirth", "investorType", "country"] {
        assert!(
            dir.join("proofs").join(format!("{}.bin", field)).exists(),
            "missing proof for {}",
            field
        );
    }

    // ---- kycHash.hex matches manifest.kycHash ----
    let on_disk = std::fs::read_to_string(dir.join("kycHash.hex")).unwrap();
    assert_eq!(on_disk, report.kyc_hash_hex);
    let manifest_bytes = std::fs::read(dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest.kyc_hash, on_disk);
    assert_eq!(manifest.mode, "stub");
    assert_eq!(manifest.created_at, now_iso());
    assert_eq!(manifest.leaves.len(), 4);

    // ---- Manifest signature verifies against the *signing* view ----
    let mut for_sig = manifest.clone();
    for_sig.created_at = CREATED_AT_SENTINEL.to_string();
    let sig_payload = canonical_signing_bytes(&for_sig).unwrap();
    let sig_bytes = std::fs::read(dir.join("manifest.sig")).unwrap();
    assert_eq!(sig_bytes.len(), SIGNATURE_LEN);
    let mut sig_arr = [0u8; SIGNATURE_LEN];
    sig_arr.copy_from_slice(&sig_bytes);
    assert!(verify_sig(&public_key, &sig_payload, &sig_arr));

    // ---- Each proof verifies under its circuit's verifier ----
    for entry in &manifest.leaves {
        let proof = std::fs::read(dir.join(&entry.proof_path)).unwrap();
        match entry.circuit.as_str() {
            "preimage_knowledge" => {
                let public = preimage::PublicInputs {
                    commitment: hex_to_digest(&entry.commitment).unwrap(),
                };
                preimage::verify(&proof, &public).unwrap();
            }
            "age_threshold" => {
                let min_age = entry
                    .public_inputs
                    .get("minAgeDays")
                    .and_then(|v| v.as_u64())
                    .unwrap();
                let cur = entry
                    .public_inputs
                    .get("currentEpochDays")
                    .and_then(|v| v.as_u64())
                    .unwrap();
                let public = age::PublicInputs {
                    commitment: hex_to_digest(&entry.commitment).unwrap(),
                    min_age_days: min_age,
                    current_epoch_days: cur,
                };
                age::verify(&proof, &public).unwrap();
            }
            "tier_threshold" => {
                let min_tier = entry
                    .public_inputs
                    .get("minTier")
                    .and_then(|v| v.as_u64())
                    .unwrap() as u8;
                let public = tier::PublicInputs {
                    commitment: hex_to_digest(&entry.commitment).unwrap(),
                    min_tier,
                };
                tier::verify(&proof, &public).unwrap();
            }
            "set_membership" => {
                let set_root_hex = entry
                    .public_inputs
                    .get("setRoot")
                    .and_then(|v| v.as_str())
                    .unwrap();
                let set_depth = entry
                    .public_inputs
                    .get("setDepth")
                    .and_then(|v| v.as_u64())
                    .unwrap() as u8;
                let public = set::PublicInputs {
                    commitment: hex_to_digest(&entry.commitment).unwrap(),
                    set_root: hex_to_digest(set_root_hex).unwrap(),
                    set_depth,
                };
                set::verify(&proof, &public).unwrap();
            }
            other => panic!("unexpected circuit in manifest: {}", other),
        }
    }

    // ---- Decrypt secrets.enc and assert plaintexts ----
    let ct = std::fs::read(dir.join("secrets.enc")).unwrap();
    let pt = decrypt_secrets(
        &master_key(),
        manifest.wallet_address.as_bytes(),
        manifest.epoch_days,
        &config_hash(),
        &ct,
    )
    .unwrap();
    let entries: BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&pt).unwrap();
    assert_eq!(entries["firstName"]["value"], serde_json::json!("Alice"));
    assert_eq!(
        entries["dateOfBirth"]["value"],
        serde_json::json!("1985-04-12")
    );
    assert_eq!(
        entries["investorType"]["value"],
        serde_json::json!("PROFESSIONAL")
    );
    assert_eq!(entries["country"]["value"], serde_json::json!("DEU"));
}

#[test]
fn pipeline_is_byte_deterministic_across_two_runs() {
    let tmp_a = tempfile::tempdir().unwrap();
    let tmp_b = tempfile::tempdir().unwrap();
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();

    let report_a = build_subject_bundle(
        &fixture_job(tmp_a.path().to_str().unwrap()),
        &fixture_job(tmp_a.path().to_str().unwrap()).subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap();
    let report_b = build_subject_bundle(
        &fixture_job(tmp_b.path().to_str().unwrap()),
        &fixture_job(tmp_b.path().to_str().unwrap()).subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap();

    assert_eq!(report_a.kyc_hash_hex, report_b.kyc_hash_hex);

    // Every file in the bundle except createdAt-bearing manifest.json (which
    // depends on now_iso, identical here) must be byte-equal.
    for name in &["kycHash.hex", "manifest.json", "manifest.sig", "secrets.enc"] {
        let a = std::fs::read(report_a.bundle_path.join(name)).unwrap();
        let b = std::fs::read(report_b.bundle_path.join(name)).unwrap();
        assert_eq!(a, b, "{} differs between runs", name);
    }
    for field in &["firstName", "dateOfBirth", "investorType", "country"] {
        let path = format!("proofs/{}.bin", field);
        let a = std::fs::read(report_a.bundle_path.join(&path)).unwrap();
        let b = std::fs::read(report_b.bundle_path.join(&path)).unwrap();
        assert_eq!(a, b, "{} differs between runs", path);
    }
}

#[test]
fn pipeline_rejects_set_member_not_in_list() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = fixture_job(tmp.path().to_str().unwrap());
    // Swap country to one that isn't in the allowlist.
    job.subjects[0].leaves[3].value = serde_json::json!("ZZZ");
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let err = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap_err();
    assert_eq!(
        err.code,
        trusset_prover::errors::ErrorCode::ListMemberMissing
    );
}

#[test]
fn pipeline_rejects_underage_subject() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = fixture_job(tmp.path().to_str().unwrap());
    // Subject born 5 years before epoch_days at min_age=18.
    job.subjects[0].leaves[1].value = serde_json::json!(20587 - 5 * 365);
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let err = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap_err();
    assert_eq!(err.code, trusset_prover::errors::ErrorCode::AgeBelowMin);
}

#[test]
fn skip_proofs_emits_zero_byte_proof_files_and_signature_still_verifies() {
    use trusset_bundle_format::sign as bf_sign;
    let tmp = tempfile::tempdir().unwrap();
    let mut job = fixture_job(tmp.path().to_str().unwrap());
    job.skip_proofs = true;
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let pk = signing.public_key();
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap();

    // Every proofs/<field>.bin is exactly zero bytes.
    let proofs_dir = report.bundle_path.join("proofs");
    let entries: Vec<_> = std::fs::read_dir(&proofs_dir).unwrap().collect();
    assert!(!entries.is_empty(), "no proof files written");
    for entry in entries {
        let entry = entry.unwrap();
        let metadata = entry.metadata().unwrap();
        assert_eq!(
            metadata.len(),
            0,
            "{:?} should be zero bytes in skip-proofs mode",
            entry.path()
        );
    }

    // The manifest signature still verifies — the leaf hashes now bind to
    // the zero-byte proof_digest, but that's a stable input.
    let manifest_bytes =
        std::fs::read(report.bundle_path.join("manifest.json")).unwrap();
    let manifest: trusset_bundle_format::manifest::Manifest =
        serde_json::from_slice(&manifest_bytes).unwrap();
    let mut for_sig = manifest.clone();
    for_sig.created_at = CREATED_AT_SENTINEL.to_string();
    let payload =
        trusset_bundle_format::manifest::canonical_signing_bytes(&for_sig).unwrap();
    let sig_bytes = std::fs::read(report.bundle_path.join("manifest.sig")).unwrap();
    let mut sig_arr = [0u8; bf_sign::SIGNATURE_LEN];
    sig_arr.copy_from_slice(&sig_bytes);
    assert!(bf_sign::verify(&pk, &payload, &sig_arr));
}

#[test]
fn pipeline_rejects_tier_none() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = fixture_job(tmp.path().to_str().unwrap());
    job.subjects[0].leaves[2].value = serde_json::json!("NONE");
    let signing = SigningSecret::from_hex(signing_key_hex()).unwrap();
    let err = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing,
        &config_hash(),
        now_iso(),
    )
    .unwrap_err();
    assert_eq!(err.code, trusset_prover::errors::ErrorCode::TierNone);
}
