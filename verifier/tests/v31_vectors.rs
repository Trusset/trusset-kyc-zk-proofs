//! v3.1 shared test vectors, checked natively here and through the WASM
//! build by `tests/wasm/v31_vectors.test.js`.
//!
//! `test-vectors/v3.1/` holds a real 3.1.0 bundle (no `secrets.enc`), a
//! `vectors.json` with its root, header, signing bytes, paths, digests, and
//! attestation, and `negative/` cases that must fail a named check. The
//! issuer backend copies the directory and runs the same cases.
//!
//! Refresh after a deliberate format change:
//!
//! ```text
//! TRUSSET_VECTORS_REFRESH=1 cargo test -p trusset-verifier --release --test v31_vectors
//! ```
//!
//! Everything is deterministic, so a refresh with no format change rewrites
//! the same bytes.

mod common_v31;

use common_v31::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use trusset_bundle_format::attestation::AttestationFile;
use trusset_bundle_format::claims::{compute_binding_digest, LeafBinding};
use trusset_bundle_format::header::{signature_to_hex, DisclosureHeader};
use trusset_bundle_format::manifest::Manifest;
use trusset_bundle_format::merkle::{compute_root_v3, root_from_path_v3};
use trusset_circuits_common::{digest_to_hex, hex_to_digest};
use trusset_verifier::v31::{public_digest_from_json, verify_disclosure, DisclosureReport};
use trusset_verifier::{bundle, verify_bundle, verify_loaded, AsOf, VerifyAnchors, VerifyOptions};

fn bundle_rel() -> String {
    format!("bundle/{}", WALLET)
}

fn read_json(p: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e)))
        .unwrap()
}

fn write_json(p: &Path, v: &Value) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    let mut bytes = serde_json::to_vec_pretty(v).unwrap();
    bytes.push(b'\n');
    std::fs::write(p, bytes).unwrap();
}

fn resign(d: &mut Value, key_hex: &str) {
    let header: DisclosureHeader = serde_json::from_value(d["header"].clone()).unwrap();
    let bytes = header.signing_bytes().unwrap();
    let sig = trusset_prover::sign::SigningSecret::from_hex(key_hex)
        .unwrap()
        .sign(&bytes);
    d["headerSignature"] = Value::String(signature_to_hex(&sig));
}

fn rebind(d: &mut Value) {
    let b: LeafBinding = serde_json::from_value(d["leaf"]["binding"].clone()).unwrap();
    d["leaf"]["bindingDigest"] = Value::String(digest_to_hex(&compute_binding_digest(&b).unwrap()));
}

fn other_public_key() -> String {
    hex_lower(
        &trusset_prover::sign::SigningSecret::from_hex(OTHER_SIGNING_HEX)
            .unwrap()
            .public_key(),
    )
}

fn public_key_hex() -> String {
    hex_lower(&signing().public_key())
}

struct Neg {
    name: &'static str,
    base: &'static str,
    proof: Option<&'static str>,
    key: Option<String>,
    wallet: &'static str,
    failed: &'static str,
    mutate: Box<dyn Fn(&mut Value)>,
}

fn negatives() -> Vec<Neg> {
    let other_addr = "0x3333333333333333333333333333333333333333";
    let other_digest = digest_to_hex(&trusset_circuits_common::hash_bytes_with_tag(
        &trusset_circuits_common::LEAF_TAG,
        b"not a sibling",
    ));
    let od = other_digest.clone();
    let od2 = other_digest.clone();
    vec![
        Neg {
            name: "wrong_operator_key",
            base: "dateOfBirth",
            proof: None,
            key: Some(other_public_key()),
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(|_| {}),
        },
        Neg {
            name: "header_wallet_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(move |d| d["header"]["wallet"] = json!(other_addr)),
        },
        Neg {
            name: "header_wallet_changed_and_resigned",
            base: "country",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_hash_valid",
            mutate: Box::new(move |d| {
                d["header"]["wallet"] = json!(other_addr);
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_epoch_changed_and_resigned",
            base: "country",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_hash_valid",
            mutate: Box::new(|d| {
                d["header"]["epochDays"] = json!(EPOCH + 1);
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_epoch_changed_and_resigned_on_age_leaf",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| {
                d["header"]["epochDays"] = json!(EPOCH + 1);
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_root_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(move |d| d["header"]["root"] = json!(od.clone())),
        },
        Neg {
            name: "header_root_changed_and_resigned",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "inclusion_valid",
            mutate: Box::new(move |d| {
                d["header"]["root"] = json!(od2.clone());
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_chain_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(|d| d["header"]["chainId"] = json!(137)),
        },
        Neg {
            name: "header_key_id_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(|d| d["header"]["keyId"] = json!(2)),
        },
        Neg {
            name: "header_leaf_count_changed_and_resigned",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "inclusion_valid",
            mutate: Box::new(|d| {
                d["header"]["leafCount"] = json!(6);
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_leaf_count_needs_a_longer_path",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| {
                d["header"]["leafCount"] = json!(9);
                resign(d, SIGNING_HEX);
            }),
        },
        Neg {
            name: "header_root_uppercase",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| {
                let r = d["header"]["root"].as_str().unwrap().to_uppercase();
                d["header"]["root"] = json!(format!("0x{}", &r[2..]));
            }),
        },
        Neg {
            name: "header_signature_uppercase",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "header_signature_valid",
            mutate: Box::new(|d| {
                let s = d["headerSignature"].as_str().unwrap().to_uppercase();
                d["headerSignature"] = json!(format!("0x{}", &s[2..]));
            }),
        },
        Neg {
            name: "path_sibling_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "inclusion_valid",
            mutate: Box::new(move |d| d["path"][0] = json!(other_digest.clone())),
        },
        Neg {
            name: "path_truncated",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| {
                d["path"].as_array_mut().unwrap().pop();
            }),
        },
        Neg {
            name: "leaf_renamed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_hash_valid",
            mutate: Box::new(|d| d["leaf"]["fieldName"] = json!("dateOfBirth2")),
        },
        Neg {
            name: "predicate_relabelled",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| d["leaf"]["binding"]["predicate"] = json!("ACCREDITED")),
        },
        Neg {
            name: "predicate_relabelled_with_binding_digest",
            base: "country",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_hash_valid",
            mutate: Box::new(|d| {
                d["leaf"]["binding"]["predicate"] = json!("RESIDENCY_ON_FILE");
                rebind(d);
            }),
        },
        Neg {
            name: "predicate_incompatible_with_circuit",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| {
                d["leaf"]["binding"]["predicate"] = json!("EEA_RESIDENT");
                rebind(d);
            }),
        },
        Neg {
            name: "params_claim_a_higher_age_than_proved",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| {
                d["leaf"]["params"]["minAgeDays"] = json!(7665);
                d["leaf"]["paramsHash"] = json!(hex32(
                    trusset_circuit_age_threshold::Params { min_age_days: 7665 }.hash()
                ));
            }),
        },
        Neg {
            name: "public_inputs_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| d["leaf"]["publicInputs"]["minAgeDays"] = json!(7665)),
        },
        Neg {
            name: "investor_class_raised_with_digests",
            base: "investorType",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_hash_valid",
            mutate: Box::new(|d| {
                d["leaf"]["publicInputs"]["minTier"] = json!(3);
                d["leaf"]["params"]["minTier"] = json!(3);
                d["leaf"]["paramsHash"] = json!(hex32(
                    trusset_circuit_tier_threshold::Params { min_tier: 3 }.hash()
                ));
                let pd = public_digest_from_json(
                    trusset_circuits_common::CircuitId::TierThreshold,
                    &d["leaf"]["publicInputs"],
                )
                .unwrap();
                d["leaf"]["publicDigest"] = json!(digest_to_hex(&pd));
            }),
        },
        Neg {
            name: "proof_swapped",
            base: "dateOfBirth",
            proof: Some("country"),
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|_| {}),
        },
        Neg {
            name: "empty_proof_on_a_predicate_leaf",
            base: "dateOfBirth",
            proof: Some(""),
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|_| {}),
        },
        Neg {
            name: "marked_commitment_only",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "leaf_valid",
            mutate: Box::new(|d| d["leaf"]["disclosure"] = json!("commitment_only")),
        },
        Neg {
            name: "unexpected_wallet",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "0x3333333333333333333333333333333333333333",
            failed: "wallet_matches",
            mutate: Box::new(|_| {}),
        },
        Neg {
            name: "unknown_leaf_key",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| d["leaf"]["note"] = json!("x")),
        },
        Neg {
            name: "unknown_top_level_key",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| d["extra"] = json!(1)),
        },
        Neg {
            name: "disclosure_version_changed",
            base: "dateOfBirth",
            proof: None,
            key: None,
            wallet: "",
            failed: "parsed",
            mutate: Box::new(|d| d["version"] = json!("3.0.0")),
        },
    ]
}

fn refresh(dir: &Path) {
    let tmp = tempfile::tempdir().unwrap();
    let built = build_bundle(tmp.path());

    let target = dir.join(bundle_rel());
    if dir.join("bundle").exists() {
        std::fs::remove_dir_all(dir.join("bundle")).unwrap();
    }
    if dir.join("negative").exists() {
        std::fs::remove_dir_all(dir.join("negative")).unwrap();
    }
    copy_dir(&built, &target);

    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(target.join("manifest.json")).unwrap()).unwrap();
    let header_value = read_json(&target.join("header.json"));
    let header: DisclosureHeader = serde_json::from_value(header_value.clone()).unwrap();
    let header_sig = std::fs::read(target.join("header.sig")).unwrap();

    let mut leaves = Vec::new();
    let mut positive = Vec::new();
    for l in &manifest.leaves {
        let d = read_json(&target.join(format!("disclosures/{}.json", l.field_name)));
        leaves.push(json!({
            "fieldName": l.field_name,
            "circuit": l.circuit,
            "predicate": l.binding.as_ref().and_then(|b| b.predicate.clone()),
            "leafHash": l.leaf_hash,
            "publicDigest": l.public_digest,
            "proofDigest": l.proof_digest,
            "bindingDigest": l.binding_digest,
            "paramsHash": l.params_hash,
            "path": d["path"],
        }));
        positive.push(json!({
            "name": l.field_name,
            "disclosure": format!("{}/disclosures/{}.json", bundle_rel(), l.field_name),
            "proof": format!("{}/{}", bundle_rel(), l.proof_path),
            "publicKey": public_key_hex(),
            "expectedWallet": WALLET,
            "expect": {"ok": true},
        }));
    }

    let mut negative = Vec::new();
    std::fs::create_dir_all(dir.join("negative")).unwrap();
    std::fs::write(dir.join("negative").join("empty.bin"), []).unwrap();
    for n in negatives() {
        let mut d = read_json(&target.join(format!("disclosures/{}.json", n.base)));
        (n.mutate)(&mut d);
        let file = format!("negative/{}.json", n.name);
        write_json(&dir.join(&file), &d);
        let proof = match n.proof {
            None => format!("{}/proofs/{}.bin", bundle_rel(), n.base),
            Some("") => "negative/empty.bin".to_string(),
            Some(other) => format!("{}/proofs/{}.bin", bundle_rel(), other),
        };
        negative.push(json!({
            "name": n.name,
            "disclosure": file,
            "proof": proof,
            "publicKey": n.key.clone().unwrap_or_else(public_key_hex),
            "expectedWallet": n.wallet,
            "expect": {"ok": false, "failed": n.failed},
        }));
    }

    let mut bundle_negative = Vec::new();
    {
        let mut h = header.clone();
        h.chain_id = 137;
        let sig = signing().sign(&h.signing_bytes().unwrap());
        let file = "negative/bundle_header_other_chain.json";
        write_json(&dir.join(file), &serde_json::to_value(&h).unwrap());
        bundle_negative.push(json!({
            "name": "bundle_header_other_chain",
            "header": file,
            "headerSignature": signature_to_hex(&sig),
            "expect": {"overall_pass": false, "failed": "consistent"},
        }));
        let other = trusset_prover::sign::SigningSecret::from_hex(OTHER_SIGNING_HEX).unwrap();
        let sig = other.sign(&header.signing_bytes().unwrap());
        bundle_negative.push(json!({
            "name": "bundle_header_signed_by_another_key",
            "header": format!("{}/header.json", bundle_rel()),
            "headerSignature": signature_to_hex(&sig),
            "expect": {"overall_pass": false, "failed": "signature_valid"},
        }));
    }

    let (eea_values, eea_root, eea_depth, eea_source) = eea_list();
    let attestation = AttestationFile::from_manifest(&manifest).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&header_sig);
    let vectors = json!({
        "format": "trusset-kyc-test-vectors/1",
        "version": "3.1.0",
        "note": "Generated by verifier/tests/v31_vectors.rs from fixed test keys. The keys are public; never use them outside tests.",
        "operatorPublicKey": public_key_hex(),
        "otherPublicKey": other_public_key(),
        "wallet": WALLET,
        "epochDays": EPOCH,
        "chain": {"attester": ATTESTER, "chainId": CHAIN_ID, "hub": HUB, "keyId": KEY_ID},
        "circuitsVersion": manifest.circuits_version,
        "merkleVersion": manifest.merkle_version,
        "bundleDir": bundle_rel(),
        "root": manifest.kyc_hash,
        "header": header_value,
        "headerSigningBytes": hex_lower(&header.signing_bytes().unwrap()),
        "headerSignature": signature_to_hex(&sig_arr),
        "attestation": attestation,
        "paramsHashes": {
            "age_threshold:minAgeDays=6570": hex32(trusset_circuit_age_threshold::Params { min_age_days: 6570 }.hash()),
            "set_membership:listId=eea": hex32(trusset_circuit_set_membership::Params { list_id: "eea".into() }.hash()),
            "set_membership:listId=country_allowlist": hex32(trusset_circuit_set_membership::Params { list_id: "country_allowlist".into() }.hash()),
            "tier_threshold:minTier=1": hex32(trusset_circuit_tier_threshold::Params { min_tier: 1 }.hash()),
            "tier_threshold:minTier=2": hex32(trusset_circuit_tier_threshold::Params { min_tier: 2 }.hash()),
            "tier_threshold:minTier=3": hex32(trusset_circuit_tier_threshold::Params { min_tier: 3 }.hash()),
            "preimage_knowledge:maxValueBytes=128": hex32(trusset_circuit_preimage_knowledge::Params { max_value_bytes: 128 }.hash()),
        },
        "lists": {
            "eea": {
                "root": eea_root,
                "depth": eea_depth,
                "entries": eea_values.len(),
                "contentHash": trusset_bundle_format::registry::list_content_hash(&eea_values),
                "sourceSha256": eea_source,
            }
        },
        "leaves": leaves,
        "positive": positive,
        "negative": negative,
        "bundleNegative": bundle_negative,
    });
    write_json(&dir.join("vectors.json"), &vectors);
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if name == "secrets.enc" {
            continue;
        }
        let src = entry.path();
        let dst = to.join(&name);
        if src.is_dir() {
            copy_dir(&src, &dst);
        } else {
            std::fs::copy(&src, &dst).unwrap();
        }
    }
}

fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    let mut k = [0u8; 32];
    k.copy_from_slice(&v);
    k
}

fn report_flag(r: &DisclosureReport, name: &str) -> bool {
    match name {
        "parsed" => r.parsed,
        "header_signature_valid" => r.header_signature_valid,
        "wallet_matches" => r.wallet_matches,
        "leaf_valid" => r.leaf_valid,
        "leaf_hash_valid" => r.leaf_hash_valid,
        "inclusion_valid" => r.inclusion_valid,
        "stark_valid" => r.stark_valid,
        other => panic!("unknown check {}", other),
    }
}

fn run_case(dir: &Path, case: &Value) -> DisclosureReport {
    let disclosure = std::fs::read(dir.join(case["disclosure"].as_str().unwrap())).unwrap();
    let proof = std::fs::read(dir.join(case["proof"].as_str().unwrap())).unwrap();
    let pk = key32(case["publicKey"].as_str().unwrap());
    let wallet = case["expectedWallet"].as_str().unwrap();
    verify_disclosure(
        &disclosure,
        &proof,
        &pk,
        if wallet.is_empty() {
            None
        } else {
            Some(wallet)
        },
    )
}

fn check(dir: &Path) {
    let v = read_json(&dir.join("vectors.json"));
    let bundle_dir: PathBuf = dir.join(v["bundleDir"].as_str().unwrap());
    let pk = key32(v["operatorPublicKey"].as_str().unwrap());
    assert_eq!(hex_lower(&pk), public_key_hex(), "fixture key drifted");

    let report = verify_bundle(
        &bundle_dir,
        &VerifyOptions {
            anchors: VerifyAnchors {
                expected_public_key: Some(pk),
                expected_root: Some(v["root"].as_str().unwrap().to_string()),
            },
            accept_stub: false,
            as_of: AsOf::Date { epoch_days: EPOCH },
            context: Default::default(),
            now_epoch_days: EPOCH,
        },
    )
    .unwrap();
    assert!(
        report.overall_pass,
        "whole-bundle verification failed: {:?}",
        report
    );
    let header_report = report.header.as_ref().expect("3.1.0 report has a header");
    assert!(header_report.present && header_report.consistent && header_report.signature_valid);
    let derived = header_report.attestation.as_ref().unwrap();
    assert_eq!(serde_json::to_value(derived).unwrap(), v["attestation"]);
    let on_disk: AttestationFile =
        serde_json::from_slice(&std::fs::read(bundle_dir.join("attestation.json")).unwrap())
            .unwrap();
    assert_eq!(&on_disk, derived);
    assert_eq!(derived.investor_class, 2);
    assert_eq!(
        derived.predicate_names,
        vec!["KYC_DONE", "ADULT", "EEA_RESIDENT"]
    );
    assert_eq!(derived.predicates, "49");

    let header: DisclosureHeader = serde_json::from_value(v["header"].clone()).unwrap();
    let signing_bytes = header.signing_bytes().unwrap();
    assert_eq!(
        hex_lower(&signing_bytes),
        v["headerSigningBytes"].as_str().unwrap()
    );
    let sig_bytes = std::fs::read(bundle_dir.join("header.sig")).unwrap();
    assert_eq!(
        format!("0x{}", hex_lower(&sig_bytes)),
        v["headerSignature"].as_str().unwrap()
    );
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    assert!(trusset_bundle_format::sign::verify_strict(
        &pk,
        &signing_bytes,
        &sig
    ));

    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(bundle_dir.join("manifest.json")).unwrap()).unwrap();
    let leaf_hashes: Vec<_> = manifest
        .leaves
        .iter()
        .map(|l| hex_to_digest(&l.leaf_hash).unwrap())
        .collect();
    let root = digest_to_hex(&compute_root_v3(&leaf_hashes).0);
    assert_eq!(root, v["root"].as_str().unwrap());
    assert_eq!(root, header.root);
    for leaf in v["leaves"].as_array().unwrap() {
        let lh = hex_to_digest(leaf["leafHash"].as_str().unwrap()).unwrap();
        let path: Vec<_> = leaf["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| hex_to_digest(p.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(
            root_from_path_v3(&lh, &path, manifest.leaves.len() as u64).map(|d| digest_to_hex(&d)),
            Some(root.clone())
        );
    }

    for (k, expected) in v["paramsHashes"].as_object().unwrap() {
        assert!(expected.as_str().unwrap().starts_with("0x"), "{}", k);
    }
    let (_, eea_root, eea_depth, _) = eea_list();
    assert_eq!(v["lists"]["eea"]["root"].as_str().unwrap(), eea_root);
    assert_eq!(
        v["lists"]["eea"]["depth"].as_u64().unwrap(),
        u64::from(eea_depth)
    );

    for case in v["positive"].as_array().unwrap() {
        let r = run_case(dir, case);
        assert!(
            r.ok,
            "positive case {} failed: {:?}",
            case["name"], r.reason
        );
    }
    for case in v["negative"].as_array().unwrap() {
        let r = run_case(dir, case);
        let failed = case["expect"]["failed"].as_str().unwrap();
        assert!(!r.ok, "negative case {} verified", case["name"]);
        assert!(
            !report_flag(&r, failed),
            "negative case {} failed {:?} but not {}",
            case["name"],
            r.reason,
            failed
        );
    }

    let manifest_bytes = std::fs::read(bundle_dir.join("manifest.json")).unwrap();
    let kyc_hash = std::fs::read_to_string(bundle_dir.join("kycHash.hex")).unwrap();
    let manifest_sig = std::fs::read(bundle_dir.join("manifest.sig")).unwrap();
    let mut proofs = std::collections::BTreeMap::new();
    for l in &manifest.leaves {
        proofs.insert(
            l.proof_path.clone(),
            std::fs::read(bundle_dir.join(&l.proof_path)).unwrap(),
        );
    }
    for case in v["bundleNegative"].as_array().unwrap() {
        let header_bytes = std::fs::read(dir.join(case["header"].as_str().unwrap())).unwrap();
        let header_sig = decode_hex(case["headerSignature"].as_str().unwrap());
        let loaded = bundle::loaded_from_parts_with_header(
            &manifest_bytes,
            &kyc_hash,
            Some(manifest_sig.clone()),
            proofs.clone(),
            Some(header_bytes),
            Some(header_sig),
        )
        .unwrap();
        let r = verify_loaded(
            &loaded,
            &VerifyOptions {
                anchors: VerifyAnchors {
                    expected_public_key: Some(pk),
                    expected_root: None,
                },
                accept_stub: false,
                as_of: AsOf::Date { epoch_days: EPOCH },
                context: Default::default(),
                now_epoch_days: EPOCH,
            },
        );
        assert!(!r.overall_pass, "bundle negative {} passed", case["name"]);
        let h = r.header.unwrap();
        match case["expect"]["failed"].as_str().unwrap() {
            "consistent" => assert!(!h.consistent),
            "signature_valid" => assert!(!h.signature_valid),
            other => panic!("unknown bundle check {}", other),
        }
    }
}

#[test]
fn v31_vectors_hold() {
    let dir = vectors_dir();
    if std::env::var("TRUSSET_VECTORS_REFRESH").as_deref() == Ok("1") {
        refresh(&dir);
    }
    assert!(
        dir.join("vectors.json").exists(),
        "test-vectors/v3.1/vectors.json is missing. Generate it with \
         TRUSSET_VECTORS_REFRESH=1 cargo test -p trusset-verifier --release --test v31_vectors"
    );
    check(&dir);
}

#[test]
fn a_fresh_build_reproduces_the_committed_vectors() {
    let dir = vectors_dir();
    if !dir.join("vectors.json").exists() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let built = build_bundle(tmp.path());
    let committed = dir.join(bundle_rel());
    for name in [
        "manifest.json",
        "manifest.sig",
        "kycHash.hex",
        "header.json",
        "header.sig",
        "attestation.json",
    ] {
        assert_eq!(
            std::fs::read(built.join(name)).unwrap(),
            std::fs::read(committed.join(name)).unwrap(),
            "{} differs from the committed vector",
            name
        );
    }
}
