//! Bundles proved by the v3.0.0 release (2.1.0 and 3.0.0 manifests) verify
//! under this verifier in strict mode, with both anchors, and are not read as
//! 3.1.0 bundles. Their bytes live in `test-vectors/legacy/`.

use std::path::PathBuf;
use trusset_verifier::{verify_bundle, AsOf, VerifyAnchors, VerifyOptions};

fn legacy_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test-vectors")
        .join("legacy")
}

#[test]
fn earlier_bundles_verify_strictly() {
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(legacy_dir().join("legacy.json")).expect("test-vectors/legacy/legacy.json"),
    )
    .unwrap();
    let pk_hex = index["operatorPublicKey"].as_str().unwrap();
    let mut pk = [0u8; 32];
    for (i, b) in pk.iter_mut().enumerate() {
        *b = u8::from_str_radix(&pk_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let bundles = index["bundles"].as_array().unwrap();
    assert!(bundles.len() >= 2);
    for b in bundles {
        let dir = legacy_dir().join(b["dir"].as_str().unwrap());
        let root = b["root"].as_str().unwrap().to_string();
        let report = verify_bundle(
            &dir,
            &VerifyOptions {
                anchors: VerifyAnchors {
                    expected_public_key: Some(pk),
                    expected_root: Some(root.clone()),
                },
                accept_stub: false,
                as_of: AsOf::Date { epoch_days: 20_776 },
                context: Default::default(),
                now_epoch_days: 20_776,
            },
        )
        .unwrap();
        assert!(
            report.overall_pass,
            "{} no longer verifies: {:?}",
            b["version"],
            report.leaves.iter().filter(|l| !l.pass).collect::<Vec<_>>()
        );
        assert_eq!(report.manifest_version, b["version"].as_str().unwrap());
        assert_eq!(report.kyc_hash, root);
        assert!(report.header.is_none());
        assert!(report.signature_valid && report.root_anchor_valid);
    }
}
