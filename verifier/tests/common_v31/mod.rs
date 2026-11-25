//! Shared fixture for the v3.1 tests: one subject with an `ADULT` age leaf,
//! an `EEA_RESIDENT` set-membership leaf, an `INVESTOR_CLASS` tier leaf, and
//! two commitment-only leaves (five leaves, so the tree carries padding).
//!
//! Everything is fixed: keys, batch date, chain, `createdAt`. Proofs are
//! deterministic, so a refresh reproduces the committed vectors byte for byte.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use trusset_bundle_format::claims::{
    ClaimDescriptor, EvidenceClass, LegalBasis, ListVersionRef, PartyRef, ValidityInterval,
};
use trusset_bundle_format::manifest::{ChainBinding, IssuerBlock};
use trusset_bundle_format::registry::list_content_hash;
use trusset_prover::bundle::build_subject_bundle;
use trusset_prover::job::{Job, JobLeaf, JobSubject, ListCommitment};
use trusset_prover::sign::SigningSecret;

pub const EPOCH: u64 = 20_776;
pub const WALLET: &str = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01";
pub const ATTESTER: &str = "0x1111111111111111111111111111111111111111";
pub const HUB: &str = "0x2222222222222222222222222222222222222222";
pub const CHAIN_ID: u64 = 11_155_111;
pub const KEY_ID: u32 = 1;
pub const CREATED_AT: &str = "2026-11-19T00:00:00Z";
pub const SIGNING_HEX: &str = "4242424242424242424242424242424242424242424242424242424242424242";
pub const OTHER_SIGNING_HEX: &str =
    "4343434343434343434343434343434343434343434343434343434343434343";

pub fn master_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

pub fn signing() -> SigningSecret {
    SigningSecret::from_hex(SIGNING_HEX).unwrap()
}

pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex32(bytes: [u8; 32]) -> String {
    format!("0x{}", hex_lower(&bytes))
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

pub fn vectors_dir() -> PathBuf {
    repo_root().join("test-vectors").join("v3.1")
}

pub fn party() -> PartyRef {
    PartyRef {
        name: "Example Bank AG".into(),
        identifier_scheme: "LEI".into(),
        identifier: "529900T8BM49AURSDO55".into(),
        jurisdiction: "DE".into(),
    }
}

fn descriptor(framework: &str, reference: &str, assertion: &str) -> ClaimDescriptor {
    ClaimDescriptor {
        legal_basis: LegalBasis {
            framework: framework.into(),
            reference: reference.into(),
            assertion: assertion.into(),
        },
        issuing_party: party(),
        evidence_class: EvidenceClass::Documentary,
        evidence_ref: None,
    }
}

fn validity(days: u64) -> ValidityInterval {
    ValidityInterval {
        from: EPOCH,
        until: Some(EPOCH + days - 1),
        basis_as_of: EPOCH,
    }
}

/// The published EEA list, read from the committed list-commitment file.
pub fn eea_list() -> (Vec<String>, String, u8, String) {
    let text = std::fs::read_to_string(
        repo_root()
            .join("config")
            .join("list_commitments")
            .join("eea.json"),
    )
    .expect("config/list_commitments/eea.json");
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let values: Vec<String> = v["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    let root = trusset_circuits_common::digest_to_hex(&root);
    assert_eq!(root, v["root"].as_str().unwrap(), "eea.json root drifted");
    (
        values,
        root,
        depth,
        v["sourceSha256"].as_str().unwrap().to_string(),
    )
}

pub fn job(output_root: &str) -> Job {
    let (values, root, depth, source_sha) = eea_list();
    let content = list_content_hash(&values);
    let mut lists = BTreeMap::new();
    lists.insert(
        "eea".to_string(),
        ListCommitment {
            values,
            source_sha256: source_sha,
            declared_root: Some(root.clone()),
            declared_depth: Some(depth),
            version: Some(1),
            content_hash: Some(content.clone()),
        },
    );
    let age = trusset_circuit_age_threshold::Params { min_age_days: 6570 }.hash();
    let set = trusset_circuit_set_membership::Params {
        list_id: "eea".into(),
    }
    .hash();
    let tier = trusset_circuit_tier_threshold::Params { min_tier: 2 }.hash();
    let pre = trusset_circuit_preimage_knowledge::Params {
        max_value_bytes: 128,
    }
    .hash();
    let leaves = vec![
        JobLeaf {
            field: "dateOfBirth".into(),
            circuit: "age_threshold".into(),
            value: serde_json::json!("1990-04-12"),
            public: serde_json::json!({"min_age_days": 6570u64}),
            params_hash: hex32(age),
            disclosure: Some("predicate".into()),
            params: Some(serde_json::json!({"minAgeDays": 6570u64})),
            descriptor: Some(descriptor(
                "NATIONAL",
                "contractual capacity, age of majority",
                "Subject is at or above the age of majority",
            )),
            validity: Some(validity(3650)),
            list_version: None,
            predicate: Some("ADULT".into()),
        },
        JobLeaf {
            field: "country".into(),
            circuit: "set_membership".into(),
            value: serde_json::json!("DEU"),
            public: serde_json::json!({"list_id": "eea"}),
            params_hash: hex32(set),
            disclosure: Some("predicate".into()),
            params: Some(serde_json::json!({"listId": "eea"})),
            descriptor: Some(descriptor(
                "EEA_AGREEMENT",
                "Annex VIII, right of establishment",
                "Subject residence is in an EEA member state",
            )),
            validity: Some(validity(365)),
            list_version: Some(ListVersionRef {
                list_id: "eea".into(),
                version: 1,
                root,
                content_hash: content,
            }),
            predicate: Some("EEA_RESIDENT".into()),
        },
        JobLeaf {
            field: "investorType".into(),
            circuit: "tier_threshold".into(),
            value: serde_json::json!("PROFESSIONAL"),
            public: serde_json::json!({"min_tier": 2u64}),
            params_hash: hex32(tier),
            disclosure: Some("predicate".into()),
            params: Some(serde_json::json!({"minTier": 2u64})),
            descriptor: Some(descriptor(
                "MiFID_II",
                "Annex II Section I, professional clients",
                "Subject is categorised as a professional client",
            )),
            validity: Some(validity(730)),
            list_version: None,
            predicate: Some("INVESTOR_CLASS".into()),
        },
        JobLeaf {
            field: "firstName".into(),
            circuit: "preimage_knowledge".into(),
            value: serde_json::json!("Alice"),
            public: serde_json::json!({}),
            params_hash: hex32(pre),
            disclosure: Some("commitment_only".into()),
            params: Some(serde_json::json!({"maxValueBytes": 128u64})),
            descriptor: Some(descriptor(
                "AMLD5",
                "Art. 13(1)(a), customer identification",
                "Subject given name as recorded at onboarding",
            )),
            validity: Some(validity(365)),
            list_version: None,
            predicate: None,
        },
        JobLeaf {
            field: "documentNumber".into(),
            circuit: "preimage_knowledge".into(),
            value: serde_json::json!("P12345678"),
            public: serde_json::json!({}),
            params_hash: hex32(pre),
            disclosure: Some("commitment_only".into()),
            params: Some(serde_json::json!({"maxValueBytes": 128u64})),
            descriptor: Some(descriptor(
                "AMLD5",
                "Art. 13(1)(a), customer identification",
                "Identifier of the identity document examined",
            )),
            validity: Some(validity(365)),
            list_version: None,
            predicate: None,
        },
    ];
    Job {
        version: "3.1.0".into(),
        deterministic: true,
        epoch_days: EPOCH,
        output_root: output_root.into(),
        config_hash: format!("0x{}", "ab".repeat(32)),
        skip_proofs: false,
        subjects: vec![JobSubject {
            subject_id: WALLET.into(),
            passthrough: serde_json::json!({"softExpiryDays": 365u64, "hardExpiryDays": 730u64}),
            leaves,
        }],
        list_commitments: lists,
        epoch_days_source: Some(format!("fixed:{}", EPOCH)),
        unpinned_epoch: false,
        issuer: Some(IssuerBlock {
            party: party(),
            public_key: hex32(signing().public_key()),
            key_id: "issuing-2026-11".into(),
        }),
        dry_run: false,
        chain: Some(ChainBinding {
            attester: ATTESTER.into(),
            chain_id: CHAIN_ID,
            hub: HUB.into(),
            key_id: KEY_ID,
        }),
    }
}

/// Prove the fixture subject into `out` and return its bundle directory.
pub fn build_bundle(out: &Path) -> PathBuf {
    let job = job(out.to_str().unwrap());
    job.validate().expect("fixture job validates");
    let config_hash = trusset_prover::job::parse_config_hash(&job.config_hash).unwrap();
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &signing(),
        &config_hash,
        CREATED_AT,
    )
    .expect("fixture bundle builds");
    report.bundle_path
}
