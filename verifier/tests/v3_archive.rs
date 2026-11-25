//! v3 archive round-trip: a real bundle goes into a container, the container
//! is re-parsed from bytes, and the bundle verifies out of it with no access
//! to the directory it came from.
//!
//! This is the "verify from the archive alone" property. The test deliberately
//! never touches the bundle directory after the archive is built.

use std::collections::BTreeMap;
use trusset_bundle_format::archive::{
    decode_b64, encode_b64, finalize, sha256_hex, Archive, ArchiveError, ArchivedSubject,
    ARCHIVE_VERSION,
};
use trusset_bundle_format::claims::{
    ClaimDescriptor, EvidenceClass, LegalBasis, ListVersionRef, PartyRef, ValidityInterval,
};
use trusset_bundle_format::manifest::{canonical_disk_bytes, IssuerBlock, Manifest};
use trusset_bundle_format::registry::{
    list_content_hash, ListRegistry, ListVersionRecord, RevocationEffect, RevocationLog,
    RevocationRecord, RootAnchor, RootHistory, REGISTRY_SCHEMA_VERSION,
};
use trusset_prover::{
    bundle::build_subject_bundle,
    job::{Job, JobLeaf, JobSubject, ListCommitment},
    registry_io::write_signed,
    sign::SigningSecret,
};
use trusset_verifier::{
    bundle::loaded_from_parts, verify_loaded, AsOf, TemporalContext, VerifyAnchors, VerifyOptions,
};

const EPOCH: u64 = 20689;
const WALLET: &str = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01";

fn signing() -> SigningSecret {
    SigningSecret::from_hex(&"42".repeat(32)).unwrap()
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

fn list_values() -> Vec<String> {
    ["DEU", "FRA", "USA", "GBR"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn set_root() -> (String, u8) {
    let values = list_values();
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    (trusset_circuits_common::digest_to_hex(&root), depth)
}

fn fixture_job(output_root: &str) -> Job {
    let (root, depth) = set_root();
    let mut lists = BTreeMap::new();
    lists.insert(
        "country_allowlist".to_string(),
        ListCommitment {
            values: list_values(),
            source_sha256: hex32([0xaa; 32]),
            declared_root: Some(root.clone()),
            declared_depth: Some(depth),
            version: Some(1),
            content_hash: Some(list_content_hash(&list_values())),
        },
    );
    Job {
        version: "3.0.0".into(),
        deterministic: true,
        epoch_days: EPOCH,
        output_root: output_root.into(),
        config_hash: hex32([0xcd; 32]),
        skip_proofs: true,
        epoch_days_source: Some(format!("fixed:{}", EPOCH)),
        unpinned_epoch: false,
        issuer: Some(issuer()),
        dry_run: false,
        chain: None,
        subjects: vec![JobSubject {
            subject_id: WALLET.into(),
            passthrough: serde_json::json!({}),
            leaves: vec![JobLeaf {
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
                descriptor: Some(ClaimDescriptor {
                    legal_basis: LegalBasis {
                        framework: "AMLD5".into(),
                        reference: "Art. 13(1)(a)".into(),
                        assertion: "Subject nationality is on the approved list".into(),
                    },
                    issuing_party: party(),
                    evidence_class: EvidenceClass::Documentary,
                    evidence_ref: None,
                }),
                validity: Some(ValidityInterval {
                    from: EPOCH,
                    until: Some(EPOCH + 364),
                    basis_as_of: EPOCH - 5,
                }),
                list_version: Some(ListVersionRef {
                    list_id: "country_allowlist".into(),
                    version: 1,
                    root,
                    content_hash: list_content_hash(&list_values()),
                }),
                predicate: None,
            }],
        }],
        list_commitments: lists,
    }
}

fn registry() -> ListRegistry {
    let (root, depth) = set_root();
    ListRegistry {
        schema_version: REGISTRY_SCHEMA_VERSION,
        list_id: "country_allowlist".into(),
        versions: vec![ListVersionRecord {
            version: 1,
            content_hash: list_content_hash(&list_values()),
            values: list_values(),
            root,
            depth,
            source_sha256: hex32([0xaa; 32]),
            effective_from: EPOCH - 10,
            effective_until: None,
            generator: "test".into(),
            recorded_at: "2026-08-24T00:00:00Z".into(),
            note: None,
        }],
    }
}

struct Built {
    archive_bytes: Vec<u8>,
    public_key: [u8; 32],
    root: String,
    bundle_dir: std::path::PathBuf,
    _tmp: tempfile::TempDir,
}

/// Build a bundle, then an archive around it, and return only the archive
/// bytes. Everything downstream works from those bytes.
fn build_archive(with_revocation: bool) -> Built {
    let tmp = tempfile::tempdir().unwrap();
    let job = fixture_job(tmp.path().to_str().unwrap());
    let sk = signing();
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &[7u8; 32],
        &sk,
        &[0xcd; 32],
        "2026-08-24T09:12:33Z",
    )
    .unwrap();

    let dir = report.bundle_path.clone();
    let manifest_bytes = std::fs::read(dir.join("manifest.json")).unwrap();
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes).unwrap();
    let sig = std::fs::read(dir.join("manifest.sig")).unwrap();
    let kyc_hash_hex = std::fs::read_to_string(dir.join("kycHash.hex")).unwrap();

    let mut proofs = BTreeMap::new();
    for leaf in &manifest.leaves {
        let bytes = std::fs::read(dir.join(&leaf.proof_path)).unwrap();
        proofs.insert(leaf.proof_path.clone(), encode_b64(&bytes));
    }

    // Sign the registry documents the same way the on-disk writer does, so the
    // archive's copies verify under the issuer key.
    let reg_dir = tmp.path().join("registry");
    let reg = registry();
    write_signed(&reg_dir.join("lists/country_allowlist.json"), &reg, &sk).unwrap();
    let reg_sig = std::fs::read(reg_dir.join("lists/country_allowlist.json.sig")).unwrap();

    let history = RootHistory {
        schema_version: REGISTRY_SCHEMA_VERSION,
        entries: vec![RootAnchor {
            subject: WALLET.into(),
            kyc_hash: report.kyc_hash_hex.clone(),
            epoch_days: EPOCH,
            chain_id: 1,
            block_height: 8_000_000,
            block_timestamp: EPOCH * 86_400 + 3600,
            tx_hash: None,
            manifest_sha256: sha256_hex(&manifest_bytes),
            recorded_at: "2026-08-24T00:00:00Z".into(),
        }],
    };
    write_signed(&reg_dir.join("root_history.json"), &history, &sk).unwrap();
    let history_sig = std::fs::read(reg_dir.join("root_history.json.sig")).unwrap();

    let revocations = RevocationLog {
        schema_version: REGISTRY_SCHEMA_VERSION,
        entries: if with_revocation {
            vec![RevocationRecord {
                subject: WALLET.into(),
                kyc_hash: report.kyc_hash_hex.clone(),
                leaf_name: None,
                effect: RevocationEffect::VoidAbInitio,
                effective_from: None,
                declared_at: EPOCH + 100,
                reason_code: "FRAUDULENT_ONBOARDING".into(),
                note: None,
                issuer_key_id: "issuing-2026-08".into(),
                recorded_at: "2026-12-01T00:00:00Z".into(),
            }]
        } else {
            Vec::new()
        },
    };
    write_signed(&reg_dir.join("revocations.json"), &revocations, &sk).unwrap();
    let revocations_sig = std::fs::read(reg_dir.join("revocations.json.sig")).unwrap();

    let archive = Archive {
        archive_version: ARCHIVE_VERSION.into(),
        archive_id: "test-batch".into(),
        created_at: "2026-08-24T12:00:00Z".into(),
        issuer: issuer(),
        toolchain: None,
        subjects: vec![ArchivedSubject {
            subject_id: WALLET.into(),
            manifest_sha256: sha256_hex(&manifest_bytes),
            manifest,
            manifest_sig: encode_b64(&sig),
            kyc_hash_hex: kyc_hash_hex.trim().to_string(),
            proofs,
            secrets_enc: None,
            header: None,
            header_sig: None,
        }],
        list_registries: BTreeMap::from([("country_allowlist".to_string(), reg)]),
        list_registry_signatures: BTreeMap::from([(
            "country_allowlist".to_string(),
            encode_b64(&reg_sig),
        )]),
        root_history: history,
        root_history_signature: Some(encode_b64(&history_sig)),
        revocations,
        revocations_signature: Some(encode_b64(&revocations_sig)),
        digest: String::new(),
    };
    let (_, bytes) = finalize(archive).unwrap();

    Built {
        archive_bytes: bytes,
        public_key: sk.public_key(),
        root: report.kyc_hash_hex,
        bundle_dir: dir,
        _tmp: tmp,
    }
}

/// Verify a subject straight out of archive bytes, touching nothing on disk.
fn verify_from_bytes(
    bytes: &[u8],
    pk: [u8; 32],
    as_of: AsOf,
    now: u64,
) -> trusset_verifier::VerifyReport {
    let archive = Archive::parse(bytes).unwrap();
    let subject = archive.subject(WALLET).unwrap();
    let manifest_bytes = canonical_disk_bytes(&subject.manifest).unwrap();
    let mut proofs = BTreeMap::new();
    for (path, b64) in &subject.proofs {
        proofs.insert(path.clone(), decode_b64(b64).unwrap());
    }
    let loaded = loaded_from_parts(
        &manifest_bytes,
        &subject.kyc_hash_hex,
        decode_b64(&subject.manifest_sig),
        proofs,
    )
    .unwrap();
    verify_loaded(
        &loaded,
        &VerifyOptions {
            anchors: VerifyAnchors {
                expected_public_key: Some(pk),
                expected_root: None,
            },
            accept_stub: true,
            as_of,
            context: TemporalContext {
                root_history: Some(archive.root_history.clone()),
                revocations: Some(archive.revocations.clone()),
                list_registries: archive.list_registries.clone(),
            },
            now_epoch_days: now,
        },
    )
}

#[test]
fn a_bundle_verifies_out_of_an_archive_with_no_access_to_its_directory() {
    let built = build_archive(false);
    // Remove the bundle entirely: whatever happens next cannot be reading it.
    std::fs::remove_dir_all(&built.bundle_dir).unwrap();

    let report = verify_from_bytes(&built.archive_bytes, built.public_key, AsOf::Now, EPOCH);
    assert!(report.overall_pass);
    assert!(report.temporal.entitled);
    assert_eq!(report.kyc_hash, built.root);
}

#[test]
fn the_archive_carries_the_list_values_a_proof_committed_to() {
    let built = build_archive(false);
    std::fs::remove_dir_all(&built.bundle_dir).unwrap();

    let archive = Archive::parse(&built.archive_bytes).unwrap();
    let (root, _) = set_root();
    let values = archive
        .resolve_list_values("country_allowlist", &root)
        .expect("the archive resolves a proof's setRoot back to its values");
    assert_eq!(values, &list_values());

    let report = verify_from_bytes(&built.archive_bytes, built.public_key, AsOf::Now, EPOCH);
    let claim = report.leaves[0].claim.as_ref().unwrap();
    assert_eq!(claim.list_resolved, Some(true));
    assert_eq!(claim.list_entry_count, Some(4));
}

#[test]
fn an_as_of_block_query_resolves_from_the_archive_alone() {
    let built = build_archive(false);
    std::fs::remove_dir_all(&built.bundle_dir).unwrap();

    let report = verify_from_bytes(
        &built.archive_bytes,
        built.public_key,
        AsOf::Block {
            chain_id: 1,
            height: 8_000_000,
        },
        EPOCH + 5000,
    );
    assert_eq!(report.temporal.resolved_root_matches, Some(true));
    assert!(
        report.temporal.entitled,
        "entitlement at the publishing block holds long after every window closed"
    );
}

#[test]
fn a_revocation_travels_with_the_archive() {
    let built = build_archive(true);
    std::fs::remove_dir_all(&built.bundle_dir).unwrap();

    let report = verify_from_bytes(&built.archive_bytes, built.public_key, AsOf::Now, EPOCH);
    assert!(report.overall_pass, "the proof is still valid");
    assert!(!report.temporal.entitled);
    assert_eq!(
        report.leaves[0].claim.as_ref().unwrap().status,
        "void_ab_initio"
    );
}

#[test]
fn the_archives_registry_signatures_verify_under_the_issuer_key() {
    let built = build_archive(true);
    let archive = Archive::parse(&built.archive_bytes).unwrap();
    assert!(archive
        .verify_registry_signatures(&built.public_key)
        .is_ok());

    let mut wrong = [0u8; 32];
    wrong[0] = 9;
    assert!(archive.verify_registry_signatures(&wrong).is_err());
}

#[test]
fn any_modification_to_an_archive_is_refused_at_parse() {
    let built = build_archive(false);
    let mut value: serde_json::Value = serde_json::from_slice(&built.archive_bytes).unwrap();
    value["subjects"][0]["manifest"]["passthrough"] = serde_json::json!({"tampered": true});
    let tampered = serde_json::to_vec(&value).unwrap();
    assert!(matches!(
        Archive::parse(&tampered),
        Err(ArchiveError::DigestMismatch { .. })
    ));
}

#[test]
fn an_archive_is_byte_stable_for_the_same_content() {
    let a = Archive::parse(&build_archive(false).archive_bytes).unwrap();
    let b = Archive::parse(&build_archive(false).archive_bytes).unwrap();
    assert_eq!(
        a.digest, b.digest,
        "two archives of identical content must compare equal"
    );
}
