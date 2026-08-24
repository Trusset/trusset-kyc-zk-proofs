//! v3 tests: claim descriptors bound into the root, list-version resolution
//! across a rotation, as-of block verification, and the lapse/voidance
//! distinction.
//!
//! The regression this release exists to prevent is the rotation one: a bundle
//! proved against version 1 of an allowlist must keep verifying, and keep
//! resolving to version 1's values, after any number of rotations. It is the
//! first test below.

use std::collections::BTreeMap;
use trusset_bundle_format::claims::{
    ClaimDescriptor, EvidenceClass, LegalBasis, ListVersionRef, PartyRef, ValidityInterval,
};
use trusset_bundle_format::manifest::{IssuerBlock, Manifest, DISCLOSURE_PREDICATE};
use trusset_bundle_format::registry::{
    list_content_hash, ListRegistry, ListVersionRecord, RevocationEffect, RevocationLog,
    RevocationRecord, RootAnchor, RootHistory, REGISTRY_SCHEMA_VERSION,
};
use trusset_prover::{
    bundle::build_subject_bundle,
    job::{Job, JobLeaf, JobSubject, ListCommitment},
    sign::SigningSecret,
};
use trusset_verifier::{
    verify_bundle, AsOf, TemporalContext, VerifyAnchors, VerifyOptions, VerifyReport,
};

const EPOCH: u64 = 20689; // 2026-08-24
const WALLET: &str = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01";
const CHAIN: u64 = 1;

fn master_key() -> [u8; 32] {
    let mut m = [0u8; 32];
    for (i, b) in m.iter_mut().enumerate() {
        *b = i as u8;
    }
    m
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
        name: "Example Bank AG".to_string(),
        identifier_scheme: "LEI".to_string(),
        identifier: "529900T8BM49AURSDO55".to_string(),
        jurisdiction: "DE".to_string(),
    }
}

fn issuer() -> IssuerBlock {
    IssuerBlock {
        party: party(),
        public_key: hex32(signing().public_key()),
        key_id: "issuing-2026-08".to_string(),
    }
}

fn descriptor(assertion: &str, class: EvidenceClass) -> ClaimDescriptor {
    ClaimDescriptor {
        legal_basis: LegalBasis {
            framework: "AMLD5".to_string(),
            reference: "Art. 13(1)(a)".to_string(),
            assertion: assertion.to_string(),
        },
        issuing_party: party(),
        evidence_class: class,
        evidence_ref: None,
    }
}

fn validity(days: u64) -> ValidityInterval {
    ValidityInterval {
        from: EPOCH,
        until: Some(EPOCH + days - 1),
        basis_as_of: EPOCH - 10,
    }
}

/// The values that were authoritative when the bundle below was proved.
fn list_v1() -> Vec<String> {
    ["DEU", "FRA", "USA", "GBR"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The values after a rotation: one added, one removed.
fn list_v2() -> Vec<String> {
    ["DEU", "FRA", "USA", "ESP"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn set_root_of(values: &[String]) -> (String, u8) {
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = trusset_circuit_set_membership::build_set_tree(&refs);
    (trusset_circuits_common::digest_to_hex(&root), depth)
}

fn fixture_job(output_root: &str) -> Job {
    let (v1_root, v1_depth) = set_root_of(&list_v1());
    let mut lists = BTreeMap::new();
    lists.insert(
        "country_allowlist".to_string(),
        ListCommitment {
            values: list_v1(),
            source_sha256: hex32([0xaa; 32]),
            declared_root: Some(v1_root.clone()),
            declared_depth: Some(v1_depth),
            version: Some(1),
            content_hash: Some(list_content_hash(&list_v1())),
        },
    );

    Job {
        version: "3.0.0".into(),
        deterministic: true,
        epoch_days: EPOCH,
        output_root: output_root.to_string(),
        config_hash: hex32(config_hash()),
        skip_proofs: false,
        epoch_days_source: Some(format!("fixed:{}", EPOCH)),
        unpinned_epoch: false,
        issuer: Some(issuer()),
        dry_run: false,
        subjects: vec![JobSubject {
            subject_id: WALLET.into(),
            passthrough: serde_json::json!({}),
            leaves: vec![
                JobLeaf {
                    field: "nationality".into(),
                    circuit: "set_membership".into(),
                    value: serde_json::json!("GBR"),
                    public: serde_json::json!({"list_id": "country_allowlist"}),
                    params_hash: hex32(
                        trusset_circuit_set_membership::Params {
                            list_id: "country_allowlist".to_string(),
                        }
                        .hash(),
                    ),
                    disclosure: Some(DISCLOSURE_PREDICATE.to_string()),
                    params: Some(serde_json::json!({"listId": "country_allowlist"})),
                    descriptor: Some(descriptor(
                        "Subject nationality is in a jurisdiction on the approved list",
                        EvidenceClass::Documentary,
                    )),
                    validity: Some(validity(365)),
                    list_version: Some(ListVersionRef {
                        list_id: "country_allowlist".to_string(),
                        version: 1,
                        root: v1_root,
                        content_hash: list_content_hash(&list_v1()),
                    }),
                },
                JobLeaf {
                    field: "investorType".into(),
                    circuit: "tier_threshold".into(),
                    value: serde_json::json!("PROFESSIONAL"),
                    public: serde_json::json!({"min_tier": 2u64}),
                    params_hash: hex32(
                        trusset_circuit_tier_threshold::Params { min_tier: 2 }.hash(),
                    ),
                    disclosure: Some(DISCLOSURE_PREDICATE.to_string()),
                    params: Some(serde_json::json!({"minTier": 2u64})),
                    descriptor: Some(descriptor(
                        "Subject is categorised at or above professional client",
                        EvidenceClass::AuthoritativeSource,
                    )),
                    validity: Some(validity(730)),
                    list_version: None,
                },
            ],
        }],
        list_commitments: lists,
    }
}

struct Fixture {
    dir: std::path::PathBuf,
    public_key: [u8; 32],
    root: String,
    _tmp: tempfile::TempDir,
}

fn build() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let job = fixture_job(tmp.path().to_str().unwrap());
    let sk = signing();
    let report = build_subject_bundle(
        &job,
        &job.subjects[0],
        &master_key(),
        &sk,
        &config_hash(),
        "2026-08-24T09:12:33Z",
    )
    .unwrap();
    Fixture {
        dir: report.bundle_path.clone(),
        public_key: sk.public_key(),
        root: report.kyc_hash_hex.clone(),
        _tmp: tmp,
    }
}

/// A registry in which version 1 was authoritative when the bundle was proved
/// and version 2 superseded it a week later.
fn rotated_registry() -> ListRegistry {
    let (v1_root, v1_depth) = set_root_of(&list_v1());
    let (v2_root, v2_depth) = set_root_of(&list_v2());
    ListRegistry {
        schema_version: REGISTRY_SCHEMA_VERSION,
        list_id: "country_allowlist".to_string(),
        versions: vec![
            ListVersionRecord {
                version: 1,
                content_hash: list_content_hash(&list_v1()),
                values: list_v1(),
                root: v1_root,
                depth: v1_depth,
                source_sha256: hex32([0xaa; 32]),
                effective_from: EPOCH - 100,
                effective_until: Some(EPOCH + 6),
                generator: "test".to_string(),
                recorded_at: "2026-08-24T00:00:00Z".to_string(),
                note: None,
            },
            ListVersionRecord {
                version: 2,
                content_hash: list_content_hash(&list_v2()),
                values: list_v2(),
                root: v2_root,
                depth: v2_depth,
                source_sha256: hex32([0xbb; 32]),
                effective_from: EPOCH + 7,
                effective_until: None,
                generator: "test".to_string(),
                recorded_at: "2026-08-31T00:00:00Z".to_string(),
                note: Some("Sanctions review".to_string()),
            },
        ],
    }
}

fn history(block: u64) -> RootHistory {
    let f = build();
    RootHistory {
        schema_version: REGISTRY_SCHEMA_VERSION,
        entries: vec![RootAnchor {
            subject: WALLET.to_string(),
            kyc_hash: f.root,
            epoch_days: EPOCH,
            chain_id: CHAIN,
            block_height: block,
            block_timestamp: EPOCH * 86_400 + 3600,
            tx_hash: None,
            manifest_sha256: hex32([0x11; 32]),
            recorded_at: "2026-08-24T00:00:00Z".to_string(),
        }],
    }
}

fn opts(pk: [u8; 32], as_of: AsOf, ctx: TemporalContext, now: u64) -> VerifyOptions {
    VerifyOptions {
        anchors: VerifyAnchors {
            expected_public_key: Some(pk),
            expected_root: None,
        },
        accept_stub: false,
        as_of,
        context: ctx,
        now_epoch_days: now,
    }
}

fn context_with_registry() -> TemporalContext {
    let mut ctx = TemporalContext::default();
    ctx.list_registries
        .insert("country_allowlist".to_string(), rotated_registry());
    ctx
}

fn leaf<'a>(report: &'a VerifyReport, field: &str) -> &'a trusset_verifier::LeafReport {
    report
        .leaves
        .iter()
        .find(|l| l.field == field)
        .unwrap_or_else(|| panic!("no leaf named {}", field))
}

// =====================================================================
// The rotation regression
// =====================================================================

/// A bundle proved against list version 1 keeps verifying after the list has
/// rotated, and still resolves to version 1's values rather than to whatever
/// is authoritative now. This is the primary regression this release exists to
/// prevent.
#[test]
fn a_bundle_survives_a_list_rotation_and_still_resolves_to_the_version_it_used() {
    let f = build();
    let report = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, context_with_registry(), EPOCH),
    )
    .unwrap();

    assert!(report.overall_pass, "rotation must not break verification");
    assert!(report.temporal.entitled);

    let claim = leaf(&report, "nationality").claim.as_ref().unwrap();
    assert_eq!(claim.list_version, Some(1));
    assert_eq!(claim.list_resolved, Some(true));
    assert_eq!(
        claim.list_entry_count,
        Some(4),
        "the superseded version's own values must be what resolves"
    );
}

/// Without a registry the bundle still verifies — the cryptography does not
/// depend on it — but the list cannot be resolved back to a set, and the
/// report says so rather than implying it is fine.
#[test]
fn without_a_registry_the_list_is_reported_unresolved_but_the_bundle_verifies() {
    let f = build();
    let report = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, TemporalContext::default(), EPOCH),
    )
    .unwrap();

    assert!(report.overall_pass);
    let claim = leaf(&report, "nationality").claim.as_ref().unwrap();
    assert_eq!(claim.list_resolved, Some(false));
    assert_eq!(claim.list_entry_count, None);
}

// =====================================================================
// Descriptors are bound into the root
// =====================================================================

#[test]
fn the_manifest_records_the_issuer_and_the_as_of_date() {
    let f = build();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(f.dir.join("manifest.json")).unwrap()).unwrap();
    let issuer = manifest.issuer.expect("v3 manifest records an issuer");
    assert_eq!(issuer.party.name, "Example Bank AG");
    assert_eq!(issuer.party.identifier_scheme, "LEI");
    assert_eq!(issuer.key_id, "issuing-2026-08");
    assert_eq!(manifest.as_of_date.as_deref(), Some("2026-08-24"));
    assert_eq!(
        manifest.epoch_days_source.as_deref(),
        Some("fixed:20689"),
        "how the as-of date was chosen is recorded, not just what it was"
    );
    assert_eq!(manifest.unpinned_epoch, None);
    // `build_subject_bundle` is the library convenience wrapper and records no
    // toolchain: only a binary can honestly measure the digest of the binary
    // that ran. In a test process `current_exe()` is the test harness, so
    // recording it here would put a meaningless value in the manifest. The
    // `trusset-prover` binary uses `build_subject_bundle_with_toolchain`; the
    // e2e harness asserts the field is populated there.
    assert_eq!(manifest.toolchain, None);
}

#[test]
fn every_leaf_carries_a_descriptor_and_its_digest() {
    let f = build();
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(f.dir.join("manifest.json")).unwrap()).unwrap();
    for l in &manifest.leaves {
        let binding = l
            .binding
            .as_ref()
            .unwrap_or_else(|| panic!("leaf {} has no binding", l.field_name));
        assert!(!binding.descriptor.legal_basis.framework.is_empty());
        assert!(l.binding_digest.is_some());
    }
}

/// Changing a descriptor must change the root. If it did not, the descriptor
/// would be decoration rather than evidence.
#[test]
fn changing_a_descriptor_changes_the_root() {
    let tmp_a = tempfile::tempdir().unwrap();
    let job_a = fixture_job(tmp_a.path().to_str().unwrap());
    let a = build_subject_bundle(
        &job_a,
        &job_a.subjects[0],
        &master_key(),
        &signing(),
        &config_hash(),
        "2026-08-24T09:12:33Z",
    )
    .unwrap();

    let tmp_b = tempfile::tempdir().unwrap();
    let mut job_b = fixture_job(tmp_b.path().to_str().unwrap());
    job_b.subjects[0].leaves[1]
        .descriptor
        .as_mut()
        .unwrap()
        .evidence_class = EvidenceClass::SelfAttested;
    let b = build_subject_bundle(
        &job_b,
        &job_b.subjects[0],
        &master_key(),
        &signing(),
        &config_hash(),
        "2026-08-24T09:12:33Z",
    )
    .unwrap();

    assert_ne!(
        a.kyc_hash_hex, b.kyc_hash_hex,
        "the evidence class is inside the leaf hash"
    );
}

/// Rewriting a descriptor in a signed manifest must be caught even by a
/// verifier that was given no anchor beyond the key: the binding digest no
/// longer reproduces, so the leaf fails before the signature is consulted.
#[test]
fn a_rewritten_descriptor_fails_its_binding_digest() {
    let f = build();
    let path = f.dir.join("manifest.json");
    let mut manifest: Manifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest.leaves[0]
        .binding
        .as_mut()
        .unwrap()
        .descriptor
        .evidence_class = EvidenceClass::PhysicalPresence;
    std::fs::write(
        &path,
        trusset_bundle_format::manifest::canonical_disk_bytes(&manifest).unwrap(),
    )
    .unwrap();

    let report = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, TemporalContext::default(), EPOCH),
    )
    .unwrap();
    assert!(!report.overall_pass);
    let failed = report.leaves.iter().find(|l| !l.pass).unwrap();
    assert!(
        failed.reason.as_deref().unwrap().contains("bindingDigest"),
        "expected a binding digest failure, got {:?}",
        failed.reason
    );
}

// =====================================================================
// As-of verification
// =====================================================================

#[test]
fn as_of_the_publishing_block_resolves_to_this_bundles_root() {
    let f = build();
    let mut ctx = context_with_registry();
    ctx.root_history = Some(history(8_000_000));

    let report = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 8_000_000,
            },
            ctx,
            EPOCH,
        ),
    )
    .unwrap();

    assert_eq!(report.temporal.resolved_root.as_deref(), Some(&f.root[..]));
    assert_eq!(report.temporal.resolved_root_matches, Some(true));
    assert!(report.temporal.entitled);
}

/// The case that motivates the whole feature: long after every validity window
/// has closed, the entitlement question about a past block still answers YES.
#[test]
fn entitlement_at_a_past_block_holds_after_every_window_has_closed() {
    let f = build();
    let mut ctx = context_with_registry();
    ctx.root_history = Some(history(8_000_000));
    let long_after = EPOCH + 2000;

    let now = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, ctx.clone(), long_after),
    )
    .unwrap();
    assert!(now.overall_pass, "the bundle still verifies");
    assert!(
        !now.temporal.entitled,
        "but nothing is asserted for a date past every window"
    );

    let then = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 8_000_000,
            },
            ctx,
            long_after,
        ),
    )
    .unwrap();
    assert!(
        then.temporal.entitled,
        "entitlement as of the earlier block must still hold"
    );
}

/// An as-of question that cannot be resolved is answered NO, never YES.
/// Reporting entitlement from absent evidence is the one failure mode this
/// feature must not have.
#[test]
fn an_unresolvable_as_of_query_is_not_entitled() {
    let f = build();

    let mut with_history = context_with_registry();
    with_history.root_history = Some(history(8_000_000));
    let before_publish = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 7_999_999,
            },
            with_history,
            EPOCH,
        ),
    )
    .unwrap();
    assert!(before_publish.overall_pass);
    assert!(
        !before_publish.temporal.entitled,
        "nothing was on chain at that block"
    );
    assert!(before_publish
        .temporal
        .notes
        .iter()
        .any(|n| n.contains("no publication")));

    let no_history = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 8_000_000,
            },
            context_with_registry(),
            EPOCH,
        ),
    )
    .unwrap();
    assert!(
        !no_history.temporal.entitled,
        "without a root history the answer is unknown, which is not YES"
    );
    assert!(no_history
        .temporal
        .notes
        .iter()
        .any(|n| n.contains("no root history")));
}

/// A different subject's issuance at that block must not be mistaken for this
/// one.
#[test]
fn a_root_that_is_not_this_bundles_fails_the_as_of_check() {
    let f = build();
    let mut ctx = context_with_registry();
    let mut h = history(8_000_000);
    h.entries[0].kyc_hash = format!("0x{}", "ee".repeat(32));
    ctx.root_history = Some(h);

    let report = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 8_000_000,
            },
            ctx,
            EPOCH,
        ),
    )
    .unwrap();
    assert_eq!(report.temporal.resolved_root_matches, Some(false));
    assert!(!report.temporal.entitled);
}

// =====================================================================
// Validity, lapse, voidance
// =====================================================================

#[test]
fn a_claim_outside_its_window_is_reported_as_such_and_not_as_revoked() {
    let f = build();
    let report = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Now,
            context_with_registry(),
            EPOCH + 400, // past the 365-day leaf, inside the 730-day one
        ),
    )
    .unwrap();
    assert!(report.overall_pass);
    assert_eq!(
        leaf(&report, "nationality").claim.as_ref().unwrap().status,
        "outside_validity"
    );
    assert_eq!(
        leaf(&report, "investorType").claim.as_ref().unwrap().status,
        "effective"
    );
    assert!(!report.temporal.entitled);
}

fn revocation_log(effect: RevocationEffect, from: Option<u64>, root: &str) -> RevocationLog {
    RevocationLog {
        schema_version: REGISTRY_SCHEMA_VERSION,
        entries: vec![RevocationRecord {
            subject: WALLET.to_string(),
            kyc_hash: root.to_string(),
            leaf_name: Some("investorType".to_string()),
            effect,
            effective_from: from,
            declared_at: EPOCH + 300,
            reason_code: "TEST".to_string(),
            note: None,
            issuer_key_id: "issuing-2026-08".to_string(),
            recorded_at: "2026-08-24T00:00:00Z".to_string(),
        }],
    }
}

#[test]
fn a_lapse_leaves_reliance_before_its_date_standing() {
    let f = build();
    let lapse_day = EPOCH + 200;
    let mut ctx = context_with_registry();
    ctx.revocations = Some(revocation_log(
        RevocationEffect::Lapsed,
        Some(lapse_day),
        &f.root,
    ));

    let before = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, ctx.clone(), lapse_day - 1),
    )
    .unwrap();
    assert_eq!(
        leaf(&before, "investorType").claim.as_ref().unwrap().status,
        "effective"
    );
    assert!(before.temporal.entitled);

    let after = verify_bundle(&f.dir, &opts(f.public_key, AsOf::Now, ctx, lapse_day)).unwrap();
    assert_eq!(
        leaf(&after, "investorType").claim.as_ref().unwrap().status,
        "lapsed"
    );
    assert!(!after.temporal.entitled);
    assert!(
        after.overall_pass,
        "a lapsed claim does not make the bundle unverifiable"
    );
}

/// A voidance says the claim was never true, so it applies at instants before
/// it was declared — including the block the root was published at.
#[test]
fn a_voidance_applies_at_every_instant_including_before_it_was_declared() {
    let f = build();
    let mut ctx = context_with_registry();
    ctx.root_history = Some(history(8_000_000));
    ctx.revocations = Some(revocation_log(
        RevocationEffect::VoidAbInitio,
        None,
        &f.root,
    ));

    for at in [EPOCH, EPOCH + 1, EPOCH + 400] {
        let report =
            verify_bundle(&f.dir, &opts(f.public_key, AsOf::Now, ctx.clone(), at)).unwrap();
        assert_eq!(
            leaf(&report, "investorType").claim.as_ref().unwrap().status,
            "void_ab_initio",
            "voidance must apply at epoch day {}",
            at
        );
        assert!(!report.temporal.entitled);
        assert!(
            report.overall_pass,
            "the proof is still a true record of what was asserted"
        );
    }

    let at_block = verify_bundle(
        &f.dir,
        &opts(
            f.public_key,
            AsOf::Block {
                chain_id: CHAIN,
                height: 8_000_000,
            },
            ctx,
            EPOCH + 400,
        ),
    )
    .unwrap();
    assert_eq!(
        at_block.temporal.resolved_root_matches,
        Some(true),
        "the root was live then"
    );
    assert!(
        !at_block.temporal.entitled,
        "and it was still never a true claim"
    );
}

/// A revocation naming a different issuance must not touch this one.
#[test]
fn a_revocation_is_scoped_to_the_issuance_it_names() {
    let f = build();
    let mut ctx = context_with_registry();
    ctx.revocations = Some(revocation_log(
        RevocationEffect::VoidAbInitio,
        None,
        &format!("0x{}", "99".repeat(32)),
    ));

    let report = verify_bundle(&f.dir, &opts(f.public_key, AsOf::Now, ctx, EPOCH)).unwrap();
    assert_eq!(
        leaf(&report, "investorType").claim.as_ref().unwrap().status,
        "effective"
    );
    assert!(report.temporal.entitled);
}

// =====================================================================
// Reporting
// =====================================================================

#[test]
fn a_report_says_what_it_could_not_establish() {
    let f = build();
    let report = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, TemporalContext::default(), EPOCH),
    )
    .unwrap();
    assert!(
        report
            .temporal
            .notes
            .iter()
            .any(|n| n.contains("no revocation log")),
        "an absent revocation log must be stated, not assumed to mean 'not revoked'"
    );
    assert!(!report.temporal.revocations_available);
    assert!(!report.temporal.root_history_available);
}

#[test]
fn a_caller_key_disagreeing_with_the_manifest_is_flagged() {
    let f = build();
    let mut other = [0u8; 32];
    other[0] = 9;
    let report = verify_bundle(
        &f.dir,
        &opts(other, AsOf::Now, TemporalContext::default(), EPOCH),
    )
    .unwrap();
    assert!(report.issuer.unwrap().public_key_disagrees_with_anchor);
    assert!(
        !report.overall_pass,
        "and the signature check governs regardless"
    );
}

#[test]
fn the_claim_report_carries_the_legal_basis_and_evidence_class() {
    let f = build();
    let report = verify_bundle(
        &f.dir,
        &opts(f.public_key, AsOf::Now, context_with_registry(), EPOCH),
    )
    .unwrap();
    let claim = leaf(&report, "investorType").claim.as_ref().unwrap();
    assert_eq!(claim.legal_basis, "AMLD5");
    assert_eq!(claim.evidence_class, "AUTHORITATIVE_SOURCE");
    assert_eq!(claim.issuing_party, "Example Bank AG");
    assert_eq!(claim.issuing_party_identifier, "LEI:529900T8BM49AURSDO55");
    assert_eq!(claim.validity_from_date, "2026-08-24");
    assert_eq!(claim.basis_as_of_date, "2026-08-14");
}
