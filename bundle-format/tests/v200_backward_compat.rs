//! v2.0.0 manifest backward compatibility.
//!
//! The v2.1 schema additions are optional-with-omission, which is what
//! keeps existing signatures valid: parsing a v2.0.0 manifest and
//! re-serializing it must reproduce the original bytes exactly. If it did
//! not, every bundle issued before v2.1 would fail signature verification
//! under the new code, and the issuer backend's vendored verifier would
//! disagree with the tool about what was signed.
//!
//! The fixture is a real v2.0.0 manifest produced by the shipped v2.0
//! prover, captured at `tests/fixtures/v2.0.0_manifest.json`.

use trusset_bundle_format::manifest::{
    canonical_disk_bytes, canonical_signing_bytes, Manifest, ACCEPTED_MANIFEST_VERSIONS,
};
use trusset_bundle_format::merkle::MERKLE_VERSION_V1;

fn fixture_bytes() -> Vec<u8> {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("tests");
    p.push("fixtures");
    p.push("v2.0.0_manifest.json");
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {} unreadable: {}", p.display(), e))
}

fn fixture() -> Manifest {
    serde_json::from_slice(&fixture_bytes())
        .expect("v2.0.0 manifest must parse under the v2.1 schema")
}

#[test]
fn v200_manifest_parses_under_the_v21_schema() {
    let m = fixture();
    assert_eq!(m.version, "2.0.0");
    assert!(ACCEPTED_MANIFEST_VERSIONS.contains(&m.version.as_str()));
    assert_eq!(m.leaves.len(), 9);
    // Every v2.1 addition is absent on a v2.0 bundle.
    assert!(m.merkle_version.is_none());
    assert!(m.config_hash.is_none());
    for leaf in &m.leaves {
        assert!(
            leaf.disclosure.is_none(),
            "{} has a disclosure",
            leaf.field_name
        );
        assert!(leaf.params.is_none(), "{} has params", leaf.field_name);
    }
}

#[test]
fn v200_manifest_defaults_to_the_v1_merkle_construction() {
    assert_eq!(fixture().effective_merkle_version(), MERKLE_VERSION_V1);
}

#[test]
fn v200_manifest_reserializes_byte_identically() {
    let original = fixture_bytes();
    let parsed = fixture();
    let round_tripped = canonical_disk_bytes(&parsed).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&round_tripped),
        String::from_utf8_lossy(&original),
        "a v2.0.0 manifest must re-serialize byte-identically, or its signature breaks under v2.1"
    );
}

#[test]
fn v200_signing_view_is_unchanged_by_the_v21_schema() {
    let parsed = fixture();
    let signing = canonical_signing_bytes(&parsed).unwrap();
    let text = String::from_utf8(signing).unwrap();
    // None of the v2.1 keys may appear in the payload the signature covers.
    for key in ["merkleVersion", "configHash", "disclosure", "\"params\""] {
        assert!(
            !text.contains(key),
            "v2.1 key {} leaked into a v2.0.0 signing view",
            key
        );
    }
    assert!(text.contains(r#""createdAt": "1970-01-01T00:00:00Z""#));
}

#[test]
fn v200_recorded_root_recomputes_under_v1() {
    use trusset_circuits_common::{digest_to_hex, hex_to_digest};
    let m = fixture();
    let leaves: Vec<_> = m
        .leaves
        .iter()
        .map(|l| hex_to_digest(&l.leaf_hash).expect("leafHash hex"))
        .collect();
    let (root, _) = trusset_bundle_format::merkle::compute_root_versioned(
        &leaves,
        m.effective_merkle_version(),
    )
    .expect("v1 construction is supported");
    assert_eq!(
        digest_to_hex(&root),
        m.kyc_hash,
        "the recorded v2.0.0 kycHash must still recompute from its own leaf hashes"
    );
}
