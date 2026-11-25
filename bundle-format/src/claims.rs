//! v3 claim descriptors, validity intervals, and the per-leaf binding digest.
//!
//! A v2 leaf asserts a numeric predicate and nothing else: `minAgeDays: 6570`
//! says a day count was met, not which legal test that day count stands for,
//! who warrants it, or what the underlying value was checked against. v3 adds
//! three blocks per leaf:
//!
//!   - [`ClaimDescriptor`] — the legal basis, the warranting party, and the
//!     evidence class the value was verified against.
//!   - [`ValidityInterval`] — the window over which the leaf asserts its
//!     claim, plus the date the underlying evidence was examined.
//!   - [`ListVersionRef`] — for `set_membership`, which version of which list
//!     the proof was made against, so a verifier resolves the list from the
//!     leaf rather than from whatever the operator's config says today.
//!
//! The three are hashed together into a single [`LeafBinding`] digest that is
//! appended to the leaf-hash preimage. A leaf with no binding block hashes
//! exactly as it did under v2, so every bundle issued before v3 keeps its leaf
//! hashes, its `kycHash`, and its signature.

use serde::{Deserialize, Serialize};
use trusset_circuits_common::{hash_bytes_with_tag, Digest, LEAF_BIND_TAG};

/// How the underlying value was verified.
///
/// This is a labelled taxonomy, not a totally ordered scale. The variants are
/// declared roughly in order of increasing assurance, but `ThirdPartyReliance`
/// in particular carries whatever assurance the relied-upon firm actually
/// applied, which this tool cannot observe. Nothing in the codebase compares
/// two evidence classes, and no predicate accepts an evidence-class threshold:
/// treating these as comparable integers would repeat the mistake that makes a
/// bare `minTier: 1` meaningless to a reader.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    /// Subject asserted it. Not independently checked.
    #[serde(rename = "SELF_ATTESTED")]
    SelfAttested,
    /// Verified against a document copy rather than the physical or chip
    /// original.
    #[serde(rename = "DOCUMENTARY")]
    Documentary,
    /// Verified by another regulated firm under a reliance arrangement. The
    /// method that firm used is outside this bundle; `issuingParty` names who
    /// was relied on.
    #[serde(rename = "THIRD_PARTY_RELIANCE")]
    ThirdPartyReliance,
    /// Verified against an issuer or registry the operator queried directly.
    #[serde(rename = "AUTHORITATIVE_SOURCE")]
    AuthoritativeSource,
    /// Verified by a cryptographic check on an issued credential.
    #[serde(rename = "CRYPTOGRAPHIC")]
    Cryptographic,
    /// Verified with the subject and original documents physically present, or
    /// to an equivalent remote-identification assurance level.
    #[serde(rename = "PHYSICAL_PRESENCE")]
    PhysicalPresence,
}

pub const EVIDENCE_CLASSES: [&str; 6] = [
    "SELF_ATTESTED",
    "DOCUMENTARY",
    "THIRD_PARTY_RELIANCE",
    "AUTHORITATIVE_SOURCE",
    "CRYPTOGRAPHIC",
    "PHYSICAL_PRESENCE",
];

impl EvidenceClass {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceClass::SelfAttested => "SELF_ATTESTED",
            EvidenceClass::Documentary => "DOCUMENTARY",
            EvidenceClass::ThirdPartyReliance => "THIRD_PARTY_RELIANCE",
            EvidenceClass::AuthoritativeSource => "AUTHORITATIVE_SOURCE",
            EvidenceClass::Cryptographic => "CRYPTOGRAPHIC",
            EvidenceClass::PhysicalPresence => "PHYSICAL_PRESENCE",
        }
    }

    // Named `from_str` to match `CircuitId::from_str` elsewhere in the
    // workspace. Implementing `std::str::FromStr` instead would force callers
    // to name an error type for what is a plain "is this one of six strings".
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SELF_ATTESTED" => Some(EvidenceClass::SelfAttested),
            "DOCUMENTARY" => Some(EvidenceClass::Documentary),
            "THIRD_PARTY_RELIANCE" => Some(EvidenceClass::ThirdPartyReliance),
            "AUTHORITATIVE_SOURCE" => Some(EvidenceClass::AuthoritativeSource),
            "CRYPTOGRAPHIC" => Some(EvidenceClass::Cryptographic),
            "PHYSICAL_PRESENCE" => Some(EvidenceClass::PhysicalPresence),
            _ => None,
        }
    }
}

/// A named legal or natural person, identified under a public scheme where one
/// exists. Used both for the bundle-level issuer and for the per-claim
/// warranting party, which are not always the same: under a reliance
/// arrangement the issuer signs a claim another firm warrants.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PartyRef {
    pub name: String,
    /// Identifier scheme: `LEI`, `BIC`, `FCA_FRN`, `BAFIN_ID`, `CRD_ID`, or
    /// `INTERNAL` when the party has no public identifier.
    #[serde(rename = "identifierScheme")]
    pub identifier_scheme: String,
    pub identifier: String,
    /// ISO 3166-1 alpha-2 of the supervising jurisdiction.
    pub jurisdiction: String,
}

pub const IDENTIFIER_SCHEMES: [&str; 6] =
    ["LEI", "BIC", "FCA_FRN", "BAFIN_ID", "CRD_ID", "INTERNAL"];

/// The legal test a predicate stands for.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LegalBasis {
    /// Regulatory framework, e.g. `MiFID_II`, `AMLD5`, `REG_D`, `NATIONAL`.
    pub framework: String,
    /// Citation within that framework, e.g. `Annex II Section I`.
    pub reference: String,
    /// One-line statement of what is being asserted, in the operator's words.
    pub assertion: String,
}

/// What a leaf asserts, under which rule, warranted by whom, on what evidence.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClaimDescriptor {
    #[serde(rename = "legalBasis")]
    pub legal_basis: LegalBasis,
    /// The party that warrants this specific claim. Equals the bundle issuer
    /// unless the claim was verified under a reliance arrangement.
    #[serde(rename = "issuingParty")]
    pub issuing_party: PartyRef,
    #[serde(rename = "evidenceClass")]
    pub evidence_class: EvidenceClass,
    /// Operator-side reference for the evidence (case number, file ID). Must
    /// not contain subject data — it travels in cleartext inside the signed
    /// manifest.
    #[serde(
        rename = "evidenceRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_ref: Option<String>,
}

/// The window over which a leaf asserts its claim.
///
/// `from` and `until` are inclusive `epochDays`. `until: None` means the claim
/// is asserted open-ended: it does not lapse on its own, and only a revocation
/// record can end it.
///
/// `basis_as_of` is when the underlying evidence was examined, which is not the
/// same as when the claim starts. A passport checked in January and used for a
/// March issuance has `basisAsOf` in January and `from` in March; the gap is
/// exactly the staleness a reviewer wants to see.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ValidityInterval {
    pub from: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(rename = "basisAsOf")]
    pub basis_as_of: u64,
}

impl ValidityInterval {
    /// True when `at` falls inside the asserted window.
    #[must_use]
    pub fn covers(&self, at: u64) -> bool {
        at >= self.from && self.until.is_none_or(|u| at <= u)
    }

    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        match self.until {
            Some(u) => u >= self.from && self.basis_as_of <= self.from,
            None => self.basis_as_of <= self.from,
        }
    }
}

/// Which version of which list a `set_membership` proof was made against.
///
/// `root` duplicates the value already in `publicInputs.setRoot`; carrying it
/// here too means a verifier can detect a descriptor that points at a
/// different list version than the proof was actually made against, rather
/// than having to trust that they agree.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ListVersionRef {
    #[serde(rename = "listId")]
    pub list_id: String,
    pub version: u32,
    /// Rescue Merkle root of the list at this version.
    pub root: String,
    /// SHA-256 over the canonical NFC values, newline-joined. Independent of
    /// comments and formatting in the source file, unlike `sourceSha256`.
    #[serde(rename = "contentHash")]
    pub content_hash: String,
}

/// The v3 additions for one leaf, hashed as a unit into the leaf hash.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LeafBinding {
    pub descriptor: ClaimDescriptor,
    pub validity: ValidityInterval,
    #[serde(
        rename = "listVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub list_version: Option<ListVersionRef>,
    /// v3.1: the predicate this leaf proves, from the hub's predicate table
    /// (`crate::predicates`). Absent on v3.0 leaves, which keeps their binding
    /// digest unchanged, and on leaves that prove no table predicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
}

/// Canonical bytes of a binding block: compact JSON with keys sorted at every
/// depth. `serde_json::Value` is backed by `BTreeMap` throughout this
/// workspace (no `preserve_order` feature anywhere), so serializing through
/// `Value` sorts keys without a separate canonicalizer.
pub fn binding_canonical_bytes(binding: &LeafBinding) -> serde_json::Result<Vec<u8>> {
    let value = serde_json::to_value(binding)?;
    serde_json::to_vec(&value)
}

/// `binding = Rescue(LEAF_BIND_TAG ‖ canonical_json(binding))`.
pub fn compute_binding_digest(binding: &LeafBinding) -> serde_json::Result<Digest> {
    let bytes = binding_canonical_bytes(binding)?;
    Ok(hash_bytes_with_tag(&LEAF_BIND_TAG, &bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusset_circuits_common::digest_to_hex;

    fn party() -> PartyRef {
        PartyRef {
            name: "Example Bank AG".to_string(),
            identifier_scheme: "LEI".to_string(),
            identifier: "529900T8BM49AURSDO55".to_string(),
            jurisdiction: "DE".to_string(),
        }
    }

    fn binding() -> LeafBinding {
        LeafBinding {
            descriptor: ClaimDescriptor {
                legal_basis: LegalBasis {
                    framework: "MiFID_II".to_string(),
                    reference: "Annex II Section I".to_string(),
                    assertion: "Client categorised as per-se professional".to_string(),
                },
                issuing_party: party(),
                evidence_class: EvidenceClass::AuthoritativeSource,
                evidence_ref: Some("CASE-2026-0417".to_string()),
            },
            validity: ValidityInterval {
                from: 20700,
                until: Some(21065),
                basis_as_of: 20690,
            },
            list_version: None,
            predicate: None,
        }
    }

    #[test]
    fn binding_digest_is_deterministic() {
        let a = compute_binding_digest(&binding()).unwrap();
        let b = compute_binding_digest(&binding()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn binding_digest_changes_with_every_field() {
        let base = compute_binding_digest(&binding()).unwrap();

        let mut b = binding();
        b.descriptor.legal_basis.framework = "AMLD5".to_string();
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.descriptor.legal_basis.reference = "Art. 13(1)(a)".to_string();
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.descriptor.legal_basis.assertion = "something else".to_string();
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.descriptor.issuing_party.identifier = "OTHERLEI0000000000AA".to_string();
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.descriptor.evidence_class = EvidenceClass::SelfAttested;
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.descriptor.evidence_ref = None;
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.validity.from = 20701;
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.validity.until = None;
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.validity.basis_as_of = 20000;
        assert_ne!(base, compute_binding_digest(&b).unwrap());

        let mut b = binding();
        b.list_version = Some(ListVersionRef {
            list_id: "country_allowlist".to_string(),
            version: 1,
            root: format!("0x{}", "aa".repeat(32)),
            content_hash: format!("0x{}", "bb".repeat(32)),
        });
        assert_ne!(base, compute_binding_digest(&b).unwrap());
    }

    #[test]
    fn predicate_changes_the_digest_and_absence_keeps_the_v3_bytes() {
        let base = binding();
        let text = String::from_utf8(binding_canonical_bytes(&base).unwrap()).unwrap();
        assert!(!text.contains("predicate"));
        let mut adult = binding();
        adult.predicate = Some("ADULT".to_string());
        let mut eea = binding();
        eea.predicate = Some("EEA_RESIDENT".to_string());
        let d0 = compute_binding_digest(&base).unwrap();
        let d1 = compute_binding_digest(&adult).unwrap();
        let d2 = compute_binding_digest(&eea).unwrap();
        assert_ne!(d0, d1);
        assert_ne!(d1, d2);
    }

    #[test]
    fn list_version_number_alone_changes_the_digest() {
        let mut a = binding();
        a.list_version = Some(ListVersionRef {
            list_id: "country_allowlist".to_string(),
            version: 1,
            root: format!("0x{}", "aa".repeat(32)),
            content_hash: format!("0x{}", "bb".repeat(32)),
        });
        let mut b = a.clone();
        if let Some(lv) = b.list_version.as_mut() {
            lv.version = 2;
        }
        assert_ne!(
            compute_binding_digest(&a).unwrap(),
            compute_binding_digest(&b).unwrap()
        );
    }

    #[test]
    fn canonical_bytes_sort_keys_at_every_depth() {
        let bytes = binding_canonical_bytes(&binding()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let desc = text.find("\"descriptor\"").unwrap();
        let valid = text.find("\"validity\"").unwrap();
        assert!(desc < valid, "top-level keys must be sorted");
        let ec = text.find("\"evidenceClass\"").unwrap();
        let lb = text.find("\"legalBasis\"").unwrap();
        assert!(ec < lb, "nested keys must be sorted");
    }

    #[test]
    fn covers_respects_inclusive_bounds_and_open_ended() {
        let v = ValidityInterval {
            from: 100,
            until: Some(200),
            basis_as_of: 90,
        };
        assert!(!v.covers(99));
        assert!(v.covers(100));
        assert!(v.covers(200));
        assert!(!v.covers(201));

        let open = ValidityInterval {
            from: 100,
            until: None,
            basis_as_of: 90,
        };
        assert!(open.covers(100));
        assert!(open.covers(u64::MAX));
        assert!(!open.covers(99));
    }

    #[test]
    fn well_formed_rejects_inverted_and_future_basis() {
        assert!(ValidityInterval {
            from: 100,
            until: Some(200),
            basis_as_of: 100
        }
        .is_well_formed());
        assert!(!ValidityInterval {
            from: 200,
            until: Some(100),
            basis_as_of: 100
        }
        .is_well_formed());
        assert!(!ValidityInterval {
            from: 100,
            until: Some(200),
            basis_as_of: 101
        }
        .is_well_formed());
    }

    #[test]
    fn evidence_class_round_trips_through_its_wire_strings() {
        for name in EVIDENCE_CLASSES {
            let parsed = EvidenceClass::from_str(name).expect("known class");
            assert_eq!(parsed.as_str(), name);
            let json = serde_json::to_string(&parsed).unwrap();
            assert_eq!(json, format!("\"{}\"", name));
        }
        assert!(EvidenceClass::from_str("NOT_A_CLASS").is_none());
    }

    #[test]
    fn digest_is_domain_separated_from_a_bare_json_hash() {
        let bytes = binding_canonical_bytes(&binding()).unwrap();
        let tagged = compute_binding_digest(&binding()).unwrap();
        let untagged = hash_bytes_with_tag(&trusset_circuits_common::LEAF_TAG, &bytes);
        assert_ne!(digest_to_hex(&tagged), digest_to_hex(&untagged));
    }
}
