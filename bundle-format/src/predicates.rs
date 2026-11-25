//! v3.1 predicate table: the public meaning of each leaf, shared with the
//! on-chain `IdentityHub`.
//!
//! A v3.1 leaf names the predicate it proves in its binding block
//! (`binding.predicate`). The name is hashed into the binding digest and
//! therefore into the leaf hash and the root, so a leaf cannot be relabelled
//! after issuance.
//!
//! The bit numbers are the hub's `Predicates` library and the issuer
//! backend's `PREDICATE_BITS`, verbatim. Bits 0 to 63 are the fixed public
//! table; 64 to 127 are attester-defined and are not issued by this tool.
//!
//! `INVESTOR_CLASS` is not a bit. It names the `tier_threshold` leaf whose
//! public `minTier` is the attestation's `investorClass` (1 retail,
//! 2 professional, 3 eligible counterparty).
//!
//! Only predicates a circuit can actually establish may name a leaf. The
//! process predicates (`KYC_DONE`, `AML_CLEAR`, `SANCTIONS_CLEAR`,
//! `PEP_CLEAR`, `NOT_US_PERSON`, `CONTRACT_HOLDER`) are the attester's own
//! statements and are refused as leaf predicates, because no proof in a
//! bundle stands behind them.

use trusset_circuits_common::CircuitId;

/// The table, in bit order. Must match `PREDICATE_BITS` in the issuer
/// backend and `Predicates.sol` in the identity contracts.
pub const PREDICATE_BITS: [(&str, u8); 12] = [
    ("KYC_DONE", 0),
    ("AML_CLEAR", 1),
    ("SANCTIONS_CLEAR", 2),
    ("PEP_CLEAR", 3),
    ("ADULT", 4),
    ("EEA_RESIDENT", 5),
    ("NOT_US_PERSON", 6),
    ("CONTRACT_HOLDER", 7),
    ("RESIDENCY_ON_FILE", 8),
    ("CITIZENSHIP_ON_FILE", 9),
    ("TAX_RESIDENCY_ON_FILE", 10),
    ("ACCREDITED", 11),
];

/// The pseudo-predicate naming the leaf behind `investorClass`.
pub const INVESTOR_CLASS: &str = "INVESTOR_CLASS";

/// Always set in a v3.1 attestation: the bundle is a completed KYC record.
pub const KYC_DONE: &str = "KYC_DONE";

/// The list id an `EEA_RESIDENT` leaf must be proved against.
pub const EEA_LIST_ID: &str = "eea";

/// 18 years at 365 days, the tool's existing convention for `minAgeYears`.
pub const ADULT_MIN_AGE_DAYS: u64 = 6570;

/// Lowest investor class a leaf may assert as `ACCREDITED`.
pub const ACCREDITED_MIN_TIER: u64 = 2;

/// Bit number of a table predicate, or `None` for `INVESTOR_CLASS` and for
/// unknown names.
#[must_use]
pub fn bit_of(name: &str) -> Option<u8> {
    PREDICATE_BITS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, b)| *b)
}

/// Whether `name` is a predicate this tool can attach to a leaf.
#[must_use]
pub fn is_leaf_predicate(name: &str) -> bool {
    matches!(
        name,
        "ADULT"
            | "EEA_RESIDENT"
            | "RESIDENCY_ON_FILE"
            | "CITIZENSHIP_ON_FILE"
            | "TAX_RESIDENCY_ON_FILE"
            | "ACCREDITED"
            | INVESTOR_CLASS
    )
}

/// The values a leaf's predicate is checked against. Every field here must
/// come from a part of the leaf that is bound into its hash: `publicInputs`
/// (through `publicDigest`, which the verifier recomputes) or the binding
/// block (through `bindingDigest`).
#[derive(Debug, Clone, Default)]
pub struct PredicateEvidence<'a> {
    pub circuit: Option<CircuitId>,
    /// True for a `commitment_only` leaf, which carries no STARK.
    pub commitment_only: bool,
    pub min_age_days: Option<u64>,
    pub min_tier: Option<u64>,
    /// `binding.listVersion.listId`.
    pub list_id: Option<&'a str>,
}

/// Check that `name` is a leaf predicate and that the leaf's circuit and
/// parameters establish it.
pub fn check_leaf_predicate(name: &str, ev: &PredicateEvidence<'_>) -> Result<(), String> {
    if !is_leaf_predicate(name) {
        return Err(if bit_of(name).is_some() {
            format!(
                "predicate {} is an attester statement that no circuit proves, so no leaf may \
                 claim it",
                name
            )
        } else {
            format!("predicate {} is not in the predicate table", name)
        });
    }
    if ev.commitment_only {
        return Err(format!(
            "predicate {} is on a commitment_only leaf, which carries no proof",
            name
        ));
    }
    let need = |want: CircuitId| -> Result<(), String> {
        if ev.circuit == Some(want) {
            Ok(())
        } else {
            Err(format!(
                "predicate {} needs a {} leaf, found {}",
                name,
                want.as_str(),
                ev.circuit
                    .map(|c| c.as_str())
                    .unwrap_or("an unknown circuit")
            ))
        }
    };
    match name {
        "ADULT" => {
            need(CircuitId::AgeThreshold)?;
            match ev.min_age_days {
                Some(d) if d >= ADULT_MIN_AGE_DAYS => Ok(()),
                Some(d) => Err(format!(
                    "predicate ADULT needs minAgeDays >= {}, the leaf proves {}",
                    ADULT_MIN_AGE_DAYS, d
                )),
                None => Err("predicate ADULT: leaf has no minAgeDays".to_string()),
            }
        }
        "EEA_RESIDENT" => {
            need(CircuitId::SetMembership)?;
            match ev.list_id {
                Some(EEA_LIST_ID) => Ok(()),
                Some(other) => Err(format!(
                    "predicate EEA_RESIDENT needs list '{}', the leaf was proved against '{}'",
                    EEA_LIST_ID, other
                )),
                None => Err("predicate EEA_RESIDENT: leaf records no list version".to_string()),
            }
        }
        "RESIDENCY_ON_FILE" | "CITIZENSHIP_ON_FILE" | "TAX_RESIDENCY_ON_FILE" => {
            need(CircuitId::SetMembership)?;
            if ev.list_id.is_none() {
                return Err(format!("predicate {}: leaf records no list version", name));
            }
            Ok(())
        }
        "ACCREDITED" => {
            need(CircuitId::TierThreshold)?;
            match ev.min_tier {
                Some(t) if t >= ACCREDITED_MIN_TIER => Ok(()),
                _ => Err(format!(
                    "predicate ACCREDITED needs minTier >= {}",
                    ACCREDITED_MIN_TIER
                )),
            }
        }
        INVESTOR_CLASS => {
            need(CircuitId::TierThreshold)?;
            match ev.min_tier {
                Some(1..=3) => Ok(()),
                _ => Err("predicate INVESTOR_CLASS needs minTier 1, 2 or 3".to_string()),
            }
        }
        _ => Err(format!("predicate {} is not in the predicate table", name)),
    }
}

/// `u128` mask of the named table predicates. `INVESTOR_CLASS` contributes no
/// bit. Unknown names are an error.
pub fn mask_of<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<u128, String> {
    let mut mask = 0u128;
    for n in names {
        if n == INVESTOR_CLASS {
            continue;
        }
        let bit = bit_of(n).ok_or_else(|| format!("predicate {} is not in the table", n))?;
        mask |= 1u128 << bit;
    }
    Ok(mask)
}

/// Table predicate names set in `mask`, in bit order.
#[must_use]
pub fn names_of(mask: u128) -> Vec<&'static str> {
    PREDICATE_BITS
        .iter()
        .filter(|(_, b)| mask & (1u128 << b) != 0)
        .map(|(n, _)| *n)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_matches_the_hub_bits() {
        let expected = [
            "KYC_DONE",
            "AML_CLEAR",
            "SANCTIONS_CLEAR",
            "PEP_CLEAR",
            "ADULT",
            "EEA_RESIDENT",
            "NOT_US_PERSON",
            "CONTRACT_HOLDER",
            "RESIDENCY_ON_FILE",
            "CITIZENSHIP_ON_FILE",
            "TAX_RESIDENCY_ON_FILE",
            "ACCREDITED",
        ];
        for (i, name) in expected.iter().enumerate() {
            assert_eq!(bit_of(name), Some(i as u8));
        }
        assert_eq!(bit_of(INVESTOR_CLASS), None);
    }

    #[test]
    fn mask_round_trips_through_names() {
        let mask = mask_of(["KYC_DONE", "ADULT", "EEA_RESIDENT", INVESTOR_CLASS]).unwrap();
        assert_eq!(mask, 0b11_0001);
        assert_eq!(names_of(mask), vec!["KYC_DONE", "ADULT", "EEA_RESIDENT"]);
        assert!(mask_of(["NOPE"]).is_err());
    }

    fn ev(circuit: CircuitId) -> PredicateEvidence<'static> {
        PredicateEvidence {
            circuit: Some(circuit),
            ..Default::default()
        }
    }

    #[test]
    fn adult_needs_an_age_leaf_of_at_least_eighteen_years() {
        let mut e = ev(CircuitId::AgeThreshold);
        e.min_age_days = Some(6570);
        assert!(check_leaf_predicate("ADULT", &e).is_ok());
        e.min_age_days = Some(6569);
        assert!(check_leaf_predicate("ADULT", &e).is_err());
        let mut wrong = ev(CircuitId::TierThreshold);
        wrong.min_age_days = Some(9000);
        assert!(check_leaf_predicate("ADULT", &wrong).is_err());
    }

    #[test]
    fn eea_resident_needs_the_eea_list() {
        let mut e = ev(CircuitId::SetMembership);
        e.list_id = Some("eea");
        assert!(check_leaf_predicate("EEA_RESIDENT", &e).is_ok());
        e.list_id = Some("country_allowlist");
        assert!(check_leaf_predicate("EEA_RESIDENT", &e).is_err());
        e.list_id = None;
        assert!(check_leaf_predicate("EEA_RESIDENT", &e).is_err());
    }

    #[test]
    fn investor_class_and_accredited_need_tier_leaves() {
        let mut e = ev(CircuitId::TierThreshold);
        for t in 1..=3 {
            e.min_tier = Some(t);
            assert!(check_leaf_predicate(INVESTOR_CLASS, &e).is_ok());
        }
        e.min_tier = Some(0);
        assert!(check_leaf_predicate(INVESTOR_CLASS, &e).is_err());
        e.min_tier = Some(1);
        assert!(check_leaf_predicate("ACCREDITED", &e).is_err());
        e.min_tier = Some(2);
        assert!(check_leaf_predicate("ACCREDITED", &e).is_ok());
    }

    #[test]
    fn process_predicates_and_commitment_only_leaves_are_refused() {
        let e = ev(CircuitId::SetMembership);
        for name in [
            "KYC_DONE",
            "AML_CLEAR",
            "SANCTIONS_CLEAR",
            "PEP_CLEAR",
            "NOT_US_PERSON",
            "CONTRACT_HOLDER",
            "MADE_UP",
        ] {
            assert!(check_leaf_predicate(name, &e).is_err(), "{}", name);
        }
        let mut co = ev(CircuitId::PreimageKnowledge);
        co.commitment_only = true;
        co.list_id = Some("eea");
        assert!(check_leaf_predicate("RESIDENCY_ON_FILE", &co).is_err());
    }
}
