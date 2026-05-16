//! Stable circuit identifier.
//!
//! The integer value is bound into every leaf hash (spec §7) and folded
//! into every Fiat-Shamir seed, so this enum is a public contract: never
//! renumber, never remove a variant. New circuits get new IDs at the end.

use core::convert::TryFrom;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitId {
    AgeThreshold = 1,
    SetMembership = 2,
    TierThreshold = 3,
    PreimageKnowledge = 4,
}

impl CircuitId {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Human-readable lowercase snake_case name. Used in manifests and
    /// configs; must match the JSON schema in `cli/src/config.ts`.
    pub const fn as_str(self) -> &'static str {
        match self {
            CircuitId::AgeThreshold => "age_threshold",
            CircuitId::SetMembership => "set_membership",
            CircuitId::TierThreshold => "tier_threshold",
            CircuitId::PreimageKnowledge => "preimage_knowledge",
        }
    }

    /// Parse from the canonical lowercase snake_case name. Returns `None` for
    /// any unknown variant — callers should map this to `E_CONFIG`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "age_threshold" => Some(CircuitId::AgeThreshold),
            "set_membership" => Some(CircuitId::SetMembership),
            "tier_threshold" => Some(CircuitId::TierThreshold),
            "preimage_knowledge" => Some(CircuitId::PreimageKnowledge),
            _ => None,
        }
    }
}

impl TryFrom<u8> for CircuitId {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(CircuitId::AgeThreshold),
            2 => Ok(CircuitId::SetMembership),
            3 => Ok(CircuitId::TierThreshold),
            4 => Ok(CircuitId::PreimageKnowledge),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_stable_public_contract() {
        // CRITICAL: these byte values are baked into shipped bundles.
        // Changing them invalidates every existing v2 proof.
        assert_eq!(CircuitId::AgeThreshold.as_u8(), 1);
        assert_eq!(CircuitId::SetMembership.as_u8(), 2);
        assert_eq!(CircuitId::TierThreshold.as_u8(), 3);
        assert_eq!(CircuitId::PreimageKnowledge.as_u8(), 4);
    }

    #[test]
    fn try_from_roundtrip() {
        for id in [
            CircuitId::AgeThreshold,
            CircuitId::SetMembership,
            CircuitId::TierThreshold,
            CircuitId::PreimageKnowledge,
        ] {
            assert_eq!(CircuitId::try_from(id.as_u8()).unwrap(), id);
        }
        assert!(CircuitId::try_from(0).is_err());
        assert!(CircuitId::try_from(5).is_err());
        assert!(CircuitId::try_from(255).is_err());
    }

    #[test]
    fn name_roundtrip() {
        for id in [
            CircuitId::AgeThreshold,
            CircuitId::SetMembership,
            CircuitId::TierThreshold,
            CircuitId::PreimageKnowledge,
        ] {
            assert_eq!(CircuitId::from_str(id.as_str()), Some(id));
        }
        assert_eq!(CircuitId::from_str("bogus"), None);
        assert_eq!(CircuitId::from_str(""), None);
    }
}
