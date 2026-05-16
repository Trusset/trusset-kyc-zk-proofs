//! `tier_threshold` circuit (spec §6.3, plan edge case 12).
//!
//! Statement: "I know `(tier, nonce)` such that
//! `Rescue(COMMITMENT_TAG ‖ 1 ‖ tier ‖ nonce) == commitment`,
//!  `tier ∈ {RETAIL=1, PROFESSIONAL=2, ELIGIBLE_COUNTERPARTY=3}`,
//!  `tier >= min_tier`."
//!
//! `NONE=0` is rejected at witness construction with `E_TIER_NONE` — the
//! v2 enum (plan §"User decisions") keeps the v1 name set but maps `NONE`
//! to 0 outside the valid proof range. Operators wanting to assert "no tier
//! claim" must remove the predicate from `config.predicates` instead.
//!
//! # Status: Phase 2A — see [`crate-level docs`](self) for stub-mode caveat.

use sha2::{Digest as _, Sha256};
use trusset_circuits_common::{
    compute_commitment, digest_to_bytes, hash_bytes_with_tag, CircuitId, Digest, StubProof,
    StubProofError, NONCE_LEN, PUBLIC_DIGEST_TAG,
};
use zeroize::Zeroize;

pub const CIRCUIT_ID: CircuitId = CircuitId::TierThreshold;

/// Tier integer codes. Stable public contract (matches v1 enum name → int
/// mapping in `config.tiers`).
pub const TIER_NONE: u8 = 0;
pub const TIER_RETAIL: u8 = 1;
pub const TIER_PROFESSIONAL: u8 = 2;
pub const TIER_ELIGIBLE_COUNTERPARTY: u8 = 3;

pub const VALID_TIERS: &[u8] = &[
    TIER_RETAIL,
    TIER_PROFESSIONAL,
    TIER_ELIGIBLE_COUNTERPARTY,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Minimum acceptable tier. Must be one of `VALID_TIERS`.
    pub min_tier: u8,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            min_tier: TIER_RETAIL,
        }
    }
}

impl Params {
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"trusset-kyc-v2:tier_threshold:params");
        h.update([self.min_tier]);
        h.finalize().into()
    }
}

pub struct Witness {
    pub tier: u8,
    pub nonce: [u8; NONCE_LEN],
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.tier.zeroize();
        self.nonce.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    pub commitment: Digest,
    pub min_tier: u8,
}

impl PublicInputs {
    /// Canonical encoding: `commitment_bytes(32) ‖ min_tier(1)`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(33);
        out.extend_from_slice(&digest_to_bytes(&self.commitment));
        out.push(self.min_tier);
        out
    }

    pub fn digest(&self) -> Digest {
        hash_bytes_with_tag(&PUBLIC_DIGEST_TAG, &self.canonical_bytes())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidateError {
    /// Witnessed `tier == 0` (NONE). Maps to error code `E_TIER_NONE`.
    TierIsNone,
    /// Witnessed tier is not in `VALID_TIERS`.
    InvalidTier(u8),
    /// `min_tier` parameter is not in `VALID_TIERS`.
    InvalidMinTier(u8),
    /// `tier < min_tier`. Maps to error code `E_TIER_BELOW_MIN`.
    BelowMinimum { tier: u8, min_tier: u8 },
    CommitmentMismatch,
    /// `params.min_tier` does not match `public.min_tier`.
    MinTierMismatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// Canonical witness serialization fed into the commitment hash. Fixed
/// 1-byte layout — no length prefix needed because the layout is fixed.
fn witness_bytes(tier: u8) -> [u8; 1] {
    [tier]
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(&witness_bytes(witness.tier), &witness.nonce)
}

pub fn validate(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<(), ValidateError> {
    if witness.tier == TIER_NONE {
        return Err(ValidateError::TierIsNone);
    }
    if !VALID_TIERS.contains(&witness.tier) {
        return Err(ValidateError::InvalidTier(witness.tier));
    }
    if !VALID_TIERS.contains(&params.min_tier) {
        return Err(ValidateError::InvalidMinTier(params.min_tier));
    }
    if params.min_tier != public.min_tier {
        return Err(ValidateError::MinTierMismatch);
    }
    if witness.tier < public.min_tier {
        return Err(ValidateError::BelowMinimum {
            tier: witness.tier,
            min_tier: public.min_tier,
        });
    }
    let recomputed = compute_commitment(&witness_bytes(witness.tier), &witness.nonce);
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

/// Generate a stub proof.
///
/// # Phase 2B TODO
/// Real Winterfell AIR must enforce:
///   1. `(tier - 1)(tier - 2)(tier - 3) = 0` (range check via product gadget).
///   2. `tier - min_tier - slack = 0`, with `slack ∈ {0, 1, 2}` (also via product).
///   3. Rescue commitment opens correctly.
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
    Ok(proof.to_bytes().to_vec())
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    let parsed = StubProof::from_bytes(proof_bytes)?;
    parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(tier: u8) -> Witness {
        Witness {
            tier,
            nonce: [0x11; NONCE_LEN],
        }
    }

    fn public_inputs(w: &Witness, min_tier: u8) -> PublicInputs {
        PublicInputs {
            commitment: commit(w),
            min_tier,
        }
    }

    #[test]
    fn params_default_min_tier_is_retail() {
        assert_eq!(Params::default().min_tier, TIER_RETAIL);
    }

    #[test]
    fn validate_accepts_retail_meeting_retail_minimum() {
        let w = witness(TIER_RETAIL);
        let p = public_inputs(&w, TIER_RETAIL);
        assert!(validate(&w, &p, &Params { min_tier: TIER_RETAIL }).is_ok());
    }

    #[test]
    fn validate_accepts_eligible_meeting_professional_minimum() {
        let w = witness(TIER_ELIGIBLE_COUNTERPARTY);
        let p = public_inputs(&w, TIER_PROFESSIONAL);
        assert!(validate(&w, &p, &Params { min_tier: TIER_PROFESSIONAL }).is_ok());
    }

    #[test]
    fn validate_rejects_tier_none() {
        let w = witness(TIER_NONE);
        let p = PublicInputs {
            commitment: commit(&w),
            min_tier: TIER_RETAIL,
        };
        assert_eq!(
            validate(&w, &p, &Params { min_tier: TIER_RETAIL }),
            Err(ValidateError::TierIsNone)
        );
    }

    #[test]
    fn validate_rejects_tier_below_minimum() {
        let w = witness(TIER_RETAIL);
        let p = public_inputs(&w, TIER_PROFESSIONAL);
        assert_eq!(
            validate(&w, &p, &Params { min_tier: TIER_PROFESSIONAL }),
            Err(ValidateError::BelowMinimum {
                tier: TIER_RETAIL,
                min_tier: TIER_PROFESSIONAL,
            })
        );
    }

    #[test]
    fn validate_rejects_unknown_tier() {
        let w = witness(5);
        let p = PublicInputs {
            commitment: commit(&w),
            min_tier: TIER_RETAIL,
        };
        assert_eq!(
            validate(&w, &p, &Params { min_tier: TIER_RETAIL }),
            Err(ValidateError::InvalidTier(5))
        );
    }

    #[test]
    fn validate_rejects_invalid_min_tier() {
        let w = witness(TIER_RETAIL);
        let p = PublicInputs {
            commitment: commit(&w),
            min_tier: 7,
        };
        assert_eq!(
            validate(&w, &p, &Params { min_tier: 7 }),
            Err(ValidateError::InvalidMinTier(7))
        );
    }

    #[test]
    fn validate_rejects_params_public_min_tier_drift() {
        let w = witness(TIER_PROFESSIONAL);
        let p = public_inputs(&w, TIER_RETAIL);
        // Params says PROFESSIONAL but public_inputs says RETAIL.
        assert_eq!(
            validate(&w, &p, &Params { min_tier: TIER_PROFESSIONAL }),
            Err(ValidateError::MinTierMismatch)
        );
    }

    #[test]
    fn validate_rejects_commitment_mismatch() {
        let w = witness(TIER_RETAIL);
        let mut p = public_inputs(&w, TIER_RETAIL);
        p.commitment[1] = trusset_circuits_common::Felt::new(42);
        assert_eq!(
            validate(&w, &p, &Params { min_tier: TIER_RETAIL }),
            Err(ValidateError::CommitmentMismatch)
        );
    }

    #[test]
    fn prove_verify_roundtrip_each_tier() {
        for tier in VALID_TIERS {
            let w = witness(*tier);
            let p = public_inputs(&w, TIER_RETAIL);
            let bytes = prove(&w, &p, &Params { min_tier: TIER_RETAIL }).unwrap();
            assert!(verify(&bytes, &p).is_ok(), "tier {} failed roundtrip", tier);
        }
    }

    #[test]
    fn verify_rejects_proof_for_different_min_tier() {
        let w = witness(TIER_PROFESSIONAL);
        let p1 = public_inputs(&w, TIER_RETAIL);
        let bytes = prove(&w, &p1, &Params { min_tier: TIER_RETAIL }).unwrap();
        // Same commitment, different min_tier → different pub_digest.
        let p2 = PublicInputs {
            commitment: p1.commitment,
            min_tier: TIER_PROFESSIONAL,
        };
        assert!(verify(&bytes, &p2).is_err());
    }

    #[test]
    fn params_hash_changes_with_min_tier() {
        assert_ne!(
            Params { min_tier: TIER_RETAIL }.hash(),
            Params { min_tier: TIER_PROFESSIONAL }.hash()
        );
    }

    #[test]
    fn prove_is_deterministic() {
        let w = witness(TIER_PROFESSIONAL);
        let p = public_inputs(&w, TIER_RETAIL);
        let a = prove(&w, &p, &Params { min_tier: TIER_RETAIL }).unwrap();
        let b = prove(&w, &p, &Params { min_tier: TIER_RETAIL }).unwrap();
        assert_eq!(a, b);
    }
}
