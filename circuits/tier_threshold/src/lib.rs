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
//! # Status
//!
//! - **Stub path** (`--features stub-proofs`, Phase 2A default): typed
//!   layer + 120-byte placeholder. Manifest carries `mode: "stub"`.
//! - **Prod-proofs path** (`--features prod-proofs-tier`, Phase 2B):
//!   real Winterfell roundtrip via `air`, `prover`, `verifier`. Current
//!   AIR is a PLACEHOLDER (see `air.rs` SCOPE notes) — the constraint
//!   body does not enforce the tier predicate yet.

#[cfg(feature = "prod-proofs-tier")]
pub mod air;
#[cfg(feature = "prod-proofs-tier")]
pub mod prover;
#[cfg(feature = "prod-proofs-tier")]
pub mod verifier;

use sha2::{Digest as _, Sha256};
#[cfg(not(feature = "prod-proofs-tier"))]
use trusset_circuits_common::StubProof;
use trusset_circuits_common::{
    compute_commitment, digest_to_bytes, hash_bytes_with_tag, CircuitId, Digest, Felt,
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

pub const VALID_TIERS: &[u8] = &[TIER_RETAIL, TIER_PROFESSIONAL, TIER_ELIGIBLE_COUNTERPARTY];

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
    BelowMinimum {
        tier: u8,
        min_tier: u8,
    },
    CommitmentMismatch,
    /// `params.min_tier` does not match `public.min_tier`.
    MinTierMismatch,
    /// Winterfell prover failed (prod-proofs-tier path only).
    WinterfellProverError(String),
}

#[derive(Debug)]
pub enum VerifyError {
    StubProofMalformed(StubProofError),
    #[cfg(feature = "prod-proofs-tier")]
    WinterfellVerifyError(verifier::AirVerifyError),
}

impl From<StubProofError> for VerifyError {
    fn from(e: StubProofError) -> Self {
        VerifyError::StubProofMalformed(e)
    }
}

/// Canonical felt-encoding of the witness for the v2 commitment scheme.
/// A 1-felt vector carrying the tier value — fixed-length, no padding.
pub fn witness_to_felts(tier: u8) -> [Felt; 1] {
    [Felt::new(u64::from(tier))]
}

pub fn commit(witness: &Witness) -> Digest {
    compute_commitment(CIRCUIT_ID, &witness_to_felts(witness.tier), &witness.nonce)
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
    let recomputed =
        compute_commitment(CIRCUIT_ID, &witness_to_felts(witness.tier), &witness.nonce);
    if recomputed != public.commitment {
        return Err(ValidateError::CommitmentMismatch);
    }
    Ok(())
}

/// Generate a proof. Stub path under default features; real Winterfell
/// (placeholder AIR) under `prod-proofs-tier`.
pub fn prove(
    witness: &Witness,
    public: &PublicInputs,
    params: &Params,
) -> Result<Vec<u8>, ValidateError> {
    validate(witness, public, params)?;
    #[cfg(feature = "prod-proofs-tier")]
    {
        use trusset_circuits_common::stark_options;
        let pi = prover::public_to_air(&public.commitment, public.min_tier);
        let seed = [0u8; 32];
        let bytes = prover::build_proof(
            witness.tier,
            &witness.nonce,
            public.min_tier,
            &pi,
            stark_options(),
            &seed,
        )
        .map_err(|e| ValidateError::WinterfellProverError(format!("{e:?}")))?;
        Ok(bytes)
    }
    #[cfg(not(feature = "prod-proofs-tier"))]
    {
        let proof = StubProof::build(CIRCUIT_ID, public.commitment, public.digest());
        Ok(proof.to_bytes().to_vec())
    }
}

pub fn verify(proof_bytes: &[u8], public: &PublicInputs) -> Result<(), VerifyError> {
    #[cfg(feature = "prod-proofs-tier")]
    {
        let pi = prover::public_to_air(&public.commitment, public.min_tier);
        verifier::verify_proof(proof_bytes, pi).map_err(VerifyError::WinterfellVerifyError)
    }
    #[cfg(not(feature = "prod-proofs-tier"))]
    {
        let parsed = StubProof::from_bytes(proof_bytes)?;
        parsed.check(CIRCUIT_ID, &public.commitment, &public.digest())?;
        Ok(())
    }
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
        assert!(validate(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_accepts_eligible_meeting_professional_minimum() {
        let w = witness(TIER_ELIGIBLE_COUNTERPARTY);
        let p = public_inputs(&w, TIER_PROFESSIONAL);
        assert!(validate(
            &w,
            &p,
            &Params {
                min_tier: TIER_PROFESSIONAL
            }
        )
        .is_ok());
    }

    #[test]
    fn validate_rejects_tier_none() {
        let w = witness(TIER_NONE);
        let p = PublicInputs {
            commitment: commit(&w),
            min_tier: TIER_RETAIL,
        };
        assert_eq!(
            validate(
                &w,
                &p,
                &Params {
                    min_tier: TIER_RETAIL
                }
            ),
            Err(ValidateError::TierIsNone)
        );
    }

    #[test]
    fn validate_rejects_tier_below_minimum() {
        let w = witness(TIER_RETAIL);
        let p = public_inputs(&w, TIER_PROFESSIONAL);
        assert_eq!(
            validate(
                &w,
                &p,
                &Params {
                    min_tier: TIER_PROFESSIONAL
                }
            ),
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
            validate(
                &w,
                &p,
                &Params {
                    min_tier: TIER_RETAIL
                }
            ),
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
            validate(
                &w,
                &p,
                &Params {
                    min_tier: TIER_PROFESSIONAL
                }
            ),
            Err(ValidateError::MinTierMismatch)
        );
    }

    #[test]
    fn validate_rejects_commitment_mismatch() {
        let w = witness(TIER_RETAIL);
        let mut p = public_inputs(&w, TIER_RETAIL);
        p.commitment[1] = trusset_circuits_common::Felt::new(42);
        assert_eq!(
            validate(
                &w,
                &p,
                &Params {
                    min_tier: TIER_RETAIL
                }
            ),
            Err(ValidateError::CommitmentMismatch)
        );
    }

    #[test]
    fn prove_verify_roundtrip_each_tier() {
        for tier in VALID_TIERS {
            let w = witness(*tier);
            let p = public_inputs(&w, TIER_RETAIL);
            let bytes = prove(
                &w,
                &p,
                &Params {
                    min_tier: TIER_RETAIL,
                },
            )
            .unwrap();
            assert!(verify(&bytes, &p).is_ok(), "tier {} failed roundtrip", tier);
        }
    }

    #[test]
    fn verify_rejects_proof_for_different_min_tier() {
        let w = witness(TIER_PROFESSIONAL);
        let p1 = public_inputs(&w, TIER_RETAIL);
        let bytes = prove(
            &w,
            &p1,
            &Params {
                min_tier: TIER_RETAIL,
            },
        )
        .unwrap();
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
            Params {
                min_tier: TIER_RETAIL
            }
            .hash(),
            Params {
                min_tier: TIER_PROFESSIONAL
            }
            .hash()
        );
    }

    #[test]
    fn prove_is_deterministic() {
        let w = witness(TIER_PROFESSIONAL);
        let p = public_inputs(&w, TIER_RETAIL);
        let a = prove(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL,
            },
        )
        .unwrap();
        let b = prove(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL,
            },
        )
        .unwrap();
        assert_eq!(a, b);
    }

    // -------------------------------------------------------------
    // AIR-time negative-witness sweeps (Stage 5a)
    //
    // These bypass `validate()` and invoke `prover::build_proof` directly
    // with spec-violating witnesses. The AIR Pattern A predicate columns
    // (acc_tier and acc_slack) MUST cause the prover to fail before
    // emitting a proof, confirming in-AIR soundness (not just
    // out-of-AIR validate() filtering).
    // -------------------------------------------------------------

    #[cfg(feature = "prod-proofs-tier")]
    fn try_prove_air_only(tier: u8, min_tier: u8) -> Result<Vec<u8>, String> {
        use trusset_circuits_common::{compute_commitment, stark_options, CircuitId, Felt};
        // Compute the v2 commitment for the (possibly invalid) tier value
        // so the AIR's commitment-opening check passes — only the Pattern A
        // predicate should reject.
        let nonce = [0x11u8; NONCE_LEN];
        let witness_felts = [Felt::new(u64::from(tier))];
        let commitment = compute_commitment(CircuitId::TierThreshold, &witness_felts, &nonce);
        let pi = prover::public_to_air(&commitment, min_tier);

        // Debug builds: Winterfell `debug_assert!`s panic on bad trace.
        // Release builds: `debug_assert!`s compiled out; prover emits invalid
        // bytes which the verifier then rejects. Chain prove+verify so the
        // wrapper's rejection contract holds in both profiles.
        let prove_result = std::panic::catch_unwind(|| {
            prover::build_proof(tier, &nonce, min_tier, &pi, stark_options(), &[0u8; 32])
        });
        let proof_bytes = match prove_result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(format!("ProverError: {e:?}")),
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| {
                        panic_payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                    })
                    .unwrap_or_else(|| "unknown panic".to_string());
                return Err(format!("Prover panic: {msg}"));
            }
        };
        let pi_verify = prover::public_to_air(&commitment, min_tier);
        match verifier::verify_proof(&proof_bytes, pi_verify) {
            Ok(()) => Ok(proof_bytes),
            Err(e) => Err(format!("VerifierError: {e:?}")),
        }
    }

    #[cfg(feature = "prod-proofs-tier")]
    #[test]
    fn air_rejects_tier_zero() {
        // tier = 0: Pattern A `(0-1)(0-2)(0-3) = -6 ≠ 0` → acc_tier[3] ≠ 0
        // → boundary constraint fails at prove time.
        let result = try_prove_air_only(0, TIER_RETAIL);
        assert!(
            result.is_err(),
            "AIR must reject tier=0 (out of {{1,2,3}}), got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-tier")]
    #[test]
    fn air_rejects_tier_four() {
        // tier = 4: Pattern A `(4-1)(4-2)(4-3) = 6 ≠ 0` → acc_tier[3] ≠ 0
        let result = try_prove_air_only(4, TIER_RETAIL);
        assert!(
            result.is_err(),
            "AIR must reject tier=4 (out of {{1,2,3}}), got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-tier")]
    #[test]
    fn air_rejects_tier_five() {
        let result = try_prove_air_only(5, TIER_RETAIL);
        assert!(
            result.is_err(),
            "AIR must reject tier=5 (out of {{1,2,3}}), got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-tier")]
    #[test]
    fn air_rejects_tier_below_min_tier() {
        // tier=1, min_tier=2: slack = 1 - 2 (wrap in u8) = 255 (≠ 0, 1, 2)
        // → Pattern A on slack: (255-0)(255-1)(255-2) ≠ 0 → acc_slack[3] ≠ 0
        // → boundary fails at prove time.
        let result = try_prove_air_only(1, 2);
        assert!(
            result.is_err(),
            "AIR must reject tier=1 with min_tier=2 (tier < min_tier), got Ok"
        );
    }

    #[cfg(feature = "prod-proofs-tier")]
    #[test]
    fn air_accepts_each_valid_tier_with_matching_min() {
        // Positive control: the negative tests above are only meaningful
        // if the AIR ACCEPTS valid witnesses through the same code path.
        for tier in [1u8, 2, 3] {
            let result = try_prove_air_only(tier, TIER_RETAIL);
            assert!(
                result.is_ok(),
                "AIR must accept tier={tier} with min_tier=1, got {:?}",
                result.err()
            );
        }
    }
}
