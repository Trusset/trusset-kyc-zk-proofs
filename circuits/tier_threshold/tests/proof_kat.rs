//! KAT + negative-witness sweep for tier_threshold (prod-proofs only).

#![cfg(feature = "prod-proofs-tier")]

use sha2::{Digest as _, Sha256};
use trusset_circuit_tier_threshold::{
    commit, prove, validate, verify, Params, PublicInputs, ValidateError, Witness,
    TIER_ELIGIBLE_COUNTERPARTY, TIER_NONE, TIER_PROFESSIONAL, TIER_RETAIL, VALID_TIERS,
};
use trusset_circuits_common::NONCE_LEN;

fn mk(tier: u8, nonce: u8) -> Witness {
    Witness {
        tier,
        nonce: [nonce; NONCE_LEN],
    }
}

fn pub_for(w: &Witness, min_tier: u8) -> PublicInputs {
    PublicInputs {
        commitment: commit(w),
        min_tier,
    }
}

#[test]
fn proof_bytes_are_deterministic() {
    let w = mk(TIER_PROFESSIONAL, 0xab);
    let p = pub_for(&w, TIER_RETAIL);
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
    assert_eq!(Sha256::digest(&a).as_slice(), Sha256::digest(&b).as_slice());
}

#[test]
fn predicate_rejects_tier_none() {
    let w = mk(TIER_NONE, 0);
    let p = pub_for(&w, TIER_RETAIL);
    assert!(matches!(
        validate(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL
            }
        ),
        Err(ValidateError::TierIsNone)
    ));
}

#[test]
fn predicate_rejects_below_min_for_all_pairs() {
    for &tier in VALID_TIERS {
        for &min in VALID_TIERS {
            let w = mk(tier, 0xcc);
            let p = pub_for(&w, min);
            let r = validate(&w, &p, &Params { min_tier: min });
            if tier >= min {
                assert!(r.is_ok(), "tier={tier} min={min}: {r:?}");
            } else {
                assert!(
                    matches!(r, Err(ValidateError::BelowMinimum { .. })),
                    "tier={tier} min={min}: {r:?}"
                );
            }
        }
    }
}

#[test]
fn all_valid_tiers_roundtrip() {
    for &tier in VALID_TIERS {
        let w = mk(tier, 0x42);
        let p = pub_for(&w, TIER_RETAIL);
        let bytes = prove(
            &w,
            &p,
            &Params {
                min_tier: TIER_RETAIL,
            },
        )
        .unwrap();
        assert!(verify(&bytes, &p).is_ok(), "tier {} roundtrip", tier);
    }
}

#[test]
fn cross_min_tier_verify_fails() {
    let w = mk(TIER_ELIGIBLE_COUNTERPARTY, 0xab);
    let p_lo = pub_for(&w, TIER_RETAIL);
    let bytes = prove(
        &w,
        &p_lo,
        &Params {
            min_tier: TIER_RETAIL,
        },
    )
    .unwrap();
    let p_hi = PublicInputs {
        commitment: p_lo.commitment,
        min_tier: TIER_PROFESSIONAL,
    };
    assert!(verify(&bytes, &p_hi).is_err());
}
