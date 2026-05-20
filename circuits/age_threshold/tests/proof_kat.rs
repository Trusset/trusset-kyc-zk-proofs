//! KAT + negative-witness sweep for age_threshold (prod-proofs only).

#![cfg(feature = "prod-proofs-age")]

use sha2::{Digest as _, Sha256};
use trusset_circuit_age_threshold::{
    commit, prove, validate, verify, Params, PublicInputs, ValidateError, Witness,
};
use trusset_circuits_common::NONCE_LEN;

const AGE_18_DAYS: u64 = 18 * 365;

fn mk(dob_days: u64, nonce: u8) -> Witness {
    Witness {
        dob_days,
        nonce: [nonce; NONCE_LEN],
    }
}

fn pub_for(w: &Witness, min_age_days: u64, current_epoch_days: u64) -> PublicInputs {
    PublicInputs {
        commitment: commit(w),
        min_age_days,
        current_epoch_days,
    }
}

#[test]
fn proof_bytes_are_deterministic() {
    let w = mk(2000, 0xab);
    let p = pub_for(&w, AGE_18_DAYS, 20587);
    let a = prove(
        &w,
        &p,
        &Params {
            min_age_days: AGE_18_DAYS,
        },
    )
    .unwrap();
    let b = prove(
        &w,
        &p,
        &Params {
            min_age_days: AGE_18_DAYS,
        },
    )
    .unwrap();
    assert_eq!(Sha256::digest(&a).as_slice(), Sha256::digest(&b).as_slice());
}

#[test]
fn predicate_rejects_under_min_age() {
    // dob = epoch - 1000 days → age=1000 days, min=AGE_18 → reject.
    let epoch = 20587u64;
    let w = mk(epoch - 1000, 0xab);
    let p = pub_for(&w, AGE_18_DAYS, epoch);
    assert!(matches!(
        validate(
            &w,
            &p,
            &Params {
                min_age_days: AGE_18_DAYS
            }
        ),
        Err(ValidateError::BelowMinimum { .. })
    ));
}

#[test]
fn predicate_rejects_time_travel() {
    let w = mk(20000, 0xab);
    let p = pub_for(&w, AGE_18_DAYS, 19000);
    assert!(matches!(
        validate(
            &w,
            &p,
            &Params {
                min_age_days: AGE_18_DAYS
            }
        ),
        Err(ValidateError::TimeTravel { .. })
    ));
}

#[test]
fn exact_min_age_accepted() {
    let epoch = 20587u64;
    let w = mk(epoch - AGE_18_DAYS, 0xab);
    let p = pub_for(&w, AGE_18_DAYS, epoch);
    let bytes = prove(
        &w,
        &p,
        &Params {
            min_age_days: AGE_18_DAYS,
        },
    )
    .unwrap();
    assert!(verify(&bytes, &p).is_ok());
}

#[test]
fn different_current_epoch_invalidates_proof() {
    let w = mk(2000, 0xab);
    let p1 = pub_for(&w, AGE_18_DAYS, 20587);
    let bytes = prove(
        &w,
        &p1,
        &Params {
            min_age_days: AGE_18_DAYS,
        },
    )
    .unwrap();
    let p2 = PublicInputs {
        commitment: p1.commitment,
        min_age_days: AGE_18_DAYS,
        current_epoch_days: 20588,
    };
    assert!(verify(&bytes, &p2).is_err());
}
