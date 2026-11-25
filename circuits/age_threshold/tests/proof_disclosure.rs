//! What an `age_threshold` proof reveals: the exact date of birth.
//!
//! Winterfell 0.13 has no zero-knowledge mode. A proof carries every trace
//! column's value at the out-of-domain point `z` (the OOD frame), and anyone
//! can recompute `z` by replaying the public transcript, as the verifier
//! does. The prover fills rows 1..31 of each slack-bit column with a fixed,
//! public pattern, so row 0 (the bit) is the only unknown in that column's
//! interpolating polynomial: one OOD value is enough to solve for it. The 22
//! bits give `slack = currentEpochDays - dob - minAgeDays`, so the date of
//! birth.
//!
//! This test performs that recovery with nothing but the proof and its
//! public inputs. It documents a limitation of the current proving stack
//! (docs/SECURITY.md, "What a proof reveals"); it is not a property to keep.
//! When blinding lands, it should start failing and be replaced by a test
//! that the recovery no longer works.

#![cfg(feature = "prod-proofs-age")]

use trusset_circuit_age_threshold::air::{
    AgeAir, AgeAirPublicInputs, COL_BIT_START, NUM_SLACK_BITS,
};
use trusset_circuit_age_threshold::{commit, prove, Params, PublicInputs, Witness};
use winterfell::crypto::hashers::Rp64_256;
use winterfell::crypto::{DefaultRandomCoin, RandomCoin};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::fields::QuadExtension;
use winterfell::math::{FieldElement, StarkField, ToElements};
use winterfell::{Air, Proof};

type E = QuadExtension<BaseElement>;

/// The value the prover writes into row `row` of slack-bit column `bit` for
/// rows 1 and up (see `prover::build_trace`). Public by construction.
fn public_fill(row: u64, bit: u64) -> u64 {
    row.wrapping_mul(31).wrapping_add(bit.wrapping_mul(17) + 7)
}

fn recover_dob(proof_bytes: &[u8], public: &AgeAirPublicInputs, min_age: u64, current: u64) -> u64 {
    let proof = Proof::from_bytes(proof_bytes).unwrap();
    let mut seed = proof.context.to_elements();
    seed.append(&mut public.to_elements());
    let air = AgeAir::new(
        proof.trace_info().clone(),
        public.clone(),
        proof.options().clone(),
    );

    let fri_layers = air
        .options()
        .to_fri_options()
        .num_fri_layers(air.lde_domain_size());
    let (trace_roots, constraint_root, _) = proof
        .commitments
        .clone()
        .parse::<Rp64_256>(1, fri_layers)
        .unwrap();
    let mut coin = DefaultRandomCoin::<Rp64_256>::new(&seed);
    coin.reseed(trace_roots[0]);
    air.get_constraint_composition_coefficients::<E, _>(&mut coin)
        .unwrap();
    coin.reseed(constraint_root);
    let z: E = coin.draw().unwrap();

    let width = proof.trace_info().main_trace_width();
    let quotients = air.context().num_constraint_composition_columns();
    let (frame, _) = proof
        .ood_frame
        .clone()
        .parse::<E>(width, 0, quotients)
        .unwrap();
    let at_z = frame.current_row();

    let n = proof.trace_info().length();
    let g = BaseElement::get_root_of_unity(n.trailing_zeros());
    let n_e = E::from(BaseElement::new(n as u64));
    let vanishing = z.exp(n as u64) - E::ONE;
    let lagrange = |k: usize| -> E {
        let gk = E::from(g.exp(k as u64));
        vanishing * gk / (n_e * (z - gk))
    };

    let mut slack = 0u64;
    for bit in 0..NUM_SLACK_BITS {
        let mut known = E::ZERO;
        for row in 1..n {
            known += E::from(BaseElement::new(public_fill(row as u64, bit as u64))) * lagrange(row);
        }
        let row0 = (at_z[COL_BIT_START + bit] - known) / lagrange(0);
        let value = if row0 == E::ZERO {
            0
        } else if row0 == E::ONE {
            1
        } else {
            panic!("bit {} did not solve to 0 or 1", bit)
        };
        slack |= value << bit;
    }
    current - min_age - slack
}

#[test]
fn an_age_proof_discloses_the_exact_date_of_birth() {
    let current = 20_776u64;
    let min_age = 6_570u64;
    for dob in [7_406u64, 12_345, 1_000] {
        let witness = Witness {
            dob_days: dob,
            nonce: [0x5a; 32],
        };
        let public = PublicInputs {
            commitment: commit(&witness),
            min_age_days: min_age,
            current_epoch_days: current,
        };
        let bytes = prove(
            &witness,
            &public,
            &Params {
                min_age_days: min_age,
            },
        )
        .unwrap();
        let air_public = trusset_circuit_age_threshold::prover::public_to_air(
            &public.commitment,
            min_age,
            current,
        );
        assert_eq!(recover_dob(&bytes, &air_public, min_age, current), dob);
    }
}
