//! What a `set_membership` proof reveals: the committed value itself.
//!
//! The AIR binds the witness through columns 12..24, which the prover holds
//! constant over all 2048 rows. A constant column's polynomial is that
//! constant, so its out-of-domain value in the proof's OOD frame is the
//! witness felt, in the clear. No transcript replay is needed. For an
//! `EEA_RESIDENT` leaf that is the country code.
//!
//! The proof checked here is the `country` leaf of the committed v3.1 test
//! vectors (`test-vectors/v3.1`), proved for "DEU". This documents a
//! limitation of the current proving stack (docs/SECURITY.md, "What a proof
//! reveals"); when blinding lands it should start failing.

#![cfg(feature = "prod-proofs-set")]

use trusset_circuit_set_membership::air::{SetAir, COL_WITNESS_START};
use trusset_circuit_set_membership::prover::public_to_air;
use trusset_circuit_set_membership::{witness_to_felts, MAX_PADDED_WITNESS_FELTS};
use trusset_circuits_common::field_to_bytes;
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::fields::QuadExtension;
use winterfell::math::FieldElement;
use winterfell::{Air, Proof};

type E = QuadExtension<BaseElement>;

#[test]
fn a_set_membership_proof_discloses_the_committed_value() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/v3.1/bundle/0xAbCdEf0123456789AbCdEf0123456789AbCdEf01/proofs/country.bin");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let proof = Proof::from_bytes(&bytes).unwrap();
    let zero = [BaseElement::ZERO; 4];
    let air = SetAir::new(
        proof.trace_info().clone(),
        public_to_air(&zero, &zero, 5),
        proof.options().clone(),
    );
    let width = proof.trace_info().main_trace_width();
    let quotients = air.context().num_constraint_composition_columns();
    let (frame, _) = proof
        .ood_frame
        .clone()
        .parse::<E>(width, 0, quotients)
        .unwrap();
    let mut felts = Vec::new();
    for e in &frame.current_row()[COL_WITNESS_START..COL_WITNESS_START + MAX_PADDED_WITNESS_FELTS] {
        let parts = E::slice_as_base_elements(std::slice::from_ref(e));
        assert_eq!(
            parts[1],
            BaseElement::ZERO,
            "a constant column evaluates into the base field"
        );
        felts.push(parts[0]);
    }
    assert_eq!(felts, witness_to_felts(b"DEU"));
    let bytes = field_to_bytes(&felts);
    let end = bytes.iter().rposition(|b| *b == 0x01).unwrap();
    assert_eq!(&bytes[..end], b"DEU");
}
