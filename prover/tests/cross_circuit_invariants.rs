//! Cross-circuit invariants — properties that span all four circuits
//! and that would be missed by per-crate tests.
//!
//! Scope: these are wire-format / cryptographic-domain-separation
//! contracts, not predicate tests. They guard against silent regressions
//! such as:
//!
//!   - A `compute_commitment` refactor that accidentally collapses
//!     `circuit_id=1` (age) and `circuit_id=3` (tier) for the same
//!     witness felts (the `circuit_id` byte in the v2 input must remain
//!     a distinguishing domain separator).
//!   - A `params_hash` refactor that produces identical hashes for two
//!     circuits' default `Params` (would let an operator silently swap
//!     predicates).
//!   - A `CircuitId::as_u8` reorder that changes the wire bytes already
//!     baked into the leaf-hash chain.
//!
//! These tests use only the public APIs of each circuit and the common
//! crate, so they exercise the integration boundary the way an external
//! consumer would.

use trusset_circuit_age_threshold as age;
use trusset_circuit_preimage_knowledge as preimage;
use trusset_circuit_set_membership as set_mem;
use trusset_circuit_tier_threshold as tier;
use trusset_circuits_common::{compute_commitment, CircuitId, Felt, NONCE_LEN};

// --------------------------------------------------------------------
// CircuitId wire-byte stability
// --------------------------------------------------------------------

/// `CircuitId::as_u8` values are part of the v2 commitment input vector
/// (the `Felt(circuit_id)` slot). Reordering or renumbering would
/// invalidate every existing bundle. Pin all four values explicitly.
#[test]
fn circuit_id_byte_values_are_pinned() {
    assert_eq!(CircuitId::AgeThreshold.as_u8(), 1, "AgeThreshold byte");
    assert_eq!(CircuitId::SetMembership.as_u8(), 2, "SetMembership byte");
    assert_eq!(CircuitId::TierThreshold.as_u8(), 3, "TierThreshold byte");
    assert_eq!(
        CircuitId::PreimageKnowledge.as_u8(),
        4,
        "PreimageKnowledge byte"
    );
}

/// CircuitId bytes are pairwise distinct (the cross-circuit domain
/// separation guarantee from `docs/SECURITY.md` §12.1).
#[test]
fn circuit_id_bytes_are_pairwise_distinct() {
    let ids = [
        CircuitId::AgeThreshold.as_u8(),
        CircuitId::SetMembership.as_u8(),
        CircuitId::TierThreshold.as_u8(),
        CircuitId::PreimageKnowledge.as_u8(),
    ];
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "CircuitId bytes {} and {} collide", i, j);
        }
    }
}

// --------------------------------------------------------------------
// Cross-circuit commitment distinctness
// --------------------------------------------------------------------

/// The same `(witness_felts, nonce)` hashed under different circuit IDs
/// MUST produce different commitments. This is the cryptographic value of
/// the `Felt(circuit_id)` separator in the v2 commitment input.
///
/// Without this property, a prover could re-use a tier=2 commitment as an
/// age=2-days commitment (both have a single witness felt with value 2),
/// which would let an attacker substitute leaves cross-circuit.
#[test]
fn same_witness_different_circuits_yields_distinct_commitments() {
    let witness = [Felt::new(42)];
    let nonce = [0x77u8; NONCE_LEN];

    let c_age = compute_commitment(CircuitId::AgeThreshold, &witness, &nonce);
    let c_tier = compute_commitment(CircuitId::TierThreshold, &witness, &nonce);
    let c_set = compute_commitment(CircuitId::SetMembership, &witness, &nonce);
    let c_preimage = compute_commitment(CircuitId::PreimageKnowledge, &witness, &nonce);

    // All four commitments must be pairwise distinct.
    let commits = [c_age, c_tier, c_set, c_preimage];
    let names = ["age", "tier", "set", "preimage"];
    for i in 0..commits.len() {
        for j in (i + 1)..commits.len() {
            assert_ne!(
                commits[i], commits[j],
                "{} and {} commitments collide for identical (witness, nonce)",
                names[i], names[j]
            );
        }
    }
}

/// Commitment determinism: same `(circuit_id, witness, nonce)` → same digest.
/// Trivially true by construction but explicit pinning catches PRNG leaks
/// or non-deterministic ordering in the absorption helper.
#[test]
fn commitment_is_deterministic_across_calls() {
    let witness = vec![Felt::new(7), Felt::new(13), Felt::new(99)];
    let nonce = [0x11u8; NONCE_LEN];
    let a = compute_commitment(CircuitId::PreimageKnowledge, &witness, &nonce);
    let b = compute_commitment(CircuitId::PreimageKnowledge, &witness, &nonce);
    let c = compute_commitment(CircuitId::PreimageKnowledge, &witness, &nonce);
    assert_eq!(a, b);
    assert_eq!(b, c);
}

/// Different nonces produce different commitments (the hiding property
/// of the commitment scheme).
#[test]
fn different_nonces_yield_distinct_commitments() {
    let witness = [Felt::new(1)];
    let n1 = [0x00u8; NONCE_LEN];
    let n2 = [0x01u8; NONCE_LEN];
    let c1 = compute_commitment(CircuitId::TierThreshold, &witness, &n1);
    let c2 = compute_commitment(CircuitId::TierThreshold, &witness, &n2);
    assert_ne!(c1, c2, "commitments must depend on the nonce");
}

// --------------------------------------------------------------------
// Cross-circuit params_hash distinctness
// --------------------------------------------------------------------

/// `params_hash` carries the operator-configurable predicate parameters
/// (min_tier, min_age_days, list_id, max_value_bytes). Different circuits'
/// default `Params` MUST hash distinctly so an operator cannot silently
/// swap one predicate for another at the `paramsHash` level.
#[test]
fn default_params_hashes_are_pairwise_distinct_across_circuits() {
    let h_age = age::Params {
        min_age_days: 18 * 365,
    }
    .hash();
    let h_tier = tier::Params {
        min_tier: tier::TIER_RETAIL,
    }
    .hash();
    let h_set = set_mem::Params {
        list_id: "country_allowlist".to_string(),
    }
    .hash();
    let h_preimage = preimage::Params::default().hash();

    let hashes = [h_age, h_tier, h_set, h_preimage];
    let names = ["age", "tier", "set", "preimage"];
    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "{} and {} default params_hash collide",
                names[i], names[j]
            );
        }
    }
}

/// `Params::hash` must be deterministic: same params → same hash across
/// repeated calls (sanity, but pins out any future use of internal HashMap
/// iteration or non-deterministic field ordering inside `hash()`).
#[test]
fn params_hash_is_deterministic() {
    let p = preimage::Params {
        max_value_bytes: 64,
    };
    assert_eq!(p.hash(), p.hash());

    let p = age::Params { min_age_days: 7305 };
    assert_eq!(p.hash(), p.hash());

    let p = tier::Params {
        min_tier: tier::TIER_PROFESSIONAL,
    };
    assert_eq!(p.hash(), p.hash());

    let p = set_mem::Params {
        list_id: "abc".to_string(),
    };
    assert_eq!(p.hash(), p.hash());
}

/// Different param values within the SAME circuit MUST produce different
/// hashes. Otherwise an operator could change `min_age_days` from 18y to
/// 0y without invalidating the determinism cache.
#[test]
fn intra_circuit_params_hash_distinguishes_values() {
    let h18 = age::Params {
        min_age_days: 18 * 365,
    }
    .hash();
    let h21 = age::Params {
        min_age_days: 21 * 365,
    }
    .hash();
    assert_ne!(h18, h21, "age min_age_days must affect params_hash");

    let h_retail = tier::Params {
        min_tier: tier::TIER_RETAIL,
    }
    .hash();
    let h_pro = tier::Params {
        min_tier: tier::TIER_PROFESSIONAL,
    }
    .hash();
    assert_ne!(h_retail, h_pro, "tier min_tier must affect params_hash");

    let h_country = set_mem::Params {
        list_id: "country".to_string(),
    }
    .hash();
    let h_country_x = set_mem::Params {
        list_id: "country_x".to_string(),
    }
    .hash();
    assert_ne!(
        h_country, h_country_x,
        "set list_id must affect params_hash"
    );

    let h_max128 = preimage::Params {
        max_value_bytes: 128,
    }
    .hash();
    let h_max256 = preimage::Params {
        max_value_bytes: 256,
    }
    .hash();
    assert_ne!(
        h_max128, h_max256,
        "preimage max_value_bytes must affect params_hash"
    );
}
