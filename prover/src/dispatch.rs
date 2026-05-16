//! Per-leaf circuit routing.
//!
//! Each `JobLeaf` is routed to one of the four circuits. This module owns
//! the witness/public-input construction from the JSON-typed `value` and
//! `public` fields and produces a fully-bound `ProvedLeaf` ready for
//! manifest assembly.

use crate::errors::{ErrorCode, ProverError, Result};
use crate::job::{JobLeaf, JobSubject, ListCommitment};
use crate::leaf::{compute_leaf_hash, compute_proof_digest};
use serde::Serialize;
use std::collections::BTreeMap;
use trusset_circuit_age_threshold as age;
use trusset_circuit_preimage_knowledge as preimage;
use trusset_circuit_set_membership as set;
use trusset_circuit_tier_threshold as tier;
use trusset_circuits_common::{derive_leaf_seed, digest_to_hex, CircuitId, Digest};
use zeroize::Zeroizing;

/// Fully bound output of `prove_leaf`.
pub struct ProvedLeaf {
    pub field: String,
    pub circuit_id: CircuitId,
    pub commitment: Digest,
    pub public_digest: Digest,
    pub proof_digest: Digest,
    pub proof_bytes: Vec<u8>,
    pub leaf_hash: Digest,
    /// JSON-typed public-inputs block for `manifest.leaves[].publicInputs`.
    pub manifest_public_inputs: serde_json::Value,
    pub params_hash_hex: String,
    /// Raw witness fields preserved for `secrets.enc` (zeroed on drop).
    pub plaintext_value: Zeroizing<String>,
    pub nonce: Zeroizing<[u8; 32]>,
    pub took_ms: u64,
}

/// JSON shape stored in `secrets.enc` (per-leaf entry).
#[derive(Serialize)]
pub struct SecretsEntry {
    pub value: String,
    pub nonce_hex: String,
    pub circuit: String,
}

pub fn prove_leaf(
    subject_seed: &[u8; 32],
    subject: &JobSubject,
    epoch_days: u64,
    leaf: &JobLeaf,
    list_commitments: &BTreeMap<String, ListCommitment>,
    skip_proofs: bool,
) -> Result<ProvedLeaf> {
    let start = std::time::Instant::now();
    let circuit_id = parse_circuit_id(&leaf.circuit)?;
    let params_hash = leaf.params_hash_bytes()?;

    let leaf_seed = derive_leaf_seed(
        subject_seed,
        leaf.field.as_bytes(),
        circuit_id.as_u8(),
        &params_hash,
    );
    let nonce: Zeroizing<[u8; 32]> = Zeroizing::new(*leaf_seed);

    let plaintext_value = leaf_value_as_string(&leaf.value)?;
    let wallet_bytes = subject.wallet_bytes()?;

    let (commitment, public_digest, manifest_public_inputs, mut proof_bytes) = match circuit_id {
        CircuitId::PreimageKnowledge => prove_preimage(leaf, &plaintext_value, &nonce)?,
        CircuitId::TierThreshold => prove_tier(leaf, &plaintext_value, &nonce)?,
        CircuitId::AgeThreshold => prove_age(leaf, &plaintext_value, &nonce, epoch_days)?,
        CircuitId::SetMembership => prove_set(leaf, &plaintext_value, &nonce, list_commitments)?,
    };

    // `--skip-proofs` mode: replace the binding placeholder proof with a
    // zero-byte file. The leaf hash still encodes the (now-empty)
    // proof_digest, so any tamper attempt that swaps a zero-byte file for
    // a real proof breaks the manifest signature too.
    if skip_proofs {
        proof_bytes.clear();
    }

    let proof_digest = compute_proof_digest(&proof_bytes);
    let leaf_hash = compute_leaf_hash(
        &leaf.field,
        circuit_id,
        &wallet_bytes,
        epoch_days,
        &commitment,
        &public_digest,
        &proof_digest,
    );

    Ok(ProvedLeaf {
        field: leaf.field.clone(),
        circuit_id,
        commitment,
        public_digest,
        proof_digest,
        proof_bytes,
        leaf_hash,
        manifest_public_inputs,
        params_hash_hex: format!("0x{}", hex::encode(params_hash)),
        plaintext_value: Zeroizing::new(plaintext_value),
        nonce,
        took_ms: start.elapsed().as_millis() as u64,
    })
}

fn parse_circuit_id(name: &str) -> Result<CircuitId> {
    CircuitId::from_str(name).ok_or_else(|| {
        ProverError::new(
            ErrorCode::Config,
            format!("unknown circuit: {}", name),
        )
    })
}

fn leaf_value_as_string(v: &serde_json::Value) -> Result<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(ProverError::input(
            "leaf.value must be a string, number, or boolean",
        )),
    }
}

// ============================ preimage_knowledge ============================

fn prove_preimage(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let value_bytes = nfc_bytes(value_str);
    let params = preimage::Params::default();
    let witness = preimage::Witness {
        value: value_bytes.clone(),
        nonce: *nonce,
    };
    let commitment = preimage::commit(&witness);
    let public = preimage::PublicInputs { commitment };

    let bytes = preimage::prove(&witness, &public, &params).map_err(|e| {
        ProverError::new(
            ErrorCode::CircuitInternal,
            format!("preimage_knowledge prove: {:?}", e),
        )
    })?;

    let manifest_pub = serde_json::json!({
        "commitment": digest_to_hex(&commitment),
    });
    let _ = leaf;
    Ok((commitment, public.digest(), manifest_pub, bytes))
}

// ============================== tier_threshold ==============================

fn prove_tier(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let tier_val = parse_tier(value_str)?;
    if tier_val == tier::TIER_NONE {
        return Err(ProverError::new(
            ErrorCode::TierNone,
            "tier value is NONE — remove the predicate or supply a non-NONE tier",
        ));
    }

    let min_tier = leaf
        .public
        .get("min_tier")
        .and_then(|v| {
            v.as_u64()
                .map(|n| n as u8)
                .or_else(|| v.as_str().and_then(|s| parse_tier(s).ok()))
        })
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::Config,
                "tier_threshold leaf missing public.min_tier",
            )
        })?;

    let params = tier::Params { min_tier };
    let witness = tier::Witness {
        tier: tier_val,
        nonce: *nonce,
    };
    let commitment = tier::commit(&witness);
    let public = tier::PublicInputs {
        commitment,
        min_tier,
    };

    let bytes = tier::prove(&witness, &public, &params).map_err(|e| match e {
        tier::ValidateError::BelowMinimum { .. } => {
            ProverError::new(ErrorCode::TierBelowMin, format!("{:?}", e))
        }
        tier::ValidateError::TierIsNone => ProverError::new(ErrorCode::TierNone, format!("{:?}", e)),
        other => ProverError::new(ErrorCode::CircuitInternal, format!("{:?}", other)),
    })?;

    let manifest_pub = serde_json::json!({
        "commitment": digest_to_hex(&commitment),
        "minTier": min_tier,
    });
    Ok((commitment, public.digest(), manifest_pub, bytes))
}

fn parse_tier(s: &str) -> Result<u8> {
    let upper = s.trim().to_ascii_uppercase();
    match upper.as_str() {
        "NONE" => Ok(tier::TIER_NONE),
        "RETAIL" => Ok(tier::TIER_RETAIL),
        "PROFESSIONAL" => Ok(tier::TIER_PROFESSIONAL),
        "ELIGIBLE_COUNTERPARTY" | "ELIGIBLE-COUNTERPARTY" => Ok(tier::TIER_ELIGIBLE_COUNTERPARTY),
        _ => {
            if let Ok(n) = s.parse::<u8>() {
                Ok(n)
            } else {
                Err(ProverError::input(format!("unknown tier value: {}", s)))
            }
        }
    }
}

// =============================== age_threshold ==============================

fn prove_age(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
    current_epoch_days: u64,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let dob_days = parse_dob(value_str)?;
    let min_age_days = leaf
        .public
        .get("min_age_days")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::Config,
                "age_threshold leaf missing public.min_age_days",
            )
        })?;

    let params = age::Params { min_age_days };
    let witness = age::Witness {
        dob_days,
        nonce: *nonce,
    };
    let commitment = age::commit(&witness);
    let public = age::PublicInputs {
        commitment,
        min_age_days,
        current_epoch_days,
    };

    let bytes = age::prove(&witness, &public, &params).map_err(|e| match e {
        age::ValidateError::BelowMinimum { .. } => {
            ProverError::new(ErrorCode::AgeBelowMin, format!("{:?}", e))
        }
        other => ProverError::new(ErrorCode::CircuitInternal, format!("{:?}", other)),
    })?;

    let manifest_pub = serde_json::json!({
        "commitment": digest_to_hex(&commitment),
        "minAgeDays": min_age_days,
        "currentEpochDays": current_epoch_days,
    });
    Ok((commitment, public.digest(), manifest_pub, bytes))
}

fn parse_dob(s: &str) -> Result<u64> {
    // Accept either "YYYY-MM-DD" or a raw day count.
    if let Ok(n) = s.trim().parse::<u64>() {
        return Ok(n);
    }
    let bytes = s.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(ProverError::input(format!(
            "dateOfBirth must be YYYY-MM-DD or days-since-epoch number: {}",
            s
        )));
    }
    let y: i64 = s[0..4]
        .parse()
        .map_err(|_| ProverError::input("dateOfBirth year not numeric"))?;
    let m: u32 = s[5..7]
        .parse()
        .map_err(|_| ProverError::input("dateOfBirth month not numeric"))?;
    let d: u32 = s[8..10]
        .parse()
        .map_err(|_| ProverError::input("dateOfBirth day not numeric"))?;
    days_from_civil(y, m, d)
        .ok_or_else(|| ProverError::input(format!("dateOfBirth out of range: {}", s)))
}

/// Howard Hinnant's `days_from_civil`. Returns days since 1970-01-01 for any
/// proleptic Gregorian date with `m in 1..=12, d in 1..=31`. Returns None if
/// the day-of-month is invalid for the month or if the year is outside the
/// representable u64 range.
fn days_from_civil(y: i64, m: u32, d: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let d = d as u64;
    let m_adj = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = ((153 * m_adj as u64 + 2) / 5) + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_y0 = (era * 146097) + doe as i64 - 719468;
    if days_since_y0 < 0 {
        None
    } else {
        Some(days_since_y0 as u64)
    }
}

// ============================== set_membership ==============================

fn prove_set(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
    list_commitments: &BTreeMap<String, ListCommitment>,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let list_id = leaf
        .public
        .get("list_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::Config,
                "set_membership leaf missing public.list_id",
            )
        })?;
    let list = list_commitments.get(list_id).ok_or_else(|| {
        ProverError::new(
            ErrorCode::ListNotFound,
            format!("list '{}' not provided in job.list_commitments", list_id),
        )
    })?;

    let nfc_value = nfc_string(value_str);
    let raw_refs: Vec<&[u8]> = list.values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, leaves) = set::build_set_tree(&raw_refs);

    let index = list
        .values
        .iter()
        .position(|v| nfc_string(v) == nfc_value)
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::ListMemberMissing,
                format!("value '{}' not in list '{}'", value_str, list_id),
            )
        })?;
    let path = set::inclusion_path(&leaves, index);

    let params = set::Params {
        list_id: list_id.to_string(),
    };
    let value_bytes = nfc_value.into_bytes();
    let witness = set::Witness {
        value: value_bytes,
        nonce: *nonce,
        merkle_path: path,
    };
    let commitment = set::commit(&witness);
    let public = set::PublicInputs {
        commitment,
        set_root: root,
        set_depth: depth,
    };

    let bytes = set::prove(&witness, &public, &params).map_err(|e| match e {
        set::ValidateError::NotInSet => ProverError::new(
            ErrorCode::ListMemberMissing,
            format!("set_membership: {:?}", e),
        ),
        set::ValidateError::EmptyValue => {
            ProverError::new(ErrorCode::EmptyValue, "set_membership value is empty")
        }
        other => ProverError::new(ErrorCode::CircuitInternal, format!("{:?}", other)),
    })?;

    let manifest_pub = serde_json::json!({
        "commitment": digest_to_hex(&commitment),
        "listId": list_id,
        "setRoot": digest_to_hex(&root),
        "setDepth": depth,
    });
    let _ = leaf;
    Ok((commitment, public.digest(), manifest_pub, bytes))
}

// ============================== helpers ==============================

fn nfc_bytes(s: &str) -> Vec<u8> {
    nfc_string(s).into_bytes()
}

fn nfc_string(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    s.nfc().collect()
}

// Re-export for crate users.
pub use trusset_circuit_age_threshold;
pub use trusset_circuit_preimage_knowledge;
pub use trusset_circuit_set_membership;
pub use trusset_circuit_tier_threshold;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_unix_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), Some(0));
    }

    #[test]
    fn days_from_civil_known_dates() {
        // 2000-01-01 is day 10957.
        assert_eq!(days_from_civil(2000, 1, 1), Some(10957));
        // 2026-05-14 is day 20587.
        assert_eq!(days_from_civil(2026, 5, 14), Some(20587));
        // 1990-01-15 is day 7319.
        assert_eq!(days_from_civil(1990, 1, 15), Some(7319));
    }

    #[test]
    fn days_from_civil_rejects_invalid_months() {
        assert_eq!(days_from_civil(2020, 0, 1), None);
        assert_eq!(days_from_civil(2020, 13, 1), None);
    }

    #[test]
    fn parse_dob_accepts_iso_and_number() {
        assert_eq!(parse_dob("2026-05-14").unwrap(), 20587);
        assert_eq!(parse_dob("20587").unwrap(), 20587);
    }

    #[test]
    fn parse_dob_rejects_garbage() {
        assert!(parse_dob("not-a-date").is_err());
        assert!(parse_dob("2026/05/14").is_err());
    }

    #[test]
    fn parse_tier_handles_names_and_numbers() {
        assert_eq!(parse_tier("RETAIL").unwrap(), 1);
        assert_eq!(parse_tier("retail").unwrap(), 1);
        assert_eq!(parse_tier("PROFESSIONAL").unwrap(), 2);
        assert_eq!(parse_tier("ELIGIBLE_COUNTERPARTY").unwrap(), 3);
        assert_eq!(parse_tier("1").unwrap(), 1);
    }

    #[test]
    fn parse_tier_rejects_unknown() {
        assert!(parse_tier("bogus").is_err());
    }
}
