//! Per-leaf circuit routing.
//!
//! Each `JobLeaf` is routed to one of the four circuits. This module owns
//! the witness/public-input construction from the JSON-typed `value` and
//! `public` fields and produces a fully-bound `ProvedLeaf` ready for
//! manifest assembly.

use crate::dates::{days_from_civil, epoch_days_to_iso_date};
use crate::errors::{ErrorCode, ProverError, Result};
use crate::job::{JobLeaf, JobSubject, ListCommitment};
use crate::leaf::compute_proof_digest;
use serde::Serialize;
use std::collections::BTreeMap;
use trusset_bundle_format::claims::{compute_binding_digest, LeafBinding};
use trusset_bundle_format::leaf::compute_leaf_hash_bound;
use trusset_bundle_format::manifest::{
    DISCLOSURE_COMMITMENT_ONLY, DISCLOSURE_PLAINTEXT, DISCLOSURE_PREDICATE,
};
use trusset_bundle_format::registry::list_content_hash;
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
    /// Resolved predicate parameters for `manifest.leaves[].params`, so a
    /// verifier reads the asserted thresholds from the bundle rather than
    /// from a config file it does not have.
    pub manifest_params: serde_json::Value,
    /// `plaintext` | `predicate` | `commitment_only`.
    pub disclosure: String,
    /// v3 claim descriptor / validity / list-version block, and its digest.
    /// `None` for a job that supplied none, which reproduces the v2 leaf hash.
    pub binding: Option<LeafBinding>,
    pub binding_digest: Option<Digest>,
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

/// Whether a leaf gets a real STARK or only its predicate checked.
///
/// `Stub` still runs the circuit's `validate()`, so an under-age subject fails
/// in stub mode exactly as it does in production. What it skips is the
/// proving, which before v3 ran in full and then had its output discarded —
/// making `--skip-proofs` cost the same as a real run while producing nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafMode {
    Prove,
    Stub,
}

impl LeafMode {
    #[must_use]
    pub fn from_skip_proofs(skip: bool) -> Self {
        if skip {
            LeafMode::Stub
        } else {
            LeafMode::Prove
        }
    }

    fn is_stub(self) -> bool {
        self == LeafMode::Stub
    }
}

pub fn prove_leaf(
    subject_seed: &[u8; 32],
    subject: &JobSubject,
    epoch_days: u64,
    leaf: &JobLeaf,
    list_commitments: &BTreeMap<String, ListCommitment>,
    skip_proofs: bool,
) -> Result<ProvedLeaf> {
    prove_leaf_inner(
        subject_seed,
        subject,
        epoch_days,
        leaf,
        list_commitments,
        skip_proofs,
    )
    .map_err(|e| with_leaf_context(leaf, e))
}

/// Attach the leaf name and circuit to any error raised while handling one
/// leaf. Without this a batch failure says only which subject failed, which is
/// useless on a nine-leaf subject with three `set_membership` predicates.
fn with_leaf_context(leaf: &JobLeaf, e: ProverError) -> ProverError {
    if e.message.starts_with("leaf \"") {
        return e;
    }
    ProverError::new(
        e.code,
        format!("leaf \"{}\" ({}): {}", leaf.field, leaf.circuit, e.message),
    )
}

fn prove_leaf_inner(
    subject_seed: &[u8; 32],
    subject: &JobSubject,
    epoch_days: u64,
    leaf: &JobLeaf,
    list_commitments: &BTreeMap<String, ListCommitment>,
    skip_proofs: bool,
) -> Result<ProvedLeaf> {
    let mode = LeafMode::from_skip_proofs(skip_proofs);
    let start = std::time::Instant::now();
    let circuit_id = parse_circuit_id(&leaf.circuit)?;
    let params_hash = leaf.params_hash_bytes()?;
    let binding = build_binding(leaf, list_commitments)?;

    let leaf_seed = derive_leaf_seed(
        subject_seed,
        leaf.field.as_bytes(),
        circuit_id.as_u8(),
        &params_hash,
    );
    let nonce: Zeroizing<[u8; 32]> = Zeroizing::new(*leaf_seed);

    let plaintext_value = leaf_value_as_string(&leaf.value)?;
    let wallet_bytes = subject.wallet_bytes()?;
    let commitment_only = leaf.disclosure.as_deref() == Some(DISCLOSURE_COMMITMENT_ONLY);

    let (commitment, public_digest, manifest_public_inputs, proof_bytes) = if commitment_only {
        commit_only(&plaintext_value, &nonce)?
    } else {
        match circuit_id {
            CircuitId::PreimageKnowledge => prove_preimage(leaf, &plaintext_value, &nonce, mode)?,
            CircuitId::TierThreshold => prove_tier(leaf, &plaintext_value, &nonce, mode)?,
            CircuitId::AgeThreshold => prove_age(leaf, &plaintext_value, &nonce, epoch_days, mode)?,
            CircuitId::SetMembership => {
                prove_set(leaf, &plaintext_value, &nonce, list_commitments, mode)?
            }
        }
    };

    let proof_digest = compute_proof_digest(&proof_bytes);
    let binding_digest = match binding.as_ref() {
        Some(b) => Some(compute_binding_digest(b).map_err(|e| {
            ProverError::new(
                ErrorCode::DescriptorInvalid,
                format!("claim descriptor could not be canonicalized: {}", e),
            )
        })?),
        None => None,
    };
    let leaf_hash = compute_leaf_hash_bound(
        &leaf.field,
        circuit_id,
        &wallet_bytes,
        epoch_days,
        &commitment,
        &public_digest,
        &proof_digest,
        binding_digest.as_ref(),
    );

    let disclosure = resolve_disclosure(leaf, circuit_id);
    let manifest_params = resolve_manifest_params(leaf, circuit_id, &manifest_public_inputs);

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
        manifest_params,
        disclosure,
        binding,
        binding_digest,
        plaintext_value: Zeroizing::new(plaintext_value),
        nonce,
        took_ms: start.elapsed().as_millis() as u64,
    })
}

/// Disclosure class for a leaf: explicit from the job spec when the CLI
/// supplied one, else the per-circuit default (`predicate` for the three
/// predicate circuits, `commitment_only` semantics only ever arrive
/// explicitly).
fn resolve_disclosure(leaf: &JobLeaf, circuit_id: CircuitId) -> String {
    if let Some(d) = leaf.disclosure.as_deref() {
        if d == DISCLOSURE_PLAINTEXT || d == DISCLOSURE_PREDICATE || d == DISCLOSURE_COMMITMENT_ONLY
        {
            return d.to_string();
        }
    }
    match circuit_id {
        CircuitId::PreimageKnowledge => DISCLOSURE_PREDICATE.to_string(),
        _ => DISCLOSURE_PREDICATE.to_string(),
    }
}

/// Resolved predicate parameters recorded in the manifest. The CLI sends
/// them explicitly; the fallback mirrors the values already present in
/// `publicInputs` so a v2.1 manifest always carries them.
fn resolve_manifest_params(
    leaf: &JobLeaf,
    circuit_id: CircuitId,
    public_inputs: &serde_json::Value,
) -> serde_json::Value {
    if let Some(p) = leaf.params.clone() {
        return p;
    }
    match circuit_id {
        CircuitId::AgeThreshold => serde_json::json!({
            "minAgeDays": public_inputs.get("minAgeDays").cloned().unwrap_or(serde_json::Value::Null),
        }),
        CircuitId::TierThreshold => serde_json::json!({
            "minTier": public_inputs.get("minTier").cloned().unwrap_or(serde_json::Value::Null),
        }),
        CircuitId::SetMembership => serde_json::json!({
            "listId": public_inputs.get("listId").cloned().unwrap_or(serde_json::Value::Null),
        }),
        CircuitId::PreimageKnowledge => serde_json::json!({
            "maxValueBytes": preimage::Params::default().max_value_bytes,
        }),
    }
}

/// Assemble and validate the v3 binding block for a leaf.
///
/// A job either supplies both a descriptor and a validity interval or neither.
/// Supplying one alone is rejected rather than silently half-recorded: a claim
/// with a legal basis but no window, or a window with no stated basis, is not
/// evidence anyone can act on.
fn build_binding(
    leaf: &JobLeaf,
    list_commitments: &BTreeMap<String, ListCommitment>,
) -> Result<Option<LeafBinding>> {
    match (leaf.descriptor.as_ref(), leaf.validity.as_ref()) {
        (None, None) => return Ok(None),
        (None, Some(_)) => {
            return Err(ProverError::new(
                ErrorCode::DescriptorMissing,
                "a validity interval was supplied with no claim descriptor. Add \
                 `descriptor` (legalBasis, issuingParty, evidenceClass) for this predicate in \
                 config.json, or remove `validity` to issue a v2-shaped leaf.",
            ));
        }
        (Some(_), None) => {
            return Err(ProverError::new(
                ErrorCode::ValidityInvalid,
                "a claim descriptor was supplied with no validity interval. Add \
                 `validity` (from, until, basisAsOf) for this predicate in config.json.",
            ));
        }
        (Some(_), Some(_)) => {}
    }

    let descriptor = leaf.descriptor.clone().expect("checked above");
    let validity = leaf.validity.clone().expect("checked above");

    for (label, value) in [
        (
            "descriptor.legalBasis.framework",
            &descriptor.legal_basis.framework,
        ),
        (
            "descriptor.legalBasis.reference",
            &descriptor.legal_basis.reference,
        ),
        (
            "descriptor.legalBasis.assertion",
            &descriptor.legal_basis.assertion,
        ),
        (
            "descriptor.issuingParty.name",
            &descriptor.issuing_party.name,
        ),
        (
            "descriptor.issuingParty.identifierScheme",
            &descriptor.issuing_party.identifier_scheme,
        ),
        (
            "descriptor.issuingParty.identifier",
            &descriptor.issuing_party.identifier,
        ),
        (
            "descriptor.issuingParty.jurisdiction",
            &descriptor.issuing_party.jurisdiction,
        ),
    ] {
        if value.trim().is_empty() {
            return Err(ProverError::new(
                ErrorCode::DescriptorInvalid,
                format!(
                    "{} is empty. Every claim must say what rule it asserts and who warrants it.",
                    label
                ),
            ));
        }
    }

    if !validity.is_well_formed() {
        return Err(ProverError::new(
            ErrorCode::ValidityInvalid,
            format!(
                "validity interval is not well formed: from={} ({}), until={}, basisAsOf={} ({}). \
                 `until` must not precede `from`, and `basisAsOf` must not follow `from` — \
                 evidence cannot post-date the window it supports.",
                validity.from,
                epoch_days_to_iso_date(validity.from),
                validity
                    .until
                    .map(|u| format!("{} ({})", u, epoch_days_to_iso_date(u)))
                    .unwrap_or_else(|| "open-ended".to_string()),
                validity.basis_as_of,
                epoch_days_to_iso_date(validity.basis_as_of),
            ),
        ));
    }

    let circuit_id = parse_circuit_id(&leaf.circuit)?;
    if circuit_id == CircuitId::SetMembership {
        let Some(list_version) = leaf.list_version.as_ref() else {
            return Err(ProverError::new(
                ErrorCode::DescriptorMissing,
                "a set_membership leaf with a claim descriptor must also record which list \
                 version it was proved against. Build the list registry with \
                 `npm run list-version` so the CLI can resolve one.",
            ));
        };
        let list = list_commitments.get(&list_version.list_id).ok_or_else(|| {
            ProverError::new(
                ErrorCode::ListNotFound,
                format!(
                    "declared list version references list '{}', which was not supplied to the \
                     prover. Check `config.lists` names the same list the descriptor does.",
                    list_version.list_id
                ),
            )
        })?;
        let refs: Vec<&[u8]> = list.values.iter().map(|s| s.as_bytes()).collect();
        let (root, _depth, _) = set::build_set_tree(&refs);
        let recomputed_root = digest_to_hex(&root);
        if !list_version.root.eq_ignore_ascii_case(&recomputed_root) {
            return Err(ProverError::new(
                ErrorCode::ListVersionMismatch,
                format!(
                    "declared list '{}' version {} has root {}, but the values supplied to the \
                     prover recompute to {}. The registry entry and the list file disagree — \
                     re-run `npm run list-version` for this list.",
                    list_version.list_id, list_version.version, list_version.root, recomputed_root
                ),
            ));
        }
        let recomputed_content = list_content_hash(&list.values);
        if !list_version
            .content_hash
            .eq_ignore_ascii_case(&recomputed_content)
        {
            return Err(ProverError::new(
                ErrorCode::ListVersionMismatch,
                format!(
                    "declared list '{}' version {} has contentHash {}, but the values supplied \
                     recompute to {}.",
                    list_version.list_id,
                    list_version.version,
                    list_version.content_hash,
                    recomputed_content
                ),
            ));
        }
    }

    Ok(Some(LeafBinding {
        descriptor,
        validity,
        list_version: leaf.list_version.clone(),
    }))
}

/// `commitment_only` leaf mode: produce the hiding Rescue commitment and
/// the preimage-shaped public digest, with a zero-length sentinel in place
/// of a STARK. The leaf still participates identically in leaf hashing and
/// the Merkle root; only the AIR proof is absent.
fn commit_only(
    value_str: &str,
    nonce: &[u8; 32],
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let value_bytes = nfc_bytes(value_str);
    let witness = preimage::Witness {
        value: value_bytes,
        nonce: *nonce,
    };
    let commitment = preimage::commit(&witness);
    let public = preimage::PublicInputs { commitment };
    let manifest_pub = serde_json::json!({
        "commitment": digest_to_hex(&commitment),
    });
    Ok((commitment, public.digest(), manifest_pub, Vec::new()))
}

fn parse_circuit_id(name: &str) -> Result<CircuitId> {
    CircuitId::from_str(name).ok_or_else(|| {
        ProverError::new(
            ErrorCode::Config,
            format!(
                "'{}' is not a circuit this build knows. Valid values are age_threshold, \
                 set_membership, tier_threshold, preimage_knowledge, and commitment_only.",
                name
            ),
        )
    })
}

fn leaf_value_as_string(v: &serde_json::Value) -> Result<String> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(ProverError::input(
            "the value for this field is an object, array, or null. Fix: supply a string, \
             number, or boolean in this subject's input row.",
        )),
    }
}

/// Human name for a tier code, used in failure messages so an operator does
/// not have to look up what `minTier: 2` meant.
fn tier_name(t: u8) -> &'static str {
    match t {
        0 => "NONE",
        1 => "RETAIL",
        2 => "PROFESSIONAL",
        3 => "ELIGIBLE_COUNTERPARTY",
        _ => "unknown",
    }
}

// ============================ preimage_knowledge ============================

fn prove_preimage(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
    mode: LeafMode,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let value_bytes = nfc_bytes(value_str);
    let params = preimage::Params::default();
    let witness = preimage::Witness {
        value: value_bytes.clone(),
        nonce: *nonce,
    };
    let commitment = preimage::commit(&witness);
    let public = preimage::PublicInputs { commitment };

    let bytes = if mode.is_stub() {
        preimage::validate(&witness, &public, &params).map_err(|e| {
            ProverError::new(
                ErrorCode::CircuitInternal,
                format!("preimage_knowledge validation failed: {:?}", e),
            )
        })?;
        Vec::new()
    } else {
        preimage::prove(&witness, &public, &params).map_err(|e| {
            ProverError::new(
                ErrorCode::CircuitInternal,
                format!("preimage_knowledge prove: {:?}", e),
            )
        })?
    };

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
    mode: LeafMode,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let tier_val = parse_tier(value_str)?;
    if tier_val == tier::TIER_NONE {
        return Err(ProverError::new(
            ErrorCode::TierNone,
            "the subject's investor tier is NONE, which the circuit cannot prove a floor for. \
             Fix: correct this subject's investorType in the input row, or remove the \
             tier_threshold predicate for subjects with no tier claim.",
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
                "no `minTier` was supplied for this predicate. Fix: set \
                 `config.predicates.<field>.params.minTier` to RETAIL, PROFESSIONAL, or \
                 ELIGIBLE_COUNTERPARTY.",
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

    let outcome = if mode.is_stub() {
        tier::validate(&witness, &public, &params).map(|()| Vec::new())
    } else {
        tier::prove(&witness, &public, &params)
    };
    let bytes = outcome.map_err(|e| match e {
        // The subject's own tier is deliberately absent from this message.
        // Failure rows land in output/failures.csv, which travels; the
        // asserted floor is public (it is in the manifest), the subject's
        // value is not.
        tier::ValidateError::BelowMinimum { .. } => ProverError::new(
            ErrorCode::TierBelowMin,
            format!(
                "the subject's investor tier is below the asserted minimum of {} ({}). \
                 Fix: correct this subject's investorType in the input row, lower `minTier` \
                 for this predicate in config.json, or exclude the subject from the batch.",
                min_tier,
                tier_name(min_tier)
            ),
        ),
        tier::ValidateError::TierIsNone => ProverError::new(
            ErrorCode::TierNone,
            "the subject's investor tier is NONE, which the circuit cannot prove a floor for."
                .to_string(),
        ),
        tier::ValidateError::InvalidMinTier(t) => ProverError::new(
            ErrorCode::Config,
            format!(
                "`minTier` is {}, which is not one of RETAIL (1), PROFESSIONAL (2), or \
                 ELIGIBLE_COUNTERPARTY (3). Fix `config.predicates.investorType.params.minTier`.",
                t
            ),
        ),
        other => ProverError::new(
            ErrorCode::CircuitInternal,
            format!(
                "tier_threshold proving failed internally ({:?}). This is a bug in the tool, \
                 not in the input; please report it with the manifest and this message.",
                other
            ),
        ),
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
    mode: LeafMode,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let dob_days = parse_dob(value_str)?;
    let min_age_days = leaf
        .public
        .get("min_age_days")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::Config,
                "no age threshold was supplied for this predicate. Fix: set \
                 `config.predicates.<field>.params.minAgeYears` (or `minAgeDays`).",
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

    let outcome = if mode.is_stub() {
        age::validate(&witness, &public, &params).map(|()| Vec::new())
    } else {
        age::prove(&witness, &public, &params)
    };
    let bytes = outcome.map_err(|e| match e {
        // The subject's actual age is withheld for the same reason as the
        // tier value above: the threshold is public, the subject's attribute
        // is not, and failure rows are written to a file that travels.
        age::ValidateError::BelowMinimum { .. } => ProverError::new(
            ErrorCode::AgeBelowMin,
            format!(
                "the subject does not meet the asserted age threshold of {} days as of {} \
                 (epoch day {}). Fix: correct this subject's dateOfBirth in the input row, \
                 lower `minAgeYears` for this predicate in config.json, or exclude the subject \
                 from the batch.",
                min_age_days,
                epoch_days_to_iso_date(current_epoch_days),
                current_epoch_days
            ),
        ),
        age::ValidateError::TimeTravel { .. } => ProverError::new(
            ErrorCode::Input,
            format!(
                "the subject's date of birth falls after the batch as-of date {} (epoch day {}). \
                 Fix: correct the date in this subject's input row, or check that \
                 `security.epochDaysSource` is not pinned to a date in the past.",
                epoch_days_to_iso_date(current_epoch_days),
                current_epoch_days
            ),
        ),
        age::ValidateError::OutOfRange => ProverError::new(
            ErrorCode::Input,
            "the date of birth or the as-of date is outside the representable range \
             (1970-01-01 to roughly year 9999). Fix: correct the value in this subject's \
             input row.",
        ),
        other => ProverError::new(
            ErrorCode::CircuitInternal,
            format!(
                "age_threshold proving failed internally ({:?}). This is a bug in the tool, \
                 not in the input; please report it with the manifest and this message.",
                other
            ),
        ),
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
        return Err(ProverError::input(
            "the date value for this field is not in YYYY-MM-DD form (or a days-since-epoch \
             integer). Fix: correct the value in this subject's input row.",
        ));
    }
    let y: i64 = s[0..4]
        .parse()
        .map_err(|_| ProverError::input("the year part of this date is not numeric."))?;
    let m: u32 = s[5..7]
        .parse()
        .map_err(|_| ProverError::input("the month part of this date is not numeric."))?;
    let d: u32 = s[8..10]
        .parse()
        .map_err(|_| ProverError::input("the day part of this date is not numeric."))?;
    days_from_civil(y, m, d).ok_or_else(|| {
        ProverError::input(
            "this date is not a real calendar date, or falls before 1970-01-01. Fix: correct \
             the value in this subject's input row.",
        )
    })
}

// ============================== set_membership ==============================

fn prove_set(
    leaf: &JobLeaf,
    value_str: &str,
    nonce: &[u8; 32],
    list_commitments: &BTreeMap<String, ListCommitment>,
    mode: LeafMode,
) -> Result<(Digest, Digest, serde_json::Value, Vec<u8>)> {
    let list_id = leaf
        .public
        .get("list_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::Config,
                "no list was supplied for this predicate. Fix: set \
                 `config.predicates.<field>.params.list` to a list id declared under \
                 `config.lists`.",
            )
        })?;
    let list = list_commitments.get(list_id).ok_or_else(|| {
        ProverError::new(
            ErrorCode::ListNotFound,
            format!(
                "list '{}' is referenced by this predicate but was not supplied to the prover. \
                 Fix: declare it under `config.lists.{}` with a path to its registry, and run \
                 `npm run list-version -- --list-id {}` if no registry exists yet.",
                list_id, list_id, list_id
            ),
        )
    })?;

    let nfc_value = nfc_string(value_str);
    let raw_refs: Vec<&[u8]> = list.values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, leaves) = set::build_set_tree(&raw_refs);

    // The failing value is deliberately not echoed: this message reaches
    // output/failures.csv, and for `nationality` or `documentIssuingCountry`
    // the value is exactly what the predicate exists to keep private. The
    // wallet and the leaf name locate the input row without disclosing it.
    let index = list
        .values
        .iter()
        .position(|v| nfc_string(v) == nfc_value)
        .ok_or_else(|| {
            ProverError::new(
                ErrorCode::ListMemberMissing,
                format!(
                    "this subject's value is not a member of list '{}' ({} entries, root {}). \
                     Fix: add the value to the list source and run `npm run list-version -- \
                     --list-id {}` to record a new version, or exclude the subject from the batch.",
                    list_id,
                    list.values.len(),
                    &digest_to_hex(&root)[..12],
                    list_id
                ),
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

    let outcome = if mode.is_stub() {
        set::validate(&witness, &public, &params).map(|()| Vec::new())
    } else {
        set::prove(&witness, &public, &params)
    };
    let bytes = outcome.map_err(|e| match e {
        set::ValidateError::NotInSet => ProverError::new(
            ErrorCode::ListMemberMissing,
            format!(
                "this subject's value is not a member of list '{}'. Fix: add it to the list \
                 source and run `npm run list-version -- --list-id {}`, or exclude the subject.",
                list_id, list_id
            ),
        ),
        set::ValidateError::EmptyValue => ProverError::new(
            ErrorCode::EmptyValue,
            "the value for this field is empty. Fix: supply a value in the input row, or \
             remove the predicate for this field in config.json.",
        ),
        other => ProverError::new(
            ErrorCode::CircuitInternal,
            format!(
                "set_membership proving failed internally ({:?}). This is a bug in the tool, \
                 not in the input; please report it with the manifest and this message.",
                other
            ),
        ),
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
