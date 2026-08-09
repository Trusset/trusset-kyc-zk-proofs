//! Prover-side manifest assembly.
//!
//! The schema types (`Manifest`, `LeafEntry`, ...), canonical serializers,
//! and sentinel-signing constants all live in `trusset-bundle-format` so
//! the verifier can consume them without depending on the prover. This
//! module owns only the `build_manifest` glue that constructs a `Manifest`
//! from prover-internal types (`ProvedLeaf`, `JobSubject`).

use crate::dispatch::ProvedLeaf;
use crate::job::{JobSubject, ListCommitment};
use std::collections::BTreeMap;
use trusset_bundle_format::manifest::{
    LeafEntry, ListEntry, Manifest, StarkBlock, CREATED_AT_SENTINEL, MANIFEST_VERSION,
    MODE_PRODUCTION, MODE_STUB, SECRETS_KDF_VERSION,
};
use trusset_bundle_format::merkle::MERKLE_VERSION_V2;
use trusset_circuits_common::{digest_to_hex, CIRCUITS_VERSION};

// Re-exports so existing call sites keep working.
pub use trusset_bundle_format::manifest::{
    canonical_disk_bytes, canonical_signing_bytes, CREATED_AT_SENTINEL as SENTINEL,
};

#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    subject: &JobSubject,
    epoch_days: u64,
    deterministic: bool,
    kyc_hash_hex: &str,
    sorted_indices: &[usize],
    proved_leaves: &[ProvedLeaf],
    list_commitments_used: &BTreeMap<String, ListCommitment>,
    list_roots: &BTreeMap<String, String>,
    skip_proofs: bool,
    config_hash_hex: &str,
) -> Manifest {
    let mut leaves = Vec::with_capacity(proved_leaves.len());
    for &orig_idx in sorted_indices {
        let p = &proved_leaves[orig_idx];
        leaves.push(LeafEntry {
            field_name: p.field.clone(),
            circuit: p.circuit_id.as_str().to_string(),
            circuit_id: p.circuit_id.as_u8(),
            commitment: digest_to_hex(&p.commitment),
            public_inputs: p.manifest_public_inputs.clone(),
            public_digest: digest_to_hex(&p.public_digest),
            proof_path: format!("proofs/{}.bin", p.field),
            proof_digest: digest_to_hex(&p.proof_digest),
            params_hash: p.params_hash_hex.clone(),
            leaf_hash: digest_to_hex(&p.leaf_hash),
            disclosure: Some(p.disclosure.clone()),
            params: Some(p.manifest_params.clone()),
        });
    }

    let mut lists = BTreeMap::new();
    for (id, root_hex) in list_roots {
        let source_sha = list_commitments_used.get(id).and_then(|lc| {
            if lc.source_sha256.is_empty() {
                None
            } else {
                Some(lc.source_sha256.clone())
            }
        });
        lists.insert(
            id.clone(),
            ListEntry {
                root: root_hex.clone(),
                source_sha256: source_sha,
            },
        );
    }

    // Stage 18 mode-flip: `MODE_STUB` is emitted only when the
    // operator explicitly passed `--skip-proofs` (zero-byte proofs,
    // development iteration). Otherwise the manifest carries
    // `MODE_PRODUCTION` and counterparty verifiers in strict mode
    // accept the bundle.
    let mode = if skip_proofs {
        MODE_STUB.to_string()
    } else {
        MODE_PRODUCTION.to_string()
    };

    Manifest {
        version: MANIFEST_VERSION.to_string(),
        mode,
        wallet_address: subject.subject_id.clone(),
        kyc_hash: kyc_hash_hex.to_string(),
        epoch_days,
        created_at: CREATED_AT_SENTINEL.to_string(),
        deterministic,
        circuits_version: CIRCUITS_VERSION,
        stark: StarkBlock::default(),
        leaves,
        passthrough: subject.passthrough.clone(),
        lists,
        secrets_kdf_version: SECRETS_KDF_VERSION,
        merkle_version: Some(MERKLE_VERSION_V2),
        config_hash: Some(config_hash_hex.to_string()),
    }
}
