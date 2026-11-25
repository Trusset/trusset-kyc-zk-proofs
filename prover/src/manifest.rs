//! Prover-side manifest assembly.
//!
//! The schema types (`Manifest`, `LeafEntry`, ...), canonical serializers,
//! and sentinel-signing constants all live in `trusset-bundle-format` so
//! the verifier can consume them without depending on the prover. This
//! module owns only the `build_manifest` glue that constructs a `Manifest`
//! from prover-internal types (`ProvedLeaf`, `JobSubject`).

use crate::dates::epoch_days_to_iso_date;
use crate::dispatch::ProvedLeaf;
use crate::job::{Job, JobSubject, ListCommitment};
use std::collections::BTreeMap;
use trusset_bundle_format::manifest::{
    is_v31, is_v3_family, LeafEntry, ListEntry, Manifest, StarkBlock, ToolchainBlock,
    CREATED_AT_SENTINEL, MODE_PRODUCTION, MODE_STUB, SECRETS_KDF_VERSION,
};
use trusset_bundle_format::merkle::{MERKLE_VERSION_V2, MERKLE_VERSION_V3};
use trusset_circuits_common::{digest_to_hex, CIRCUITS_VERSION};

// Re-exports so existing call sites keep working.
pub use trusset_bundle_format::manifest::{
    canonical_disk_bytes, canonical_signing_bytes, CREATED_AT_SENTINEL as SENTINEL,
};

#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    job: &Job,
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
    toolchain: Option<ToolchainBlock>,
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
            binding: p.binding.clone(),
            binding_digest: p.binding_digest.as_ref().map(digest_to_hex),
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

    // A v3 manifest is emitted only when the job asked for one. A job that
    // still declares 2.0.0 or 2.1.0 produces exactly the manifest that
    // version always produced, so an operator can upgrade the tool without
    // their bundle shape changing under them.
    let emitting_v3 = is_v3_family(&job.version);
    let emitting_v31 = is_v31(&job.version);

    Manifest {
        version: job.version.clone(),
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
        merkle_version: Some(if emitting_v31 {
            MERKLE_VERSION_V3
        } else {
            MERKLE_VERSION_V2
        }),
        config_hash: Some(config_hash_hex.to_string()),
        epoch_days_source: if emitting_v3 {
            job.epoch_days_source.clone()
        } else {
            None
        },
        as_of_date: if emitting_v3 {
            Some(epoch_days_to_iso_date(epoch_days))
        } else {
            None
        },
        // Recorded only when true. A bundle that says nothing about pinning
        // was produced by tooling that had no concept of it; a bundle that
        // says `false` is claiming something, and the two should not look
        // the same to a reader.
        unpinned_epoch: if emitting_v3 && job.unpinned_epoch {
            Some(true)
        } else {
            None
        },
        issuer: if emitting_v3 {
            job.issuer.clone()
        } else {
            None
        },
        toolchain: if emitting_v3 { toolchain } else { None },
        chain: if emitting_v31 {
            job.chain.clone()
        } else {
            None
        },
    }
}
