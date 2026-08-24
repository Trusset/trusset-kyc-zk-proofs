//! Atomic per-subject bundle writer (plan §"Output bundle").
//!
//! The orchestration goes:
//!
//! 1. For every leaf, dispatch to its circuit, capturing `ProvedLeaf`.
//! 2. Sort leaf hashes and compute the Rescue Merkle root → `kycHash.hex`.
//! 3. Build the manifest skeleton (with sentinel `createdAt`) and sign it.
//! 4. Encrypt the secrets blob (per-leaf plaintext value + nonce) →
//!    `secrets.enc`.
//! 5. Write everything into `<output_root>/.tmp/<wallet>/`, set the final
//!    `createdAt`, then rename to `<output_root>/<wallet>/`.
//!
//! If any step fails, the partial `.tmp` directory is removed and no
//! plaintext touches the final destination.

use crate::dispatch::{prove_leaf, ProvedLeaf, SecretsEntry};
use crate::encrypt::encrypt_secrets_v2;
use crate::entropy::fill_random;
use crate::errors::{ErrorCode, ProverError, Result};
use crate::job::{Job, JobSubject};
use crate::manifest::build_manifest;
use crate::merkle::compute_root_v2;
use crate::sign::{SigningSecret, SIGNATURE_LEN};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use trusset_bundle_format::manifest::{
    canonical_disk_bytes, canonical_signing_bytes, Manifest, ToolchainBlock, CREATED_AT_SENTINEL,
};
use trusset_circuit_set_membership as set;
use trusset_circuits_common::{
    derive_deterministic_subject_key, derive_subject_seed, digest_to_hex, CIRCUITS_VERSION,
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct BundleReport {
    pub subject_id: String,
    pub bundle_path: PathBuf,
    pub kyc_hash_hex: String,
    pub leaf_count: usize,
    pub total_proof_bytes: usize,
    /// Per-leaf `(field, proof_bytes, ms)` for the `leaf_proved` events
    /// the caller streams to stdout and the audit log.
    pub leaf_timings: Vec<LeafTiming>,
}

#[derive(Debug, Clone)]
pub struct LeafTiming {
    pub field: String,
    pub proof_bytes: usize,
    pub ms: u64,
}

/// Build one subject's bundle and write it to disk atomically.
///
/// Records no toolchain block. The binary that runs a real batch identifies
/// itself via [`build_subject_bundle_with_toolchain`]; this shorter form
/// exists for callers driving the library directly.
pub fn build_subject_bundle(
    job: &Job,
    subject: &JobSubject,
    master_key: &[u8; 32],
    signing_key: &SigningSecret,
    config_hash: &[u8; 32],
    now_iso: &str,
) -> Result<BundleReport> {
    build_subject_bundle_with_toolchain(
        job,
        subject,
        master_key,
        signing_key,
        config_hash,
        now_iso,
        None,
    )
}

/// Build one subject's bundle, recording which build produced it.
#[allow(clippy::too_many_arguments)]
pub fn build_subject_bundle_with_toolchain(
    job: &Job,
    subject: &JobSubject,
    master_key: &[u8; 32],
    signing_key: &SigningSecret,
    config_hash: &[u8; 32],
    now_iso: &str,
    toolchain: Option<&ToolchainBlock>,
) -> Result<BundleReport> {
    // 0. Per-subject key (secretsKdfVersion 2). Deterministic runs derive
    // it from the master key so re-runs stay byte-identical; otherwise it
    // is drawn from OS entropy and lives only inside the wrapped
    // `secrets.enc` blob. The master key wraps this key and derives
    // nothing else.
    let subject_key: Zeroizing<[u8; 32]> = if job.deterministic {
        derive_deterministic_subject_key(
            master_key,
            subject.subject_id.as_bytes(),
            job.epoch_days,
            config_hash,
            CIRCUITS_VERSION,
        )
    } else {
        let mut k = Zeroizing::new([0u8; 32]);
        fill_random(k.as_mut())?;
        k
    };

    let subject_seed = derive_subject_seed(
        &subject_key,
        subject.subject_id.as_bytes(),
        job.epoch_days,
        config_hash,
        CIRCUITS_VERSION,
    );

    // 1. Prove every leaf.
    let mut proved: Vec<ProvedLeaf> = Vec::with_capacity(subject.leaves.len());
    for leaf in &subject.leaves {
        let p = prove_leaf(
            &subject_seed,
            subject,
            job.epoch_days,
            leaf,
            &job.list_commitments,
            job.skip_proofs,
        )?;
        proved.push(p);
    }

    // 2. Merkle root over sorted leaf hashes (v2 construction).
    let leaf_hashes: Vec<_> = proved.iter().map(|p| p.leaf_hash).collect();
    let (root, sorted_indices) = compute_root_v2(&leaf_hashes);
    let kyc_hash_hex = digest_to_hex(&root);

    // 3. List roots needed by the manifest. A list-commitment file that
    // declares a root, a depth, or a content hash is cross-checked against
    // the recomputation here, so a stale committed file fails the run
    // instead of being ignored.
    let list_roots = check_list_commitments(job)?;

    let manifest = build_manifest(
        job,
        subject,
        job.epoch_days,
        job.deterministic,
        &kyc_hash_hex,
        &sorted_indices,
        &proved,
        &job.list_commitments,
        &list_roots,
        job.skip_proofs,
        &job.config_hash,
        toolchain.cloned(),
    );

    // 4. Sign the canonical signing view (sentinel timestamp).
    let sig_payload = canonical_signing_bytes(&manifest)?;
    let signature: [u8; SIGNATURE_LEN] = signing_key.sign(&sig_payload);

    // 5. Encrypt secrets blob (per-leaf value + nonce + circuit name)
    // under the wrapped per-subject key.
    let secrets_json = build_secrets_blob(&proved)?;
    let secrets_enc = encrypt_secrets_v2(
        master_key,
        &subject_key,
        subject.subject_id.as_bytes(),
        job.epoch_days,
        config_hash,
        &secrets_json,
    )?;

    // 6. Write bundle into output_root/.tmp/<wallet>/, then rename.
    let output_root = Path::new(&job.output_root);
    let bundle_path = write_bundle(
        output_root,
        &manifest,
        now_iso,
        &signature,
        &proved,
        &secrets_enc,
    )?;

    let leaf_timings = proved
        .iter()
        .map(|p| LeafTiming {
            field: p.field.clone(),
            proof_bytes: p.proof_bytes.len(),
            ms: p.took_ms,
        })
        .collect();

    Ok(BundleReport {
        subject_id: subject.subject_id.clone(),
        bundle_path,
        kyc_hash_hex,
        leaf_count: proved.len(),
        total_proof_bytes: proved.iter().map(|p| p.proof_bytes.len()).sum(),
        leaf_timings,
    })
}

/// One problem found while validating a subject without writing anything.
#[derive(Debug, Clone)]
pub struct SubjectProblem {
    pub subject_id: String,
    pub leaf: Option<String>,
    pub code: ErrorCode,
    pub message: String,
}

/// Validate every leaf of one subject and return **all** the problems, not
/// just the first.
///
/// The proving path stops at the first bad leaf, which is right when the
/// output is a bundle: there is nothing to write once one leaf fails. It is
/// wrong when the operator is asking "what is wrong with my batch", because it
/// turns one review pass into as many passes as there are broken rows. This
/// runs the same witness construction, predicate validation, descriptor and
/// list-version checks, and collects every failure.
pub fn dry_run_subject(job: &Job, subject: &JobSubject) -> Vec<SubjectProblem> {
    let mut problems = Vec::new();

    // A zero seed is sufficient: nothing here depends on the nonce being
    // secret, and a dry run must not require key material.
    let seed = [0u8; 32];
    for leaf in &subject.leaves {
        if let Err(e) = prove_leaf(
            &seed,
            subject,
            job.epoch_days,
            leaf,
            &job.list_commitments,
            // Skip the STARK: a dry run answers "would this batch prove",
            // which is decided by witness and predicate validation, and
            // proving every leaf would make the check as slow as the run it
            // is meant to precede.
            true,
        ) {
            problems.push(SubjectProblem {
                subject_id: subject.subject_id.clone(),
                leaf: Some(leaf.field.clone()),
                code: e.code,
                message: e.message,
            });
        }
    }
    problems
}

/// Cross-check every list the job supplied before any subject is processed, so
/// a stale registry is one batch-level failure rather than one failure per
/// subject.
pub fn check_list_commitments(job: &Job) -> Result<BTreeMap<String, String>> {
    let mut list_roots: BTreeMap<String, String> = BTreeMap::new();
    for (id, lc) in job.list_commitments.iter() {
        let refs: Vec<&[u8]> = lc.values.iter().map(|s| s.as_bytes()).collect();
        if refs.is_empty() {
            continue;
        }
        let (r, depth, _) = set::build_set_tree(&refs);
        let root_hex = digest_to_hex(&r);
        if let Some(declared) = lc.declared_root.as_deref() {
            if !declared.eq_ignore_ascii_case(&root_hex) {
                return Err(ProverError::new(
                    ErrorCode::Config,
                    format!(
                        "list '{}' declares root {} but its values recompute to {}. Fix: \
                         regenerate it with `npm run list-version -- --list-id {}`.",
                        id, declared, root_hex, id
                    ),
                ));
            }
        }
        if let Some(declared_depth) = lc.declared_depth {
            if declared_depth != depth {
                return Err(ProverError::new(
                    ErrorCode::Config,
                    format!(
                        "list '{}' declares depth {} but its values recompute to depth {}. Fix: \
                         regenerate it with `npm run list-version -- --list-id {}`.",
                        id, declared_depth, depth, id
                    ),
                ));
            }
        }
        if let Some(declared_content) = lc.content_hash.as_deref() {
            let recomputed = trusset_bundle_format::registry::list_content_hash(&lc.values);
            if !declared_content.eq_ignore_ascii_case(&recomputed) {
                return Err(ProverError::new(
                    ErrorCode::ListVersionMismatch,
                    format!(
                        "list '{}' declares contentHash {} but its values recompute to {}. The \
                         registry entry and the values disagree.",
                        id, declared_content, recomputed
                    ),
                ));
            }
        }
        list_roots.insert(id.clone(), root_hex);
    }
    Ok(list_roots)
}

fn build_secrets_blob(proved: &[ProvedLeaf]) -> Result<Vec<u8>> {
    let mut entries: BTreeMap<String, SecretsEntry> = BTreeMap::new();
    for p in proved {
        entries.insert(
            p.field.clone(),
            SecretsEntry {
                value: p.plaintext_value.to_string(),
                nonce_hex: format!("0x{}", hex::encode(*p.nonce)),
                circuit: p.circuit_id.as_str().to_string(),
            },
        );
    }
    let v = serde_json::to_vec(&entries)?;
    Ok(v)
}

fn write_bundle(
    output_root: &Path,
    manifest: &Manifest,
    now_iso: &str,
    signature: &[u8; SIGNATURE_LEN],
    proved: &[ProvedLeaf],
    secrets_enc: &[u8],
) -> Result<PathBuf> {
    let wallet = &manifest.wallet_address;
    let tmp_root = output_root.join(".tmp");
    let tmp_dir = tmp_root.join(wallet);
    let final_dir = output_root.join(wallet);

    // Clean stale temp from a previous interrupted run.
    if tmp_dir.exists() {
        fs::remove_dir_all(&tmp_dir)?;
    }
    fs::create_dir_all(tmp_dir.join("proofs"))?;

    // kycHash.hex
    let mut hash_file = fs::File::create(tmp_dir.join("kycHash.hex"))?;
    hash_file.write_all(manifest.kyc_hash.as_bytes())?;
    // Spec §9 says no trailing newline.

    // proofs/<field>.bin
    for p in proved {
        let proof_path = tmp_dir.join("proofs").join(format!("{}.bin", p.field));
        let mut f = fs::File::create(&proof_path)?;
        f.write_all(&p.proof_bytes)?;
    }

    // manifest.json (with REAL createdAt now)
    let mut disk_manifest = manifest.clone();
    disk_manifest.created_at = now_iso.to_string();
    if disk_manifest.created_at == CREATED_AT_SENTINEL {
        // Shouldn't happen in practice — just guard.
        return Err(ProverError::new(
            ErrorCode::CircuitInternal,
            "now_iso accidentally matches sentinel — refusing to sign-stamp",
        ));
    }
    let disk_bytes = canonical_disk_bytes(&disk_manifest)?;
    fs::write(tmp_dir.join("manifest.json"), &disk_bytes)?;

    // manifest.sig
    fs::write(tmp_dir.join("manifest.sig"), signature.as_slice())?;

    // secrets.enc
    fs::write(tmp_dir.join("secrets.enc"), secrets_enc)?;

    // Atomic-ish rename: blow away any prior final dir, then rename.
    if final_dir.exists() {
        fs::remove_dir_all(&final_dir)?;
    }
    fs::rename(&tmp_dir, &final_dir)?;

    // Remove the staging root once it is empty. A concurrent subject may
    // still be staging its own bundle, in which case the directory is not
    // empty and `remove_dir` fails harmlessly.
    let _ = fs::remove_dir(&tmp_root);

    Ok(final_dir)
}

#[cfg(test)]
mod tests {
    // Integration-level testing of bundle writing lives in
    // `tests/end_to_end.rs` where a tempdir and real signing key are wired up.
}
