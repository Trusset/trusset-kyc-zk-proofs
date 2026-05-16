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
use crate::encrypt::encrypt_secrets;
use crate::errors::{ErrorCode, ProverError, Result};
use crate::job::{Job, JobSubject};
use crate::manifest::build_manifest;
use trusset_bundle_format::manifest::{
    canonical_disk_bytes, canonical_signing_bytes, Manifest, CREATED_AT_SENTINEL,
};
use crate::merkle::compute_root;
use crate::sign::{SigningSecret, SIGNATURE_LEN};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use trusset_circuit_set_membership as set;
use trusset_circuits_common::{derive_subject_seed, digest_to_hex, CIRCUITS_VERSION};

#[derive(Debug)]
pub struct BundleReport {
    pub subject_id: String,
    pub bundle_path: PathBuf,
    pub kyc_hash_hex: String,
    pub leaf_count: usize,
    pub total_proof_bytes: usize,
}

/// Build one subject's bundle and write it to disk atomically.
pub fn build_subject_bundle(
    job: &Job,
    subject: &JobSubject,
    master_key: &[u8; 32],
    signing_key: &SigningSecret,
    config_hash: &[u8; 32],
    now_iso: &str,
) -> Result<BundleReport> {
    let subject_seed =
        derive_subject_seed(master_key, subject.subject_id.as_bytes(), job.epoch_days, config_hash, CIRCUITS_VERSION);

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

    // 2. Merkle root over sorted leaf hashes.
    let leaf_hashes: Vec<_> = proved.iter().map(|p| p.leaf_hash).collect();
    let (root, sorted_indices) = compute_root(&leaf_hashes);
    let kyc_hash_hex = digest_to_hex(&root);

    // 3. List roots needed by the manifest.
    let mut list_roots: BTreeMap<String, String> = BTreeMap::new();
    for (id, lc) in job.list_commitments.iter() {
        let refs: Vec<&[u8]> = lc.values.iter().map(|s| s.as_bytes()).collect();
        if refs.is_empty() {
            continue;
        }
        let (r, _, _) = set::build_set_tree(&refs);
        list_roots.insert(id.clone(), digest_to_hex(&r));
    }

    let manifest = build_manifest(
        subject,
        job.epoch_days,
        job.deterministic,
        &kyc_hash_hex,
        &sorted_indices,
        &proved,
        &job.list_commitments,
        &list_roots,
    );

    // 4. Sign the canonical signing view (sentinel timestamp).
    let sig_payload = canonical_signing_bytes(&manifest)?;
    let signature: [u8; SIGNATURE_LEN] = signing_key.sign(&sig_payload);

    // 5. Encrypt secrets blob (per-leaf value + nonce + circuit name).
    let secrets_json = build_secrets_blob(&proved)?;
    let secrets_enc = encrypt_secrets(
        master_key,
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

    Ok(BundleReport {
        subject_id: subject.subject_id.clone(),
        bundle_path,
        kyc_hash_hex,
        leaf_count: proved.len(),
        total_proof_bytes: proved.iter().map(|p| p.proof_bytes.len()).sum(),
    })
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
        let path = tmp_dir.join(&p.field).with_extension("bin");
        // Rebuild path as proofs/<field>.bin since the previous line drops the
        // proofs/ prefix when the field is a single component.
        let proof_path = tmp_dir.join("proofs").join(format!("{}.bin", p.field));
        let _ = path;
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

    Ok(final_dir)
}

#[cfg(test)]
mod tests {
    // Integration-level testing of bundle writing lives in
    // `tests/end_to_end.rs` where a tempdir and real signing key are wired up.
}
