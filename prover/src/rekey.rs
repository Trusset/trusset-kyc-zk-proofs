//! Per-subject re-key path (`secretsKdfVersion: 2`).
//!
//! Rotating the master key normally means re-proving every subject: the
//! old chain derived nonces from the master key, so a new master key
//! produced different commitments and a different `kycHash`. With the
//! wrapped per-subject key the payload key is independent of the master
//! key, so rotation only has to unwrap under the old key and re-wrap
//! under the new one.
//!
//! `rekey_bundle` rewrites `secrets.enc` in place and touches nothing
//! else. `manifest.json`, `manifest.sig`, `kycHash.hex`, and every
//! `proofs/<leaf>.bin` are unchanged, so the signature stays valid and
//! the on-chain root still matches: `secrets.enc` sits outside the signing
//! payload by design.

use crate::encrypt::{encrypt_secrets_v2, unwrap_subject_key_v2};
use crate::errors::{ErrorCode, ProverError, Result};
use crate::job::parse_config_hash;
use std::path::Path;
use trusset_bundle_format::manifest::{Manifest, SECRETS_KDF_VERSION};

/// Outcome of a re-key, returned for operator-facing reporting.
#[derive(Debug)]
pub struct RekeyReport {
    pub subject_id: String,
    pub secrets_path: std::path::PathBuf,
    pub bytes_written: usize,
}

/// Re-wrap one bundle's `secrets.enc` from `old_master_key` to
/// `new_master_key`. The bundle's proofs and manifest are untouched.
pub fn rekey_bundle(
    bundle_dir: &Path,
    old_master_key: &[u8; 32],
    new_master_key: &[u8; 32],
) -> Result<RekeyReport> {
    let manifest_bytes = std::fs::read(bundle_dir.join("manifest.json"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;

    if manifest.secrets_kdf_version != SECRETS_KDF_VERSION {
        return Err(ProverError::new(
            ErrorCode::Input,
            format!(
                "bundle uses secretsKdfVersion {} — only version {} supports re-keying without re-proving",
                manifest.secrets_kdf_version, SECRETS_KDF_VERSION
            ),
        ));
    }

    let config_hash_hex = manifest.config_hash.as_deref().ok_or_else(|| {
        ProverError::new(
            ErrorCode::Input,
            "manifest has no configHash — cannot reconstruct the KDF context",
        )
    })?;
    let config_hash = parse_config_hash(config_hash_hex)?;

    let secrets_path = bundle_dir.join("secrets.enc");
    let blob = std::fs::read(&secrets_path)?;
    let subject_id = manifest.wallet_address.as_bytes();

    let subject_key = unwrap_subject_key_v2(
        old_master_key,
        subject_id,
        manifest.epoch_days,
        &config_hash,
        &blob,
    )?;

    let plaintext = crate::encrypt::decrypt_secrets(
        old_master_key,
        subject_id,
        manifest.epoch_days,
        &config_hash,
        manifest.secrets_kdf_version,
        &blob,
    )?;

    let rewrapped = encrypt_secrets_v2(
        new_master_key,
        &subject_key,
        subject_id,
        manifest.epoch_days,
        &config_hash,
        &plaintext,
    )?;

    let tmp_path = secrets_path.with_extension("enc.tmp");
    std::fs::write(&tmp_path, &rewrapped)?;
    std::fs::rename(&tmp_path, &secrets_path)?;

    Ok(RekeyReport {
        subject_id: manifest.wallet_address.clone(),
        secrets_path,
        bytes_written: rewrapped.len(),
    })
}
