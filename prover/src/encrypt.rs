//! `secrets.enc` encryption with libsodium-compatible secretbox (spec §4, §12.7).
//!
//! Algorithm: XSalsa20-Poly1305 via the pure-Rust `xsalsa20poly1305` crate
//! (RustCrypto). Output bytes are bit-compatible with libsodium's
//! `crypto_secretbox_easy`, so an auditor can decrypt with either toolchain.
//!
//! Two on-disk layouts, selected by `manifest.secretsKdfVersion`:
//!
//! - **Version 1** (v2.0 bundles, decrypt-only path): the secretbox key
//!   and nonce derive directly from the master key. One master-key
//!   compromise recovers every nonce ever issued.
//!
//! - **Version 2** (v2.1 default): the payload is encrypted under an
//!   independent 32-byte per-subject key, which is itself wrapped under a
//!   master-derived wrapping key. The master key becomes a key-wrapping
//!   key only; recovering a subject's secrets now requires both the master
//!   key and that subject's `secrets.enc` blob.
//!
//! ```text
//! v2 layout:
//!   version_byte(=2)
//!   wrap_nonce(24) || secretbox(wrap_key, subject_key)      (32 + 16 = 48)
//!   data_nonce(24) || secretbox(subject_key, secrets_json)
//!
//! wrap_key   = HKDF(master, salt="trusset-kyc-v2/wrap-key",   info=ctx)
//! wrap_nonce = HKDF(master, salt="trusset-kyc-v2/wrap-nonce", info=ctx)
//! data_nonce = HKDF(subject_key, salt="trusset-kyc-v2/data-nonce", info=ctx)
//! ctx        = subject_id || epoch_days_le8 || config_hash || kdf_version_le4
//! ```
//!
//! Under `security.deterministic: true` the subject key is HKDF-derived
//! from the master key so re-runs are byte-identical; the wrapping still
//! holds because an attacker without the specific blob cannot reconstruct
//! the payload. Under `deterministic: false` the subject key is drawn from
//! OS entropy and stored only inside the wrapped blob.

use crate::errors::{ErrorCode, ProverError, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    Key, Nonce, XSalsa20Poly1305,
};
use zeroize::Zeroizing;

// Stable version constant folded into the per-subject KDF info. Sourced
// from `trusset-bundle-format` so the manifest's `secretsKdfVersion` field
// is wired to the same value (plan §"Resolved edge cases" 10).
pub use trusset_bundle_format::manifest::{SECRETS_KDF_VERSION, SECRETS_KDF_VERSION_V1};

const KDF_SALT_KEY: &[u8] = b"trusset-kyc-v2/secretbox-key";
const KDF_SALT_NONCE: &[u8] = b"trusset-kyc-v2/secretbox-nonce";
const KDF_SALT_WRAP_KEY: &[u8] = b"trusset-kyc-v2/wrap-key";
const KDF_SALT_WRAP_NONCE: &[u8] = b"trusset-kyc-v2/wrap-nonce";
const KDF_SALT_DATA_NONCE: &[u8] = b"trusset-kyc-v2/data-nonce";

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const WRAPPED_KEY_LEN: usize = KEY_LEN + 16;

fn kdf_context(
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    kdf_version: u32,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(subject_id.len() + 8 + 32 + 4);
    info.extend_from_slice(subject_id);
    info.extend_from_slice(&epoch_days.to_le_bytes());
    info.extend_from_slice(config_hash);
    info.extend_from_slice(&kdf_version.to_le_bytes());
    info
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF expand infallible for <= 255*32 bytes");
}

// ============================ v1 (legacy, decrypt-only) ============================

/// Derive `(key, nonce)` for a v1 subject's `secrets.enc`.
fn derive_box_material_v1(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
) -> (Zeroizing<[u8; KEY_LEN]>, [u8; NONCE_LEN]) {
    let info = kdf_context(subject_id, epoch_days, config_hash, SECRETS_KDF_VERSION_V1);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_expand(KDF_SALT_KEY, master_key, &info, key.as_mut());
    let mut nonce = [0u8; NONCE_LEN];
    hkdf_expand(KDF_SALT_NONCE, master_key, &info, &mut nonce);
    (key, nonce)
}

// ============================ v2 (wrapped subject key) ============================

/// Encrypt a payload under a subject key that is itself wrapped by the
/// master key (`secretsKdfVersion == 2`). The `subject_key` is derived
/// deterministically or drawn from entropy by the caller.
pub fn encrypt_secrets_v2(
    master_key: &[u8; 32],
    subject_key: &[u8; KEY_LEN],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ctx = kdf_context(subject_id, epoch_days, config_hash, SECRETS_KDF_VERSION);

    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_expand(KDF_SALT_WRAP_KEY, master_key, &ctx, wrap_key.as_mut());
    let mut wrap_nonce = [0u8; NONCE_LEN];
    hkdf_expand(KDF_SALT_WRAP_NONCE, master_key, &ctx, &mut wrap_nonce);

    let wrap_cipher = XSalsa20Poly1305::new(Key::from_slice(wrap_key.as_ref()));
    let wrapped_key = wrap_cipher
        .encrypt(Nonce::from_slice(&wrap_nonce), subject_key.as_slice())
        .map_err(|e| {
            ProverError::new(
                ErrorCode::CircuitInternal,
                format!("subject-key wrap failed: {}", e),
            )
        })?;

    let mut data_nonce = [0u8; NONCE_LEN];
    hkdf_expand(KDF_SALT_DATA_NONCE, subject_key, &ctx, &mut data_nonce);
    let data_cipher = XSalsa20Poly1305::new(Key::from_slice(subject_key));
    let data_ct = data_cipher
        .encrypt(Nonce::from_slice(&data_nonce), plaintext)
        .map_err(|e| {
            ProverError::new(
                ErrorCode::CircuitInternal,
                format!("secretbox encrypt failed: {}", e),
            )
        })?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + wrapped_key.len() + NONCE_LEN + data_ct.len());
    out.push(SECRETS_KDF_VERSION as u8);
    out.extend_from_slice(&wrap_nonce);
    out.extend_from_slice(&wrapped_key);
    out.extend_from_slice(&data_nonce);
    out.extend_from_slice(&data_ct);
    Ok(out)
}

/// Unwrap the per-subject key from a v2 `secrets.enc` blob. Used by the
/// re-key path and by decryption.
pub fn unwrap_subject_key_v2(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    blob: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let (wrapped_key, _rest) = split_v2_blob(blob)?;
    let ctx = kdf_context(subject_id, epoch_days, config_hash, SECRETS_KDF_VERSION);

    let mut wrap_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf_expand(KDF_SALT_WRAP_KEY, master_key, &ctx, wrap_key.as_mut());
    let mut wrap_nonce = [0u8; NONCE_LEN];
    hkdf_expand(KDF_SALT_WRAP_NONCE, master_key, &ctx, &mut wrap_nonce);

    let wrap_cipher = XSalsa20Poly1305::new(Key::from_slice(wrap_key.as_ref()));
    let key_bytes = wrap_cipher
        .decrypt(Nonce::from_slice(&wrap_nonce), wrapped_key)
        .map_err(|_| {
            ProverError::new(
                ErrorCode::Input,
                "secrets.enc key unwrap failed — wrong master key or tampered file",
            )
        })?;
    if key_bytes.len() != KEY_LEN {
        return Err(ProverError::new(
            ErrorCode::Input,
            "unwrapped subject key has wrong length",
        ));
    }
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&key_bytes);
    Ok(out)
}

fn split_v2_blob(blob: &[u8]) -> Result<(&[u8], &[u8])> {
    let min = 1 + NONCE_LEN + WRAPPED_KEY_LEN + NONCE_LEN;
    if blob.len() < min || blob[0] != SECRETS_KDF_VERSION as u8 {
        return Err(ProverError::new(
            ErrorCode::Input,
            "secrets.enc is not a well-formed v2 blob",
        ));
    }
    let wrapped_start = 1 + NONCE_LEN;
    let wrapped_end = wrapped_start + WRAPPED_KEY_LEN;
    Ok((&blob[wrapped_start..wrapped_end], &blob[wrapped_end..]))
}

// ============================ public dispatch ============================

/// Decrypt a `secrets.enc` blob of either version. `kdf_version` comes from
/// `manifest.secretsKdfVersion`.
pub fn decrypt_secrets(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    kdf_version: u32,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if kdf_version == SECRETS_KDF_VERSION_V1 {
        return decrypt_secrets_v1(master_key, subject_id, epoch_days, config_hash, blob);
    }
    if kdf_version != SECRETS_KDF_VERSION {
        return Err(ProverError::new(
            ErrorCode::Input,
            format!("unsupported secretsKdfVersion {}", kdf_version),
        ));
    }
    let subject_key = unwrap_subject_key_v2(master_key, subject_id, epoch_days, config_hash, blob)?;
    let (_wrapped, data) = split_v2_blob(blob)?;
    if data.len() < NONCE_LEN {
        return Err(ProverError::new(ErrorCode::Input, "secrets.enc too short"));
    }
    let (data_nonce, ct) = data.split_at(NONCE_LEN);
    let cipher = XSalsa20Poly1305::new(Key::from_slice(subject_key.as_ref()));
    let pt = cipher
        .decrypt(Nonce::from_slice(data_nonce), ct)
        .map_err(|_| {
            ProverError::new(
                ErrorCode::Input,
                "secrets.enc authentication failed — wrong key or tampered file",
            )
        })?;
    Ok(Zeroizing::new(pt))
}

fn decrypt_secrets_v1(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    ciphertext_with_nonce: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext_with_nonce.len() < NONCE_LEN {
        return Err(ProverError::new(ErrorCode::Input, "secrets.enc too short"));
    }
    let (file_nonce, ct) = ciphertext_with_nonce.split_at(NONCE_LEN);
    let (key, derived_nonce) =
        derive_box_material_v1(master_key, subject_id, epoch_days, config_hash);
    if file_nonce != derived_nonce {
        return Err(ProverError::new(
            ErrorCode::Input,
            "secrets.enc nonce does not match derived nonce — wrong key or tampered file",
        ));
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()));
    let pt = cipher
        .decrypt(Nonce::from_slice(&derived_nonce), ct)
        .map_err(|_| {
            ProverError::new(
                ErrorCode::Input,
                "secrets.enc authentication failed — wrong key or tampered file",
            )
        })?;
    Ok(Zeroizing::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = i as u8;
        }
        m
    }
    fn subject_key() -> [u8; 32] {
        [0x5a; 32]
    }
    fn cfg() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn v2_encrypt_decrypt_roundtrip() {
        let pt = b"private subject data, do not share";
        let ct =
            encrypt_secrets_v2(&master(), &subject_key(), b"0xAbCd", 20587, &cfg(), pt).unwrap();
        let recovered = decrypt_secrets(
            &master(),
            b"0xAbCd",
            20587,
            &cfg(),
            SECRETS_KDF_VERSION,
            &ct,
        )
        .unwrap();
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn v2_is_byte_deterministic_for_fixed_subject_key() {
        let pt = b"x";
        let a = encrypt_secrets_v2(&master(), &subject_key(), b"0xA", 20587, &cfg(), pt).unwrap();
        let b = encrypt_secrets_v2(&master(), &subject_key(), b"0xA", 20587, &cfg(), pt).unwrap();
        assert_eq!(a, b, "secrets.enc must be byte-identical across runs");
        assert_eq!(a[0], SECRETS_KDF_VERSION as u8);
    }

    #[test]
    fn v2_rekey_preserves_plaintext_under_new_master() {
        let pt = b"rotate me";
        let old_master = master();
        let mut new_master = master();
        new_master[0] ^= 0xff;
        let sk = subject_key();

        let ct = encrypt_secrets_v2(&old_master, &sk, b"0xA", 20587, &cfg(), pt).unwrap();
        // Unwrap under old master, re-wrap under new master, same subject key.
        let recovered_key = unwrap_subject_key_v2(&old_master, b"0xA", 20587, &cfg(), &ct).unwrap();
        assert_eq!(recovered_key.as_ref(), &sk);
        let rekeyed =
            encrypt_secrets_v2(&new_master, &recovered_key, b"0xA", 20587, &cfg(), pt).unwrap();
        // Old master can no longer read the rekeyed blob; new master can.
        assert!(decrypt_secrets(
            &old_master,
            b"0xA",
            20587,
            &cfg(),
            SECRETS_KDF_VERSION,
            &rekeyed
        )
        .is_err());
        let out = decrypt_secrets(
            &new_master,
            b"0xA",
            20587,
            &cfg(),
            SECRETS_KDF_VERSION,
            &rekeyed,
        )
        .unwrap();
        assert_eq!(out.as_slice(), pt);
    }

    #[test]
    fn v2_decrypt_rejects_wrong_master_key() {
        let pt = b"x";
        let ct = encrypt_secrets_v2(&master(), &subject_key(), b"0xA", 20587, &cfg(), pt).unwrap();
        let mut other = master();
        other[0] ^= 0x01;
        let err =
            decrypt_secrets(&other, b"0xA", 20587, &cfg(), SECRETS_KDF_VERSION, &ct).unwrap_err();
        assert_eq!(err.code, ErrorCode::Input);
    }

    #[test]
    fn v2_decrypt_rejects_tampered_ciphertext() {
        let pt = b"x";
        let mut ct =
            encrypt_secrets_v2(&master(), &subject_key(), b"0xA", 20587, &cfg(), pt).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(
            decrypt_secrets(&master(), b"0xA", 20587, &cfg(), SECRETS_KDF_VERSION, &ct).is_err()
        );
    }

    #[test]
    fn v1_blob_still_decrypts_via_version_dispatch() {
        // Reconstruct a v1 blob using the legacy derivation and confirm the
        // dispatcher reads it when secretsKdfVersion == 1.
        let pt = b"legacy payload";
        let (key, nonce) = derive_box_material_v1(&master(), b"0xA", 20587, &cfg());
        let cipher = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()));
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), pt.as_slice())
            .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        let out = decrypt_secrets(
            &master(),
            b"0xA",
            20587,
            &cfg(),
            SECRETS_KDF_VERSION_V1,
            &blob,
        )
        .unwrap();
        assert_eq!(out.as_slice(), pt);
    }
}
