//! `secrets.enc` encryption with libsodium-compatible secretbox (spec §4, §12.7).
//!
//! Algorithm: XSalsa20-Poly1305 via the pure-Rust `xsalsa20poly1305` crate
//! (RustCrypto). Output bytes are bit-compatible with libsodium's
//! `crypto_secretbox_easy`, so an auditor can decrypt with either toolchain.
//!
//! Per-subject key derivation:
//!
//! ```text
//! secretbox_key = HKDF-SHA256(
//!   ikm  = TRUSSET_KYC_MASTER_KEY,
//!   salt = "trusset-kyc-v2/secretbox",
//!   info = subject_id_bytes || epoch_days_le8 || config_hash || kdf_version_le4
//! )
//! ```
//!
//! Nonce: 24 bytes, deterministically derived from the same KDF chain so
//! re-runs produce byte-identical `secrets.enc`. With a unique
//! `(subject_id, epoch_days, config_hash, kdf_version)` quadruple per
//! encryption, the nonce-reuse condition for XSalsa20-Poly1305 (key+nonce
//! reuse with different plaintext) is structurally impossible.

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
pub use trusset_bundle_format::manifest::SECRETS_KDF_VERSION;

const KDF_SALT_KEY: &[u8] = b"trusset-kyc-v2/secretbox-key";
const KDF_SALT_NONCE: &[u8] = b"trusset-kyc-v2/secretbox-nonce";

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Derive `(key, nonce)` for a subject's `secrets.enc`.
fn derive_box_material(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
) -> (Zeroizing<[u8; KEY_LEN]>, [u8; NONCE_LEN]) {
    let mut info = Vec::with_capacity(subject_id.len() + 8 + 32 + 4);
    info.extend_from_slice(subject_id);
    info.extend_from_slice(&epoch_days.to_le_bytes());
    info.extend_from_slice(config_hash);
    info.extend_from_slice(&SECRETS_KDF_VERSION.to_le_bytes());

    let hk_key = Hkdf::<Sha256>::new(Some(KDF_SALT_KEY), master_key);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk_key
        .expand(&info, key.as_mut())
        .expect("HKDF expand to 32 bytes infallible");

    let hk_nonce = Hkdf::<Sha256>::new(Some(KDF_SALT_NONCE), master_key);
    let mut nonce = [0u8; NONCE_LEN];
    hk_nonce
        .expand(&info, &mut nonce)
        .expect("HKDF expand to 24 bytes infallible");

    (key, nonce)
}

/// Encrypt a secrets plaintext into a single byte stream. Output layout:
///   `nonce(24) ‖ ciphertext_with_mac(plaintext.len + 16)`
pub fn encrypt_secrets(
    master_key: &[u8; 32],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let (key, nonce_bytes) = derive_box_material(master_key, subject_id, epoch_days, config_hash);

    let cipher = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
        ProverError::new(
            ErrorCode::CircuitInternal,
            format!("secretbox encrypt failed: {}", e),
        )
    })?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a secrets blob produced by `encrypt_secrets`. Used by the
/// `npm run decrypt` round-trip (spec §10) and the integration tests here.
pub fn decrypt_secrets(
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
    let (key, derived_nonce) = derive_box_material(master_key, subject_id, epoch_days, config_hash);
    if file_nonce != derived_nonce {
        return Err(ProverError::new(
            ErrorCode::Input,
            "secrets.enc nonce does not match derived nonce — wrong key or tampered file",
        ));
    }
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&derived_nonce);
    let pt = cipher.decrypt(nonce, ct).map_err(|_| {
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
    fn cfg() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let pt = b"private subject data, do not share";
        let ct = encrypt_secrets(&master(), b"0xAbCd", 20587, &cfg(), pt).unwrap();
        let recovered = decrypt_secrets(&master(), b"0xAbCd", 20587, &cfg(), &ct).unwrap();
        assert_eq!(recovered.as_slice(), pt);
    }

    #[test]
    fn encryption_is_byte_deterministic() {
        let pt = b"x";
        let a = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        let b = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        assert_eq!(a, b, "secrets.enc must be byte-identical across runs");
    }

    #[test]
    fn different_subjects_produce_different_ciphertexts() {
        let pt = b"x";
        let a = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        let b = encrypt_secrets(&master(), b"0xB", 20587, &cfg(), pt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_epoch_days_produce_different_ciphertexts() {
        let pt = b"x";
        let a = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        let b = encrypt_secrets(&master(), b"0xA", 20588, &cfg(), pt).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn decrypt_rejects_wrong_master_key() {
        let pt = b"x";
        let ct = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        let mut other = master();
        other[0] ^= 0x01;
        let err = decrypt_secrets(&other, b"0xA", 20587, &cfg(), &ct).unwrap_err();
        assert_eq!(err.code, ErrorCode::Input);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let pt = b"x";
        let mut ct = encrypt_secrets(&master(), b"0xA", 20587, &cfg(), pt).unwrap();
        ct[NONCE_LEN + 1] ^= 0x01;
        assert!(decrypt_secrets(&master(), b"0xA", 20587, &cfg(), &ct).is_err());
    }

    #[test]
    fn decrypt_rejects_too_short() {
        assert!(decrypt_secrets(&master(), b"x", 0, &cfg(), &[0u8; 10]).is_err());
    }
}
