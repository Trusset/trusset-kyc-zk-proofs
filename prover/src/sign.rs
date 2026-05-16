//! ed25519 manifest signing (plan §"Determinism", §"Output bundle").
//!
//! Signing seed: 32 bytes read from the env var named by
//! `manifest.signingKeyEnv` in the config (default `TRUSSET_KYC_SIGNING_KEY`).
//!
//! ed25519-dalek produces deterministic signatures by default (RFC 8032), so
//! identical signing inputs yield identical 64-byte signature bytes —
//! satisfying the determinism canary.

use crate::errors::{ErrorCode, ProverError, Result};
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use zeroize::Zeroize;

pub use trusset_bundle_format::sign::{verify, PUBLIC_KEY_LEN, SIGNATURE_LEN};

/// Load a signing key from a 32-byte hex string. Wipes the source on drop.
pub struct SigningSecret(SigningKey);

impl std::fmt::Debug for SigningSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the secret in logs / panics.
        f.write_str("SigningSecret(<redacted>)")
    }
}

impl SigningSecret {
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
            .map_err(|_| ProverError::new(ErrorCode::KeyMalformed, "signing key is not hex"))?;
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(ProverError::new(
                ErrorCode::KeyMalformed,
                format!(
                    "signing key must be {} bytes, got {}",
                    SECRET_KEY_LENGTH,
                    bytes.len()
                ),
            ));
        }
        let mut key_bytes = [0u8; SECRET_KEY_LENGTH];
        key_bytes.copy_from_slice(&bytes);
        let sk = SigningKey::from_bytes(&key_bytes);
        // Zeroize the local copy now that the key has been moved into SigningKey.
        let _ = bytes;
        key_bytes.zeroize();
        Ok(SigningSecret(sk))
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(message).to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key_hex() -> &'static str {
        // 32 bytes of 0x42 — deterministic test key.
        "4242424242424242424242424242424242424242424242424242424242424242"
    }

    #[test]
    fn signs_and_verifies_roundtrip() {
        let s = SigningSecret::from_hex(fixed_key_hex()).unwrap();
        let pk = s.public_key();
        let sig = s.sign(b"hello world");
        assert!(verify(&pk, b"hello world", &sig));
    }

    #[test]
    fn signature_is_deterministic() {
        let s = SigningSecret::from_hex(fixed_key_hex()).unwrap();
        let a = s.sign(b"manifest bytes");
        let b = s.sign(b"manifest bytes");
        assert_eq!(a, b, "ed25519 (RFC 8032) must be deterministic");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let s = SigningSecret::from_hex(fixed_key_hex()).unwrap();
        let pk = s.public_key();
        let sig = s.sign(b"original");
        assert!(!verify(&pk, b"tampered", &sig));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let s = SigningSecret::from_hex(fixed_key_hex()).unwrap();
        let pk = s.public_key();
        let mut sig = s.sign(b"msg");
        sig[0] ^= 0x01;
        assert!(!verify(&pk, b"msg", &sig));
    }

    #[test]
    fn rejects_short_hex() {
        let err = SigningSecret::from_hex("4242").unwrap_err();
        assert_eq!(err.code, ErrorCode::KeyMalformed);
    }

    #[test]
    fn rejects_non_hex() {
        let err = SigningSecret::from_hex("not-hex").unwrap_err();
        assert_eq!(err.code, ErrorCode::KeyMalformed);
    }

    #[test]
    fn accepts_0x_prefix() {
        let pre = SigningSecret::from_hex(&format!("0x{}", fixed_key_hex())).unwrap();
        let plain = SigningSecret::from_hex(fixed_key_hex()).unwrap();
        assert_eq!(pre.public_key(), plain.public_key());
    }
}
