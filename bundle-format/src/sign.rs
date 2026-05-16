//! ed25519 signature verification — WASM-compatible subset.
//!
//! Signing-side helpers (`SigningSecret`, key loading from hex) live in
//! `prover/src/sign.rs` because the verifier never signs.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;
pub const PUBLIC_KEY_LEN: usize = 32;

/// Verify an ed25519 signature against a raw 32-byte public key. Returns
/// `false` on any parse error, length mismatch, or signature failure — the
/// verifier path treats all of these as the same "untrusted bundle" outcome.
pub fn verify(public_key: &[u8; PUBLIC_KEY_LEN], message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[test]
    fn verifies_known_good_signature() {
        let sk = fixed_key();
        let pk = sk.verifying_key().to_bytes();
        let msg = b"manifest bytes";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn rejects_tampered_message() {
        let sk = fixed_key();
        let pk = sk.verifying_key().to_bytes();
        let sig = sk.sign(b"original").to_bytes();
        assert!(!verify(&pk, b"tampered", &sig));
    }

    #[test]
    fn rejects_tampered_signature() {
        let sk = fixed_key();
        let pk = sk.verifying_key().to_bytes();
        let mut sig = sk.sign(b"msg").to_bytes();
        sig[0] ^= 0x01;
        assert!(!verify(&pk, b"msg", &sig));
    }

    #[test]
    fn rejects_wrong_public_key() {
        let sk = fixed_key();
        let sig = sk.sign(b"msg").to_bytes();
        // All-zero key won't verify the signature signed by the all-0x42 key.
        let zero_key = [0u8; 32];
        assert!(!verify(&zero_key, b"msg", &sig));
    }
}
