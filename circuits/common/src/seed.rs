//! Deterministic seed derivation (plan §"Determinism", spec §12.8).
//!
//! All randomness in the prover flows from `TRUSSET_KYC_MASTER_KEY` through
//! HKDF-SHA256. The prover never reads OS entropy directly; in determinism
//! mode any attempt to do so panics (see `prover/Cargo.toml` getrandom hook).
//!
//! Two derivation steps:
//!
//! ```text
//! subject_seed = HKDF-SHA256(
//!   ikm  = master_key,
//!   salt = "trusset-kyc-v2/subject",
//!   info = subject_id || epoch_days_le8 || config_hash || circuits_version_le4
//! )
//!
//! leaf_seed = HKDF-SHA256(
//!   ikm  = subject_seed,
//!   salt = "trusset-kyc-v2/leaf",
//!   info = field_name || circuit_id_byte || params_hash
//! )
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MASTER_KEY_LEN: usize = 32;
pub const SEED_LEN: usize = 32;

const SALT_SUBJECT: &[u8] = b"trusset-kyc-v2/subject";
const SALT_LEAF: &[u8] = b"trusset-kyc-v2/leaf";
const SALT_PROVER: &[u8] = b"trusset-kyc-v2/prover";

/// HKDF info-string suffix for the Phase 2B Winterfell prover PRNG seed.
/// `prover_seed(leaf_seed, field_name)` is the ONLY entropy source the
/// Winterfell prover sees — no OS randomness, no time-of-day.
pub const PROVER_SEED_INFO: &[u8] = b"prover-seed";

/// Derive the 32-byte per-subject seed. Auto-zeroed on drop.
pub fn derive_subject_seed(
    master_key: &[u8; MASTER_KEY_LEN],
    subject_id: &[u8],
    epoch_days: u64,
    config_hash: &[u8; 32],
    circuits_version: u32,
) -> Zeroizing<[u8; SEED_LEN]> {
    let mut info = Vec::with_capacity(subject_id.len() + 8 + 32 + 4);
    info.extend_from_slice(subject_id);
    info.extend_from_slice(&epoch_days.to_le_bytes());
    info.extend_from_slice(config_hash);
    info.extend_from_slice(&circuits_version.to_le_bytes());

    let hk = Hkdf::<Sha256>::new(Some(SALT_SUBJECT), master_key);
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    out
}

/// Derive the 32-byte per-leaf seed. Auto-zeroed on drop.
/// The first 32 bytes are used both as the hiding-commitment nonce and as
/// the seed for any auxiliary RNG inside the AIR prover.
pub fn derive_leaf_seed(
    subject_seed: &[u8; SEED_LEN],
    field_name: &[u8],
    circuit_id: u8,
    params_hash: &[u8; 32],
) -> Zeroizing<[u8; SEED_LEN]> {
    let mut info = Vec::with_capacity(field_name.len() + 1 + 32);
    info.extend_from_slice(field_name);
    info.push(circuit_id);
    info.extend_from_slice(params_hash);

    let hk = Hkdf::<Sha256>::new(Some(SALT_LEAF), subject_seed);
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    out
}

/// Derive the 32-byte per-leaf Winterfell prover PRNG seed (Phase 2B).
/// Auto-zeroed on drop. Folds the field name in so that two circuits sharing
/// a master key + subject can never produce identical prover transcripts.
pub fn derive_prover_seed(
    leaf_seed: &[u8; SEED_LEN],
    field_name: &[u8],
) -> Zeroizing<[u8; SEED_LEN]> {
    let mut info = Vec::with_capacity(PROVER_SEED_INFO.len() + 1 + field_name.len());
    info.extend_from_slice(PROVER_SEED_INFO);
    info.push(b'/');
    info.extend_from_slice(field_name);

    let hk = Hkdf::<Sha256>::new(Some(SALT_PROVER), leaf_seed);
    let mut out = Zeroizing::new([0u8; SEED_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master() -> [u8; MASTER_KEY_LEN] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn config_hash() -> [u8; 32] {
        [0xab; 32]
    }

    #[test]
    fn subject_seed_is_deterministic() {
        let a = derive_subject_seed(&master(), b"0xAbCd", 20587, &config_hash(), 1);
        let b = derive_subject_seed(&master(), b"0xAbCd", 20587, &config_hash(), 1);
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn subject_id_change_changes_seed() {
        let a = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let b = derive_subject_seed(&master(), b"0xB", 20587, &config_hash(), 1);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn epoch_days_change_changes_seed() {
        let a = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let b = derive_subject_seed(&master(), b"0xA", 20588, &config_hash(), 1);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn config_hash_change_changes_seed() {
        let a = derive_subject_seed(&master(), b"0xA", 20587, &[0xab; 32], 1);
        let b = derive_subject_seed(&master(), b"0xA", 20587, &[0xac; 32], 1);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn circuits_version_change_changes_seed() {
        let a = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let b = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 2);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn leaf_seed_is_deterministic() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let a = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        let b = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn leaf_seed_field_name_change() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let a = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        let b = derive_leaf_seed(&subj, b"firstName", 1, &[0u8; 32]);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn leaf_seed_circuit_id_change() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let a = derive_leaf_seed(&subj, b"x", 1, &[0u8; 32]);
        let b = derive_leaf_seed(&subj, b"x", 2, &[0u8; 32]);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn leaf_seed_params_hash_change() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let a = derive_leaf_seed(&subj, b"x", 1, &[0u8; 32]);
        let b = derive_leaf_seed(&subj, b"x", 1, &[1u8; 32]);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn prover_seed_is_deterministic() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let leaf = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        let a = derive_prover_seed(&leaf, b"dateOfBirth");
        let b = derive_prover_seed(&leaf, b"dateOfBirth");
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn prover_seed_differs_from_leaf_seed() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let leaf = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        let prov = derive_prover_seed(&leaf, b"dateOfBirth");
        // The prover seed must NEVER equal the leaf seed — the leaf seed is
        // already used as the hiding-commitment nonce, so reusing it as the
        // STARK PRNG seed would leak the commitment randomness through the
        // FRI transcript.
        assert_ne!(prov.as_ref(), leaf.as_ref());
    }

    #[test]
    fn prover_seed_field_name_change() {
        let subj = derive_subject_seed(&master(), b"0xA", 20587, &config_hash(), 1);
        let leaf = derive_leaf_seed(&subj, b"dateOfBirth", 1, &[0u8; 32]);
        let a = derive_prover_seed(&leaf, b"dateOfBirth");
        let b = derive_prover_seed(&leaf, b"firstName");
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
