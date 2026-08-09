//! 32-byte domain tags used in every Rescue-Prime call (spec §7, §12.1).
//!
//! Each tag is a human-readable ASCII string padded to exactly 32 bytes with
//! `-` characters. Auditors can read them in a hex dump. Distinctness is
//! enforced at compile time via `static_assertions` — any future refactor
//! that accidentally collides two tags will fail to build.

use static_assertions::const_assert;

pub const DOMAIN_TAG_BYTES: usize = 32;

const fn pad32(label: &str) -> [u8; DOMAIN_TAG_BYTES] {
    let src = label.as_bytes();
    // Reject overly long labels at compile time.
    assert!(
        src.len() <= DOMAIN_TAG_BYTES,
        "domain tag label exceeds 32 bytes"
    );
    let mut out = [b'-'; DOMAIN_TAG_BYTES];
    let mut i = 0;
    while i < src.len() {
        out[i] = src[i];
        i += 1;
    }
    out
}

pub const LEAF_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:LEAF");
pub const NODE_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:NODE");
pub const PUBLIC_DIGEST_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:PUB-DIGEST");
pub const PROOF_DIGEST_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:PRF-DIGEST");
pub const SET_LEAF_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:SET-LEAF");
pub const SET_NODE_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:SET-NODE");
/// Tag for the hiding commitment Rescue call: `commitment = Rescue(COMMITMENT_TAG ‖ value ‖ nonce)`.
/// Spec §6 phrases commitment as `Rescue(value ‖ nonce)` without a tag; the plan
/// (§12.1) requires every Rescue call be domain-separated, so we add it here.
pub const COMMITMENT_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:COMMIT");
/// Tag for the v2 Merkle padding leaf: `pad = Rescue(MERKLE_PAD_TAG ‖ leaf_count_le8)`.
/// Padding leaves fill the sorted leaf layer to the next power of two so no
/// layer ever duplicates its last node. The tag keeps a padding leaf from
/// colliding with any real `LEAF_TAG` digest.
pub const MERKLE_PAD_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:MERKLE-PAD");
/// Tag for the v2 Merkle root wrap:
/// `root = Rescue(MERKLE_ROOT_TAG ‖ inner_root ‖ leaf_count_le8 ‖ arity_u8)`.
/// Binding the leaf count and arity into the root makes structurally
/// different trees produce distinct roots and keeps a bare leaf digest from
/// ever being interpretable as a root.
pub const MERKLE_ROOT_TAG: [u8; DOMAIN_TAG_BYTES] = pad32("TRUSSET-KYC-V2:MERKLE-ROOT");

/// Const-context inequality for two 32-byte arrays.
const fn const_ne(a: &[u8; DOMAIN_TAG_BYTES], b: &[u8; DOMAIN_TAG_BYTES]) -> bool {
    let mut i = 0;
    while i < DOMAIN_TAG_BYTES {
        if a[i] != b[i] {
            return true;
        }
        i += 1;
    }
    false
}

// All C(9,2) = 36 pairs. Adding a new tag requires extending this block.
const_assert!(const_ne(&LEAF_TAG, &NODE_TAG));
const_assert!(const_ne(&LEAF_TAG, &PUBLIC_DIGEST_TAG));
const_assert!(const_ne(&LEAF_TAG, &PROOF_DIGEST_TAG));
const_assert!(const_ne(&LEAF_TAG, &SET_LEAF_TAG));
const_assert!(const_ne(&LEAF_TAG, &SET_NODE_TAG));
const_assert!(const_ne(&LEAF_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&NODE_TAG, &PUBLIC_DIGEST_TAG));
const_assert!(const_ne(&NODE_TAG, &PROOF_DIGEST_TAG));
const_assert!(const_ne(&NODE_TAG, &SET_LEAF_TAG));
const_assert!(const_ne(&NODE_TAG, &SET_NODE_TAG));
const_assert!(const_ne(&NODE_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &PROOF_DIGEST_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &SET_LEAF_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &SET_NODE_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&PROOF_DIGEST_TAG, &SET_LEAF_TAG));
const_assert!(const_ne(&PROOF_DIGEST_TAG, &SET_NODE_TAG));
const_assert!(const_ne(&PROOF_DIGEST_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&SET_LEAF_TAG, &SET_NODE_TAG));
const_assert!(const_ne(&SET_LEAF_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&SET_NODE_TAG, &COMMITMENT_TAG));
const_assert!(const_ne(&LEAF_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&LEAF_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&NODE_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&NODE_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&PUBLIC_DIGEST_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&PROOF_DIGEST_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&PROOF_DIGEST_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&SET_LEAF_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&SET_LEAF_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&SET_NODE_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&SET_NODE_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&COMMITMENT_TAG, &MERKLE_PAD_TAG));
const_assert!(const_ne(&COMMITMENT_TAG, &MERKLE_ROOT_TAG));
const_assert!(const_ne(&MERKLE_PAD_TAG, &MERKLE_ROOT_TAG));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_32_bytes() {
        for tag in [
            &LEAF_TAG,
            &NODE_TAG,
            &PUBLIC_DIGEST_TAG,
            &PROOF_DIGEST_TAG,
            &SET_LEAF_TAG,
            &SET_NODE_TAG,
            &COMMITMENT_TAG,
            &MERKLE_PAD_TAG,
            &MERKLE_ROOT_TAG,
        ] {
            assert_eq!(tag.len(), 32);
        }
    }

    #[test]
    fn tags_are_pairwise_distinct_at_runtime_too() {
        // Belt-and-braces: compile-time const_assert already enforces this,
        // but a runtime test serves as documentation for auditors.
        let all = [
            ("LEAF", LEAF_TAG),
            ("NODE", NODE_TAG),
            ("PUB", PUBLIC_DIGEST_TAG),
            ("PRF", PROOF_DIGEST_TAG),
            ("SET-LEAF", SET_LEAF_TAG),
            ("SET-NODE", SET_NODE_TAG),
            ("COMMIT", COMMITMENT_TAG),
            ("MERKLE-PAD", MERKLE_PAD_TAG),
            ("MERKLE-ROOT", MERKLE_ROOT_TAG),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i].1, all[j].1,
                    "domain tags {} and {} are equal",
                    all[i].0, all[j].0
                );
            }
        }
    }

    #[test]
    fn tags_start_with_versioned_namespace() {
        // Cheap sanity check that the project namespace is intact. If anyone
        // changes the prefix, every shipped proof becomes invalid — the test
        // forces them to acknowledge it.
        let prefix = b"TRUSSET-KYC-V2:";
        for tag in [
            &LEAF_TAG,
            &NODE_TAG,
            &PUBLIC_DIGEST_TAG,
            &PROOF_DIGEST_TAG,
            &SET_LEAF_TAG,
            &SET_NODE_TAG,
            &COMMITMENT_TAG,
            &MERKLE_PAD_TAG,
            &MERKLE_ROOT_TAG,
        ] {
            assert!(tag.starts_with(prefix));
        }
    }
}
