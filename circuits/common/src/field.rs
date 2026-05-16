//! Goldilocks field helpers.
//!
//! Encoding strategy: chunk arbitrary byte data into 7-byte little-endian
//! limbs. 7 bytes = 56 bits < 63 bits < log2(p) ≈ 64 bits, so every chunk
//! fits comfortably below the Goldilocks modulus p = 2^64 - 2^32 + 1 with
//! room for canonicalization. The final chunk is right-padded with zero
//! bytes if shorter than 7. To stay invertible, callers must embed an
//! explicit length encoding upstream (see `serialize::write_canonical_bytes`).

use unicode_normalization::UnicodeNormalization;
use winter_math::fields::f64::BaseElement;

pub type Felt = BaseElement;

/// Number of bytes each Goldilocks limb carries.
pub const BYTES_PER_FELT: usize = 7;

/// Encode bytes as Goldilocks field elements.
pub fn bytes_to_field(bytes: &[u8]) -> Vec<Felt> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(BYTES_PER_FELT));
    for chunk in bytes.chunks(BYTES_PER_FELT) {
        let mut limb = [0u8; 8];
        limb[..chunk.len()].copy_from_slice(chunk);
        // u64 value is at most 2^56 - 1 — strictly below the Goldilocks prime.
        out.push(Felt::new(u64::from_le_bytes(limb)));
    }
    out
}

/// Inverse of `bytes_to_field`: recover up to 7 bytes per felt. The caller
/// is responsible for trimming trailing zero padding using upstream length
/// metadata. Bytes returned in the same order they went in.
pub fn field_to_bytes(felts: &[Felt]) -> Vec<u8> {
    let mut out = Vec::with_capacity(felts.len() * BYTES_PER_FELT);
    for f in felts {
        let v: u64 = f.as_int();
        let limb = v.to_le_bytes();
        out.extend_from_slice(&limb[..BYTES_PER_FELT]);
    }
    out
}

/// Canonical encoding of a string into Goldilocks field elements:
///
/// 1. Apply Unicode NFC normalization (plan edge case 7).
/// 2. UTF-8 serialize.
/// 3. Chunk into 7-byte little-endian limbs via `bytes_to_field`.
///
/// Without NFC, `"café"` with composed vs. decomposed `é` would produce
/// different proofs and verification would silently fail across locales.
pub fn string_to_field_canonical(s: &str) -> Vec<Felt> {
    let nfc: String = s.nfc().collect();
    bytes_to_field(nfc.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_output() {
        assert_eq!(bytes_to_field(&[]), Vec::<Felt>::new());
        assert_eq!(field_to_bytes(&[]), Vec::<u8>::new());
    }

    #[test]
    fn single_chunk_under_seven_bytes_pads_to_seven() {
        let f = bytes_to_field(b"abc");
        assert_eq!(f.len(), 1);
        let back = field_to_bytes(&f);
        // Padding bytes appear as trailing zeros — caller must trim.
        assert_eq!(&back[..3], b"abc");
        assert_eq!(&back[3..], &[0u8; 4]);
    }

    #[test]
    fn seven_byte_chunks_roundtrip_cleanly() {
        let input: Vec<u8> = (0u8..=20).collect();
        let f = bytes_to_field(&input);
        // 21 bytes => 3 chunks of 7.
        assert_eq!(f.len(), 3);
        let back = field_to_bytes(&f);
        assert_eq!(back, input);
    }

    #[test]
    fn nfc_normalization_collapses_decomposed_forms() {
        // U+00E9 (composed é) vs U+0065 U+0301 (decomposed e + combining acute).
        let composed = "caf\u{00e9}";
        let decomposed = "cafe\u{0301}";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());
        assert_eq!(
            string_to_field_canonical(composed),
            string_to_field_canonical(decomposed),
            "NFC must canonicalize these to the same field element sequence"
        );
    }

    #[test]
    fn different_strings_produce_different_felts() {
        assert_ne!(
            string_to_field_canonical("Alice"),
            string_to_field_canonical("Bob")
        );
    }
}
