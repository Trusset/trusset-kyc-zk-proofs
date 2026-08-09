//! Canonical serialization helpers (plan §4 "Determinism", spec §12.8).
//!
//! No JSON. No length-prefixed strings without explicit length encoding.
//! Integers are little-endian. Digests are serialized big-endian per limb
//! so the resulting hex string reads left-to-right in the natural order.
//!
//! Every byte stream that ever feeds a hash input goes through this module —
//! the prover must not invent ad-hoc layouts.

use crate::field::Felt;
use crate::hash::{Digest, DIGEST_LEN_BYTES, DIGEST_LEN_FELTS};

/// Append a u64 in little-endian (8 bytes).
pub fn write_canonical_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a length-prefixed byte slice: `u32_le len ‖ bytes`.
///
/// The 4-byte length cap (2^32 - 1) is intentional: real KYC field values
/// are never anywhere close, and a smaller prefix keeps the canonical
/// encoding compact. Callers that need >4 GiB payloads should compose
/// multiple chunks.
pub fn write_canonical_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len: u32 = bytes
        .len()
        .try_into()
        .expect("canonical byte slice exceeds u32::MAX");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Serialize a digest as 32 bytes: each of the 4 felts as 8 big-endian bytes.
/// BE per limb is what every `kycHash.hex` consumer expects (read l→r).
pub fn digest_to_bytes(d: &Digest) -> [u8; DIGEST_LEN_BYTES] {
    let mut out = [0u8; DIGEST_LEN_BYTES];
    for (i, f) in d.iter().enumerate() {
        let v: u64 = f.as_int();
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Inverse of `digest_to_bytes`.
pub fn digest_from_bytes(bytes: &[u8; DIGEST_LEN_BYTES]) -> Digest {
    let mut out = [Felt::new(0u64); DIGEST_LEN_FELTS];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        *slot = Felt::new(u64::from_be_bytes(limb));
    }
    out
}

/// `0x`-prefixed lowercase hex of a 32-byte array. Used for `paramsHash`
/// and other non-digest 32-byte values so the verifier does not need a hex
/// dependency in its WASM build.
pub fn bytes32_to_hex(b: &[u8; DIGEST_LEN_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + DIGEST_LEN_BYTES * 2);
    s.push('0');
    s.push('x');
    for byte in b.iter() {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// `0x`-prefixed lowercase hex of a digest. The format published as
/// `kycHash.hex` and embedded in `manifest.json`.
pub fn digest_to_hex(d: &Digest) -> String {
    bytes32_to_hex(&digest_to_bytes(d))
}

#[derive(Debug, PartialEq, Eq)]
pub enum HexDecodeError {
    WrongLength,
    InvalidHexCharacter,
}

/// Parse a `0x`-prefixed (or bare) 64-char hex string into a `Digest`.
pub fn hex_to_digest(hex: &str) -> Result<Digest, HexDecodeError> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    if stripped.len() != DIGEST_LEN_BYTES * 2 {
        return Err(HexDecodeError::WrongLength);
    }
    let mut bytes = [0u8; DIGEST_LEN_BYTES];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16)
            .map_err(|_| HexDecodeError::InvalidHexCharacter)?;
    }
    Ok(digest_from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_le_layout() {
        let mut buf = Vec::new();
        write_canonical_u64(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf, vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn byte_slice_is_length_prefixed() {
        let mut buf = Vec::new();
        write_canonical_bytes(&mut buf, b"abc");
        assert_eq!(buf, vec![3, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn empty_byte_slice_has_zero_length_prefix() {
        let mut buf = Vec::new();
        write_canonical_bytes(&mut buf, &[]);
        assert_eq!(buf, vec![0, 0, 0, 0]);
    }

    #[test]
    fn digest_hex_roundtrip() {
        let d: Digest = [
            Felt::new(0x0102_0304_0506_0708_u64),
            Felt::new(0x1112_1314_1516_1718_u64),
            Felt::new(0x2122_2324_2526_2728_u64),
            Felt::new(0x3132_3334_3536_3738_u64),
        ];
        let hex = digest_to_hex(&d);
        assert_eq!(hex.len(), 2 + 64);
        assert!(hex.starts_with("0x"));
        let back = hex_to_digest(&hex).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn digest_hex_is_lowercase() {
        let d: Digest = [Felt::new(0xabcdu64); DIGEST_LEN_FELTS];
        let hex = digest_to_hex(&d);
        assert_eq!(hex, hex.to_lowercase());
    }

    #[test]
    fn hex_decode_rejects_wrong_length() {
        assert_eq!(
            hex_to_digest("0x00").unwrap_err(),
            HexDecodeError::WrongLength
        );
        assert_eq!(hex_to_digest("").unwrap_err(), HexDecodeError::WrongLength);
    }

    #[test]
    fn hex_decode_rejects_invalid_chars() {
        let bad = format!("0x{}", "z".repeat(64));
        assert_eq!(
            hex_to_digest(&bad).unwrap_err(),
            HexDecodeError::InvalidHexCharacter
        );
    }

    #[test]
    fn hex_decode_accepts_with_or_without_prefix() {
        let raw = "f".repeat(64);
        let prefixed = format!("0x{}", raw);
        assert_eq!(
            hex_to_digest(&raw).unwrap(),
            hex_to_digest(&prefixed).unwrap()
        );
    }
}
