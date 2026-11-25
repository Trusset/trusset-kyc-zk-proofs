//! v3.1 signed header: the small statement that ties one root to one wallet,
//! one batch date, and one on-chain attestation.
//!
//! The operator key signs this header in addition to the manifest. A holder
//! can then disclose a single leaf with its inclusion path and the signed
//! header, and anyone can check it without the rest of the bundle.
//!
//! Signing bytes are a fixed 155-byte layout, equal to Solidity's
//! `abi.encodePacked` of the same fields, so a contract or a script can
//! rebuild them without a JSON canonicalizer:
//!
//! ```text
//! offset len  field
//!      0  32  HEADER_SIGNING_TAG ("TRUSSET-KYC-V3.1:HEADER" padded with '-')
//!     32   3  version major, minor, patch (u8 each), 3.1.0 = 03 01 00
//!     35  32  root (kycHash), big-endian per limb as in kycHash.hex
//!     67  20  wallet
//!     87   8  epochDays, u64 big-endian
//!     95  20  attester (EVM address that attests on the hub)
//!    115   8  chainId, u64 big-endian
//!    123  20  hub (IdentityHub address)
//!    143   4  keyId, u32 big-endian (the hub's operator key id)
//!    147   4  merkleVersion, u32 big-endian (3)
//!    151   4  leafCount, u32 big-endian
//! ```
//!
//! The ed25519 signature is over those bytes directly.

use serde::{Deserialize, Serialize};
use trusset_circuits_common::{digest_to_hex, hex_to_digest, Digest, HEADER_SIGNING_TAG};

use crate::merkle::MERKLE_VERSION_V3;

/// The only header version this build understands.
pub const HEADER_VERSION: &str = "3.1.0";

/// `HEADER_VERSION` as three bytes.
pub const HEADER_VERSION_BYTES: [u8; 3] = [3, 1, 0];

/// Length of the signing bytes.
pub const HEADER_SIGNING_LEN: usize = 32 + 3 + 32 + 20 + 8 + 20 + 8 + 20 + 4 + 4 + 4;

/// Upper bound on `leafCount`. Keeps an inclusion path at most 8 siblings and
/// rejects absurd counts before any hashing.
pub const MAX_LEAF_COUNT: u32 = 256;

/// The circuits version a 3.1.0 header implies. A disclosure has no other
/// signed source for it, so it is fixed by the header version rather than
/// read from unsigned input. This is what stops a disclosure from selecting
/// the weaker circuitsVersion 2 `set_membership` AIR.
pub const HEADER_CIRCUITS_VERSION: u32 = 3;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureHeader {
    pub version: String,
    pub root: String,
    pub wallet: String,
    #[serde(rename = "epochDays")]
    pub epoch_days: u64,
    pub attester: String,
    #[serde(rename = "chainId")]
    pub chain_id: u64,
    pub hub: String,
    #[serde(rename = "keyId")]
    pub key_id: u32,
    #[serde(rename = "merkleVersion")]
    pub merkle_version: u32,
    #[serde(rename = "leafCount")]
    pub leaf_count: u32,
}

/// The fields of a header once every one of them has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub root: Digest,
    pub wallet: [u8; 20],
    pub epoch_days: u64,
    pub attester: [u8; 20],
    pub chain_id: u64,
    pub hub: [u8; 20],
    pub key_id: u32,
    pub merkle_version: u32,
    pub leaf_count: u32,
}

impl DisclosureHeader {
    /// Check every field and decode it. Anything a signature would otherwise
    /// cover ambiguously is refused here.
    pub fn parse(&self) -> Result<ParsedHeader, String> {
        if self.version != HEADER_VERSION {
            return Err(format!(
                "header version {} is not {}",
                self.version, HEADER_VERSION
            ));
        }
        let root = parse_digest_strict(&self.root)
            .ok_or("header root is not 0x + 64 lowercase hex of a canonical digest")?;
        let wallet = parse_address(&self.wallet).ok_or("header wallet is not 0x + 40 hex")?;
        let attester = parse_address(&self.attester).ok_or("header attester is not 0x + 40 hex")?;
        let hub = parse_address(&self.hub).ok_or("header hub is not 0x + 40 hex")?;
        if wallet == [0u8; 20] || attester == [0u8; 20] || hub == [0u8; 20] {
            return Err("header wallet, attester and hub must not be the zero address".to_string());
        }
        if self.epoch_days == 0 {
            return Err("header epochDays must be positive".to_string());
        }
        if self.chain_id == 0 {
            return Err("header chainId must be positive".to_string());
        }
        if self.key_id == 0 {
            return Err("header keyId must be at least 1, the hub's first key id".to_string());
        }
        if self.merkle_version != MERKLE_VERSION_V3 {
            return Err(format!(
                "header merkleVersion {} is not {}",
                self.merkle_version, MERKLE_VERSION_V3
            ));
        }
        if self.leaf_count == 0 || self.leaf_count > MAX_LEAF_COUNT {
            return Err(format!(
                "header leafCount {} is outside 1..={}",
                self.leaf_count, MAX_LEAF_COUNT
            ));
        }
        Ok(ParsedHeader {
            root,
            wallet,
            epoch_days: self.epoch_days,
            attester,
            chain_id: self.chain_id,
            hub,
            key_id: self.key_id,
            merkle_version: self.merkle_version,
            leaf_count: self.leaf_count,
        })
    }

    /// The exact bytes the operator key signs.
    pub fn signing_bytes(&self) -> Result<[u8; HEADER_SIGNING_LEN], String> {
        Ok(self.parse()?.signing_bytes())
    }

    /// Pretty JSON with sorted keys, as written to `header.json` and embedded
    /// in each disclosure.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let mut out = serde_json::to_vec_pretty(&value)?;
        out.retain(|b| *b != b'\r');
        Ok(out)
    }
}

impl ParsedHeader {
    #[must_use]
    pub fn signing_bytes(&self) -> [u8; HEADER_SIGNING_LEN] {
        let mut out = [0u8; HEADER_SIGNING_LEN];
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            out[at..at + bytes.len()].copy_from_slice(bytes);
            at += bytes.len();
        };
        put(&HEADER_SIGNING_TAG);
        put(&HEADER_VERSION_BYTES);
        put(&trusset_circuits_common::digest_to_bytes(&self.root));
        put(&self.wallet);
        put(&self.epoch_days.to_be_bytes());
        put(&self.attester);
        put(&self.chain_id.to_be_bytes());
        put(&self.hub);
        put(&self.key_id.to_be_bytes());
        put(&self.merkle_version.to_be_bytes());
        put(&self.leaf_count.to_be_bytes());
        out
    }

    /// The canonical JSON form: lowercase hex everywhere.
    #[must_use]
    pub fn to_header(&self) -> DisclosureHeader {
        DisclosureHeader {
            version: HEADER_VERSION.to_string(),
            root: digest_to_hex(&self.root),
            wallet: address_to_hex(&self.wallet),
            epoch_days: self.epoch_days,
            attester: address_to_hex(&self.attester),
            chain_id: self.chain_id,
            hub: address_to_hex(&self.hub),
            key_id: self.key_id,
            merkle_version: self.merkle_version,
            leaf_count: self.leaf_count,
        }
    }
}

/// `0x` + 64 lowercase hex that decodes to a digest and re-encodes to the same
/// string. Refuses uppercase and limbs at or above the field modulus, so one
/// digest has exactly one accepted spelling.
#[must_use]
pub fn parse_digest_strict(s: &str) -> Option<Digest> {
    let body = s.strip_prefix("0x")?;
    if body.len() != 64
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let d = hex_to_digest(s).ok()?;
    if digest_to_hex(&d) == s {
        Some(d)
    } else {
        None
    }
}

/// `0x` + 40 hex, either case.
#[must_use]
pub fn parse_address(s: &str) -> Option<[u8; 20]> {
    let body = s.strip_prefix("0x")?;
    if body.len() != 40 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// `0x` + 40 lowercase hex.
#[must_use]
pub fn address_to_hex(a: &[u8; 20]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// `0x` + 128 lowercase hex of a 64-byte signature.
#[must_use]
pub fn signature_to_hex(sig: &[u8; 64]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(130);
    s.push_str("0x");
    for b in sig {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Inverse of [`signature_to_hex`]; lowercase only.
#[must_use]
pub fn parse_signature_hex(s: &str) -> Option<[u8; 64]> {
    let body = s.strip_prefix("0x")?;
    if body.len() != 128
        || !body
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&body[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusset_circuits_common::{hash_bytes_with_tag, LEAF_TAG};

    fn sample() -> DisclosureHeader {
        ParsedHeader {
            root: hash_bytes_with_tag(&LEAF_TAG, b"root"),
            wallet: [0xab; 20],
            epoch_days: 20_776,
            attester: [0x11; 20],
            chain_id: 11_155_111,
            hub: [0x22; 20],
            key_id: 1,
            merkle_version: 3,
            leaf_count: 5,
        }
        .to_header()
    }

    #[test]
    fn signing_bytes_have_the_documented_layout() {
        let h = sample();
        let bytes = h.signing_bytes().unwrap();
        assert_eq!(bytes.len(), 155);
        assert_eq!(&bytes[0..32], &HEADER_SIGNING_TAG);
        assert_eq!(&bytes[32..35], &[3, 1, 0]);
        assert_eq!(&bytes[67..87], &[0xab; 20]);
        assert_eq!(&bytes[87..95], &20_776u64.to_be_bytes());
        assert_eq!(&bytes[95..115], &[0x11; 20]);
        assert_eq!(&bytes[115..123], &11_155_111u64.to_be_bytes());
        assert_eq!(&bytes[123..143], &[0x22; 20]);
        assert_eq!(&bytes[143..147], &1u32.to_be_bytes());
        assert_eq!(&bytes[147..151], &3u32.to_be_bytes());
        assert_eq!(&bytes[151..155], &5u32.to_be_bytes());
    }

    #[test]
    fn every_field_changes_the_signing_bytes() {
        let base = sample().signing_bytes().unwrap();
        let mut variants: Vec<DisclosureHeader> = Vec::new();
        let mut h = sample();
        h.root = digest_to_hex(&hash_bytes_with_tag(&LEAF_TAG, b"other"));
        variants.push(h);
        let mut h = sample();
        h.wallet = address_to_hex(&[0xac; 20]);
        variants.push(h);
        let mut h = sample();
        h.epoch_days += 1;
        variants.push(h);
        let mut h = sample();
        h.attester = address_to_hex(&[0x12; 20]);
        variants.push(h);
        let mut h = sample();
        h.chain_id = 137;
        variants.push(h);
        let mut h = sample();
        h.hub = address_to_hex(&[0x23; 20]);
        variants.push(h);
        let mut h = sample();
        h.key_id = 2;
        variants.push(h);
        let mut h = sample();
        h.leaf_count = 6;
        variants.push(h);
        for v in variants {
            assert_ne!(v.signing_bytes().unwrap(), base);
        }
    }

    #[test]
    fn bad_fields_are_refused() {
        type Mutation = Box<dyn Fn(&mut DisclosureHeader)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|h| h.version = "3.0.0".into()),
            Box::new(|h| h.root = h.root.to_uppercase().replacen("0X", "0x", 1)),
            Box::new(|h| h.root = format!("0x{}", "f".repeat(64))),
            Box::new(|h| h.root.push('0')),
            Box::new(|h| h.wallet = "0x1234".into()),
            Box::new(|h| h.attester = address_to_hex(&[0; 20])),
            Box::new(|h| h.hub = address_to_hex(&[0; 20])),
            Box::new(|h| h.epoch_days = 0),
            Box::new(|h| h.chain_id = 0),
            Box::new(|h| h.key_id = 0),
            Box::new(|h| h.merkle_version = 2),
            Box::new(|h| h.leaf_count = 0),
            Box::new(|h| h.leaf_count = MAX_LEAF_COUNT + 1),
        ];
        for (i, mutate) in cases.iter().enumerate() {
            let mut h = sample();
            mutate(&mut h);
            assert!(h.parse().is_err(), "case {} should be refused", i);
        }
    }

    #[test]
    fn unknown_and_duplicate_json_keys_are_refused() {
        let good = String::from_utf8(sample().to_json_bytes().unwrap()).unwrap();
        assert!(serde_json::from_str::<DisclosureHeader>(&good).is_ok());
        let extra = good.replacen('{', "{\n  \"extra\": 1,", 1);
        assert!(serde_json::from_str::<DisclosureHeader>(&extra).is_err());
        let dup = good.replacen('{', "{\n  \"keyId\": 2,", 1);
        assert!(serde_json::from_str::<DisclosureHeader>(&dup).is_err());
    }

    #[test]
    fn json_round_trips_and_is_lowercase() {
        let h = sample();
        let bytes = h.to_json_bytes().unwrap();
        for v in [&h.root, &h.wallet, &h.attester, &h.hub] {
            assert_eq!(*v, v.to_lowercase());
        }
        let back: DisclosureHeader = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn signature_hex_round_trips() {
        let sig = [0x5a; 64];
        let hex = signature_to_hex(&sig);
        assert_eq!(parse_signature_hex(&hex), Some(sig));
        assert!(parse_signature_hex(&hex.to_uppercase()).is_none());
        assert!(parse_signature_hex(&hex[..100]).is_none());
    }
}
