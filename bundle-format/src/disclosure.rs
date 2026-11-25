//! v3.1 single-leaf disclosure: one leaf, its inclusion path, and the signed
//! header, enough for anyone to check that leaf without the rest of the
//! bundle.
//!
//! ```json
//! {
//!   "version": "3.1.0",
//!   "header": { ...the signed header... },
//!   "headerSignature": "0x<128 hex>",
//!   "leaf": { ...the leaf entry exactly as in manifest.leaves[]... },
//!   "path": ["0x<64 hex>", ...]
//! }
//! ```
//!
//! The proof bytes travel next to it (`proofs/<leaf>.bin`) and are passed to
//! the verifier separately. Their digest is in the leaf hash, so they cannot
//! be swapped.
//!
//! Parsing is strict: unknown keys anywhere, a missing key, a path of the
//! wrong length, or a non-canonical digest spelling are all refused.

use serde::{Deserialize, Serialize};

use crate::header::{parse_digest_strict, DisclosureHeader, HEADER_VERSION};
use crate::manifest::LeafEntry;
use crate::merkle::tree_depth;

pub const DISCLOSURE_VERSION: &str = HEADER_VERSION;

/// Largest disclosure document the parser accepts. A real one is a few KB.
pub const MAX_DISCLOSURE_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    pub version: String,
    pub header: DisclosureHeader,
    #[serde(rename = "headerSignature")]
    pub header_signature: String,
    pub leaf: LeafEntry,
    pub path: Vec<String>,
}

/// Keys a disclosed leaf may carry. `LeafEntry` itself tolerates unknown keys
/// for manifest compatibility; a disclosure does not.
const LEAF_KEYS: [&str; 14] = [
    "fieldName",
    "circuit",
    "circuitId",
    "commitment",
    "publicInputs",
    "publicDigest",
    "proofPath",
    "proofDigest",
    "paramsHash",
    "leafHash",
    "disclosure",
    "params",
    "binding",
    "bindingDigest",
];

impl Disclosure {
    /// Parse and structurally check a disclosure document. Does no
    /// cryptography; the verifier does that.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_DISCLOSURE_BYTES {
            return Err(format!(
                "disclosure is {} bytes, above the {} byte limit",
                bytes.len(),
                MAX_DISCLOSURE_BYTES
            ));
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| format!("disclosure is not JSON: {}", e))?;
        let leaf = value
            .get("leaf")
            .and_then(|l| l.as_object())
            .ok_or("disclosure has no leaf object")?;
        if let Some(unknown) = leaf.keys().find(|k| !LEAF_KEYS.contains(&k.as_str())) {
            return Err(format!("disclosed leaf has an unknown key: {}", unknown));
        }
        let d: Disclosure = serde_json::from_value(value.clone())
            .map_err(|e| format!("disclosure does not match the schema: {}", e))?;
        // Typed parsing drops keys it does not know inside nested blocks (the
        // binding, the descriptor). Requiring the document to equal its own
        // typed form refuses those, and any explicit null, so every byte of a
        // disclosure means something.
        if serde_json::to_value(&d).ok().as_ref() != Some(&value) {
            return Err(
                "disclosure carries keys or values outside its schema (unknown keys, or nulls)"
                    .to_string(),
            );
        }
        if d.version != DISCLOSURE_VERSION {
            return Err(format!(
                "disclosure version {} is not {}",
                d.version, DISCLOSURE_VERSION
            ));
        }
        let header = d.header.parse()?;
        let depth = tree_depth(header.leaf_count as usize);
        if d.path.len() != depth {
            return Err(format!(
                "inclusion path has {} siblings, a tree of {} leaves needs {}",
                d.path.len(),
                header.leaf_count,
                depth
            ));
        }
        for (i, s) in d.path.iter().enumerate() {
            if parse_digest_strict(s).is_none() {
                return Err(format!(
                    "inclusion path sibling {} is not a canonical digest",
                    i
                ));
            }
        }
        Ok(d)
    }

    /// Pretty JSON with sorted keys, as written to `disclosures/<leaf>.json`.
    pub fn to_json_bytes(&self) -> serde_json::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        let mut out = serde_json::to_vec_pretty(&value)?;
        out.retain(|b| *b != b'\r');
        Ok(out)
    }
}
