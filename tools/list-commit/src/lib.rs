//! Library for the `trusset-list-commit` binary.
//!
//! Parses a plain-text source file (one entry per line, `#` comments,
//! NFC-normalized) and emits a `ListCommitmentFile` JSON document carrying
//! the Rescue Merkle root, SHA-256 of the source, and the canonical values.
//! Pinned in `config.lists.<id>` so any later source-file tampering changes
//! the SHA-256 and aborts the prover.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use trusset_circuit_set_membership as set;
use trusset_circuits_common::digest_to_hex;
use unicode_normalization::UnicodeNormalization;

/// On-disk JSON schema (re-readable by the prover via
/// `prover::job::ListCommitment` for the subset it consumes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCommitmentFile {
    #[serde(rename = "listId")]
    pub list_id: String,
    pub version: u32,
    pub generator: String,
    #[serde(rename = "sourceSha256")]
    pub source_sha256: String,
    pub values: Vec<String>,
    pub root: String,
    pub depth: u8,
}

pub const SCHEMA_VERSION: u32 = 1;
pub const GENERATOR_VERSION: &str = "trusset-list-commit 2.0.0";

#[derive(Debug, PartialEq, Eq)]
pub enum CommitError {
    /// Source file is not valid UTF-8.
    NotUtf8,
    /// Fewer than 2 entries after parsing (`build_set_tree` requires ≥2 for
    /// a meaningful inclusion proof).
    TooFewEntries(usize),
    /// Duplicate entry; lists must be unique sets.
    DuplicateAtLine { line: usize, value: String },
    /// Empty line after trimming that wasn't a comment — usually means an
    /// editor inserted whitespace-only lines. Rejected to keep the source
    /// file's SHA-256 stable across well-meaning reformats.
    WhitespaceOnlyLine(usize),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitError::NotUtf8 => write!(f, "source file is not UTF-8"),
            CommitError::TooFewEntries(n) => {
                write!(f, "list must have at least 2 entries, found {}", n)
            }
            CommitError::DuplicateAtLine { line, value } => {
                write!(f, "duplicate entry '{}' at line {}", value, line)
            }
            CommitError::WhitespaceOnlyLine(line) => {
                write!(f, "whitespace-only entry at line {}", line)
            }
        }
    }
}

impl std::error::Error for CommitError {}

#[derive(Debug, Clone)]
pub struct CommitOptions {
    /// Allow duplicate entries in the source (silently dedupe). Default false:
    /// duplicates are an error so an operator can't accidentally include the
    /// same country code twice.
    pub allow_duplicates: bool,
}

impl Default for CommitOptions {
    fn default() -> Self {
        Self {
            allow_duplicates: false,
        }
    }
}

/// Parse a source file and produce a `ListCommitmentFile`. The source bytes
/// are hashed verbatim (SHA-256) — comments and blank lines are part of the
/// commitment, so any reformat invalidates the pinned hash.
pub fn commit_list(
    list_id: &str,
    source_bytes: &[u8],
    opts: &CommitOptions,
) -> Result<ListCommitmentFile, CommitError> {
    let source_sha256 = sha256_hex(source_bytes);
    let text = std::str::from_utf8(source_bytes).map_err(|_| CommitError::NotUtf8)?;
    let values = parse_source(text, opts)?;
    if values.len() < 2 {
        return Err(CommitError::TooFewEntries(values.len()));
    }

    // Build the Rescue Merkle tree once to capture the root and depth.
    let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _leaves) = set::build_set_tree(&refs);

    Ok(ListCommitmentFile {
        list_id: list_id.to_string(),
        version: SCHEMA_VERSION,
        generator: GENERATOR_VERSION.to_string(),
        source_sha256: format!("0x{}", source_sha256),
        values,
        root: digest_to_hex(&root),
        depth,
    })
}

/// Hex SHA-256 of arbitrary bytes (without `0x` prefix).
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn parse_source(text: &str, opts: &CommitOptions) -> Result<Vec<String>, CommitError> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        // Drop UTF-8 BOM on the first line if present.
        let stripped = if idx == 0 {
            raw_line.strip_prefix('\u{feff}').unwrap_or(raw_line)
        } else {
            raw_line
        };
        let trimmed = stripped.trim();

        // Blank lines and `#` comments are part of the SHA-256 commitment
        // but excluded from `values`.
        if trimmed.is_empty() {
            // Whitespace-only lines (e.g. " \t ") are an error to keep the
            // source file's SHA-256 stable across editor reformats. A truly
            // empty line is fine.
            if !stripped.is_empty() {
                return Err(CommitError::WhitespaceOnlyLine(line_no));
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }

        // Apply Unicode NFC so the canonical form matches what the prover
        // and set-membership circuit produce.
        let canonical: String = trimmed.nfc().collect();

        if !seen.insert(canonical.clone()) {
            if opts.allow_duplicates {
                continue;
            } else {
                return Err(CommitError::DuplicateAtLine {
                    line: line_no,
                    value: canonical,
                });
            }
        }
        out.push(canonical);
    }

    Ok(out)
}

// hex re-export so callers don't have to pull it themselves
use sha2 as _;

mod hex {
    /// Lightweight hex encoder — avoids adding the `hex` crate just for this.
    pub fn encode<T: AsRef<[u8]>>(bytes: T) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let b = bytes.as_ref();
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0x0f) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_list_with_comments() {
        let src = "# ISO 3166-1 alpha-3 allowlist\nDEU\nFRA\nUSA\nGBR\n";
        let r = commit_list("country_allowlist", src.as_bytes(), &CommitOptions::default())
            .unwrap();
        assert_eq!(r.list_id, "country_allowlist");
        assert_eq!(r.version, SCHEMA_VERSION);
        assert_eq!(r.values, vec!["DEU", "FRA", "USA", "GBR"]);
        assert_eq!(r.depth, 2); // 4 leaves
        assert!(r.root.starts_with("0x"));
        assert_eq!(r.root.len(), 2 + 64);
        assert!(r.source_sha256.starts_with("0x"));
    }

    #[test]
    fn rejects_duplicates_by_default() {
        let src = "DEU\nFRA\nDEU\n";
        let err = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap_err();
        assert!(matches!(
            err,
            CommitError::DuplicateAtLine { line: 3, .. }
        ));
    }

    #[test]
    fn allow_duplicates_dedupes_silently() {
        let src = "DEU\nFRA\nDEU\n";
        let r = commit_list(
            "x",
            src.as_bytes(),
            &CommitOptions {
                allow_duplicates: true,
            },
        )
        .unwrap();
        assert_eq!(r.values, vec!["DEU", "FRA"]);
    }

    #[test]
    fn rejects_too_few_entries() {
        let src = "DEU\n";
        let err = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap_err();
        assert_eq!(err, CommitError::TooFewEntries(1));
    }

    #[test]
    fn rejects_non_utf8_source() {
        let src = [0x80, 0x81, 0x82];
        let err = commit_list("x", &src, &CommitOptions::default()).unwrap_err();
        assert_eq!(err, CommitError::NotUtf8);
    }

    #[test]
    fn rejects_whitespace_only_line() {
        let src = "DEU\n   \nFRA\n";
        let err = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap_err();
        assert!(matches!(err, CommitError::WhitespaceOnlyLine(2)));
    }

    #[test]
    fn ignores_truly_empty_lines() {
        let src = "DEU\n\nFRA\n\nUSA\n";
        let r = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap();
        assert_eq!(r.values, vec!["DEU", "FRA", "USA"]);
    }

    #[test]
    fn nfc_normalizes_composed_forms() {
        // U+00E9 (composed) and U+0065 U+0301 (decomposed) collapse to the
        // same canonical form under NFC — but the source file's SHA-256
        // still differs (it's hashed verbatim before normalization).
        let composed = "caf\u{00e9}\nfoo\n";
        let decomposed = "cafe\u{0301}\nfoo\n";
        let r1 = commit_list("x", composed.as_bytes(), &CommitOptions::default()).unwrap();
        let r2 = commit_list("x", decomposed.as_bytes(), &CommitOptions::default()).unwrap();
        assert_eq!(r1.values, r2.values, "NFC must collapse the two forms");
        assert_eq!(r1.root, r2.root, "Merkle root must be NFC-invariant");
        assert_ne!(
            r1.source_sha256, r2.source_sha256,
            "source SHA-256 commits to the verbatim file bytes"
        );
    }

    #[test]
    fn root_changes_with_different_set() {
        let a = commit_list("x", b"DEU\nFRA\nUSA\nGBR\n", &CommitOptions::default()).unwrap();
        let b = commit_list("x", b"DEU\nFRA\nJPN\nGBR\n", &CommitOptions::default()).unwrap();
        assert_ne!(a.root, b.root);
    }

    #[test]
    fn source_sha256_changes_with_comments() {
        // Same canonical values, different comments → different SHA-256.
        let a = commit_list("x", b"DEU\nFRA\n", &CommitOptions::default()).unwrap();
        let b = commit_list(
            "x",
            b"# updated 2026\nDEU\nFRA\n",
            &CommitOptions::default(),
        )
        .unwrap();
        assert_eq!(a.values, b.values);
        assert_eq!(a.root, b.root);
        assert_ne!(a.source_sha256, b.source_sha256);
    }

    #[test]
    fn strips_utf8_bom_on_first_line() {
        let src = "\u{feff}DEU\nFRA\n";
        let r = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap();
        assert_eq!(r.values[0], "DEU");
    }

    #[test]
    fn output_json_is_stable_keyed() {
        let r = commit_list("x", b"DEU\nFRA\n", &CommitOptions::default()).unwrap();
        let text = serde_json::to_string_pretty(&r).unwrap();
        // Sanity: every field present in the on-disk schema.
        for needle in &[
            "\"listId\"",
            "\"version\"",
            "\"generator\"",
            "\"sourceSha256\"",
            "\"values\"",
            "\"root\"",
            "\"depth\"",
        ] {
            assert!(text.contains(needle), "missing field {}", needle);
        }
    }
}
