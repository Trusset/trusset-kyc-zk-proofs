//! `audit.log` emitter (spec §12.12).
//!
//! Writes a structured NDJSON file at `<output_root>/audit.log` for every
//! run. The audit log is a **separate event stream** from the stdout NDJSON
//! consumed by the TS CLI — different schema, different PII posture, written
//! to disk regardless of pipe behavior.
//!
//! ## What it contains (per spec §12.12)
//!
//! - **timestamps**: ISO-8601 UTC on every event
//! - **config hash**: the SHA-256 of the canonical config, folded into the
//!   per-subject seed
//! - **list commitment hashes**: per `list_id`, the root from the bundled
//!   list commitment file (so the audit log records exactly which lists
//!   were used)
//! - **library versions**: `trusset-prover` Cargo version + the pinned
//!   `winterfell-prover` version
//!
//! ## What it does NOT contain (per spec §12.12 "but no PII")
//!
//! - No subject field values (names, DoB, document numbers — never
//!   appear anywhere)
//! - For failed subjects: the `error_code` is recorded (e.g. `E_AGE_BELOW_MIN`)
//!   but the human-readable `message` is **redacted** — messages can contain
//!   numeric context like "age 17 < 18" which, while not strictly PII,
//!   would let an audit-log reader infer subject attributes. The error code
//!   gives operators enough to debug without leaking attributes.
//!
//! The wallet address (`subject_id`) IS recorded — it's a public on-chain
//! identifier, not PII.
//!
//! ## Determinism
//!
//! Each event carries a wall-clock timestamp, so `audit.log` is **not**
//! byte-stable across runs. The determinism canary
//! ([tests/e2e/canary.sh](../../tests/e2e/canary.sh)) compares
//! per-bundle files only and ignores `audit.log` by design — operators
//! checking determinism should not gate on the audit log.

use crate::errors::ErrorCode;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Library versions pinned at compile time so the audit log records the
/// exact toolchain used to produce a bundle.
fn library_versions() -> BTreeMap<&'static str, &'static str> {
    let mut m = BTreeMap::new();
    m.insert("trusset_prover", env!("CARGO_PKG_VERSION"));
    // Winterfell version is pinned in the workspace Cargo.lock at 0.13.1
    // (the major.minor must match the Cargo.toml declaration; the patch
    // tracks Cargo.lock). Hardcoded here so the audit log's library
    // version field is stable across runs and known at compile time.
    m.insert("winterfell_prover", "0.13.1");
    m.insert("winterfell_air", "0.13.1");
    m.insert("winterfell_verifier", "0.13.1");
    m
}

/// Audit-log event schema. Independent from the stdout `Event` enum
/// — this one is wider (carries timestamps + run metadata) and
/// narrower (no PII-bearing message strings).
#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent<'a> {
    /// Emitted once at run start with all the run-level metadata
    /// required by spec §12.12.
    RunStart {
        timestamp: &'a str,
        library_versions: BTreeMap<&'static str, &'static str>,
        config_hash: &'a str,
        list_commitments: BTreeMap<&'a str, &'a str>,
        skip_proofs: bool,
        subject_count: usize,
    },
    SubjectStart {
        timestamp: &'a str,
        subject_id: &'a str,
    },
    LeafProved {
        timestamp: &'a str,
        subject_id: &'a str,
        field: &'a str,
        proof_bytes: usize,
        ms: u64,
    },
    SubjectDone {
        timestamp: &'a str,
        subject_id: &'a str,
    },
    SubjectFailed {
        timestamp: &'a str,
        subject_id: &'a str,
        /// Stable error code (e.g. `E_AGE_BELOW_MIN`). Message is omitted
        /// by design to avoid leaking attribute values into the audit log.
        error_code: &'a str,
    },
    RunDone {
        timestamp: &'a str,
        ok: usize,
        failed: usize,
    },
}

pub struct AuditLog {
    writer: Option<BufWriter<std::fs::File>>,
}

impl AuditLog {
    /// Open `<output_root>/audit.log` for append. Existing files are
    /// truncated — each run starts with a fresh audit log.
    ///
    /// Returns an `AuditLog` whose `emit` is a no-op when the file can't
    /// be opened (e.g. read-only output dir during a dry run). The prover
    /// must continue to function without audit logging — `audit.log` is
    /// observability, not load-bearing for the bundle itself.
    pub fn open(output_root: &Path) -> Self {
        // Ensure output_root exists. The bundle pipeline creates it
        // later, but we want to write run_start before any bundle work.
        if let Err(e) = std::fs::create_dir_all(output_root) {
            eprintln!(
                "[audit] could not create output dir {}: {} — audit log disabled",
                output_root.display(),
                e
            );
            return Self { writer: None };
        }
        let path = output_root.join("audit.log");
        match OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
        {
            Ok(f) => Self {
                writer: Some(BufWriter::new(f)),
            },
            Err(e) => {
                eprintln!(
                    "[audit] could not open {}: {} — audit log disabled",
                    path.display(),
                    e
                );
                Self { writer: None }
            }
        }
    }

    /// Emit an event. Errors are logged to stderr but never propagated —
    /// audit-log failures must not break the prover's main flow.
    pub fn emit(&mut self, event: &AuditEvent<'_>) {
        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = serde_json::to_writer(&mut *w, event) {
                eprintln!("[audit] serialize: {}", e);
                return;
            }
            if let Err(e) = w.write_all(b"\n").and_then(|_| w.flush()) {
                eprintln!("[audit] write: {}", e);
            }
        }
    }

    /// Construct + emit a `RunStart` event in one call.
    pub fn emit_run_start(
        &mut self,
        timestamp: &str,
        config_hash: &str,
        list_commitments: &BTreeMap<String, String>,
        skip_proofs: bool,
        subject_count: usize,
    ) {
        let listmap: BTreeMap<&str, &str> = list_commitments
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.emit(&AuditEvent::RunStart {
            timestamp,
            library_versions: library_versions(),
            config_hash,
            list_commitments: listmap,
            skip_proofs,
            subject_count,
        });
    }

    pub fn emit_subject_start(&mut self, timestamp: &str, subject_id: &str) {
        self.emit(&AuditEvent::SubjectStart {
            timestamp,
            subject_id,
        });
    }

    pub fn emit_subject_done(&mut self, timestamp: &str, subject_id: &str) {
        self.emit(&AuditEvent::SubjectDone {
            timestamp,
            subject_id,
        });
    }

    pub fn emit_subject_failed(&mut self, timestamp: &str, subject_id: &str, code: &ErrorCode) {
        self.emit(&AuditEvent::SubjectFailed {
            timestamp,
            subject_id,
            error_code: code.as_str(),
        });
    }

    pub fn emit_run_done(&mut self, timestamp: &str, ok: usize, failed: usize) {
        self.emit(&AuditEvent::RunDone {
            timestamp,
            ok,
            failed,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn emits_run_start_with_metadata() {
        let dir = TempDir::new().unwrap();
        let mut audit = AuditLog::open(dir.path());
        let mut lists = BTreeMap::new();
        lists.insert("country_allowlist".to_string(), "0xabc123".to_string());
        audit.emit_run_start("2026-05-20T14:00:00Z", "0xdeadbeef", &lists, false, 3);
        drop(audit);

        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let line = log.trim();
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["event"], "run_start");
        assert_eq!(v["timestamp"], "2026-05-20T14:00:00Z");
        assert_eq!(v["config_hash"], "0xdeadbeef");
        assert_eq!(v["list_commitments"]["country_allowlist"], "0xabc123");
        assert_eq!(v["skip_proofs"], false);
        assert_eq!(v["subject_count"], 3);
        // Library versions present.
        assert!(v["library_versions"]["trusset_prover"].is_string());
        assert_eq!(v["library_versions"]["winterfell_prover"], "0.13.1");
    }

    #[test]
    fn subject_failed_omits_message() {
        let dir = TempDir::new().unwrap();
        let mut audit = AuditLog::open(dir.path());
        audit.emit_subject_failed("2026-05-20T14:00:01Z", "0xabcd", &ErrorCode::AgeBelowMin);
        drop(audit);

        let log = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        let v: serde_json::Value = serde_json::from_str(log.trim()).unwrap();
        assert_eq!(v["event"], "subject_failed");
        assert_eq!(v["error_code"], "E_AGE_BELOW_MIN");
        // No `message` field — spec §12.12 "no PII".
        assert!(
            v.get("message").is_none(),
            "audit.log must not include 'message' field (PII risk)"
        );
    }

    #[test]
    fn open_failure_is_soft() {
        // Pass a path that can't be created (existing file as a directory).
        let dir = TempDir::new().unwrap();
        let blocking_file = dir.path().join("not_a_dir");
        std::fs::write(&blocking_file, b"x").unwrap();
        let mut audit = AuditLog::open(&blocking_file.join("inner"));
        // emit must not panic even though writer is None.
        audit.emit_subject_start("2026-05-20T14:00:00Z", "0xabcd");
    }

    /// Pin the audit-log event schema so a rename / new field is caught
    /// in tests rather than at runtime in the auditor's tooling.
    #[test]
    fn audit_event_schema_is_pinned() {
        let mut lists = BTreeMap::new();
        lists.insert("country_allowlist", "0xabc");

        let cases: Vec<(AuditEvent<'_>, &str, &[&str])> = vec![
            (
                AuditEvent::RunStart {
                    timestamp: "2026-05-20T14:00:00Z",
                    library_versions: library_versions(),
                    config_hash: "0xdead",
                    list_commitments: lists,
                    skip_proofs: false,
                    subject_count: 1,
                },
                "run_start",
                &[
                    "event",
                    "timestamp",
                    "library_versions",
                    "config_hash",
                    "list_commitments",
                    "skip_proofs",
                    "subject_count",
                ],
            ),
            (
                AuditEvent::SubjectStart {
                    timestamp: "t",
                    subject_id: "0xab",
                },
                "subject_start",
                &["event", "timestamp", "subject_id"],
            ),
            (
                AuditEvent::LeafProved {
                    timestamp: "t",
                    subject_id: "0xab",
                    field: "f",
                    proof_bytes: 0,
                    ms: 0,
                },
                "leaf_proved",
                &[
                    "event",
                    "timestamp",
                    "subject_id",
                    "field",
                    "proof_bytes",
                    "ms",
                ],
            ),
            (
                AuditEvent::SubjectDone {
                    timestamp: "t",
                    subject_id: "0xab",
                },
                "subject_done",
                &["event", "timestamp", "subject_id"],
            ),
            (
                AuditEvent::SubjectFailed {
                    timestamp: "t",
                    subject_id: "0xab",
                    error_code: "E_X",
                },
                "subject_failed",
                &["event", "timestamp", "subject_id", "error_code"],
            ),
            (
                AuditEvent::RunDone {
                    timestamp: "t",
                    ok: 1,
                    failed: 0,
                },
                "run_done",
                &["event", "timestamp", "ok", "failed"],
            ),
        ];

        for (event, expected_tag, expected_fields) in &cases {
            let json = serde_json::to_value(event).unwrap();
            let obj = json.as_object().expect("event must serialize to object");
            assert_eq!(
                obj.get("event").and_then(|v| v.as_str()),
                Some(*expected_tag),
                "wrong tag for {:?}",
                expected_tag
            );
            for name in *expected_fields {
                assert!(
                    obj.contains_key(*name),
                    "event {:?} missing field {:?}",
                    expected_tag,
                    name
                );
            }
            assert_eq!(
                obj.len(),
                expected_fields.len(),
                "event {:?} has {} fields but {} are pinned (add new fields to test AND to docs)",
                expected_tag,
                obj.len(),
                expected_fields.len()
            );
        }
    }
}
