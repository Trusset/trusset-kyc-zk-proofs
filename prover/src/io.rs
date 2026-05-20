//! NDJSON event emitter (plan §"TS ↔ Rust Integration" response protocol).
//!
//! Every event is one line of compact JSON written to stdout and flushed
//! immediately so the TS layer can stream-process. `stderr` is reserved for
//! unstructured logs and panics.

use crate::errors::ErrorCode;
use serde::Serialize;
use std::io::Write;

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event<'a> {
    Start {
        subjects: usize,
    },
    SubjectStart {
        subject_id: &'a str,
    },
    LeafProved {
        subject_id: &'a str,
        field: &'a str,
        proof_bytes: usize,
        ms: u64,
    },
    SubjectDone {
        subject_id: &'a str,
        bundle_path: &'a str,
    },
    SubjectFailed {
        subject_id: &'a str,
        error_code: &'a str,
        message: &'a str,
    },
    Done {
        ok: usize,
        failed: usize,
    },
}

pub struct EventStream<W: Write> {
    out: W,
}

impl<W: Write> EventStream<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }

    pub fn emit(&mut self, event: &Event<'_>) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.out, event)?;
        self.out.write_all(b"\n")?;
        self.out.flush()
    }

    pub fn fail(
        &mut self,
        subject_id: &str,
        code: ErrorCode,
        message: &str,
    ) -> std::io::Result<()> {
        self.emit(&Event::SubjectFailed {
            subject_id,
            error_code: code.as_str(),
            message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_newline_delimited_json() {
        let mut buf = Vec::new();
        {
            let mut stream = EventStream::new(&mut buf);
            stream.emit(&Event::Start { subjects: 3 }).unwrap();
            stream
                .emit(&Event::SubjectDone {
                    subject_id: "0xAbCd",
                    bundle_path: "output/0xAbCd",
                })
                .unwrap();
            stream.emit(&Event::Done { ok: 3, failed: 0 }).unwrap();
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        // Each line is valid JSON.
        for line in &lines {
            let _: serde_json::Value = serde_json::from_str(line).unwrap();
        }
        // Field names follow the documented schema.
        assert!(lines[0].contains(r#""event":"start""#));
        assert!(lines[0].contains(r#""subjects":3"#));
        assert!(lines[1].contains(r#""event":"subject_done""#));
    }

    #[test]
    fn fail_event_carries_stable_error_code() {
        let mut buf = Vec::new();
        let mut stream = EventStream::new(&mut buf);
        stream
            .fail("0xAbCd", ErrorCode::AgeBelowMin, "age 17 < 18")
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains(r#""error_code":"E_AGE_BELOW_MIN""#));
        assert!(text.contains(r#""message":"age 17 < 18""#));
    }

    /// Pin every NDJSON event variant's wire-level `event` discriminator
    /// and every field name within each variant.
    ///
    /// **Why this test is load-bearing**: the TS CLI declares the NDJSON
    /// event schema independently at [cli/src/spawnProver.ts](../../cli/src/spawnProver.ts).
    /// The Rust prover emits NDJSON via the `Event` enum here. Drift on
    /// either side is silent and shows up only as TS parse failures at
    /// runtime.
    ///
    /// Failure of this test means: an engineer renamed an `Event` variant
    /// or field name in `io.rs` without updating
    /// [cli/src/spawnProver.ts](../../cli/src/spawnProver.ts)'s
    /// `ProverEvent` union. To fix: either revert the Rust rename or
    /// apply the matching rename to the TS union AND every TS call site
    /// that pattern-matches on `event.event === '<name>'`.
    #[test]
    fn ndjson_event_schema_is_pinned() {
        // Generate one example of each variant and assert its full JSON
        // wire shape. The assertions cover both the `event` discriminator
        // (driven by serde `tag = "event", rename_all = "snake_case"`)
        // and every field name within each variant.
        let cases: Vec<(Event<'_>, &str, &[&str])> = vec![
            (
                Event::Start { subjects: 3 },
                "start",
                &["event", "subjects"],
            ),
            (
                Event::SubjectStart {
                    subject_id: "0xAbCd",
                },
                "subject_start",
                &["event", "subject_id"],
            ),
            (
                Event::LeafProved {
                    subject_id: "0xAbCd",
                    field: "firstName",
                    proof_bytes: 120,
                    ms: 42,
                },
                "leaf_proved",
                &["event", "subject_id", "field", "proof_bytes", "ms"],
            ),
            (
                Event::SubjectDone {
                    subject_id: "0xAbCd",
                    bundle_path: "output/0xAbCd",
                },
                "subject_done",
                &["event", "subject_id", "bundle_path"],
            ),
            (
                Event::SubjectFailed {
                    subject_id: "0xAbCd",
                    error_code: "E_INPUT",
                    message: "bad wallet",
                },
                "subject_failed",
                &["event", "subject_id", "error_code", "message"],
            ),
            (
                Event::Done { ok: 5, failed: 0 },
                "done",
                &["event", "ok", "failed"],
            ),
        ];

        for (event, expected_tag, expected_fields) in &cases {
            let json = serde_json::to_value(event).unwrap();
            let obj = json
                .as_object()
                .unwrap_or_else(|| panic!("event {:?} did not serialize to object", expected_tag));

            // Discriminator
            assert_eq!(
                obj.get("event").and_then(|v| v.as_str()),
                Some(*expected_tag),
                "wrong event discriminator for variant {:?}",
                expected_tag
            );

            // Every expected field is present.
            for name in *expected_fields {
                assert!(
                    obj.contains_key(*name),
                    "event {:?} JSON is missing field {:?} (cli/src/spawnProver.ts expects this)",
                    expected_tag,
                    name
                );
            }

            // No surprise extra fields — adding a field to the Rust enum
            // requires deliberately updating the TS interface AND this test.
            assert_eq!(
                obj.len(),
                expected_fields.len(),
                "event {:?} has {} JSON fields but {} are pinned. \
                 Add the new field to cli/src/spawnProver.ts:ProverEvent AND to expected_fields here.",
                expected_tag,
                obj.len(),
                expected_fields.len()
            );
        }
    }
}
