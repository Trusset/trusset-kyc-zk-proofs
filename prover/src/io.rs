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

    pub fn fail(&mut self, subject_id: &str, code: ErrorCode, message: &str) -> std::io::Result<()> {
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
}
