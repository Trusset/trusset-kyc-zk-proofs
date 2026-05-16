//! `trusset-list-commit` CLI entrypoint.
//!
//! ```text
//! trusset-list-commit \
//!   --list-id country_allowlist \
//!   --source path/to/countries.txt \
//!   --output config/list_commitments/country_allowlist.json \
//!   [--allow-duplicates]
//! ```
//!
//! Produces an audit-friendly JSON file pinning the Rescue Merkle root and
//! SHA-256 of the source. Operators reference it from `config.lists.<id>`.

use std::path::PathBuf;
use std::process::ExitCode;
use trusset_list_commit::{commit_list, CommitOptions};

const USAGE: &str = "\
Usage: trusset-list-commit --list-id <ID> --source <FILE> --output <FILE> [--allow-duplicates]

Required:
  --list-id <ID>           Logical identifier (e.g. country_allowlist)
  --source <FILE>          Plain-text source, one entry per line (UTF-8)
  --output <FILE>          Destination JSON path

Optional:
  --allow-duplicates       Silently dedupe instead of erroring on repeated entries
  --help, -h               Show this help

Each line is trimmed and Unicode NFC-normalized. Lines starting with '#' are
comments; blank lines are ignored. The output JSON contains the canonical
values, the Rescue Merkle root, the depth of the padded power-of-two tree,
and the SHA-256 of the source file (verbatim bytes, comments included).
";

struct Args {
    list_id: String,
    source: PathBuf,
    output: PathBuf,
    allow_duplicates: bool,
}

enum ParseOutcome {
    Ok(Args),
    Help,
    Err(String),
}

fn parse_args() -> ParseOutcome {
    let mut iter = std::env::args().skip(1);
    let mut list_id: Option<String> = None;
    let mut source: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut allow_duplicates = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return ParseOutcome::Help,
            "--list-id" => match iter.next() {
                Some(v) => list_id = Some(v),
                None => return ParseOutcome::Err("--list-id requires a value".into()),
            },
            "--source" => match iter.next() {
                Some(v) => source = Some(PathBuf::from(v)),
                None => return ParseOutcome::Err("--source requires a path".into()),
            },
            "--output" => match iter.next() {
                Some(v) => output = Some(PathBuf::from(v)),
                None => return ParseOutcome::Err("--output requires a path".into()),
            },
            "--allow-duplicates" => allow_duplicates = true,
            other => return ParseOutcome::Err(format!("unknown argument: {}", other)),
        }
    }

    let list_id = match list_id {
        Some(v) if !v.is_empty() => v,
        _ => return ParseOutcome::Err("--list-id is required".into()),
    };
    let source = match source {
        Some(v) => v,
        _ => return ParseOutcome::Err("--source is required".into()),
    };
    let output = match output {
        Some(v) => v,
        _ => return ParseOutcome::Err("--output is required".into()),
    };

    ParseOutcome::Ok(Args {
        list_id,
        source,
        output,
        allow_duplicates,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        ParseOutcome::Ok(a) => a,
        ParseOutcome::Help => {
            print!("{}", USAGE);
            return ExitCode::SUCCESS;
        }
        ParseOutcome::Err(msg) => {
            eprintln!("trusset-list-commit: {}\n", msg);
            eprint!("{}", USAGE);
            return ExitCode::from(64); // EX_USAGE
        }
    };

    let source_bytes = match std::fs::read(&args.source) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "trusset-list-commit: cannot read {}: {}",
                args.source.display(),
                e
            );
            return ExitCode::from(66); // EX_NOINPUT
        }
    };

    let opts = CommitOptions {
        allow_duplicates: args.allow_duplicates,
    };

    let file = match commit_list(&args.list_id, &source_bytes, &opts) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("trusset-list-commit: {}", e);
            return ExitCode::from(65); // EX_DATAERR
        }
    };

    let json = match serde_json::to_string_pretty(&file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("trusset-list-commit: json serialize: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "trusset-list-commit: cannot create {}: {}",
                    parent.display(),
                    e
                );
                return ExitCode::from(73); // EX_CANTCREAT
            }
        }
    }
    if let Err(e) = std::fs::write(&args.output, format!("{}\n", json)) {
        eprintln!(
            "trusset-list-commit: cannot write {}: {}",
            args.output.display(),
            e
        );
        return ExitCode::from(73);
    }

    println!(
        "{}: {} entries, root {}, source SHA-256 {}",
        args.list_id,
        file.values.len(),
        &file.root[..14],
        &file.source_sha256[..14],
    );
    ExitCode::SUCCESS
}
