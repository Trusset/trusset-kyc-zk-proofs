//! Two-part integration test:
//!
//!   1. Run the `trusset-list-commit` binary on a source file and assert the
//!      JSON output validates against the schema.
//!   2. Load the same source list into the prover's `ListCommitment` and
//!      confirm the prover's recomputed Rescue Merkle root matches the
//!      list-commit binary's pinned root — i.e. the two tools agree.

use std::process::Command;
use trusset_circuit_set_membership as set;
use trusset_circuits_common::digest_to_hex;
use trusset_list_commit::{commit_list, CommitOptions, ListCommitmentFile};

fn list_commit_binary() -> std::path::PathBuf {
    let exe = env!("CARGO_BIN_EXE_trusset-list-commit");
    std::path::PathBuf::from(exe)
}

#[test]
fn cli_emits_valid_json_for_country_allowlist() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("countries.txt");
    std::fs::write(
        &source,
        "# ISO 3166-1 alpha-3 allowlist\n# Last updated: 2026-05-14\nDEU\nFRA\nUSA\nGBR\nJPN\n",
    )
    .unwrap();
    let output = tmp.path().join("country_allowlist.json");

    let status = Command::new(list_commit_binary())
        .args([
            "--list-id",
            "country_allowlist",
            "--source",
            source.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "list-commit binary exited with {:?}", status);

    let json: ListCommitmentFile =
        serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert_eq!(json.list_id, "country_allowlist");
    assert_eq!(json.values, vec!["DEU", "FRA", "USA", "GBR", "JPN"]);
    // 5 entries → padded to 8 → depth 3.
    assert_eq!(json.depth, 3);
    assert!(json.root.starts_with("0x"));
    assert!(json.source_sha256.starts_with("0x"));
}

#[test]
fn cli_rejects_duplicates_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("dupes.txt");
    std::fs::write(&source, "DEU\nFRA\nDEU\n").unwrap();
    let output = tmp.path().join("out.json");
    let out = Command::new(list_commit_binary())
        .args([
            "--list-id",
            "x",
            "--source",
            source.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("duplicate"), "expected duplicate-error stderr, got: {}", stderr);
}

#[test]
fn cli_help_works_and_exits_zero() {
    let out = Command::new(list_commit_binary()).args(["--help"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Usage:"));
}

#[test]
fn cli_missing_args_print_usage() {
    let out = Command::new(list_commit_binary()).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("--list-id is required"));
    assert!(stderr.contains("Usage:"));
}

#[test]
fn prover_set_tree_matches_list_commit_root() {
    // The decisive cross-tool check: building the Merkle tree two ways
    // must yield the same root. If a future refactor accidentally diverges
    // either NFC handling, tag domain, or tree padding, this test fires.
    let src = "# header\nDEU\nFRA\nUSA\nGBR\nJPN\nESP\nITA\n";
    let lc = commit_list("x", src.as_bytes(), &CommitOptions::default()).unwrap();
    let refs: Vec<&[u8]> = lc.values.iter().map(|s| s.as_bytes()).collect();
    let (root, depth, _) = set::build_set_tree(&refs);
    assert_eq!(lc.root, digest_to_hex(&root));
    assert_eq!(lc.depth, depth);
}

#[test]
fn nfc_collapses_to_same_root_across_input_encodings() {
    let composed = "caf\u{00e9}\nfoo\n";
    let decomposed = "cafe\u{0301}\nfoo\n";
    let r1 = commit_list("x", composed.as_bytes(), &CommitOptions::default()).unwrap();
    let r2 = commit_list("x", decomposed.as_bytes(), &CommitOptions::default()).unwrap();
    assert_eq!(r1.root, r2.root);
    assert_eq!(r1.values, r2.values);
    assert_ne!(r1.source_sha256, r2.source_sha256);
}
