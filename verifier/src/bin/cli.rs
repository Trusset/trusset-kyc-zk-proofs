//! `trusset-verifier-cli` — thin CLI wrapper around `verify_bundle`.
//!
//! ```text
//! trusset-verifier-cli \
//!   --bundle output/0xAbCd... \
//!   [--public-key <64-hex>]  # offline bundles: pin the operator key
//!   [--root <0x64-hex>]      # on-chain bundles: pin the published root
//!   [--accept-stub]   # accept manifest.mode == "stub" (development bundles)
//!   [--strict]        # no-op (strict is the default since Stage 18)
//!   [--json]          # machine-readable output
//! ```
//!
//! At least one anchor (`--public-key` or `--root`) is required. When the
//! verifier reads `kycHash` from chain the root already authenticates the
//! bundle, so no out-of-band key pinning is needed; `--public-key` remains
//! for offline bundles whose root is not independently known.
//!
//! Used by the TypeScript CLI's `npm run verify` command via child_process.
//!
//! Stage 18 (2026-05-20): strict mode (`accept_stub = false`) is now the
//! default. The `--strict` flag is kept as a no-op for backward
//! compatibility with existing operator scripts; `--accept-stub`
//! explicitly opts in to accepting `mode: "stub"` bundles for
//! development workflows.

use std::path::PathBuf;
use std::process::ExitCode;
use trusset_verifier::{verify_bundle, VerifyAnchors, VerifyOptions};

const USAGE: &str = "\
Usage: trusset-verifier-cli --bundle <DIR> (--public-key <HEX> | --root <HEX>) [--accept-stub] [--strict] [--json]

Required:
  --bundle <DIR>           Path to a bundle directory (`output/<wallet>`)

Anchors (at least one required):
  --public-key <HEX>       Operator's 32-byte ed25519 public key, hex
  --root <HEX>             kycHash read from chain, 0x + 64 hex

Optional:
  --accept-stub            Accept bundles with mode == \"stub\" (development)
  --strict                 No-op (strict mode is the default since Stage 18)
  --json                   Emit machine-readable JSON report
  --help, -h               Show this help

Exit codes:
  0   verify passed
  2   verify failed (cryptographic mismatch or policy rejection)
  64  usage error
  66  bundle directory unreadable
";

struct Args {
    bundle: PathBuf,
    public_key: Option<[u8; 32]>,
    root: Option<String>,
    accept_stub: bool,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut bundle: Option<PathBuf> = None;
    let mut public_key_hex: Option<String> = None;
    let mut root_hex: Option<String> = None;
    let mut accept_stub = false;
    let mut json = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "--bundle" => {
                bundle = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--bundle requires a path".to_string())?,
                ));
            }
            "--public-key" => {
                public_key_hex = Some(
                    iter.next()
                        .ok_or_else(|| "--public-key requires a value".to_string())?,
                );
            }
            "--root" => {
                root_hex = Some(
                    iter.next()
                        .ok_or_else(|| "--root requires a value".to_string())?,
                );
            }
            "--accept-stub" => accept_stub = true,
            // `--strict` is the post-Stage-18 default; the flag is kept
            // as a no-op so older operator scripts that explicitly pass
            // it continue to work.
            "--strict" => {}
            "--json" => json = true,
            other => return Err(format!("unknown argument: {}", other)),
        }
    }

    let bundle = bundle.ok_or_else(|| "--bundle is required".to_string())?;
    if public_key_hex.is_none() && root_hex.is_none() {
        return Err(
            "at least one anchor is required: pass --public-key (offline bundles) or --root (on-chain root)"
                .to_string(),
        );
    }
    let public_key = match public_key_hex {
        Some(h) => Some(decode_hex32(&h).map_err(|e| format!("--public-key: {}", e))?),
        None => None,
    };
    let root = match root_hex {
        Some(h) => Some(normalize_root(&h).map_err(|e| format!("--root: {}", e))?),
        None => None,
    };
    Ok(Args {
        bundle,
        public_key,
        root,
        accept_stub,
        json,
    })
}

/// Normalize a caller-supplied root to the `0x` + 64 lowercase hex form
/// the manifest uses.
fn normalize_root(s: &str) -> Result<String, String> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.len() != 64 || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "root must be 0x + 64 hex chars, got {}",
            stripped.len()
        ));
    }
    Ok(format!("0x{}", stripped.to_ascii_lowercase()))
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.len() != 64 {
        return Err(format!(
            "public key must be 64 hex chars, got {}",
            stripped.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&stripped[i * 2..i * 2 + 2], 16)
            .map_err(|_| "invalid hex character".to_string())?;
    }
    Ok(out)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("trusset-verifier-cli: {}\n", msg);
            eprint!("{}", USAGE);
            return ExitCode::from(64);
        }
    };

    let opts = VerifyOptions {
        anchors: VerifyAnchors {
            expected_public_key: args.public_key,
            expected_root: args.root.clone(),
        },
        accept_stub: args.accept_stub,
    };

    let report = match verify_bundle(&args.bundle, &opts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("trusset-verifier-cli: {}", e);
            return ExitCode::from(66);
        }
    };

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("trusset-verifier-cli: json: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        println!("Bundle:    {}", args.bundle.display());
        println!("Wallet:    {}", report.wallet_address);
        println!("kycHash:   {}", report.kyc_hash);
        println!("Leaves:    {}", report.leaf_count);
        println!("Version:   {}", report.manifest_version);
        println!("Anchor:    {}", report.anchor);
        println!();
        println!(
            "  layout_ok:               {}",
            check_mark(report.layout_ok)
        );
        println!(
            "  mode_acceptable:         {}",
            check_mark(report.mode_acceptable)
        );
        println!(
            "  kyc_hash_file_matches:   {}",
            check_mark(report.kyc_hash_file_matches)
        );
        println!(
            "  signature_valid:         {}",
            anchor_mark(args.public_key.is_some(), report.signature_valid)
        );
        println!(
            "  root_anchor_valid:       {}",
            anchor_mark(args.root.is_some(), report.root_anchor_valid)
        );
        println!(
            "  merkle_root_valid:       {}",
            check_mark(report.merkle_root_valid)
        );
        println!();
        println!("Per-leaf:");
        for leaf in &report.leaves {
            let mark = check_mark(leaf.pass);
            match &leaf.reason {
                Some(r) => println!(
                    "  {} {:<22} {:<22}  ({})",
                    mark, leaf.field, leaf.circuit, r
                ),
                None => println!("  {} {:<22} {:<22}", mark, leaf.field, leaf.circuit),
            }
        }
        println!();
        println!(
            "Overall:   {}",
            if report.overall_pass { "PASS" } else { "FAIL" }
        );
    }

    if report.overall_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn check_mark(ok: bool) -> &'static str {
    if ok {
        "[ok]"
    } else {
        "[FAIL]"
    }
}

/// An anchor the caller did not supply is not a failure - it simply does
/// not apply to this verification.
fn anchor_mark(supplied: bool, ok: bool) -> &'static str {
    if !supplied {
        "[n/a]"
    } else {
        check_mark(ok)
    }
}
