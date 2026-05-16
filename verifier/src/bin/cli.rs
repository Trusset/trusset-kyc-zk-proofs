//! `trusset-verifier-cli` — thin CLI wrapper around `verify_bundle`.
//!
//! ```text
//! trusset-verifier-cli \
//!   --bundle output/0xAbCd... \
//!   --public-key <64-hex> \
//!   [--strict]   # reject mode:"stub"
//!   [--json]     # machine-readable output
//! ```
//!
//! Used by the TypeScript CLI's `npm run verify` command via child_process.

use std::path::PathBuf;
use std::process::ExitCode;
use trusset_verifier::{verify_bundle, VerifyOptions};

const USAGE: &str = "\
Usage: trusset-verifier-cli --bundle <DIR> --public-key <HEX> [--strict] [--json]

Required:
  --bundle <DIR>           Path to a bundle directory (`output/<wallet>`)
  --public-key <HEX>       Operator's 32-byte ed25519 public key, hex

Optional:
  --strict                 Reject bundles with mode != \"production\"
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
    public_key: [u8; 32],
    strict: bool,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut bundle: Option<PathBuf> = None;
    let mut public_key_hex: Option<String> = None;
    let mut strict = false;
    let mut json = false;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "--bundle" => {
                bundle = Some(PathBuf::from(
                    iter.next().ok_or_else(|| "--bundle requires a path".to_string())?,
                ));
            }
            "--public-key" => {
                public_key_hex =
                    Some(iter.next().ok_or_else(|| "--public-key requires a value".to_string())?);
            }
            "--strict" => strict = true,
            "--json" => json = true,
            other => return Err(format!("unknown argument: {}", other)),
        }
    }

    let bundle = bundle.ok_or_else(|| "--bundle is required".to_string())?;
    let pk_hex = public_key_hex.ok_or_else(|| "--public-key is required".to_string())?;
    let pk_bytes = decode_hex32(&pk_hex).map_err(|e| format!("--public-key: {}", e))?;
    Ok(Args {
        bundle,
        public_key: pk_bytes,
        strict,
        json,
    })
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.len() != 64 {
        return Err(format!("public key must be 64 hex chars, got {}", stripped.len()));
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
        expected_public_key: args.public_key,
        accept_stub: !args.strict,
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
        println!();
        println!("  layout_ok:               {}", check_mark(report.layout_ok));
        println!("  mode_acceptable:         {}", check_mark(report.mode_acceptable));
        println!("  kyc_hash_file_matches:   {}", check_mark(report.kyc_hash_file_matches));
        println!("  signature_valid:         {}", check_mark(report.signature_valid));
        println!("  merkle_root_valid:       {}", check_mark(report.merkle_root_valid));
        println!();
        println!("Per-leaf:");
        for leaf in &report.leaves {
            let mark = check_mark(leaf.pass);
            match &leaf.reason {
                Some(r) => println!("  {} {:<22} {:<22}  ({})", mark, leaf.field, leaf.circuit, r),
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
