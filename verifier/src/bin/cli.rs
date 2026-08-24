//! `trusset-verifier-cli` — thin CLI wrapper around `verify_bundle`.
//!
//! ```text
//! trusset-verifier-cli \
//!   (--bundle <DIR> | --archive <FILE> [--subject <0xADDR>]) \
//!   [--public-key <64-hex>]   # offline bundles: pin the operator key
//!   [--root <0x64-hex>]       # on-chain bundles: pin the published root
//!   [--as-of-block <N> --chain-id <N>]   # entitlement at a past block
//!   [--as-of-date YYYY-MM-DD]            # entitlement on a past day
//!   [--registry <DIR>]        # signed list/root/revocation registries
//!   [--accept-stub]           # accept manifest.mode == "stub"
//!   [--json]                  # machine-readable output
//! ```
//!
//! Two distinct questions this answers, kept apart on purpose:
//!
//!   - **Does the bundle verify?** (`overall_pass`) Pure cryptography. A
//!     bundle whose claims were later declared void still passes: the proof is
//!     a true record of what the operator asserted.
//!   - **Could this subject rely on it at instant X?** (`temporal.entitled`)
//!     Adds the root that was on chain then, the leaf validity windows, and
//!     any revocation the operator has since signed.
//!
//! Verifying from `--archive` needs nothing but the file: the archive carries
//! the bundles, the list versions their proofs were made against, the root
//! history, and the revocation log.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use trusset_bundle_format::archive::{decode_b64, Archive};
use trusset_bundle_format::registry::{ListRegistry, RevocationLog, RootHistory};
use trusset_verifier::{
    bundle, verify_bundle, verify_loaded, AsOf, TemporalContext, VerifyAnchors, VerifyOptions,
    VerifyReport,
};

const USAGE: &str = "\
Usage: trusset-verifier-cli (--bundle <DIR> | --archive <FILE>) [anchors] [options]

Source (exactly one required):
  --bundle <DIR>           A bundle directory (`output/<wallet>`)
  --archive <FILE>         A .tka archive; self-contained, needs nothing else
  --subject <0xADDR>       Which subject to verify from an archive
                           (default: every subject in it)

Anchors (at least one required):
  --public-key <HEX>       Operator's 32-byte ed25519 public key, hex
  --root <HEX>             kycHash read from chain, 0x + 64 hex

As-of (optional; default is the bundle's own date):
  --as-of-block <N>        Evaluate entitlement at this block height
  --chain-id <N>           Chain the block is on (required with --as-of-block)
  --as-of-date <D>         Evaluate entitlement on YYYY-MM-DD
  --now <D>                Treat YYYY-MM-DD as today (default: system clock)

Context (optional; an archive supplies all of these itself):
  --registry <DIR>         Signed registry root (default: config/registry)

Other:
  --accept-stub            Accept bundles with mode == \"stub\" (development)
  --strict                 No-op (strict mode is the default since Stage 18)
  --json                   Emit machine-readable JSON report
  --help, -h               Show this help

Exit codes:
  0   verify passed
  2   verify failed (cryptographic mismatch or policy rejection)
  3   verify passed but the subject was not entitled at the queried instant
  64  usage error
  66  bundle or archive unreadable
";

struct Args {
    bundle: Option<PathBuf>,
    archive: Option<PathBuf>,
    subject: Option<String>,
    public_key: Option<[u8; 32]>,
    root: Option<String>,
    as_of_block: Option<u64>,
    chain_id: Option<u64>,
    as_of_date: Option<u64>,
    now: Option<u64>,
    registry: Option<PathBuf>,
    accept_stub: bool,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut iter = std::env::args().skip(1);
    let mut bundle: Option<PathBuf> = None;
    let mut archive: Option<PathBuf> = None;
    let mut subject: Option<String> = None;
    let mut public_key_hex: Option<String> = None;
    let mut root_hex: Option<String> = None;
    let mut as_of_block: Option<u64> = None;
    let mut chain_id: Option<u64> = None;
    let mut as_of_date: Option<u64> = None;
    let mut now: Option<u64> = None;
    let mut registry: Option<PathBuf> = None;
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
            "--archive" => {
                archive = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--archive requires a path".to_string())?,
                ));
            }
            "--subject" => {
                subject = Some(
                    iter.next()
                        .ok_or_else(|| "--subject requires an address".to_string())?,
                );
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
            "--as-of-block" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--as-of-block requires a height".to_string())?;
                as_of_block = Some(
                    v.parse()
                        .map_err(|_| "--as-of-block must be an integer".to_string())?,
                );
            }
            "--chain-id" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--chain-id requires a value".to_string())?;
                chain_id = Some(
                    v.parse()
                        .map_err(|_| "--chain-id must be an integer".to_string())?,
                );
            }
            "--as-of-date" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--as-of-date requires YYYY-MM-DD".to_string())?;
                as_of_date = Some(parse_date(&v)?);
            }
            "--now" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--now requires YYYY-MM-DD".to_string())?;
                now = Some(parse_date(&v)?);
            }
            "--registry" => {
                registry = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--registry requires a path".to_string())?,
                ));
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

    if bundle.is_none() && archive.is_none() {
        return Err("one of --bundle <DIR> or --archive <FILE> is required".to_string());
    }
    if bundle.is_some() && archive.is_some() {
        return Err("--bundle and --archive are mutually exclusive".to_string());
    }
    if public_key_hex.is_none() && root_hex.is_none() {
        return Err(
            "at least one anchor is required: pass --public-key (offline bundles) or --root \
             (on-chain root)"
                .to_string(),
        );
    }
    if as_of_block.is_some() && chain_id.is_none() {
        return Err(
            "--as-of-block requires --chain-id: a block height only identifies an instant \
             relative to a chain"
                .to_string(),
        );
    }
    if as_of_block.is_some() && as_of_date.is_some() {
        return Err("--as-of-block and --as-of-date are mutually exclusive".to_string());
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
        archive,
        subject,
        public_key,
        root,
        as_of_block,
        chain_id,
        as_of_date,
        now,
        registry,
        accept_stub,
        json,
    })
}

/// `YYYY-MM-DD` to `epochDays`.
fn parse_date(input: &str) -> Result<u64, String> {
    if let Ok(n) = input.trim().parse::<u64>() {
        return Ok(n);
    }
    let b = input.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(format!("'{}' is not YYYY-MM-DD", input));
    }
    let y: i64 = input[0..4].parse().map_err(|_| "year is not numeric")?;
    let m: u32 = input[5..7].parse().map_err(|_| "month is not numeric")?;
    let d: u32 = input[8..10].parse().map_err(|_| "day is not numeric")?;
    days_from_civil(y, m, d).ok_or_else(|| format!("'{}' is not a real calendar date", input))
}

fn days_from_civil(y: i64, m: u32, d: u32) -> Option<u64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = m as u64;
    let d = d as u64;
    let m_adj = if m > 2 { m as i64 - 3 } else { m as i64 + 9 };
    let doy = ((153 * m_adj as u64 + 2) / 5) + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146097) + doe as i64 - 719468;
    if days < 0 {
        None
    } else {
        Some(days as u64)
    }
}

fn today_epoch_days() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

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

/// Load whatever signed registries exist under a registry root. Missing files
/// are not an error: a verifier who was handed only a bundle still gets a
/// cryptographic answer, with the gaps named in `temporal.notes`.
fn load_registries(dir: &Path) -> TemporalContext {
    let mut ctx = TemporalContext::default();

    let history_path = dir.join("root_history.json");
    if let Ok(bytes) = std::fs::read(&history_path) {
        match serde_json::from_slice::<RootHistory>(&bytes) {
            Ok(h) if h.validate().is_ok() => ctx.root_history = Some(h),
            Ok(_) => eprintln!(
                "trusset-verifier-cli: {} is structurally invalid and was ignored",
                history_path.display()
            ),
            Err(e) => eprintln!(
                "trusset-verifier-cli: {} is not a readable root history ({}) and was ignored",
                history_path.display(),
                e
            ),
        }
    }

    let revocations_path = dir.join("revocations.json");
    if let Ok(bytes) = std::fs::read(&revocations_path) {
        match serde_json::from_slice::<RevocationLog>(&bytes) {
            Ok(r) if r.validate().is_ok() => ctx.revocations = Some(r),
            Ok(_) => eprintln!(
                "trusset-verifier-cli: {} is structurally invalid and was ignored",
                revocations_path.display()
            ),
            Err(e) => eprintln!(
                "trusset-verifier-cli: {} is not a readable revocation log ({}) and was ignored",
                revocations_path.display(),
                e
            ),
        }
    }

    if let Ok(entries) = std::fs::read_dir(dir.join("lists")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(reg) = serde_json::from_slice::<ListRegistry>(&bytes) {
                    if reg.validate().is_ok() {
                        ctx.list_registries.insert(reg.list_id.clone(), reg);
                    }
                }
            }
        }
    }

    ctx
}

fn build_as_of(args: &Args) -> AsOf {
    if let (Some(height), Some(chain_id)) = (args.as_of_block, args.chain_id) {
        AsOf::Block { chain_id, height }
    } else if let Some(epoch_days) = args.as_of_date {
        AsOf::Date { epoch_days }
    } else {
        AsOf::Now
    }
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

    let now_epoch_days = args.now.unwrap_or_else(today_epoch_days);
    let as_of = build_as_of(&args);

    let reports: Vec<(String, VerifyReport)> = if let Some(archive_path) = args.archive.as_ref() {
        match verify_from_archive(archive_path, &args, &as_of, now_epoch_days) {
            Ok(r) => r,
            Err(msg) => {
                eprintln!("trusset-verifier-cli: {}", msg);
                return ExitCode::from(66);
            }
        }
    } else {
        let bundle_path = args.bundle.clone().expect("checked in parse_args");
        let context = load_registries(
            args.registry
                .as_deref()
                .unwrap_or_else(|| Path::new("config/registry")),
        );
        let opts = VerifyOptions {
            anchors: VerifyAnchors {
                expected_public_key: args.public_key,
                expected_root: args.root.clone(),
            },
            accept_stub: args.accept_stub,
            as_of: as_of.clone(),
            context,
            now_epoch_days,
        };
        match verify_bundle(&bundle_path, &opts) {
            Ok(r) => vec![(bundle_path.display().to_string(), r)],
            Err(e) => {
                eprintln!("trusset-verifier-cli: {}", e);
                return ExitCode::from(66);
            }
        }
    };

    if args.json {
        let payload: Vec<&VerifyReport> = reports.iter().map(|(_, r)| r).collect();
        let out = if payload.len() == 1 {
            serde_json::to_string_pretty(payload[0])
        } else {
            serde_json::to_string_pretty(&payload)
        };
        match out {
            Ok(j) => println!("{}", j),
            Err(e) => {
                eprintln!("trusset-verifier-cli: json: {}", e);
                return ExitCode::FAILURE;
            }
        }
    } else {
        for (source, report) in &reports {
            print_human(
                source,
                report,
                args.public_key.is_some(),
                args.root.is_some(),
            );
            println!();
        }
    }

    let all_pass = reports.iter().all(|(_, r)| r.overall_pass);
    let all_entitled = reports.iter().all(|(_, r)| r.temporal.entitled);
    if !all_pass {
        ExitCode::from(2)
    } else if !all_entitled {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}

fn verify_from_archive(
    path: &Path,
    args: &Args,
    as_of: &AsOf,
    now_epoch_days: u64,
) -> Result<Vec<(String, VerifyReport)>, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let archive = Archive::parse(&bytes).map_err(|e| e.to_string())?;

    if let Some(pk) = args.public_key {
        archive
            .verify_registry_signatures(&pk)
            .map_err(|e| e.to_string())?;
    }

    let context = TemporalContext {
        root_history: Some(archive.root_history.clone()),
        revocations: Some(archive.revocations.clone()),
        list_registries: archive.list_registries.clone(),
    };

    let wanted: Vec<&trusset_bundle_format::archive::ArchivedSubject> =
        match args.subject.as_deref() {
            Some(s) => vec![archive
                .subject(s)
                .ok_or_else(|| format!("archive contains no subject {}", s))?],
            None => archive.subjects.iter().collect(),
        };

    let mut out = Vec::with_capacity(wanted.len());
    for subject in wanted {
        let manifest_bytes =
            trusset_bundle_format::manifest::canonical_disk_bytes(&subject.manifest)
                .map_err(|e| format!("{}: manifest re-serialize: {}", subject.subject_id, e))?;
        let signature = decode_b64(&subject.manifest_sig);
        let mut proofs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (p, b64) in &subject.proofs {
            proofs.insert(
                p.clone(),
                decode_b64(b64)
                    .ok_or_else(|| format!("{}: {} is not valid base64", subject.subject_id, p))?,
            );
        }
        let loaded =
            bundle::loaded_from_parts(&manifest_bytes, &subject.kyc_hash_hex, signature, proofs)
                .map_err(|e| format!("{}: {}", subject.subject_id, e))?;

        let opts = VerifyOptions {
            anchors: VerifyAnchors {
                expected_public_key: args.public_key,
                expected_root: args.root.clone(),
            },
            accept_stub: args.accept_stub,
            as_of: as_of.clone(),
            context: context.clone(),
            now_epoch_days,
        };
        out.push((
            format!("{} (archive {})", subject.subject_id, path.display()),
            verify_loaded(&loaded, &opts),
        ));
    }
    Ok(out)
}

fn print_human(source: &str, report: &VerifyReport, used_key: bool, used_root: bool) {
    println!("Source:    {}", source);
    println!("Wallet:    {}", report.wallet_address);
    println!("kycHash:   {}", report.kyc_hash);
    println!("Leaves:    {}", report.leaf_count);
    println!("Version:   {}", report.manifest_version);
    println!("Anchor:    {}", report.anchor);
    if let Some(issuer) = &report.issuer {
        println!(
            "Issuer:    {} ({}:{}, {})  key {}",
            issuer.name,
            issuer.identifier_scheme,
            issuer.identifier,
            issuer.jurisdiction,
            issuer.key_id
        );
    } else {
        println!("Issuer:    (not recorded — pre-v3 bundle)");
    }
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
        anchor_mark(used_key, report.signature_valid)
    );
    println!(
        "  root_anchor_valid:       {}",
        anchor_mark(used_root, report.root_anchor_valid)
    );
    println!(
        "  merkle_root_valid:       {}",
        check_mark(report.merkle_root_valid)
    );
    println!();

    let t = &report.temporal;
    println!("As of:     {} ({})", t.as_of_date, t.as_of);
    if let (Some(chain), Some(block)) = (t.as_of_chain_id, t.as_of_block) {
        println!("           chain {} block {}", chain, block);
    }
    if let Some(root) = &t.resolved_root {
        println!(
            "  root on chain then:      {} {}",
            &root[..std::cmp::min(14, root.len())],
            match t.resolved_root_matches {
                Some(true) => "[ok] this bundle",
                Some(false) => "[FAIL] a different issuance",
                None => "",
            }
        );
    }
    if t.unpinned_epoch {
        println!("  reproducible:            [FAIL] built with an unpinned epoch");
    }

    println!();
    println!("Per-leaf:");
    for leaf in &report.leaves {
        let mark = check_mark(leaf.pass);
        match &leaf.reason {
            Some(r) => println!(
                "  {} {:<24} {:<20}  ({})",
                mark, leaf.field, leaf.circuit, r
            ),
            None => println!("  {} {:<24} {:<20}", mark, leaf.field, leaf.circuit),
        }
        if let Some(claim) = &leaf.claim {
            println!(
                "        claim    {} / {} — {}",
                claim.legal_basis, claim.legal_reference, claim.assertion
            );
            println!(
                "        evidence {}   warranted by {} ({})",
                claim.evidence_class, claim.issuing_party, claim.issuing_party_identifier
            );
            println!(
                "        valid    {} .. {}   evidence examined {}",
                claim.validity_from_date,
                claim
                    .validity_until_date
                    .clone()
                    .unwrap_or_else(|| "open-ended".to_string()),
                claim.basis_as_of_date
            );
            if let (Some(list_id), Some(version)) = (&claim.list_id, claim.list_version) {
                let resolved = match (claim.list_resolved, claim.list_entry_count) {
                    (Some(true), Some(n)) => format!("resolved, {} entries", n),
                    (Some(true), None) => "resolved".to_string(),
                    _ => "NOT RESOLVED — no registry for this root was supplied".to_string(),
                };
                println!("        list     {} v{} ({})", list_id, version, resolved);
            }
            let status_mark = if claim.status == "effective" {
                "[ok]"
            } else {
                "[!!]"
            };
            println!("        status   {} {}", status_mark, claim.status);
            if let Some(detail) = &claim.detail {
                println!("                 {}", detail);
            }
        }
    }

    if !t.notes.is_empty() {
        println!();
        println!("Notes:");
        for n in &t.notes {
            println!("  - {}", n);
        }
    }

    println!();
    println!(
        "Verifies:  {}",
        if report.overall_pass { "PASS" } else { "FAIL" }
    );
    println!(
        "Entitled:  {}   (as of {})",
        if t.entitled { "YES" } else { "NO" },
        t.as_of_date
    );
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
