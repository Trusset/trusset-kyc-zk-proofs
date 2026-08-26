//! `trusset-registry` — append to and inspect the v3 append-only registries.
//!
//! ```text
//! trusset-registry list-version --list-id <ID> --source <FILE> [--effective-date YYYY-MM-DD]
//! trusset-registry anchor --bundle <DIR> --chain-id <N> --block <N> --block-time <UNIX>
//! trusset-registry revoke --bundle <DIR> --effect lapsed|void_ab_initio --reason <CODE>
//! trusset-registry show
//! ```
//!
//! Every write is signed with `TRUSSET_KYC_SIGNING_KEY`, the same key that
//! signs manifests, so a counterparty who trusts an operator's bundles trusts
//! their registries without pinning a second key.
//!
//! Nothing here ever edits or removes an existing record. See
//! `prover::registry_io` for the invariants each writer enforces.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use trusset_bundle_format::manifest::Manifest;
use trusset_bundle_format::registry::{
    RevocationEffect, RevocationRecord, RootAnchor, REGISTRY_SCHEMA_VERSION,
};
use trusset_list_commit::{commit_list, CommitOptions};
use trusset_prover::dates::{days_from_civil, epoch_days_to_iso_date};
use trusset_prover::registry_io::{
    append_list_version, append_revocation, append_root_anchor, load_list_registry,
    load_revocations, load_root_history, RegistryPaths, DEFAULT_REGISTRY_DIR,
};
use trusset_prover::sign::SigningSecret;

const USAGE: &str = "\
Usage: trusset-registry <command> [options]

Commands:
  list-version   Record a new authoritative version of an allowlist
  anchor         Record that a bundle's kycHash was published on chain
  revoke         Record that a claim lapsed, or was never valid
  show           Print the registries in this working tree

Common options:
  --registry <DIR>       Registry root (default: config/registry)
  --help, -h             Show this help

list-version:
  --list-id <ID>         Logical list identifier, e.g. country_allowlist
  --source <FILE>        Plain-text source, one entry per line, '#' comments
  --effective-date <D>   YYYY-MM-DD this version becomes authoritative
                         (default: today). The previous version's window is
                         closed on the day before.
  --note <TEXT>          Why the list changed. Retained in the record.
  --allow-duplicates     Dedupe silently instead of failing on repeats

anchor:
  --bundle <DIR>         Bundle directory the root came from
  --chain-id <N>         EVM chain id the root was published to
  --block <N>            Block height of the publishing transaction
  --block-time <UNIX>    Block timestamp, unix seconds
  --tx <HASH>            Transaction hash (optional, recorded verbatim)

revoke:
  --bundle <DIR>         Bundle directory being revoked
  --leaf <NAME>          Leaf to revoke (default: every leaf in the bundle)
  --effect <E>           lapsed | void_ab_initio
  --effective-date <D>   YYYY-MM-DD the claim stopped holding. Required for
                         lapsed; rejected for void_ab_initio, which asserts
                         the claim never held and so has no start date.
  --reason <CODE>        Short machine-readable reason, e.g. DOC_EXPIRED
  --note <TEXT>          Free text for the audit trail

Environment:
  TRUSSET_KYC_SIGNING_KEY   32-byte hex ed25519 seed. Required for every write.

Exit codes:
  0   recorded
  1   failed
  64  usage error
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print!("{}", USAGE);
        return ExitCode::SUCCESS;
    }

    let command = args[0].clone();
    let opts = match parse_options(&args[1..]) {
        Ok(o) => o,
        Err(msg) => return usage_error(&msg),
    };

    let result = match command.as_str() {
        "list-version" => cmd_list_version(&opts),
        "anchor" => cmd_anchor(&opts),
        "revoke" => cmd_revoke(&opts),
        "show" => cmd_show(&opts),
        other => {
            return usage_error(&format!("unknown command '{}'", other));
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("trusset-registry: {}", msg);
            ExitCode::FAILURE
        }
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("trusset-registry: {}\n", msg);
    eprint!("{}", USAGE);
    ExitCode::from(64)
}

#[derive(Default)]
struct Options {
    registry: Option<String>,
    list_id: Option<String>,
    source: Option<PathBuf>,
    effective_date: Option<String>,
    note: Option<String>,
    allow_duplicates: bool,
    bundle: Option<PathBuf>,
    chain_id: Option<u64>,
    block: Option<u64>,
    block_time: Option<u64>,
    tx: Option<String>,
    leaf: Option<String>,
    effect: Option<String>,
    reason: Option<String>,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{} requires a value", name))
        };
        match flag {
            "--registry" => o.registry = Some(take("--registry")?),
            "--list-id" => o.list_id = Some(take("--list-id")?),
            "--source" => o.source = Some(PathBuf::from(take("--source")?)),
            "--effective-date" => o.effective_date = Some(take("--effective-date")?),
            "--note" => o.note = Some(take("--note")?),
            "--allow-duplicates" => o.allow_duplicates = true,
            "--bundle" => o.bundle = Some(PathBuf::from(take("--bundle")?)),
            "--chain-id" => {
                let v = take("--chain-id")?;
                o.chain_id = Some(v.parse().map_err(|_| "--chain-id must be an integer")?);
            }
            "--block" => {
                let v = take("--block")?;
                o.block = Some(v.parse().map_err(|_| "--block must be an integer")?);
            }
            "--block-time" => {
                let v = take("--block-time")?;
                o.block_time = Some(v.parse().map_err(|_| "--block-time must be unix seconds")?);
            }
            "--tx" => o.tx = Some(take("--tx")?),
            "--leaf" => o.leaf = Some(take("--leaf")?),
            "--effect" => o.effect = Some(take("--effect")?),
            "--reason" => o.reason = Some(take("--reason")?),
            "--help" | "-h" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("unknown option '{}'", other)),
        }
        i += 1;
    }
    Ok(o)
}

fn paths(o: &Options) -> RegistryPaths {
    RegistryPaths::new(
        o.registry
            .clone()
            .unwrap_or_else(|| DEFAULT_REGISTRY_DIR.to_string()),
    )
}

fn signing_key() -> Result<SigningSecret, String> {
    let hex = std::env::var("TRUSSET_KYC_SIGNING_KEY").map_err(|_| {
        "TRUSSET_KYC_SIGNING_KEY is not set. Registry records are signed with the same key that \
         signs manifests, so a counterparty who trusts your bundles trusts your registries. Run \
         `npm run init` if you have not generated one."
            .to_string()
    })?;
    SigningSecret::from_hex(&hex).map_err(|e| e.message)
}

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs / 86_400;
    let t = (secs % 86_400) as u64;
    let (y, mo, d) = trusset_prover::dates::civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        mo,
        d,
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

fn today_epoch_days() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400
}

/// Accept `YYYY-MM-DD` or a raw epoch-day integer. Operators think in dates;
/// the registry stores day counts.
fn parse_date(input: &str) -> Result<u64, String> {
    if let Ok(n) = input.trim().parse::<u64>() {
        return Ok(n);
    }
    let b = input.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(format!(
            "'{}' is not a date. Use YYYY-MM-DD, or an epoch-day integer.",
            input
        ));
    }
    let y: i64 = input[0..4].parse().map_err(|_| "year is not numeric")?;
    let m: u32 = input[5..7].parse().map_err(|_| "month is not numeric")?;
    let d: u32 = input[8..10].parse().map_err(|_| "day is not numeric")?;
    days_from_civil(y, m, d).ok_or_else(|| format!("'{}' is not a real calendar date", input))
}

fn read_manifest(bundle: &Path) -> Result<(Manifest, Vec<u8>), String> {
    let path = bundle.join("manifest.json");
    let bytes = std::fs::read(&path).map_err(|e| {
        format!(
            "cannot read {}: {}. Pass --bundle pointing at a directory containing manifest.json.",
            path.display(),
            e
        )
    })?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not a readable manifest: {}", path.display(), e))?;
    Ok((manifest, bytes))
}

// ============================== list-version ==============================

fn cmd_list_version(o: &Options) -> Result<(), String> {
    let list_id = o
        .list_id
        .as_deref()
        .ok_or("list-version requires --list-id")?;
    let source = o
        .source
        .as_ref()
        .ok_or("list-version requires --source <FILE>")?;
    let key = signing_key()?;

    let source_bytes =
        std::fs::read(source).map_err(|e| format!("cannot read {}: {}", source.display(), e))?;
    let committed = commit_list(
        list_id,
        &source_bytes,
        &CommitOptions {
            allow_duplicates: o.allow_duplicates,
        },
    )
    .map_err(|e| format!("{}: {}", source.display(), e))?;

    let effective_from = match o.effective_date.as_deref() {
        Some(d) => parse_date(d)?,
        None => today_epoch_days(),
    };

    let appended = append_list_version(
        &paths(o),
        list_id,
        committed.values.clone(),
        committed.root.clone(),
        committed.depth,
        committed.source_sha256.clone(),
        effective_from,
        committed.generator.clone(),
        now_iso(),
        o.note.clone(),
        &key,
    )
    .map_err(|e| e.message)?;

    println!(
        "{}: recorded version {} effective {} ({} entries)",
        list_id,
        appended.version,
        epoch_days_to_iso_date(effective_from),
        committed.values.len()
    );
    println!("  root         {}", appended.root);
    println!("  contentHash  {}", appended.content_hash);
    match appended.superseded {
        Some(prev) => println!(
            "  supersedes   version {} (its window closed on {})",
            prev,
            epoch_days_to_iso_date(effective_from - 1)
        ),
        None => println!("  supersedes   nothing (this is the first version)"),
    }
    println!(
        "  Bundles proved against earlier versions keep verifying: their leaves record the \
         version they used."
    );
    Ok(())
}

// ================================= anchor =================================

fn cmd_anchor(o: &Options) -> Result<(), String> {
    let bundle = o.bundle.as_ref().ok_or("anchor requires --bundle <DIR>")?;
    let chain_id = o.chain_id.ok_or("anchor requires --chain-id <N>")?;
    let block = o.block.ok_or("anchor requires --block <N>")?;
    let block_time = o.block_time.ok_or(
        "anchor requires --block-time <UNIX SECONDS>. It is what lets an as-of check be phrased \
         as a date rather than a block height.",
    )?;
    let key = signing_key()?;

    let (manifest, manifest_bytes) = read_manifest(bundle)?;
    let anchor = RootAnchor {
        subject: manifest.wallet_address.clone(),
        kyc_hash: manifest.kyc_hash.clone(),
        epoch_days: manifest.epoch_days,
        chain_id,
        block_height: block,
        block_timestamp: block_time,
        tx_hash: o.tx.clone(),
        manifest_sha256: trusset_bundle_format::archive::sha256_hex(&manifest_bytes),
        recorded_at: now_iso(),
    };

    append_root_anchor(&paths(o), anchor, &key).map_err(|e| e.message)?;
    println!(
        "anchored {} at block {} on chain {} ({})",
        manifest.wallet_address,
        block,
        chain_id,
        epoch_days_to_iso_date(block_time / 86_400)
    );
    println!("  kycHash  {}", manifest.kyc_hash);
    println!(
        "  An as-of check at or after this block now resolves to this root without chain access."
    );
    Ok(())
}

// ================================= revoke =================================

fn cmd_revoke(o: &Options) -> Result<(), String> {
    let bundle = o.bundle.as_ref().ok_or("revoke requires --bundle <DIR>")?;
    let effect_str = o
        .effect
        .as_deref()
        .ok_or("revoke requires --effect lapsed|void_ab_initio")?;
    let reason = o
        .reason
        .as_deref()
        .ok_or("revoke requires --reason <CODE>")?;
    let key = signing_key()?;

    let effect = match effect_str {
        "lapsed" => RevocationEffect::Lapsed,
        "void_ab_initio" => RevocationEffect::VoidAbInitio,
        other => {
            return Err(format!(
                "--effect '{}' is not recognised. Use 'lapsed' when the claim was true and \
                 stopped being true — everything that relied on it before that date stands. Use \
                 'void_ab_initio' when the claim was never true — every reliance on it, at any \
                 date, is in question. These are not interchangeable.",
                other
            ))
        }
    };

    let effective_from =
        match (effect, o.effective_date.as_deref()) {
            (RevocationEffect::Lapsed, Some(d)) => Some(parse_date(d)?),
            (RevocationEffect::Lapsed, None) => {
                return Err(
                    "a lapsed revocation requires --effective-date: the day the claim stopped \
                 holding. Everything before that date remains valid, so the date is the whole \
                 content of the record."
                        .to_string(),
                )
            }
            (RevocationEffect::VoidAbInitio, Some(_)) => return Err(
                "--effective-date is not accepted with --effect void_ab_initio. A voidance says \
                 the claim was never true; naming a start date would imply it held before then. \
                 If the claim was valid up to a point, use --effect lapsed."
                    .to_string(),
            ),
            (RevocationEffect::VoidAbInitio, None) => None,
        };

    let (manifest, _) = read_manifest(bundle)?;
    if let Some(leaf) = o.leaf.as_deref() {
        if !manifest.leaves.iter().any(|l| l.field_name == leaf) {
            return Err(format!(
                "bundle {} has no leaf named '{}'. Its leaves are: {}.",
                bundle.display(),
                leaf,
                manifest
                    .leaves
                    .iter()
                    .map(|l| l.field_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }

    let record = RevocationRecord {
        subject: manifest.wallet_address.clone(),
        kyc_hash: manifest.kyc_hash.clone(),
        leaf_name: o.leaf.clone(),
        effect,
        effective_from,
        declared_at: today_epoch_days(),
        reason_code: reason.to_string(),
        note: o.note.clone(),
        issuer_key_id: manifest
            .issuer
            .as_ref()
            .map(|i| i.key_id.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        recorded_at: now_iso(),
    };

    append_revocation(&paths(o), record, &key).map_err(|e| e.message)?;

    let scope = o.leaf.as_deref().unwrap_or("every leaf");
    match effect {
        RevocationEffect::Lapsed => println!(
            "recorded: {} on {} lapsed from {} ({})",
            scope,
            manifest.wallet_address,
            epoch_days_to_iso_date(effective_from.expect("checked above")),
            reason
        ),
        RevocationEffect::VoidAbInitio => println!(
            "recorded: {} on {} is void from the start ({})",
            scope, manifest.wallet_address, reason
        ),
    }
    println!(
        "  The bundle still verifies cryptographically — the proof is a true record of what was \
         asserted. Verification now reports the revocation alongside it."
    );
    Ok(())
}

// ================================== show ==================================

fn cmd_show(o: &Options) -> Result<(), String> {
    let p = paths(o);
    println!("Registry root: {}", p.root.display());
    println!();

    let lists_dir = p.lists_dir();
    println!("List registries:");
    let mut found = false;
    if let Ok(entries) = std::fs::read_dir(&lists_dir) {
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.strip_suffix(".json").map(|s| s.to_string())
            })
            .collect();
        names.sort();
        for id in names {
            found = true;
            match load_list_registry(&p, &id).map_err(|e| e.message)? {
                Some(reg) => {
                    println!("  {}", id);
                    for v in &reg.versions {
                        let until = match v.effective_until {
                            Some(u) => epoch_days_to_iso_date(u),
                            None => "current".to_string(),
                        };
                        println!(
                            "    v{}  {} .. {}  {} entries  root {}",
                            v.version,
                            epoch_days_to_iso_date(v.effective_from),
                            until,
                            v.values.len(),
                            &v.root[..std::cmp::min(14, v.root.len())]
                        );
                    }
                }
                None => println!("  {} (unreadable)", id),
            }
        }
    }
    if !found {
        println!("  (none) — run `npm run list-version` to record one");
    }

    println!();
    let history = load_root_history(&p).map_err(|e| e.message)?;
    println!("Root history: {} anchor(s)", history.entries.len());
    for a in &history.entries {
        println!(
            "  {}  chain {} block {}  {}  {}",
            a.subject,
            a.chain_id,
            a.block_height,
            epoch_days_to_iso_date(a.block_timestamp / 86_400),
            &a.kyc_hash[..std::cmp::min(14, a.kyc_hash.len())]
        );
    }

    println!();
    let revocations = load_revocations(&p).map_err(|e| e.message)?;
    println!("Revocations: {} record(s)", revocations.entries.len());
    for r in &revocations.entries {
        let when = match r.effective_from {
            Some(f) => format!("from {}", epoch_days_to_iso_date(f)),
            None => "from the start".to_string(),
        };
        println!(
            "  {}  {}  {}  {}  ({})",
            r.subject,
            r.leaf_name.as_deref().unwrap_or("<all leaves>"),
            r.effect.as_str(),
            when,
            r.reason_code
        );
    }

    println!();
    println!("Schema version: {}", REGISTRY_SCHEMA_VERSION);
    Ok(())
}
