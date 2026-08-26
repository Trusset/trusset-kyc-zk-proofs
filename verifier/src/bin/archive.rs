//! `trusset-archive` — build and inspect self-contained verification archives.
//!
//! ```text
//! trusset-archive build --output <FILE> [--bundle <DIR>]... [--all]
//! trusset-archive inspect --archive <FILE>
//! ```
//!
//! What an archive is for: a bundle directory verifies offline, but only
//! against what the verifier already knows. It cannot say what `setRoot`
//! committed to, which key signed it, which root was on chain at a given
//! block, or whether the operator has since declared the claim void. Those
//! live in the operator's working tree, so a bundle handed to a third party is
//! verifiable but not interpretable.
//!
//! `build` copies the bundles together with the list registries their proofs
//! depend on, the root history, the revocation log, and the issuer identity,
//! and stamps an integrity digest over the lot. `trusset-verifier-cli
//! --archive` then works on a clean machine with no access to the operator.
//!
//! Building needs no key material: the registries carry their own detached
//! signatures, and the manifests carry theirs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use trusset_bundle_format::archive::{
    encode_b64, finalize, sha256_hex, Archive, ArchivedSubject, ARCHIVE_VERSION,
};
use trusset_bundle_format::manifest::{
    canonical_disk_bytes, is_safe_proof_path, IssuerBlock, Manifest,
};
use trusset_bundle_format::registry::{ListRegistry, RevocationLog, RootHistory};

const USAGE: &str = "\
Usage: trusset-archive <command> [options]

Commands:
  build      Produce one self-contained archive from bundles + registries
  inspect    Print what an archive contains and re-check its integrity

build:
  --output <FILE>        Archive path to write (e.g. batch-2026Q3.tka)
  --bundle <DIR>         A bundle directory. Repeatable.
  --all <DIR>            Every bundle directory under <DIR> (e.g. output)
  --archive-id <LABEL>   Operator label for the batch (default: derived from
                         the output filename)
  --registry <DIR>       Registry root (default: config/registry)
  --include-secrets      Also embed each bundle's secrets.enc. Off by default:
                         an archive is usually handed to a counterparty, and
                         secrets.enc is operator-private even though encrypted.

inspect:
  --archive <FILE>       Archive to read

Exit codes:
  0   ok
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
        Err(msg) => {
            eprintln!("trusset-archive: {}\n", msg);
            eprint!("{}", USAGE);
            return ExitCode::from(64);
        }
    };
    let result = match command.as_str() {
        "build" => cmd_build(&opts),
        "inspect" => cmd_inspect(&opts),
        other => Err(format!("unknown command '{}'", other)),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("trusset-archive: {}", msg);
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    bundles: Vec<PathBuf>,
    all: Option<PathBuf>,
    archive_id: Option<String>,
    registry: Option<PathBuf>,
    include_secrets: bool,
    archive: Option<PathBuf>,
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
            "--output" => o.output = Some(PathBuf::from(take("--output")?)),
            "--bundle" => o.bundles.push(PathBuf::from(take("--bundle")?)),
            "--all" => o.all = Some(PathBuf::from(take("--all")?)),
            "--archive-id" => o.archive_id = Some(take("--archive-id")?),
            "--registry" => o.registry = Some(PathBuf::from(take("--registry")?)),
            "--include-secrets" => o.include_secrets = true,
            "--archive" => o.archive = Some(PathBuf::from(take("--archive")?)),
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

fn now_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs / 86_400;
    let t = (secs % 86_400) as u64;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y0 = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y0 + 1 } else { y0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        t / 3600,
        (t % 3600) / 60,
        t % 60
    )
}

fn discover_bundles(root: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        std::fs::read_dir(root).map_err(|e| format!("cannot read {}: {}", root.display(), e))?;
    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p.join("manifest.json").exists())
        .collect();
    out.sort();
    Ok(out)
}

fn read_registry_dir(dir: &Path) -> (BTreeMap<String, ListRegistry>, BTreeMap<String, String>) {
    let mut registries = BTreeMap::new();
    let mut signatures = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(dir.join("lists")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(reg) = serde_json::from_slice::<ListRegistry>(&bytes) else {
                continue;
            };
            let id = reg.list_id.clone();
            if let Ok(sig) = std::fs::read(path.with_extension("json.sig")) {
                signatures.insert(id.clone(), encode_b64(&sig));
            }
            registries.insert(id, reg);
        }
    }
    (registries, signatures)
}

fn cmd_build(o: &Options) -> Result<(), String> {
    let output = o.output.as_ref().ok_or("build requires --output <FILE>")?;

    let mut bundle_dirs = o.bundles.clone();
    if let Some(root) = o.all.as_ref() {
        bundle_dirs.extend(discover_bundles(root)?);
    }
    bundle_dirs.sort();
    bundle_dirs.dedup();
    if bundle_dirs.is_empty() {
        return Err(
            "no bundles selected. Pass --bundle <DIR> one or more times, or --all output to take \
             every bundle in a directory."
                .to_string(),
        );
    }

    let registry_dir = o
        .registry
        .clone()
        .unwrap_or_else(|| PathBuf::from("config/registry"));

    let mut subjects: Vec<ArchivedSubject> = Vec::with_capacity(bundle_dirs.len());
    let mut issuer: Option<IssuerBlock> = None;
    let mut toolchain = None;
    let mut lists_needed: BTreeSet<String> = BTreeSet::new();

    for dir in &bundle_dirs {
        let manifest_path = dir.join("manifest.json");
        let manifest_bytes = std::fs::read(&manifest_path)
            .map_err(|e| format!("cannot read {}: {}", manifest_path.display(), e))?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            format!(
                "{} is not a readable manifest: {}",
                manifest_path.display(),
                e
            )
        })?;

        // The archive stores the manifest as structured JSON. That is only
        // safe if it re-serializes to the exact bytes the signature covers,
        // so the check happens here rather than at read time when it would be
        // too late to do anything about it.
        let reserialized = canonical_disk_bytes(&manifest)
            .map_err(|e| format!("{}: manifest re-serialize: {}", dir.display(), e))?;
        if reserialized != manifest_bytes {
            return Err(format!(
                "{}: manifest.json does not match its own canonical serialization, so archiving \
                 it would change the bytes its signature covers. The file has been edited since \
                 it was written; re-issue the subject rather than archiving this.",
                dir.display()
            ));
        }

        if issuer.is_none() {
            issuer = manifest.issuer.clone();
        } else if manifest.issuer.is_some() && issuer != manifest.issuer {
            return Err(format!(
                "{}: this bundle names a different issuer than the others in the batch. An \
                 archive asserts one responsible party; build separate archives per issuer.",
                dir.display()
            ));
        }
        if toolchain.is_none() {
            toolchain = manifest.toolchain.clone();
        }

        for leaf in &manifest.leaves {
            if let Some(b) = leaf.binding.as_ref() {
                if let Some(lv) = b.list_version.as_ref() {
                    lists_needed.insert(lv.list_id.clone());
                }
            }
        }
        for id in manifest.lists.keys() {
            lists_needed.insert(id.clone());
        }

        let sig = std::fs::read(dir.join("manifest.sig"))
            .map_err(|e| format!("{}: manifest.sig: {}", dir.display(), e))?;
        let kyc_hash_hex = std::fs::read_to_string(dir.join("kycHash.hex"))
            .map_err(|e| format!("{}: kycHash.hex: {}", dir.display(), e))?;

        let mut proofs = BTreeMap::new();
        for leaf in &manifest.leaves {
            // Archiving reads every path the manifest names. A bundle received
            // from elsewhere is untrusted, so a traversing `proofPath` must not
            // be able to pull a file from outside the bundle into the archive.
            if !is_safe_proof_path(&leaf.proof_path) {
                return Err(format!(
                    "{}: manifest names proof path {:?}, which is not a plain `proofs/<name>` \
                     entry. Refusing to read outside the bundle directory.",
                    dir.display(),
                    leaf.proof_path
                ));
            }
            let p = dir.join(&leaf.proof_path);
            let bytes = std::fs::read(&p)
                .map_err(|e| format!("{}: {}: {}", dir.display(), leaf.proof_path, e))?;
            proofs.insert(leaf.proof_path.clone(), encode_b64(&bytes));
        }

        let secrets_enc = if o.include_secrets {
            std::fs::read(dir.join("secrets.enc"))
                .ok()
                .map(|b| encode_b64(&b))
        } else {
            None
        };

        subjects.push(ArchivedSubject {
            subject_id: manifest.wallet_address.clone(),
            manifest_sha256: sha256_hex(&manifest_bytes),
            manifest,
            manifest_sig: encode_b64(&sig),
            kyc_hash_hex: kyc_hash_hex.trim().to_string(),
            proofs,
            secrets_enc,
        });
    }

    let issuer = issuer.ok_or(
        "none of the selected bundles records an issuer, so the archive would not say who is \
         responsible for its contents. Re-issue the batch with a v3 config (`npm run init` \
         configures `manifest.issuer`), or archive v2 bundles individually with the issuer \
         supplied out of band.",
    )?;

    let (all_registries, all_signatures) = read_registry_dir(&registry_dir);
    let mut list_registries = BTreeMap::new();
    let mut list_registry_signatures = BTreeMap::new();
    let mut missing: Vec<String> = Vec::new();
    for id in &lists_needed {
        match all_registries.get(id) {
            Some(reg) => {
                list_registries.insert(id.clone(), reg.clone());
                if let Some(sig) = all_signatures.get(id) {
                    list_registry_signatures.insert(id.clone(), sig.clone());
                }
            }
            None => missing.push(id.clone()),
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "the selected bundles depend on list(s) {} but {} has no registry for them. Without \
             the registry the archive cannot say what those set-membership proofs committed to. \
             Record one with `npm run list-version -- --list-id <id> --source <file>`.",
            missing.join(", "),
            registry_dir.display()
        ));
    }

    let root_history = std::fs::read(registry_dir.join("root_history.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<RootHistory>(&b).ok())
        .unwrap_or_default();
    let root_history_signature = std::fs::read(registry_dir.join("root_history.json.sig"))
        .ok()
        .map(|b| encode_b64(&b));

    let revocations = std::fs::read(registry_dir.join("revocations.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<RevocationLog>(&b).ok())
        .unwrap_or_default();
    let revocations_signature = std::fs::read(registry_dir.join("revocations.json.sig"))
        .ok()
        .map(|b| encode_b64(&b));

    let archive_id = o.archive_id.clone().unwrap_or_else(|| {
        output
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "archive".to_string())
    });

    let archive = Archive {
        archive_version: ARCHIVE_VERSION.to_string(),
        archive_id,
        created_at: now_iso(),
        issuer,
        toolchain,
        subjects,
        list_registries,
        list_registry_signatures,
        root_history,
        root_history_signature,
        revocations,
        revocations_signature,
        digest: String::new(),
    };

    let (archive, bytes) = finalize(archive).map_err(|e| e.to_string())?;

    // Re-parse what is about to be written. An archive that cannot pass its
    // own integrity and structure checks must never reach disk, or the
    // operator finds out years later.
    Archive::parse(&bytes).map_err(|e| {
        format!(
            "refusing to write an archive that fails its own checks: {}",
            e
        )
    })?;

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
        }
    }
    std::fs::write(output, &bytes)
        .map_err(|e| format!("cannot write {}: {}", output.display(), e))?;

    println!("Archive:   {}", output.display());
    println!("  id             {}", archive.archive_id);
    println!("  digest         {}", archive.digest);
    println!("  size           {} bytes", bytes.len());
    println!(
        "  issuer         {} ({}:{}, {})",
        archive.issuer.party.name,
        archive.issuer.party.identifier_scheme,
        archive.issuer.party.identifier,
        archive.issuer.party.jurisdiction
    );
    println!("  subjects       {}", archive.subjects.len());
    println!(
        "  list versions  {}",
        archive
            .list_registries
            .values()
            .map(|r| r.versions.len())
            .sum::<usize>()
    );
    println!("  root anchors   {}", archive.root_history.entries.len());
    println!("  revocations    {}", archive.revocations.entries.len());
    println!();
    println!("Verify from this file alone with:");
    println!(
        "  trusset-verifier-cli --archive {} --public-key {}",
        output.display(),
        archive.issuer.public_key.trim_start_matches("0x")
    );
    Ok(())
}

fn cmd_inspect(o: &Options) -> Result<(), String> {
    let path = o
        .archive
        .as_ref()
        .ok_or("inspect requires --archive <FILE>")?;
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let archive = Archive::parse(&bytes).map_err(|e| e.to_string())?;

    println!("Archive:   {}", path.display());
    println!("  format         {}", archive.archive_version);
    println!("  id             {}", archive.archive_id);
    println!("  created        {}", archive.created_at);
    println!("  digest         {}  [ok] recomputed", archive.digest);
    println!("  size           {} bytes", bytes.len());
    println!();
    println!(
        "Issuer:    {} ({}:{}, {})",
        archive.issuer.party.name,
        archive.issuer.party.identifier_scheme,
        archive.issuer.party.identifier,
        archive.issuer.party.jurisdiction
    );
    println!(
        "  key {}  {}",
        archive.issuer.key_id, archive.issuer.public_key
    );
    if let Some(t) = &archive.toolchain {
        println!();
        println!("Built by:  trusset-prover {}", t.prover_version);
        println!("  sha256         {}", t.prover_sha256);
        if let Some(c) = &t.source_commit {
            println!("  source commit  {}", c);
        }
    }

    println!();
    println!("Subjects: {}", archive.subjects.len());
    for s in &archive.subjects {
        println!(
            "  {}  {} leaves  {}  as of {}",
            s.subject_id,
            s.manifest.leaves.len(),
            &s.kyc_hash_hex[..std::cmp::min(14, s.kyc_hash_hex.len())],
            s.manifest
                .as_of_date
                .clone()
                .unwrap_or_else(|| format!("epoch day {}", s.manifest.epoch_days))
        );
    }

    println!();
    println!("List registries:");
    if archive.list_registries.is_empty() {
        println!("  (none)");
    }
    for (id, reg) in &archive.list_registries {
        println!("  {}", id);
        for v in &reg.versions {
            println!(
                "    v{}  from epoch day {}{}  {} entries  root {}",
                v.version,
                v.effective_from,
                v.effective_until
                    .map(|u| format!(" to {}", u))
                    .unwrap_or_else(|| " (current)".to_string()),
                v.values.len(),
                &v.root[..std::cmp::min(14, v.root.len())]
            );
        }
    }

    println!();
    println!("Root anchors: {}", archive.root_history.entries.len());
    for a in &archive.root_history.entries {
        println!(
            "  {}  chain {} block {}  {}",
            a.subject,
            a.chain_id,
            a.block_height,
            &a.kyc_hash[..std::cmp::min(14, a.kyc_hash.len())]
        );
    }

    println!();
    println!("Revocations: {}", archive.revocations.entries.len());
    for r in &archive.revocations.entries {
        println!(
            "  {}  {}  {}  ({})",
            r.subject,
            r.leaf_name.as_deref().unwrap_or("<all leaves>"),
            r.effect.as_str(),
            r.reason_code
        );
    }
    Ok(())
}
