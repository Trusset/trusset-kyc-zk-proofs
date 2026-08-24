// CLI entrypoint. Preserves the v1/v2 verbs (`hash`, `decrypt`, `verify`,
// `show`) and adds the v3 ones: `init`, `list-version`, `anchor`, `revoke`,
// and `archive`. Each command supports `--json` for machine-readable output.

import { Command } from 'commander';
import { spawnSync } from 'child_process';
import * as path from 'path';
import { describeConfig, loadConfig, ResolvedConfig } from './config';
import {
  buildIndexRows,
  failuresFromProver,
  failuresFromValidation,
  readKycHashFromBundle,
  writeBatchedIndex,
  writeFailures,
  BundleSummary,
  FailureRow,
} from './bundleWriter';
import { buildJobWithSkips } from './jobSpec';
import { validateRecords } from './recordValidation';
import { locateBinary, runProver, ProverEvent } from './spawnProver';
import { formatHumanReport, runVerify } from './verify';
import { formatInitReport, runInit } from './init';
import {
  buildDryRunReport,
  formatDryRunReport,
  problemsFromProver,
  problemsFromSkipped,
  problemsFromValidation,
} from './dryRun';
import { epochDaysToIsoDate } from './dates';
import { publicKeyHexFromSigningKey } from './keys';
import { describeListVersion, loadListRegistry, loadRevocations, loadRootHistory } from './registry';
import { describeDescriptor, resolveDescriptor } from './descriptors';
import {
  clearInputFolder,
  ensureDirectories,
  getInputFiles,
  outputDir,
  readInputFile,
} from './utils';

const program = new Command();

program
  .name('trusset-kyc')
  .description('KYC zk-STARK hashing tool for Trusset tokenization infrastructure')
  .version('3.0.0');

/** Print an error the way every command in this CLI should: cause, then fix. */
function fail(json: boolean | undefined, err: unknown, exitCode = 1): never {
  const message = (err as Error).message ?? String(err);
  if (json) {
    console.log(JSON.stringify({ error: message }));
  } else {
    console.error('');
    for (const line of message.split('\n')) console.error(line);
    console.error('');
  }
  process.exit(exitCode);
}

/**
 * The operator's ed25519 public key, derived from the configured signing key.
 * Returns undefined when the key is not loaded, which is the case during a dry
 * run.
 */
function publicKeyOrUndefined(rc: ResolvedConfig): string | undefined {
  const signing = process.env[rc.signingKeyEnv];
  return signing ? publicKeyHexFromSigningKey(signing) : undefined;
}

// ============================= init =============================

program
  .command('init')
  .description('Generate keys, write config.json, validate the environment, report what is missing')
  .option('--issuer-name <name>', 'Institution legal name recorded in every manifest')
  .option('--issuer-scheme <scheme>', 'Identifier scheme: LEI, BIC, FCA_FRN, BAFIN_ID, CRD_ID, INTERNAL')
  .option('--issuer-identifier <id>', 'Identifier under that scheme')
  .option('--issuer-jurisdiction <cc>', 'Supervising jurisdiction, ISO 3166-1 alpha-2')
  .option('--key-id <label>', 'Stable label for the signing key (default: issuing-YYYY-MM)')
  .option('--force', 'Replace an existing config.json and key file')
  .option('--non-interactive', 'Never prompt; fail if anything required is missing')
  .option('--json', 'Emit the report as JSON')
  .action(async (options) => {
    try {
      const report = await runInit({
        issuerName: options.issuerName,
        issuerScheme: options.issuerScheme,
        issuerIdentifier: options.issuerIdentifier,
        issuerJurisdiction: options.issuerJurisdiction,
        keyId: options.keyId,
        force: options.force,
        nonInteractive: options.nonInteractive,
        json: options.json,
      });
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
      } else {
        console.log(formatInitReport(report));
      }
      process.exit(report.ready ? 0 : 1);
    } catch (err) {
      fail(options.json, err);
    }
  });

// ============================= hash (default) =============================

program
  .command('hash', { isDefault: true })
  .description('Process /input, prove each subject, write bundles to /output')
  .option('--raw', 'Omit the index column from the batched CSV')
  .option('--skip-proofs', 'Development mode: emit zero-byte proofs, mark manifest mode:"stub"')
  .option('--no-deterministic', 'Allow OS randomness for per-subject keys (debugging)')
  .option('--dry-run', 'Validate the whole batch and report every problem; write nothing')
  .option(
    '--dev-unpinned-epoch',
    'Development only: allow epochDaysSource "utc_today". Bundles built this way cannot be reproduced and are stamped unpinnedEpoch',
  )
  .option('--json', 'Emit structured JSON to stdout instead of human progress')
  .action(async (options) => {
    try {
      const rc = loadConfig({ allowUnpinnedEpoch: !!options.devUnpinnedEpoch });
      ensureDirectories();
      const files = getInputFiles();
      if (files.length === 0) {
        printOrJson(
          options.json,
          'No input files found.\n  Fix: place .json or .csv records in input/ — see README.md for the schema.',
        );
        return;
      }

      const allRecords = [];
      for (const f of files) {
        for (const r of readInputFile(f)) allRecords.push(r);
      }
      if (allRecords.length === 0) {
        printOrJson(options.json, 'Input files contain no records.');
        return;
      }

      const validation = validateRecords(allRecords, rc.raw, rc.evidenceDateField);

      // ---------------------------- dry run ----------------------------
      if (options.dryRun) {
        const built = buildJobWithSkips(validation.valid, rc, outputDir(), {
          skipProofs: true,
          deterministic: options.deterministic,
          dryRun: true,
          publicKeyHex: publicKeyOrUndefined(rc),
        });
        const problems = [
          ...problemsFromValidation(validation.failed),
          ...problemsFromSkipped(built.skipped),
        ];
        if (built.job.subjects.length > 0) {
          const result = await runProver(built.job, rc, {});
          problems.push(...problemsFromProver(result.events));
        }
        const report = buildDryRunReport(rc, allRecords.length, problems);
        if (options.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatDryRunReport(report));
        }
        process.exit(problems.length === 0 ? 0 : 2);
      }

      // ---------------------------- real run ----------------------------
      const publicKeyHex = publicKeyOrUndefined(rc);
      if (rc.manifestVersion === '3.0.0' && !publicKeyHex) {
        throw new Error(
          [
            `Environment variable ${rc.signingKeyEnv} is not set, so the issuer's public key could not be derived.`,
            '  A v3 manifest records the key its signature should be checked against.',
            '  Fix: set -a && . ./.trusset/keys.env && set +a',
          ].join('\n'),
        );
      }

      const validationFailures = failuresFromValidation(validation.failed);
      if (!options.json) {
        for (const f of validationFailures) {
          console.log(`  ✘  ${f.walletAddress || '<row ?>'}  [${f.errorCode}] ${f.message}`);
        }
      }

      let successes: BundleSummary[] = [];
      let proverFailures: FailureRow[] = [];
      let jobFailures: FailureRow[] = [];

      if (validation.valid.length > 0) {
        const built = buildJobWithSkips(validation.valid, rc, outputDir(), {
          skipProofs: !!options.skipProofs,
          deterministic: options.deterministic,
          publicKeyHex,
        });
        const job = built.job;
        jobFailures = built.skipped.map((s) => ({
          walletAddress: s.walletAddress,
          stage: 'validation' as const,
          errorCode: s.errorCode,
          message: s.message,
        }));
        if (!options.json) {
          for (const f of jobFailures) {
            console.log(`  ✘  ${f.walletAddress}  [${f.errorCode}] ${f.message}`);
          }
        }
        if (job.subjects.length === 0) {
          const allFailures = [...validationFailures, ...jobFailures];
          const failuresPath = writeFailures(allFailures);
          if (options.json) {
            console.log(
              JSON.stringify({
                ok: 0,
                failed: allFailures.length,
                validationFailed: allFailures.length,
                proverFailed: 0,
                indexPath: '',
                failuresPath,
                successes: [],
              }),
            );
          } else {
            console.log('No valid records to send to the prover; all rows quarantined.');
            if (failuresPath) console.log(`Failures:  ${failuresPath} (${allFailures.length})`);
          }
          process.exit(1);
        }

        if (!options.json) {
          console.log(
            `Batch as-of date ${epochDaysToIsoDate(rc.epochDays)} (epoch day ${rc.epochDays}), manifest ${rc.manifestVersion}.`,
          );
        }

        const result = await runProver(job, rc, {
          onEvent: (e: ProverEvent) => {
            if (!options.json) {
              switch (e.event) {
                case 'start':
                  console.log(`Processing ${e.subjects} subject(s)…`);
                  break;
                case 'subject_start':
                  console.log(`  ⏳ ${e.subject_id}`);
                  break;
                case 'subject_done':
                  console.log(`  ✔  ${e.subject_id}  →  ${e.bundle_path}`);
                  break;
                case 'subject_failed':
                  console.log(`  ✘  ${e.subject_id}  [${e.error_code}] ${e.message}`);
                  break;
              }
            }
            if (e.event === 'subject_done') {
              successes.push({
                walletAddress: e.subject_id,
                bundlePath: e.bundle_path,
                kycHash: readKycHashFromBundle(e.bundle_path),
              });
            }
          },
        });
        proverFailures = failuresFromProver(result.events);
        if (!result.done && successes.length === 0) {
          throw new Error(
            `The prover exited with code ${result.exitCode} without completing the batch.\n  Fix: re-run with --dry-run to see the per-leaf problems, and check the [prover] lines above for a fatal configuration error.`,
          );
        }
      } else if (!options.json) {
        console.log('No valid records to send to the prover; all rows quarantined.');
      }

      const indexRows = buildIndexRows(
        validation.valid,
        successes,
        !!options.raw,
        rc.raw.output.includeIndex,
      );
      const indexPath = writeBatchedIndex(indexRows, rc, !!options.raw);
      const allFailures = [...validationFailures, ...jobFailures, ...proverFailures];
      const failuresPath = writeFailures(allFailures);

      if (rc.raw.security.clearInputAfterProcessing) {
        clearInputFolder();
      }

      if (options.json) {
        console.log(
          JSON.stringify({
            ok: successes.length,
            failed: allFailures.length,
            validationFailed: validationFailures.length,
            proverFailed: proverFailures.length,
            epochDays: rc.epochDays,
            asOfDate: epochDaysToIsoDate(rc.epochDays),
            manifestVersion: rc.manifestVersion,
            indexPath,
            failuresPath,
            successes,
          }),
        );
      } else {
        if (indexPath) console.log(`Index CSV: ${indexPath}`);
        if (failuresPath) console.log(`Failures:  ${failuresPath} (${allFailures.length})`);
        if (successes.length > 0 && publicKeyHex) {
          console.log('');
          console.log('Next: record each published root so as-of checks resolve offline —');
          console.log(
            `  npm run anchor -- --bundle output/<wallet> --chain-id <id> --block <n> --block-time <unix>`,
          );
          console.log('Then archive the batch for long-term verification —');
          console.log(`  npm run archive -- --output <name>.tka --all output`);
        }
      }

      const totalAttempted = validation.valid.length + validation.failed.length;
      if (allFailures.length === 0 && totalAttempted > 0) {
        process.exit(0);
      } else if (successes.length > 0) {
        process.exit(2);
      } else {
        process.exit(1);
      }
    } catch (err) {
      fail(options.json, err);
    }
  });

// ============================= verify =============================

program
  .command('verify <wallet>')
  .description('Verify a per-subject bundle, optionally as of a past block or date')
  .option('--public-key <hex>', 'Operator ed25519 public key (32 bytes hex)')
  .option('--root <hex>', 'kycHash read from chain (0x + 64 hex)')
  .option('--as-of-block <n>', 'Evaluate entitlement at this block height')
  .option('--chain-id <n>', 'Chain the block is on (required with --as-of-block)')
  .option('--as-of-date <date>', 'Evaluate entitlement on YYYY-MM-DD')
  .option(
    '--now <date>',
    "Treat YYYY-MM-DD as today when evaluating validity windows (default: the system clock)",
  )
  .option('--archive <file>', 'Verify from an archive instead of output/<wallet>')
  .option('--strict', 'No-op (strict mode is the default since Stage 18)')
  .option('--accept-stub', 'Accept bundles with mode == "stub"')
  .option('--json', 'Emit JSON report')
  .action(async (wallet: string, options) => {
    try {
      if (!options.publicKey && !options.root) {
        throw new Error(
          [
            'At least one anchor is required.',
            '  --root <0x64-hex>     the kycHash you read from chain; it already authenticates the bundle',
            '  --public-key <hex>    the operator key, for offline bundles whose root you cannot look up',
            '  A bundle verified against neither proves only internal self-consistency, which anyone who',
            '  rewrote the whole bundle could also produce.',
            '  Your own key is printed by `npm run show`.',
          ].join('\n'),
        );
      }
      const bundlePath = options.archive ? undefined : path.join(outputDir(), wallet);
      const result = await runVerify({
        bundlePath,
        archivePath: options.archive,
        subject: options.archive ? wallet : undefined,
        publicKeyHex: options.publicKey,
        rootHex: options.root,
        acceptStub: options.acceptStub,
        asOfBlock: options.asOfBlock,
        chainId: options.chainId,
        asOfDate: options.asOfDate,
        now: options.now,
        registryDir: loadRegistryDirQuietly(),
      });
      if (options.json) {
        if (result.report) console.log(JSON.stringify(result.report, null, 2));
        else console.log(JSON.stringify({ error: 'no report', stderr: result.stderr }));
      } else {
        if (result.report) console.log(formatHumanReport(result.report, bundlePath ?? options.archive));
        else process.stdout.write(result.humanOutput);
        if (result.stderr) process.stderr.write(result.stderr);
      }
      process.exit(result.exitCode);
    } catch (err) {
      fail(options.json, err);
    }
  });

// ============================= list-version =============================

program
  .command('list-version')
  .description('Record a new authoritative version of an allowlist in the signed registry')
  .requiredOption('--list-id <id>', 'Logical list identifier, e.g. country_allowlist')
  .requiredOption('--source <file>', 'Plain-text source, one entry per line')
  .option('--effective-date <date>', 'YYYY-MM-DD this version becomes authoritative (default: today)')
  .option('--note <text>', 'Why the list changed; retained in the record')
  .option('--allow-duplicates', 'Dedupe silently instead of failing on repeats')
  .action((options) => {
    const args = ['list-version', '--list-id', options.listId, '--source', options.source];
    if (options.effectiveDate) args.push('--effective-date', options.effectiveDate);
    if (options.note) args.push('--note', options.note);
    if (options.allowDuplicates) args.push('--allow-duplicates');
    args.push('--registry', loadRegistryDirQuietly());
    runNative('trusset-registry', args);
  });

// ============================= anchor =============================

program
  .command('anchor')
  .description("Record that a bundle's kycHash was published on chain, so as-of checks resolve offline")
  .requiredOption('--bundle <dir>', 'Bundle directory the root came from')
  .requiredOption('--chain-id <n>', 'EVM chain id the root was published to')
  .requiredOption('--block <n>', 'Block height of the publishing transaction')
  .requiredOption('--block-time <unix>', 'Block timestamp, unix seconds')
  .option('--tx <hash>', 'Transaction hash, recorded verbatim')
  .action((options) => {
    const args = [
      'anchor',
      '--bundle',
      options.bundle,
      '--chain-id',
      String(options.chainId),
      '--block',
      String(options.block),
      '--block-time',
      String(options.blockTime),
    ];
    if (options.tx) args.push('--tx', options.tx);
    args.push('--registry', loadRegistryDirQuietly());
    runNative('trusset-registry', args);
  });

// ============================= revoke =============================

program
  .command('revoke')
  .description('Record that a claim lapsed, or that it was never valid')
  .requiredOption('--bundle <dir>', 'Bundle directory being revoked')
  .requiredOption('--effect <effect>', 'lapsed | void_ab_initio')
  .requiredOption('--reason <code>', 'Short machine-readable reason, e.g. DOC_EXPIRED')
  .option('--leaf <name>', 'Leaf to revoke (default: every leaf in the bundle)')
  .option('--effective-date <date>', 'YYYY-MM-DD the claim stopped holding (lapsed only)')
  .option('--note <text>', 'Free text for the audit trail')
  .action((options) => {
    const args = [
      'revoke',
      '--bundle',
      options.bundle,
      '--effect',
      options.effect,
      '--reason',
      options.reason,
    ];
    if (options.leaf) args.push('--leaf', options.leaf);
    if (options.effectiveDate) args.push('--effective-date', options.effectiveDate);
    if (options.note) args.push('--note', options.note);
    args.push('--registry', loadRegistryDirQuietly());
    runNative('trusset-registry', args);
  });

// ============================= archive =============================

program
  .command('archive')
  .description('Produce one self-contained, integrity-checked file that verifies without this machine')
  .requiredOption('--output <file>', 'Archive path to write, e.g. batch-2026Q3.tka')
  .option('--all <dir>', 'Every bundle directory under <dir>')
  .option('--bundle <dir...>', 'Specific bundle directories')
  .option('--archive-id <label>', 'Operator label for the batch')
  .option('--include-secrets', 'Embed each bundle secrets.enc (operator-private; off by default)')
  .option('--inspect', 'Read an existing archive instead of building one')
  .action((options) => {
    if (options.inspect) {
      runNative('trusset-archive', ['inspect', '--archive', options.output]);
      return;
    }
    const args = ['build', '--output', options.output];
    for (const b of options.bundle ?? []) args.push('--bundle', b);
    if (options.all) args.push('--all', options.all);
    if (options.archiveId) args.push('--archive-id', options.archiveId);
    if (options.includeSecrets) args.push('--include-secrets');
    args.push('--registry', loadRegistryDirQuietly());
    runNative('trusset-archive', args);
  });

// ============================= decrypt =============================

program
  .command('decrypt')
  .description('[not implemented in TS] Decrypt secrets.enc, re-prove, recompute root, compare')
  .action(() => {
    console.error(
      [
        'npm run decrypt is not implemented in the TypeScript CLI.',
        '  The round-trip it would perform is exercised by prover/tests/end_to_end.rs.',
        '  Fix: to self-audit a bundle today, re-run `npm start` over the original records with the',
        '       same pinned epochDaysSource and master key, and compare the bundle byte for byte.',
      ].join('\n'),
    );
    process.exit(70);
  });

// ============================= show =============================

program
  .command('show')
  .description('Print resolved config: predicates, descriptors, list versions, registries, and your public key')
  .option('--json', 'Emit JSON instead of human-readable')
  .action((options: { json?: boolean }) => {
    try {
      const rc = loadConfig({ allowUnpinnedEpoch: true });
      const publicKeyHex = publicKeyOrUndefined(rc);
      if (options.json) {
        console.log(
          JSON.stringify(
            {
              manifestVersion: rc.manifestVersion,
              issuer: rc.issuer,
              publicKey: publicKeyHex ?? null,
              predicates: rc.predicates,
              tiers: rc.tiers,
              lists: Object.fromEntries(
                Object.entries(rc.lists).map(([id, l]) => [
                  id,
                  {
                    root: l.root,
                    depth: l.depth,
                    sourceSha256: l.sourceSha256,
                    version: l.version ?? null,
                    contentHash: l.contentHash ?? null,
                  },
                ]),
              ),
              masterKeyEnv: rc.masterKeyEnv,
              signingKeyEnv: rc.signingKeyEnv,
              epochDaysSource: rc.epochDaysSource,
              epochDays: rc.epochDays,
              asOfDate: epochDaysToIsoDate(rc.epochDays),
              unpinnedEpoch: rc.unpinnedEpoch,
              registryDir: rc.registryDir,
              deterministic: rc.deterministic,
              configHash: rc.configHashHex,
            },
            null,
            2,
          ),
        );
      } else {
        console.log(describeConfig(rc));
        console.log('');
        console.log('  Operator public key:');
        console.log(
          publicKeyHex
            ? `    ${publicKeyHex}`
            : `    (unavailable — ${rc.signingKeyEnv} is not set; run: set -a && . ./.trusset/keys.env && set +a)`,
        );
        console.log('');
        console.log('  Claim descriptors:');
        for (const inst of rc.instances) {
          if (!rc.issuer) break;
          try {
            const d = resolveDescriptor(inst.leafName, inst.spec, rc.claims?.defaults, rc.issuer);
            console.log(`    ${inst.leafName.padEnd(24)} ${describeDescriptor(d)}`);
          } catch (e) {
            console.log(`    ${inst.leafName.padEnd(24)} [not resolvable] ${(e as Error).message.split('\n')[0]}`);
          }
        }
        console.log('');
        console.log(`  Registry (${rc.registryDir}):`);
        let sawList = false;
        for (const listId of Object.keys(rc.lists)) {
          const reg = loadListRegistry(rc.registryDir, listId);
          if (!reg) continue;
          sawList = true;
          console.log(`    ${listId}`);
          for (const v of reg.versions) console.log(`      ${describeListVersion(v)}`);
        }
        if (!sawList) console.log('    no list registries recorded');
        const history = loadRootHistory(rc.registryDir);
        console.log(`    root anchors: ${history.entries.length}`);
        const revocations = loadRevocations(rc.registryDir);
        console.log(`    revocations:  ${revocations.entries.length}`);
      }
    } catch (err) {
      fail(options.json, err);
    }
  });

ensureDirectories();
program.parse();

function printOrJson(json: boolean | undefined, message: string): void {
  if (json) {
    console.log(JSON.stringify({ message }));
  } else {
    console.log(message);
  }
}

/**
 * Read `security.registryDir` without failing the command when config.json is
 * absent or incomplete — the registry commands are useful before the config is
 * finished, and a missing config is not a reason to refuse to record a list.
 */
function loadRegistryDirQuietly(): string {
  try {
    return loadConfig({ allowUnpinnedEpoch: true }).registryDir;
  } catch {
    return path.join(process.cwd(), 'config', 'registry');
  }
}

/** Run a workspace binary, passing its output and exit code straight through. */
function runNative(name: string, args: string[]): never {
  const binary = locateBinary(name);
  const result = spawnSync(binary, args, { stdio: 'inherit', env: process.env });
  if (result.error) {
    console.error('');
    console.error(`Could not run ${name}: ${result.error.message}`);
    console.error('  Fix: run `npm run build` to compile the workspace binaries.');
    console.error('');
    process.exit(1);
  }
  process.exit(result.status ?? 1);
}
