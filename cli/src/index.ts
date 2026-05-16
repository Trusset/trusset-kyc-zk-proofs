// CLI entrypoint. Preserves v1 verbs: `hash` (default), `decrypt`, `verify`,
// `show`. Each command supports `--json` for machine-readable output.

import { Command } from 'commander';
import * as path from 'path';
import { describeConfig, loadConfig } from './config';
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
import { buildJob } from './jobSpec';
import { validateRecords } from './recordValidation';
import { runProver, ProverEvent } from './spawnProver';
import { formatHumanReport, runVerify } from './verify';
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
  .version('2.0.0');

// ============================= hash (default) =============================

program
  .command('hash', { isDefault: true })
  .description('Process /input, prove each subject, write bundles to /output')
  .option('--raw', 'Omit the index column from the batched CSV')
  .option('--skip-proofs', 'Stub mode: emit zero-byte proofs, mark manifest mode:"stub" (not yet wired)')
  .option('--isolate', 'Spawn one prover process per subject (debugging)')
  .option('--no-deterministic', 'Allow OS randomness for nonces (debugging)')
  .option('--json', 'Emit structured JSON to stdout instead of human progress')
  .action(async (options: { raw?: boolean; skipProofs?: boolean; isolate?: boolean; deterministic: boolean; json?: boolean }) => {
    try {
      const rc = loadConfig();
      ensureDirectories();
      const files = getInputFiles();
      if (files.length === 0) {
        printOrJson(options.json, 'No input files found. Place .json or .csv files in /input.');
        return;
      }

      const allRecords = [];
      for (const f of files) {
        for (const r of readInputFile(f)) allRecords.push(r);
      }
      if (allRecords.length === 0) {
        printOrJson(options.json, 'No records to process.');
        return;
      }

      const validation = validateRecords(allRecords, rc.raw);
      const validationFailures = failuresFromValidation(validation.failed);

      // Report quarantined rows up front so operators see them even if the
      // prover hangs or crashes mid-batch.
      if (!options.json) {
        for (const f of validationFailures) {
          console.log(
            `  ✘  ${f.walletAddress || `<row ${validation.failed[0]?.rowNum ?? '?'}>`}  [${f.errorCode}] ${f.message}`,
          );
        }
      }

      let successes: BundleSummary[] = [];
      let proverFailures: FailureRow[] = [];

      if (validation.valid.length > 0) {
        const job = buildJob(validation.valid, rc, outputDir(), {
          skipProofs: !!options.skipProofs,
        });
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
                case 'done':
                  console.log(`Done: ${e.ok} ok, ${e.failed} failed.`);
                  break;
                // leaf_proved: skip in human mode; too chatty.
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
      const allFailures = [...validationFailures, ...proverFailures];
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
            indexPath,
            failuresPath,
            successes,
          }),
        );
      } else {
        if (indexPath) console.log(`Index CSV: ${indexPath}`);
        if (failuresPath) console.log(`Failures:  ${failuresPath} (${allFailures.length})`);
      }
      // Exit codes: 0 ok, 2 partial, 1 batch-aborting.
      const totalAttempted = validation.valid.length + validation.failed.length;
      const allFailed = allFailures.length > 0 && successes.length === 0;
      if (allFailures.length === 0 && totalAttempted > 0) {
        process.exit(0);
      } else if (successes.length > 0) {
        process.exit(2);
      } else {
        process.exit(1);
      }
    } catch (err) {
      const e = err as Error;
      if (options.json) {
        console.log(JSON.stringify({ error: e.message }));
      } else {
        console.error('Error:', e.message);
      }
      process.exit(1);
    }
  });

// ============================= verify =============================

program
  .command('verify <wallet>')
  .description('Verify a per-subject bundle in /output against a pinned public key')
  .requiredOption('--public-key <hex>', 'Operator ed25519 public key (32 bytes hex)')
  .option('--strict', 'Reject bundles with mode != "production"')
  .option('--json', 'Emit JSON report')
  .action(async (wallet: string, options: { publicKey: string; strict?: boolean; json?: boolean }) => {
    try {
      const bundlePath = path.join(outputDir(), wallet);
      const result = await runVerify({
        bundlePath,
        publicKeyHex: options.publicKey,
        strict: options.strict,
      });
      if (options.json) {
        if (result.report) console.log(JSON.stringify(result.report, null, 2));
        else console.log(JSON.stringify({ error: 'no report', stderr: result.stderr }));
      } else {
        if (result.report) console.log(formatHumanReport(result.report, bundlePath));
        else process.stdout.write(result.humanOutput);
        if (result.stderr) process.stderr.write(result.stderr);
      }
      process.exit(result.exitCode);
    } catch (err) {
      console.error('Error:', (err as Error).message);
      process.exit(1);
    }
  });

// ============================= decrypt =============================

program
  .command('decrypt')
  .description('[Phase 6B] Decrypt secrets.enc, re-prove, recompute root, compare to kycHash.hex')
  .action(() => {
    console.error(
      'npm run decrypt: not yet implemented in TS. Use the integration tests in prover/tests/end_to_end.rs which exercise the round-trip.',
    );
    process.exit(70); // EX_SOFTWARE
  });

// ============================= show =============================

program
  .command('show')
  .description('Print resolved config: field→circuit mapping, tiers, list roots')
  .option('--json', 'Emit JSON instead of human-readable')
  .action((options: { json?: boolean }) => {
    try {
      const rc = loadConfig();
      if (options.json) {
        console.log(JSON.stringify({
          predicates: rc.predicates,
          tiers: rc.tiers,
          lists: Object.fromEntries(
            Object.entries(rc.lists).map(([id, l]) => [id, { root: l.root, depth: l.depth, sourceSha256: l.sourceSha256 }]),
          ),
          masterKeyEnv: rc.masterKeyEnv,
          signingKeyEnv: rc.signingKeyEnv,
          epochDaysSource: rc.epochDaysSource,
          deterministic: rc.deterministic,
          configHash: rc.configHashHex,
        }, null, 2));
      } else {
        console.log(describeConfig(rc));
      }
    } catch (err) {
      console.error('Error:', (err as Error).message);
      process.exit(1);
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
