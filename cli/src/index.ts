// CLI entrypoint. Preserves the v1/v2 verbs (`hash`, `decrypt`, `verify`,
// `show`), the v3 ones (`init`, `list-version`, `anchor`, `revoke`,
// `archive`), and adds the v3.1 ones: `issue` and `key`. Each command
// supports `--json` for machine-readable output.

import { Command } from 'commander';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { describeConfig, isV31, isV3Family, loadConfig, ResolvedConfig } from './config';
import {
  checkPassphraseStrength,
  childEnvForStdinKeys,
  decryptKeyStore,
  DEFAULT_KEY_FILE,
  encryptKeyStore,
  generateOperatorKeys,
  keychainLoad,
  keychainStore,
  KEYCHAIN_ACCOUNT,
  KEYCHAIN_SERVICE,
  keyFilePath,
  keyLine,
  loadOperatorKeys,
  LoadKeysContext,
  OperatorKeys,
  peekPublicKey,
  readKeyStoreFile,
  readPassphrase,
  writeKeyStoreFile,
} from './keystore';
import { compareAttestation, keccakHex, readHub, setAttesterProfileCalldata } from './chain';
import { normalizeKeyHex } from './keys';
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
import { VerifyReport } from './verify';
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
  .version('3.1.0');

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
 * The operator's ed25519 public key, without unlocking anything: from the key
 * file's header, or from the signing key in the environment. Undefined for the
 * keychain, which has to be read, and when nothing is configured.
 */
function publicKeyOrUndefined(rc: ResolvedConfig): string | undefined {
  try {
    return peekPublicKey(keyContext(rc));
  } catch {
    return undefined;
  }
}

function keyContext(rc: Pick<ResolvedConfig, 'keyStore' | 'masterKeyEnv' | 'signingKeyEnv'>): LoadKeysContext {
  return { keyStore: rc.keyStore, masterKeyEnv: rc.masterKeyEnv, signingKeyEnv: rc.signingKeyEnv };
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
  .option('--chain-id <n>', 'v3.1: chain of the IdentityHub the bundles are attested on')
  .option('--hub <address>', 'v3.1: IdentityHub address')
  .option('--attester <address>', 'v3.1: the wallet that attests on the hub')
  .option('--hub-key-id <n>', 'v3.1: the hub key id of this operator key (default 1)')
  .option('--key-store <kind>', 'file (encrypted, default for v3.1), keychain, or env (plaintext keys.env, CI)')
  .option('--force', 'Replace an existing config.json and key file')
  .option('--non-interactive', 'Never prompt; fail if anything required is missing')
  .option('--json', 'Emit the report as JSON')
  .action(async (options) => {
    try {
      if (options.keyStore && !['file', 'keychain', 'env'].includes(options.keyStore)) {
        throw new Error('--key-store must be file, keychain, or env');
      }
      const report = await runInit({
        chainId: options.chainId !== undefined ? Number(options.chainId) : undefined,
        hub: options.hub,
        attester: options.attester,
        hubKeyId: options.hubKeyId !== undefined ? Number(options.hubKeyId) : undefined,
        keyStore: options.keyStore,
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

const batchOptions = (cmd: Command): Command =>
  cmd
    .option('--raw', 'Omit the index column from the batched CSV')
    .option('--skip-proofs', 'Development mode: emit zero-byte proofs, mark manifest mode:"stub"')
    .option('--no-deterministic', 'Allow OS randomness for per-subject keys (debugging)')
    .option('--dry-run', 'Validate the whole batch and report every problem; write nothing')
    .option(
      '--dev-unpinned-epoch',
      'Development only: allow epochDaysSource "utc_today". Bundles built this way cannot be reproduced and are stamped unpinnedEpoch',
    )
    .option('--json', 'Emit structured JSON to stdout instead of human progress');

batchOptions(
  program
    .command('hash', { isDefault: true })
    .description('Process /input, prove each subject, write bundles to /output'),
).action(async (options) => runBatch(options, 'hash'));

batchOptions(
  program
    .command('issue')
    .description(
      'v3.1: prove /input into bundles bound to your hub attestation, and write attestation.json for each subject',
    ),
).action(async (options) => runBatch(options, 'issue'));

interface BatchOptions {
  raw?: boolean;
  skipProofs?: boolean;
  deterministic?: boolean;
  dryRun?: boolean;
  devUnpinnedEpoch?: boolean;
  json?: boolean;
}

async function runBatch(options: BatchOptions, mode: 'hash' | 'issue'): Promise<void> {
  try {
    const rc = loadConfig({ allowUnpinnedEpoch: !!options.devUnpinnedEpoch });
    if (mode === 'issue' && !isV31(rc.manifestVersion)) {
      throw new Error(
        [
          `issue writes 3.1.0 bundles bound to a hub attestation; config.json emits ${rc.manifestVersion}.`,
          '  Fix: set manifest.version to "3.1.0" and add the chain block (chainId, hub, attester, keyId).',
          '  See docs/MIGRATION_V30_TO_V31.md. To keep producing the old shape, use `npm start`.',
        ].join('\n'),
      );
    }
    ensureDirectories();
    const files = getInputFiles();
    if (files.length === 0) {
      printOrJson(
        options.json,
        'No input files found.\n  Fix: place .json or .csv records in input/. See README.md for the schema.',
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
    const loaded = await loadOperatorKeys(keyContext(rc));
    const publicKeyHex = loaded.publicKey;
    if (isV3Family(rc.manifestVersion) && !publicKeyHex) {
      throw new Error(
        [
          'No operator signing key, so the issuer public key could not be derived.',
          '  A v3 manifest records the key its signature should be checked against.',
          '  Fix: point security.keyStore in config.json at your key file or the keychain',
          '       (`npm run key -- create`), or for CI set ' + rc.signingKeyEnv + '.',
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
        keys: loaded.keys,
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
      isV31(rc.manifestVersion),
    );
    const attestationPaths = isV31(rc.manifestVersion)
      ? successes
          .map((s) => path.join(s.bundlePath, 'attestation.json'))
          .filter((p) => fs.existsSync(p))
      : [];
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
          attestations: attestationPaths,
        }),
      );
    } else {
      if (indexPath) console.log(`Index CSV: ${indexPath}`);
      if (failuresPath) console.log(`Failures:  ${failuresPath} (${allFailures.length})`);
      if (attestationPaths.length > 0) {
        console.log(`Attestations (${attestationPaths.length}): upload each attestation.json to the issuer app to build the attest calldata.`);
        for (const p of attestationPaths) console.log(`  ${p}`);
      }
      if (successes.length > 0 && publicKeyHex) {
        console.log('');
        console.log('Next: record each published root so as-of checks resolve offline:');
        console.log(
          `  npm run anchor -- --bundle output/<wallet> --chain-id <id> --block <n> --block-time <unix>`,
        );
        console.log('Then archive the batch for long-term verification:');
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
}

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
  .option(
    '--rpc-url <url>',
    'v3.1: read the hub over this JSON-RPC endpoint (read-only eth_call) for the attester key and the attestation, and compare them with the bundle',
  )
  .option('--strict', 'No-op (strict mode is the default since Stage 18)')
  .option('--accept-stub', 'Accept bundles with mode == "stub"')
  .option('--json', 'Emit JSON report')
  .action(async (wallet: string, options) => {
    try {
      if (options.rpcUrl) {
        await verifyAgainstHub(wallet, options);
        return;
      }
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

/**
 * `verify --rpc-url`: read the attester's published operator key and the hub
 * attestation for this subject, use them as the anchors, and compare the hub
 * record with what the bundle proves. Only eth_chainId and eth_call are sent.
 */
async function verifyAgainstHub(
  wallet: string,
  options: { rpcUrl: string; publicKey?: string; root?: string; json?: boolean; acceptStub?: boolean; now?: string },
): Promise<void> {
  const bundlePath = path.join(outputDir(), wallet);
  const headerFile = path.join(bundlePath, 'header.json');
  if (!fs.existsSync(headerFile)) {
    throw new Error(
      `${headerFile} not found. --rpc-url checks 3.1.0 bundles, which carry a signed header naming their hub attestation.`,
    );
  }
  const header = JSON.parse(fs.readFileSync(headerFile, 'utf-8')) as {
    wallet: string;
    attester: string;
    chainId: number;
    hub: string;
    keyId: number;
  };
  const hub = await readHub({
    rpcUrl: options.rpcUrl,
    chainId: header.chainId,
    hub: header.hub,
    attester: header.attester,
    keyId: header.keyId,
    subject: header.wallet,
  });
  const problems: string[] = [];
  const chainKey = hub.operatorKey.replace(/^0x/, '');
  if (/^0+$/.test(chainKey)) {
    problems.push(`the hub has no operator key ${header.keyId} for attester ${header.attester}`);
  }
  if (options.publicKey && normalizeKeyHex(options.publicKey, '--public-key') !== chainKey) {
    problems.push('--public-key differs from the operator key the attester published on the hub');
  }
  if (hub.attestation.status === 'NONE') {
    problems.push(`the hub holds no attestation by ${header.attester} for ${header.wallet}`);
  }
  const result = await runVerify({
    bundlePath,
    publicKeyHex: options.publicKey ?? chainKey,
    rootHex: options.root ?? (hub.attestation.status === 'NONE' ? undefined : hub.attestation.root),
    acceptStub: options.acceptStub,
    now: options.now,
    registryDir: loadRegistryDirQuietly(),
  });
  const expected = result.report?.header?.attestation;
  if (!expected) {
    problems.push('the bundle verifier derived no attestation from this bundle');
  } else {
    problems.push(...compareAttestation(hub.attestation, expected));
  }
  const onChain = {
    rpcChainId: hub.chainId,
    hub: header.hub,
    attester: header.attester,
    keyId: header.keyId,
    operatorKey: hub.operatorKey,
    attestation: hub.attestation,
    matches: problems.length === 0,
    problems,
  };
  if (options.json) {
    console.log(JSON.stringify({ ...(result.report ?? {}), onChain }, null, 2));
  } else {
    if (result.report) console.log(formatHumanReport(result.report, bundlePath));
    else process.stdout.write(result.humanOutput);
    if (result.stderr) process.stderr.write(result.stderr);
    console.log('');
    console.log(`On chain (read only, chain ${hub.chainId}, hub ${header.hub}):`);
    console.log(`  operator key ${header.keyId}:  ${hub.operatorKey}`);
    console.log(
      `  attestation:      ${hub.attestation.status}, class ${hub.attestation.investorClass}, predicates ${hub.attestation.predicates}, root ${hub.attestation.root}`,
    );
    if (problems.length === 0) console.log('  matches bundle:   YES');
    else for (const p of problems) console.log(`  mismatch:         ${p}`);
  }
  const code = result.exitCode !== 0 ? result.exitCode : problems.length > 0 ? 2 : 0;
  process.exit(code);
}

// ============================= key =============================

const key = program
  .command('key')
  .description('Operator keys: create, encrypt existing keys, show the public key and keyId');

key
  .command('create')
  .description('Generate a new operator signing key and master key, encrypted at rest')
  .option('--key-file <path>', `Encrypted key file to write (default: ${DEFAULT_KEY_FILE})`)
  .option('--keychain', 'Store in the macOS keychain instead of a file')
  .option('--service <name>', `Keychain service (default: ${KEYCHAIN_SERVICE})`)
  .option('--account <name>', `Keychain account (default: ${KEYCHAIN_ACCOUNT})`)
  .option('--force', 'Replace an existing key file')
  .option('--json', 'Emit JSON')
  .action(async (options) => {
    try {
      const keys = generateOperatorKeys();
      const location = await storeKeys(keys, options);
      printKeyReport(keys, location, options.json);
    } catch (err) {
      fail(options.json, err);
    }
  });

key
  .command('encrypt')
  .description('Move existing keys from the environment or .trusset/keys.env into an encrypted key file or the keychain')
  .option('--from <file>', 'A keys.env file to read (default: the environment)')
  .option('--key-file <path>', `Encrypted key file to write (default: ${DEFAULT_KEY_FILE})`)
  .option('--keychain', 'Store in the macOS keychain instead of a file')
  .option('--service <name>', `Keychain service (default: ${KEYCHAIN_SERVICE})`)
  .option('--account <name>', `Keychain account (default: ${KEYCHAIN_ACCOUNT})`)
  .option('--force', 'Replace an existing key file')
  .option('--json', 'Emit JSON')
  .action(async (options) => {
    try {
      const source = options.from ? parseEnvFile(options.from) : process.env;
      const signing = source.TRUSSET_KYC_SIGNING_KEY;
      const master = source.TRUSSET_KYC_MASTER_KEY;
      if (!signing || !master) {
        throw new Error(
          'TRUSSET_KYC_SIGNING_KEY and TRUSSET_KYC_MASTER_KEY are both needed.\n  Fix: --from .trusset/keys.env, or export them for this one command.',
        );
      }
      const keys: OperatorKeys = {
        signingKey: normalizeKeyHex(signing, 'TRUSSET_KYC_SIGNING_KEY'),
        masterKey: normalizeKeyHex(master, 'TRUSSET_KYC_MASTER_KEY'),
      };
      const location = await storeKeys(keys, options);
      printKeyReport(keys, location, options.json);
      if (!options.json && options.from) {
        console.log('');
        console.log(`The plaintext ${options.from} is no longer needed. Delete it once you have checked that`);
        console.log('`npm run key -- show --verify` unlocks the new store.');
      }
    } catch (err) {
      fail(options.json, err);
    }
  });

key
  .command('show')
  .description('Print the operator public key, the hub keyId, and the setAttesterProfile calldata')
  .option('--verify', 'Unlock the store and check it holds the key it names')
  .option('--lei-hash <hex>', 'bytes32 for the hub leiHash (default: keccak256 of the issuer LEI)')
  .option('--metadata-uri <uri>', 'Attester metadata URI recorded on the hub', '')
  .option('--json', 'Emit JSON')
  .action(async (options) => {
    try {
      const rc = loadConfig({ allowUnpinnedEpoch: true });
      const ctx = keyContext(rc);
      let publicKey = peekPublicKey(ctx);
      let location = describeKeyStore(rc);
      if (options.verify || !publicKey) {
        const loaded = await loadOperatorKeys(ctx);
        if (!loaded.keys.signingKey) throw new Error('No signing key found in ' + location + '.');
        publicKey = publicKeyHexFromSigningKey(loaded.keys.signingKey);
        if (loaded.publicKey && loaded.publicKey !== publicKey) {
          throw new Error('The key store names a different public key than the key it holds.');
        }
        location = loaded.location ?? location;
      }
      const lei =
        options.leiHash ??
        (rc.issuer?.identifierScheme === 'LEI' ? keccakHex(rc.issuer.identifier) : '0x' + '00'.repeat(32));
      const calldata = setAttesterProfileCalldata('0x' + publicKey, lei, options.metadataUri ?? '');
      const report = {
        publicKey,
        keyId: rc.chain?.keyId ?? null,
        keyStore: location,
        attester: rc.chain?.attester ?? null,
        chainId: rc.chain?.chainId ?? null,
        hub: rc.chain?.hub ?? null,
        setAttesterProfile: { to: rc.chain?.hub ?? null, data: calldata, leiHash: lei, metadataURI: options.metadataUri ?? '' },
      };
      if (options.json) {
        console.log(JSON.stringify(report, null, 2));
        return;
      }
      console.log(`Operator public key:  ${publicKey}`);
      console.log(`Key store:            ${location}`);
      console.log(`Hub keyId:            ${report.keyId ?? '(set chain.keyId in config.json)'}`);
      if (rc.chain) {
        console.log(`Attester:             ${rc.chain.attester} on chain ${rc.chain.chainId}`);
      }
      console.log('');
      console.log('Publish it on the hub by sending this from the attester wallet (this tool never sends it):');
      console.log(`  to:   ${report.setAttesterProfile.to ?? '<IdentityHub address>'}`);
      console.log(`  data: ${calldata}`);
      console.log('');
      console.log('The hub assigns keyId = previous keyId + 1 (1 for your first key). Put that number in');
      console.log('chain.keyId. Roots issued under an older keyId stay verifiable against operatorKeyAt(attester, keyId).');
    } catch (err) {
      fail(options.json, err);
    }
  });

function describeKeyStore(rc: ResolvedConfig): string {
  const ks = rc.keyStore;
  if (ks?.type === 'file') return keyFilePath(ks);
  if (ks?.type === 'keychain') return `keychain ${ks.service ?? KEYCHAIN_SERVICE}/${ks.account ?? KEYCHAIN_ACCOUNT}`;
  return `environment (${rc.signingKeyEnv}, ${rc.masterKeyEnv}), for CI only`;
}

async function storeKeys(
  keys: OperatorKeys,
  options: { keyFile?: string; keychain?: boolean; service?: string; account?: string; force?: boolean },
): Promise<string> {
  if (options.keychain) {
    const service = options.service ?? KEYCHAIN_SERVICE;
    const account = options.account ?? KEYCHAIN_ACCOUNT;
    keychainStore(keys, service, account);
    const back = keychainLoad(service, account);
    if (back.signingKey !== keys.signingKey || back.masterKey !== keys.masterKey) {
      throw new Error('The keychain item did not read back as written.');
    }
    return `keychain ${service}/${account}`;
  }
  const file = keyFilePath({ path: options.keyFile ?? DEFAULT_KEY_FILE });
  if (fs.existsSync(file) && !options.force) {
    throw new Error(`${file} already exists. Pass --force to replace it (keep a backup of the old one first).`);
  }
  const passphrase = await readPassphrase(`New passphrase for ${path.relative(process.cwd(), file) || file}: `, true);
  checkPassphraseStrength(passphrase);
  const store = encryptKeyStore(keys, passphrase);
  decryptKeyStore(store, passphrase);
  writeKeyStoreFile(file, store, !!options.force);
  return file;
}

function printKeyReport(keys: OperatorKeys, location: string, json?: boolean): void {
  const publicKey = publicKeyHexFromSigningKey(keys.signingKey);
  const keyStore = location.startsWith('keychain ')
    ? {
        type: 'keychain',
        service: location.split(' ')[1].split('/')[0],
        account: location.split(' ')[1].split('/')[1],
      }
    : { type: 'file', path: path.relative(process.cwd(), location) || location };
  if (json) {
    console.log(JSON.stringify({ publicKey, keyStore }, null, 2));
    return;
  }
  console.log(`Operator public key:  ${publicKey}`);
  console.log(`Stored in:            ${location}`);
  console.log('');
  console.log('Point config.json at it:');
  console.log(`  "security": { ..., "keyStore": ${JSON.stringify(keyStore)} }`);
  console.log('Then publish the key on the hub: `npm run key -- show` prints the setAttesterProfile calldata.');
  console.log('Back up the key store. Without it no bundle can be signed under this key or decrypted.');
}

function parseEnvFile(file: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(file, 'utf-8').split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*"?([^"\s#]*)"?\s*$/.exec(line);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

// ============================= list-version =============================

program
  .command('list-version')
  .description('Record a new authoritative version of an allowlist in the signed registry')
  .requiredOption('--list-id <id>', 'Logical list identifier, e.g. country_allowlist')
  .requiredOption('--source <file>', 'Plain-text source, one entry per line')
  .option('--effective-date <date>', 'YYYY-MM-DD this version becomes authoritative (default: today)')
  .option('--note <text>', 'Why the list changed; retained in the record')
  .option('--allow-duplicates', 'Dedupe silently instead of failing on repeats')
  .action(async (options) => {
    const args = ['list-version', '--list-id', options.listId, '--source', options.source];
    if (options.effectiveDate) args.push('--effective-date', options.effectiveDate);
    if (options.note) args.push('--note', options.note);
    if (options.allowDuplicates) args.push('--allow-duplicates');
    args.push('--registry', loadRegistryDirQuietly());
    await runSignedNative('trusset-registry', args);
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
  .action(async (options) => {
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
    await runSignedNative('trusset-registry', args);
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
  .action(async (options) => {
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
    await runSignedNative('trusset-registry', args);
  });

// ============================= archive =============================

program
  .command('archive')
  .description('Produce one self-contained, integrity-checked file that verifies without this machine')
  .option('--output <file>', 'Archive path to write, e.g. batch-2026Q3.tka')
  .option('--all <dir>', 'Every bundle directory under <dir>')
  .option('--bundle <dir...>', 'Specific bundle directories')
  .option('--archive-id <label>', 'Operator label for the batch')
  .option('--include-secrets', 'Embed each bundle secrets.enc (operator-private; off by default)')
  .option('--inspect [file]', 'Read an existing archive instead of building one')
  .action((options) => {
    if (options.inspect) {
      // `--inspect` takes the path directly, and also accepts the `--output`
      // form so the same file argument works whichever way round it is written.
      const target = typeof options.inspect === 'string' ? options.inspect : options.output;
      if (!target) {
        fail(false, new Error('archive --inspect needs a file: pass it as `--inspect <file>`.'));
      }
      runNative('trusset-archive', ['inspect', '--archive', target]);
      return;
    }
    if (!options.output) {
      fail(
        false,
        new Error(
          'archive needs --output <file>.\n  Fix: npm run archive -- --output batch.tka --all output',
        ),
      );
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
              keyStore: describeKeyStore(rc),
              chain: rc.chain ?? null,
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
            : `    (not shown without unlocking ${describeKeyStore(rc)}; run: npm run key -- show)`,
        );
        console.log(`  Key store:        ${describeKeyStore(rc)}`);
        if (rc.chain) {
          console.log(
            `  Hub attestation:  attester ${rc.chain.attester} on chain ${rc.chain.chainId}, hub ${rc.chain.hub}, keyId ${rc.chain.keyId}`,
          );
        }
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
 * absent or incomplete, the registry commands are useful before the config is
 * finished, and a missing config is not a reason to refuse to record a list.
 */
function loadRegistryDirQuietly(): string {
  try {
    return loadConfig({ allowUnpinnedEpoch: true }).registryDir;
  } catch {
    return path.join(process.cwd(), 'config', 'registry');
  }
}

/**
 * Run a workspace binary that signs registry records. The signing key comes
 * from the configured key store and goes to the binary on its first stdin
 * line; with no key store configured the binary reads the environment (CI).
 */
async function runSignedNative(name: string, args: string[]): Promise<never> {
  let ctx: LoadKeysContext | undefined;
  try {
    ctx = keyContext(loadConfig({ allowUnpinnedEpoch: true }));
  } catch {
    ctx = undefined;
  }
  if (!ctx?.keyStore) runNative(name, args);
  let signingKey: string | undefined;
  try {
    signingKey = (await loadOperatorKeys(ctx)).keys.signingKey;
  } catch (err) {
    fail(false, err);
  }
  const binary = locateBinary(name);
  const result = spawnSync(binary, args, {
    stdio: ['pipe', 'inherit', 'inherit'],
    input: keyLine({ signingKey }),
    env: childEnvForStdinKeys(process.env),
  });
  if (result.error) {
    console.error('');
    console.error(`Could not run ${name}: ${result.error.message}`);
    console.error('  Fix: run `npm run build` to compile the workspace binaries.');
    console.error('');
    process.exit(1);
  }
  process.exit(result.status ?? 1);
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
