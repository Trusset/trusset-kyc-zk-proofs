// `trusset-kyc init` — one command from a clone to a runnable configuration.
//
// Before this, reaching a first valid bundle took sixteen steps, five of them
// documented only in docs/ and one impossible (the README told operators to
// verify with `--public-key <hex>` and the tool emitted that hex nowhere).
// This command does the ones that can be automated, and for the ones that
// cannot it says exactly what is missing and what to run.
//
// Nothing here is destructive: an existing config.json, key file, or list
// registry is reported and left alone unless `--force` is passed.

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { epochDaysToIsoDate, todayEpochDays } from './dates';
import { generateKeyHex, publicKeyHexFromSigningKey } from './keys';
import { loadListRegistry, registryRoot } from './registry';
import { EVIDENCE_CLASSES, IDENTIFIER_SCHEMES } from './types';

export const KEY_FILE = '.trusset/keys.env';

export interface InitOptions {
  issuerName?: string;
  issuerScheme?: string;
  issuerIdentifier?: string;
  issuerJurisdiction?: string;
  keyId?: string;
  force?: boolean;
  json?: boolean;
  /** Do not prompt even when stdin is a TTY; fail on anything missing. */
  nonInteractive?: boolean;
}

export interface CheckResult {
  name: string;
  ok: boolean;
  detail: string;
  /** What to run or change. Present only when `ok` is false. */
  fix?: string;
}

export interface InitReport {
  checks: CheckResult[];
  configPath: string;
  configWritten: boolean;
  keyFilePath: string;
  keysWritten: boolean;
  publicKeyHex?: string;
  registryDir: string;
  listVersionsRecorded: string[];
  ready: boolean;
  nextSteps: string[];
}

// ============================ environment checks ============================

function checkNode(): CheckResult {
  const major = Number(process.versions.node.split('.')[0]);
  return major >= 18
    ? { name: 'Node.js', ok: true, detail: `v${process.versions.node}` }
    : {
        name: 'Node.js',
        ok: false,
        detail: `v${process.versions.node}, but 18 or newer is required`,
        fix: 'install Node.js 18+ from https://nodejs.org and re-run',
      };
}

function which(bin: string): string | null {
  try {
    return execFileSync(process.platform === 'win32' ? 'where' : 'which', [bin], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .split('\n')[0]
      .trim();
  } catch {
    return null;
  }
}

function checkCargo(): CheckResult {
  const found = which('cargo');
  if (!found) {
    return {
      name: 'Rust toolchain',
      ok: false,
      detail: 'cargo not found on PATH',
      fix: 'install Rust from https://rustup.rs — the prover and verifier are built from source, and this tool ships no prebuilt binaries',
    };
  }
  try {
    const version = execFileSync('cargo', ['--version'], { encoding: 'utf-8' }).trim();
    return { name: 'Rust toolchain', ok: true, detail: version };
  } catch {
    return { name: 'Rust toolchain', ok: true, detail: found };
  }
}

function binaryPath(name: string): string | null {
  for (const profile of ['release', 'debug']) {
    const p = path.join(process.cwd(), 'target', profile, name);
    if (fs.existsSync(p)) return p;
  }
  const env = process.env[`TRUSSET_${name.replace(/-/g, '_').toUpperCase()}`];
  if (env && fs.existsSync(env)) return env;
  return null;
}

function checkBinaries(): CheckResult[] {
  const wanted = [
    ['trusset-prover', 'proving'],
    ['trusset-verifier-cli', 'verification'],
    ['trusset-registry', 'list versions, chain anchors, and revocations'],
    ['trusset-archive', 'self-contained archives'],
  ];
  return wanted.map(([bin, purpose]) => {
    const found = binaryPath(bin);
    return found
      ? { name: bin, ok: true, detail: found }
      : {
          name: bin,
          ok: false,
          detail: `not built — needed for ${purpose}`,
          fix: 'run `npm run build` (first build compiles ~130 crates and takes a few minutes)',
        };
  });
}

function checkInputDir(): CheckResult {
  const dir = path.join(process.cwd(), 'input');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.toLowerCase().endsWith('.json') || f.toLowerCase().endsWith('.csv'));
  return files.length > 0
    ? { name: 'input/', ok: true, detail: `${files.length} file(s) ready to process` }
    : {
        name: 'input/',
        ok: false,
        detail: 'empty',
        fix: 'place .json or .csv records in input/ — see the input format in README.md',
      };
}

// ============================== key material ==============================

function writeKeyFile(force: boolean): { written: boolean; masterKey: string; signingKey: string } {
  const file = path.join(process.cwd(), KEY_FILE);
  if (fs.existsSync(file) && !force) {
    const text = fs.readFileSync(file, 'utf-8');
    const master = /TRUSSET_KYC_MASTER_KEY=([0-9a-fA-F]{64})/.exec(text);
    const signing = /TRUSSET_KYC_SIGNING_KEY=([0-9a-fA-F]{64})/.exec(text);
    if (master && signing) {
      return { written: false, masterKey: master[1], signingKey: signing[1] };
    }
    throw new Error(
      `${KEY_FILE} exists but does not contain both keys.\n  Fix: repair it by hand, or re-run with --force to replace it (this invalidates every existing bundle's reproducibility).`,
    );
  }

  const masterKey = generateKeyHex();
  const signingKey = generateKeyHex();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const body = [
    '# Trusset KYC operator keys. Generated by `npm run init`.',
    '#',
    '# These two values are the only thing standing between an auditor and a',
    '# reproducible bundle. Lose the master key and no existing secrets.enc can',
    '# be decrypted and no bundle can be regenerated. Lose the signing key and',
    '# no future bundle can be signed under the same identity.',
    '#',
    '# Back them up where you back up other operator-private material. Do not',
    '# commit this file.',
    '',
    `TRUSSET_KYC_MASTER_KEY=${masterKey}`,
    `TRUSSET_KYC_SIGNING_KEY=${signingKey}`,
    '',
  ].join('\n');
  fs.writeFileSync(file, body, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  ensureGitignored('.trusset/');
  return { written: true, masterKey, signingKey };
}

function ensureGitignored(entry: string): void {
  const gitignore = path.join(process.cwd(), '.gitignore');
  if (!fs.existsSync(gitignore)) return;
  const text = fs.readFileSync(gitignore, 'utf-8');
  if (text.split('\n').some((l) => l.trim() === entry.trim())) return;
  fs.appendFileSync(gitignore, `\n# Operator key material written by \`npm run init\`\n${entry}\n`);
}

// ============================== config writing ==============================

/**
 * A v3 config with descriptors already filled in for the shipped predicates.
 *
 * The descriptors here are starting points that name the right instrument and
 * provision for the common European case; the operator is expected to review
 * them against their own permissions and evidence. Shipping a config with no
 * descriptors would satisfy the schema and defeat the point, and shipping one
 * with placeholder text would produce bundles that assert nothing.
 */
function configTemplate(
  issuer: { name: string; identifierScheme: string; identifier: string; jurisdiction: string; keyId: string },
  epochDays: number,
): unknown {
  return {
    mapping: {
      fields: [
        'firstName',
        'lastName',
        'dateOfBirth',
        'nationality',
        'documentType',
        'documentNumber',
        'documentIssuingCountry',
      ],
      walletAddressField: 'walletAddress',
      countryField: 'country',
      investorTypeField: 'investorType',
      softExpiryDaysField: 'softExpiryDays',
      hardExpiryDaysField: 'hardExpiryDays',
      evidenceDateField: 'evidenceDate',
    },
    claims: {
      defaults: {
        issuingParty: 'self',
        evidenceClass: 'DOCUMENTARY',
        validity: { days: 365, basisAsOfOffsetDays: 0 },
      },
    },
    predicates: {
      dateOfBirth: {
        circuit: 'age_threshold',
        params: { minAgeYears: 18 },
        descriptor: {
          legalBasis: {
            framework: 'NATIONAL',
            reference: 'contractual capacity — age of majority',
            assertion: 'Subject is at or above the age of majority',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 3650 },
      },
      country: {
        circuit: 'set_membership',
        params: { list: 'country_allowlist' },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 9 — high-risk third countries',
            assertion: 'Subject residence is in a jurisdiction on the approved list',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      nationality: {
        circuit: 'set_membership',
        params: { list: 'country_allowlist' },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Subject nationality is in a jurisdiction on the approved list',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      documentIssuingCountry: {
        circuit: 'set_membership',
        params: { list: 'country_allowlist' },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Identity document was issued by a jurisdiction on the approved list',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      investorType: {
        circuit: 'tier_threshold',
        params: { minTier: 'PROFESSIONAL' },
        descriptor: {
          legalBasis: {
            framework: 'MiFID_II',
            reference: 'Annex II Section I — professional clients',
            assertion: 'Subject is categorised at or above professional client',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 730 },
      },
      firstName: {
        circuit: 'commitment_only',
        params: { maxValueBytes: 128 },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Subject given name as recorded at onboarding',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      lastName: {
        circuit: 'commitment_only',
        params: { maxValueBytes: 128 },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Subject family name as recorded at onboarding',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      documentType: {
        circuit: 'commitment_only',
        params: { maxValueBytes: 64 },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Class of identity document examined',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
      documentNumber: {
        circuit: 'commitment_only',
        params: { maxValueBytes: 64 },
        descriptor: {
          legalBasis: {
            framework: 'AMLD5',
            reference: 'Art. 13(1)(a) — customer identification',
            assertion: 'Identifier of the identity document examined',
          },
          evidenceClass: 'DOCUMENTARY',
        },
        validity: { days: 365 },
      },
    },
    tiers: { NONE: 0, RETAIL: 1, PROFESSIONAL: 2, ELIGIBLE_COUNTERPARTY: 3 },
    lists: { country_allowlist: {} },
    output: {
      format: 'csv',
      includeIndex: true,
      bundleDir: 'output',
      emitIndexCsv: true,
      defaults: { investorType: 'RETAIL', softExpiryDays: 365, hardExpiryDays: 730 },
    },
    security: {
      clearInputAfterProcessing: true,
      masterKeyEnv: 'TRUSSET_KYC_MASTER_KEY',
      // Pinned to the day init ran. Every per-subject key and commitment
      // derives from this number, so leaving it unpinned would make bundles
      // impossible to reproduce after the day they were built.
      epochDaysSource: `fixed:${epochDays}`,
      deterministic: true,
      registryDir: 'config/registry',
    },
    manifest: {
      signingKeyEnv: 'TRUSSET_KYC_SIGNING_KEY',
      version: '3.0.0',
      issuer,
    },
  };
}

// ============================== prompting ==============================

async function prompt(question: string, fallback?: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const suffix = fallback ? ` [${fallback}]` : '';
    const answer = await new Promise<string>((resolve) =>
      rl.question(`${question}${suffix}: `, resolve),
    );
    const trimmed = answer.trim();
    return trimmed || fallback || '';
  } finally {
    rl.close();
  }
}

async function resolveIssuer(opts: InitOptions): Promise<{
  name: string;
  identifierScheme: string;
  identifier: string;
  jurisdiction: string;
  keyId: string;
}> {
  const interactive = !opts.nonInteractive && process.stdin.isTTY && !opts.json;
  const today = epochDaysToIsoDate(todayEpochDays());
  const defaultKeyId = `issuing-${today.slice(0, 7)}`;

  let name = opts.issuerName;
  let scheme = opts.issuerScheme;
  let identifier = opts.issuerIdentifier;
  let jurisdiction = opts.issuerJurisdiction;
  const keyId = opts.keyId || defaultKeyId;

  if (interactive) {
    if (!name) {
      console.log('');
      console.log('Who is legally responsible for the assertions this tool will produce?');
      console.log('This is recorded in every manifest and cannot be added retroactively.');
      console.log('');
      name = await prompt('  Institution legal name');
    }
    if (!scheme) {
      scheme = await prompt(`  Identifier scheme (${IDENTIFIER_SCHEMES.join('/')})`, 'LEI');
    }
    if (!identifier) {
      identifier = await prompt(`  ${scheme} identifier`);
    }
    if (!jurisdiction) {
      jurisdiction = await prompt('  Supervising jurisdiction (ISO 3166-1 alpha-2)');
    }
  }

  const missing = [
    !name && '--issuer-name',
    !scheme && '--issuer-scheme',
    !identifier && '--issuer-identifier',
    !jurisdiction && '--issuer-jurisdiction',
  ].filter(Boolean);
  if (missing.length > 0) {
    throw new Error(
      [
        `Cannot write config.json: the issuer block is incomplete (${missing.join(', ')}).`,
        '  A v3 bundle records the party legally responsible for its assertions; a bundle without one',
        '  says what was proved but not who stands behind it.',
        '  Fix: re-run with those flags, e.g.',
        '    npm run init -- --issuer-name "Example Bank AG" --issuer-scheme LEI \\',
        '                    --issuer-identifier 529900T8BM49AURSDO55 --issuer-jurisdiction DE',
      ].join('\n'),
    );
  }

  return {
    name: name!,
    identifierScheme: (scheme || 'LEI').toUpperCase(),
    identifier: identifier!,
    jurisdiction: jurisdiction!.toUpperCase(),
    keyId,
  };
}

// ================================= main =================================

export async function runInit(opts: InitOptions): Promise<InitReport> {
  const checks: CheckResult[] = [checkNode(), checkCargo(), ...checkBinaries()];

  const configPath = path.join(process.cwd(), 'config.json');
  const configExists = fs.existsSync(configPath);

  const keys = writeKeyFile(!!opts.force);
  const publicKeyHex = publicKeyHexFromSigningKey(keys.signingKey);

  let configWritten = false;
  if (!configExists || opts.force) {
    const issuer = await resolveIssuer(opts);
    const template = configTemplate(issuer, todayEpochDays());
    fs.writeFileSync(configPath, JSON.stringify(template, null, 2) + '\n');
    configWritten = true;
  }

  const regDir = registryRoot(
    configExists && !configWritten ? readRegistryDir(configPath) : 'config/registry',
  );

  // Bootstrap a list registry from the shipped source, so the first run is not
  // blocked on a step the operator has no way to know about yet.
  const listVersionsRecorded: string[] = [];
  const listSources = discoverListSources();
  for (const { listId, source } of listSources) {
    if (loadListRegistry(regDir, listId)) continue;
    const registryBin = binaryPath('trusset-registry');
    if (!registryBin) break;
    try {
      execFileSync(
        registryBin,
        ['list-version', '--list-id', listId, '--source', source, '--registry', regDir],
        {
          env: { ...process.env, TRUSSET_KYC_SIGNING_KEY: keys.signingKey },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      listVersionsRecorded.push(listId);
    } catch (e) {
      checks.push({
        name: `list registry: ${listId}`,
        ok: false,
        detail: `could not be recorded: ${(e as Error).message.split('\n')[0]}`,
        fix: `run \`npm run list-version -- --list-id ${listId} --source ${source}\` by hand`,
      });
    }
  }

  for (const { listId } of listSources) {
    const reg = loadListRegistry(regDir, listId);
    checks.push(
      reg
        ? {
            name: `list registry: ${listId}`,
            ok: true,
            detail: `${reg.versions.length} version(s), current has ${reg.versions[reg.versions.length - 1].values.length} entries`,
          }
        : {
            name: `list registry: ${listId}`,
            ok: false,
            detail: 'no signed registry recorded',
            fix: `npm run list-version -- --list-id ${listId} --source <the source .txt>`,
          },
    );
  }

  checks.push(checkInputDir());

  const blocking = checks.filter((c) => !c.ok && c.name !== 'input/');
  const ready = blocking.length === 0;

  const nextSteps: string[] = [];
  if (!ready) {
    nextSteps.push('Resolve the items marked [missing] above, then re-run `npm run init`.');
  }
  nextSteps.push(`Load your keys into the shell:   set -a && . ./${KEY_FILE} && set +a`);
  if (configWritten) {
    nextSteps.push('Review config.json: the claim descriptors are starting points, not legal advice.');
    nextSteps.push(
      `Review the allowlist at config/list_commitments/*.source.txt — the shipped one is a sample.`,
    );
  }
  nextSteps.push('Put records in input/, then check them without proving:  npm run hash -- --dry-run');
  nextSteps.push('Produce bundles:                 npm start');
  nextSteps.push(`Verify one:                      npm run verify -- <wallet> --public-key ${publicKeyHex}`);

  return {
    checks,
    configPath,
    configWritten,
    keyFilePath: path.join(process.cwd(), KEY_FILE),
    keysWritten: keys.written,
    publicKeyHex,
    registryDir: regDir,
    listVersionsRecorded,
    ready,
    nextSteps,
  };
}

function readRegistryDir(configPath: string): string {
  try {
    const parsed = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    return parsed?.security?.registryDir || 'config/registry';
  } catch {
    return 'config/registry';
  }
}

function discoverListSources(): { listId: string; source: string }[] {
  const dir = path.join(process.cwd(), 'config', 'list_commitments');
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.source.txt'))
    .map((f) => ({
      listId: f.replace(/\.source\.txt$/, ''),
      source: path.join(dir, f),
    }));
}

export function formatInitReport(report: InitReport): string {
  const lines: string[] = [];
  lines.push('Environment');
  for (const c of report.checks) {
    const mark = c.ok ? '  [ok]     ' : '  [missing]';
    lines.push(`${mark} ${c.name.padEnd(24)} ${c.detail}`);
    if (!c.ok && c.fix) lines.push(`             ↳ ${c.fix}`);
  }
  lines.push('');
  lines.push('Configuration');
  lines.push(
    `  ${report.configWritten ? '[written] ' : '[kept]    '} ${report.configPath}${report.configWritten ? '' : ' (already existed — left untouched; --force replaces it)'}`,
  );
  lines.push(
    `  ${report.keysWritten ? '[written] ' : '[kept]    '} ${report.keyFilePath} (mode 0600)`,
  );
  if (report.listVersionsRecorded.length > 0) {
    lines.push(`  [written]  list registry version 1 for: ${report.listVersionsRecorded.join(', ')}`);
  }
  lines.push('');
  lines.push('Operator public key (give this to counterparties who verify offline)');
  lines.push(`  ${report.publicKeyHex}`);
  lines.push('');
  lines.push('Evidence classes available for `descriptor.evidenceClass`');
  lines.push(`  ${EVIDENCE_CLASSES.join('  ')}`);
  lines.push('');
  lines.push(report.ready ? 'Ready.' : 'Not ready yet.');
  lines.push('');
  lines.push('Next');
  for (const s of report.nextSteps) lines.push(`  - ${s}`);
  return lines.join('\n');
}
