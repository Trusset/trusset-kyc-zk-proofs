// v3.1 CLI pieces: the encrypted key file, the keychain bridge (against a
// stand-in `security` binary, never the real keychain), hub calldata and
// return-data decoding, and the 3.1.0 job a batch turns into.

import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import test from 'node:test';
import {
  childEnvForStdinKeys,
  decryptKeyStore,
  encryptKeyStore,
  generateOperatorKeys,
  keychainLoad,
  keychainStore,
  keyLine,
  KeyStoreFile,
  readKeyStoreFile,
  writeKeyStoreFile,
} from '../keystore';
import { publicKeyHexFromSigningKey } from '../keys';
import {
  compareAttestation,
  decodeAttestation,
  getAttestationCalldata,
  keccakHex,
  operatorKeyAtCalldata,
  selector,
  setAttesterProfileCalldata,
} from '../chain';
import { resolveConfig, validateChain } from '../config';
import { buildJobWithSkips } from '../jobSpec';
import { validateRecords } from '../recordValidation';
import { buildIndexRows } from '../bundleWriter';
import { listContentHash } from '../registry';
import type { Config } from '../types';

const FAST = { N: 1 << 14, r: 8, p: 1 };
const SIGNING = '42'.repeat(32);
const MASTER = '11'.repeat(32);

test('key file round trip, with the public key bound in', () => {
  const ks = encryptKeyStore({ signingKey: SIGNING, masterKey: MASTER }, 'correct horse battery', FAST);
  assert.equal(ks.publicKey, publicKeyHexFromSigningKey(SIGNING));
  assert.equal(ks.cipher.name, 'chacha20-poly1305');
  assert.ok(!JSON.stringify(ks).includes(SIGNING));
  assert.ok(!JSON.stringify(ks).includes(MASTER));
  const keys = decryptKeyStore(ks, 'correct horse battery');
  assert.deepEqual(keys, { signingKey: SIGNING, masterKey: MASTER });
});

test('key file refuses a wrong passphrase and every edited field', () => {
  const ks = encryptKeyStore({ signingKey: SIGNING, masterKey: MASTER }, 'correct horse battery', FAST);
  assert.throws(() => decryptKeyStore(ks, 'wrong horse battery'), /did not decrypt/);
  const other = publicKeyHexFromSigningKey('43'.repeat(32));
  const edits: Array<(k: KeyStoreFile) => void> = [
    (k) => (k.publicKey = other),
    (k) => (k.kdf.salt = 'ab'.repeat(32)),
    (k) => (k.kdf.N = 1 << 15),
    (k) => (k.cipher.nonce = '00'.repeat(12)),
    (k) => (k.cipher.tag = '00'.repeat(16)),
    (k) => (k.ciphertext = 'ff' + k.ciphertext.slice(2)),
  ];
  for (const edit of edits) {
    const copy = JSON.parse(JSON.stringify(ks)) as KeyStoreFile;
    edit(copy);
    assert.throws(() => decryptKeyStore(copy, 'correct horse battery'));
  }
  const weak = JSON.parse(JSON.stringify(ks)) as KeyStoreFile;
  weak.kdf.N = 1024;
  assert.throws(() => decryptKeyStore(weak, 'correct horse battery'), /16384/);
});

test('key file is written 0600 and never overwritten silently', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusset-ks-'));
  const file = path.join(dir, 'nested', 'operator.key');
  const ks = encryptKeyStore(generateOperatorKeys(), 'correct horse battery', FAST);
  writeKeyStoreFile(file, ks);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(readKeyStoreFile(file), ks);
  assert.throws(() => writeKeyStoreFile(file, ks), /already exists/);
  writeKeyStoreFile(file, ks, true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('keychain bridge sends the secret over stdin, not argv', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusset-sec-'));
  const store = path.join(dir, 'store');
  const log = path.join(dir, 'argv');
  const fake = path.join(dir, 'security');
  fs.writeFileSync(
    fake,
    [
      '#!/bin/sh',
      `echo "$@" >> "${log}"`,
      'if [ "$1" = "-i" ]; then',
      `  read line; echo "$line" | sed -E 's/.* -w ([^ ]+).*/\\1/' > "${store}"; exit 0`,
      'fi',
      `if [ -f "${store}" ]; then cat "${store}"; exit 0; fi`,
      'exit 44',
      '',
    ].join('\n'),
    { mode: 0o755 },
  );
  const previous = process.env.TRUSSET_SECURITY_BIN;
  process.env.TRUSSET_SECURITY_BIN = fake;
  try {
    assert.throws(() => keychainLoad('svc', 'acct'), /No operator key/);
    keychainStore({ signingKey: SIGNING, masterKey: MASTER }, 'svc', 'acct');
    assert.deepEqual(keychainLoad('svc', 'acct'), { signingKey: SIGNING, masterKey: MASTER });
    const argv = fs.readFileSync(log, 'utf-8');
    assert.ok(!argv.includes(SIGNING) && !argv.includes(MASTER), 'secret leaked into argv');
    assert.throws(() => keychainStore({ signingKey: SIGNING, masterKey: MASTER }, 'bad service', 'a'));
  } finally {
    if (previous === undefined) delete process.env.TRUSSET_SECURITY_BIN;
    else process.env.TRUSSET_SECURITY_BIN = previous;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('keys reach the Rust binaries on stdin, with key variables removed', () => {
  assert.equal(keyLine({ signingKey: SIGNING }), `{"signingKey":"${SIGNING}"}\n`);
  const env = childEnvForStdinKeys({
    PATH: '/bin',
    TRUSSET_KYC_SIGNING_KEY: SIGNING,
    TRUSSET_KYC_MASTER_KEY: MASTER,
    TRUSSET_KYC_KEY_PASSPHRASE: 'x',
  });
  assert.equal(env.TRUSSET_KYC_KEYS_STDIN, '1');
  assert.equal(env.TRUSSET_KYC_SIGNING_KEY, undefined);
  assert.equal(env.TRUSSET_KYC_MASTER_KEY, undefined);
  assert.equal(env.TRUSSET_KYC_KEY_PASSPHRASE, undefined);
  assert.equal(env.PATH, '/bin');
});

test('hub selectors and calldata match the ABI', () => {
  assert.equal(selector('transfer(address,uint256)'), 'a9059cbb');
  assert.equal(
    keccakHex(''),
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  );
  const pk = '0x' + 'ab'.repeat(32);
  const lei = keccakHex('529900T8BM49AURSDO55');
  const data = setAttesterProfileCalldata(pk, lei, 'https://example.org/attester.json');
  const body = data.slice(10);
  assert.equal(data.slice(2, 10), selector('setAttesterProfile(bytes32,bytes32,string)'));
  assert.equal(body.slice(0, 64), 'ab'.repeat(32));
  assert.equal(body.slice(64, 128), lei.slice(2));
  assert.equal(BigInt('0x' + body.slice(128, 192)), 96n);
  assert.equal(BigInt('0x' + body.slice(192, 256)), 33n);
  assert.equal(
    Buffer.from(body.slice(256, 256 + 66), 'hex').toString('utf-8'),
    'https://example.org/attester.json',
  );
  assert.equal((body.length - 256) % 64, 0);
  assert.equal(
    operatorKeyAtCalldata('0x1111111111111111111111111111111111111111', 2),
    '0x' + selector('operatorKeyAt(address,uint32)') + '0'.repeat(24) + '11'.repeat(20) + '0'.repeat(63) + '2',
  );
  assert.ok(getAttestationCalldata('0x' + '11'.repeat(20), '0x' + '22'.repeat(20)).endsWith('22'.repeat(20)));
});

test('getAttestation return data decodes and compares field by field', () => {
  const words = [
    '74'.repeat(32),
    (49).toString(16),
    (1_800_000_000).toString(16),
    (1_826_582_400).toString(16),
    (1_858_118_400).toString(16),
    '2',
    '1',
  ].map((w) => w.padStart(64, '0'));
  const att = decodeAttestation('0x' + words.join(''));
  assert.deepEqual(att, {
    root: '0x' + '74'.repeat(32),
    predicates: '49',
    issuedAt: 1_800_000_000,
    softExpiry: 1_826_582_400,
    hardExpiry: 1_858_118_400,
    investorClass: 2,
    status: 'ACTIVE',
  });
  const expected = {
    root: '0x' + '74'.repeat(32),
    investorClass: 2,
    predicates: '49',
    softExpiry: 1_826_582_400,
    hardExpiry: 1_858_118_400,
  };
  assert.deepEqual(compareAttestation(att, expected), []);
  assert.equal(compareAttestation({ ...att, predicates: '51' }, expected).length, 1);
  assert.equal(compareAttestation({ ...att, investorClass: 3 }, expected).length, 1);
  assert.equal(compareAttestation({ ...att, status: 'REVOKED' }, expected).length, 1);
  assert.equal(compareAttestation(att, { ...expected, root: '0x' + '00'.repeat(32) }).length, 1);
  const attesterBits = (1n << 70n) + 49n;
  assert.deepEqual(compareAttestation({ ...att, predicates: attesterBits.toString() }, expected), []);
});

test('chain block validation', () => {
  const good = {
    chainId: 11155111,
    hub: '0x2222222222222222222222222222222222222222',
    attester: '0x1111111111111111111111111111111111111111',
    keyId: 1,
  };
  assert.deepEqual(validateChain(good), good);
  assert.throws(() => validateChain(undefined), /chain: missing/);
  assert.throws(() => validateChain({ ...good, hub: '0x' + '0'.repeat(40) }));
  assert.throws(() => validateChain({ ...good, keyId: 0 }));
  assert.throws(() => validateChain({ ...good, chainId: 0 }));
  assert.throws(() => validateChain({ ...good, attester: '0xAbCdEf0123456789AbCdEf0123456789AbCdEf02' }), /checksum/);
});

function eeaRegistry(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trusset-reg-'));
  const list = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', '..', 'config', 'list_commitments', 'eea.json'), 'utf-8'),
  ) as { values: string[]; root: string; depth: number; sourceSha256: string };
  fs.mkdirSync(path.join(dir, 'lists'));
  fs.writeFileSync(
    path.join(dir, 'lists', 'eea.json'),
    JSON.stringify({
      schemaVersion: 1,
      listId: 'eea',
      versions: [
        {
          version: 1,
          values: list.values,
          root: list.root,
          depth: list.depth,
          contentHash: listContentHash(list.values),
          sourceSha256: list.sourceSha256,
          effectiveFrom: 20000,
          generator: 'test',
          recordedAt: '2026-11-19T00:00:00Z',
        },
      ],
    }),
  );
  return dir;
}

function v31Config(): Config {
  const descriptor = {
    legalBasis: { framework: 'NATIONAL', reference: 'ref', assertion: 'assertion' },
    evidenceClass: 'DOCUMENTARY' as const,
  };
  return {
    mapping: {
      fields: ['dateOfBirth', 'firstName'],
      walletAddressField: 'walletAddress',
      countryField: 'country',
      investorTypeField: 'investorType',
      softExpiryDaysField: 'softExpiryDays',
      hardExpiryDaysField: 'hardExpiryDays',
    },
    predicates: {
      dateOfBirth: { circuit: 'age_threshold', params: { minAgeYears: 18 }, predicate: 'ADULT', descriptor, validity: { days: 3650 } },
      country: [
        { circuit: 'set_membership', params: { list: 'eea' }, predicate: 'EEA_RESIDENT', optional: true, descriptor, validity: { days: 365 } },
      ],
      investorType: { circuit: 'tier_threshold', params: { minTier: 'ATTESTED' }, predicate: 'INVESTOR_CLASS', descriptor, validity: { days: 730 } },
      firstName: { circuit: 'commitment_only', params: { maxValueBytes: 128 }, descriptor, validity: { days: 365 } },
    },
    lists: {},
    output: { format: 'csv', includeIndex: true, defaults: { investorType: 'RETAIL', softExpiryDays: 365, hardExpiryDays: 730 } },
    security: { clearInputAfterProcessing: false, epochDaysSource: 'fixed:20776', registryDir: eeaRegistry() },
    manifest: {
      version: '3.1.0',
      issuer: { name: 'Example Bank AG', identifierScheme: 'LEI', identifier: '529900T8BM49AURSDO55', jurisdiction: 'DE', keyId: 'k1' },
    },
    chain: {
      chainId: 11155111,
      hub: '0x2222222222222222222222222222222222222222',
      attester: '0x1111111111111111111111111111111111111111',
      keyId: 1,
    },
  };
}

function quietly<T>(fn: () => T): T {
  const warn = console.warn;
  console.warn = () => undefined;
  try {
    return fn();
  } finally {
    console.warn = warn;
  }
}

test('a 3.1.0 job carries no clear-text personal value and one leaf per predicate that holds', () => {
  const rc = quietly(() => resolveConfig(v31Config()));
  const records = [
    { walletAddress: '0xabcdef0123456789abcdef0123456789abcdef01', country: 'DEU', investorType: 'PROFESSIONAL', dateOfBirth: '1990-04-12', firstName: 'Alice' },
    { walletAddress: '0xabcdef0123456789abcdef0123456789abcdef02', country: 'CHE', investorType: 'RETAIL', dateOfBirth: '1980-01-01', firstName: 'Bob' },
    { walletAddress: '0xabcdef0123456789abcdef0123456789abcdef03', country: 'DEU', investorType: 'NONE', dateOfBirth: '1980-01-01', firstName: 'Carol' },
  ];
  const v = validateRecords(records, rc.raw, rc.evidenceDateField);
  assert.equal(v.failed.length, 0);
  const { job, skipped } = buildJobWithSkips(v.valid, rc, '/tmp/out');
  assert.equal(job.version, '3.1.0');
  assert.deepEqual(job.chain, rc.chain);
  assert.equal(skipped.length, 1);
  assert.equal(skipped[0].errorCode, 'E_TIER_NONE');
  assert.equal(job.subjects.length, 2);

  const text = JSON.stringify(job.subjects.map((s) => s.passthrough));
  for (const s of job.subjects) {
    assert.deepEqual(Object.keys(s.passthrough).sort(), ['hardExpiryDays', 'softExpiryDays']);
  }
  assert.ok(!text.includes('DEU') && !text.includes('PROFESSIONAL'));

  const [eea, nonEea] = job.subjects;
  assert.deepEqual(eea.leaves.map((l) => l.predicate ?? null).sort(), ['ADULT', 'EEA_RESIDENT', 'INVESTOR_CLASS', null].sort());
  assert.ok(!nonEea.leaves.some((l) => l.predicate === 'EEA_RESIDENT'), 'optional EEA leaf left out for CHE');
  const tierOf = (s: typeof eea) => s.leaves.find((l) => l.predicate === 'INVESTOR_CLASS')!;
  assert.equal(tierOf(eea).public.min_tier, 2);
  assert.equal(tierOf(nonEea).public.min_tier, 1);
  assert.notEqual(tierOf(eea).params_hash, tierOf(nonEea).params_hash);
  for (const s of job.subjects) {
    for (const l of s.leaves) {
      assert.notEqual(l.disclosure, 'plaintext');
      if (l.circuit === 'set_membership') assert.deepEqual(Object.keys(l.params), ['listId']);
    }
  }

  const rows = buildIndexRows(v.valid, [{ walletAddress: eea.subject_id, bundlePath: '/x', kycHash: '0x00' }], false, true, true);
  assert.equal(rows.length, 1);
  assert.ok(!('country' in rows[0]));
});

test('3.1.0 config rules', () => {
  const noClass = v31Config();
  delete (noClass.predicates as Record<string, unknown>).investorType;
  noClass.mapping.investorTypeField = undefined;
  assert.throws(() => quietly(() => resolveConfig(noClass)), /exactly one INVESTOR_CLASS/);

  const processPredicate = v31Config();
  (processPredicate.predicates!.firstName as { predicate?: string }).predicate = 'KYC_DONE';
  assert.throws(() => quietly(() => resolveConfig(processPredicate)), /cannot name a leaf/);

  const noChain = v31Config();
  delete noChain.chain;
  assert.throws(() => quietly(() => resolveConfig(noChain)), /chain: missing/);

  const older = v31Config();
  older.manifest!.version = '3.0.0';
  assert.throws(() => quietly(() => resolveConfig(older)), /3\.1\.0/);
});
