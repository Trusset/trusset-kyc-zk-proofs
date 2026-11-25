// Operator key storage.
//
// Three sources, chosen by `security.keyStore` in config.json:
//
//   file      An encrypted key file. The two operator secrets (the ed25519
//             signing seed and the master key that wraps per-subject keys) are
//             encrypted together with ChaCha20-Poly1305 under a key derived
//             from a passphrase with scrypt (N = 2^17, r = 8, p = 1). The
//             public key, format, and KDF parameters are bound in as
//             associated data, so editing any of them makes decryption fail.
//   keychain  The macOS keychain, through /usr/bin/security. The secret is
//             written over stdin, never on a command line.
//   (none)    TRUSSET_KYC_MASTER_KEY and TRUSSET_KYC_SIGNING_KEY. For CI and
//             scripted test runs only.
//
// The CLI hands the keys to the Rust binaries on the first line of their
// stdin, so they never enter an environment variable or a file on the
// operator path.

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { canonicalJson } from './config';
import { generateKeyHex, normalizeKeyHex, publicKeyHexFromSigningKey } from './keys';
import { KeyStoreConfig } from './types';

export const KEYSTORE_FORMAT = 'trusset-kyc-keystore/1';
export const DEFAULT_KEY_FILE = '.trusset/operator.key';
export const KEYCHAIN_SERVICE = 'trusset-kyc-operator';
export const KEYCHAIN_ACCOUNT = 'default';
export const PASSPHRASE_ENV = 'TRUSSET_KYC_KEY_PASSPHRASE';
export const MIN_PASSPHRASE_LENGTH = 12;

/** scrypt cost. 128 MiB of memory and about 0.2 s per attempt on the measured host. */
export const SCRYPT_PARAMS = { N: 1 << 17, r: 8, p: 1 };

export interface OperatorKeys {
  /** 32-byte ed25519 seed, lowercase hex without 0x. */
  signingKey: string;
  /** 32-byte master key, lowercase hex without 0x. */
  masterKey: string;
}

export interface KeyStoreFile {
  format: string;
  publicKey: string;
  createdAt: string;
  kdf: { name: 'scrypt'; N: number; r: number; p: number; salt: string };
  cipher: { name: 'chacha20-poly1305'; nonce: string; tag: string };
  ciphertext: string;
}

export interface LoadedKeys {
  keys: Partial<OperatorKeys>;
  source: 'file' | 'keychain' | 'env';
  publicKey?: string;
  location?: string;
}

export function generateOperatorKeys(): OperatorKeys {
  return { signingKey: generateKeyHex(), masterKey: generateKeyHex() };
}

function associatedData(f: Pick<KeyStoreFile, 'format' | 'publicKey' | 'kdf'>): Buffer {
  return Buffer.from(
    canonicalJson({ format: f.format, publicKey: f.publicKey, kdf: f.kdf, cipher: 'chacha20-poly1305' }),
    'utf-8',
  );
}

function deriveKey(passphrase: string, kdf: KeyStoreFile['kdf']): Buffer {
  return scryptSync(passphrase.normalize('NFC'), Buffer.from(kdf.salt, 'hex'), 32, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    maxmem: 256 * kdf.N * kdf.r,
  });
}

export function checkPassphraseStrength(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `The passphrase is ${passphrase.length} characters; use at least ${MIN_PASSPHRASE_LENGTH}. It is the only thing protecting the operator key at rest.`,
    );
  }
}

export function encryptKeyStore(
  keys: OperatorKeys,
  passphrase: string,
  params: { N: number; r: number; p: number } = SCRYPT_PARAMS,
): KeyStoreFile {
  const signingKey = normalizeKeyHex(keys.signingKey, 'signing key');
  const masterKey = normalizeKeyHex(keys.masterKey, 'master key');
  const header = {
    format: KEYSTORE_FORMAT,
    publicKey: publicKeyHexFromSigningKey(signingKey),
    kdf: { name: 'scrypt' as const, ...params, salt: randomBytes(32).toString('hex') },
  };
  const key = deriveKey(passphrase, header.kdf);
  const nonce = randomBytes(12);
  const plaintext = Buffer.from(JSON.stringify({ signingKey, masterKey }), 'utf-8');
  const cipher = createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cipher.setAAD(associatedData(header), { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  plaintext.fill(0);
  key.fill(0);
  return {
    ...header,
    createdAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    cipher: { name: 'chacha20-poly1305', nonce: nonce.toString('hex'), tag: tag.toString('hex') },
    ciphertext: ciphertext.toString('hex'),
  };
}

export function decryptKeyStore(file: KeyStoreFile, passphrase: string): OperatorKeys {
  validateKeyStoreShape(file);
  const key = deriveKey(passphrase, file.kdf);
  const decipher = createDecipheriv('chacha20-poly1305', key, Buffer.from(file.cipher.nonce, 'hex'), {
    authTagLength: 16,
  });
  const ciphertext = Buffer.from(file.ciphertext, 'hex');
  decipher.setAAD(associatedData(file), { plaintextLength: ciphertext.length });
  decipher.setAuthTag(Buffer.from(file.cipher.tag, 'hex'));
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error(
      'The key file did not decrypt: wrong passphrase, or the file was modified.\n  Fix: re-enter the passphrase; if it is right, restore the key file from your backup.',
    );
  } finally {
    key.fill(0);
  }
  const parsed = JSON.parse(plaintext.toString('utf-8')) as OperatorKeys;
  plaintext.fill(0);
  const keys = {
    signingKey: normalizeKeyHex(parsed.signingKey, 'signing key'),
    masterKey: normalizeKeyHex(parsed.masterKey, 'master key'),
  };
  if (publicKeyHexFromSigningKey(keys.signingKey) !== file.publicKey) {
    throw new Error('The key file names a different public key than the key it holds.');
  }
  return keys;
}

function validateKeyStoreShape(f: KeyStoreFile): void {
  const hex = (v: unknown, len: number) => typeof v === 'string' && new RegExp(`^[0-9a-f]{${len}}$`).test(v);
  if (f?.format !== KEYSTORE_FORMAT) {
    throw new Error(`Not a ${KEYSTORE_FORMAT} key file (format is ${String(f?.format)}).`);
  }
  if (!hex(f.publicKey, 64)) throw new Error('Key file publicKey is not 64 hex characters.');
  if (f.kdf?.name !== 'scrypt' || !hex(f.kdf.salt, 64)) throw new Error('Key file kdf is not scrypt with a 32-byte salt.');
  if (!Number.isSafeInteger(f.kdf.N) || f.kdf.N < 1 << 14 || (f.kdf.N & (f.kdf.N - 1)) !== 0) {
    throw new Error('Key file scrypt N must be a power of two of at least 16384.');
  }
  if (f.kdf.r < 8 || f.kdf.p < 1) throw new Error('Key file scrypt r must be at least 8 and p at least 1.');
  if (f.cipher?.name !== 'chacha20-poly1305' || !hex(f.cipher.nonce, 24) || !hex(f.cipher.tag, 32)) {
    throw new Error('Key file cipher is not chacha20-poly1305 with a 12-byte nonce and 16-byte tag.');
  }
  if (!hex(f.ciphertext, f.ciphertext?.length ?? 0) || f.ciphertext.length === 0) {
    throw new Error('Key file ciphertext is not hex.');
  }
}

export function readKeyStoreFile(file: string): KeyStoreFile {
  if (!fs.existsSync(file)) {
    throw new Error(
      `Key file ${file} does not exist.\n  Fix: create one with \`npm run key -- create\`, or import existing keys with \`npm run key -- encrypt\`.`,
    );
  }
  const parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as KeyStoreFile;
  validateKeyStoreShape(parsed);
  return parsed;
}

export function writeKeyStoreFile(file: string, ks: KeyStoreFile, force = false): void {
  if (fs.existsSync(file) && !force) {
    throw new Error(`${file} already exists. Pass --force to replace it (keep a backup of the old one first).`);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(ks, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

// ----------------------------- keychain -----------------------------

const KEYCHAIN_LABEL = /^[A-Za-z0-9._-]{1,64}$/;

function securityBinary(): string {
  return process.env.TRUSSET_SECURITY_BIN || '/usr/bin/security';
}

function checkLabel(name: string, value: string): void {
  if (!KEYCHAIN_LABEL.test(value)) {
    throw new Error(`keychain ${name} "${value}" must be 1 to 64 of A-Z a-z 0-9 . _ -`);
  }
}

/** Store both secrets as one keychain item. The secret goes over stdin. */
export function keychainStore(keys: OperatorKeys, service = KEYCHAIN_SERVICE, account = KEYCHAIN_ACCOUNT): void {
  checkLabel('service', service);
  checkLabel('account', account);
  const secret = `${normalizeKeyHex(keys.signingKey, 'signing key')}:${normalizeKeyHex(keys.masterKey, 'master key')}`;
  const result = spawnSync(securityBinary(), ['-i'], {
    input: `add-generic-password -U -s ${service} -a ${account} -w ${secret}\n`,
    encoding: 'utf-8',
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `Could not write the keychain item: ${result.error?.message ?? result.stderr?.trim() ?? 'unknown error'}`,
    );
  }
}

export function keychainLoad(service = KEYCHAIN_SERVICE, account = KEYCHAIN_ACCOUNT): OperatorKeys {
  checkLabel('service', service);
  checkLabel('account', account);
  const result = spawnSync(securityBinary(), ['find-generic-password', '-s', service, '-a', account, '-w'], {
    encoding: 'utf-8',
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `No operator key in the keychain under service "${service}", account "${account}".\n  Fix: \`npm run key -- create --keychain\`, or point security.keyStore at your key file.`,
    );
  }
  const [signingKey, masterKey] = String(result.stdout).trim().split(':');
  return {
    signingKey: normalizeKeyHex(signingKey ?? '', 'keychain signing key'),
    masterKey: normalizeKeyHex(masterKey ?? '', 'keychain master key'),
  };
}

// ----------------------------- passphrase -----------------------------

/** Read a passphrase from the terminal without echoing it. */
export async function promptHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    throw new Error(
      `No terminal to ask for the key passphrase.\n  Fix: run interactively, or for an unattended run set ${PASSPHRASE_ENV} in the environment of that one command.`,
    );
  }
  process.stderr.write(question);
  return new Promise<string>((resolve, reject) => {
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf-8');
    const done = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stderr.write('\n');
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return done();
        if (ch === '\u0003') return done(new Error('Cancelled.'));
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

export async function readPassphrase(question: string, confirm = false): Promise<string> {
  const fromEnv = process.env[PASSPHRASE_ENV];
  if (fromEnv) return fromEnv;
  const first = await promptHidden(question);
  if (confirm) {
    const second = await promptHidden('Repeat the passphrase: ');
    if (first !== second) throw new Error('The two passphrases differ.');
  }
  return first;
}

// ----------------------------- loading -----------------------------

export interface LoadKeysContext {
  keyStore?: KeyStoreConfig;
  masterKeyEnv: string;
  signingKeyEnv: string;
}

export function keyFilePath(ks: { path: string }): string {
  return path.isAbsolute(ks.path) ? ks.path : path.join(process.cwd(), ks.path);
}

/**
 * The operator's public key without unlocking anything, when that is
 * possible: from the key file's header, or from the signing key in the
 * environment. `undefined` for the keychain, which has to be read.
 */
export function peekPublicKey(ctx: LoadKeysContext): string | undefined {
  if (ctx.keyStore?.type === 'file') {
    const file = keyFilePath(ctx.keyStore);
    return fs.existsSync(file) ? readKeyStoreFile(file).publicKey : undefined;
  }
  if (ctx.keyStore?.type === 'keychain') return undefined;
  const signing = process.env[ctx.signingKeyEnv];
  return signing ? publicKeyHexFromSigningKey(signing) : undefined;
}

/** Load the operator keys from wherever config.json says they live. */
export async function loadOperatorKeys(ctx: LoadKeysContext): Promise<LoadedKeys> {
  const ks = ctx.keyStore;
  if (ks?.type === 'file') {
    const file = keyFilePath(ks);
    const store = readKeyStoreFile(file);
    const passphrase = await readPassphrase(`Passphrase for ${path.relative(process.cwd(), file) || file}: `);
    const keys = decryptKeyStore(store, passphrase);
    return { keys, source: 'file', publicKey: store.publicKey, location: file };
  }
  if (ks?.type === 'keychain') {
    const service = ks.service ?? KEYCHAIN_SERVICE;
    const account = ks.account ?? KEYCHAIN_ACCOUNT;
    const keys = keychainLoad(service, account);
    return {
      keys,
      source: 'keychain',
      publicKey: publicKeyHexFromSigningKey(keys.signingKey),
      location: `keychain ${service}/${account}`,
    };
  }
  const signing = process.env[ctx.signingKeyEnv];
  const master = process.env[ctx.masterKeyEnv];
  return {
    keys: {
      ...(signing ? { signingKey: normalizeKeyHex(signing, ctx.signingKeyEnv) } : {}),
      ...(master ? { masterKey: normalizeKeyHex(master, ctx.masterKeyEnv) } : {}),
    },
    source: 'env',
    publicKey: signing ? publicKeyHexFromSigningKey(signing) : undefined,
    location: `environment (${ctx.signingKeyEnv}, ${ctx.masterKeyEnv})`,
  };
}

/** The line the Rust binaries read first when `TRUSSET_KYC_KEYS_STDIN=1`. */
export function keyLine(keys: Partial<OperatorKeys>): string {
  return (
    JSON.stringify({
      ...(keys.masterKey ? { masterKey: keys.masterKey } : {}),
      ...(keys.signingKey ? { signingKey: keys.signingKey } : {}),
    }) + '\n'
  );
}

/** Environment for a Rust child: key variables removed, stdin flag set. */
export function childEnvForStdinKeys(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, TRUSSET_KYC_KEYS_STDIN: '1' };
  delete env.TRUSSET_KYC_MASTER_KEY;
  delete env.TRUSSET_KYC_SIGNING_KEY;
  delete env[PASSPHRASE_ENV];
  return env;
}
