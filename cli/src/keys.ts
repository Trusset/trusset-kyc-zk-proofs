// Key generation and ed25519 public-key derivation.
//
// v2 told the operator to run `openssl rand -hex 32` twice. There is no
// security reason for that: Node's `crypto.randomBytes` reads the same OS
// CSPRNG that openssl does, and requiring a second toolchain to produce 32
// random bytes only adds a step that can be got wrong. Deriving the public key
// here also closes the gap where the tool documented `--public-key <hex>` but
// emitted that hex nowhere, so the offline verification path could not be run
// by anyone who had not read the test suite.

import { createPrivateKey, createPublicKey, randomBytes } from 'crypto';

/** DER prefix for a PKCS#8-wrapped Ed25519 private key with a 32-byte seed. */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
/** DER prefix for an SPKI-wrapped Ed25519 public key. */
const SPKI_ED25519_PREFIX_LEN = 12;

export function generateKeyHex(): string {
  return randomBytes(32).toString('hex');
}

export function normalizeKeyHex(hex: string, name: string): string {
  const stripped = hex.trim().replace(/^0x/i, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(stripped)) {
    throw new Error(
      `${name} must be 32 bytes of hex (64 characters), got ${stripped.length} character(s).\n  Fix: run \`npm run init\` to generate a valid key, or set it to 64 hex characters.`,
    );
  }
  return stripped;
}

/**
 * The ed25519 verifying key for a 32-byte signing seed, as lowercase hex with
 * no `0x` prefix — the form `--public-key` expects.
 */
export function publicKeyHexFromSigningKey(signingKeyHex: string): string {
  const seed = Buffer.from(normalizeKeyHex(signingKeyHex, 'signing key'), 'hex');
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  const priv = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return Buffer.from(spki).subarray(SPKI_ED25519_PREFIX_LEN).toString('hex');
}
