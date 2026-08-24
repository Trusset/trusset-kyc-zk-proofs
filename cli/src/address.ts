// EIP-55 address validation and checksum encoding.
//
// This replaced `ethers`, which was pulled in for exactly two functions —
// `isAddress` and `getAddress` — and brought roughly twenty transitive
// packages with it, including a WebSocket client and an ENS normalizer. A
// tool whose security model is "no outbound network calls, ever" should not
// ship a WebSocket library, and that dependency is what produced the only
// high-severity advisory in the tree.
//
// What remains is `@noble/hashes` (audited, zero-dependency, and what ethers
// v6 itself uses for keccak) plus the EIP-55 algorithm, which is fifteen
// lines against a published spec. `cli/src/__tests__/address.test.ts` pins it
// against every checksum vector in EIP-55 itself.
//
// Correctness here is load-bearing: the 20-byte address is hashed into every
// leaf, so a divergence from the previous implementation would change every
// root the tool has ever produced.

import { keccak_256 } from '@noble/hashes/sha3';

const HEX_40 = /^(0x)?[0-9a-fA-F]{40}$/;

function keccakHex(input: string): string {
  const digest = keccak_256(new TextEncoder().encode(input));
  let out = '';
  for (const byte of digest) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * The EIP-55 mixed-case form of an address.
 *
 * Each hex digit of the lowercase address is uppercased when the
 * corresponding nibble of `keccak256(lowercase_address_without_0x)` is 8 or
 * greater. Digits 0-9 have no case, so the rule only affects a-f.
 */
export function toChecksumAddress(address: string): string {
  const lower = address.replace(/^0x/, '').toLowerCase();
  const hash = keccakHex(lower);
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const char = lower[i];
    out += parseInt(hash[i], 16) >= 8 ? char.toUpperCase() : char;
  }
  return out;
}

/**
 * True for a well-formed Ethereum address.
 *
 * All-lowercase and all-uppercase forms are accepted without a checksum —
 * they carry no case information to check, which is what EIP-55 specifies.
 * A mixed-case address must have a correct checksum: mixed case is a claim
 * that the checksum was computed, and accepting a wrong one would defeat the
 * typo protection the standard exists to provide.
 */
export function isAddress(address: string): boolean {
  if (typeof address !== 'string' || !HEX_40.test(address)) return false;
  const body = address.replace(/^0x/, '');
  if (body === body.toLowerCase() || body === body.toUpperCase()) return true;
  return toChecksumAddress(body) === (address.startsWith('0x') ? address : `0x${address}`);
}

/**
 * Normalize to the EIP-55 checksummed form, or throw. Mirrors the contract of
 * the function it replaced: reject anything malformed, and reject a
 * mixed-case address whose checksum does not hold.
 */
export function getAddress(address: string): string {
  if (!isAddress(address)) {
    throw new Error(`"${address}" is not a valid Ethereum address`);
  }
  return toChecksumAddress(address);
}
