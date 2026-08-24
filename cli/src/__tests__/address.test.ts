// EIP-55 address handling.
//
// These vectors are load-bearing beyond ordinary correctness: the 20-byte
// address is hashed into every leaf, so a change in what `getAddress` returns
// would change every root the tool has ever produced. The checksum vectors
// below are the ones published in EIP-55 itself.

import { strict as assert } from 'node:assert';
import test from 'node:test';
import { getAddress, isAddress, toChecksumAddress } from '../address';

// From EIP-55, "Test Cases".
const EIP55_VECTORS = [
  // All caps
  '0x52908400098527886E0F7030069857D2E4169EE7',
  '0x8617E340B3D01FA5F11F306F4090FD50E238070D',
  // All lower
  '0xde709f2102306220921060314715629080e2fb77',
  '0x27b1fdb04752bbc536007a920d24acb045561c26',
  // Normal
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
];

test('every EIP-55 published vector validates', () => {
  for (const v of EIP55_VECTORS) {
    assert.equal(isAddress(v), true, `should accept ${v}`);
  }
});

test('checksumming reproduces the EIP-55 mixed-case forms', () => {
  // The four "Normal" vectors are already in checksummed form, so
  // checksumming their lowercase must return them unchanged.
  for (const v of EIP55_VECTORS.slice(4)) {
    assert.equal(toChecksumAddress(v.toLowerCase()), v);
    assert.equal(getAddress(v.toLowerCase()), v);
    assert.equal(getAddress(v.toUpperCase().replace('0X', '0x')), v);
    assert.equal(getAddress(v), v, 'checksumming is idempotent');
  }
});

test('a single flipped case digit fails the checksum', () => {
  const good = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  // Position 1 of the body is 'a' in the checksummed form; upper-casing it
  // makes the address mixed-case with a wrong checksum.
  const bad = '0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  assert.equal(isAddress(good), true);
  assert.equal(isAddress(bad), false);
  assert.throws(() => getAddress(bad), /not a valid Ethereum address/);
});

test('single-case addresses are accepted without a checksum', () => {
  // EIP-55: an all-lower or all-upper address carries no case information, so
  // there is nothing to check. Rejecting them would break every tool that
  // emits lowercase.
  const lower = '0xde709f2102306220921060314715629080e2fb77';
  assert.equal(isAddress(lower), true);
  assert.equal(isAddress(lower.toUpperCase().replace('0X', '0x')), true);
});

test('malformed input is rejected rather than coerced', () => {
  for (const bad of [
    '',
    '0x',
    'not-an-address',
    '0x123',
    `0x${'g'.repeat(40)}`,
    `0x${'0'.repeat(39)}`,
    `0x${'0'.repeat(41)}`,
    ` 0x${'0'.repeat(40)}`,
    `0x${'0'.repeat(40)} `,
  ]) {
    assert.equal(isAddress(bad), false, `should reject ${JSON.stringify(bad)}`);
    assert.throws(() => getAddress(bad));
  }
});

test('non-string input is rejected without throwing from isAddress', () => {
  for (const bad of [null, undefined, 42, {}, []] as unknown[]) {
    assert.equal(isAddress(bad as string), false);
  }
});

test('the 0x prefix is optional on input and always present on output', () => {
  const body = '5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
  assert.equal(isAddress(body), true);
  assert.equal(getAddress(body), `0x${body}`);
  assert.equal(getAddress(`0x${body}`), `0x${body}`);
});

// The addresses the shipped fixtures and docs use, pinned so a change in
// checksum behaviour breaks a test rather than every bundle in the field.
test('the fixture addresses keep their established checksum forms', () => {
  assert.equal(
    getAddress('0xabcdef0123456789abcdef0123456789abcdef01'),
    '0xabCDeF0123456789AbcdEf0123456789aBCDEF01',
  );
  assert.equal(
    getAddress('0xfedcba9876543210fedcba9876543210fedcba98'),
    '0xfEdcBA9876543210FedCBa9876543210fEdCBa98',
  );
  assert.equal(
    getAddress('0x1111111111111111111111111111111111111111'),
    '0x1111111111111111111111111111111111111111',
  );
});
