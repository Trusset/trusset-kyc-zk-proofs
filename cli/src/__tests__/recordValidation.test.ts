// TS-side unit tests for recordValidation.
//
// Uses Node's built-in node:test runner (Node 18+) — zero dev-dep cost.
// Run with: node --test cli/dist/__tests__/recordValidation.test.js (after tsc).

import { strict as assert } from 'node:assert';
import test from 'node:test';
import { validateRecords, type ValidationOutcome } from '../recordValidation';
import type { Config, KycRecord } from '../types';

function baseConfig(): Config {
  return {
    mapping: {
      fields: ['firstName', 'lastName', 'dateOfBirth'],
      walletAddressField: 'walletAddress',
      countryField: 'country',
      investorTypeField: 'investorType',
      softExpiryDaysField: 'softExpiryDays',
      hardExpiryDaysField: 'hardExpiryDays',
    },
    output: {
      format: 'csv',
      includeIndex: true,
      defaults: { investorType: 'RETAIL', softExpiryDays: 365, hardExpiryDays: 730 },
    },
    security: { clearInputAfterProcessing: false },
  };
}

function record(overrides: Partial<KycRecord> = {}): KycRecord {
  return {
    walletAddress: '0xabcdef0123456789abcdef0123456789abcdef01',
    country: 'DEU',
    investorType: 'RETAIL',
    firstName: 'Alice',
    lastName: 'Anderson',
    dateOfBirth: '1985-04-12',
    ...overrides,
  };
}

test('accepts a valid record', () => {
  const out: ValidationOutcome = validateRecords([record()], baseConfig());
  assert.equal(out.valid.length, 1);
  assert.equal(out.failed.length, 0);
  assert.equal(out.valid[0].country, 'DEU');
  // Wallet is EIP-55 normalized; the all-lowercase input becomes mixed case.
  assert.match(out.valid[0].walletAddress, /^0x[a-fA-F0-9]{40}$/);
});

test('quarantines a bad wallet but processes the rest of the batch', () => {
  const records: KycRecord[] = [
    record(),
    record({ walletAddress: 'not-a-wallet' }),
    record({ walletAddress: '0xfedcba9876543210fedcba9876543210fedcba98' }),
  ];
  const out = validateRecords(records, baseConfig());
  assert.equal(out.valid.length, 2);
  assert.equal(out.failed.length, 1);
  assert.equal(out.failed[0].errorCode, 'E_INPUT');
  assert.equal(out.failed[0].rowNum, 2);
  assert.match(out.failed[0].message, /invalid wallet address/);
});

test('quarantines missing country', () => {
  const out = validateRecords([record({ country: '' })], baseConfig());
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 1);
  assert.match(out.failed[0].message, /missing or invalid country/);
});

test('quarantines softExpiry > hardExpiry', () => {
  const out = validateRecords(
    [record({ softExpiryDays: 800, hardExpiryDays: 400 })],
    baseConfig(),
  );
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 1);
  assert.match(out.failed[0].message, /softExpiryDays.*cannot exceed/);
});

test('multiple failures all collected; valid rows survive', () => {
  const records: KycRecord[] = [
    record({ walletAddress: 'bad1' }),
    record(),
    record({ country: '' }),
    record({ walletAddress: '0xfedcba9876543210fedcba9876543210fedcba98' }),
    record({ walletAddress: 'bad2' }),
  ];
  const out = validateRecords(records, baseConfig());
  assert.equal(out.valid.length, 2);
  assert.equal(out.failed.length, 3);
  // Row numbers preserved in input order.
  assert.deepEqual(
    out.failed.map((f) => f.rowNum),
    [1, 3, 5],
  );
});

test('investorType falls back to default when invalid', () => {
  const out = validateRecords([record({ investorType: 'BOGUS' })], baseConfig());
  assert.equal(out.valid.length, 1);
  assert.equal(out.valid[0].investorType, 'RETAIL');
});

test('investorType accepts case-insensitive matches', () => {
  const out = validateRecords([record({ investorType: 'professional' })], baseConfig());
  assert.equal(out.valid[0].investorType, 'PROFESSIONAL');
});

test('country normalized to upper-3', () => {
  const out = validateRecords([record({ country: 'deutschland' })], baseConfig());
  assert.equal(out.valid[0].country, 'DEU');
});

test('empty input produces empty outcome', () => {
  const out = validateRecords([], baseConfig());
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 0);
});
