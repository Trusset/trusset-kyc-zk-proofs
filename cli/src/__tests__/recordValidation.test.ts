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
  assert.match(out.failed[0].message, /not a valid Ethereum address/);
  assert.equal(out.failed[0].field, 'walletAddress');
  assert.match(out.failed[0].message, /Fix:/);
});

test('quarantines missing country', () => {
  const out = validateRecords([record({ country: '' })], baseConfig());
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 1);
  assert.match(out.failed[0].message, /shorter than two characters/);
  assert.equal(out.failed[0].field, 'country');
});

test('quarantines softExpiry > hardExpiry', () => {
  const out = validateRecords(
    [record({ softExpiryDays: 800, hardExpiryDays: 400 })],
    baseConfig(),
  );
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 1);
  assert.match(out.failed[0].message, /softExpiryDays \(800\) exceeds hardExpiryDays \(400\)/);
});

test('every failing row is reported, not just the first', () => {
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

// Through v2.1 an unrecognised investorType was silently replaced by the
// configured default. A row declaring PROFESSIONAL_INVESTOR was recorded as
// RETAIL, signed, and committed into kycHash with no warning and no failure
// row — a bundle asserting a tier the operator never declared, in a context
// where retail and professional are different regulatory regimes. Producing
// evidence that contradicts the source record is worse than refusing to
// produce any.
test('an unrecognised investorType quarantines the row instead of coercing it', () => {
  const out = validateRecords([record({ investorType: 'BOGUS' })], baseConfig());
  assert.equal(out.valid.length, 0);
  assert.equal(out.failed.length, 1);
  assert.equal(out.failed[0].field, 'investorType');
  assert.match(out.failed[0].message, /not a recognised investor type/);
  assert.match(out.failed[0].message, /leave the column blank/);
});

// A blank column still means "use the configured default": the operator has
// said what an absent value means, which is different from having said
// something the tool cannot read.
test('a blank investorType takes the configured default', () => {
  for (const blank of ['', null, undefined]) {
    const out = validateRecords([record({ investorType: blank })], baseConfig());
    assert.equal(out.valid.length, 1, `blank value ${JSON.stringify(blank)}`);
    assert.equal(out.valid[0].investorType, 'RETAIL');
  }
});

test('an unusable expiry value quarantines the row', () => {
  const notANumber = validateRecords(
    [record({ softExpiryDays: 'soon' })],
    baseConfig(),
  );
  assert.equal(notANumber.failed.length, 1);
  assert.match(notANumber.failed[0].message, /is not a number/);

  const outOfRange = validateRecords(
    [record({ hardExpiryDays: 99999 })],
    baseConfig(),
  );
  assert.equal(outOfRange.failed.length, 1);
  assert.match(outOfRange.failed[0].message, /outside 0\.\.36500 days/);

  const blank = validateRecords([record({ softExpiryDays: '' })], baseConfig());
  assert.equal(blank.valid.length, 1);
  assert.equal(blank.valid[0].softExpiryDays, 365);
});

// v3: the per-subject evidence date, which sets `validity.basisAsOf`.
test('a valid evidenceDate is parsed into epochDays', () => {
  const out = validateRecords([record({ evidenceDate: '2026-08-01' })], baseConfig());
  assert.equal(out.valid.length, 1);
  assert.equal(out.valid[0].evidenceDate, 20666);
});

test('an impossible evidenceDate quarantines the row', () => {
  const out = validateRecords([record({ evidenceDate: '2026-13-45' })], baseConfig());
  assert.equal(out.failed.length, 1);
  assert.equal(out.failed[0].field, 'evidenceDate');
  assert.match(out.failed[0].message, /not a real calendar date/);
});

test('an absent evidenceDate is not an error', () => {
  const out = validateRecords([record()], baseConfig());
  assert.equal(out.valid.length, 1);
  assert.equal(out.valid[0].evidenceDate, undefined);
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
