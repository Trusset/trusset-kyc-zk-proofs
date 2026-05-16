// Wallet + country + investor + expiry validation, lifted from v1
// src/hash.ts:90-152 with one structural change: per-record errors are
// collected, not thrown. This implements plan edge case 4 ("partial batch
// failure") — one bad row no longer kills a 10k-row batch.

import { ethers } from 'ethers';
import { Config, InvestorTypeName, KycFieldValue, KycRecord } from './types';

const INVESTOR_TYPES: InvestorTypeName[] = ['NONE', 'RETAIL', 'PROFESSIONAL', 'ELIGIBLE_COUNTERPARTY'];
const MAX_EXPIRY_DAYS = 36500;

export function normalizeValue(value: KycFieldValue): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    throw new Error('Nested objects and arrays are not supported as field values');
  }
  return String(value).trim();
}

export function resolveInvestorType(
  value: KycFieldValue,
  fallback: InvestorTypeName,
): InvestorTypeName {
  if (typeof value !== 'string') return fallback;
  const upper = value.toUpperCase().trim() as InvestorTypeName;
  return INVESTOR_TYPES.includes(upper) ? upper : fallback;
}

export function resolveExpiryDays(value: KycFieldValue, fallback: number): number {
  if (value === null || value === undefined || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num) || num < 0 || num > MAX_EXPIRY_DAYS) return fallback;
  return Math.floor(num);
}

export interface ValidatedRecord {
  rowNum: number;
  walletAddress: string;
  country: string;
  investorType: InvestorTypeName;
  softExpiryDays: number;
  hardExpiryDays: number;
  record: KycRecord;
}

export interface ValidationFailure {
  rowNum: number;
  /** Best-effort wallet display string. Empty if the wallet field is missing or malformed. */
  walletAddress: string;
  /** Stable error code matching the prover's E_* codes where applicable. */
  errorCode: string;
  message: string;
}

export interface ValidationOutcome {
  valid: ValidatedRecord[];
  failed: ValidationFailure[];
}

/**
 * Validate a batch of records, collecting per-row failures instead of
 * throwing on the first error. Plan §"Resolved edge cases" item 4.
 */
export function validateRecords(records: KycRecord[], config: Config): ValidationOutcome {
  const m = config.mapping;
  const defaults = config.output.defaults || {};
  const defInvestor: InvestorTypeName =
    defaults.investorType && INVESTOR_TYPES.includes(defaults.investorType)
      ? defaults.investorType
      : 'RETAIL';
  const defSoft = Number.isFinite(defaults.softExpiryDays as number)
    ? Math.max(0, Math.min(MAX_EXPIRY_DAYS, Math.floor(defaults.softExpiryDays as number)))
    : 365;
  const defHard = Number.isFinite(defaults.hardExpiryDays as number)
    ? Math.max(0, Math.min(MAX_EXPIRY_DAYS, Math.floor(defaults.hardExpiryDays as number)))
    : 730;

  const valid: ValidatedRecord[] = [];
  const failed: ValidationFailure[] = [];

  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const rowNum = i + 1;
    const outcome = validateOneRecord(
      record,
      rowNum,
      m,
      defInvestor,
      defSoft,
      defHard,
    );
    if ('value' in outcome) {
      valid.push(outcome.value);
    } else {
      failed.push(outcome.error);
    }
  }

  return { valid, failed };
}

type Outcome = { value: ValidatedRecord } | { error: ValidationFailure };

function validateOneRecord(
  record: KycRecord,
  rowNum: number,
  m: Config['mapping'],
  defInvestor: InvestorTypeName,
  defSoft: number,
  defHard: number,
): Outcome {
  // Best-effort wallet for the failure row even when validation fails.
  const walletRaw = record[m.walletAddressField];
  const walletForReport =
    typeof walletRaw === 'string' ? walletRaw.trim() : '';

  try {
    if (!walletRaw || typeof walletRaw !== 'string') {
      return {
        error: {
          rowNum,
          walletAddress: walletForReport,
          errorCode: 'E_INPUT',
          message: `missing wallet address (field "${m.walletAddressField}")`,
        },
      };
    }
    const walletTrim = walletRaw.trim();
    if (!ethers.utils.isAddress(walletTrim)) {
      return {
        error: {
          rowNum,
          walletAddress: walletForReport,
          errorCode: 'E_INPUT',
          message: `invalid wallet address "${walletTrim}"`,
        },
      };
    }
    const walletAddress = ethers.utils.getAddress(walletTrim);

    const countryRaw = normalizeValue(record[m.countryField]);
    if (!countryRaw || countryRaw.length < 2) {
      return {
        error: {
          rowNum,
          walletAddress,
          errorCode: 'E_INPUT',
          message: `missing or invalid country (field "${m.countryField}")`,
        },
      };
    }
    const country = countryRaw.toUpperCase().slice(0, 3);

    const investorType = m.investorTypeField
      ? resolveInvestorType(record[m.investorTypeField], defInvestor)
      : defInvestor;

    const softExpiryDays = m.softExpiryDaysField
      ? resolveExpiryDays(record[m.softExpiryDaysField], defSoft)
      : defSoft;

    const hardExpiryDays = m.hardExpiryDaysField
      ? resolveExpiryDays(record[m.hardExpiryDaysField], defHard)
      : defHard;

    if (hardExpiryDays > 0 && softExpiryDays > 0 && softExpiryDays > hardExpiryDays) {
      return {
        error: {
          rowNum,
          walletAddress,
          errorCode: 'E_INPUT',
          message: `softExpiryDays (${softExpiryDays}) cannot exceed hardExpiryDays (${hardExpiryDays})`,
        },
      };
    }

    return {
      value: {
        rowNum,
        walletAddress,
        country,
        investorType,
        softExpiryDays,
        hardExpiryDays,
        record,
      },
    };
  } catch (err) {
    return {
      error: {
        rowNum,
        walletAddress: walletForReport,
        errorCode: 'E_INPUT',
        message: (err as Error).message,
      },
    };
  }
}
