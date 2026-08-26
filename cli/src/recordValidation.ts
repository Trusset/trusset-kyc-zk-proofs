// Wallet + country + investor + expiry validation, lifted from v1
// src/hash.ts:90-152 with one structural change: per-record errors are
// collected, not thrown. This implements plan edge case 4 ("partial batch
// failure") — one bad row no longer kills a 10k-row batch.

import { getAddress, isAddress } from './address';
import { parseDateToEpochDays } from './dates';
import { Config, InvestorTypeName, KycFieldValue, KycRecord } from './types';

const INVESTOR_TYPES: InvestorTypeName[] = ['NONE', 'RETAIL', 'PROFESSIONAL', 'ELIGIBLE_COUNTERPARTY'];
const MAX_EXPIRY_DAYS = 36500;

export function normalizeValue(value: KycFieldValue): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    throw new Error(
      'the value is an object or array. Fix: field values must be strings, numbers, or booleans.',
    );
  }
  return String(value).trim();
}

/**
 * Resolve an investor type, or report why it could not be resolved.
 *
 * An absent value takes the configured default: the operator has said what a
 * blank column means. A *present but unrecognised* value is a failure, not a
 * default. Substituting RETAIL for a mistyped "PROFESSIONAL_INVESTOR" produces
 * a signed bundle asserting a tier the operator never declared, and under
 * MiFID II retail and professional are different regulatory regimes. The tool
 * produces evidence; quietly rewriting the evidence is worse than refusing.
 */
export function resolveInvestorType(
  value: KycFieldValue,
  fallback: InvestorTypeName,
  fieldName: string,
): { value: InvestorTypeName } | { error: string } {
  if (value === null || value === undefined || value === '') return { value: fallback };
  if (typeof value !== 'string') {
    return {
      error: `field "${fieldName}" is ${typeof value}, not a string. Fix: use one of ${INVESTOR_TYPES.join(', ')}.`,
    };
  }
  const upper = value.toUpperCase().trim() as InvestorTypeName;
  if (!INVESTOR_TYPES.includes(upper)) {
    return {
      error: `field "${fieldName}" is "${value}", which is not a recognised investor type. Fix: use one of ${INVESTOR_TYPES.join(', ')}, or leave the column blank to take the configured default (${fallback}).`,
    };
  }
  return { value: upper };
}

/**
 * Resolve an expiry-day count, or report why it could not be resolved. Same
 * reasoning as `resolveInvestorType`: blank means "use the default", but a
 * value that is present and unusable is a failure rather than a silent
 * substitution.
 */
export function resolveExpiryDays(
  value: KycFieldValue,
  fallback: number,
  fieldName: string,
): { value: number } | { error: string } {
  if (value === null || value === undefined || value === '') return { value: fallback };
  const num = Number(value);
  if (!Number.isFinite(num)) {
    return {
      error: `field "${fieldName}" is "${value}", which is not a number. Fix: supply a whole number of days between 0 and ${MAX_EXPIRY_DAYS}, or leave it blank for the default (${fallback}).`,
    };
  }
  if (num < 0 || num > MAX_EXPIRY_DAYS) {
    return {
      error: `field "${fieldName}" is ${num}, which is outside 0..${MAX_EXPIRY_DAYS} days. Fix: supply a value in range, or leave it blank for the default (${fallback}).`,
    };
  }
  return { value: Math.floor(num) };
}

export interface ValidatedRecord {
  rowNum: number;
  walletAddress: string;
  country: string;
  investorType: InvestorTypeName;
  softExpiryDays: number;
  hardExpiryDays: number;
  /**
   * v3: `epochDays` on which this subject's evidence was examined, from the
   * configured evidence-date column. Absent when the column is not present,
   * in which case the per-predicate offset applies.
   */
  evidenceDate?: number;
  record: KycRecord;
}

export interface ValidationFailure {
  rowNum: number;
  /** Best-effort wallet display string. Empty if the wallet field is missing or malformed. */
  walletAddress: string;
  /** Stable error code matching the prover's E_* codes where applicable. */
  errorCode: string;
  message: string;
  /** The input column the failure is about, when it is about one. */
  field?: string;
}

export interface ValidationOutcome {
  valid: ValidatedRecord[];
  failed: ValidationFailure[];
}

/**
 * Validate a batch of records, collecting per-row failures instead of
 * throwing on the first error. Plan §"Resolved edge cases" item 4.
 */
export function validateRecords(
  records: KycRecord[],
  config: Config,
  evidenceDateField = 'evidenceDate',
): ValidationOutcome {
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
      evidenceDateField,
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
  evidenceDateField: string,
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
          field: m.walletAddressField,
          message: `field "${m.walletAddressField}" is missing or not a string. Fix: supply a 0x-prefixed 40-hex Ethereum address for this row.`,
        },
      };
    }
    const walletTrim = walletRaw.trim();
    if (!isAddress(walletTrim)) {
      return {
        error: {
          rowNum,
          walletAddress: walletForReport,
          errorCode: 'E_INPUT',
          field: m.walletAddressField,
          message: `field "${m.walletAddressField}" is "${walletTrim}", which is not a valid Ethereum address. Fix: supply a 0x-prefixed 40-hex address; mixed-case addresses must have a correct EIP-55 checksum.`,
        },
      };
    }
    const walletAddress = getAddress(walletTrim);

    const countryRaw = normalizeValue(record[m.countryField]);
    if (!countryRaw || countryRaw.length < 2) {
      return {
        error: {
          rowNum,
          walletAddress,
          errorCode: 'E_INPUT',
          field: m.countryField,
          message: `field "${m.countryField}" is missing or shorter than two characters. Fix: supply an ISO 3166-1 alpha-3 country code, e.g. DEU.`,
        },
      };
    }
    const country = countryRaw.toUpperCase().slice(0, 3);

    let investorType = defInvestor;
    if (m.investorTypeField) {
      const outcome = resolveInvestorType(
        record[m.investorTypeField],
        defInvestor,
        m.investorTypeField,
      );
      if ('error' in outcome) {
        return {
          error: {
            rowNum,
            walletAddress,
            errorCode: 'E_INPUT',
            field: m.investorTypeField,
            message: outcome.error,
          },
        };
      }
      investorType = outcome.value;
    }

    let softExpiryDays = defSoft;
    if (m.softExpiryDaysField) {
      const outcome = resolveExpiryDays(record[m.softExpiryDaysField], defSoft, m.softExpiryDaysField);
      if ('error' in outcome) {
        return {
          error: {
            rowNum,
            walletAddress,
            errorCode: 'E_INPUT',
            field: m.softExpiryDaysField,
            message: outcome.error,
          },
        };
      }
      softExpiryDays = outcome.value;
    }

    let hardExpiryDays = defHard;
    if (m.hardExpiryDaysField) {
      const outcome = resolveExpiryDays(record[m.hardExpiryDaysField], defHard, m.hardExpiryDaysField);
      if ('error' in outcome) {
        return {
          error: {
            rowNum,
            walletAddress,
            errorCode: 'E_INPUT',
            field: m.hardExpiryDaysField,
            message: outcome.error,
          },
        };
      }
      hardExpiryDays = outcome.value;
    }

    let evidenceDate: number | undefined;
    const evidenceRaw = record[evidenceDateField];
    if (evidenceRaw !== null && evidenceRaw !== undefined && evidenceRaw !== '') {
      try {
        evidenceDate = parseDateToEpochDays(String(evidenceRaw), `field "${evidenceDateField}"`);
      } catch (e) {
        return {
          error: {
            rowNum,
            walletAddress,
            errorCode: 'E_INPUT',
            field: evidenceDateField,
            message: `${(e as Error).message} Fix: use YYYY-MM-DD, or remove the column to take the configured offset.`,
          },
        };
      }
    }

    if (hardExpiryDays > 0 && softExpiryDays > 0 && softExpiryDays > hardExpiryDays) {
      return {
        error: {
          rowNum,
          walletAddress,
          errorCode: 'E_INPUT',
          field: m.softExpiryDaysField,
          message: `softExpiryDays (${softExpiryDays}) exceeds hardExpiryDays (${hardExpiryDays}). Fix: a soft expiry is a review prompt before the hard one, so it must come first.`,
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
        ...(evidenceDate !== undefined ? { evidenceDate } : {}),
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
