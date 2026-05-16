// v1-compatible batched index CSV/JSON writer + failures.csv emitter.
//
// The Rust prover writes per-subject bundle directories. This module
// produces the top-level summary file that legacy Trusset uploaders
// expect (single row per subject with `walletAddress, country,
// investorType, softExpiryDays, hardExpiryDays, kycHash`) and the
// failures.csv with a `stage` column distinguishing validation vs
// prover failures (plan §"Resolved edge cases" item 4).

import * as fs from 'fs';
import * as path from 'path';
import { ResolvedConfig } from './config';
import { ValidatedRecord, ValidationFailure } from './recordValidation';
import { writeIndexFile, outputDir } from './utils';
import { IndexRow } from './types';
import { ProverEvent } from './spawnProver';

export interface BundleSummary {
  walletAddress: string;
  bundlePath: string;
  kycHash: string;
}

/** Read the kycHash.hex written by the prover for a given subject. */
export function readKycHashFromBundle(bundlePath: string): string {
  const file = path.join(bundlePath, 'kycHash.hex');
  return fs.readFileSync(file, 'utf-8').trim();
}

export function buildIndexRows(
  records: ValidatedRecord[],
  successes: BundleSummary[],
  raw: boolean,
  includeIndex: boolean,
): IndexRow[] {
  const successByWallet = new Map<string, BundleSummary>();
  for (const s of successes) successByWallet.set(s.walletAddress, s);

  const out: IndexRow[] = [];
  let i = 1;
  for (const r of records) {
    const s = successByWallet.get(r.walletAddress);
    if (!s) continue; // skipped: this row's subject failed in the prover
    const row: IndexRow = {
      walletAddress: r.walletAddress,
      country: r.country,
      investorType: r.investorType,
      softExpiryDays: r.softExpiryDays,
      hardExpiryDays: r.hardExpiryDays,
      kycHash: s.kycHash,
    };
    if (includeIndex && !raw) row.index = i++;
    out.push(row);
  }
  return out;
}

export function writeBatchedIndex(
  rows: IndexRow[],
  config: ResolvedConfig,
  raw: boolean,
): string {
  const emit = config.raw.output.emitIndexCsv ?? true;
  if (!emit) return '';
  return writeIndexFile(rows, config.raw, raw ? '_raw' : '');
}

export type FailureStage = 'validation' | 'prover';

export interface FailureRow {
  walletAddress: string;
  stage: FailureStage;
  errorCode: string;
  message: string;
}

/** Convert validation failures into failure rows. */
export function failuresFromValidation(failures: ValidationFailure[]): FailureRow[] {
  return failures.map((f) => ({
    walletAddress: f.walletAddress,
    stage: 'validation',
    errorCode: f.errorCode,
    message: f.message,
  }));
}

/** Collect prover-side failures from an NDJSON event stream. */
export function failuresFromProver(events: ProverEvent[]): FailureRow[] {
  const out: FailureRow[] = [];
  for (const e of events) {
    if (e.event === 'subject_failed') {
      out.push({
        walletAddress: e.subject_id,
        stage: 'prover',
        errorCode: e.error_code,
        message: e.message,
      });
    }
  }
  return out;
}

/**
 * Write `output/failures.csv` (or remove it if no failures). Headers are
 * fixed; row order preserves input order: validation failures first (in
 * row-number order), then prover failures (in dispatch order).
 */
export function writeFailures(failures: FailureRow[]): string | null {
  const filePath = path.join(outputDir(), 'failures.csv');
  if (failures.length === 0) {
    // Clean up any prior run's failures.csv so stale state doesn't confuse.
    try {
      fs.unlinkSync(filePath);
    } catch {
      /* ignore */
    }
    return null;
  }
  const header = 'walletAddress,stage,errorCode,message\n';
  const body = failures
    .map((f) =>
      [
        f.walletAddress,
        f.stage,
        f.errorCode,
        `"${f.message.replace(/"/g, '""')}"`,
      ].join(','),
    )
    .join('\n');
  fs.writeFileSync(filePath, header + body + '\n');
  return filePath;
}
