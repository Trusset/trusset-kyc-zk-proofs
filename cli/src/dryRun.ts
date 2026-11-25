// `--dry-run`: validate an entire batch and report every problem at once.
//
// The proving path stops at the first bad leaf of a subject, which is right
// when the output is a bundle — there is nothing to write once one leaf fails.
// It is wrong when the question is "what is wrong with my batch", because it
// turns one review pass into as many passes as there are broken rows. A dry
// run collects every failure from every stage: file parsing, TypeScript
// validation, job construction, and the prover's own witness and predicate
// checks.

import { ResolvedConfig } from './config';
import { ValidationFailure } from './recordValidation';
import { ProverEvent } from './spawnProver';
import { SkippedRecord } from './jobSpec';
import { epochDaysToIsoDate } from './dates';

export type ProblemStage = 'validation' | 'job' | 'prover';

export interface Problem {
  stage: ProblemStage;
  rowNum?: number;
  walletAddress: string;
  /** Input column or leaf name the problem is about. */
  field?: string;
  errorCode: string;
  message: string;
}

export interface DryRunReport {
  subjectsSeen: number;
  subjectsClean: number;
  problems: Problem[];
  epochDays: number;
  asOfDate: string;
  manifestVersion: string;
  wouldProduceBundles: number;
}

export function problemsFromValidation(failures: ValidationFailure[]): Problem[] {
  return failures.map((f) => ({
    stage: 'validation' as const,
    rowNum: f.rowNum,
    walletAddress: f.walletAddress,
    field: f.field,
    errorCode: f.errorCode,
    message: f.message,
  }));
}

export function problemsFromSkipped(skipped: SkippedRecord[]): Problem[] {
  return skipped.map((s) => ({
    stage: 'job' as const,
    rowNum: s.rowNum,
    walletAddress: s.walletAddress,
    errorCode: s.errorCode,
    message: s.message,
  }));
}

/**
 * Collect the per-leaf problems a dry-run prover emits. Unlike the proving
 * path, several `leaf_failed` events arrive per subject; the trailing
 * `subject_failed` is a count, not a distinct problem, so it is dropped.
 */
export function problemsFromProver(events: ProverEvent[]): Problem[] {
  const out: Problem[] = [];
  for (const e of events) {
    if (e.event === 'leaf_failed') {
      out.push({
        stage: 'prover',
        walletAddress: e.subject_id,
        field: e.field || undefined,
        errorCode: e.error_code,
        message: e.message,
      });
    }
  }
  return out;
}

export function buildDryRunReport(
  rc: ResolvedConfig,
  subjectsSeen: number,
  problems: Problem[],
): DryRunReport {
  const broken = new Set(problems.map((p) => p.walletAddress).filter(Boolean));
  const clean = Math.max(0, subjectsSeen - broken.size);
  return {
    subjectsSeen,
    subjectsClean: clean,
    problems,
    epochDays: rc.epochDays,
    asOfDate: epochDaysToIsoDate(rc.epochDays),
    manifestVersion: rc.manifestVersion,
    wouldProduceBundles: clean,
  };
}

const STAGE_LABEL: Record<ProblemStage, string> = {
  validation: 'input',
  job: 'config',
  prover: 'predicate',
};

export function formatDryRunReport(report: DryRunReport): string {
  const lines: string[] = [];
  lines.push(`Dry run: nothing was written.`);
  lines.push(
    `Batch as-of date ${report.asOfDate} (epoch day ${report.epochDays}), manifest version ${report.manifestVersion}.`,
  );
  lines.push('');

  if (report.problems.length === 0) {
    lines.push(`All ${report.subjectsSeen} subject(s) would produce a bundle.`);
    return lines.join('\n');
  }

  // Group by subject so an operator fixing one row sees everything wrong with
  // it at once, rather than one problem per run.
  const bySubject = new Map<string, Problem[]>();
  for (const p of report.problems) {
    const key = p.walletAddress || `<row ${p.rowNum ?? '?'}>`;
    const list = bySubject.get(key) ?? [];
    list.push(p);
    bySubject.set(key, list);
  }

  for (const [subject, problems] of bySubject) {
    const row = problems.find((p) => p.rowNum !== undefined)?.rowNum;
    lines.push(`${subject}${row !== undefined ? `  (input row ${row})` : ''}`);
    for (const p of problems) {
      const where = p.field ? ` ${p.field}` : '';
      lines.push(`  [${STAGE_LABEL[p.stage]}]${where}  ${p.errorCode}`);
      for (const line of p.message.split('\n')) {
        lines.push(`      ${line.trim()}`);
      }
    }
    lines.push('');
  }

  lines.push(
    `${report.problems.length} problem(s) across ${bySubject.size} subject(s); ${report.wouldProduceBundles} of ${report.subjectsSeen} would produce a bundle.`,
  );
  return lines.join('\n');
}
