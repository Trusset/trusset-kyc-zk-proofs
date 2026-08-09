// Build the JSON job spec passed to `trusset-prover` on stdin
// (plan §"TS ↔ Rust IPC"). Each subject's leaves are constructed from the
// validated record + the resolved predicate plan. List_commitments are
// embedded inline so the prover doesn't need filesystem access for them.

import { ResolvedConfig, ResolvedList } from './config';
import { ValidatedRecord } from './recordValidation';
import { computeParamsHash, ageDaysFromParams } from './paramsHash';
import { Disclosure, PredicateInstance, PredicateSpec } from './types';
import * as path from 'path';

export interface JobLeaf {
  /** Leaf name. Equals the source field for single-instance predicates. */
  field: string;
  circuit: string;
  value: unknown;
  public: Record<string, unknown>;
  params_hash: string;
  disclosure: Disclosure;
  /** Resolved parameter values recorded in `manifest.leaves[].params`. */
  params: Record<string, unknown>;
}

export interface JobSubject {
  subject_id: string;
  passthrough: Record<string, unknown>;
  leaves: JobLeaf[];
}

export interface JobListCommitment {
  values: string[];
  source_sha256: string;
  /** Root the committed file declares; the prover cross-checks it. */
  declared_root?: string;
  declared_depth?: number;
}

export interface Job {
  version: string;
  deterministic: boolean;
  epoch_days: number;
  output_root: string;
  config_hash: string;
  skip_proofs: boolean;
  subjects: JobSubject[];
  list_commitments: Record<string, JobListCommitment>;
}

export interface BuildJobOptions {
  skipProofs?: boolean;
  deterministic?: boolean;
}

/** A row that could not be turned into a subject, with the reason. */
export interface SkippedRecord {
  walletAddress: string;
  rowNum: number;
  errorCode: string;
  message: string;
}

export interface BuiltJob {
  job: Job;
  /** Rows quarantined while building leaves; the batch continues without them. */
  skipped: SkippedRecord[];
}

export function buildJob(
  records: ValidatedRecord[],
  rc: ResolvedConfig,
  outputRoot: string,
  opts: BuildJobOptions = {},
): Job {
  return buildJobWithSkips(records, rc, outputRoot, opts).job;
}

/**
 * Build the job spec, quarantining rows whose witness values are missing
 * instead of aborting the whole batch.
 */
export function buildJobWithSkips(
  records: ValidatedRecord[],
  rc: ResolvedConfig,
  outputRoot: string,
  opts: BuildJobOptions = {},
): BuiltJob {
  const subjects: JobSubject[] = [];
  const skipped: SkippedRecord[] = [];
  for (const r of records) {
    try {
      subjects.push(buildSubject(r, rc));
    } catch (err) {
      if (err instanceof MissingWitnessError) {
        skipped.push({
          walletAddress: err.walletAddress,
          rowNum: err.rowNum,
          errorCode: 'E_INPUT',
          message: err.message,
        });
        continue;
      }
      throw err;
    }
  }

  return {
    job: {
      version: '2.1.0',
      deterministic: opts.deterministic ?? rc.deterministic,
      epoch_days: resolveEpochDays(rc),
      output_root: path.resolve(outputRoot),
      config_hash: rc.configHashHex,
      skip_proofs: !!opts.skipProofs,
      subjects,
      list_commitments: buildListCommitments(rc),
    },
    skipped,
  };
}

function buildSubject(record: ValidatedRecord, rc: ResolvedConfig): JobSubject {
  const passthrough: Record<string, unknown> = {
    country: record.country,
    investorType: record.investorType,
    softExpiryDays: record.softExpiryDays,
    hardExpiryDays: record.hardExpiryDays,
  };

  // One leaf per resolved predicate instance. The prover re-orders by
  // lex(leafHash) for the Merkle tree, so this order affects only the
  // readability of the job spec.
  const leaves: JobLeaf[] = rc.instances.map((inst) => buildLeaf(inst, record, rc));

  return {
    subject_id: record.walletAddress,
    passthrough,
    leaves,
  };
}

function buildLeaf(
  instance: PredicateInstance,
  record: ValidatedRecord,
  rc: ResolvedConfig,
): JobLeaf {
  const { field, leafName, spec: predicate } = instance;
  const params_hash = computeParamsHash(field, predicate, rc);

  // The witness `value` is sourced from the validated record for
  // mapping.fields entries, or directly from the special block for
  // country/investorType.
  let value: unknown;
  if (field === 'country') {
    value = record.country;
  } else if (field === 'investorType') {
    value = record.investorType;
  } else {
    const raw = record.record[field];
    if (raw === null || raw === undefined) {
      // Quarantine this row rather than aborting the batch: one record
      // missing an optional field must not take down every other subject.
      throw new MissingWitnessError(record.walletAddress, record.rowNum, field);
    }
    value = raw;
  }

  const publicInputs: Record<string, unknown> = {};
  const params: Record<string, unknown> = {};
  switch (predicate.circuit) {
    case 'age_threshold':
      publicInputs.min_age_days = Number(ageDaysFromParams(predicate.params));
      params.minAgeDays = publicInputs.min_age_days;
      break;
    case 'tier_threshold': {
      const min = predicate.params.minTier;
      if (typeof min === 'number') {
        publicInputs.min_tier = min;
      } else {
        const value = (rc.tiers as Record<string, number | undefined>)[min.toUpperCase()];
        if (value === undefined) {
          throw new Error(`tier_threshold(${field}): unknown tier name "${min}"`);
        }
        publicInputs.min_tier = value;
      }
      params.minTier = publicInputs.min_tier;
      break;
    }
    case 'set_membership':
      publicInputs.list_id = predicate.params.list;
      params.listId = predicate.params.list;
      params.sourceSha256 = rc.lists[predicate.params.list]?.sourceSha256 ?? null;
      break;
    case 'preimage_knowledge':
    case 'commitment_only':
      // no extra public inputs
      params.maxValueBytes = predicate.params?.maxValueBytes ?? 128;
      break;
  }

  return {
    field: leafName,
    // `commitment_only` leaves carry no STARK, but they keep the
    // preimage_knowledge circuit identity in the manifest so downstream
    // consumers that validate circuit names against a fixed set (the
    // issuer backend does) still accept the bundle. The mode is carried
    // by `disclosure`.
    circuit:
      predicate.circuit === 'commitment_only' ? 'preimage_knowledge' : predicate.circuit,
    value,
    public: publicInputs,
    params_hash,
    disclosure: instance.disclosure,
    params,
  };
}

/**
 * A record is missing a value a configured predicate needs. Carries the
 * wallet so the caller can quarantine just that row.
 */
export class MissingWitnessError extends Error {
  readonly walletAddress: string;
  readonly rowNum: number;
  readonly field: string;
  constructor(walletAddress: string, rowNum: number, field: string) {
    super(`Record ${rowNum}: missing value for predicate field "${field}"`);
    this.name = 'MissingWitnessError';
    this.walletAddress = walletAddress;
    this.rowNum = rowNum;
    this.field = field;
  }
}

function buildListCommitments(rc: ResolvedConfig): Record<string, JobListCommitment> {
  const out: Record<string, JobListCommitment> = {};
  for (const [id, list] of Object.entries(rc.lists)) {
    out[id] = {
      values: list.values,
      source_sha256: list.sourceSha256,
      declared_root: list.root,
      declared_depth: list.depth,
    };
  }
  return out;
}

function resolveEpochDays(rc: ResolvedConfig): number {
  const src = rc.epochDaysSource;
  if (src === 'utc_today') {
    return Math.floor(Date.now() / 86_400_000);
  }
  if (src.startsWith('fixed:')) {
    const n = Number(src.slice('fixed:'.length));
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(`epochDaysSource fixed:<n> requires a non-negative integer, got "${src}"`);
    }
    return n;
  }
  if (src.startsWith('env:')) {
    const name = src.slice('env:'.length);
    const v = process.env[name];
    if (!v) throw new Error(`epochDaysSource env:${name} — env var unset`);
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(`env var ${name} must be a non-negative integer, got "${v}"`);
    }
    return n;
  }
  throw new Error(`unknown epochDaysSource: ${src}`);
}

// Re-export for tests/cli.
export function buildListCommitmentsForTest(
  lists: Record<string, ResolvedList>,
): Record<string, JobListCommitment> {
  const fakeRc = { lists } as unknown as ResolvedConfig;
  return buildListCommitments(fakeRc);
}
