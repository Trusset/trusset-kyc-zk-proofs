// Build the JSON job spec passed to `trusset-prover` on stdin
// (plan §"TS ↔ Rust IPC"). Each subject's leaves are constructed from the
// validated record + the resolved predicate plan. List_commitments are
// embedded inline so the prover doesn't need filesystem access for them.

import { ResolvedConfig, ResolvedList } from './config';
import { ValidatedRecord } from './recordValidation';
import { computeParamsHash, ageDaysFromParams } from './paramsHash';
import { PredicateSpec } from './types';
import * as path from 'path';

export interface JobLeaf {
  field: string;
  circuit: string;
  value: unknown;
  public: Record<string, unknown>;
  params_hash: string;
}

export interface JobSubject {
  subject_id: string;
  passthrough: Record<string, unknown>;
  leaves: JobLeaf[];
}

export interface JobListCommitment {
  values: string[];
  source_sha256: string;
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
}

export function buildJob(
  records: ValidatedRecord[],
  rc: ResolvedConfig,
  outputRoot: string,
  opts: BuildJobOptions = {},
): Job {
  return {
    version: '2.0.0',
    deterministic: rc.deterministic,
    epoch_days: resolveEpochDays(rc),
    output_root: path.resolve(outputRoot),
    config_hash: rc.configHashHex,
    skip_proofs: !!opts.skipProofs,
    subjects: records.map((r) => buildSubject(r, rc)),
    list_commitments: buildListCommitments(rc),
  };
}

function buildSubject(record: ValidatedRecord, rc: ResolvedConfig): JobSubject {
  const passthrough: Record<string, unknown> = {
    country: record.country,
    investorType: record.investorType,
    softExpiryDays: record.softExpiryDays,
    hardExpiryDays: record.hardExpiryDays,
  };

  const leaves: JobLeaf[] = [];

  // Order: explicit mapping.fields first, then special fields (country,
  // investorType) if they have predicates. The prover re-orders by
  // lex(leafHash) for the Merkle tree, so this initial order doesn't
  // affect the bundle output — it only affects readability of the job spec.
  const eligibleFields = new Set<string>(rc.raw.mapping.fields);
  if (rc.predicates.country) eligibleFields.add('country');
  if (rc.predicates.investorType) eligibleFields.add('investorType');

  for (const field of eligibleFields) {
    const predicate = rc.predicates[field];
    if (!predicate) continue;
    leaves.push(buildLeaf(field, predicate, record, rc));
  }

  return {
    subject_id: record.walletAddress,
    passthrough,
    leaves,
  };
}

function buildLeaf(
  field: string,
  predicate: PredicateSpec,
  record: ValidatedRecord,
  rc: ResolvedConfig,
): JobLeaf {
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
      throw new Error(
        `Record ${record.rowNum}: missing value for predicate field "${field}"`,
      );
    }
    value = raw;
  }

  const publicInputs: Record<string, unknown> = {};
  switch (predicate.circuit) {
    case 'age_threshold':
      publicInputs.min_age_days = Number(ageDaysFromParams(predicate.params));
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
      break;
    }
    case 'set_membership':
      publicInputs.list_id = predicate.params.list;
      break;
    case 'preimage_knowledge':
      // no extra public inputs
      break;
  }

  return {
    field,
    circuit: predicate.circuit,
    value,
    public: publicInputs,
    params_hash,
  };
}

function buildListCommitments(rc: ResolvedConfig): Record<string, JobListCommitment> {
  const out: Record<string, JobListCommitment> = {};
  for (const [id, list] of Object.entries(rc.lists)) {
    out[id] = {
      values: list.values,
      source_sha256: list.sourceSha256,
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
