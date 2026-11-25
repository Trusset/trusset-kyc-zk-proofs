// Build the JSON job spec passed to `trusset-prover` on stdin
// (plan §"TS ↔ Rust IPC"). Each subject's leaves are constructed from the
// validated record + the resolved predicate plan. List_commitments are
// embedded inline so the prover doesn't need filesystem access for them.

import { isV31, isV3Family, ResolvedConfig, ResolvedList } from './config';
import { ValidatedRecord } from './recordValidation';
import { computeParamsHash, ageDaysFromParams, resolveTier } from './paramsHash';
import { parseDateToEpochDays } from './dates';
import { resolveDescriptor, resolveValidity } from './descriptors';
import {
  Disclosure,
  IssuerConfig,
  PredicateInstance,
  PredicateSpec,
  ResolvedDescriptor,
  ResolvedValidity,
} from './types';
import * as path from 'path';

/** Which version of which list a set_membership proof was made against. */
export interface JobListVersionRef {
  listId: string;
  version: number;
  root: string;
  contentHash: string;
}

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
  /** v3: what legal test this predicate stands for and who warrants it. */
  descriptor?: ResolvedDescriptor;
  /** v3: how long the assertion holds. */
  validity?: ResolvedValidity;
  /** v3: the list version, for set_membership leaves. */
  list_version?: JobListVersionRef;
  /** v3.1: the hub predicate this leaf proves. */
  predicate?: string;
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
  /** v3 registry version and content hash; both cross-checked by the prover. */
  version?: number;
  content_hash?: string;
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
  /** v3: the expression that produced `epoch_days`, recorded in the manifest. */
  epoch_days_source?: string;
  /** v3: set when the operator opted into an unpinned wall-clock epoch. */
  unpinned_epoch: boolean;
  /** v3: the party legally responsible for the assertions. */
  issuer?: IssuerConfig & { publicKey: string };
  /** v3: validate everything and write nothing. */
  dry_run: boolean;
  /** v3.1: the hub attestation every bundle is bound to. */
  chain?: { attester: string; chainId: number; hub: string; keyId: number };
}

export interface BuildJobOptions {
  skipProofs?: boolean;
  deterministic?: boolean;
  /** Validate every leaf and write nothing. */
  dryRun?: boolean;
  /**
   * The operator's ed25519 public key, hex. Recorded in the manifest's issuer
   * block so a counterparty knows which key to obtain, and so an archived
   * bundle carries the key its signature should check against.
   */
  publicKeyHex?: string;
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
      if (err instanceof QuarantineError) {
        skipped.push({
          walletAddress: err.walletAddress,
          rowNum: err.rowNum,
          errorCode: err.code,
          message: err.message,
        });
        continue;
      }
      throw err;
    }
  }

  // The public key is only available once the signing key is loaded. A dry
  // run does not need it — nothing is signed — so the issuer identity still
  // travels, with the key left empty rather than the whole block dropped.
  const issuer = rc.issuer
    ? { ...rc.issuer, publicKey: opts.publicKeyHex ? normalizeHex(opts.publicKeyHex) : '' }
    : undefined;

  return {
    job: {
      version: rc.manifestVersion,
      deterministic: opts.deterministic ?? rc.deterministic,
      epoch_days: rc.epochDays,
      output_root: path.resolve(outputRoot),
      config_hash: rc.configHashHex,
      skip_proofs: !!opts.skipProofs,
      subjects,
      list_commitments: buildListCommitments(rc),
      epoch_days_source: rc.epochDaysSource,
      unpinned_epoch: rc.unpinnedEpoch,
      issuer,
      dry_run: !!opts.dryRun,
      ...(rc.chain ? { chain: { ...rc.chain } } : {}),
    },
    skipped,
  };
}

function normalizeHex(hex: string): string {
  const stripped = hex.trim().replace(/^0x/i, '').toLowerCase();
  return `0x${stripped}`;
}

function buildSubject(record: ValidatedRecord, rc: ResolvedConfig): JobSubject {
  const v31 = isV31(rc.manifestVersion);
  // 3.1.0 carries no personal value in clear text: country and investor type
  // become predicate leaves, and only the expiry settings travel as they are.
  const passthrough: Record<string, unknown> = v31
    ? { softExpiryDays: record.softExpiryDays, hardExpiryDays: record.hardExpiryDays }
    : {
        country: record.country,
        investorType: record.investorType,
        softExpiryDays: record.softExpiryDays,
        hardExpiryDays: record.hardExpiryDays,
      };

  const subjectTier = (rc.tiers as Record<string, number | undefined>)[record.investorType];
  if (v31) {
    if (!subjectTier || subjectTier < 1 || subjectTier > 3) {
      throw new QuarantineError(
        record.walletAddress,
        record.rowNum,
        'E_TIER_NONE',
        `Record ${record.rowNum}: investor type ${record.investorType} cannot be attested. The hub records a class of RETAIL, PROFESSIONAL or ELIGIBLE_COUNTERPARTY. Fix: set the investorType column, or the output.defaults.investorType default.`,
      );
    }
    if (
      record.softExpiryDays > 0 &&
      record.hardExpiryDays > 0 &&
      record.softExpiryDays >= record.hardExpiryDays
    ) {
      throw new QuarantineError(
        record.walletAddress,
        record.rowNum,
        'E_INPUT',
        `Record ${record.rowNum}: softExpiryDays (${record.softExpiryDays}) must be below hardExpiryDays (${record.hardExpiryDays}); the hub refuses the attestation otherwise.`,
      );
    }
  }

  // One leaf per resolved predicate instance. The prover re-orders by
  // lex(leafHash) for the Merkle tree, so this order affects only the
  // readability of the job spec. An optional 3.1.0 predicate the subject does
  // not meet is left out: the attestation then simply lacks that bit.
  const leaves: JobLeaf[] = [];
  for (const inst of rc.instances) {
    if (v31 && inst.spec.optional && !predicateHolds(inst, record, rc, subjectTier)) continue;
    leaves.push(buildLeaf(inst, record, rc, subjectTier));
  }

  return {
    subject_id: record.walletAddress,
    passthrough,
    leaves,
  };
}

/** The witness value a predicate instance reads, or undefined when absent. */
function witnessValue(field: string, record: ValidatedRecord): unknown {
  if (field === 'country') return record.country || undefined;
  if (field === 'investorType') return record.investorType;
  const raw = record.record[field];
  return raw === null || raw === undefined || raw === '' ? undefined : raw;
}

/**
 * Whether the subject's value satisfies an instance's predicate, evaluated the
 * way the prover will. Used only to leave out optional 3.1.0 leaves; a
 * required leaf always goes to the prover, which reports the failure.
 */
function predicateHolds(
  inst: PredicateInstance,
  record: ValidatedRecord,
  rc: ResolvedConfig,
  subjectTier: number | undefined,
): boolean {
  const value = witnessValue(inst.field, record);
  if (value === undefined) return false;
  const spec = inst.spec;
  switch (spec.circuit) {
    case 'set_membership': {
      const list = rc.lists[spec.params.list];
      return !!list && list.values.includes(String(value).trim().normalize('NFC'));
    }
    case 'age_threshold': {
      let dob: number;
      try {
        dob = typeof value === 'number' ? value : parseDateToEpochDays(String(value), inst.leafName);
      } catch {
        return false;
      }
      return rc.epochDays - dob >= Number(ageDaysFromParams(spec.params));
    }
    case 'tier_threshold':
      return (
        subjectTier !== undefined && subjectTier >= resolveTier(spec.params.minTier, rc, subjectTier)
      );
    default:
      return true;
  }
}

function buildLeaf(
  instance: PredicateInstance,
  record: ValidatedRecord,
  rc: ResolvedConfig,
  subjectTier?: number,
): JobLeaf {
  const { field, leafName, spec: predicate } = instance;
  const params_hash = computeParamsHash(field, predicate, rc, subjectTier);

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
      } else if (min === 'ATTESTED') {
        publicInputs.min_tier = resolveTier(min, rc, subjectTier);
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
      // 3.1.0 leaves carry exactly the parameters the proof binds; the list
      // version (with its content hash) is in the binding block instead.
      if (!isV31(rc.manifestVersion)) {
        params.sourceSha256 = rc.lists[predicate.params.list]?.sourceSha256 ?? null;
      }
      break;
    case 'preimage_knowledge':
    case 'commitment_only':
      // no extra public inputs
      params.maxValueBytes = predicate.params?.maxValueBytes ?? 128;
      break;
  }

  // v3 claim descriptor and validity. Emitted only when the run targets the
  // 3.0.0 wire version, so a config still pinned to 2.1.0 keeps producing
  // exactly the bundle shape it always did.
  let descriptor: ResolvedDescriptor | undefined;
  let validity: ResolvedValidity | undefined;
  let listVersion: JobListVersionRef | undefined;
  if (isV3Family(rc.manifestVersion)) {
    descriptor = resolveDescriptor(leafName, predicate, rc.claims?.defaults, rc.issuer!);
    validity = resolveValidity(
      leafName,
      predicate,
      rc.claims?.defaults,
      rc.epochDays,
      record.evidenceDate,
    );
    if (predicate.circuit === 'set_membership') {
      const list = rc.lists[predicate.params.list];
      if (list?.version === undefined || list.contentHash === undefined) {
        throw new Error(
          [
            `predicates.${leafName}: list "${predicate.params.list}" has no registry version, so this leaf could not record which version it was proved against.`,
            `  Without that, a verifier holding the bundle years from now cannot resolve its setRoot back to the values it committed to.`,
            `  Fix: npm run list-version -- --list-id ${predicate.params.list} --source <the source .txt>`,
          ].join('\n'),
        );
      }
      listVersion = {
        listId: list.listId,
        version: list.version,
        root: list.root,
        contentHash: list.contentHash,
      };
    }
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
    ...(descriptor ? { descriptor } : {}),
    ...(validity ? { validity } : {}),
    ...(listVersion ? { list_version: listVersion } : {}),
    ...(isV31(rc.manifestVersion) && predicate.predicate ? { predicate: predicate.predicate } : {}),
  };
}

/** A row that cannot become a subject for a reason other than a missing value. */
export class QuarantineError extends Error {
  readonly walletAddress: string;
  readonly rowNum: number;
  readonly code: string;
  constructor(walletAddress: string, rowNum: number, code: string, message: string) {
    super(message);
    this.name = 'QuarantineError';
    this.walletAddress = walletAddress;
    this.rowNum = rowNum;
    this.code = code;
  }
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
      ...(list.version !== undefined ? { version: list.version } : {}),
      ...(list.contentHash !== undefined ? { content_hash: list.contentHash } : {}),
    };
  }
  return out;
}

// Re-export for tests/cli.
export function buildListCommitmentsForTest(
  lists: Record<string, ResolvedList>,
): Record<string, JobListCommitment> {
  const fakeRc = { lists } as unknown as ResolvedConfig;
  return buildListCommitments(fakeRc);
}
