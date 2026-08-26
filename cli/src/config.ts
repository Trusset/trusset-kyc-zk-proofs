// v2 config validator and resolver.
//
// Backward-compatibility behavior:
//   - v1 keys (mapping.*, output.*, security.*) preserved.
//   - v2-only keys (predicates, tiers, lists, manifest, security.epochDaysSource,
//     ...) fall back to sane defaults if absent.
//   - The presence of v1's `security.hashAlgorithm` triggers a deprecation
//     warning but is otherwise ignored — v2 always uses Rescue-Prime.
//   - `set_membership` predicates require their list to be defined in
//     `config.lists.<id>` with a readable file; missing → fatal.

import * as fs from 'fs';
import * as path from 'path';
import { ageDaysFromParams } from './paramsHash';
import { epochDaysToIsoDate, todayEpochDays } from './dates';
import {
  loadListRegistry,
  listContentHash,
  registryRoot,
  resolveListAt,
  ListRegistry,
  ListVersionRecord,
} from './registry';
import { validateIssuer } from './descriptors';
import {
  CircuitName,
  ClaimsConfig,
  Config,
  Disclosure,
  EpochDaysSource,
  IssuerConfig,
  ListsEntry,
  PredicateEntry,
  PredicateInstance,
  PredicateSpec,
  Predicates,
  TierMap,
} from './types';

/** The manifest wire version this build emits unless the config pins another. */
export const DEFAULT_MANIFEST_VERSION = '3.0.0';
export const SUPPORTED_MANIFEST_VERSIONS = ['2.0.0', '2.1.0', '3.0.0'];

const CONFIG_PATH = path.join(process.cwd(), 'config.json');

export const DEFAULT_TIER_MAP: Required<TierMap> = {
  NONE: 0,
  RETAIL: 1,
  PROFESSIONAL: 2,
  ELIGIBLE_COUNTERPARTY: 3,
};

export const DEFAULT_PREDICATES_BY_FIELD: Record<string, PredicateSpec> = {
  dateOfBirth: { circuit: 'age_threshold', params: { minAgeYears: 18 } },
  nationality: { circuit: 'set_membership', params: { list: 'country_allowlist' } },
  documentIssuingCountry: { circuit: 'set_membership', params: { list: 'country_allowlist' } },
  country: { circuit: 'set_membership', params: { list: 'country_allowlist' } },
  documentType: { circuit: 'set_membership', params: { list: 'document_types' } },
  investorType: { circuit: 'tier_threshold', params: { minTier: 'RETAIL' } },
  firstName: { circuit: 'preimage_knowledge', params: { maxValueBytes: 128 } },
  lastName: { circuit: 'preimage_knowledge', params: { maxValueBytes: 128 } },
  documentNumber: { circuit: 'preimage_knowledge', params: { maxValueBytes: 128 } },
};

/** Effective per-field predicate plan, with all defaults applied. */
export type ResolvedPredicates = Record<string, PredicateSpec>;

/**
 * Flattened predicate instances in deterministic order. A field with a
 * single predicate yields one instance named after the field; a field with
 * several yields `<field>`, `<field>@<suffix>`, ... where the suffix is
 * derived from the resolved parameters so the name is stable across runs
 * and filesystem-safe.
 */
export type ResolvedInstances = PredicateInstance[];

export interface ResolvedConfig {
  raw: Config;
  predicates: ResolvedPredicates;
  /** One entry per leaf, including multi-instance predicates. */
  instances: ResolvedInstances;
  tiers: Required<TierMap>;
  /** Resolved list-commitment files keyed by listId. */
  lists: Record<string, ResolvedList>;
  /** `security.masterKeyEnv` resolved (defaults to TRUSSET_KYC_MASTER_KEY). */
  masterKeyEnv: string;
  /** `manifest.signingKeyEnv` resolved (defaults to TRUSSET_KYC_SIGNING_KEY). */
  signingKeyEnv: string;
  /** Epoch-days source resolved into a concrete u64 at job-spec time. */
  epochDaysSource: EpochDaysSource;
  /** `security.deterministic` resolved (default true). */
  deterministic: boolean;
  /** Cached SHA-256 hex of canonical config (the bytes the prover sees in HKDF). */
  configHashHex: string;
  /** Manifest wire version this run emits. */
  manifestVersion: string;
  /** v3 issuer block. Required when `manifestVersion` is 3.0.0. */
  issuer?: IssuerConfig;
  /** v3 claim defaults applied to every predicate. */
  claims?: ClaimsConfig;
  /** Absolute path to the registry root. */
  registryDir: string;
  /** Resolved batch as-of date in epochDays. */
  epochDays: number;
  /** True when the operator explicitly opted into an unpinned wall-clock epoch. */
  unpinnedEpoch: boolean;
  /** Input column carrying a per-subject evidence date, if configured. */
  evidenceDateField: string;
}

export interface ResolveOptions {
  /**
   * Allow `epochDaysSource: "utc_today"`. Off by default: a batch proved
   * against a wall-clock epoch cannot be reproduced after the day it ran,
   * because every per-subject key and every commitment derives from that
   * number.
   */
  allowUnpinnedEpoch?: boolean;
}

export interface ResolvedList {
  listId: string;
  /** Raw values from the list-commitments JSON or the registry version. */
  values: string[];
  /** SHA-256 of the source text file. */
  sourceSha256: string;
  /** Manifest-recorded Rescue Merkle root. */
  root: string;
  depth: number;
  /** Path the file was loaded from (for diagnostics). */
  resolvedPath: string;
  /**
   * v3: which registry version this resolved to, and the hash of its values.
   * Absent when the list came from a bare list-commitments file with no
   * registry behind it — in which case superseded versions are not retained
   * and an old proof's root cannot be resolved back to a set.
   */
  version?: number;
  contentHash?: string;
  effectiveFrom?: number;
  effectiveUntil?: number;
}

export function loadConfig(opts: ResolveOptions = {}): ResolvedConfig {
  if (!fs.existsSync(CONFIG_PATH)) {
    throw new Error(
      `config.json not found at ${CONFIG_PATH}.\n  Fix: run \`npm run init\` to generate one, or copy config.example.json and edit it.`,
    );
  }
  const text = fs.readFileSync(CONFIG_PATH, 'utf-8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`config.json: invalid JSON: ${(e as Error).message}`);
  }
  return resolveConfig(parsed as Config, opts);
}

export function resolveConfig(raw: Config, opts: ResolveOptions = {}): ResolvedConfig {
  validateV1Surface(raw);

  if (raw.security.hashAlgorithm && raw.security.hashAlgorithm !== 'rescue_prime') {
    // v1 keys honored for backwards-readability — emit one warning per run.
    console.warn(
      `[config] security.hashAlgorithm: "${raw.security.hashAlgorithm}" is deprecated; v2 uses rescue-prime unconditionally.`,
    );
  }

  const tiers = mergeTiers(raw.tiers);
  const predicates = resolvePredicates(raw);
  const instances = resolveInstances(raw, tiers);

  const masterKeyEnv = raw.security.masterKeyEnv || 'TRUSSET_KYC_MASTER_KEY';
  const signingKeyEnv = raw.manifest?.signingKeyEnv || 'TRUSSET_KYC_SIGNING_KEY';
  const epochDaysSource: EpochDaysSource = raw.security.epochDaysSource ?? 'utc_today';
  const deterministic = raw.security.deterministic ?? true;

  const manifestVersion = raw.manifest?.version ?? DEFAULT_MANIFEST_VERSION;
  if (!SUPPORTED_MANIFEST_VERSIONS.includes(manifestVersion)) {
    throw new Error(
      `manifest.version: "${manifestVersion}" is not a version this build emits.\n  Fix: use one of ${SUPPORTED_MANIFEST_VERSIONS.join(', ')}, or remove the field to emit ${DEFAULT_MANIFEST_VERSION}.`,
    );
  }

  const { epochDays, unpinnedEpoch } = resolveEpochDays(epochDaysSource, opts);

  const issuer = raw.manifest?.issuer;
  if (manifestVersion === '3.0.0') {
    if (!issuer) {
      throw new Error(
        'manifest.issuer: missing.\n  A version 3.0.0 bundle records the party legally responsible for its assertions; without it the bundle says what was proved but not who stands behind it.\n  Fix: run `npm run init` to configure it, or set manifest.version to "2.1.0" to keep emitting the previous bundle shape.',
      );
    }
    validateIssuer(issuer);
  }

  const registryDir = registryRoot(raw.security.registryDir);
  const lists = resolveLists(raw, instances, registryDir, epochDays, manifestVersion);
  const evidenceDateField = raw.mapping.evidenceDateField || 'evidenceDate';

  const configHashHex = canonicalConfigHash(raw);

  return {
    raw,
    predicates,
    instances,
    tiers,
    lists,
    masterKeyEnv,
    signingKeyEnv,
    epochDaysSource,
    deterministic,
    configHashHex,
    manifestVersion,
    issuer,
    claims: raw.claims,
    registryDir,
    epochDays,
    unpinnedEpoch,
    evidenceDateField,
  };
}

/**
 * Resolve the batch as-of date, refusing an unpinned wall-clock epoch unless
 * the operator explicitly asked for one.
 *
 * `epochDays` is folded into every per-subject key, every commitment nonce,
 * and every leaf hash. Under `utc_today` that number is whatever day the batch
 * happened to run, so the bundle cannot be regenerated tomorrow — and
 * regenerating it is exactly what an auditor asks for. The refusal is loud
 * because the alternative is a bundle that looks like evidence and cannot be
 * re-derived.
 */
export function resolveEpochDays(
  source: EpochDaysSource,
  opts: ResolveOptions = {},
): { epochDays: number; unpinnedEpoch: boolean } {
  if (source === 'utc_today') {
    const today = todayEpochDays();
    if (!opts.allowUnpinnedEpoch) {
      throw new Error(
        [
          'security.epochDaysSource is "utc_today", which resolves to whatever day this batch happens to run.',
          `  Today that is ${epochDaysToIsoDate(today)} (epoch day ${today}).`,
          '  Every per-subject key, commitment nonce, and leaf hash derives from that number, so a bundle',
          '  proved this way cannot be reproduced tomorrow and cannot satisfy an audit that asks you to.',
          `  Fix: set "epochDaysSource": "fixed:${today}" in config.json to pin today as the batch as-of date,`,
          '       or "env:TRUSSET_KYC_EPOCH_DAYS" to supply it per run.',
          '  For development only, re-run with --dev-unpinned-epoch. Bundles built that way are stamped',
          '  unpinnedEpoch in the manifest for the rest of their lives.',
        ].join('\n'),
      );
    }
    return { epochDays: today, unpinnedEpoch: true };
  }
  if (source.startsWith('fixed:')) {
    const n = Number(source.slice('fixed:'.length));
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(
        `security.epochDaysSource: "${source}" is malformed.\n  Fix: use "fixed:<non-negative integer epoch day>", e.g. "fixed:${todayEpochDays()}" for today.`,
      );
    }
    return { epochDays: n, unpinnedEpoch: false };
  }
  if (source.startsWith('env:')) {
    const name = source.slice('env:'.length);
    const v = process.env[name];
    if (!v) {
      throw new Error(
        `security.epochDaysSource: "${source}" but the environment variable ${name} is unset.\n  Fix: export ${name}=${todayEpochDays()} for today, or pin "fixed:<n>" in config.json instead.`,
      );
    }
    const n = Number(v);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(
        `Environment variable ${name} is "${v}", which is not a non-negative integer epoch day.\n  Fix: export ${name}=${todayEpochDays()} for today.`,
      );
    }
    return { epochDays: n, unpinnedEpoch: false };
  }
  throw new Error(
    `security.epochDaysSource: "${source}" is not recognised.\n  Fix: use "fixed:<n>", "env:<VAR>", or "utc_today" (development only).`,
  );
}

// ============================ validation ============================

function validateV1Surface(c: Config): void {
  if (!c.mapping) throw new Error('config.mapping is required');
  if (!Array.isArray(c.mapping.fields) || c.mapping.fields.length === 0) {
    throw new Error('config.mapping.fields must be a non-empty array');
  }
  const set = new Set<string>();
  for (const f of c.mapping.fields) {
    if (typeof f !== 'string' || !f) {
      throw new Error('config.mapping.fields entries must be non-empty strings');
    }
    if (set.has(f)) throw new Error(`config.mapping.fields contains duplicate: ${f}`);
    set.add(f);
  }
  if (!c.mapping.walletAddressField || !c.mapping.countryField) {
    throw new Error('config.mapping.walletAddressField and countryField are required');
  }
  if (!c.output) throw new Error('config.output is required');
  if (c.output.format !== 'csv' && c.output.format !== 'json') {
    throw new Error('config.output.format must be "csv" or "json"');
  }
  if (typeof c.output.includeIndex !== 'boolean') {
    throw new Error('config.output.includeIndex must be a boolean');
  }
  if (!c.security) throw new Error('config.security is required');
  if (typeof c.security.clearInputAfterProcessing !== 'boolean') {
    throw new Error('config.security.clearInputAfterProcessing must be a boolean');
  }
}

function mergeTiers(provided?: TierMap): Required<TierMap> {
  if (!provided) return { ...DEFAULT_TIER_MAP };
  return {
    NONE: provided.NONE ?? DEFAULT_TIER_MAP.NONE,
    RETAIL: provided.RETAIL ?? DEFAULT_TIER_MAP.RETAIL,
    PROFESSIONAL: provided.PROFESSIONAL ?? DEFAULT_TIER_MAP.PROFESSIONAL,
    ELIGIBLE_COUNTERPARTY:
      provided.ELIGIBLE_COUNTERPARTY ?? DEFAULT_TIER_MAP.ELIGIBLE_COUNTERPARTY,
  };
}

/** Fields whose plaintext value is also written to the batch index CSV. */
const PLAINTEXT_DISCLOSED_FIELDS = new Set(['country', 'investorType']);

function disclosureFor(field: string, spec: PredicateSpec): Disclosure {
  if (spec.circuit === 'commitment_only') return 'commitment_only';
  if (PLAINTEXT_DISCLOSED_FIELDS.has(field)) return 'plaintext';
  return 'predicate';
}

/**
 * Suffix distinguishing multiple instances of one predicate over the same
 * field. Derived from the resolved parameters so leaf names are stable and
 * filesystem-safe (`dateOfBirth@7665d`, `investorType@PROFESSIONAL`).
 */
function instanceSuffix(spec: PredicateSpec, tiers: Required<TierMap>): string {
  switch (spec.circuit) {
    case 'age_threshold':
      return `${ageDaysFromParams(spec.params)}d`;
    case 'tier_threshold': {
      const t = spec.params.minTier;
      return typeof t === 'number' ? `tier${t}` : String(t).toUpperCase();
    }
    case 'set_membership':
      return spec.params.list;
    case 'preimage_knowledge':
    case 'commitment_only':
      return `max${spec.params?.maxValueBytes ?? 128}`;
  }
}

const LEAF_NAME_SAFE = /^[A-Za-z0-9_.@-]+$/;

/**
 * Flatten `predicates` into one instance per leaf. The first instance for
 * a field keeps the bare field name so existing single-predicate bundles
 * are unchanged; later instances get a params-derived suffix.
 */
export function resolveInstances(c: Config, tiers: Required<TierMap>): ResolvedInstances {
  const explicit = c.predicates ?? {};
  const eligibleFields = new Set<string>(c.mapping.fields);
  if (c.mapping.countryField) eligibleFields.add('country');
  if (c.mapping.investorTypeField) eligibleFields.add('investorType');

  const out: ResolvedInstances = [];
  const seen = new Set<string>();
  for (const field of eligibleFields) {
    const entry: PredicateEntry | undefined =
      explicit[field] ?? DEFAULT_PREDICATES_BY_FIELD[field];
    if (!entry) {
      throw new Error(
        `config.predicates.${field} not provided and no default exists. Add an entry or remove "${field}" from mapping.fields.`,
      );
    }
    const specs = Array.isArray(entry) ? entry : [entry];
    if (specs.length === 0) {
      throw new Error(`config.predicates.${field}: predicate array must not be empty`);
    }
    specs.forEach((spec, i) => {
      validatePredicate(field, spec);
      const leafName = i === 0 ? field : `${field}@${instanceSuffix(spec, tiers)}`;
      if (!LEAF_NAME_SAFE.test(leafName)) {
        throw new Error(
          `config.predicates.${field}: derived leaf name "${leafName}" is not filesystem-safe`,
        );
      }
      if (seen.has(leafName.toLowerCase())) {
        throw new Error(
          `config.predicates.${field}: duplicate leaf name "${leafName}" — two instances resolve to identical parameters`,
        );
      }
      seen.add(leafName.toLowerCase());
      out.push({ field, leafName, spec, disclosure: disclosureFor(field, spec) });
    });
  }
  out.sort((a, b) => (a.leafName < b.leafName ? -1 : a.leafName > b.leafName ? 1 : 0));
  return out;
}

function resolvePredicates(c: Config): ResolvedPredicates {
  const out: ResolvedPredicates = {};
  const explicit = c.predicates ?? {};
  // Every hashed field PLUS the special passthrough fields (country,
  // investorType) gets a predicate. Spec §5 defaults fill in anything not
  // explicitly mapped.
  const eligibleFields = new Set<string>(c.mapping.fields);
  if (c.mapping.countryField) eligibleFields.add('country');
  if (c.mapping.investorTypeField) eligibleFields.add('investorType');

  for (const field of eligibleFields) {
    const provided = explicit[field];
    if (provided) {
      const first = Array.isArray(provided) ? provided[0] : provided;
      if (!first) {
        throw new Error(`config.predicates.${field}: predicate array must not be empty`);
      }
      validatePredicate(field, first);
      out[field] = first;
      continue;
    }
    const fallback = DEFAULT_PREDICATES_BY_FIELD[field];
    if (!fallback) {
      throw new Error(
        `config.predicates.${field} not provided and no default exists. Add an entry or remove "${field}" from mapping.fields.`,
      );
    }
    out[field] = fallback;
  }

  // Sanity: any explicit predicate referencing an unknown field is a typo.
  for (const key of Object.keys(explicit)) {
    if (!eligibleFields.has(key)) {
      throw new Error(
        `config.predicates.${key} references unknown field — not in mapping.fields nor a special (country/investorType) field.`,
      );
    }
  }
  return out;
}

function validatePredicate(field: string, p: PredicateSpec): void {
  switch (p.circuit) {
    case 'preimage_knowledge':
    case 'commitment_only':
      // params optional.
      return;
    case 'age_threshold':
      if (
        !p.params ||
        (p.params.minAgeDays === undefined && p.params.minAgeYears === undefined)
      ) {
        throw new Error(`predicates.${field}: age_threshold requires params.minAgeYears or minAgeDays`);
      }
      return;
    case 'tier_threshold':
      if (!p.params || p.params.minTier === undefined) {
        throw new Error(`predicates.${field}: tier_threshold requires params.minTier`);
      }
      return;
    case 'set_membership':
      if (!p.params?.list) {
        throw new Error(`predicates.${field}: set_membership requires params.list`);
      }
      return;
    default: {
      const exhaustive: never = p;
      throw new Error(`predicates.${field}: unknown circuit (${(exhaustive as { circuit?: string }).circuit})`);
    }
  }
}

// ============================ list loading ============================

/**
 * Resolve every list a `set_membership` predicate references.
 *
 * The signed registry is preferred over a bare list-commitments file, because
 * it is the only source that also retains superseded versions. A proof carries
 * its list's Merkle root; without a registry there is nothing that maps an old
 * root back to the values it committed to, so a bundle from two rotations ago
 * asserts membership in a set nobody can name. Falling back to a bare file is
 * still allowed for v2 configs, with a warning.
 */
function resolveLists(
  c: Config,
  instances: ResolvedInstances,
  registryDir: string,
  epochDays: number,
  manifestVersion: string,
): Record<string, ResolvedList> {
  const referenced = new Set<string>();
  for (const inst of instances) {
    if (inst.spec.circuit === 'set_membership') {
      referenced.add(inst.spec.params.list);
    }
  }
  if (referenced.size === 0) return {};

  const out: Record<string, ResolvedList> = {};
  for (const listId of referenced) {
    const registry = loadListRegistry(registryDir, listId);
    if (registry) {
      out[listId] = resolveFromRegistry(registry, listId, registryDir, epochDays);
      continue;
    }

    const entry: ListsEntry | undefined = c.lists?.[listId];
    if (!entry || !entry.path) {
      throw new Error(
        [
          `List "${listId}" is referenced by a set_membership predicate but has no source.`,
          `  Looked for a signed registry at ${listRegistryFile(registryDir, listId)} and for config.lists.${listId}.path, and found neither.`,
          `  Fix: record the list's first version with`,
          `       npm run list-version -- --list-id ${listId} --source config/list_commitments/${listId}.source.txt`,
        ].join('\n'),
      );
    }
    if (manifestVersion === '3.0.0') {
      console.warn(
        [
          `[config] list "${listId}" resolved from ${entry.path} rather than from the signed registry.`,
          `         Superseded versions of a bare list file are not retained, so a proof made against an`,
          `         earlier root cannot later be resolved back to the values it committed to.`,
          `         Record it in the registry with:`,
          `           npm run list-version -- --list-id ${listId} --source <the source .txt>`,
        ].join('\n'),
      );
    }
    out[listId] = resolveFromFile(c, listId, entry);
  }
  return out;
}

function listRegistryFile(registryDir: string, listId: string): string {
  return path.join(registryDir, 'lists', `${listId}.json`);
}

function resolveFromRegistry(
  registry: ListRegistry,
  listId: string,
  registryDir: string,
  epochDays: number,
): ResolvedList {
  const version = resolveListAt(registry, epochDays);
  if (!version) {
    const first = registry.versions[0];
    throw new Error(
      [
        `List "${listId}" has no version authoritative on the batch as-of date ${epochDaysToIsoDate(epochDays)} (epoch day ${epochDays}).`,
        `  Its earliest version became effective on ${epochDaysToIsoDate(first.effectiveFrom)} (epoch day ${first.effectiveFrom}).`,
        `  Fix: pin a later security.epochDaysSource, or record a version covering this date with`,
        `       npm run list-version -- --list-id ${listId} --source <file> --effective-date ${epochDaysToIsoDate(epochDays)}`,
      ].join('\n'),
    );
  }
  return {
    listId,
    values: version.values,
    sourceSha256: version.sourceSha256,
    root: version.root,
    depth: version.depth,
    resolvedPath: listRegistryFile(registryDir, listId),
    version: version.version,
    contentHash: version.contentHash,
    effectiveFrom: version.effectiveFrom,
    effectiveUntil: version.effectiveUntil,
  };
}

function resolveFromFile(c: Config, listId: string, entry: ListsEntry): ResolvedList {
  const resolvedPath = path.isAbsolute(entry.path!)
    ? entry.path!
    : path.join(process.cwd(), entry.path!);
  if (!fs.existsSync(resolvedPath)) {
    throw new Error(
      `config.lists.${listId}.path points at ${resolvedPath}, which does not exist.\n  Fix: correct the path, or record the list in the registry with \`npm run list-version -- --list-id ${listId} --source <file>\`.`,
    );
  }
  const bytes = fs.readFileSync(resolvedPath);
  const parsed = parseListCommitmentFile(listId, bytes);
  if (entry.sha256) {
    const actual = '0x' + require('crypto').createHash('sha256').update(bytes).digest('hex');
    const expected = entry.sha256.toLowerCase().startsWith('0x')
      ? entry.sha256.toLowerCase()
      : '0x' + entry.sha256.toLowerCase();
    if (actual !== expected) {
      throw new Error(
        `config.lists.${listId}: pinned SHA-256 mismatch — ${resolvedPath} has changed since it was pinned.\n  Expected ${expected}\n  Found    ${actual}\n  Fix: if the change was intended, update config.lists.${listId}.sha256; otherwise restore the file.`,
      );
    }
  }
  const _unusedConfig = c;
  return { ...parsed, resolvedPath, contentHash: listContentHash(parsed.values) };
}

interface ListFileShape {
  listId: string;
  values: string[];
  sourceSha256: string;
  root: string;
  depth: number;
}

function parseListCommitmentFile(
  expectedListId: string,
  bytes: Buffer,
): Omit<ResolvedList, 'resolvedPath'> {
  let parsed: ListFileShape;
  try {
    parsed = JSON.parse(bytes.toString('utf-8')) as ListFileShape;
  } catch (e) {
    throw new Error(`list_commitments ${expectedListId}: invalid JSON: ${(e as Error).message}`);
  }
  if (parsed.listId !== expectedListId) {
    throw new Error(
      `list_commitments file declares listId="${parsed.listId}" but config references "${expectedListId}"`,
    );
  }
  if (!Array.isArray(parsed.values) || parsed.values.length < 2) {
    throw new Error(`list_commitments ${expectedListId}: values must be ≥ 2 entries`);
  }
  if (!parsed.root || !parsed.sourceSha256) {
    throw new Error(`list_commitments ${expectedListId}: root and sourceSha256 are required`);
  }
  if (typeof parsed.depth !== 'number' || parsed.depth < 1) {
    throw new Error(`list_commitments ${expectedListId}: depth must be a positive number`);
  }
  return {
    listId: parsed.listId,
    values: parsed.values,
    sourceSha256: parsed.sourceSha256,
    root: parsed.root,
    depth: parsed.depth,
  };
}

// ============================ config_hash ============================

/**
 * Canonical SHA-256 of the config used as HKDF input. Cosmetic fields are
 * stripped so reformatting output/cleanup options doesn't invalidate
 * determinism caches, while every field that affects bundle bytes is
 * covered.
 *
 * Serialization sorts object keys at every depth so source-text key order
 * never changes the hash. Before v2.1 this function passed a key array as
 * `JSON.stringify`'s replacer, which filters keys at every nesting level
 * and collapsed the payload to a constant: the hash was identical for all
 * configs and the documented HKDF binding did not hold. Bundles issued
 * before v2.1 therefore carry `secretsKdfVersion: 1` and the legacy
 * constant; the decrypt path selects on that field.
 */
function canonicalConfigHash(c: Config): string {
  const stripped = {
    mapping: c.mapping,
    predicates: c.predicates ?? null,
    tiers: c.tiers ?? null,
    lists: c.lists ?? null,
    manifest: c.manifest ?? null,
    security: {
      masterKeyEnv: c.security.masterKeyEnv,
      epochDaysSource: c.security.epochDaysSource,
      deterministic: c.security.deterministic,
    },
  };
  const text = canonicalJson(stripped);
  const h = require('crypto').createHash('sha256').update(text).digest('hex');
  return '0x' + h;
}

/** Deterministic JSON: object keys sorted at every depth, arrays in order. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    if (obj[k] === undefined) continue;
    parts.push(JSON.stringify(k) + ':' + canonicalJson(obj[k]));
  }
  return '{' + parts.join(',') + '}';
}

// ============================ show ============================

export function describeConfig(rc: ResolvedConfig): string {
  const lines: string[] = [];
  lines.push('Resolved configuration:');
  lines.push('  Hashed fields:');
  for (const f of rc.raw.mapping.fields) {
    const pred = rc.predicates[f];
    lines.push(`    ${f.padEnd(24)} ${pred ? pred.circuit : '(none)'}`);
  }
  lines.push('  Passthrough fields:');
  lines.push(`    walletAddress    -> ${rc.raw.mapping.walletAddressField}`);
  lines.push(`    country          -> ${rc.raw.mapping.countryField}`);
  if (rc.raw.mapping.investorTypeField) {
    lines.push(`    investorType     -> ${rc.raw.mapping.investorTypeField}`);
  }
  lines.push('');
  lines.push('  Tier mapping:');
  for (const [k, v] of Object.entries(rc.tiers)) {
    lines.push(`    ${k.padEnd(24)} = ${v}`);
  }
  lines.push('');
  lines.push('  Set-membership lists:');
  if (Object.keys(rc.lists).length === 0) {
    lines.push('    (none)');
  } else {
    for (const [id, list] of Object.entries(rc.lists)) {
      lines.push(`    ${id.padEnd(24)} root=${list.root.slice(0, 14)}…  depth=${list.depth}  values=${list.values.length}`);
    }
  }
  lines.push('');
  lines.push(`  Master-key env:  ${rc.masterKeyEnv}`);
  lines.push(`  Signing-key env: ${rc.signingKeyEnv}`);
  lines.push(`  Epoch days:      ${rc.epochDaysSource}`);
  lines.push(`  Deterministic:   ${rc.deterministic}`);
  lines.push(`  Config hash:     ${rc.configHashHex.slice(0, 14)}…`);
  return lines.join('\n');
}
