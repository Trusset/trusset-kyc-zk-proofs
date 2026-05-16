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
import {
  CircuitName,
  Config,
  EpochDaysSource,
  ListsEntry,
  PredicateSpec,
  Predicates,
  TierMap,
} from './types';

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

export interface ResolvedConfig {
  raw: Config;
  predicates: ResolvedPredicates;
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
}

export interface ResolvedList {
  listId: string;
  /** Raw values from the list-commitments JSON. */
  values: string[];
  /** SHA-256 of the source text file. */
  sourceSha256: string;
  /** Manifest-recorded Rescue Merkle root. */
  root: string;
  depth: number;
  /** Path the file was loaded from (for diagnostics). */
  resolvedPath: string;
}

export function loadConfig(): ResolvedConfig {
  if (!fs.existsSync(CONFIG_PATH)) {
    throw new Error(
      `config.json not found at ${CONFIG_PATH}. Copy config.example.json and edit it.`,
    );
  }
  const text = fs.readFileSync(CONFIG_PATH, 'utf-8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(`config.json: invalid JSON: ${(e as Error).message}`);
  }
  return resolveConfig(parsed as Config);
}

export function resolveConfig(raw: Config): ResolvedConfig {
  validateV1Surface(raw);

  if (raw.security.hashAlgorithm && raw.security.hashAlgorithm !== 'rescue_prime') {
    // v1 keys honored for backwards-readability — emit one warning per run.
    console.warn(
      `[config] security.hashAlgorithm: "${raw.security.hashAlgorithm}" is deprecated; v2 uses rescue-prime unconditionally.`,
    );
  }

  const tiers = mergeTiers(raw.tiers);
  const predicates = resolvePredicates(raw);
  const lists = resolveLists(raw, predicates);

  const masterKeyEnv = raw.security.masterKeyEnv || 'TRUSSET_KYC_MASTER_KEY';
  const signingKeyEnv = raw.manifest?.signingKeyEnv || 'TRUSSET_KYC_SIGNING_KEY';
  const epochDaysSource: EpochDaysSource =
    raw.security.epochDaysSource ?? 'utc_today';
  const deterministic = raw.security.deterministic ?? true;

  const configHashHex = canonicalConfigHash(raw);

  return {
    raw,
    predicates,
    tiers,
    lists,
    masterKeyEnv,
    signingKeyEnv,
    epochDaysSource,
    deterministic,
    configHashHex,
  };
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
      validatePredicate(field, provided);
      out[field] = provided;
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
      // params optional.
      return;
    case 'age_threshold':
      if (!p.params || (!p.params.minAgeDays && !p.params.minAgeYears)) {
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

function resolveLists(c: Config, predicates: ResolvedPredicates): Record<string, ResolvedList> {
  // Collect list IDs referenced by set_membership predicates.
  const referenced = new Set<string>();
  for (const pred of Object.values(predicates)) {
    if (pred.circuit === 'set_membership') {
      referenced.add(pred.params.list);
    }
  }
  if (referenced.size === 0) return {};

  if (!c.lists) {
    throw new Error(
      `config.lists is required when any set_membership predicate is configured. Referenced lists: ${[
        ...referenced,
      ].join(', ')}`,
    );
  }

  const out: Record<string, ResolvedList> = {};
  for (const listId of referenced) {
    const entry = c.lists[listId];
    if (!entry || !entry.path) {
      throw new Error(`config.lists.${listId}.path is required`);
    }
    const resolvedPath = path.isAbsolute(entry.path)
      ? entry.path
      : path.join(process.cwd(), entry.path);
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`list_commitments file not found: ${resolvedPath}`);
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
          `list_commitments ${listId}: pinned SHA-256 mismatch (file changed). Expected ${expected}, got ${actual}.`,
        );
      }
    }
    out[listId] = { ...parsed, resolvedPath };
  }
  return out;
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
 * determinism caches.
 */
function canonicalConfigHash(c: Config): string {
  // Build a stripped copy with only fields that affect bundle bytes.
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
  const text = JSON.stringify(stripped, Object.keys(stripped).sort());
  const h = require('crypto').createHash('sha256').update(text).digest('hex');
  return '0x' + h;
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
