// Reader for the v3 append-only registries. Writing is the Rust
// `trusset-registry` binary's job because every record is signed; the CLI only
// reads, resolves, and reports.

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { epochDaysToIsoDate } from './dates';

export const DEFAULT_REGISTRY_DIR = 'config/registry';

export interface ListVersionRecord {
  version: number;
  values: string[];
  root: string;
  depth: number;
  contentHash: string;
  sourceSha256: string;
  effectiveFrom: number;
  effectiveUntil?: number;
  generator: string;
  recordedAt: string;
  note?: string;
}

export interface ListRegistry {
  schemaVersion: number;
  listId: string;
  versions: ListVersionRecord[];
}

export interface RootAnchor {
  subject: string;
  kycHash: string;
  epochDays: number;
  chainId: number;
  blockHeight: number;
  blockTimestamp: number;
  txHash?: string;
  manifestSha256: string;
  recordedAt: string;
}

export interface RootHistory {
  schemaVersion: number;
  entries: RootAnchor[];
}

export interface RevocationRecord {
  subject: string;
  kycHash: string;
  leafName?: string;
  effect: 'lapsed' | 'void_ab_initio';
  effectiveFrom?: number;
  declaredAt: number;
  reasonCode: string;
  note?: string;
  issuerKeyId: string;
  recordedAt: string;
}

export interface RevocationLog {
  schemaVersion: number;
  entries: RevocationRecord[];
}

export function registryRoot(configuredDir?: string): string {
  const dir = configuredDir || DEFAULT_REGISTRY_DIR;
  return path.isAbsolute(dir) ? dir : path.join(process.cwd(), dir);
}

export function listRegistryPath(root: string, listId: string): string {
  return path.join(root, 'lists', `${listId}.json`);
}

/**
 * SHA-256 over the NFC values joined by newline. Must match
 * `bundle-format::registry::list_content_hash` byte for byte, or the prover
 * rejects the version reference the CLI built.
 */
export function listContentHash(values: string[]): string {
  const h = createHash('sha256');
  values.forEach((v, i) => {
    if (i > 0) h.update('\n');
    h.update(v, 'utf-8');
  });
  return '0x' + h.digest('hex');
}

export function loadListRegistry(root: string, listId: string): ListRegistry | null {
  const file = listRegistryPath(root, listId);
  if (!fs.existsSync(file)) return null;
  let parsed: ListRegistry;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as ListRegistry;
  } catch (e) {
    throw new Error(`${file}: not readable as a list registry: ${(e as Error).message}`);
  }
  validateListRegistry(parsed, file);
  if (parsed.listId !== listId) {
    throw new Error(`${file}: declares listId "${parsed.listId}" but was loaded as "${listId}"`);
  }
  return parsed;
}

/**
 * The same structural invariants the Rust side enforces: contiguous versions
 * from 1, non-overlapping ascending windows, only the last open-ended, and
 * every contentHash reproducible from its own values. Checked on read so a
 * hand-edited registry fails here rather than producing bundles that reference
 * a version that does not mean what it says.
 */
export function validateListRegistry(reg: ListRegistry, source: string): void {
  if (!Array.isArray(reg.versions) || reg.versions.length === 0) {
    throw new Error(`${source}: list registry has no versions`);
  }
  let previousUntil: number | undefined;
  reg.versions.forEach((v, i) => {
    if (v.version !== i + 1) {
      throw new Error(
        `${source}: list versions must be contiguous from 1; expected version ${i + 1}, found ${v.version}`,
      );
    }
    if (listContentHash(v.values) !== (v.contentHash || '').toLowerCase()) {
      throw new Error(
        `${source}: version ${v.version} contentHash does not match its recorded values`,
      );
    }
    if (previousUntil !== undefined && v.effectiveFrom <= previousUntil) {
      throw new Error(
        `${source}: version ${v.version} starts on epoch day ${v.effectiveFrom}, which overlaps version ${v.version - 1}`,
      );
    }
    if (v.effectiveUntil === undefined || v.effectiveUntil === null) {
      if (i !== reg.versions.length - 1) {
        throw new Error(
          `${source}: version ${v.version} has no effectiveUntil but is not the current version`,
        );
      }
    } else {
      if (v.effectiveUntil < v.effectiveFrom) {
        throw new Error(
          `${source}: version ${v.version} ends (${v.effectiveUntil}) before it starts (${v.effectiveFrom})`,
        );
      }
      previousUntil = v.effectiveUntil;
    }
  });
}

/** The version authoritative on a given day. */
export function resolveListAt(reg: ListRegistry, epochDays: number): ListVersionRecord | null {
  for (const v of reg.versions) {
    const startsInTime = epochDays >= v.effectiveFrom;
    const endsAfter = v.effectiveUntil === undefined || v.effectiveUntil === null || epochDays <= v.effectiveUntil;
    if (startsInTime && endsAfter) return v;
  }
  return null;
}

export function loadRootHistory(root: string): RootHistory {
  const file = path.join(root, 'root_history.json');
  if (!fs.existsSync(file)) return { schemaVersion: 1, entries: [] };
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8')) as RootHistory;
  } catch (e) {
    throw new Error(`${file}: not readable as a root history: ${(e as Error).message}`);
  }
}

export function loadRevocations(root: string): RevocationLog {
  const file = path.join(root, 'revocations.json');
  if (!fs.existsSync(file)) return { schemaVersion: 1, entries: [] };
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8')) as RevocationLog;
  } catch (e) {
    throw new Error(`${file}: not readable as a revocation log: ${(e as Error).message}`);
  }
}

/** One-line summary of a list version, for `show` and for init diagnostics. */
export function describeListVersion(v: ListVersionRecord): string {
  const until =
    v.effectiveUntil === undefined || v.effectiveUntil === null
      ? 'current'
      : epochDaysToIsoDate(v.effectiveUntil);
  return `v${v.version}  ${epochDaysToIsoDate(v.effectiveFrom)} .. ${until}  ${v.values.length} entries  root ${v.root.slice(0, 14)}…`;
}
