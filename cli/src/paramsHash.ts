// Params hash — must match what the Rust circuit crates produce for the
// same params. Each circuit's `Params::hash()` in Rust is replicated below;
// any drift between the two sides invalidates determinism canaries.

import { createHash } from 'crypto';
import { ResolvedConfig } from './config';
import { CircuitName, PredicateSpec } from './types';

function sha256(bytes: Buffer): string {
  return '0x' + createHash('sha256').update(bytes).digest('hex');
}

function leU64(n: number | bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(n));
  return buf;
}

function leU32(n: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(n);
  return buf;
}

function tagPlus(label: string, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from(label, 'utf-8'), body]);
}

// ============================ public API ============================

export function computeParamsHash(
  field: string,
  predicate: PredicateSpec,
  rc: ResolvedConfig,
): string {
  switch (predicate.circuit) {
    // `commitment_only` leaves reuse the preimage_knowledge parameter
    // shape: the mode changes what is proved, not how the parameters are
    // committed.
    case 'commitment_only':
    case 'preimage_knowledge': {
      const maxBytes = BigInt(predicate.params?.maxValueBytes ?? 128);
      return sha256(
        tagPlus('trusset-kyc-v2:preimage_knowledge:params', leU64(maxBytes)),
      );
    }
    case 'tier_threshold': {
      const minTier = resolveTier(predicate.params.minTier, rc);
      return sha256(
        tagPlus('trusset-kyc-v2:tier_threshold:params', Buffer.from([minTier])),
      );
    }
    case 'age_threshold': {
      const minAgeDays = ageDaysFromParams(predicate.params);
      return sha256(
        tagPlus('trusset-kyc-v2:age_threshold:params', leU64(minAgeDays)),
      );
    }
    case 'set_membership': {
      const listId = predicate.params.list;
      const listBytes = Buffer.from(listId, 'utf-8');
      const body = Buffer.concat([leU64(listBytes.length), listBytes]);
      return sha256(tagPlus('trusset-kyc-v2:set_membership:params', body));
    }
    default: {
      const exhaustive: never = predicate;
      throw new Error(`unknown circuit: ${JSON.stringify(exhaustive)}`);
    }
  }
}

// ============================ helpers ============================

function resolveTier(minTier: string | number, rc: ResolvedConfig): number {
  if (typeof minTier === 'number') return minTier;
  const upper = minTier.toUpperCase();
  const value = (rc.tiers as Record<string, number | undefined>)[upper];
  if (value === undefined) {
    throw new Error(`unknown tier name "${minTier}" — must be one of ${Object.keys(rc.tiers).join(', ')}`);
  }
  return value;
}

export function ageDaysFromParams(params: { minAgeYears?: number; minAgeDays?: number }): bigint {
  if (params.minAgeDays !== undefined) return BigInt(params.minAgeDays);
  if (params.minAgeYears !== undefined) return BigInt(params.minAgeYears * 365);
  throw new Error('age_threshold params: minAgeYears or minAgeDays required');
}

export const _internals = { sha256, leU64, leU32, tagPlus };
