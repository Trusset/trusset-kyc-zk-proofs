// Cross-language KAT bridge: assert TS `computeParamsHash` produces the
// same bytes as the Rust prover for every vector in tests/kat/params_hash.json.
//
// If this test fails, either:
//   - cli/src/paramsHash.ts has drifted from each circuit's Rust Params::hash
//   - the Rust side changed and the KAT was refreshed without updating TS
//
// Either way it's a cross-language drift that would silently produce
// unverifiable bundles in production — catch it in CI.

import { strict as assert } from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';
import test from 'node:test';
import { computeParamsHash } from '../paramsHash';
import type { PredicateSpec } from '../types';
import type { ResolvedConfig } from '../config';

interface Vector {
  name: string;
  circuit: string;
  /** What the TS CLI consumes, including unresolved tier names / years. */
  params: Record<string, unknown>;
  /** Post-resolution form the Rust prover hashes, when they differ. */
  resolvedParams?: Record<string, unknown>;
}

interface KatFile {
  vectors: Vector[];
  expected: Record<string, string>;
}

function loadKat(): KatFile {
  // The KAT file lives at the workspace root: tests/kat/params_hash.json.
  // From cli/dist/__tests__ at runtime, that's three levels up.
  const candidates = [
    path.join(__dirname, '..', '..', '..', 'tests', 'kat', 'params_hash.json'),
    path.join(process.cwd(), 'tests', 'kat', 'params_hash.json'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return JSON.parse(fs.readFileSync(candidate, 'utf-8')) as KatFile;
    }
  }
  throw new Error(`tests/kat/params_hash.json not found; tried:\n  ${candidates.join('\n  ')}`);
}

function fixtureConfig(): ResolvedConfig {
  // Only the `tiers` field is consulted by computeParamsHash for tier
  // vectors with string minTier — the KAT uses integer minTier, so any
  // valid tier map works.
  return {
    raw: {} as ResolvedConfig['raw'],
    predicates: {},
    instances: [],
    tiers: { NONE: 0, RETAIL: 1, PROFESSIONAL: 2, ELIGIBLE_COUNTERPARTY: 3 },
    lists: {},
    masterKeyEnv: 'TRUSSET_KYC_MASTER_KEY',
    signingKeyEnv: 'TRUSSET_KYC_SIGNING_KEY',
    epochDaysSource: 'fixed:20700',
    deterministic: true,
    configHashHex: '0x' + '0'.repeat(64),
    manifestVersion: '3.0.0',
    registryDir: '/nonexistent',
    epochDays: 20700,
    unpinnedEpoch: false,
    evidenceDateField: 'evidenceDate',
  };
}

function toPredicateSpec(vector: Vector): PredicateSpec {
  // Pass through the JSON params verbatim — `computeParamsHash` knows how
  // to consume each circuit's params shape.
  switch (vector.circuit) {
    case 'preimage_knowledge':
    case 'commitment_only':
    case 'tier_threshold':
    case 'age_threshold':
    case 'set_membership':
      return {
        circuit: vector.circuit,
        params: vector.params as never,
      } as PredicateSpec;
    default:
      throw new Error(`unknown circuit: ${vector.circuit}`);
  }
}

test('every KAT vector agrees with Rust on params_hash', () => {
  const kat = loadKat();
  const rc = fixtureConfig();
  const mismatches: string[] = [];
  for (const v of kat.vectors) {
    const computed = computeParamsHash(v.name, toPredicateSpec(v), rc);
    const expected = kat.expected[v.name];
    if (computed !== expected) {
      mismatches.push(`  ${v.name}: expected ${expected}, got ${computed}`);
    }
  }
  if (mismatches.length > 0) {
    assert.fail(
      `TS ↔ Rust params_hash drift in ${mismatches.length} vector(s):\n` +
        mismatches.join('\n') +
        '\n\nRefresh KAT with: TRUSSET_KAT_REFRESH=1 cargo test -p trusset-prover --test params_hash_kat',
    );
  }
});

test('KAT has at least one vector per circuit', () => {
  const kat = loadKat();
  const circuits = new Set(kat.vectors.map((v) => v.circuit));
  for (const c of [
    'preimage_knowledge',
    'commitment_only',
    'tier_threshold',
    'age_threshold',
    'set_membership',
  ]) {
    assert.ok(circuits.has(c), `KAT missing a vector for circuit "${c}"`);
  }
});

test('KAT covers the TS-side parameter resolution paths', () => {
  const kat = loadKat();
  // Vectors carrying `resolvedParams` are the ones where TS must resolve
  // something Rust receives pre-resolved: tier names and minAgeYears.
  const resolving = kat.vectors.filter((v) => v.resolvedParams !== undefined);
  assert.ok(
    resolving.some((v) => v.circuit === 'tier_threshold' && typeof (v.params as { minTier?: unknown }).minTier === 'string'),
    'KAT must cover a string minTier so resolveTier is checked against Rust',
  );
  assert.ok(
    resolving.some((v) => v.circuit === 'age_threshold' && (v.params as { minAgeYears?: unknown }).minAgeYears !== undefined),
    'KAT must cover minAgeYears so the years-to-days conversion is checked against Rust',
  );
});
