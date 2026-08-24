// Resolution and validation of v3 claim descriptors and validity intervals.
//
// A v2 leaf asserted `minAgeDays: 6570` and nothing about what that day count
// stands for, who warrants it, or how long it holds. Everything that turns a
// threshold into a statement a regulator can read is assembled here, then bound
// into the leaf hash by the prover.

import {
  ClaimDefaults,
  DescriptorConfig,
  EvidenceClass,
  EVIDENCE_CLASSES,
  IDENTIFIER_SCHEMES,
  IssuerConfig,
  PartyRef,
  PredicateSpec,
  ResolvedDescriptor,
  ResolvedValidity,
  ValidityConfig,
} from './types';
import { epochDaysToIsoDate, parseDateToEpochDays } from './dates';

/**
 * Raised when a descriptor or validity block cannot be resolved. Carries the
 * field, the config path, and what to do, because a failure an operator cannot
 * act on is the same as no message at all.
 */
export class DescriptorError extends Error {
  readonly configPath: string;
  readonly fix: string;
  constructor(configPath: string, problem: string, fix: string) {
    super(`${configPath}: ${problem}\n  Fix: ${fix}`);
    this.name = 'DescriptorError';
    this.configPath = configPath;
    this.fix = fix;
  }
}

function validateParty(party: PartyRef, configPath: string): void {
  for (const [key, value] of Object.entries({
    name: party.name,
    identifierScheme: party.identifierScheme,
    identifier: party.identifier,
    jurisdiction: party.jurisdiction,
  })) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new DescriptorError(
        `${configPath}.${key}`,
        'is missing or empty',
        `set it to the ${key} of the party that warrants this claim`,
      );
    }
  }
  if (!IDENTIFIER_SCHEMES.includes(party.identifierScheme as never)) {
    throw new DescriptorError(
      `${configPath}.identifierScheme`,
      `is "${party.identifierScheme}", which is not a recognised scheme`,
      `use one of ${IDENTIFIER_SCHEMES.join(', ')}. Use INTERNAL when the party has no public identifier.`,
    );
  }
  if (!/^[A-Z]{2}$/.test(party.jurisdiction)) {
    throw new DescriptorError(
      `${configPath}.jurisdiction`,
      `is "${party.jurisdiction}", which is not an ISO 3166-1 alpha-2 code`,
      'use a two-letter uppercase country code, e.g. DE, GB, US',
    );
  }
}

export function validateIssuer(issuer: IssuerConfig): void {
  validateParty(issuer, 'manifest.issuer');
  if (typeof issuer.keyId !== 'string' || issuer.keyId.trim() === '') {
    throw new DescriptorError(
      'manifest.issuer.keyId',
      'is missing',
      'give the signing key a stable label, e.g. "issuing-2026-01", so a future key rotation does not read as a change of issuer',
    );
  }
}

/**
 * Resolve a predicate's descriptor against the config-level defaults.
 *
 * `issuingParty: "self"` — the default — means the bundle issuer warrants the
 * claim. A named party is for reliance arrangements, where another regulated
 * firm did the verification and the issuer is passing on their assurance.
 */
export function resolveDescriptor(
  leafName: string,
  spec: PredicateSpec,
  defaults: ClaimDefaults | undefined,
  issuer: IssuerConfig,
): ResolvedDescriptor {
  const configPath = `predicates.${leafName}.descriptor`;
  const descriptor: DescriptorConfig | undefined = spec.descriptor;

  if (!descriptor) {
    throw new DescriptorError(
      configPath,
      'is missing, so this leaf would assert a threshold with no statement of what legal test it corresponds to or who warrants it',
      `add a descriptor with legalBasis {framework, reference, assertion} and evidenceClass (one of ${EVIDENCE_CLASSES.join(', ')}). Run \`npm run init\` to write starting descriptors for the shipped predicates.`,
    );
  }

  const basis = descriptor.legalBasis;
  if (!basis) {
    throw new DescriptorError(
      `${configPath}.legalBasis`,
      'is missing',
      'add {framework, reference, assertion} naming the rule this predicate is asserted under',
    );
  }
  for (const key of ['framework', 'reference', 'assertion'] as const) {
    if (typeof basis[key] !== 'string' || basis[key].trim() === '') {
      throw new DescriptorError(
        `${configPath}.legalBasis.${key}`,
        'is missing or empty',
        key === 'framework'
          ? 'name the regulatory framework, e.g. MiFID_II, AMLD5, REG_D, NATIONAL'
          : key === 'reference'
            ? 'cite the provision, e.g. "Annex II Section I" or "Art. 13(1)(a)"'
            : 'state in one line what is being asserted, in your own words',
      );
    }
  }

  const evidenceClass = (descriptor.evidenceClass ?? defaults?.evidenceClass) as
    | EvidenceClass
    | undefined;
  if (!evidenceClass) {
    throw new DescriptorError(
      `${configPath}.evidenceClass`,
      'is missing and no claims.defaults.evidenceClass is set',
      `set it to one of ${EVIDENCE_CLASSES.join(', ')}`,
    );
  }
  if (!EVIDENCE_CLASSES.includes(evidenceClass)) {
    throw new DescriptorError(
      `${configPath}.evidenceClass`,
      `is "${evidenceClass}", which is not a recognised evidence class`,
      `use one of ${EVIDENCE_CLASSES.join(', ')}`,
    );
  }

  const partySpec = descriptor.issuingParty ?? defaults?.issuingParty ?? 'self';
  let issuingParty: PartyRef;
  if (partySpec === 'self') {
    issuingParty = {
      name: issuer.name,
      identifierScheme: issuer.identifierScheme,
      identifier: issuer.identifier,
      jurisdiction: issuer.jurisdiction,
    };
  } else {
    validateParty(partySpec, `${configPath}.issuingParty`);
    issuingParty = partySpec;
  }

  if (descriptor.evidenceRef !== undefined && typeof descriptor.evidenceRef !== 'string') {
    throw new DescriptorError(
      `${configPath}.evidenceRef`,
      'is not a string',
      'use an operator-side case or file reference, and never subject data — it travels in cleartext inside the signed manifest',
    );
  }

  return {
    legalBasis: {
      framework: basis.framework.trim(),
      reference: basis.reference.trim(),
      assertion: basis.assertion.trim(),
    },
    issuingParty,
    evidenceClass,
    ...(descriptor.evidenceRef ? { evidenceRef: descriptor.evidenceRef } : {}),
  };
}

/**
 * Resolve a predicate's validity window against the batch date.
 *
 * `from` is the batch's as-of date. `until` is either a fixed length, a fixed
 * calendar day, or absent for an open-ended claim that only a revocation can
 * end. `basisAsOf` is when the evidence was examined, which is not the same as
 * when the claim starts — the gap between them is the staleness a reviewer
 * wants to see, so it is recorded rather than assumed to be zero.
 */
export function resolveValidity(
  leafName: string,
  spec: PredicateSpec,
  defaults: ClaimDefaults | undefined,
  epochDays: number,
  subjectEvidenceDate: number | undefined,
): ResolvedValidity {
  const configPath = `predicates.${leafName}.validity`;
  const cfg: ValidityConfig | undefined = spec.validity ?? defaults?.validity;

  if (!cfg) {
    throw new DescriptorError(
      configPath,
      'is missing, so the leaf would not say how long its claim is asserted for',
      'add {"days": N} for a fixed window, {"until": "YYYY-MM-DD"} for a fixed end, or {"openEnded": true} for a claim only a revocation can end. A default for every predicate goes in claims.defaults.validity.',
    );
  }

  const given = [cfg.days !== undefined, cfg.until !== undefined, cfg.openEnded === true].filter(
    Boolean,
  ).length;
  if (given === 0) {
    throw new DescriptorError(
      configPath,
      'specifies no window',
      'give exactly one of days, until, or openEnded',
    );
  }
  if (given > 1) {
    throw new DescriptorError(
      configPath,
      'specifies more than one of days, until, and openEnded',
      'give exactly one; they are alternative ways of saying the same thing and cannot be combined',
    );
  }

  let until: number | undefined;
  if (cfg.days !== undefined) {
    if (!Number.isInteger(cfg.days) || cfg.days < 1) {
      throw new DescriptorError(
        `${configPath}.days`,
        `is ${cfg.days}, which is not a positive whole number of days`,
        'use a positive integer; the window is inclusive of its first day, so 365 means a year',
      );
    }
    until = epochDays + cfg.days - 1;
  } else if (cfg.until !== undefined) {
    until = parseDateToEpochDays(cfg.until, `${configPath}.until`);
    if (until < epochDays) {
      throw new DescriptorError(
        `${configPath}.until`,
        `is ${cfg.until} (epoch day ${until}), which is before the batch as-of date ${epochDaysToIsoDate(epochDays)} (epoch day ${epochDays})`,
        'set a later end date, or pin security.epochDaysSource to an earlier batch date',
      );
    }
  }

  const offset = cfg.basisAsOfOffsetDays ?? 0;
  if (!Number.isInteger(offset) || offset < 0) {
    throw new DescriptorError(
      `${configPath}.basisAsOfOffsetDays`,
      `is ${offset}, which is not a non-negative whole number of days`,
      'use 0 when the evidence was examined on the batch date, or the number of days before it',
    );
  }
  const basisAsOf = subjectEvidenceDate ?? epochDays - offset;

  if (basisAsOf > epochDays) {
    throw new DescriptorError(
      configPath,
      `resolves basisAsOf to ${epochDaysToIsoDate(basisAsOf)}, which is after the batch as-of date ${epochDaysToIsoDate(epochDays)}`,
      'evidence cannot post-date the window it supports; correct the subject evidence date or the offset',
    );
  }

  return { from: epochDays, ...(until !== undefined ? { until } : {}), basisAsOf };
}

/** Human summary used by `show` and by init's report. */
export function describeDescriptor(d: ResolvedDescriptor): string {
  return `${d.legalBasis.framework} ${d.legalBasis.reference} — ${d.legalBasis.assertion} [${d.evidenceClass}, warranted by ${d.issuingParty.name}]`;
}
