// v2 type definitions. Extends v1 schema additively per plan §"config.json v2 schema".

export type InvestorTypeName = 'NONE' | 'RETAIL' | 'PROFESSIONAL' | 'ELIGIBLE_COUNTERPARTY';

export type CircuitName =
  | 'preimage_knowledge'
  | 'tier_threshold'
  | 'age_threshold'
  | 'set_membership'
  | 'commitment_only';

/**
 * Per-leaf disclosure class recorded in `manifest.leaves[].disclosure`.
 * `plaintext` marks a field whose value is also disclosed outside the zk
 * layer (batch index CSV and manifest passthrough), so the proof does not
 * hide it in the default pipeline. `predicate` marks a field where only
 * the predicate outcome is meaningful to a counterparty. `commitment_only`
 * marks a hiding commitment with no STARK.
 */
export type Disclosure = 'plaintext' | 'predicate' | 'commitment_only';

// =================== predicate parameters ===================

export interface PreimageParams {
  maxValueBytes?: number;
}

export interface TierParams {
  /**
   * A fixed tier floor, or `ATTESTED` (3.1.0): the subject's own investor
   * class, so the leaf proves exactly the class the hub attestation records.
   */
  minTier: InvestorTypeName | number | 'ATTESTED';
}

export interface AgeParams {
  minAgeYears?: number;
  minAgeDays?: number;
}

export interface SetMembershipParams {
  list: string;
}

/**
 * v3 additions carried on every predicate: what legal test it stands for and
 * how long it is asserted. Both are required for manifest version 3.0.0 and
 * both bind into the leaf hash.
 */
export interface PredicateClaimFields {
  descriptor?: DescriptorConfig;
  validity?: ValidityConfig;
  /**
   * 3.1.0: the hub predicate this leaf proves (`ADULT`, `EEA_RESIDENT`,
   * `RESIDENCY_ON_FILE`, `CITIZENSHIP_ON_FILE`, `TAX_RESIDENCY_ON_FILE`,
   * `ACCREDITED`, or `INVESTOR_CLASS`). Bound into the leaf hash.
   */
  predicate?: string;
  /**
   * 3.1.0: when the subject's value does not satisfy the predicate, leave the
   * leaf out (the attestation then lacks that bit) instead of failing the
   * subject. For predicates such as `EEA_RESIDENT` that many valid subjects
   * do not meet.
   */
  optional?: boolean;
}

export type PredicateSpec = PredicateClaimFields &
  (
    | { circuit: 'preimage_knowledge'; params?: PreimageParams }
    | { circuit: 'tier_threshold'; params: TierParams }
    | { circuit: 'age_threshold'; params: AgeParams }
    | { circuit: 'set_membership'; params: SetMembershipParams }
    | { circuit: 'commitment_only'; params?: PreimageParams }
  );

/**
 * A field maps to either one predicate or several instances of one over
 * the same value (for example `age_threshold` at 18 and at 21). Each
 * instance becomes its own leaf with its own params hash.
 */
export type PredicateEntry = PredicateSpec | PredicateSpec[];

export type Predicates = Record<string, PredicateEntry>;

/** One resolved predicate instance bound to a filesystem-safe leaf name. */
export interface PredicateInstance {
  /** Source field the witness value comes from. */
  field: string;
  /** Leaf name: `<field>` for the first instance, `<field>@<suffix>` after. */
  leafName: string;
  spec: PredicateSpec;
  disclosure: Disclosure;
}

// =================== config ===================

export interface MappingConfig {
  fields: string[];
  walletAddressField: string;
  countryField: string;
  investorTypeField?: string;
  softExpiryDaysField?: string;
  hardExpiryDaysField?: string;
  /**
   * v3: optional input column holding the date the subject's evidence was
   * examined, `YYYY-MM-DD`. When present it sets `validity.basisAsOf` for that
   * subject's leaves; otherwise the per-predicate offset applies. Defaults to
   * `evidenceDate`.
   */
  evidenceDateField?: string;
}

export interface OutputDefaults {
  investorType?: InvestorTypeName;
  softExpiryDays?: number;
  hardExpiryDays?: number;
}

export interface OutputConfig {
  format: 'csv' | 'json';
  includeIndex: boolean;
  bundleDir?: string;
  emitIndexCsv?: boolean;
  defaults?: OutputDefaults;
}

export type EpochDaysSource = 'utc_today' | `fixed:${number}` | `env:${string}`;

/**
 * Where the operator keys live. `file`: an encrypted key file (scrypt plus
 * ChaCha20-Poly1305) unlocked with a passphrase. `keychain`: the macOS
 * keychain. Absent: the `TRUSSET_KYC_*` environment variables, for CI only.
 */
export type KeyStoreConfig =
  | { type: 'file'; path: string }
  | { type: 'keychain'; service?: string; account?: string };

/**
 * 3.1.0: the on-chain attestation every bundle is bound to. `keyId` is the
 * hub's id for the operator key (`operatorKeyAt(attester, keyId)`), 1 for an
 * attester's first key.
 */
export interface ChainConfig {
  chainId: number;
  hub: string;
  attester: string;
  keyId: number;
}

export interface SecurityConfig {
  clearInputAfterProcessing: boolean;
  /** v2 always uses Rescue-Prime; v1's `hashAlgorithm` is honored for backwards-readability with a deprecation warning. */
  hashAlgorithm?: string;
  masterKeyEnv?: string;
  epochDaysSource?: EpochDaysSource;
  deterministic?: boolean;
  /** v3: root of the append-only registries. Default `config/registry`. */
  registryDir?: string;
  /** v3.1: where the operator keys are kept. */
  keyStore?: KeyStoreConfig;
}

export interface ManifestConfig {
  signingKeyEnv?: string;
  /**
   * v3: the party legally responsible for every assertion in the bundle.
   * Required to issue a version 3.0.0 manifest.
   */
  issuer?: IssuerConfig;
  /**
   * Wire version to emit. Defaults to 3.0.0. Set to 2.1.0 to keep producing
   * the previous bundle shape while migrating.
   */
  version?: string;
}

export interface ListsEntry {
  /**
   * Relative path to a list-commitments JSON. Optional in v3: when omitted,
   * the list resolves from the signed registry under
   * `security.registryDir`, which is the only source that also retains
   * superseded versions.
   */
  path?: string;
  /** Optional pinned SHA-256 — the prover refuses to start if the file's hash drifts. */
  sha256?: string;
}

export interface TierMap {
  NONE?: number;
  RETAIL?: number;
  PROFESSIONAL?: number;
  ELIGIBLE_COUNTERPARTY?: number;
  [key: string]: number | undefined;
}

export interface Config {
  mapping: MappingConfig;
  predicates?: Predicates;
  tiers?: TierMap;
  lists?: Record<string, ListsEntry>;
  output: OutputConfig;
  security: SecurityConfig;
  manifest?: ManifestConfig;
  /** v3: defaults applied to every predicate's claim descriptor. */
  claims?: ClaimsConfig;
  /** v3.1: the hub attestation the bundles are issued for. */
  chain?: ChainConfig;
}

// =================== KYC record ===================

export type KycFieldValue = string | number | boolean | null | undefined;
export type KycRecord = Record<string, KycFieldValue>;

// =================== summary output (batched CSV row) ===================

export interface IndexRow {
  index?: number;
  walletAddress: string;
  /** Absent from 3.1.0 index files: no clear-text personal values. */
  country?: string;
  investorType: InvestorTypeName;
  softExpiryDays: number;
  hardExpiryDays: number;
  kycHash: string;
}

// =================== v3: claim descriptors ===================

/**
 * How the underlying value was verified. A labelled taxonomy, not a scale:
 * nothing compares two evidence classes, and no predicate takes an
 * evidence-class threshold. `THIRD_PARTY_RELIANCE` in particular carries
 * whatever assurance the relied-upon firm applied, which this tool cannot
 * observe.
 */
export type EvidenceClass =
  | 'SELF_ATTESTED'
  | 'DOCUMENTARY'
  | 'THIRD_PARTY_RELIANCE'
  | 'AUTHORITATIVE_SOURCE'
  | 'CRYPTOGRAPHIC'
  | 'PHYSICAL_PRESENCE';

export const EVIDENCE_CLASSES: EvidenceClass[] = [
  'SELF_ATTESTED',
  'DOCUMENTARY',
  'THIRD_PARTY_RELIANCE',
  'AUTHORITATIVE_SOURCE',
  'CRYPTOGRAPHIC',
  'PHYSICAL_PRESENCE',
];

export const IDENTIFIER_SCHEMES = ['LEI', 'BIC', 'FCA_FRN', 'BAFIN_ID', 'CRD_ID', 'INTERNAL'] as const;
export type IdentifierScheme = (typeof IDENTIFIER_SCHEMES)[number];

/** A named legal person, identified under a public scheme where one exists. */
export interface PartyRef {
  name: string;
  identifierScheme: IdentifierScheme | string;
  identifier: string;
  /** ISO 3166-1 alpha-2 of the supervising jurisdiction. */
  jurisdiction: string;
}

/** The legal test a predicate stands for. */
export interface LegalBasis {
  framework: string;
  reference: string;
  assertion: string;
}

/**
 * Per-predicate descriptor as written in config.json. `issuingParty` may be
 * the literal `"self"`, meaning the bundle issuer warrants the claim itself;
 * a named party is for reliance arrangements where another regulated firm did
 * the verification.
 */
export interface DescriptorConfig {
  legalBasis: LegalBasis;
  evidenceClass: EvidenceClass;
  issuingParty?: PartyRef | 'self';
  evidenceRef?: string;
}

/** Fully resolved descriptor as it goes into the job spec and the leaf hash. */
export interface ResolvedDescriptor {
  legalBasis: LegalBasis;
  issuingParty: PartyRef;
  evidenceClass: EvidenceClass;
  evidenceRef?: string;
}

/**
 * How long a predicate's assertion holds, as written in config.json. Exactly
 * one of `days`, `until`, or `openEnded` must be given.
 */
export interface ValidityConfig {
  /** Window length in days, inclusive of the first day. */
  days?: number;
  /** Fixed last day, `YYYY-MM-DD`. */
  until?: string;
  /** No self-imposed end; only a revocation record can end the claim. */
  openEnded?: boolean;
  /**
   * Days before the batch date on which the evidence was examined. Overridden
   * per subject by `mapping.evidenceDateField` when that column is present.
   */
  basisAsOfOffsetDays?: number;
}

export interface ResolvedValidity {
  from: number;
  until?: number;
  basisAsOf: number;
}

/** The party legally responsible for every assertion in a bundle. */
export interface IssuerConfig extends PartyRef {
  /** Stable label for the signing key, so rotation does not change identity. */
  keyId: string;
}

export interface ClaimDefaults {
  issuingParty?: PartyRef | 'self';
  evidenceClass?: EvidenceClass;
  validity?: ValidityConfig;
}

export interface ClaimsConfig {
  defaults?: ClaimDefaults;
}
