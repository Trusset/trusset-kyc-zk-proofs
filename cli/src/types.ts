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
  minTier: InvestorTypeName | number;
}

export interface AgeParams {
  minAgeYears?: number;
  minAgeDays?: number;
}

export interface SetMembershipParams {
  list: string;
}

export type PredicateSpec =
  | { circuit: 'preimage_knowledge'; params?: PreimageParams }
  | { circuit: 'tier_threshold'; params: TierParams }
  | { circuit: 'age_threshold'; params: AgeParams }
  | { circuit: 'set_membership'; params: SetMembershipParams }
  | { circuit: 'commitment_only'; params?: PreimageParams };

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

export interface SecurityConfig {
  clearInputAfterProcessing: boolean;
  /** v2 always uses Rescue-Prime; v1's `hashAlgorithm` is honored for backwards-readability with a deprecation warning. */
  hashAlgorithm?: string;
  masterKeyEnv?: string;
  epochDaysSource?: EpochDaysSource;
  deterministic?: boolean;
}

export interface ManifestConfig {
  signingKeyEnv?: string;
}

export interface ListsEntry {
  /** Relative path to the list-commitments JSON produced by `trusset-list-commit`. */
  path: string;
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
}

// =================== KYC record ===================

export type KycFieldValue = string | number | boolean | null | undefined;
export type KycRecord = Record<string, KycFieldValue>;

// =================== summary output (batched CSV row) ===================

export interface IndexRow {
  index?: number;
  walletAddress: string;
  country: string;
  investorType: InvestorTypeName;
  softExpiryDays: number;
  hardExpiryDays: number;
  kycHash: string;
}
