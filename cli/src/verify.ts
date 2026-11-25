// Wrapper around the native `trusset-verifier-cli` binary.

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export interface ClaimReport {
  status: string;
  detail: string | null;
  legal_basis: string;
  legal_reference: string;
  assertion: string;
  evidence_class: string;
  issuing_party: string;
  issuing_party_identifier: string;
  validity_from: number;
  validity_from_date: string;
  validity_until: number | null;
  validity_until_date: string | null;
  basis_as_of: number;
  basis_as_of_date: string;
  list_id: string | null;
  list_version: number | null;
  list_resolved: boolean | null;
  list_entry_count: number | null;
}

export interface LeafReport {
  field: string;
  circuit: string;
  pass: boolean;
  reason: string | null;
  claim: ClaimReport | null;
}

export interface IssuerReport {
  name: string;
  identifier_scheme: string;
  identifier: string;
  jurisdiction: string;
  key_id: string;
  public_key: string;
  public_key_disagrees_with_anchor: boolean;
}

export interface TemporalReport {
  as_of: string;
  as_of_epoch_days: number;
  as_of_date: string;
  as_of_chain_id: number | null;
  as_of_block: number | null;
  resolved_root: string | null;
  resolved_root_matches: boolean | null;
  root_history_available: boolean;
  revocations_available: boolean;
  entitled: boolean;
  notes: string[];
  unpinned_epoch: boolean;
  manifest_as_of_date: string | null;
  epoch_days_source: string | null;
}

export interface AttestationFile {
  version: string;
  subject: string;
  root: string;
  investorClass: number;
  predicates: string;
  predicateNames: string[];
  softExpiry: number;
  hardExpiry: number;
  attester: string;
  chainId: number;
  hub: string;
  keyId: number;
}

/** v3.1: the signed header and the attestation the bundle supports. */
export interface HeaderReport {
  present: boolean;
  signature_valid: boolean;
  consistent: boolean;
  reason: string | null;
  attester: string | null;
  chain_id: number | null;
  hub: string | null;
  key_id: number | null;
  attestation: AttestationFile | null;
}

export interface VerifyReport {
  wallet_address: string;
  kyc_hash: string;
  leaf_count: number;
  layout_ok: boolean;
  mode_acceptable: boolean;
  kyc_hash_file_matches: boolean;
  signature_valid: boolean;
  merkle_root_valid: boolean;
  leaves: LeafReport[];
  /** Anchor(s) used: `public_key`, `root`, `public_key+root`, or `none`. */
  anchor: string;
  root_anchor_valid: boolean;
  manifest_version: string;
  overall_pass: boolean;
  issuer: IssuerReport | null;
  temporal: TemporalReport;
  /** v3.1 only; null for earlier bundles. */
  header: HeaderReport | null;
}

export interface VerifyInvocation {
  /** A bundle directory. Mutually exclusive with `archivePath`. */
  bundlePath?: string;
  /** A self-contained archive. Mutually exclusive with `bundlePath`. */
  archivePath?: string;
  /** Which subject to read from an archive. */
  subject?: string;
  /** Operator ed25519 public key. Optional when `rootHex` is supplied. */
  publicKeyHex?: string;
  /** kycHash read from chain. Optional when `publicKeyHex` is supplied. */
  rootHex?: string;
  /**
   * Accept bundles with `manifest.mode == "stub"` (development bundles
   * built with `--skip-proofs`). Default is to reject — strict mode is
   * the post-Stage-18 default.
   */
  acceptStub?: boolean;
  /** Evaluate entitlement at this block height, with `chainId`. */
  asOfBlock?: string | number;
  chainId?: string | number;
  /** Evaluate entitlement on this `YYYY-MM-DD`. */
  asOfDate?: string;
  /**
   * Treat this `YYYY-MM-DD` as today. Lets a reviewer ask what a bundle is
   * worth at a future or past date without moving the machine's clock.
   */
  now?: string;
  /** Registry root for as-of resolution. Ignored when reading an archive. */
  registryDir?: string;
  /** Override binary path. Default: auto-discover. */
  verifierPath?: string;
}

export interface VerifyResult {
  exitCode: number;
  report?: VerifyReport;
  humanOutput: string;
  stderr: string;
}

export async function runVerify(args: VerifyInvocation): Promise<VerifyResult> {
  const binary = args.verifierPath ?? locateVerifier();
  const cliArgs: string[] = ['--json'];
  if (args.archivePath) {
    cliArgs.push('--archive', args.archivePath);
    if (args.subject) cliArgs.push('--subject', args.subject);
  } else if (args.bundlePath) {
    cliArgs.push('--bundle', args.bundlePath);
  }
  if (args.publicKeyHex) cliArgs.push('--public-key', args.publicKeyHex);
  if (args.rootHex) cliArgs.push('--root', args.rootHex);
  if (args.acceptStub) cliArgs.push('--accept-stub');
  if (args.asOfBlock !== undefined) cliArgs.push('--as-of-block', String(args.asOfBlock));
  if (args.chainId !== undefined) cliArgs.push('--chain-id', String(args.chainId));
  if (args.asOfDate) cliArgs.push('--as-of-date', args.asOfDate);
  if (args.now) cliArgs.push('--now', args.now);
  if (args.registryDir) cliArgs.push('--registry', args.registryDir);

  return new Promise<VerifyResult>((resolve, reject) => {
    const child = spawn(binary, cliArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdoutBuf = '';
    let stderrBuf = '';
    child.stdout.on('data', (chunk) => (stdoutBuf += chunk.toString('utf-8')));
    child.stderr.on('data', (chunk) => (stderrBuf += chunk.toString('utf-8')));
    child.on('error', reject);
    child.on('close', (code) => {
      let report: VerifyReport | undefined;
      const trimmed = stdoutBuf.trim();
      if (trimmed) {
        try {
          report = JSON.parse(trimmed) as VerifyReport;
        } catch {
          /* leave undefined; humanOutput preserves it */
        }
      }
      resolve({
        exitCode: code ?? -1,
        report,
        humanOutput: stdoutBuf,
        stderr: stderrBuf,
      });
    });
  });
}

export function locateVerifier(): string {
  if (process.env.TRUSSET_VERIFIER_BIN) return process.env.TRUSSET_VERIFIER_BIN;
  let dir = process.cwd();
  for (let i = 0; i < 5; i++) {
    const release = path.join(dir, 'target', 'release', 'trusset-verifier-cli');
    if (fs.existsSync(release)) return release;
    const debug = path.join(dir, 'target', 'debug', 'trusset-verifier-cli');
    if (fs.existsSync(debug)) return debug;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return 'trusset-verifier-cli';
}

export function formatHumanReport(report: VerifyReport, source?: string): string {
  const check = (ok: boolean) => (ok ? '[ok]' : '[FAIL]');
  // An anchor the caller did not supply is not a failure.
  const usedKey = report.anchor === 'public_key' || report.anchor === 'public_key+root';
  const usedRoot = report.anchor === 'root' || report.anchor === 'public_key+root';
  const anchorCheck = (supplied: boolean, ok: boolean) => (supplied ? check(ok) : '[n/a]');
  const lines: string[] = [];
  if (source) lines.push(`Source:    ${source}`);
  lines.push(`Wallet:    ${report.wallet_address}`);
  lines.push(`kycHash:   ${report.kyc_hash}`);
  lines.push(`Leaves:    ${report.leaf_count}`);
  lines.push(`Version:   ${report.manifest_version}`);
  lines.push(`Anchor:    ${report.anchor}`);
  lines.push(
    report.issuer
      ? `Issuer:    ${report.issuer.name} (${report.issuer.identifier_scheme}:${report.issuer.identifier}, ${report.issuer.jurisdiction})  key ${report.issuer.key_id}`
      : 'Issuer:    (not recorded, pre-v3 bundle)',
  );
  lines.push('');
  lines.push(`  layout_ok:              ${check(report.layout_ok)}`);
  lines.push(`  mode_acceptable:        ${check(report.mode_acceptable)}`);
  lines.push(`  kyc_hash_file_matches:  ${check(report.kyc_hash_file_matches)}`);
  lines.push(`  signature_valid:        ${anchorCheck(usedKey, report.signature_valid)}`);
  lines.push(`  root_anchor_valid:      ${anchorCheck(usedRoot, report.root_anchor_valid)}`);
  lines.push(`  merkle_root_valid:      ${check(report.merkle_root_valid)}`);
  const h = report.header;
  if (h) {
    lines.push(`  header_present:         ${check(h.present)}`);
    lines.push(`  header_consistent:      ${check(h.consistent)}`);
    lines.push(`  header_signature_valid: ${anchorCheck(usedKey, h.signature_valid)}`);
    if (h.attester) {
      lines.push(`  attestation:            attester ${h.attester} on chain ${h.chain_id} (hub ${h.hub}, key ${h.key_id})`);
    }
    if (h.attestation) {
      lines.push(
        `                          class ${h.attestation.investorClass}, predicates ${h.attestation.predicates} [${h.attestation.predicateNames.join(', ')}]`,
      );
    }
    if (h.reason) lines.push(`  header_reason:          ${h.reason}`);
  }
  lines.push('');

  const t = report.temporal;
  lines.push(`As of:     ${t.as_of_date} (${t.as_of})`);
  if (t.as_of_chain_id !== null && t.as_of_block !== null) {
    lines.push(`           chain ${t.as_of_chain_id} block ${t.as_of_block}`);
  }
  if (t.resolved_root) {
    const verdict =
      t.resolved_root_matches === true
        ? '[ok] this bundle'
        : t.resolved_root_matches === false
          ? '[FAIL] a different issuance'
          : '';
    lines.push(`  root on chain then:     ${t.resolved_root.slice(0, 14)}… ${verdict}`);
  }
  if (t.unpinned_epoch) {
    lines.push('  reproducible:           [FAIL] built with an unpinned epoch');
  }
  lines.push('');
  lines.push('Per-leaf:');
  for (const leaf of report.leaves) {
    const mark = check(leaf.pass);
    const reason = leaf.reason ? `  (${leaf.reason})` : '';
    lines.push(`  ${mark} ${leaf.field.padEnd(24)} ${leaf.circuit.padEnd(20)}${reason}`);
    const c = leaf.claim;
    if (c) {
      lines.push(`        claim    ${c.legal_basis} / ${c.legal_reference}: ${c.assertion}`);
      lines.push(`        evidence ${c.evidence_class}   warranted by ${c.issuing_party} (${c.issuing_party_identifier})`);
      lines.push(
        `        valid    ${c.validity_from_date} .. ${c.validity_until_date ?? 'open-ended'}   evidence examined ${c.basis_as_of_date}`,
      );
      if (c.list_id && c.list_version !== null) {
        const resolved =
          c.list_resolved === true
            ? `resolved, ${c.list_entry_count ?? '?'} entries`
            : 'NOT RESOLVED: no registry for this root was supplied';
        lines.push(`        list     ${c.list_id} v${c.list_version} (${resolved})`);
      }
      lines.push(`        status   ${c.status === 'effective' ? '[ok]' : '[!!]'} ${c.status}`);
      if (c.detail) lines.push(`                 ${c.detail}`);
    }
  }
  if (t.notes.length > 0) {
    lines.push('');
    lines.push('Notes:');
    for (const n of t.notes) lines.push(`  - ${n}`);
  }
  lines.push('');
  lines.push(`Verifies:  ${report.overall_pass ? 'PASS' : 'FAIL'}`);
  lines.push(`Entitled:  ${t.entitled ? 'YES' : 'NO'}   (as of ${t.as_of_date})`);
  return lines.join('\n');
}
