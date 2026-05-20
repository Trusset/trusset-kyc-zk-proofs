// Wrapper around the native `trusset-verifier-cli` binary.

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

export interface VerifyReport {
  wallet_address: string;
  kyc_hash: string;
  leaf_count: number;
  layout_ok: boolean;
  mode_acceptable: boolean;
  kyc_hash_file_matches: boolean;
  signature_valid: boolean;
  merkle_root_valid: boolean;
  leaves: { field: string; circuit: string; pass: boolean; reason: string | null }[];
  overall_pass: boolean;
}

export interface VerifyInvocation {
  bundlePath: string;
  publicKeyHex: string;
  /**
   * Accept bundles with `manifest.mode == "stub"` (development bundles
   * built with `--skip-proofs`). Default is to reject — strict mode is
   * the post-Stage-18 default.
   */
  acceptStub?: boolean;
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
  const cliArgs = [
    '--bundle',
    args.bundlePath,
    '--public-key',
    args.publicKeyHex,
    '--json',
  ];
  if (args.acceptStub) cliArgs.push('--accept-stub');

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

export function formatHumanReport(report: VerifyReport, bundlePath: string): string {
  const check = (ok: boolean) => (ok ? '[ok]' : '[FAIL]');
  const lines: string[] = [];
  lines.push(`Bundle:    ${bundlePath}`);
  lines.push(`Wallet:    ${report.wallet_address}`);
  lines.push(`kycHash:   ${report.kyc_hash}`);
  lines.push(`Leaves:    ${report.leaf_count}`);
  lines.push('');
  lines.push(`  layout_ok:              ${check(report.layout_ok)}`);
  lines.push(`  mode_acceptable:        ${check(report.mode_acceptable)}`);
  lines.push(`  kyc_hash_file_matches:  ${check(report.kyc_hash_file_matches)}`);
  lines.push(`  signature_valid:        ${check(report.signature_valid)}`);
  lines.push(`  merkle_root_valid:      ${check(report.merkle_root_valid)}`);
  lines.push('');
  lines.push('Per-leaf:');
  for (const leaf of report.leaves) {
    const mark = check(leaf.pass);
    const reason = leaf.reason ? `  (${leaf.reason})` : '';
    lines.push(`  ${mark} ${leaf.field.padEnd(22)} ${leaf.circuit.padEnd(22)}${reason}`);
  }
  lines.push('');
  lines.push(`Overall:   ${report.overall_pass ? 'PASS' : 'FAIL'}`);
  return lines.join('\n');
}
