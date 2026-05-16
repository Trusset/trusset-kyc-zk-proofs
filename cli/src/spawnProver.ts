// Child-process bridge to the Rust prover binary.
//
// The TS layer:
//   1. Locates the binary in the workspace target directory.
//   2. Verifies the master key + signing key env vars are present before
//      spawning (matching what main.rs does in Rust, but with a faster
//      failure path).
//   3. Streams the Job JSON to stdin.
//   4. Parses NDJSON events from stdout.
//   5. Captures stderr as unstructured logs.

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ResolvedConfig } from './config';
import { Job } from './jobSpec';

export type ProverEvent =
  | { event: 'start'; subjects: number }
  | { event: 'subject_start'; subject_id: string }
  | { event: 'leaf_proved'; subject_id: string; field: string; proof_bytes: number; ms: number }
  | { event: 'subject_done'; subject_id: string; bundle_path: string }
  | { event: 'subject_failed'; subject_id: string; error_code: string; message: string }
  | { event: 'done'; ok: number; failed: number };

export interface ProverInvocationResult {
  exitCode: number;
  events: ProverEvent[];
  stderr: string;
  done?: { ok: number; failed: number };
}

export interface SpawnOptions {
  /** Override the binary path (otherwise auto-discovered under target/). */
  proverPath?: string;
  /** Forwarded to the child as the prover's working directory. Default: cwd. */
  cwd?: string;
  /** Called for every NDJSON event. */
  onEvent?: (event: ProverEvent) => void;
}

export async function runProver(
  job: Job,
  rc: ResolvedConfig,
  opts: SpawnOptions = {},
): Promise<ProverInvocationResult> {
  // ---- Pre-flight env checks ----
  const masterKey = process.env[rc.masterKeyEnv];
  const signingKey = process.env[rc.signingKeyEnv];
  if (!masterKey) {
    throw new Error(
      `env var ${rc.masterKeyEnv} is required (32-byte hex). Set it before running:\n  export ${rc.masterKeyEnv}=$(openssl rand -hex 32)`,
    );
  }
  if (!signingKey) {
    throw new Error(
      `env var ${rc.signingKeyEnv} is required (32-byte hex). Set it before running:\n  export ${rc.signingKeyEnv}=$(openssl rand -hex 32)`,
    );
  }

  const binary = opts.proverPath ?? locateProver();

  // Pass master/signing keys through using the canonical env var names the
  // Rust binary expects (TRUSSET_KYC_MASTER_KEY / TRUSSET_KYC_SIGNING_KEY),
  // regardless of what the config calls them on the TS side.
  const childEnv = {
    ...process.env,
    TRUSSET_KYC_MASTER_KEY: masterKey,
    TRUSSET_KYC_SIGNING_KEY: signingKey,
    RUST_BACKTRACE: '0',
  };

  const child = spawn(binary, [], {
    cwd: opts.cwd ?? process.cwd(),
    env: childEnv,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const events: ProverEvent[] = [];
  let stdoutBuf = '';
  let stderrBuf = '';

  child.stdout.on('data', (chunk: Buffer) => {
    stdoutBuf += chunk.toString('utf-8');
    let nl = stdoutBuf.indexOf('\n');
    while (nl !== -1) {
      const line = stdoutBuf.slice(0, nl);
      stdoutBuf = stdoutBuf.slice(nl + 1);
      nl = stdoutBuf.indexOf('\n');
      if (!line.trim()) continue;
      let parsed: ProverEvent;
      try {
        parsed = JSON.parse(line) as ProverEvent;
      } catch {
        process.stderr.write(`[prover] (non-JSON line): ${line}\n`);
        continue;
      }
      events.push(parsed);
      opts.onEvent?.(parsed);
    }
  });

  child.stderr.on('data', (chunk: Buffer) => {
    const s = chunk.toString('utf-8');
    stderrBuf += s;
    process.stderr.write(s.replace(/^/gm, '[prover] '));
  });

  // Write the job JSON.
  child.stdin.write(JSON.stringify(job));
  child.stdin.end();

  return new Promise<ProverInvocationResult>((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (code) => {
      const done = events.find((e): e is Extract<ProverEvent, { event: 'done' }> => e.event === 'done');
      resolve({
        exitCode: code ?? -1,
        events,
        stderr: stderrBuf,
        done,
      });
    });
  });
}

/**
 * Locate `trusset-prover` in the workspace. Looks for the release binary
 * first, then debug, then assumes it's on PATH.
 */
export function locateProver(): string {
  // 1. Env override.
  if (process.env.TRUSSET_PROVER_BIN) return process.env.TRUSSET_PROVER_BIN;

  // 2. Walk up from cwd looking for `target/release/trusset-prover`.
  let dir = process.cwd();
  for (let i = 0; i < 5; i++) {
    const release = path.join(dir, 'target', 'release', 'trusset-prover');
    if (fs.existsSync(release)) return release;
    const debug = path.join(dir, 'target', 'debug', 'trusset-prover');
    if (fs.existsSync(debug)) return debug;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  // 3. Fall back to PATH lookup.
  return 'trusset-prover';
}
