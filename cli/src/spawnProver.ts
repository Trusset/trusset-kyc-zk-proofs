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
  | { event: 'leaf_failed'; subject_id: string; field: string; error_code: string; message: string }
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
  // A dry run writes nothing and signs nothing, so it must not require key
  // material: an operator should be able to check a batch before they have
  // finished setting the tool up.
  const masterKey = process.env[rc.masterKeyEnv];
  const signingKey = process.env[rc.signingKeyEnv];
  if (!job.dry_run) {
    for (const [name, value] of [
      [rc.masterKeyEnv, masterKey],
      [rc.signingKeyEnv, signingKey],
    ] as const) {
      if (!value) {
        throw new Error(
          [
            `Environment variable ${name} is not set; it holds 32 bytes of hex key material.`,
            '  Fix: load the keys `npm run init` generated for you:',
            '    set -a && . ./.trusset/keys.env && set +a',
            '  If you have not run init yet:  npm run init',
          ].join('\n'),
        );
      }
    }
  }

  const binary = opts.proverPath ?? locateProver();

  // Pass master/signing keys through using the canonical env var names the
  // Rust binary expects (TRUSSET_KYC_MASTER_KEY / TRUSSET_KYC_SIGNING_KEY),
  // regardless of what the config calls them on the TS side.
  // `TRUSSET_KYC_DETERMINISTIC=1` arms the prover's entropy guard: any OS
  // entropy draw during a deterministic run aborts instead of producing a
  // bundle that cannot be reproduced.
  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    RUST_BACKTRACE: '0',
  };
  if (masterKey) childEnv.TRUSSET_KYC_MASTER_KEY = masterKey;
  if (signingKey) childEnv.TRUSSET_KYC_SIGNING_KEY = signingKey;
  if (job.deterministic) {
    childEnv.TRUSSET_KYC_DETERMINISTIC = '1';
  } else {
    delete childEnv.TRUSSET_KYC_DETERMINISTIC;
  }

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
      // Flush a trailing line that arrived without a final newline, so a
      // prover killed mid-write does not silently lose its last event.
      const tail = stdoutBuf.trim();
      if (tail) {
        try {
          const parsed = JSON.parse(tail) as ProverEvent;
          events.push(parsed);
          opts.onEvent?.(parsed);
        } catch {
          process.stderr.write(`[prover] (non-JSON line): ${tail}\n`);
        }
        stdoutBuf = '';
      }
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

/**
 * Locate any workspace binary, with the same walk-up strategy. Used by the
 * commands that shell out to `trusset-registry` and `trusset-archive`.
 */
export function locateBinary(name: string): string {
  const envName = `TRUSSET_${name.replace(/-/g, '_').toUpperCase()}`;
  if (process.env[envName]) return process.env[envName] as string;
  let dir = process.cwd();
  for (let i = 0; i < 5; i++) {
    for (const profile of ['release', 'debug']) {
      const candidate = path.join(dir, 'target', profile, name);
      if (fs.existsSync(candidate)) return candidate;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return name;
}
