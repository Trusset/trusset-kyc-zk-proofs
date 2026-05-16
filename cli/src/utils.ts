// Lifted verbatim from v1 src/utils.ts (plan §"Critical files" — reused
// unchanged). BOM-safe CSV reader, JSON ingest, ISO-timestamp output
// filenames, and `--clearInputAfterProcessing` cleanup. The only edit is
// the import path for v2 Config / KycRecord.

import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'csv-parse/sync';
import { stringify, Input } from 'csv-stringify/sync';
import { Config, KycRecord } from './types';

const INPUT_DIR = path.join(process.cwd(), 'input');
const OUTPUT_DIR = path.join(process.cwd(), 'output');

export function inputDir(): string {
  return INPUT_DIR;
}

export function outputDir(): string {
  return OUTPUT_DIR;
}

export function ensureDirectories(): void {
  if (!fs.existsSync(INPUT_DIR)) fs.mkdirSync(INPUT_DIR, { recursive: true });
  if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });
}

export function getInputFiles(): string[] {
  ensureDirectories();
  return fs
    .readdirSync(INPUT_DIR)
    .filter((f) => {
      const lower = f.toLowerCase();
      return lower.endsWith('.json') || lower.endsWith('.csv');
    })
    .sort()
    .map((f) => path.join(INPUT_DIR, f));
}

export function readInputFile(filePath: string): KycRecord[] {
  const ext = path.extname(filePath).toLowerCase();
  const content = fs.readFileSync(filePath, 'utf-8');

  if (ext === '.json') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content);
    } catch {
      throw new Error(`Invalid JSON in file: ${path.basename(filePath)}`);
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      parsed = [parsed];
    }
    if (!Array.isArray(parsed)) {
      throw new Error(`File ${path.basename(filePath)} must contain an array or object`);
    }
    return parsed as KycRecord[];
  }

  if (ext === '.csv') {
    return parse(content, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      bom: true,
    }) as KycRecord[];
  }

  throw new Error(`Unsupported file format: ${ext}`);
}

/**
 * Write the v1-compatible batched index CSV/JSON. v2 also emits per-subject
 * directories under `output/<wallet>/`; this function only writes the
 * top-level summary file consumed by the existing Trusset uploader.
 */
export function writeIndexFile<T extends object>(
  data: T[],
  config: Config,
  suffix: string = '',
): string {
  ensureDirectories();
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const ext = config.output.format;
  const filename = `kyc_hashes_${timestamp}${suffix}.${ext}`;
  const outputPath = path.join(OUTPUT_DIR, filename);

  if (data.length === 0) {
    fs.writeFileSync(outputPath, ext === 'json' ? '[]' : '');
    return outputPath;
  }

  if (ext === 'json') {
    fs.writeFileSync(outputPath, JSON.stringify(data, null, 2));
  } else {
    const columnSet = new Set<string>(Object.keys(data[0] as Record<string, unknown>));
    for (const row of data) {
      Object.keys(row as Record<string, unknown>).forEach((k) => columnSet.add(k));
    }
    const columns = Array.from(columnSet);
    const csv = stringify(data as unknown as Input, { header: true, columns });
    fs.writeFileSync(outputPath, csv);
  }

  return outputPath;
}

export function clearInputFolder(): void {
  if (!fs.existsSync(INPUT_DIR)) return;
  const files = fs.readdirSync(INPUT_DIR);
  for (const file of files) {
    if (file === '.gitkeep') continue;
    const filePath = path.join(INPUT_DIR, file);
    try {
      const stat = fs.statSync(filePath);
      if (stat.isFile()) fs.unlinkSync(filePath);
    } catch {
      continue;
    }
  }
}
