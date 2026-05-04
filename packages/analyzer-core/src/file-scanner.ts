import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import {
  emptySummary,
  summarize,
  compareSeverity,
  type Finding,
  type ScanMode,
  type ScanResponse,
} from '@vibeguard/findings-schema';
import { Analyzer, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
import { detectLanguageFromPath } from './language-detect.js';

const DEFAULT_IGNORE = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'out',
  '.next',
  '.turbo',
  'coverage',
  '.venv',
  'venv',
  '__pycache__',
  '.idea',
  '.vscode',
]);

const MAX_FILE_BYTES = 1_000_000; // 1 MB; skip larger files in MVP

async function* walk(dir: string, ignore: Set<string>): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (ignore.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walk(full, ignore);
    } else if (entry.isFile()) {
      yield full;
    }
  }
}

export interface ScanPathOptions extends AnalyzerOptions {
  mode?: ScanMode;
  includeRemediation?: boolean;
  /** Extra directory names to ignore on top of the defaults. */
  ignore?: string[];
  /** When true, only scan files whose extension maps to a known language. */
  knownLanguagesOnly?: boolean;
  /** Optional reporter invoked for each file scanned. */
  onFile?: (filePath: string) => void;
}

export async function scanPath(target: string, options: ScanPathOptions = {}): Promise<ScanResponse> {
  const start = Date.now();
  const ignore = new Set([...DEFAULT_IGNORE, ...(options.ignore ?? [])]);
  const analyzer = new Analyzer(options);
  const findings: Finding[] = [];

  const stats = await stat(target);
  const files: string[] = [];
  if (stats.isFile()) {
    files.push(target);
  } else {
    for await (const file of walk(target, ignore)) {
      files.push(file);
    }
  }

  for (const file of files) {
    options.onFile?.(file);
    const language = detectLanguageFromPath(file);
    if (options.knownLanguagesOnly && !language) continue;
    let info;
    try {
      info = await stat(file);
    } catch {
      continue;
    }
    if (info.size > MAX_FILE_BYTES) continue;
    let content: string;
    try {
      content = await readFile(file, 'utf8');
    } catch {
      continue;
    }
    const relPath = stats.isFile() ? file : relative(target, file).split(sep).join('/');
    const result = analyzer.scan({
      targetType: 'file',
      filePath: relPath,
      content,
      language,
      mode: options.mode ?? 'standard',
      includeRemediation: options.includeRemediation,
    });
    findings.push(...result.findings);
  }

  findings.sort((a, b) => {
    const sev = compareSeverity(a.severity, b.severity);
    if (sev !== 0) return sev;
    const fileA = a.filePath ?? '';
    const fileB = b.filePath ?? '';
    if (fileA !== fileB) return fileA.localeCompare(fileB);
    return (a.startLine ?? 0) - (b.startLine ?? 0);
  });

  return {
    summary: findings.length ? summarize(findings) : emptySummary(),
    findings,
    executionTimeMs: Date.now() - start,
    engineVersions: { core: ENGINE_VERSION },
    generatedAt: new Date().toISOString(),
  };
}
