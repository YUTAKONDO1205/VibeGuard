import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  emptySummary,
  summarize,
  compareSeverity,
  type Finding,
  type RuleError,
  type ScanDegradation,
  type ScanMode,
  type ScanResponse,
} from '@vibeguard/findings-schema';
import { Analyzer, ENGINE_VERSION, type AnalyzerOptions } from './analyzer.js';
import { detectLanguageFromPath } from './language-detect.js';
import { evaluatePathSuppression, suppressionsForPath, type VibeguardConfig } from './config.js';
import { collectSuppressions, mergeSuppressions, tallySuppression, type SuppressionTally } from './suppress.js';
import { loadConfig } from './config-loader.js';

export const DEFAULT_IGNORE = new Set([
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
  /**
   * Explicit config file path. When omitted, scanPath auto-discovers
   * `.vibeguardrc.json` / `vibeguard.config.json` in the scan target's
   * directory. Pass `false` to skip discovery entirely.
   */
  config?: string | false;
  /** Override "now" when evaluating config `expires` dates. Primarily for tests. */
  now?: Date;
}

export async function scanPath(target: string, options: ScanPathOptions = {}): Promise<ScanResponse> {
  const start = Date.now();
  const ignore = new Set([...DEFAULT_IGNORE, ...(options.ignore ?? [])]);
  const analyzer = new Analyzer(options);
  const findings: Finding[] = [];
  // Deduped by ruleId: a rule that throws on every file would otherwise appear
  // once per file. Keep the first message. Without this, a rule crash is visible
  // in a single-snippet `Analyzer.scan` but silently lost across a directory scan.
  const ruleErrorsByRule = new Map<string, RuleError>();
  const degradationsByFileKind = new Map<string, ScanDegradation>();
  // D8: both suppression channels land in one tally. The analyzer reports the
  // pragma half per file (and that per-file response is otherwise discarded
  // here), the loop below adds the config half.
  const suppressionTally: SuppressionTally = new Map();
  const now = options.now ?? new Date();

  const stats = await stat(target);
  const files: string[] = [];
  if (stats.isFile()) {
    files.push(target);
  } else {
    for await (const file of walk(target, ignore)) {
      files.push(file);
    }
  }

  let config: VibeguardConfig | undefined;
  if (options.config !== false) {
    const configDir = stats.isFile() ? dirname(resolve(target)) : resolve(target);
    const explicit = options.config
      ? isAbsolute(options.config)
        ? options.config
        : resolve(options.config)
      : undefined;
    const loaded = await loadConfig(configDir, explicit);
    config = loaded?.config;
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
    const pathSuppressed = suppressionsForPath(config, relPath, now);
    for (const f of result.findings) {
      // A config wildcard that the severity gate refused keeps the finding and
      // records the refusal on it, exactly like the pragma channel does inside
      // the analyzer. Note the pragma channel may already have marked this
      // finding; the config refusal does not overwrite that — one mark is the
      // signal, and the earlier one is the more specific of the two.
      const decision = evaluatePathSuppression(pathSuppressed, f.ruleId, f.severity);
      if (decision.suppressed) {
        // D8, config half. Not a defence — the finding is dropped exactly as
        // before — but the drop is now counted. `scope` is `path` unconditionally
        // because that is the only scope the config channel has (`suppress[].paths`).
        tallySuppression(suppressionTally, {
          channel: 'config',
          scope: 'path',
          ruleId: f.ruleId,
          filePath: f.filePath ?? relPath,
        });
        continue;
      }
      findings.push(
        decision.overridden && !f.suppressionOverridden
          ? { ...f, suppressionOverridden: decision.overridden }
          : f,
      );
    }
    // The pragma-channel tally from inside the analyzer. Merged, never
    // overwritten: these are counts, and two files suppressing the same rule are
    // two suppressions.
    mergeSuppressions(suppressionTally, result.suppressions);
    for (const e of result.ruleErrors ?? []) {
      if (!ruleErrorsByRule.has(e.ruleId)) ruleErrorsByRule.set(e.ruleId, e);
    }
    // Degradations must survive the directory walk or the whole D3 observability
    // path is dead on the channel that matters most: the CLI and the GitHub
    // Action both come through here, so dropping them meant a 66 KB file was
    // reported as "1 finding" with no hint that 16 KB of it was never scanned —
    // exactly the "partial scan reads as clean" failure the bounds exist to
    // prevent.
    //
    // Keyed by FILE + KIND, not by rule. One oversized file trips the bound in
    // every rule that looks at it (54 of them, measured), and 54 identical lines
    // would bury the signal they exist to raise. One line per file per kind says
    // everything the reader needs: which file was cut short, and how.
    for (const d of result.degradations ?? []) {
      const key = `${d.filePath ?? relPath}::${d.kind}`;
      if (!degradationsByFileKind.has(key)) {
        degradationsByFileKind.set(key, { ...d, filePath: d.filePath ?? relPath });
      }
    }
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
    ...(ruleErrorsByRule.size ? { ruleErrors: [...ruleErrorsByRule.values()] } : {}),
    ...(degradationsByFileKind.size ? { degradations: [...degradationsByFileKind.values()] } : {}),
    ...(suppressionTally.size ? { suppressions: collectSuppressions(suppressionTally) } : {}),
  };
}
