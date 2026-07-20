/**
 * Diff scanning support.
 *
 * `parseUnifiedDiff` reads `git diff` output (preferably with `--unified=0`
 * for tight ranges) and returns the set of *added* line numbers for each
 * touched file in the new revision.
 *
 * `scanDiff` is the high-level entry: it runs `git diff` for the given
 * range, scans each touched file from the working tree, then filters
 * findings to only those that overlap an added line.
 *
 * Why scan the whole file then filter (instead of scanning only the added
 * snippet)? Regex context: rules look at surrounding lines (e.g., the
 * comment-line skip in matcher-utils, multi-line patterns). Slicing the
 * file would lose that context and produce subtly wrong matches.
 */

import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  Analyzer,
  DEFAULT_IGNORE,
  ENGINE_VERSION,
  detectLanguageFromPath,
  collectSuppressions,
  evaluatePathSuppression,
  loadConfig,
  mergeSuppressions,
  suppressionsForPath,
  tallySuppression,
  type SuppressionTally,
  type AnalyzerOptions,
  type VibeguardConfig,
} from '@vibeguard/analyzer-core';
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

const FILE_HEADER_RE = /^\+\+\+ b\/(.+)$/;
const DEV_NULL = /^\+\+\+ \/dev\/null$/;
const HUNK_HEADER_RE = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;

/** Map of file path (post-image, repo-relative) → set of added 1-based line numbers. */
export type DiffMap = Map<string, Set<number>>;

/**
 * Parse `git diff` output. Recognises the `+++ b/<path>` headers and
 * `@@ -a,b +c,d @@` hunk headers; collects the added lines per file.
 */
export function parseUnifiedDiff(diff: string): DiffMap {
  const out: DiffMap = new Map();
  const lines = diff.split('\n');
  let currentFile: string | null = null;
  let nextLine = 0;
  let remaining = 0;

  for (const raw of lines) {
    if (DEV_NULL.test(raw)) {
      currentFile = null;
      continue;
    }
    const fileMatch = FILE_HEADER_RE.exec(raw);
    if (fileMatch) {
      currentFile = fileMatch[1] ?? null;
      remaining = 0;
      continue;
    }
    if (!currentFile) continue;

    const hunkMatch = HUNK_HEADER_RE.exec(raw);
    if (hunkMatch) {
      nextLine = Number.parseInt(hunkMatch[1] ?? '0', 10);
      // Default count is 1 when omitted (per unified diff format).
      remaining = hunkMatch[2] != null ? Number.parseInt(hunkMatch[2], 10) : 1;
      continue;
    }

    if (remaining <= 0) continue;

    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      let bucket = out.get(currentFile);
      if (!bucket) {
        bucket = new Set<number>();
        out.set(currentFile, bucket);
      }
      bucket.add(nextLine);
      nextLine += 1;
      remaining -= 1;
    } else if (raw.startsWith(' ')) {
      // Context line — only appears with --unified > 0.
      nextLine += 1;
      remaining -= 1;
    } else if (raw.startsWith('-')) {
      // Deletion: doesn't advance the new-file line counter.
    }
  }

  return out;
}

export async function gitDiff(range: string, cwd: string): Promise<string> {
  return spawnCapture('git', ['diff', '--unified=0', '--no-color', range, '--'], cwd);
}

function spawnCapture(cmd: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (b) => (stdout += b.toString('utf8')));
    child.stderr.on('data', (b) => (stderr += b.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${stderr.trim()}`));
    });
  });
}

export interface ScanDiffOptions extends AnalyzerOptions {
  cwd: string;
  range: string;
  mode?: ScanMode;
  includeRemediation?: boolean;
  /**
   * Extra directory names to ignore. Mirrors --ignore on scanPath. A diff
   * file is skipped when any of its path segments matches the ignore set
   * (default segments from DEFAULT_IGNORE plus these extras).
   */
  ignore?: string[];
  /** Pre-computed diff text instead of running git (for tests). */
  diffText?: string;
  /** Path to a vibeguard config file. `false` = skip discovery. */
  config?: string | false;
}

/**
 * True when any segment of `relPath` matches a name in `ignore`. Mirrors
 * the directory-name walk filter used by scanPath, applied to a flat
 * relative path here.
 */
function isIgnoredPath(relPath: string, ignore: Set<string>): boolean {
  // Normalise Windows separators so segment matching is OS-independent.
  const segments = relPath.split(/[\\/]/);
  for (const seg of segments) {
    if (ignore.has(seg)) return true;
  }
  return false;
}

/** True when finding's [startLine, endLine] overlaps any added line. */
function overlapsAdded(finding: Finding, added: Set<number>): boolean {
  const start = finding.startLine ?? 0;
  if (!start) return false;
  const end = finding.endLine ?? start;
  for (let line = start; line <= end; line++) {
    if (added.has(line)) return true;
  }
  return false;
}

export async function scanDiff(options: ScanDiffOptions): Promise<ScanResponse> {
  const startedAt = Date.now();
  const diffText = options.diffText ?? (await gitDiff(options.range, options.cwd));
  const diffMap = parseUnifiedDiff(diffText);
  const analyzer = new Analyzer(options);
  const findings: Finding[] = [];
  // Deduped by ruleId across the diffed files (see scanPath for the rationale).
  const ruleErrorsByRule = new Map<string, RuleError>();
  const degradationsByFileKind = new Map<string, ScanDegradation>();
  // D8, mirroring `scanPath`: pragma records come up from the analyzer, config
  // records are added below. Observability only; nothing here gates anything.
  const suppressionTally: SuppressionTally = new Map();
  const ignore = new Set([...DEFAULT_IGNORE, ...(options.ignore ?? [])]);
  const now = new Date();

  let config: VibeguardConfig | undefined;
  if (options.config !== false) {
    const explicit = options.config;
    const loaded = await loadConfig(options.cwd, explicit);
    config = loaded?.config;
  }

  for (const [relPath, added] of diffMap) {
    if (added.size === 0) continue;
    if (isIgnoredPath(relPath, ignore)) continue;
    const language = detectLanguageFromPath(relPath);
    let content: string;
    try {
      content = await readFile(join(options.cwd, relPath), 'utf8');
    } catch {
      // File deleted in the new revision, or unreadable — skip.
      continue;
    }
    const result = analyzer.scan({
      targetType: 'diff',
      filePath: relPath,
      content,
      language,
      mode: options.mode ?? 'standard',
      includeRemediation: options.includeRemediation,
    });
    const pathSuppressed = suppressionsForPath(config, relPath, now);
    for (const f of result.findings) {
      // Mirrors scanPath: a config wildcard refused by the severity gate keeps
      // the finding and records the refusal instead of dropping it.
      const decision = evaluatePathSuppression(pathSuppressed, f.ruleId, f.severity);
      if (decision.suppressed) {
        // Counted only if the finding would have been REPORTED, i.e. if it
        // touches the added lines. A diff scan drops everything outside the
        // changed range anyway, so counting a suppression there would claim
        // something was hidden when the diff scan was never going to show it.
        //
        // The pragma half cannot be filtered the same way and is not: the
        // analyzer has no diff context, so on this path its counts may include
        // findings outside the changed lines. Stated rather than papered over —
        // the error is towards reporting more suppressions than the diff would
        // have surfaced, never fewer.
        if (overlapsAdded(f, added)) {
          tallySuppression(suppressionTally, {
            channel: 'config',
            scope: 'path',
            ruleId: f.ruleId,
            filePath: f.filePath ?? relPath,
          });
        }
        continue;
      }
      const kept =
        decision.overridden && !f.suppressionOverridden
          ? { ...f, suppressionOverridden: decision.overridden }
          : f;
      if (overlapsAdded(kept, added)) findings.push(kept);
    }
    mergeSuppressions(suppressionTally, result.suppressions);
    for (const e of result.ruleErrors ?? []) {
      if (!ruleErrorsByRule.has(e.ruleId)) ruleErrorsByRule.set(e.ruleId, e);
    }
    // Carried through the same way `scanPath` does, and for the same reason: this
    // is the GitHub Action's path, so dropping degradations here would let a PR
    // pass review on a partial scan with nothing saying so. Keyed by file+kind,
    // not by rule — one oversized file trips the bound in dozens of rules.
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
    executionTimeMs: Date.now() - startedAt,
    engineVersions: { core: ENGINE_VERSION },
    generatedAt: new Date().toISOString(),
    ...(ruleErrorsByRule.size ? { ruleErrors: [...ruleErrorsByRule.values()] } : {}),
    ...(degradationsByFileKind.size ? { degradations: [...degradationsByFileKind.values()] } : {}),
    ...(suppressionTally.size ? { suppressions: collectSuppressions(suppressionTally) } : {}),
  };
}
