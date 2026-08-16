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
import { readFile, stat } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import {
  Analyzer,
  DEFAULT_IGNORE,
  MAX_FILE_BYTES,
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
  type DeclaredPackageVetoRecord,
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

/**
 * Run `git diff` in a format this parser can actually read.
 *
 * The `-c` flags are not cosmetic — each one pins a knob that a USER's
 * gitconfig can otherwise flip out from under us, and every one of those flips
 * is silent. `parseUnifiedDiff` recognises `+++ b/<path>` and nothing else, so
 * a header in any other shape registers no file, contributes no added lines,
 * and the scan reports a clean diff with exit 0. That is the worst failure mode
 * a security tool has: not an error, an all-clear.
 *
 *  - `diff.noprefix=true` drops the `a/`/`b/` prefixes entirely, so headers
 *    arrive as `+++ path`. A developer who set this once for copy-pasteable
 *    patches turns every diff scan into a no-op — including in CI, because a
 *    self-hosted runner or a Docker image with a baked-in gitconfig carries the
 *    setting into the Action.
 *  - `diff.mnemonicPrefix=true` rewrites the prefixes semantically (`i/`, `w/`,
 *    `c/`, `o/`), which misses the regex the same way.
 *  - `core.quotepath=true` (git's DEFAULT) octal-escapes any non-ASCII byte and
 *    wraps the header in quotes: `+++ "b/src/\350\252\215..."`. Repositories
 *    with non-ASCII filenames therefore skip exactly those files.
 *
 * Forcing the prefixes explicitly is deliberately preferred over teaching the
 * parser every variant: there is one shape to parse, and it does not depend on
 * ambient configuration. `-c` applies to this invocation only and does not
 * touch the user's config.
 */
export async function gitDiff(range: string, cwd: string): Promise<string> {
  return spawnCapture(
    'git',
    [
      '-c',
      'core.quotepath=false',
      '-c',
      'diff.noprefix=false',
      '-c',
      'diff.mnemonicPrefix=false',
      'diff',
      '--unified=0',
      '--no-color',
      '--src-prefix=a/',
      '--dst-prefix=b/',
      range,
      '--',
    ],
    cwd,
  );
}

/**
 * Absolute path of the repository root containing `cwd`, or `null` when `cwd`
 * is not inside a work tree.
 *
 * Diff headers are ALWAYS repo-root-relative, whatever directory git ran in.
 * Resolving files against the scan target instead — which is what this code did
 * before — builds paths like `samples/vulnerable/apps/cli/src/x.ts` for a scan
 * of `samples/vulnerable`. Those do not exist, every read fails, and the run
 * reports zero findings and exits 0. The scan looks clean because nothing was
 * read, which is indistinguishable from clean because nothing was wrong.
 */
export async function gitRepoRootOf(cwd: string): Promise<string | null> {
  return gitRepoRoot(cwd);
}

async function gitRepoRoot(cwd: string): Promise<string | null> {
  try {
    const out = await spawnCapture('git', ['rev-parse', '--show-toplevel'], cwd);
    const root = out.trim();
    return root.length > 0 ? root : null;
  } catch {
    return null;
  }
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
  /**
   * Only scan files whose extension maps to a known language. Mirrors
   * `--known-only` on `scanPath`, which is where it used to stop: the flag
   * parsed, was accepted, and was then silently ignored on this path, so a
   * diff run scanned exactly the files the user had asked it not to.
   */
  knownLanguagesOnly?: boolean;
  /** Pre-computed diff text instead of running git (for tests). */
  diffText?: string;
  /** Path to a vibeguard config file. `false` = skip discovery. */
  config?: string | false;
}

/**
 * The repo-root-relative, `/`-separated prefix that `target` denotes, or `''`
 * when the target IS the root (or sits outside it, where filtering would be
 * meaningless). Diff paths are compared against this to decide what a scan of a
 * subdirectory covers.
 *
 * The trailing slash matters: without it, a target of `app` would also admit
 * `apps/`, which is a different directory.
 */
export function diffScopePrefix(repoRoot: string, target: string): string {
  const rel = relative(resolve(repoRoot), resolve(target));
  // Same directory, or target is above/outside the root — no filtering.
  if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return '';
  return `${rel.split(sep).join('/')}/`;
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

  // Where diff paths are rooted, and which of them this scan was asked about.
  //
  // `options.cwd` is the TARGET the user named, which may be a subdirectory.
  // Diff paths are repo-root-relative regardless, so reads resolve against the
  // root; the target then acts as a FILTER. Naming a subdirectory therefore
  // means "the part of this diff under here", which is what a user asking for
  // `vibeguard packages/rules --diff main..HEAD` means — not "the whole diff"
  // and, as it behaved before, not "nothing at all".
  //
  // `diffText` is the injected-for-tests path; those fixtures are already
  // root-relative and have no repo to consult, so the target stays the base.
  const repoRoot = options.diffText === undefined ? await gitRepoRoot(options.cwd) : null;
  const readBase = repoRoot ?? options.cwd;
  const scopePrefix = repoRoot ? diffScopePrefix(repoRoot, options.cwd) : '';
  const analyzer = new Analyzer(options);
  const findings: Finding[] = [];
  // Deduped by ruleId across the diffed files (see scanPath for the rationale).
  const ruleErrorsByRule = new Map<string, RuleError>();
  const degradationsByFileKind = new Map<string, ScanDegradation>();
  // Aggregated across files for the same reason the suppression tally is: a
  // channel that DELETES findings has to be visible in the artifact, not only
  // on the CLI's stderr. Keyed rule|package|file, so a project depending on a
  // dozen near-miss names gets a dozen lines and not one per match.
  const vetoesByKey = new Map<string, DeclaredPackageVetoRecord>();
  // Whether the veto was ARMED, which is a different fact from whether it
  // fired. Read off the per-file responses exactly as `scanPath` does — the
  // analyzer emits `declaredPackageVetoes` at all (`[]` included) only when it
  // ran — rather than recomputed from the request, which would drift.
  //
  // This path is the GitHub Action's, so it is the one place where the
  // distinction matters most: a PR comment that cannot tell "nobody read your
  // lockfile" from "your lockfile refuted nothing" is the artifact a reviewer
  // acts on.
  let vetoArmed = false;
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
    // Outside the directory the user named — not this scan's business.
    if (scopePrefix && !relPath.startsWith(scopePrefix)) continue;
    // Two different paths for two different jobs, and conflating them is what
    // this whole block exists to avoid:
    //  - `relPath` is repo-root-relative, because that is what git emits. It
    //    addresses the file ON DISK and is used for nothing else.
    //  - `displayPath` is relative to the TARGET the user named, because that
    //    is what a directory scan reports and what every consumer downstream
    //    already assumes. `fix.ts` reads a finding back as
    //    `join(target, displayPath)`; config `suppress[].paths` globs are
    //    written against it; the SARIF adapter emits it as the artifact URI.
    //    Reporting root-relative paths here would silently change the meaning
    //    of all three for a subdirectory scan.
    // When the target IS the repository root, `scopePrefix` is empty and the
    // two are identical — which is why this distinction never surfaced before.
    const displayPath = scopePrefix ? relPath.slice(scopePrefix.length) : relPath;
    const language = detectLanguageFromPath(relPath);
    // Mirrors `scanPath`. Both admission rules used to be missing here, so
    // `--known-only` did nothing on a diff run and a 40 MB generated file in a
    // commit was read into memory whole — the same input the directory scan
    // caps at MAX_FILE_BYTES.
    if (options.knownLanguagesOnly && !language) continue;
    const absolute = join(readBase, relPath);
    try {
      const info = await stat(absolute);
      if (info.size > MAX_FILE_BYTES) continue;
    } catch {
      // Deleted in the new revision, or unreadable — the read below reports it.
    }
    let content: string;
    try {
      content = await readFile(absolute, 'utf8');
    } catch {
      // File deleted in the new revision, or unreadable — skip.
      continue;
    }
    const result = analyzer.scan({
      targetType: 'diff',
      filePath: displayPath,
      content,
      language,
      mode: options.mode ?? 'standard',
      includeRemediation: options.includeRemediation,
    });
    const pathSuppressed = suppressionsForPath(config, displayPath, now);
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
            filePath: f.filePath ?? displayPath,
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
    if (result.declaredPackageVetoes !== undefined) vetoArmed = true;
    for (const v of result.declaredPackageVetoes ?? []) {
      const k = `${v.ruleId}|${v.packageName}|${v.filePath ?? relPath}`;
      const prev = vetoesByKey.get(k);
      if (prev) prev.count += v.count;
      else vetoesByKey.set(k, { ...v, filePath: v.filePath ?? relPath });
    }
    for (const e of result.ruleErrors ?? []) {
      if (!ruleErrorsByRule.has(e.ruleId)) ruleErrorsByRule.set(e.ruleId, e);
    }
    // Carried through the same way `scanPath` does, and for the same reason: this
    // is the GitHub Action's path, so dropping degradations here would let a PR
    // pass review on a partial scan with nothing saying so. Keyed by file+kind,
    // not by rule — one oversized file trips the bound in dozens of rules.
    for (const d of result.degradations ?? []) {
      const key = `${d.filePath ?? displayPath}::${d.kind}`;
      if (!degradationsByFileKind.has(key)) {
        degradationsByFileKind.set(key, { ...d, filePath: d.filePath ?? displayPath });
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
    // The same three-state contract `scanPath` carries, for the same reason:
    // absent = never ran, `[]` = ran and removed nothing, non-empty = removed
    // these. See `ScanResponse.declaredPackageVetoes` in @vibeguard/findings-schema.
    ...(vetoesByKey.size
      ? { declaredPackageVetoes: [...vetoesByKey.values()] }
      : vetoArmed
        ? { declaredPackageVetoes: [] }
        : {}),
  };
}
