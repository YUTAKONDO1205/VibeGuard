/**
 * CLI wiring for the deterministic, LLM-free auto-fixer (block #18).
 *
 * The fix engine itself lives in `@vibeguard/remediation-engine`
 * (`buildFix` / `applyFixes`). This module is the CLI-side plumbing that
 * turns a scan's findings back into on-disk edits:
 *
 *   1. group findings by the file they were reported in,
 *   2. re-read that file's bytes (the SAME bytes the scan saw, so the
 *      line/column offsets a fixer keys off still point at the right token),
 *   3. ask the fixer table for edits, apply them, write or preview.
 *
 * Zero-send is preserved: nothing here reaches the network, and the fix code
 * never ships in the Chrome / VS Code bundles — it is CLI-only.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Finding } from '@vibeguard/findings-schema';
import { applyFixes, buildFix, type FixEdit } from '@vibeguard/remediation-engine';

export interface AppliedFix {
  ruleId: string;
  title: string;
  safety: 'safe' | 'needs-review';
  /** 1-based line the fix landed on. */
  line: number;
}

export interface FileFixPlan {
  /** Path exactly as the finding reported it (stable, relative). */
  displayPath: string;
  /** Path resolved to somewhere we can read and write. */
  diskPath: string;
  oldContent: string;
  newContent: string;
  fixes: AppliedFix[];
  /**
   * True when two fixes for this file would have overlapped. `applyFixes`
   * refuses a partial apply, so the whole file is left untouched and every
   * would-be fix here is counted unfixable.
   */
  overlapSkipped: boolean;
}

export interface FixPlanResult {
  plans: FileFixPlan[];
  /** Findings that had no fixer, failed to build an edit, or lost to an overlap. */
  unfixable: number;
}

export interface ResolveOptions {
  /** The scan target as passed on the command line. */
  target: string;
  /** True when `target` is a single file (findings' filePath === target). */
  targetIsFile: boolean;
}

/**
 * Rebuild the minimal RuleMatch a fixer consumes from a reported Finding.
 * Fixers only read `startLine`/`startColumn`, but the shape must satisfy
 * RuleMatch, so the rest is filled conservatively.
 */
function matchOf(f: Finding) {
  const startLine = f.startLine ?? 1;
  const startColumn = f.startColumn ?? 1;
  return {
    startLine,
    endLine: f.endLine ?? startLine,
    startColumn,
    endColumn: f.endColumn ?? startColumn,
    evidence: f.evidence?.[0] ?? '',
  };
}

/**
 * Resolve the on-disk path for a finding. Mirrors how the scanner read it:
 *  - a single-file target reports `filePath === target`,
 *  - a directory (or --diff) scan reports paths relative to the target, read
 *    back as `join(target, displayPath)`.
 */
function diskPathOf(displayPath: string, o: ResolveOptions): string {
  return o.targetIsFile ? o.target : join(o.target, displayPath);
}

/** The 1-based `line` of `content`, without its terminator. */
function lineAt(content: string, line: number): string {
  const lines = content.split('\n');
  return lines[line - 1] ?? '';
}

/** Group findings by their reported file path (findings with no path are dropped). */
function groupByPath(findings: Finding[]): Map<string, Finding[]> {
  const byPath = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!f.filePath) continue;
    const arr = byPath.get(f.filePath);
    if (arr) arr.push(f);
    else byPath.set(f.filePath, [f]);
  }
  return byPath;
}

/**
 * Build the fix plan for a scan's findings. Reads files but writes nothing —
 * `writePlans` does that separately, so --dry-run and --fix share this path.
 */
export async function planFixes(findings: Finding[], o: ResolveOptions): Promise<FixPlanResult> {
  const byPath = groupByPath(findings);
  // A finding with no filePath can never be located on disk.
  let unfixable = findings.filter((f) => !f.filePath).length;
  const plans: FileFixPlan[] = [];

  for (const [displayPath, group] of byPath) {
    const diskPath = diskPathOf(displayPath, o);
    let content: string;
    try {
      content = await readFile(diskPath, 'utf8');
    } catch {
      // File moved/unreadable between scan and fix: count them manual, skip.
      unfixable += group.length;
      continue;
    }

    const edits: FixEdit[] = [];
    const applied: AppliedFix[] = [];
    for (const f of group) {
      const built = buildFix(f.ruleId, content, matchOf(f));
      if (!built) {
        unfixable++;
        continue;
      }
      edits.push(...built.edits);
      applied.push({
        ruleId: f.ruleId,
        title: built.title,
        safety: built.safety,
        line: f.startLine ?? 1,
      });
    }
    if (edits.length === 0) continue;

    const newContent = applyFixes(content, edits);
    if (newContent === null) {
      // Overlap: applyFixes applied nothing. Report but leave the file alone.
      plans.push({
        displayPath,
        diskPath,
        oldContent: content,
        newContent: content,
        fixes: applied,
        overlapSkipped: true,
      });
      unfixable += applied.length;
      continue;
    }
    plans.push({
      displayPath,
      diskPath,
      oldContent: content,
      newContent,
      fixes: applied,
      overlapSkipped: false,
    });
  }

  plans.sort((a, b) => (a.displayPath < b.displayPath ? -1 : a.displayPath > b.displayPath ? 1 : 0));
  return { plans, unfixable };
}

/** Write the applied plans to disk. Overlap-skipped and no-op plans are left alone. */
export async function writePlans(plans: FileFixPlan[]): Promise<void> {
  for (const p of plans) {
    if (p.overlapSkipped) continue;
    if (p.newContent !== p.oldContent) {
      await writeFile(p.diskPath, p.newContent, 'utf8');
    }
  }
}

const SAFETY_TAG: Record<AppliedFix['safety'], string> = {
  safe: '[safe]        ',
  'needs-review': '[needs-review]',
};

/**
 * Human-readable report of a fix plan. `write=false` (dry-run) frames it as a
 * preview; `write=true` frames it as applied. Deterministic: no timestamps,
 * stable path order, so the output can seed a PR body verbatim.
 */
export function renderFixReport(result: FixPlanResult, write: boolean): string {
  const { plans, unfixable } = result;
  const appliedCount = plans
    .filter((p) => !p.overlapSkipped)
    .reduce((n, p) => n + p.fixes.length, 0);
  const files = plans.filter((p) => !p.overlapSkipped && p.newContent !== p.oldContent).length;

  if (appliedCount === 0) {
    const tail = unfixable > 0 ? ` (${unfixable} finding(s) need manual review)` : '';
    return `No auto-fixable findings.${tail}\n`;
  }

  const verb = write ? 'Applied' : 'Would apply';
  const lines: string[] = [`${verb} ${appliedCount} fix(es) across ${files} file(s):`, ''];

  for (const p of plans) {
    if (p.overlapSkipped) {
      lines.push(`  ${p.displayPath}`);
      lines.push(
        `    ! ${p.fixes.length} conflicting fix(es) overlapped — file left unchanged, review manually`,
      );
      lines.push('');
      continue;
    }
    lines.push(`  ${p.displayPath}`);
    // De-dup the before/after by line: two fixes on one line share the diff.
    const shownLines = new Set<number>();
    for (const fx of p.fixes) {
      lines.push(`    L${fx.line}  ${SAFETY_TAG[fx.safety]}  ${fx.ruleId}  ${fx.title}`);
      if (!shownLines.has(fx.line)) {
        shownLines.add(fx.line);
        const before = lineAt(p.oldContent, fx.line);
        const after = lineAt(p.newContent, fx.line);
        if (before !== after) {
          lines.push(`        - ${before}`);
          lines.push(`        + ${after}`);
        }
      }
    }
    lines.push('');
  }

  if (unfixable > 0) {
    lines.push(`${unfixable} finding(s) had no deterministic fix — review manually.`);
  }
  if (!write) {
    lines.push('Dry run: no files were written. Re-run with --fix to apply.');
  }
  return lines.join('\n') + '\n';
}

/**
 * Top-level fix entry used by the CLI. Plans, optionally writes, and returns
 * the report plus a process exit code (0 success, 2 on nothing-to-do is still
 * success — a clean scan is not an error).
 */
export async function runFix(
  findings: Finding[],
  resolve: ResolveOptions,
  write: boolean,
): Promise<{ output: string; code: number }> {
  const result = await planFixes(findings, resolve);
  if (write) {
    await writePlans(result.plans);
  }
  return { output: renderFixReport(result, write), code: 0 };
}
