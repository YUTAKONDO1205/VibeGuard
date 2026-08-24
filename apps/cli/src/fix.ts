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
import { identifierWitness, type Finding, type ProtectionClaim } from '@vibeguard/findings-schema';
import { applyFixes, buildFix, type FixEdit } from '@vibeguard/remediation-engine';

export interface AppliedFix {
  ruleId: string;
  title: string;
  safety: 'safe' | 'needs-review';
  /** 1-based line the fix landed on. */
  line: number;
  /**
   * The text this fix actually WROTE, as the fixer produced it.
   *
   * ── WHY THE LINE NUMBER WAS NOT ENOUGH ──────────────────────────────────
   *
   * `line` is where the FINDING was, and for a fix that REPLACES something
   * that is also where the new text is. For a fix that INSERTS — the
   * prototype-pollution guard is one — the new text goes on a line that did not
   * exist before, and everything below it shifts. Reading `newContent` at
   * `line` then returns the anchor: a line that was there before the fix and is
   * there after it.
   *
   * That is not a small inaccuracy for the claim ledger, it inverts the
   * mechanism. The probe is supposed to be the thing that tells a build made
   * AFTER the edit apart from one made before, and an anchor line appears in
   * both. The witness is derived from the same text, so it was being read off
   * the wrong line too — for the guard above it comes out empty, and a claim
   * with no witness can never be settled by anything.
   *
   * So the fixer's own output is carried here rather than recovered by
   * indexing. `replacement` is exactly what was written; nothing has to guess.
   */
  insertedText: string;
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
        // Longest replacement when a fix is several edits: the others are
        // usually punctuation or a closing token, and the longest is the one
        // that carries the protection's own vocabulary.
        insertedText: built.edits
          .map((e) => e.replacement.trim())
          .reduce((best, cur) => (cur.length > best.length ? cur : best), ''),
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
): Promise<{ output: string; code: number; claims: ProtectionClaim[] }> {
  const result = await planFixes(findings, resolve);
  if (write) {
    await writePlans(result.plans);
  }
  return { output: renderFixReport(result, write), code: 0, claims: fixerClaims(result.plans) };
}

/**
 * What the fixer says it inserted — as a claim, not as a result.
 *
 * ── WHY THE FIXER IS A CLAIMANT AND NOT A WITNESS ──────────────────────────
 *
 * A fixer knows exactly what text it wrote, which makes it the one claimant
 * whose witness token is certainly correct. It is also, for that same reason,
 * the claimant most tempting to believe: it reports success, the finding
 * disappears from a re-scan of the source, and everything looks repaired. But
 * "I replaced a console.assert with a throw" is a statement about the SOURCE,
 * and the entire subject of this ledger is that the source is not what ships.
 * A fixer vouching for its own edit is the same error as an assistant vouching
 * for its own code, one layer down.
 *
 * So every claim here is `NOT_OBSERVED`, and the only thing that can settle one
 * is an observation of the shipped bytes — `--after-build` on a later run. The
 * fix report already tells the reader to re-scan; this is what the re-scan is
 * for.
 *
 * The probe is the text the fixer WROTE, which is the identity control
 * `crossExamine` needs: a build that included this edit carries that text in
 * its source map, and a build made before the edit does not.
 *
 * ★ IT USED TO BE `newContent` INDEXED AT THE FINDING'S LINE, and the sentence
 * above was false whenever the fix INSERTED rather than replaced. The new line
 * did not exist before, so everything below it shifts and the index lands on
 * the ANCHOR — a line present in both builds, which distinguishes nothing. The
 * witness came off the same wrong text: for the prototype-pollution guard it
 * came out empty, and a claim with no witness is one nothing can ever settle.
 * The fix wrote the protection and the ledger recorded the line above it.
 * `insertedText` carries the fixer's own output so nothing has to be recovered
 * by arithmetic.
 */
/**
 * Lines that are in the new content and were not in the old one.
 *
 * ── WHY A DIFF AND NOT THE FIXER'S REPLACEMENT ALONE ────────────────────────
 *
 * `insertedText` is exactly what the fixer wrote, which makes it unambiguous
 * about WHICH fix produced what — but on its own it is often not distinctive.
 * `VG-EMB-020` swaps a debug define to `0`, and `0` identifies no build. The
 * useful probe is the resulting LINE, `#define DEBUG 0`, which the pre-edit
 * build does not contain because it said `1`.
 *
 * Taking added lines gives that for both shapes of fix, and gives it by
 * construction rather than by argument: a line that is in the new content and
 * not in the old one is, definitionally, text a build made before this edit
 * cannot carry. That is the exact property `crossExamine` needs of a probe.
 *
 * Compared by trimmed text, so a re-indentation is not mistaken for an
 * insertion, and consumed once each so a file with two identical lines does not
 * report a phantom addition.
 */
function addedLines(oldContent: string, newContent: string): { line: number; text: string }[] {
  const before = new Map<string, number>();
  for (const l of oldContent.split(/\r?\n/)) {
    const t = l.trim();
    before.set(t, (before.get(t) ?? 0) + 1);
  }
  const out: { line: number; text: string }[] = [];
  const after = newContent.split(/\r?\n/);
  for (let i = 0; i < after.length; i += 1) {
    const t = after[i]!.trim();
    const left = before.get(t) ?? 0;
    if (left > 0) {
      before.set(t, left - 1);
      continue;
    }
    if (t) out.push({ line: i + 1, text: t });
  }
  return out;
}

function fixerClaims(plans: FileFixPlan[]): ProtectionClaim[] {
  const out: ProtectionClaim[] = [];
  let n = 0;
  for (const plan of plans) {
    if (plan.overlapSkipped || plan.oldContent === plan.newContent) continue;
    const added = addedLines(plan.oldContent, plan.newContent);
    for (const fix of plan.fixes) {
      // The added line that CONTAINS this fixer's own output. That ties an
      // exact per-fix string to a full, distinctive line without having to
      // guess which fix a given added line belongs to when a file has several.
      const written = fix.insertedText.trim();
      const own = written ? added.find((l) => l.text.includes(written)) : undefined;
      const inserted = own?.text ?? written;
      const witness = inserted ? identifierWitness(inserted) : null;
      out.push({
        id: `fixer-claim-${++n}`,
        claimant: `fixer:${fix.ruleId}`,
        claimantLayer: 'fixer',
        subject: `${fix.title} (${fix.safety})`,
        ...(witness ? { witness } : {}),
        ...(inserted.length >= 20 ? { sourceProbe: inserted } : {}),
        filePath: plan.displayPath,
        // Where the text now IS, not where the finding was. For an insertion
        // those differ by the lines the fix pushed down, and a reader following
        // this number wants to land on the protection.
        startLine: own?.line ?? fix.line,
        state: 'NOT_OBSERVED',
      });
    }
  }
  return out;
}
