import type { Confidence } from '@vibeguard/findings-schema';
import type { RuleContext, RuleMatch } from './rule-types.js';
import { isCommentLine } from './matcher-utils.js';

/**
 * Context-window confidence adjustment (paper item ①).
 *
 * VibeGuard's findings carry two orthogonal axes: `severity` (impact if real,
 * static per rule) and `confidence` (certainty the match is real). DESIGN.ja.md
 * §13.3 defines confidence as the false-positive control knob — Medium means
 * "pattern matched but the surrounding context may be safe", Low means
 * "heuristic, needs human review". Until now no rule ever set a per-match
 * confidence, so every finding inherited the rule's static `defaultConfidence`
 * and the axis was effectively dead. This module makes confidence *contextual*:
 * it inspects the small window around each match and DOWN-RANKS findings that
 * sit in a context where the matched pattern is very unlikely to be a live
 * vulnerability — a comment, a docstring / block comment, or a test fixture.
 *
 * Policy decision (see paper): this is **downgrade-only**. We never raise
 * confidence, because "this match is on a real production path" cannot be
 * decided reliably from a regex window and a wrong guess manufactures false
 * `high`-confidence findings. Lowering confidence in a demonstrably non-executed
 * context is, by contrast, safe and directly reduces false-positive noise.
 *
 * The adjustment is applied centrally in the analyzer (the single
 * `m.confidence ?? contextConfidence(...)` chokepoint), so it covers every rule
 * uniformly. Rules whose detection signal *is* the comment itself
 * (VG-AUTH-002 "TODO near security", VG-QUAL-009 "not for production") opt out
 * with `contextConfidence: 'off'`; for them a comment must not lower confidence.
 */

/** Per-rule policy switch stored on RuleDefinition.contextConfidence. */
export type ContextConfidenceMode = 'auto' | 'off';

/** A reason the confidence of a match was lowered. */
export type DowngradeSignal = 'comment' | 'docstring' | 'test-path';

// Confidence as an ordered ladder. Index is the "rank"; downgrading subtracts.
const LADDER: readonly Confidence[] = ['low', 'medium', 'high'];
const RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

// How many ladder steps each signal removes. A match inside a comment or a
// docstring/block comment is almost never executable, so it drops two steps
// (high → low). A test-path match is real code, just lower-stakes, so one step.
const SIGNAL_STEPS: Record<DowngradeSignal, number> = {
  comment: 2,
  docstring: 2,
  'test-path': 1,
};

/**
 * Recognise file paths that are test fixtures / mocks / specs. Shared with the
 * VG-QUAL-007 `filterTestPaths` guard so there is a single source of truth.
 */
export const TEST_PATH_RE =
  /(?:^|[\\/])(?:tests?|__tests__|__mocks__|fixtures|spec|specs)(?:[\\/]|$)|\.(?:test|spec)\.[a-z]+$/i;

export function isTestPath(filePath?: string): boolean {
  return filePath != null && TEST_PATH_RE.test(filePath);
}

/** Languages where a leading `#` is NOT a line comment (so we must not treat it as one). */
const HASH_NOT_COMMENT = new Set(['javascript', 'typescript', 'java', 'go', 'csharp']);

/**
 * Decide whether line `lineNumber` (1-based) begins *inside* a multi-line
 * docstring (Python triple-quotes) or a C-style block comment that was opened
 * on an earlier line. This is a deliberately small heuristic state machine: it
 * scans every line strictly before the match line, toggling block state. It is
 * the complement to `isCommentLine` (which only catches whole-line `//`/`#`
 * comments) and to `runRegex({ skipCommentLines })` (same limitation).
 *
 * Known limits (documented on purpose): it keys off the line that *opens* the
 * block, so a pattern matched on the very same line that opens a triple quote is
 * not caught; and it does not model strings-containing-comment-tokens perfectly.
 * Those edge cases are rare for the target false positives (example config
 * inside a docstring, sample code inside a JSDoc/block comment).
 */
type ScanState =
  | 'normal'
  | 'line-comment'
  | 'block'
  | 'triple-d' // inside """ … """
  | 'triple-s' // inside ''' … '''
  | 'str-d' // inside " … "
  | 'str-s' // inside ' … '
  | 'str-bt'; // inside ` … ` (template literal)

export function isInDocstringOrBlockComment(
  lines: string[],
  lineNumber: number,
  language?: string,
): boolean {
  const hashIsComment = !(language != null && HASH_NOT_COMMENT.has(language));
  let state: ScanState = 'normal';
  const end = Math.min(lineNumber - 1, lines.length);

  for (let i = 0; i < end; i++) {
    const line = lines[i] ?? '';
    // Line comments and single-line string literals never span a newline.
    // Multi-line constructs (block comment, triple-quote, JS template literal)
    // intentionally survive into the next line.
    if (state === 'line-comment' || state === 'str-d' || state === 'str-s') {
      state = 'normal';
    }
    let k = 0;
    while (k < line.length) {
      const ch = line[k]!;
      const two = line.slice(k, k + 2);
      const three = line.slice(k, k + 3);
      switch (state) {
        case 'normal':
          if (three === '"""') { state = 'triple-d'; k += 3; continue; }
          if (three === "'''") { state = 'triple-s'; k += 3; continue; }
          if (two === '/*') { state = 'block'; k += 2; continue; }
          if (two === '//') { state = 'line-comment'; k = line.length; continue; }
          if (ch === '#' && hashIsComment) { k = line.length; continue; }
          if (ch === '"') { state = 'str-d'; k += 1; continue; }
          if (ch === "'") { state = 'str-s'; k += 1; continue; }
          if (ch === '`') { state = 'str-bt'; k += 1; continue; }
          k += 1; continue;
        case 'block':
          if (two === '*/') { state = 'normal'; k += 2; continue; }
          k += 1; continue;
        case 'triple-d':
          if (three === '"""') { state = 'normal'; k += 3; continue; }
          k += 1; continue;
        case 'triple-s':
          if (three === "'''") { state = 'normal'; k += 3; continue; }
          k += 1; continue;
        case 'str-d':
          if (ch === '\\') { k += 2; continue; }
          if (ch === '"') { state = 'normal'; k += 1; continue; }
          k += 1; continue;
        case 'str-s':
          if (ch === '\\') { k += 2; continue; }
          if (ch === "'") { state = 'normal'; k += 1; continue; }
          k += 1; continue;
        case 'str-bt':
          if (ch === '\\') { k += 2; continue; }
          if (ch === '`') { state = 'normal'; k += 1; continue; }
          k += 1; continue;
        default:
          k += 1; continue;
      }
    }
  }

  return state === 'block' || state === 'triple-d' || state === 'triple-s';
}

/**
 * The line we should inspect for context. Several rules anchor with `^\s*…` under
 * the `m` flag, and `\s` matches `\n`, so a match's `startLine` can point at the
 * *blank tail of the previous line* while the real payload is on the next line
 * (evidence like `"\nDEBUG = True"`). We therefore key off the line containing
 * the first non-whitespace character of the evidence, not the raw startLine —
 * otherwise a code line could inherit the previous comment line's context.
 */
function inspectedLine(match: RuleMatch): number {
  const ev = match.evidence ?? '';
  const firstNonWs = ev.search(/\S/);
  if (firstNonWs <= 0) return match.startLine;
  let newlines = 0;
  for (let i = 0; i < firstNonWs; i++) {
    if (ev[i] === '\n') newlines += 1;
  }
  return match.startLine + newlines;
}

/** Collect the downgrade signals that apply to a single match. */
export function detectDowngradeSignals(ctx: RuleContext, match: RuleMatch): DowngradeSignal[] {
  const signals: DowngradeSignal[] = [];
  const lineNumber = inspectedLine(match);
  const lineText = ctx.lines[lineNumber - 1] ?? '';
  if (isCommentLine(lineText)) {
    signals.push('comment');
  } else if (isInDocstringOrBlockComment(ctx.lines, lineNumber, ctx.language)) {
    signals.push('docstring');
  }
  if (isTestPath(ctx.filePath)) {
    signals.push('test-path');
  }
  return signals;
}

/** Lower `base` by `steps` rungs on the confidence ladder, clamped at `low`. */
export function downgradeConfidence(base: Confidence, steps: number): Confidence {
  if (steps <= 0) return base;
  const next = Math.max(0, RANK[base] - steps);
  return LADDER[next]!;
}

/**
 * Resolve the effective confidence for a match given its surrounding context.
 * `mode === 'off'` returns the base unchanged (for comment-is-the-signal rules).
 * Otherwise sums the downgrade steps of every applicable signal and clamps.
 */
export function contextConfidence(
  base: Confidence,
  ctx: RuleContext,
  match: RuleMatch,
  mode: ContextConfidenceMode = 'auto',
): Confidence {
  if (mode === 'off') return base;
  const steps = detectDowngradeSignals(ctx, match).reduce((sum, s) => sum + SIGNAL_STEPS[s], 0);
  return downgradeConfidence(base, steps);
}
