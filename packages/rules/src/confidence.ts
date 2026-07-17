import type { Confidence, Severity } from '@vibeguard/findings-schema';
import type { RuleContext, RuleMatch } from './rule-types.js';
import { HASH_NOT_COMMENT, isCommentLine } from './matcher-utils.js';

/**
 * Context-window confidence adjustment (paper item ①).
 *
 * VibeGuard's findings carry two orthogonal axes: `severity` (impact if real,
 * static per rule) and `confidence` (certainty the match is real). docs/DESIGN.ja.md
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
 *
 * ## The severity gate: downgrades are utility, not a security verdict
 *
 * A false-positive filter is also an attack surface. Someone who controls the
 * file can wrap a *real* vulnerability in a docstring, or park it under a
 * `tests/` path, and ride the downgrade below whatever confidence threshold the
 * consumer acts on — hiding the finding in plain sight without touching the
 * detection rule at all. The defence is a policy statement rather than a better
 * heuristic, because any heuristic sharp enough to see through the disguise is
 * also sharp enough to be fooled by the next one: **a context downgrade is a
 * noise-reduction convenience and must never decide a security question.**
 * `SEVERITY_CONFIDENCE_FLOOR` therefore bounds how far this module may lower a
 * finding whose *impact* would be severe if real, no matter how convincing the
 * surrounding context looks. Severity is static per rule and attacker-controlled
 * text cannot move it, which is exactly what makes it usable as the bound.
 *
 * The resolved rank is:
 *
 *     effectiveRank = max( RANK[base] - Σsteps, 0, min( RANK[base], FLOOR_RANK[severity] ) )
 *
 * The inner `min(RANK[base], …)` is load-bearing. Read the floor loosely as
 * "clamp confidence up to at least `high`" and you break the downgrade-only
 * invariant the whole module rests on: a `critical` rule whose
 * `defaultConfidence` is `medium`, matched in a test file, would be RAISED
 * medium → high — this module would start manufacturing precisely the false
 * `high`-confidence findings the policy above forbids. The floor is a *bound on
 * downgrading*, never a promotion device; clamping it to `base` first makes
 * `result <= base` hold by construction, for every input, no case analysis
 * needed.
 *
 * A consequence worth naming: `RANK['high'] = 2` is the top rung of the ladder,
 * so `min(RANK[base], 2) === RANK[base]` for every `base`. `floor: 'high'` is
 * therefore *exactly equivalent* to "critical/high findings take no context
 * downgrade at all" — the two ways of stating the gate ("clamp at high" and
 * "don't downgrade") collapse into the same function. `null` means no gate, i.e.
 * the item ① behaviour above, unchanged.
 *
 * ## Precedence: `off` short-circuits before the gate
 *
 * `mode === 'off'` returns `base` and never reaches the gate. The two are not
 * competing axes: `off` is strictly stronger, meaning "zero downgrade at any
 * severity", which already satisfies every possible floor. For VG-AUTH-002 /
 * VG-QUAL-009 the comment IS the detection signal, so a comment must not lower
 * confidence whatever the rule's severity happens to be.
 *
 * ## `m.confidence` bypasses this module entirely
 *
 * The analyzer resolves `m.confidence ?? contextConfidence(...)`, so a rule that
 * returns a per-match confidence skips the downgrade layer *and* this gate.
 * That is intended: `m.confidence` is a rule asserting certainty from its own
 * domain knowledge of the match, a separate channel from the generic
 * heuristics here — and therefore from their attack surface. The trade is
 * explicit: **a rule that sets `m.confidence` takes on the gate's
 * responsibility itself.** No rule sets it today, and the analyzer pins the
 * bypass with a test so that the day one starts, it surfaces in review.
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
 * The lowest confidence the context layer may downgrade a finding to, per
 * severity; `null` means ungated (plain item ① behaviour). See the header for
 * why this exists and why `high` here reads as "never downgraded".
 *
 * `critical` and `high` are floored: when a finding would be severe if real,
 * "it looks like it's in a comment" is not evidence we are willing to act on,
 * because that is the one signal an attacker can forge for free. `medium` and
 * below keep the unmodified downgrade behaviour — there the noise reduction is
 * worth more than the hiding place it opens.
 *
 * Deliberately a total `Record` rather than a `Partial`: a new severity in the
 * schema must break this build and force an explicit decision, instead of
 * silently defaulting to "ungated" — the quiet direction is the unsafe one.
 */
export const SEVERITY_CONFIDENCE_FLOOR: Record<Severity, Confidence | null> = {
  critical: 'high',
  high: 'high',
  medium: null,
  low: null,
  info: null,
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

/**
 * Languages whose multi-line string literals act as docstrings (triple-quoted
 * `"""`/`'''`). Only Python among the supported languages uses these as the
 * idiomatic documentation block we want to down-rank. For every other language
 * `"""` is NOT a docstring opener — e.g. a JavaScript/TypeScript regex literal
 * `/"""/` must not be mistaken for the start of a multi-line docstring (doing so
 * would phantom-open a block and wrongly down-rank a *real* finding on the next
 * line). Outside this set the three quote characters are handled as ordinary
 * single-line string delimiters, which reset at the end of each line.
 */
const TRIPLE_QUOTE_LANGS = new Set(['python']);

/**
 * Decide whether the match on line `lineNumber` (1-based) sits *inside* a
 * multi-line docstring (Python triple-quotes) or a C-style block comment that
 * was opened on an earlier line. This is a deliberately small heuristic state
 * machine: it scans every line strictly before the match line, toggling block
 * state. It is the complement to `isCommentLine` (which only catches whole-line
 * `//`/`#` comments) and to `runRegex({ skipCommentLines })` (same limitation).
 * Both consume the same `HASH_NOT_COMMENT` set imported from matcher-utils, so
 * "is `#` a comment in this language?" is answered identically here and there.
 *
 * Two deliberate, *safe-direction* limitations (they only ever WITHHOLD a
 * down-rank, never wrongly apply one, so they cannot demote a true positive):
 *  - Same-line open: a pattern on the very line that *opens* a triple quote /
 *    block is not treated as in-block (we scan lines strictly before), so it
 *    keeps its default confidence.
 *  - Close line: if the match line also *closes* the enclosing block (contains
 *    the closing `"""`/`'''`/`*\/`), the payload may be real code after the
 *    closer, so we conservatively return `false` (keep default confidence)
 *    rather than risk down-ranking executable code on a block-closing line.
 * Both err toward NOT down-ranking, preserving the "no collateral damage"
 * property at the cost of occasionally missing a down-rank in these rare cases.
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
  const allowTripleQuote = language != null && TRIPLE_QUOTE_LANGS.has(language);
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
          if (allowTripleQuote && three === '"""') { state = 'triple-d'; k += 3; continue; }
          if (allowTripleQuote && three === "'''") { state = 'triple-s'; k += 3; continue; }
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

  // Not inside a surviving multi-line construct → definitely not in a docstring.
  if (state !== 'block' && state !== 'triple-d' && state !== 'triple-s') {
    return false;
  }
  // We are inside a block/docstring entering the match line. If that same line
  // also CLOSES the block (contains the matching closer), the matched payload
  // may be real code after the closer, so conservatively withhold the
  // down-rank (safe direction — never demote a possible true positive).
  const matchLine = lines[lineNumber - 1] ?? '';
  if (state === 'block' && matchLine.includes('*/')) return false;
  if (state === 'triple-d' && matchLine.includes('"""')) return false;
  if (state === 'triple-s' && matchLine.includes("'''")) return false;
  return true;
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
  if (isCommentLine(lineText, ctx.language)) {
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

/** The full reasoning behind one resolved confidence, for auditing and evaluation. */
export interface ContextConfidenceResult {
  /** The value to use: after signals AND after the severity gate. */
  confidence: Confidence;
  /** What item ① alone would have produced, with no gate applied. */
  ungated: Confidence;
  /** Signals that fired. Always empty when `mode === 'off'` (it short-circuits). */
  signals: DowngradeSignal[];
  /** Whether the gate actually changed the outcome (`ungated !== confidence`). */
  floored: boolean;
}

/**
 * Resolve the effective confidence for a match, and explain how.
 *
 * The order is fixed and each step is the reason the next one is well-defined:
 *  1. `mode === 'off'` → return `base`; the gate is never reached (see header).
 *  2. collect the context signals for this match;
 *  3. downgrade `base` by their summed steps — pure ladder arithmetic, and the
 *     value item ① is evaluated on;
 *  4. bound that by the severity floor, itself clamped to `base` so the result
 *     can never exceed `base`.
 *
 * Callers that only need the number should use `contextConfidence`. This
 * variant exists because `ungated` and `floored` are measurements, not
 * debugging aids: they let an A/B harness compare gated against un-gated
 * confidence from the *same* primitive — so evaluating the gate never requires
 * a "disable the gate" flag in shipped code — and they let an audit trail
 * record why a finding kept its confidence, both without re-running signal
 * detection.
 */
export function explainContextConfidence(
  base: Confidence,
  severity: Severity,
  ctx: RuleContext,
  match: RuleMatch,
  mode: ContextConfidenceMode = 'auto',
): ContextConfidenceResult {
  if (mode === 'off') {
    return { confidence: base, ungated: base, signals: [], floored: false };
  }
  const signals = detectDowngradeSignals(ctx, match);
  const steps = signals.reduce((sum, s) => sum + SIGNAL_STEPS[s], 0);
  const ungated = downgradeConfidence(base, steps);

  const floor = SEVERITY_CONFIDENCE_FLOOR[severity];
  if (floor == null) {
    return { confidence: ungated, ungated, signals, floored: false };
  }
  // `min(RANK[base], …)`: the floor may only ever hold a downgrade back, never
  // push a finding above the confidence its rule declared. Without this clamp a
  // critical/medium-confidence rule would be promoted to `high` by the very
  // context that was supposed to make us trust it less.
  const effective = Math.max(RANK[ungated], Math.min(RANK[base], RANK[floor]));
  const confidence = LADDER[effective]!;
  return { confidence, ungated, signals, floored: confidence !== ungated };
}

/**
 * Resolve the effective confidence for a match given its surrounding context and
 * the rule's severity. `mode === 'off'` returns the base unchanged (for
 * comment-is-the-signal rules). Otherwise sums the downgrade steps of every
 * applicable signal, then applies the severity gate.
 *
 * `severity` is required on purpose. Making it optional would create a silent
 * failure mode — forget the argument at a call site and the security gate simply
 * stops existing, with no error anywhere — which is the exact class of defect
 * this gate defends against. Required, the type checker names every call site
 * that has to make the decision.
 */
export function contextConfidence(
  base: Confidence,
  severity: Severity,
  ctx: RuleContext,
  match: RuleMatch,
  mode: ContextConfidenceMode = 'auto',
): Confidence {
  return explainContextConfidence(base, severity, ctx, match, mode).confidence;
}
