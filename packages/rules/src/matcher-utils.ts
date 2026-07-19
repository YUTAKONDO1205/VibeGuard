import type { RuleMatch } from './rule-types.js';

export interface Position {
  line: number;
  column: number;
}

export function indexToPosition(content: string, index: number): Position {
  let line = 1;
  let column = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === '\n') {
      line += 1;
      column = 1;
    } else {
      column += 1;
    }
  }
  return { line, column };
}

export function getLineText(lines: string[], lineNumber: number): string {
  return lines[lineNumber - 1] ?? '';
}

/**
 * Every language `EXT_TO_LANGUAGE` (analyzer-core/src/language-detect.ts) can
 * produce. Kept as a union rather than `string` so `LINE_COMMENT_SPECS` below
 * can be checked for exhaustiveness at compile time.
 */
export type KnownLanguage =
  | 'javascript'
  | 'typescript'
  | 'python'
  | 'ruby'
  | 'go'
  | 'java'
  | 'kotlin'
  | 'csharp'
  | 'php'
  | 'rust'
  | 'swift'
  | 'c'
  | 'cpp'
  | 'shell'
  | 'yaml'
  | 'json'
  | 'toml'
  | 'sql'
  | 'html';

/**
 * What opens a line comment in one language.
 *
 * `prefixes` are the tokens that start a comment; `exclusions` are longer tokens
 * that begin with one of them but are executable syntax, not a comment (PHP 8's
 * `#[Attribute]`). An exclusion always wins over a prefix, so the two lists are
 * order-independent — see `lineCommentStartsAt`.
 */
export interface LineCommentSpec {
  readonly prefixes: readonly string[];
  readonly exclusions: readonly string[];
}

/**
 * ALLOWLIST of line-comment syntax, keyed by language.
 *
 * This is the single source of truth for "does a comment start here?": both
 * `isCommentLine` below (whose result makes `runRegex({ skipCommentLines })`
 * DROP a match) and `isInDocstringOrBlockComment` in confidence.ts consume it,
 * so a language is classified once, in one place.
 *
 * It is an allowlist, and that direction is the point. A language with no entry
 * — an unrecognised extension, a file whose language could not be detected —
 * gets `EMPTY_SPEC`: nothing is a comment, so no match is dropped. Failing that
 * way yields at worst a false positive (a finding on a line that really was a
 * comment), never a silent false negative. The dropped match never reaches the
 * analyzer's confidence chokepoint, so the severity gate cannot bound the
 * mistake; a noisy finding, by contrast, is visible and can be triaged. The old
 * blocklist defaulted to "`#` starts a comment" for unknown languages, which let
 * a single unrecognised extension erase findings before anything could see them.
 *
 * ADDING A LANGUAGE: add it to `EXT_TO_LANGUAGE` *and* to this map. Forgetting
 * the map is a compile error (`satisfies Record<KnownLanguage, …>`); forgetting
 * either side is caught by the sync test that compares the two. If one somehow
 * ships anyway, the runtime behavior is `EMPTY_SPEC` — fail-safe.
 *
 * Non-obvious choices, and why:
 *
 * - `json` gets `//`. Strict JSON has no comments, but no valid JSON token can
 *   begin with `/` either, so a line whose first non-space characters are `//`
 *   is syntactically impossible in conforming JSON. Listing it therefore costs
 *   nothing and correctly drops comments in the JSONC dialects we actually meet
 *   (tsconfig.json and friends).
 * - `php` gets `//` and `#`, minus the `#[` exclusion. PHP 8 attributes
 *   (`#[Route('/admin')]`) are executed syntax and must not be swallowed, while
 *   `# comment` is a genuine comment. `# [x]` keeps its comment status: the
 *   space means it does not start with `#[`.
 * - `html` is empty. Its only comment syntax is `<!-- -->`, which is a
 *   multi-line construct this line-oriented predicate does not model (a known
 *   limitation, unchanged here). `#` in an HTML file is a CSS id selector or a
 *   private class field inside an inline `<script>`, never a comment.
 * - `sql` gets `#` (MySQL) and `--`. The `--` test is a naive `startsWith`,
 *   whereas MySQL requires whitespace after `--` for it to be a comment. So
 *   `--payload` — which MySQL executes — is classified as a comment and its
 *   match dropped. KNOWN RESIDUAL GAP, deliberately left: tightening it is out
 *   of scope for this change.
 *
 * Note the map is not exported raw: callers go through `getLineCommentSpec` so
 * the unknown-language fallback cannot be bypassed.
 */
const LINE_COMMENT_SPECS = {
  javascript: { prefixes: ['//'], exclusions: [] },
  typescript: { prefixes: ['//'], exclusions: [] },
  java: { prefixes: ['//'], exclusions: [] },
  go: { prefixes: ['//'], exclusions: [] },
  kotlin: { prefixes: ['//'], exclusions: [] },
  csharp: { prefixes: ['//'], exclusions: [] },
  swift: { prefixes: ['//'], exclusions: [] },
  c: { prefixes: ['//'], exclusions: [] },
  cpp: { prefixes: ['//'], exclusions: [] },
  rust: { prefixes: ['//'], exclusions: [] },
  json: { prefixes: ['//'], exclusions: [] },
  php: { prefixes: ['//', '#'], exclusions: ['#['] },
  python: { prefixes: ['#'], exclusions: [] },
  ruby: { prefixes: ['#'], exclusions: [] },
  shell: { prefixes: ['#'], exclusions: [] },
  yaml: { prefixes: ['#'], exclusions: [] },
  toml: { prefixes: ['#'], exclusions: [] },
  sql: { prefixes: ['#', '--'], exclusions: [] },
  html: { prefixes: [], exclusions: [] },
} satisfies Record<KnownLanguage, LineCommentSpec>;

/**
 * The fail-safe spec for a language with no entry: nothing starts a comment, so
 * nothing is dropped. A single frozen instance, so `getLineCommentSpec` can
 * return it by identity and `hasLineCommentSpec` can test for it by reference.
 */
const EMPTY_SPEC: LineCommentSpec = Object.freeze({
  prefixes: Object.freeze([]),
  exclusions: Object.freeze([]),
});

/**
 * The line-comment syntax for `language`, or the fail-safe empty spec when the
 * language is unknown or absent. Never returns undefined — callers cannot
 * accidentally skip the fallback.
 */
export function getLineCommentSpec(language: string | undefined): LineCommentSpec {
  // `Object.hasOwn` guard, not a bare index: a caller-supplied `language` of
  // `'__proto__'`, `'constructor'`, or `'toString'` would otherwise resolve to
  // an inherited value that is not nullish, dodge the `?? EMPTY_SPEC` fallback,
  // and return an object with no `prefixes` for `lineCommentStartsAt` to crash
  // on. That crash, thrown inside `rule.match` via `runRegex`, is swallowed by
  // the analyzer's per-rule try/catch — i.e. it would silently drop a rule's
  // findings, the exact undeclared-suppression channel this map exists to close.
  if (language == null || !Object.hasOwn(LINE_COMMENT_SPECS, language)) return EMPTY_SPEC;
  return LINE_COMMENT_SPECS[language as KnownLanguage];
}

/**
 * True when `language` has an explicit entry in the allowlist, as opposed to
 * falling back to the empty spec. Lets the sync test tell "we know this language
 * has no line comments" (html) apart from "we have never heard of this
 * language" — `getLineCommentSpec` returns an equal-looking spec for both.
 */
export function hasLineCommentSpec(language: string | undefined): boolean {
  return getLineCommentSpec(language) !== EMPTY_SPEC;
}

/**
 * True when a line comment starts at exactly `index` in `line`: some prefix
 * matches there and no exclusion does. Positional and order-independent — it
 * does not trim, and the order of either list carries no meaning (an exclusion
 * suppresses a prefix wherever each appears in its list).
 *
 * Empty-string prefixes are not allowed in the map: `''.startsWith('')` is true,
 * so one would classify every line as a comment.
 */
export function lineCommentStartsAt(line: string, index: number, spec: LineCommentSpec): boolean {
  const hasPrefix = spec.prefixes.some((p) => line.startsWith(p, index));
  const hasExclusion = spec.exclusions.some((x) => line.startsWith(x, index));
  return hasPrefix && !hasExclusion;
}

/**
 * True when a line is a whole-line comment, i.e. its first non-whitespace
 * characters open a comment in `language`. This is the single comment-line
 * predicate used by both `runRegex({ skipCommentLines })` (which drops such
 * matches) and the context-window confidence helper (which down-ranks them) —
 * keeping one definition so the two stay consistent.
 *
 * `language` is optional but should be passed wherever it is known. Omitted, no
 * syntax counts as a comment and every match survives: the deliberate fail-safe
 * described on `LINE_COMMENT_SPECS`. Getting this wrong in the other direction
 * is not a down-rank — `runRegex({ skipCommentLines })` DROPS a match on a line
 * this predicate accepts, before the analyzer's confidence chokepoint ever sees
 * it, so the severity gate cannot bound it. A misclassification toward "comment"
 * is a silent false negative, which is strictly worse than a wrong confidence.
 *
 * It does NOT detect trailing comments, block comments, or docstrings (see
 * confidence.ts for multi-line awareness).
 */
export function isCommentLine(lineText: string, language?: string): boolean {
  const spec = getLineCommentSpec(language);
  return lineCommentStartsAt(lineText.trimStart(), 0, spec);
}

/**
 * D3 — the input-length bound. Content longer than this is TRUNCATED before any
 * pattern runs; see `runRegex` for why truncation and not skipping.
 *
 * THIS IS A BACKSTOP, NOT THE PRIMARY REDOS DEFENCE — and it did not start that
 * way. The first version of D3 leaned on this cap to bound ReDoS, and
 * MEASUREMENT REFUTED THAT: the worst rule was super-linear on inputs far INSIDE
 * any cap large enough to keep scanning real files, inside a single
 * uninterruptible `exec`. What actually fixed it was rewriting the patterns
 * themselves (L1): bounding every whitespace quantifier so none can span an
 * arbitrary run of blank lines, and leaving no two variable-length runs
 * adjacent. After that rewrite the whole all-rules canonical pass costs single-
 * digit milliseconds at every size up to 1 MB, where it was previously quadratic.
 * `redos-invariant.test.ts` is what keeps it that way.
 *
 * (The rule-by-rule before/after numbers, the attack shapes and the derivation
 * live in security-experiment/, not here. This file ships to every user,
 * including ones still on an older release; a precise recipe for which rule
 * breaks on which input does not belong in it.)
 *
 * WHY THE CAP STAYS, AND WHY 50_000. Its job changed rather than disappeared. The
 * binding cost is now FINDING ASSEMBLY — snippet extraction and remediation, ~1.7 ms
 * per finding — which grows with how many findings a file contains, not with
 * regex complexity. On a deliberately finding-dense input a full scan at the cap
 * measures ~1.3 s, inside DESIGN §11.1's 3 s single-file budget; at 1 MB the same
 * shape would produce tens of thousands of findings and blow it by an order of
 * magnitude. 50_000 keeps that worst case inside the contract, and is still ~7×
 * the largest file in the regression corpus (6.7 KB) so the bound stays invisible
 * to real scans (asserted in redos-bounds.test.ts, not hoped for).
 *
 * The cap ALSO remains the only runtime defence against an injected rule set
 * (`AnalyzerOptions.rules`), which never passes the CI invariant — a
 * caller-supplied catastrophic pattern is bounded in input length even though it
 * cannot be bounded in time.
 *
 * Raising it is now a question about finding-assembly cost, not backtracking:
 * bound that separately and this could go up.
 *
 * THE COST OF THIS CHOICE IS REAL. Source files between 50 KB and the
 * file-scanner's 1 MB ceiling are now scanned only in part. That is a false
 * negative, which is why truncation is always REPORTED (see `runRegex`) instead
 * of silently applied: a partial scan must never read as a clean one.
 *
 * This bound is DETERMINISTIC — it depends on `content.length` and nothing else.
 * That is the whole reason it, and not the deadline below, is what decides which
 * matches come back. Same input, same result, on every host and every channel;
 * E1's four-channel agreement cannot be broken by a fast or slow machine.
 */
export const REGEX_INPUT_CAP = 50_000;

/**
 * D3 — the wall-clock bound. SCAN-WIDE, not per call.
 *
 * Per-call was the obvious design and it does not bound anything useful: one
 * scan makes 84 `runRegex` calls across 47 rules, twice over once the canonical
 * pass is counted, so a 1 s per-call budget permits a 168 s scan while every
 * individual call stays "within budget". The budget has to span the unit the
 * user actually waits for, which is the scan. `captureRegexBoundaries` opens
 * that span; calls made outside one fall back to this value as a per-call
 * budget, which is the safe reading for a rule invoked directly in a test.
 *
 * IT EXISTS FOR INJECTED RULES, NOT FOR THE SHIPPED ONES. After L1 the shipped
 * rules are linear — the whole canonical pass over all 47 measures ~3 ms even at
 * 1 MB — so they cannot come close to this budget, and `redos-invariant.test.ts`
 * keeps it so. What CAN reach it is a rule set supplied through
 * `AnalyzerOptions.rules`, which never passes the CI invariant; a caller-supplied
 * backtracking pattern is a live possibility and this is the only thing that ends
 * it. Two consequences, both intended:
 *
 * - On every input a real scan meets, the comparison is always false, so results
 *   stay DETERMINISTIC and E1's four-channel agreement cannot be broken by one
 *   host being slower than another. Timing becomes load-bearing only for inputs
 *   that are already pathological.
 * - The budget counts REGEX time, not wall-clock (see below), so a scan is never
 *   declared degraded because it happened to find a lot of findings.
 *
 * KNOWN AND UNAVOIDABLE LIMIT — this is not a hard timeout.
 * `RegExp.prototype.exec` is synchronous and cannot be interrupted, so a single
 * `exec` that enters catastrophic backtracking runs to completion regardless of
 * this value; a deadline checked between matches cannot preempt the match in
 * progress. This is not hypothetical: it is the measured reason the original
 * "input cap + per-match timeout" design failed, because a pattern that matches
 * NOTHING calls `exec` once and neither bound is ever consulted. Only rewriting
 * the pattern (L1) fixed it. For an injected rule that cannot be rewritten, the
 * honest position is that the input cap bounds its INPUT but nothing bounds its
 * TIME; true preemption would need a worker per scan, making the synchronous
 * rule API async and diverging the four channels, and that trade is declined
 * deliberately. Load-time screening of injected patterns is the right fix and is
 * not implemented here.
 */
export const REGEX_DEADLINE_MS = 2_000;

/**
 * The budget measures TIME SPENT IN REGEX MATCHING, not wall-clock since the scan
 * began.
 *
 * The distinction is load-bearing, and getting it wrong produced a false
 * positive: a legitimate 34 KB file with 1000+ findings took 2.3 s to scan — not
 * in regex, but in assembling those findings (snippets, remediation) — and a
 * wall-clock deadline then fired on the NEXT rule (`VG-CRYPTO-002`, which matched
 * nothing), reporting a ReDoS degradation on a scan that had no ReDoS. A budget
 * on regex time alone cannot be tripped by how many findings a scan produces or
 * how long remediation takes; it trips only on rules that actually sit in `exec`.
 *
 * `regexTimeSpentMs` accumulates across every `runRegex` in the current
 * `withScanDeadline` span; `regexBudgetMs` is the ceiling, or null when no span
 * is open (a directly-invoked rule then gets a per-call budget). Module-level and
 * safe for the same reason the sink is: `Analyzer.scan` is synchronous.
 */
let regexBudgetMs: number | null = null;
let regexTimeSpentMs = 0;

/**
 * How many `exec` calls between deadline checks.
 *
 * The original code wrote `execCount % 256 === 0` against a per-`runRegex`-call
 * local, so a rule with fewer than 256 matches — nearly all of them — reset the
 * counter before it reached 256 and the budget was NEVER consulted: dead code.
 * The check now runs against a module-level counter spanning the whole scan, at a
 * small interval. `Date.now()` costs tens of nanoseconds against an `exec` that
 * costs micro- to milliseconds, so 32 is effectively free while bounding
 * post-deadline overrun to a handful of matches.
 */
const DEADLINE_CHECK_INTERVAL = 32;

/** exec calls since the last budget check. Module-level; reset when a span opens. */
let execsSinceDeadlineCheck = 0;

/** A bound that `runRegex` applied, reported rather than silently absorbed. */
export interface RegexBoundaryEvent {
  kind: 'truncated' | 'timedOut' | 'limitReached';
  /** Pattern that hit the bound, as `String(pattern)`. */
  pattern: string;
  /** Original input length in characters. */
  inputLength: number;
  /** Matches produced before the bound applied. */
  matchCount: number;
}

/**
 * The active boundary collector, or null when nobody is capturing.
 *
 * A module-level sink rather than a parameter because the alternative is
 * threading one through all 84 `runRegex` call sites in packages/rules/src/rules
 * — a change that would touch every rule to add a channel none of them care
 * about, and that a new rule would forget.
 *
 * SAFE HERE, AND ONLY HERE, BECAUSE THE SCAN IS SYNCHRONOUS. `Analyzer.scan`
 * (analyzer-core/src/analyzer.ts) is a plain synchronous method: no `await`
 * anywhere in the rule loop, so two scans cannot interleave and attribute one
 * scan's boundary to another's report. If `scan` ever becomes async, this must
 * become a context-carried sink — the assumption is asserted by a test rather
 * than left as a comment.
 */
let boundarySink: RegexBoundaryEvent[] | null = null;

/**
 * Collect the bounds applied during `fn`. Pairs begin/end via try/finally so an
 * exception thrown by a rule cannot leave the sink installed and leak the next
 * scan's events into this one's report.
 */
export function captureRegexBoundaries<T>(
  fn: () => T,
  options?: {
    /**
     * Wall-clock budget for everything inside `fn`, shared across every
     * `runRegex` it makes. Defaults to `REGEX_DEADLINE_MS`. Pass the SAME span
     * around a whole scan to bound the scan; opening one span per rule would
     * multiply the budget by the rule count and bound nothing.
     */
    deadlineMs?: number;
    /**
     * Continue an enclosing span's deadline instead of starting a fresh one.
     * The analyzer opens one span per rule so events can be attributed to a
     * rule, but the clock has to keep running across all of them, or 47
     * consecutive spans would each get the full budget.
     */
    inheritDeadline?: boolean;
  },
): { result: T; events: RegexBoundaryEvent[] } {
  const previousSink = boundarySink;
  const previousBudget = regexBudgetMs;
  const previousSpent = regexTimeSpentMs;
  const events: RegexBoundaryEvent[] = [];
  boundarySink = events;
  // Inherit the enclosing budget (and its running total) when asked, so the
  // analyzer's per-rule spans share ONE scan-wide budget rather than each
  // getting a fresh one. Otherwise open a fresh budget with a fresh accumulator.
  const openedOwnBudget = !(options?.inheritDeadline && regexBudgetMs !== null);
  if (openedOwnBudget) {
    regexBudgetMs = options?.deadlineMs ?? REGEX_DEADLINE_MS;
    regexTimeSpentMs = 0;
  }
  try {
    return { result: fn(), events };
  } finally {
    // Restored in a finally so a rule that throws cannot leave the sink
    // installed and leak its events into the next scan's report.
    boundarySink = previousSink;
    regexBudgetMs = previousBudget;
    // The accumulator is restored ONLY when this span reset it. An inheriting
    // span must LEAVE its spend on the total — that is the whole point of
    // sharing one scan-wide budget across per-rule spans. Restoring
    // unconditionally would discard every rule's time as its span closed and
    // hand the scan an eternally-fresh budget; restoring never would let a
    // nested non-inheriting span zero the enclosing scan's total.
    if (openedOwnBudget) regexTimeSpentMs = previousSpent;
  }
}

/** Opens a scan-wide deadline that per-rule spans then inherit. */
export function withScanDeadline<T>(fn: () => T, deadlineMs = REGEX_DEADLINE_MS): T {
  const previousBudget = regexBudgetMs;
  const previousSpent = regexTimeSpentMs;
  const previousExecs = execsSinceDeadlineCheck;
  regexBudgetMs = deadlineMs;
  regexTimeSpentMs = 0;
  execsSinceDeadlineCheck = 0;
  try {
    return fn();
  } finally {
    regexBudgetMs = previousBudget;
    regexTimeSpentMs = previousSpent;
    execsSinceDeadlineCheck = previousExecs;
  }
}

function reportBoundary(event: RegexBoundaryEvent): void {
  boundarySink?.push(event);
}

/**
 * Run a global regex against the source and convert each match into a RuleMatch.
 * Pattern MUST have the global flag.
 *
 * BOUNDED (D3). Three bounds apply, in order of how much they are relied on:
 * the deterministic input-length cap (`REGEX_INPUT_CAP`), the existing match
 * limit, and the wall-clock deadline (`REGEX_DEADLINE_MS`) that real inputs
 * never reach. Each is reported through `captureRegexBoundaries` when one is in
 * scope.
 *
 * NOTHING HERE THROWS TO SIGNAL A BOUND. `Analyzer.scan` wraps `rule.match` in a
 * try/catch that records the error and drops the rule; a bound raised as an
 * exception would therefore delete every finding that rule had already produced
 * and turn a partial result into a silent total loss — the undeclared-
 * suppression failure mode this file's allowlist exists to avoid. Bounds return
 * the matches found so far and describe themselves on the side.
 */
export function runRegex(
  content: string,
  pattern: RegExp,
  options?: {
    /** When true, skip matches whose line is in a comment-only context (// or # at line start ignoring whitespace). */
    skipCommentLines?: boolean;
    /** Maximum matches to return. */
    limit?: number;
    /**
     * Source language, selecting which syntax counts as a comment (see
     * `LINE_COMMENT_SPECS`). Pass `ctx.language`. Omitted or unrecognised, no
     * line is treated as a comment and no match is dropped — fail-safe.
     */
    language?: string;
  },
): RuleMatch[] {
  if (!pattern.global) {
    throw new Error(`pattern must be global: ${pattern}`);
  }
  const matches: RuleMatch[] = [];
  const limit = options?.limit ?? 1000;

  // Truncate, never skip. Skipping the file would drop every finding it
  // contains, which is a silent false negative on the largest inputs — the ones
  // most worth scanning. Truncating keeps the findings in the first
  // REGEX_INPUT_CAP characters and reports the loss, so a scan that saw only
  // part of a file never looks like a scan that found nothing.
  const truncated = content.length > REGEX_INPUT_CAP;
  const scanText = truncated ? content.slice(0, REGEX_INPUT_CAP) : content;
  if (truncated) {
    reportBoundary({
      kind: 'truncated',
      pattern: String(pattern),
      inputLength: content.length,
      matchCount: 0,
    });
  }

  // Split once per call, not once per match — and lazily, so a pattern that
  // never matches never pays for it.
  //
  // This was inside the loop, and MEASUREMENT SHOWED IT DOMINATES. A 220 KB file
  // of mostly comment lines — i.e. within the input cap, so nominally "bounded"
  // — took 6.9 s to scan, against the 3 s single-file budget in DESIGN §11.1.
  // The regexes were not the problem: `split('\n')` allocates an array of every
  // line in the file on EVERY match, so the comment test alone cost O(n) per
  // match and O(n·m) per rule. Bounding `n` does not bound `n·m`, which meant
  // the input cap could not by itself deliver the bounded scan time this change
  // exists to provide. Hoisting it is the difference between a bound that holds
  // and a bound that is merely written down.
  let cachedLines: string[] | null = null;
  const lineAt = (lineNumber: number): string => {
    cachedLines ??= scanText.split('\n');
    return cachedLines[lineNumber - 1] ?? '';
  };

  // The budget bounds regex TIME, so measure from here — the start of this
  // call's matching work — and compare (already-spent + this-call-so-far)
  // against the ceiling. When no scan span is open (a directly-invoked rule),
  // fall back to a per-call budget so the rule is still bounded.
  const runStart = Date.now();
  const budgetMs = regexBudgetMs ?? REGEX_DEADLINE_MS;
  const alreadySpent = regexBudgetMs !== null ? regexTimeSpentMs : 0;
  let timedOut = false;
  let m: RegExpExecArray | null;
  pattern.lastIndex = 0;
  // `matches.length < limit` is the loop CONDITION, not a break inside the body.
  // It used to be the latter, which meant the limit was tested only after
  // `exec` had already returned: on reaching 1000 matches the engine ran one
  // more search across the remainder of the file before stopping. For a pattern
  // that backtracks, that final unbounded search is the expensive one, so the
  // limit bounded the result size while bounding no work at all.
  while (matches.length < limit) {
    execsSinceDeadlineCheck += 1;
    if (execsSinceDeadlineCheck >= DEADLINE_CHECK_INTERVAL) {
      execsSinceDeadlineCheck = 0;
      if (alreadySpent + (Date.now() - runStart) > budgetMs) {
        timedOut = true;
        break;
      }
    }
    m = pattern.exec(scanText);
    if (m === null) break;
    // Anchor the match at its first non-whitespace character, not at wherever
    // the pattern happened to start.
    //
    // Many rules begin `^\s*` under the `m` flag, and `\s` matches line
    // terminators, so a match routinely opens on the blank tail of an EARLIER
    // line. That is not merely cosmetic: `^` treats a lone `\r` as a line
    // terminator while `indexToPosition` counts lines by `\n` alone, so on
    // CRLF input the two disagree by a whole line. The consequences were a
    // wrong `startLine` on every such finding and — far worse — a SILENT FALSE
    // NEGATIVE, because the `skipCommentLines` test below looked up that wrong
    // line, and if the previous line was a comment the match was DELETED. A
    // `DEBUG = True` preceded by a comment therefore vanished from every CRLF
    // file, with nothing anywhere to indicate a rule had fired at all.
    //
    // Resolving from the payload makes both the position and the comment test
    // describe the line the user would point at. `confidence.ts` already
    // applies exactly this correction internally (`inspectedLine`), and
    // `anchorMatch` in analyzer-core applies it to canonical-pass matches, so
    // this brings the three into agreement rather than inventing a fourth rule.
    const leading = m[0].length - m[0].replace(/^\s+/, '').length;
    // An all-whitespace match has no payload to anchor to; leave it as found.
    const payloadIndex = leading < m[0].length ? m.index + leading : m.index;
    const evidence = leading < m[0].length ? m[0].slice(leading) : m[0];

    // Resolved against `scanText`, not `content`. Every index here came from
    // `exec` over `scanText`, and `scanText` is a prefix of `content`, so the
    // line and column are identical either way — but only `scanText` is bounded
    // by REGEX_INPUT_CAP. Using `content` would leave these per-match O(n) walks
    // scaling with the untruncated file and quietly undo the bound.
    const start = indexToPosition(scanText, payloadIndex);
    const end = indexToPosition(scanText, m.index + m[0].length);
    if (options?.skipCommentLines) {
      const lineText = lineAt(start.line);
      if (isCommentLine(lineText, options.language)) {
        if (m[0].length === 0) pattern.lastIndex += 1;
        continue;
      }
    }
    matches.push({
      startLine: start.line,
      endLine: end.line,
      startColumn: start.column,
      endColumn: end.column,
      evidence,
      variables: m.groups ? { ...m.groups } : undefined,
    });
    if (m[0].length === 0) pattern.lastIndex += 1;
  }

  // Fold this call's matching time into the scan-wide accumulator, so the next
  // rule's budget check sees the time this one spent. Only when a span is open:
  // a directly-invoked rule uses a fresh per-call budget and has nothing to add.
  if (regexBudgetMs !== null) regexTimeSpentMs += Date.now() - runStart;

  // Reported after the loop, so `matchCount` states how much of the file was
  // actually covered before the bound applied — the number a reader needs to
  // judge whether the result is partial.
  if (timedOut) {
    reportBoundary({
      kind: 'timedOut',
      pattern: String(pattern),
      inputLength: content.length,
      matchCount: matches.length,
    });
  } else if (matches.length >= limit) {
    // The pre-existing match limit, now reported for the same reason as the two
    // new bounds: it has always been able to hide matches, and always did so
    // without saying anything.
    reportBoundary({
      kind: 'limitReached',
      pattern: String(pattern),
      inputLength: content.length,
      matchCount: matches.length,
    });
  }
  return matches;
}

export function languageMatches(ruleLanguages: string[], inputLanguage?: string): boolean {
  if (ruleLanguages.includes('*')) return true;
  if (!inputLanguage) return false;
  return ruleLanguages.includes(inputLanguage);
}
