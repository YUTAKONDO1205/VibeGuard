/**
 * D2 — normalization pre-pass (the canonicalizer).
 *
 * THE SHAPE OF THE PROBLEM. Evasion is a semantics-preserving input transform
 * `t` chosen so the detector disagrees with itself: `D(t(x)) ≠ D(x)`. The
 * defense is a normalization map `N` that projects an input onto the canonical
 * representative of its equivalence class under those transforms, so that
 * `D(N(t(x))) = D(N(x))`. Evasion and defense are dual — a transform group
 * against a normal form.
 *
 * `N` is deliberately restricted to three semantics-preserving operations:
 *   (1) comment removal
 *   (2) whitespace normalization
 *   (3) constant-only string-concatenation folding (`"ev" + "al"` → `"eval"`)
 *
 * Folding stops at constants because folding `x + y` requires runtime values.
 * The complete normalization of meaning is undecidable (a Rice-theorem wall),
 * so `N` can only collapse a decidable sub-family of transforms and RESIDUAL
 * EVASION NECESSARILY EXISTS. That residue is pinned by tests rather than
 * papered over — see `canonicalizer-soundness.test.ts`.
 *
 * WHY THIS MODULE DOES NOT REPLACE THE SCANNED CONTENT. The obvious reading of
 * "normalize before matching" is to feed `N(x)` to the rules instead of `x`.
 * That is unsound here, and the rules themselves prove it:
 *
 *   - `secrets.ts` runs `runRegex(ctx.content, …)` with no `skipCommentLines`.
 *     An AWS key sitting in a comment is a genuinely leaked credential and is
 *     detected today. Blanking comments first would erase it.
 *   - VG-AUTH-002 and VG-QUAL-009 match ON the comment markers themselves
 *     (`/(?:\/\/|#|\/\*)\s*(?:TODO|FIXME…)/`). For them the comment IS the
 *     signal — both carry `contextConfidence: 'off'` for exactly that reason.
 *     Blanking comments makes those rules match nothing at all.
 *
 * Both failures are silent false negatives, which this codebase treats as
 * strictly worse than false positives: a dropped match never reaches the
 * analyzer's confidence chokepoint, so the severity gate cannot bound the
 * mistake, whereas a noisy finding is visible and triageable. (Same asymmetry
 * argued at length on `LINE_COMMENT_SPECS` in matcher-utils.)
 *
 * So the analyzer runs rules over BOTH the original and the canonical content
 * and merges: `D′(x) = D(x) ∪ D(N(x))`. `D′(x) ⊇ D(x)` then holds BY
 * CONSTRUCTION for every input — the soundness obligation is discharged by the
 * shape of the composition, not by passing a corpus. `analyzer.ts` owns the
 * union; this module only computes `N`.
 *
 * GEOMETRY IS LOAD-BEARING. Findings carry `startLine`/`startColumn` straight
 * from the match, snippets are cut from `ctx.lines`, and suppressions are keyed
 * by original line number. So `N` is LENGTH- AND NEWLINE-PRESERVING: removed
 * characters are overwritten with U+0020 and folded literals are right-padded,
 * never shifted. Canonical-space positions are therefore identity-mapped to
 * original-space positions, and no consumer of a position needs to know this
 * pass exists. The alternative — a canonical→original source map — would put a
 * translation seam in front of findings, suppressions, snippets and
 * remediation, each one an off-by-one waiting to happen.
 *
 * Comment syntax is NOT decided here. It comes from `getLineCommentSpec` /
 * `lineCommentStartsAt` in @vibeguard/rules, the single source of truth that
 * also backs `runRegex({ skipCommentLines })` and the confidence scanner.
 * Rolling a private comment model here would reopen the concealment vectors
 * that allowlist closes (`//` in python, `#` in html, PHP 8's `#[Attribute]`,
 * and undetected languages).
 */

import { getLineCommentSpec, lineCommentStartsAt } from '@vibeguard/rules';

/** Per-op counters — feed the audit trail and the evasion A/B harness. */
export interface CanonicalizeStats {
  /** Characters overwritten because they were inside a comment. */
  commentsBlanked: number;
  /** Exotic whitespace characters mapped to U+0020. */
  whitespaceMapped: number;
  /** Constant-only concatenation runs folded into a single literal. */
  foldsApplied: number;
}

export interface CanonicalizeResult {
  /**
   * The canonical form. Same length and same newline offsets as the input, so
   * any position computed over it is valid in the original.
   */
  content: string;
  /** Whether anything actually changed — lets the caller skip a second pass. */
  changed: boolean;
  stats: CanonicalizeStats;
}

/**
 * What a language allows, for the three normalization ops.
 *
 * Absence from this table is the fail-safe: an unknown or unmodelled language
 * gets no canonicalization at all. That matters most for op (2) — mapping a tab
 * to a space inside a string literal CHANGES the program, so whitespace
 * normalization is only sound when we can tell strings from code, which
 * requires knowing the delimiters.
 */
interface LanguageProfile {
  /** `/* … *\/` is a comment in this language. */
  readonly blockComment: boolean;
  /**
   * Single-character quote delimiters whose interiors are skipped. This is the
   * SCANNING set: everything here is protected from comment- and
   * whitespace-rewriting, which is why `'` appears even for languages where it
   * quotes a character rather than a string.
   */
  readonly stringDelims: readonly string[];
  /**
   * The subset of `stringDelims` that actually delimits a STRING, and may
   * therefore participate in concatenation folding.
   *
   * The distinction is not pedantic. In Java, C#, Kotlin, Go, C, C++, Rust and
   * Swift, `'e'` is a character/rune literal and `'e' + 'v'` is INTEGER
   * ADDITION — 101 + 118 = 219, not `"ev"`. Folding it would fabricate a
   * literal the program does not contain, and could manufacture a finding out
   * of arithmetic. Those languages scan `'` but never fold it.
   */
  readonly foldDelims: readonly string[];
  /**
   * Delimiters that open a RAW literal, where `\` is an ordinary character
   * rather than an escape. Go's backtick strings are raw: in `` `C:\` `` the
   * backslash does not escape the closing backtick. Treating it as an escape
   * swallows the terminator and the scan runs to end of file, silently
   * disabling canonicalization for everything after it.
   */
  readonly rawDelims: readonly string[];
  /** Python-style `"""`/`'''`. */
  readonly tripleQuote: boolean;
  /** Infix operators that concatenate two string constants. */
  readonly concatOps: readonly string[];
  /** Adjacent literals concatenate with no operator (`"ev" "al"`). */
  readonly adjacencyConcat: boolean;
  /**
   * Languages where `#` opens a comment ONLY at the start of a word, so a `#`
   * with a non-space character before it is ordinary syntax.
   *
   * Shell parameter expansion (`${PATH#/usr}`), a URL fragment
   * (`curl http://h/x#frag`), and YAML/TOML values (`a#b`) all rely on this.
   * Python, Ruby and PHP are NOT in this set: there `#` opens a comment
   * wherever it appears outside a string.
   */
  readonly hashNeedsWordStart: boolean;
  /**
   * Languages where `--` opens a comment only when followed by whitespace.
   * MySQL requires the space, so `a--b` is `a - (-b)`, executable arithmetic.
   */
  readonly dashDashNeedsSpace: boolean;
  /**
   * Languages with `/-/` regular-expression literals, whose interior is
   * ordinary data rather than code.
   *
   * Without this the interior is scanned as code, and a `/` or `*` inside it is
   * read as the syntax it resembles. A literal holding one then opens a phantom
   * block comment that runs to the next closer or, far more often, to end of
   * file - one harmless-looking line at the top of a file silently switches the
   * canonical pass off for everything below it. `D' >= D` still holds because
   * the original pass is untouched, so nothing is lost outright; what is lost
   * is every detection the normalization was supposed to ADD, which is the
   * entire point of the pre-pass.
   *
   * Only `javascript`/`typescript`. Ruby and Perl also have slash-delimited
   * patterns, but their disambiguation rules are genuinely different (`%r{}`
   * forms, method-call parsing) and a wrong rule here destroys text. Guessing
   * at them would be worse than the honest residual of not modelling them.
   */
  readonly regexLiteral: boolean;
}

/**
 * The block-comment allowlist is deliberately STRICTER than the confidence
 * scanner's, which treats `/*` as an opener in every language. Down-ranking a
 * line that merely looks like a block comment costs a little precision;
 * BLANKING it destroys text, so it is only done where `/* … *\/` really is
 * comment syntax.
 *
 * `json` gets block comments for the same reason it gets `//` in
 * `LINE_COMMENT_SPECS`: strict JSON has neither, but no valid JSON token can
 * begin with `/`, so recognising them costs nothing and handles the JSONC
 * dialects actually encountered (tsconfig.json and friends).
 *
 * Notable `concatOps` omissions, each of which would be UNSOUND to fold:
 *   - `c` / `cpp`: `+` on string literals is pointer arithmetic, not
 *     concatenation. They fold by adjacency only, which is the real syntax.
 *   - `rust`: `"a" + "b"` does not compile (`&str + &str` is not an operator).
 *   - `php`: concatenates with `.`, never `+` (`+` is numeric coercion).
 *   - `sql` (`||`), `shell`, `yaml`, `toml`, `json`: left as residual rather
 *     than guessed at.
 *
 * `html` has no entry at all: its only comment syntax is the multi-line
 * `<!-- -->` this line-oriented model does not handle, and its quotes delimit
 * attributes rather than string literals.
 */
const LANGUAGE_PROFILES: Record<string, LanguageProfile> = {
  javascript: { blockComment: true, stringDelims: ['"', "'", '`'], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: true },
  typescript: { blockComment: true, stringDelims: ['"', "'", '`'], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: true },
  java: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  kotlin: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  csharp: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  swift: { blockComment: true, stringDelims: ['"'], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  go: { blockComment: true, stringDelims: ['"', "'", '`'], foldDelims: ['"'], rawDelims: ['`'], tripleQuote: false, concatOps: ['+'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  c: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: true, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  cpp: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: true, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  rust: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  php: { blockComment: true, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: ['.'], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  python: { blockComment: false, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: true, concatOps: ['+'], adjacencyConcat: true, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  ruby: { blockComment: false, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: ['+'], adjacencyConcat: true, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
  shell: { blockComment: false, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: true, dashDashNeedsSpace: false, regexLiteral: false },
  yaml: { blockComment: false, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: true, dashDashNeedsSpace: false, regexLiteral: false },
  toml: { blockComment: false, stringDelims: ['"', "'"], foldDelims: ['"', "'"], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: true, dashDashNeedsSpace: false, regexLiteral: false },
  sql: { blockComment: true, stringDelims: ["'", '"'], foldDelims: ["'"], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: true, dashDashNeedsSpace: true, regexLiteral: false },
  json: { blockComment: true, stringDelims: ['"'], foldDelims: ['"'], rawDelims: [], tripleQuote: false, concatOps: [], adjacencyConcat: false, hashNeedsWordStart: false, dashDashNeedsSpace: false, regexLiteral: false },
};

/**
 * Horizontal and exotic whitespace, mapped 1:1 to a plain space in code
 * regions. Runs are never collapsed and `\n`/`\r` are never touched — that
 * would move offsets and break the geometry contract.
 *
 * Zero-width characters (U+200B/200C/200D) are deliberately NOT included.
 * Deleting a zero-width joiner from inside an identifier changes which
 * identifier it is: `eval‌` is a different name from `eval`, not an
 * obfuscation of it. Normalizing it away would not preserve semantics, so it
 * falls outside `N` by definition.
 */
const EXOTIC_WHITESPACE = /[\t\v\f\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\ufeff]/;

/** A `"…"`/`'…'` literal found in code position, and whether it can be folded. */
interface StringLiteral {
  /** Offset of the opening delimiter. */
  start: number;
  /** Offset one past the closing delimiter. */
  end: number;
  delim: string;
  /** Text between the delimiters. */
  inner: string;
  /** Contains a backslash — folding would have to reason about escapes. */
  hasEscape: boolean;
  /**
   * Preceded by an identifier character, so the quote is not a bare literal:
   * `f"…"`, `r"…"`, `b"…"`, `u"…"` in python, or a delimiter glued to a name.
   * The prefix changes how the literal is interpreted, so it is never folded.
   */
  prefixed: boolean;
  /** Unterminated at end of input. */
  unterminated: boolean;
  /** 1-based line the literal starts on. */
  line: number;
}

const ZERO_STATS: CanonicalizeStats = { commentsBlanked: 0, whitespaceMapped: 0, foldsApplied: 0 };

function isIdentChar(ch: string | undefined): boolean {
  return ch != null && /[A-Za-z0-9_$]/.test(ch);
}

/**
 * Words after which a `/` opens a regular expression rather than dividing.
 *
 * Needed because the preceding-token test below is otherwise character-based:
 * `return /x/` and `total /x/` end in the same character class, and only the
 * word tells them apart. Leaving a word OUT of this set costs a missed regex,
 * which degrades to the behaviour that existed before literals were modelled at
 * all; putting a wrong one IN would start a regex scan inside arithmetic.
 */
const REGEX_ALLOWED_AFTER_WORD = new Set([
  'return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'do',
  'else', 'yield', 'await', 'case', 'throw',
]);

/**
 * End of the regular-expression literal opening at `start`, or `-1` if what
 * starts there is not one after all.
 *
 * `-1` is the SAFE answer and every uncertain path returns it: the caller then
 * advances a single character, which is exactly what it did before literals
 * were modelled. A wrong `-1` costs one unrecognized regex; a wrong end offset
 * would skip over live code.
 *
 * The character class is tracked because `/` does not terminate a literal
 * inside one, which is the compact form of this evasion and needs no backslash.
 * A newline ends the scan unconditionally: JavaScript regex literals cannot
 * span lines, so anything reaching one was a division after all, and bounding
 * the misread to a single line is what makes it cheap.
 */
function scanRegexLiteral(content: string, start: number): number {
  const n = content.length;
  // `//` and `/*` are comment openers, decided before this is ever called, and
  // neither is a legal way to begin a regex (a bare `*` has nothing to repeat).
  const first = content[start + 1];
  if (first == null || first === '/' || first === '*') return -1;

  let k = start + 1;
  let inClass = false;
  while (k < n) {
    const c = content[k]!;
    if (c === '\n' || c === '\r') return -1;
    if (c === '\\') {
      k += 2;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      k += 1;
      continue;
    }
    if (c === '[') {
      inClass = true;
      k += 1;
      continue;
    }
    if (c === '/') {
      k += 1;
      while (k < n && /[a-z]/i.test(content[k]!)) k += 1;
      return k;
    }
    k += 1;
  }
  return -1;
}

/**
 * Second opinion on a comment opener that `lineCommentStartsAt` has already
 * accepted, for the positions that predicate was never designed to judge.
 *
 * `lineCommentStartsAt` is consulted by `isCommentLine` only at the first
 * non-space character of a line, where "is this a comment?" and "does this
 * token start a comment?" are the same question. Scanning INLINE asks it at
 * every offset, where they come apart: shell `${PATH#/usr}`, a URL fragment in
 * `curl http://h/x#frag`, and MySQL's `a--b` all carry a token the allowlist
 * recognises in a position where the language does not treat it as a comment.
 *
 * Blanking those is not a small error — it destroys the rest of the line,
 * including any payload a rule was meant to find. So the shared allowlist stays
 * the single source of truth for WHICH tokens open comments (nothing here
 * introduces a token of its own), and this function only narrows WHERE an
 * accepted token counts. At a line's first non-space character both guards are
 * satisfied by construction, so behaviour there is identical to `isCommentLine`
 * and the two cannot drift.
 */
function commentReallyStartsAt(content: string, i: number, profile: LanguageProfile): boolean {
  if (profile.hashNeedsWordStart && content[i] === '#') {
    const prev = content[i - 1];
    if (prev != null && prev !== '\n' && prev !== '\r' && !/\s/.test(prev)) return false;
  }
  if (profile.dashDashNeedsSpace && content.startsWith('--', i)) {
    const next = content[i + 2];
    if (next != null && next !== '\n' && next !== '\r' && !/\s/.test(next)) return false;
  }
  return true;
}

/**
 * `N` — project `content` onto the canonical representative of its lexical
 * equivalence class.
 *
 * Deterministic and idempotent: `canonicalize(canonicalize(x, l).content, l)`
 * returns its input unchanged. Length- and newline-preserving by construction.
 * Pure string manipulation, so node and browser entrypoints behave identically.
 */
export function canonicalize(content: string, language: string | undefined): CanonicalizeResult {
  // `Object.hasOwn`, not a bare index. A `language` of `'__proto__'`,
  // `'constructor'` or `'toString'` otherwise resolves to an inherited value
  // that is not nullish, dodges the fallback below, and crashes on
  // `profile.stringDelims`. Thrown from inside `rule.match`, that crash is
  // swallowed by the analyzer's per-rule try/catch — i.e. it would silently
  // drop a rule's findings, the exact undeclared-suppression channel this
  // module is supposed to help close. Same guard, same reason, as
  // `getLineCommentSpec`.
  const profile =
    language != null && Object.hasOwn(LANGUAGE_PROFILES, language)
      ? LANGUAGE_PROFILES[language]
      : undefined;
  // Unknown or unmodelled language: do nothing. Blanking what we cannot parse
  // would be the silent-false-negative direction, and mapping whitespace
  // without knowing where strings are would not preserve semantics.
  if (!profile) return { content, changed: false, stats: { ...ZERO_STATS } };

  const spec = getLineCommentSpec(language);
  const out = content.split('');
  const stats: CanonicalizeStats = { ...ZERO_STATS };
  const literals: StringLiteral[] = [];

  /** Overwrite `[from, to)` with spaces, preserving newlines so offsets hold. */
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to; k++) {
      const ch = content[k]!;
      if (ch === '\n' || ch === '\r') continue;
      out[k] = ' ';
      stats.commentsBlanked += 1;
    }
  };

  let i = 0;
  let line = 1;
  const n = content.length;
  /**
   * Whether the last significant token was a VALUE (identifier, number,
   * string, regex, or a closing bracket). A `/` after a value divides; a `/`
   * anywhere else opens a regular expression. Comments and whitespace are not
   * tokens and leave it alone, which is why this is threaded through the loop
   * rather than derived from `content[i - 1]`.
   *
   * `}` counts as a value even though it ends a block as often as an object
   * literal. That is the safe side of the ambiguity: it prefers division, and
   * preferring division only ever costs an unrecognized regex.
   */
  let prevIsValue = false;

  while (i < n) {
    const ch = content[i]!;

    if (ch === '\n') {
      line += 1;
      i += 1;
      continue;
    }

    // Triple-quoted strings are STRINGS, not comments — a python docstring has
    // a runtime value. Payloads hidden in a docstring are a concealment (B3)
    // problem for the severity gate, not a normalization problem. Skipped
    // wholesale so nothing inside is touched.
    if (profile.tripleQuote && (content.startsWith('"""', i) || content.startsWith("'''", i))) {
      const q = content.slice(i, i + 3);
      const close = content.indexOf(q, i + 3);
      const stop = close === -1 ? n : close + 3;
      for (let k = i; k < stop; k++) if (content[k] === '\n') line += 1;
      i = stop;
      prevIsValue = true;
      continue;
    }

    if (profile.blockComment && content.startsWith('/*', i)) {
      const close = content.indexOf('*/', i + 2);
      // Unterminated block comment runs to EOF, which is what a compiler
      // ignores too.
      const stop = close === -1 ? n : close + 2;
      blank(i, stop);
      for (let k = i; k < stop; k++) if (content[k] === '\n') line += 1;
      i = stop;
      continue;
    }

    // Absolute-offset call is safe: no prefix in the allowlist contains a
    // newline, so `startsWith(p, i)` over the whole content is equivalent to
    // asking within the line.
    if (lineCommentStartsAt(content, i, spec) && commentReallyStartsAt(content, i, profile)) {
      let stop = content.indexOf('\n', i);
      if (stop === -1) stop = n;
      blank(i, stop);
      i = stop;
      continue;
    }

    // AFTER both comment branches, never before. A legal regex literal cannot
    // begin `/*` or `//`, so nothing here is reachable for real comment syntax
    // - whereas putting it first would read the comment in `x = 1; /* c */` as
    // a regex (it ends on the closer's slash) and stop blanking genuine
    // comments, a worse regression than the bug being fixed.
    if (profile.regexLiteral && ch === '/' && !prevIsValue) {
      const end = scanRegexLiteral(content, i);
      if (end !== -1) {
        // Left verbatim, not blanked. The interior is data the rules are
        // entitled to see, and skipping it costs nothing: length and newline
        // offsets are preserved trivially, and a second pass takes the same
        // branch, so idempotence holds by doing nothing at all.
        i = end;
        prevIsValue = true;
        continue;
      }
    }

    // Identifiers are consumed whole so the WORD before a `/` can be tested,
    // not just its last character. The guard on the preceding character keeps
    // the tail of a longer identifier from being mistaken for a keyword.
    if (isIdentChar(ch) && !isIdentChar(content[i - 1])) {
      let k = i;
      while (k < n && isIdentChar(content[k])) k += 1;
      prevIsValue = !REGEX_ALLOWED_AFTER_WORD.has(content.slice(i, k));
      i = k;
      continue;
    }

    if (profile.stringDelims.includes(ch)) {
      const startLine = line;
      const raw = profile.rawDelims.includes(ch);
      let k = i + 1;
      let hasEscape = false;
      let closed = false;
      while (k < n) {
        const c = content[k]!;
        // Raw literals have no escape sequences. Honouring `\` inside one would
        // consume its own terminator (Go's `` `C:\` ``) and run the scan to end
        // of file, which silently disables canonicalization for the remainder.
        if (c === '\\' && !raw) {
          hasEscape = true;
          if (content[k + 1] === '\n') line += 1;
          k += 2;
          continue;
        }
        if (c === ch) {
          closed = true;
          break;
        }
        // A bare newline ends a single-quoted literal in every language here
        // except the backtick forms, which legitimately span lines.
        if (c === '\n') {
          if (ch !== '`') break;
          line += 1;
        }
        k += 1;
      }
      const end = closed ? k + 1 : Math.min(k, n);
      if (ch === '"' || ch === "'") {
        literals.push({
          start: i,
          end,
          delim: ch,
          inner: content.slice(i + 1, closed ? k : end),
          hasEscape,
          prefixed: isIdentChar(content[i - 1]),
          unterminated: !closed,
          line: startLine,
        });
      }
      i = end;
      prevIsValue = true;
      continue;
    }

    if (EXOTIC_WHITESPACE.test(ch)) {
      out[i] = ' ';
      stats.whitespaceMapped += 1;
    }
    // Whitespace is not a token and must not clear the flag: a slash on the
    // line after `a` still divides, and it is the `a` that says so. Everything
    // else reaching here is punctuation or an operator, after which a `/`
    // starts a regex - except the closing brackets, which end a value.
    if (!/\s/.test(ch)) prevIsValue = ch === ')' || ch === ']' || ch === '}';
    i += 1;
  }

  foldConcatenations(content, out, literals, profile, stats);

  const canonical = out.join('');
  return { content: canonical, changed: canonical !== content, stats };
}

/**
 * Op (3) — fold runs of constant string literals joined by a concatenation
 * operator into a single literal, in place.
 *
 * Folding is restricted to a SINGLE PHYSICAL LINE. The folded literal is
 * written left-aligned at the start of the run and the remainder of the span is
 * padded with spaces, which is what keeps the geometry contract. It always
 * fits: a run of `k ≥ 2` literals spends `2k` characters on delimiters plus the
 * operators and gaps between them, while the result spends only `2`, so the
 * replacement is strictly shorter than the span it overwrites. A run spanning
 * lines has no single span to pad into, so it is left as residual evasion.
 *
 * Every condition below is a REASON TO SKIP, never a reason to guess. An
 * unfolded evasion is a residual that gets reported honestly; a wrongly folded
 * one would fabricate or destroy findings.
 */
function foldConcatenations(
  content: string,
  out: string[],
  literals: StringLiteral[],
  profile: LanguageProfile,
  stats: CanonicalizeStats,
): void {
  if (profile.concatOps.length === 0 && !profile.adjacencyConcat) return;

  const foldable = literals.filter(
    (l) =>
      !l.hasEscape &&
      !l.prefixed &&
      !l.unterminated &&
      // `'e' + 'v'` is integer addition in Java/C#/Kotlin/Go/C/C++/Rust/Swift,
      // not concatenation. Folding it would invent a literal.
      profile.foldDelims.includes(l.delim),
  );

  let idx = 0;
  while (idx < foldable.length) {
    const run: StringLiteral[] = [foldable[idx]!];
    let j = idx + 1;
    while (j < foldable.length) {
      const prev = run[run.length - 1]!;
      const next = foldable[j]!;
      if (next.line !== prev.line) break;
      if (next.delim !== prev.delim) break;
      if (!isConcatGap(content.slice(prev.end, next.start), profile)) break;
      run.push(next);
      j += 1;
    }

    if (run.length >= 2) {
      const first = run[0]!;
      const last = run[run.length - 1]!;
      const merged = first.delim + run.map((l) => l.inner).join('') + first.delim;
      const span = last.end - first.start;
      const text = content.slice(first.start, last.end);
      // A line terminator inside the span means the run is not really on one
      // line — the line counter advances only on `\n`, so a lone `\r` between
      // two literals slips past the same-line guard above. Writing through it
      // would delete a terminator, the one thing `blank` is careful never to
      // do. Refuse instead: an unfolded run is an honest residual.
      const spansTerminator = text.includes('\n') || text.includes('\r');
      // Defensive: the arithmetic guarantees this (k ≥ 2 literals spend 2k
      // characters on delimiters, the result spends 2), but a silent overrun
      // would corrupt every position in the file after this point.
      if (merged.length <= span && !spansTerminator) {
        for (let k = 0; k < span; k++) {
          out[first.start + k] = k < merged.length ? merged[k]! : ' ';
        }
        stats.foldsApplied += 1;
      }
    }

    idx = Math.max(j, idx + 1);
  }
}

/**
 * True when the text between two literals is nothing but a concatenation.
 *
 * The gap is read from the ORIGINAL content, but a comment sitting between the
 * operands has already been blanked in `out`, so `"ev" /* x *\/ + "al"` still
 * folds — the gap seen here contains the comment text, which is why the check
 * below tolerates only what it can prove. Anything else (a comma, a paren, an
 * identifier) means these are two separate arguments, not one expression.
 */
function isConcatGap(gap: string, profile: LanguageProfile): boolean {
  const stripped = stripBlankableGap(gap, profile);
  if (stripped === null) return false;
  const trimmed = stripped.trim();
  if (trimmed === '') return profile.adjacencyConcat;
  return profile.concatOps.includes(trimmed);
}

/**
 * Remove any comment text from a gap, so an operand separated by a comment is
 * still recognised as a concatenation. Returns null if the gap contains a
 * construct this pass will not reason about.
 */
function stripBlankableGap(gap: string, profile: LanguageProfile): string | null {
  if (!profile.blockComment) return gap;
  let result = '';
  let i = 0;
  while (i < gap.length) {
    if (gap.startsWith('/*', i)) {
      const close = gap.indexOf('*/', i + 2);
      if (close === -1) return null;
      i = close + 2;
      continue;
    }
    result += gap[i];
    i += 1;
  }
  return result;
}
