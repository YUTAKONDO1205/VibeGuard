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
 * Run a global regex against the source and convert each match into a RuleMatch.
 * Pattern MUST have the global flag.
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
  let m: RegExpExecArray | null;
  pattern.lastIndex = 0;
  while ((m = pattern.exec(content)) !== null) {
    if (matches.length >= limit) break;
    const start = indexToPosition(content, m.index);
    const end = indexToPosition(content, m.index + m[0].length);
    if (options?.skipCommentLines) {
      const lineText = content.split('\n')[start.line - 1] ?? '';
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
      evidence: m[0],
      variables: m.groups ? { ...m.groups } : undefined,
    });
    if (m[0].length === 0) pattern.lastIndex += 1;
  }
  return matches;
}

export function languageMatches(ruleLanguages: string[], inputLanguage?: string): boolean {
  if (ruleLanguages.includes('*')) return true;
  if (!inputLanguage) return false;
  return ruleLanguages.includes(inputLanguage);
}
