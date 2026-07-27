import { nearestKnownPackage, type RuleMatch } from '@vibeguard/rules';

// VG-EMB 18 FIX — deterministic, LLM-free, zero-send autofix.
//
// A fixer table keyed by rule ID, DELIBERATELY separate from RuleDefinition:
//   - the rules package is the detection core shipped to all four channels; the
//     Chrome / VS Code bundles do not need fix code.
//   - one file enumerates exactly which rules are auto-fixable — auditable at a
//     glance.
//   - no findings-schema / RuleDefinition churn.
// The drift risk (a stale ruleId key) is closed by fixers.test.ts, which asserts
// every key here exists in `allRules`.
//
// THE DESIGN PRINCIPLE, one line: a fixer's `build` returns edits ONLY when the
// fix is deterministically correct from the file bytes alone, and `null`
// otherwise. It never invents data the code does not contain (a buffer size, a
// certificate, a credential) and never changes a signature. Fixes that would
// require any of that carry NO fixer — prose remediation only.
//
// `safety`:
//   - 'safe'         : strictly-stronger semantics, applyable without review.
//   - 'needs-review' : correct and fail-closed, but changes behaviour (a TLS
//                      handshake starts validating, a bypass turns off) — a human
//                      must confirm the intent.

/** A single text replacement, as absolute character offsets into the file. */
export interface FixEdit {
  start: number;
  end: number;
  replacement: string;
}

export interface Fixer {
  /** Imperative title shown in the PR / diff. */
  title: string;
  safety: 'safe' | 'needs-review';
  /** Edits for this match, or null when the fix is not provably correct here. */
  build(content: string, match: RuleMatch): FixEdit[] | null;
}

/** Absolute offset of the start of 1-based `line`. */
function lineStartOffset(content: string, line: number): number {
  let off = 0;
  for (let l = 1; l < line; l++) {
    const nl = content.indexOf('\n', off);
    if (nl === -1) return content.length;
    off = nl + 1;
  }
  return off;
}

/** The physical line (without terminator) containing `startLine`, and its offset. */
function lineOf(content: string, match: RuleMatch): { text: string; offset: number } {
  const offset = lineStartOffset(content, match.startLine);
  const nl = content.indexOf('\n', offset);
  const end = nl === -1 ? content.length : nl;
  return { text: content.slice(offset, end), offset };
}

/** Build a single-token replacement from a regex whose group 1 is the token. */
function tokenSwap(
  content: string,
  match: RuleMatch,
  re: RegExp,
  replacement: string,
): FixEdit[] | null {
  const { text, offset } = lineOf(content, match);
  // Seed the search at the finding's COLUMN, not the line start, so a line with
  // two matching tokens (`a("http://x"); b("http://y");`) fixes the one the
  // finding actually anchors to — not always the first.
  const col0 = Math.max(0, (match.startColumn ?? 1) - 1);
  const sub = text.slice(col0);
  const m = re.exec(sub);
  if (!m || m.index === undefined) return null;
  // Offset of group 1 within the searched substring.
  const g1 = m[1]!;
  const g1Local = sub.indexOf(g1, m.index);
  if (g1Local === -1) return null;
  const start = offset + col0 + g1Local;
  return [{ start, end: start + g1.length, replacement }];
}

// --- VG-INJ-020 (prototype-polluting merge) ------------------------------------
//
// A for-in loop HEADER with a braced body, ANCHORED (`^`) because the caller
// matches it against the line sliced at the finding's column. See
// `protoGuardEdits` for why anchoring — rather than tokenSwap's search-forward —
// is the whole safety mechanism here.
//
// Two deliberate differences from the rule's own `FOR_IN`:
//   1. the `const|let|var` keyword, when present, must be followed by real
//      whitespace. The rule allows zero, so `for (variable in src)` captures
//      `iable` there; that is harmless for DETECTION (the resulting write-regex
//      simply fails to match, so no finding), but a fixer that echoed `iable`
//      into a guard would emit a reference to an undeclared identifier. A fixer
//      has to be stricter than the detector, never looser.
//   2. the closing `)` and the body's `{` are REQUIRED. The rule does not need
//      them; the insertion point does.
// Bounded quantifiers only (D3): every `{0,n}`/`{1,n}` run is adjacent to a
// disjoint character class, so there is nothing to backtrack over.
const FOR_IN_HEAD =
  /^for[^\S\r\n]{0,4}\([^\S\r\n]{0,4}(?:(?:const|let|var)[^\S\r\n]{1,4})?(?<k>[\w$]{1,40})[^\S\r\n]{1,4}in[^\S\r\n]{1,4}[\w$.]{1,60}[^\S\r\n]{0,4}\)[^\S\r\n]{0,4}\{/;

/** Leading horizontal whitespace of a line (its indentation), verbatim. */
function indentOf(line: string): string {
  return /^[^\S\r\n]*/.exec(line)?.[0] ?? '';
}

/** The physical line AFTER the one starting at `offset`, or null at EOF. */
function nextLineAfter(content: string, offset: number): string | null {
  const nl = content.indexOf('\n', offset);
  if (nl === -1) return null;
  const start = nl + 1;
  if (start >= content.length) return null;
  const end = content.indexOf('\n', start);
  return content.slice(start, end === -1 ? content.length : end);
}

/**
 * Insert the own-key guard as the first statement of an unguarded for-in merge.
 *
 * WHY THIS IS DETERMINISTIC: every byte of the inserted text comes from the file
 * — the loop variable is re-extracted lexically from the loop header, the
 * indentation is copied from a neighbouring line, the line terminator is the
 * one this file already uses. Nothing is invented; the three guarded keys are
 * the fixed, language-defined set of prototype sinks (they are also exactly what
 * the rule's own `remediation.exampleFix` prescribes).
 *
 * WHY ANCHORING AT THE COLUMN IS LOAD-BEARING: VG-INJ-020 reports TWO shapes
 * under one rule ID. Branch A is a literal write into a prototype sink
 * (`obj.__proto__ = x`) and its match column points at the SINK; Branch B is
 * the unguarded recursive merge and its column points at the `for` keyword. A
 * for-in guard inserted for a Branch A finding is at best the wrong fix and, on
 * a line like `obj.__proto__ = {}; for (const k in src) {`, silently edits a
 * loop nobody complained about. Searching forward from the column (what
 * `tokenSwap` does) would do exactly that. Requiring the loop header to begin AT
 * the reported column makes Branch A structurally unfixable — it can never point
 * at a `for` — so no shape test, denylist, or evidence sniffing is needed.
 *
 * REJECTED ALTERNATIVES:
 *   - rewriting the loop to `for (const k of Object.keys(src))`: changes
 *     iteration semantics (own vs inherited enumerable keys) and would silently
 *     drop keys the program was relying on. `continue` on the three sinks is the
 *     minimal edit that closes CWE-1321.
 *   - matching the file's quote style for the three literals: sniffing quotes is
 *     a heuristic, and the guard is correct either way. Double quotes are used
 *     unconditionally; a formatter settles the rest.
 *   - brace-less bodies (`for (k in o) dst[k] = src[k];`): fixing those needs a
 *     block to be SYNTHESISED around the statement, i.e. deciding where the
 *     statement ends. That is parsing, not lexing — `null`.
 */
function protoGuardEdits(content: string, match: RuleMatch): FixEdit[] | null {
  const { text, offset } = lineOf(content, match);
  // Idempotence, part 1: the rule's own guard vocabulary includes the literal
  // string `"__proto__"`, so once this fix lands the rule goes silent and this
  // fixer is never asked again. The check is belt-and-braces for a stale finding
  // replayed against already-fixed bytes (inline form lands on this line…).
  if (text.includes('__proto__')) return null;
  const col0 = Math.max(0, (match.startColumn ?? 1) - 1);
  if (col0 >= text.length) return null;
  const head = FOR_IN_HEAD.exec(text.slice(col0));
  if (!head?.groups?.k) return null;
  const k = head.groups.k;

  // The `{` is the last character the header pattern consumed; insert after it.
  const braceLocal = col0 + head[0].length - 1;
  const insertAt = offset + braceLocal + 1;
  const guard = `if (${k} === "__proto__" || ${k} === "constructor" || ${k} === "prototype") continue;`;

  const rest = text.slice(braceLocal + 1);
  if (rest.trim() !== '') {
    // Code already follows the brace on this line (`… ) { dst[k] = src[k]; }`).
    // Keep it a one-liner: a leading space plus the guard is valid JS and does
    // not reflow anything.
    return [{ start: insertAt, end: insertAt, replacement: ` ${guard}` }];
  }

  // Block form. The terminator comes from THIS line when it has one (a file with
  // mixed endings is then still handled per-line); only a final line without a
  // terminator falls back to sniffing the file, which is still the file's bytes
  // and never a hardcoded default.
  const eol = text.endsWith('\r') ? '\r\n' : content.includes('\r\n') ? '\r\n' : '\n';
  const headIndent = indentOf(text);
  const next = nextLineAfter(content, offset);
  // Idempotence, part 2: the block form puts the guard on the NEXT line.
  if (next !== null && next.includes('__proto__')) return null;
  // Copy the body's own indentation when there is a body line more indented than
  // the header. Otherwise reuse the header's indentation verbatim: guessing a
  // width ("two spaces", "one tab") would be inventing formatting the file never
  // showed us, and a guard at the header's indent is still correct code.
  let indent = headIndent;
  if (next !== null && next.trim() !== '') {
    const nextIndent = indentOf(next);
    if (nextIndent.length > headIndent.length && nextIndent.startsWith(headIndent)) {
      indent = nextIndent;
    }
  }
  return [{ start: insertAt, end: insertAt, replacement: `${eol}${indent}${guard}` }];
}

// --- VG-AISC-001 (hallucinated dependency) -------------------------------------
//
// Import-position specifiers only. Scanning every quoted string on the line was
// rejected: `log("expres")` is not an import, and renaming it would corrupt a
// message. The two alternations mirror the DETECTOR'S extraction positions
// (`require(…)`, dynamic `import(…)`, `from '…'`, bare `import '…'`); the
// classification — "is this a near miss, and of what?" — is NOT mirrored, it is
// imported from the rules package (see `nearestKnownPackage`).
const JS_IMPORT_SPEC =
  /(?:require|import)[^\S\r\n]{0,2}\([^\S\r\n]{0,2}(?<q1>["'])(?<s1>[^"'\n]{1,120})\k<q1>|\b(?:from|import)[^\S\r\n]{1,4}(?<q2>["'])(?<s2>[^"'\n]{1,120})\k<q2>/g;
// Python: the module named by a leading `import X` / `from X import …`.
const PY_IMPORT_SPEC = /^[^\S\r\n]{0,40}(?:import|from)[^\S\r\n]{1,4}(?<mod>[A-Za-z_][\w.]{0,80})/;

interface SpecHit {
  /** Offset of the first path segment within the line. */
  local: number;
  /** The segment as written (case preserved). */
  seg: string;
}

/** Import-position package-name segments on one line, in source order. */
function importSegments(text: string): { hits: SpecHit[]; language: string } {
  const hits: SpecHit[] = [];
  // A quoted specifier in import position was SEEN, even if it was exempted.
  // That is what decides the language, not whether a candidate survived: an
  // `import x from "./local"` line is JavaScript with nothing to rename, and
  // falling through to the Python branch would let it re-read `import x` and
  // treat the binding `x` as a module name.
  let sawJsImport = false;
  JS_IMPORT_SPEC.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;
  while (guard < 100 && (m = JS_IMPORT_SPEC.exec(text)) !== null) {
    guard += 1;
    if (m[0].length === 0) {
      JS_IMPORT_SPEC.lastIndex += 1;
      continue;
    }
    const spec = m.groups?.s1 ?? m.groups?.s2;
    if (!spec) continue;
    sawJsImport = true;
    // Same exemptions as the detector: relative / absolute / scoped / protocol
    // specifiers are never candidates, so they can never be renamed.
    if (/^[.@/~#]/.test(spec) || spec.includes(':')) continue;
    const seg = spec.split('/')[0]!;
    if (!seg) continue;
    // The closing quote is the LAST character of m[0], so the specifier starts
    // `spec.length + 1` back from the match end. Computing it that way (rather
    // than `indexOf(spec)`) is not pedantry: `require("quire")` would otherwise
    // find `quire` inside the word `require`.
    hits.push({ local: m.index + m[0].length - 1 - spec.length, seg });
  }
  if (sawJsImport) return { hits, language: 'javascript' };

  // No quoted specifier anywhere → the only other import syntax this rule reads
  // is Python's unquoted one.
  const py = PY_IMPORT_SPEC.exec(text);
  const mod = py?.groups?.mod;
  if (py && mod) {
    const seg = mod.split('.')[0]!;
    if (seg) return { hits: [{ local: py.index + py[0].length - mod.length, seg }], language: 'python' };
  }
  return { hits: [], language: 'javascript' };
}

/**
 * Rename a hallucinated import to the popular package it near-misses.
 *
 * THE CONSTRAINT THAT SHAPES THIS: `RuleMatch.variables` (where the detector put
 * `didYouMean`) does not survive into a `Finding`, and the CLI rebuilds only
 * line/column when it calls a fixer. So the suggestion cannot be read back — it
 * has to be RECOMPUTED. It is recomputed by calling the detector's own
 * `nearestKnownPackage`, never by re-implementing the edit-distance/normalised-
 * key logic here: a copy would drift the day the known-package data changes and
 * would then rename imports to names the detector never suggested.
 *
 * AMBIGUITY IS FATAL, NOT GUESSED: VG-AISC-001 reports a whole-line span
 * (startColumn 1), so when a line carries two DIFFERENT near-miss imports the
 * column cannot say which finding is which — and each of the two findings would
 * ask for the first candidate, producing duplicate edits that `applyFixes` would
 * reject as overlapping anyway. Requiring exactly one distinct near-miss segment
 * on the line makes that case an honest `null` instead of a coin flip. Repeats
 * of the SAME segment are not ambiguous (one finding, one rename) and are all
 * edited.
 *
 * Curated hallucinations (`huggingface-cli`) have no suggestion at all —
 * `nearestKnownPackage` returns null for them and no edit is produced. Inventing
 * a target for a name nobody claims to know is precisely what this file refuses
 * to do.
 */
function renameHallucinatedImport(content: string, match: RuleMatch): FixEdit[] | null {
  // The finding spans the whole line, so its column carries no information to
  // seed a search with — read the entire line and disambiguate by uniqueness.
  const { text, offset } = lineOf(content, match);
  const { hits, language } = importSegments(text);
  if (hits.length === 0) return null;

  const byName = new Map<string, { canonical: string; hits: SpecHit[] }>();
  for (const hit of hits) {
    const key = hit.seg.toLowerCase();
    const existing = byName.get(key);
    if (existing) {
      existing.hits.push(hit);
      continue;
    }
    const canonical = nearestKnownPackage(hit.seg, language);
    // null covers builtins, aliases, literally-known packages, curated
    // hallucinations and plain unknowns — everything the detector would not
    // have suggested a rename for.
    if (canonical) byName.set(key, { canonical, hits: [hit] });
  }
  if (byName.size !== 1) return null; // 0 = nothing to rename, ≥2 = ambiguous
  const only = [...byName.values()][0];
  if (!only) return null; // unreachable given size === 1; noUncheckedIndexedAccess
  return only.hits.map((h) => ({
    start: offset + h.local,
    end: offset + h.local + h.seg.length,
    replacement: only.canonical,
  }));
}

// --- VG-SMELL-012 (primitive role check): NO FIXER, DELIBERATELY ---------------
//
// "Replace the string literals with an enum" was evaluated for this table and
// rejected. It fails the one-line design principle above on four independent
// counts, any one of which is disqualifying:
//   1. the enum's NAME, and every member name, would be invented — the file
//      contains "admin" and "root", not `Role.ADMIN`;
//   2. the DECLARATION has to be placed somewhere (top of file? a new module?
//      which module?) and imported at every site, i.e. the fix is cross-file
//      while this engine is single-file and offset-based;
//   3. the target language decides the construct (TS `enum` vs a frozen object
//      vs Python `enum.StrEnum` vs a Java `enum` vs Go `const`+`iota` vs a
//      Kotlin `enum class`), so one edit cannot serve the rule's six languages —
//      and that count went from three to six in §17z-e, which makes this reason
//      stronger over time rather than weaker;
//   4. the authoritative value set is usually OUTSIDE the code — a roles table
//      in a database or an IdP — so a code-only rewrite can silently narrow it.
// The rule keeps prose remediation only. This comment exists so the next person
// re-deriving "surely this one is mechanical" finds the answer before the work.

export const fixers: Record<string, Fixer> = {
  // #define DEBUG 1 → #define DEBUG 0. Strictly-stronger: turns debug OFF.
  'VG-EMB-020': {
    title: 'Set the debug define to 0',
    safety: 'safe',
    build: (content, match) =>
      tokenSwap(
        content,
        match,
        /#[ \t]*define[ \t]+(?:DEBUG|DEBUG_MODE|ENABLE_DEBUG|DEBUG_ENABLED|VERBOSE(?:_DEBUG)?)[ \t]+(1|true|TRUE)\b/,
        '0',
      ),
  },

  // #define BYPASS_AUTH 1 → 0. Fail-closed but behaviour-changing (the bypass
  // stops working, which is the point). The `if (BYPASS_...)` runtime form has
  // no safe token to flip, so build returns null there.
  'VG-EMB-021': {
    title: 'Turn the bypass flag off',
    safety: 'needs-review',
    build: (content, match) =>
      tokenSwap(
        content,
        match,
        /#[ \t]*define[ \t]+(?:BYPASS|SKIP|DISABLE)_(?:AUTH|LOGIN|SECURITY|VERIFY|TLS|SSL)\w*[ \t]+(1|true)\b/,
        '0',
      ),
  },

  // MBEDTLS_SSL_VERIFY_NONE → MBEDTLS_SSL_VERIFY_REQUIRED. The setInsecure() /
  // skip_cert_common_name_check alternatives of VG-EMB-011 have no clean token
  // swap (they need a CA to be installed), so build returns null for them.
  'VG-EMB-011': {
    title: 'Require certificate verification',
    safety: 'needs-review',
    build: (content, match) =>
      tokenSwap(content, match, /(MBEDTLS_SSL_VERIFY_NONE)/, 'MBEDTLS_SSL_VERIFY_REQUIRED'),
  },

  // "http://…" → "https://…". Behaviour-changing: the endpoint must serve TLS
  // and the device must trust its CA, hence needs-review, not safe.
  'VG-EMB-010': {
    title: 'Use https for the endpoint',
    safety: 'needs-review',
    build: (content, match) => tokenSwap(content, match, /"(http):\/\//, 'https'),
  },

  // O_DIRECT → O_DIRECT | O_SYNC. Adds durability; a perf change, so review.
  'VG-RTOS-004': {
    title: 'Add O_SYNC for durability',
    safety: 'needs-review',
    build: (content, match) => {
      // Idempotence guard: if the flags already contain O_SYNC/O_DSYNC, there is
      // nothing to add — never append a second one.
      if (/O_SYNC|O_DSYNC/.test(lineOf(content, match).text)) return null;
      return tokenSwap(content, match, /(O_DIRECT)\b/, 'O_DIRECT | O_SYNC');
    },
  },

  // Insert the own-key guard at the top of an unguarded for-in merge.
  // needs-review, not safe: keys named __proto__/constructor/prototype STOP
  // being copied. That is the point of the fix, but a program that (bizarrely)
  // relied on copying them changes behaviour, so a human confirms.
  // Only Branch B (the recursive merge) is fixable — see protoGuardEdits.
  'VG-INJ-020': {
    title: 'Skip prototype keys in the merge loop',
    safety: 'needs-review',
    build: protoGuardEdits,
  },

  // Rename a near-miss import to the popular package it near-misses.
  // needs-review because it changes which module the program loads: the
  // suggestion is the detector's own near-neighbour, not proof of intent, and a
  // genuinely-internal package that happens to sit one edit away from a popular
  // name must not be silently rewritten.
  'VG-AISC-001': {
    title: 'Rename the import to the package it near-misses',
    safety: 'needs-review',
    build: renameHallucinatedImport,
  },
};

/** Build the fix for one finding, or null when this rule/match is not fixable. */
export function buildFix(
  ruleId: string,
  content: string,
  match: RuleMatch,
): { title: string; safety: Fixer['safety']; edits: FixEdit[] } | null {
  const fixer = fixers[ruleId];
  if (!fixer) return null;
  const edits = fixer.build(content, match);
  if (!edits || edits.length === 0) return null;
  return { title: fixer.title, safety: fixer.safety, edits };
}

/**
 * Apply edits to content. Bottom-up (edits sorted by start descending) so
 * earlier offsets stay valid. Returns null and applies NOTHING if any two edits
 * overlap — never a partial apply, which could corrupt the file.
 */
export function applyFixes(content: string, edits: FixEdit[]): string | null {
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  for (let i = 1; i < sorted.length; i++) {
    // sorted descending: the previous (higher) edit must start at or after this
    // edit's end, or they overlap.
    if (sorted[i]!.end > sorted[i - 1]!.start) return null;
  }
  let out = content;
  for (const e of sorted) {
    out = out.slice(0, e.start) + e.replacement + out.slice(e.end);
  }
  return out;
}
