// B1 — semantics-preserving evasion transforms (security paper, track B).
//
// The transform group `t` of the evasion/normalization duality argued in
// canonicalizer.ts: each entry here rewrites a source file so the PROGRAM is
// unchanged but its LEXICAL SURFACE is not, and the harness then asks whether
// the detector still agrees with itself — `D(t(x)) =? D(x)` — with the
// canonicalizer `N` on and off.
//
// This module is PURE. No fs, no clock, no randomness, no `Analyzer` import.
// Every `apply` is a deterministic function of its `ctx`, so re-running the
// generator on the same tree must reproduce byte-identical corpus files.
// Everything that reads or writes files lives in sec-b1-gen-corpus.mjs.
//
// THE TWO RULES THAT MATTER WHEN READING THIS FILE:
//
//   1. A transform that does not preserve semantics is not an evasion, it is a
//      broken file. `languages` is therefore narrow on purpose. PHP concatenates
//      with `.` and never `+` (`+` is numeric coercion); `'a' + 'b'` in Go and
//      C# is INTEGER ADDITION over rune/char literals, not concatenation; U+00A0
//      is a syntax error in Python, Go and Ruby. Each such exclusion is recorded
//      at its transform, with the reason, rather than being quietly widened.
//
//   2. `d2Predicted` is PRE-REGISTERED. It is a prediction made by reading
//      packages/analyzer-core/src/canonicalizer.ts — specifically the reasons
//      `foldConcatenations` refuses to fold (hasEscape / prefixed / unterminated
//      / delimiter outside `foldDelims` / run spanning a physical line /
//      mismatched delimiters / `isConcatGap` failing) and the fact that `N`
//      performs NO name resolution and NO escape decoding. Rewriting it after
//      seeing the measurement would turn the prediction ledger in
//      sec-b1-er-eval.mjs into a tautology, so it is not rewritten. Mismatches
//      are reported as mismatches.
//
// Contract with the generator:
//
//   apply(ctx) -> { content, lineMap, insertAt, insertCount, changedLines }
//              |  { rejected: '<reason>' }
//
//   ctx        = { content, lines, language, payloadLine, evidence, ruleId }
//   payloadLine  1-based, the line holding the first non-whitespace character of
//                the evidence (NOT startLine — see the pairing note in b3).
//   insertAt     0-based index into the ORIGINAL lines array before which lines
//                were inserted, or null when nothing was inserted above the
//                payload. Same convention as sec-b3-gen-corpus.mjs so
//                `expectedShift` works unchanged.
//   lineMap      Map(outputLine1based -> originalLine1based) for transforms whose
//                geometry is not pure insertion-above; null when insertAt /
//                insertCount describe the mapping completely.
//
// Gates are exported for the generator, which records every rejection with its
// reason rather than dropping it. All five return `{ ok, reason }`.

// ---------------------------------------------------------------------------
// Language profiles — a MIRROR of LANGUAGE_PROFILES in
// packages/analyzer-core/src/canonicalizer.ts (lines 172-191) restricted to the
// six languages the B1 population actually contains. It is duplicated rather
// than imported because that table is not exported; if the two ever disagree the
// prediction ledger silently degrades, so the values are quoted verbatim.
// ---------------------------------------------------------------------------
export const LANG_PROFILES = {
  javascript: { foldDelims: ['"', "'"], concatOp: '+', adjacencyConcat: false, blockComment: true, lineComment: '//' },
  typescript: { foldDelims: ['"', "'"], concatOp: '+', adjacencyConcat: false, blockComment: true, lineComment: '//' },
  python: { foldDelims: ['"', "'"], concatOp: '+', adjacencyConcat: true, blockComment: false, lineComment: '#' },
  ruby: { foldDelims: ['"', "'"], concatOp: '+', adjacencyConcat: true, blockComment: false, lineComment: '#' },
  // `.` only. `+` here would coerce both operands to numbers and change the
  // program — the single most tempting way to fabricate a bogus PHP result.
  php: { foldDelims: ['"', "'"], concatOp: '.', adjacencyConcat: false, blockComment: true, lineComment: '//' },
  // foldDelims omits `'` deliberately: `'a'` is a rune/char literal.
  go: { foldDelims: ['"'], concatOp: '+', adjacencyConcat: false, blockComment: true, lineComment: '//' },
  csharp: { foldDelims: ['"'], concatOp: '+', adjacencyConcat: false, blockComment: true, lineComment: '//' },
};

const ALL_LANGS = ['javascript', 'typescript', 'python', 'ruby', 'php', 'go', 'csharp'];

/** Statement templates. `decl` binds a fresh local; `ref` is how it is used. */
const DECL = {
  javascript: { decl: (n, v) => `const ${n} = ${v};`, ref: (n) => n },
  typescript: { decl: (n, v) => `const ${n} = ${v};`, ref: (n) => n },
  python: { decl: (n, v) => `${n} = ${v}`, ref: (n) => n },
  ruby: { decl: (n, v) => `${n} = ${v}`, ref: (n) => n },
  php: { decl: (n, v) => `$${n} = ${v};`, ref: (n) => `$${n}` },
  go: { decl: (n, v) => `${n} := ${v}`, ref: (n) => n },
  csharp: { decl: (n, v) => `var ${n} = ${v};`, ref: (n) => n },
};

/** Tautological wrapper. `reindent` is Python's block, which needs the payload
 *  moved right; every other language brackets the payload where it stands. */
const TAUTOLOGY = {
  javascript: { open: 'if (true) {', close: '}', reindent: 0 },
  typescript: { open: 'if (true) {', close: '}', reindent: 0 },
  php: { open: 'if (true) {', close: '}', reindent: 0 },
  csharp: { open: 'if (true) {', close: '}', reindent: 0 },
  go: { open: 'if true {', close: '}', reindent: 0 },
  python: { open: 'if True:', close: null, reindent: 4 },
  ruby: { open: 'if true', close: 'end', reindent: 0 },
};

// Reserved words that must not be rewritten as identifiers (L7) or mistaken for
// a callee (N3). Deliberately over-broad: a false positive here only costs a
// rejection, a false negative produces a file that does not compile.
const JS_RESERVED = new Set([
  'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'new',
  'class', 'this', 'typeof', 'instanceof', 'await', 'async', 'import', 'export',
  'from', 'default', 'true', 'false', 'null', 'undefined', 'try', 'catch', 'throw',
]);
const CALL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'foreach', 'elseif',
  'echo', 'print', 'require', 'require_once', 'include', 'and', 'or', 'not', 'in',
]);

const VG = '_vgB1';

// ---------------------------------------------------------------------------
// Lexing helpers. Single-line only: every transform here works within one
// physical line of the source, so a line-local scanner is sufficient and cannot
// be thrown off by an unterminated construct earlier in the file.
// ---------------------------------------------------------------------------

const indentOf = (line) => (line.match(/^[ \t]*/) || [''])[0];

/** The payload line's own terminator, so an INSERTED line does not turn a CRLF
 *  file into a mixed-ending one. The corpus is written under a `* -text`
 *  .gitattributes precisely so endings cannot move the result; matching them
 *  here keeps the emitted diff readable too. */
const eolOf = (line) => (line.endsWith('\r') ? '\r' : '');

/** True when the PRECEDING line is a decorator/attribute, in which case nothing
 *  may be inserted between the two — the annotation would no longer attach to
 *  the definition it annotates. `gateStatementPosition` only sees one line, so
 *  this neighbour check lives with the transforms that insert. */
function precededByAnnotation(lines, at) {
  for (let i = at - 1; i >= 0; i--) {
    const t = (lines[i] ?? '').trim();
    if (t === '') return false;
    return /^@[A-Za-z_]/.test(t) || /^#\[/.test(t) || /^\[[A-Za-z_][\w.]*[\s(\]]/.test(t);
  }
  return false;
}

/** True when the line carries nothing but a comment. Such a line is not a
 *  statement, so it cannot be the body of a wrapper: `if True:` above a bare
 *  `# TODO` yields an empty block and an IndentationError. */
function isCommentOnly(line, profile) {
  const t = line.trim();
  if (t === '') return true;
  if (profile.lineComment && t.startsWith(profile.lineComment)) return true;
  if (profile.blockComment && t.startsWith('/*')) return true;
  if (profile.lineComment === '//' && t.startsWith('#')) return true; // PHP's `#`
  return false;
}

/**
 * String literals in code position on a single line, with the same three
 * disqualifiers `canonicalize` records (`hasEscape`, `prefixed`, `unterminated`)
 * so a caller can reason about whether `N` would fold what it produces.
 *
 * Text after an unquoted line-comment prefix is not scanned: a `"` inside a
 * trailing comment is not a literal, and splitting it would rewrite a comment
 * while claiming to rewrite code.
 */
export function scanLineLiterals(line, profile) {
  const out = [];
  const delims = ['"', "'"];
  let i = 0;
  while (i < line.length) {
    if (profile.lineComment && line.startsWith(profile.lineComment, i)) break;
    if (profile.blockComment && line.startsWith('/*', i)) {
      const close = line.indexOf('*/', i + 2);
      if (close === -1) break;
      i = close + 2;
      continue;
    }
    const ch = line[i];
    if (!delims.includes(ch)) { i += 1; continue; }
    // A python/ruby triple quote is not a single-line literal this module will
    // touch: `N` skips triple-quoted regions wholesale, and splitting one is a
    // different (B3) problem.
    if (line.startsWith(ch.repeat(3), i)) {
      out.push({ tripleQuoted: true, start: i, end: i + 3, delim: ch, inner: '', hasEscape: false, prefixed: false, unterminated: true });
      i += 3;
      continue;
    }
    let k = i + 1;
    let hasEscape = false;
    let closed = false;
    while (k < line.length) {
      if (line[k] === '\\') { hasEscape = true; k += 2; continue; }
      if (line[k] === ch) { closed = true; break; }
      k += 1;
    }
    const end = closed ? k + 1 : line.length;
    out.push({
      tripleQuoted: false,
      start: i,
      end,
      delim: ch,
      inner: line.slice(i + 1, closed ? k : end),
      hasEscape,
      // `f"…"`, `r"…"`, `b"…"` — the prefix changes the literal's meaning, and
      // `N` refuses to fold a prefixed literal for the same reason.
      prefixed: /[A-Za-z0-9_$]/.test(line[i - 1] ?? ''),
      unterminated: !closed,
    });
    i = end;
  }
  return out;
}

/** True when `idx` (an offset into `line`) sits inside one of `lits`. */
const insideLiteral = (lits, idx) => lits.some((l) => idx >= l.start && idx < l.end);

/**
 * Comment spans on a single physical line, as `{ start, end }` offset pairs. The
 * string regions are jumped over using the SAME literal spans `scanLineLiterals`
 * produced, so a `//` or `/*` sitting inside a string is data here exactly as it
 * is there — the two scanners cannot drift apart. A line comment runs to the end
 * of the line; a block comment with no closer on this line does too. The only
 * caller is `renameOnLine`, which needs to leave a token that appears in a
 * comment untouched instead of rewriting a comment while claiming to rewrite
 * code — the same discipline `scanLineLiterals` already enforces for strings.
 */
function scanLineComments(line, profile, lits) {
  const out = [];
  let i = 0;
  while (i < line.length) {
    const lit = lits.find((l) => i >= l.start && i < l.end);
    if (lit) { i = lit.end; continue; }
    if (profile.lineComment && line.startsWith(profile.lineComment, i)) {
      out.push({ start: i, end: line.length });
      break;
    }
    if (profile.blockComment && line.startsWith('/*', i)) {
      const close = line.indexOf('*/', i + 2);
      const end = close === -1 ? line.length : close + 2;
      out.push({ start: i, end });
      i = end;
      continue;
    }
    i += 1;
  }
  return out;
}

/** Deterministic split point: the middle, biased left. */
const midpoint = (s) => Math.floor(s.length / 2);

const hexEscape = (s) =>
  [...s].map((c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`).join('');

/** Reject helper — a rejection is data, never a thrown error. */
const reject = (reason) => ({ rejected: reason });

// ---------------------------------------------------------------------------
// Gates (exported; the generator records every rejection with its reason)
// ---------------------------------------------------------------------------

/**
 * G1 — is this literal safe to CUT AT `lit.splitAt`?
 *
 * Rejects the cases where a split changes meaning rather than spelling:
 * prefixed literals (`f"…"` interpolates, `r"…"` disables escapes, `b"…"` is
 * bytes — none of which survive being halved), triple-quoted and unterminated
 * literals, regex literals, a cut landing inside a backslash escape, and a cut
 * landing inside a format placeholder (`%s`, `{name}`, `${…}`), which would
 * split a token the runtime reads as one unit.
 */
export function gateLiteral(lit, profile) {
  if (!lit) return { ok: false, reason: 'no string literal on the payload line' };
  if (lit.tripleQuoted) return { ok: false, reason: 'triple-quoted literal: N skips these regions wholesale' };
  if (lit.unterminated) return { ok: false, reason: 'unterminated literal on this line' };
  if (lit.prefixed) return { ok: false, reason: 'prefixed literal (f/r/b/u or glued to an identifier): the prefix changes interpretation' };
  if (lit.isRegex) return { ok: false, reason: 'regex literal, not a string literal' };
  if (!profile) return { ok: false, reason: 'no language profile' };
  const at = lit.splitAt;
  if (at == null) return { ok: false, reason: 'no split point computed' };
  if (at <= 0 || at >= lit.inner.length) return { ok: false, reason: `literal too short to split (inner length ${lit.inner.length})` };
  // Count backslashes immediately before the cut: an odd run means the cut is
  // inside an escape sequence and each half would be malformed.
  let back = 0;
  for (let i = at - 1; i >= 0 && lit.inner[i] === '\\'; i--) back += 1;
  if (back % 2 === 1) return { ok: false, reason: 'split point lands inside a backslash escape' };
  if (lit.inner[at - 1] === '%') return { ok: false, reason: 'split point lands inside a %-placeholder' };
  const before = lit.inner.slice(0, at);
  const openBrace = Math.max(before.lastIndexOf('{'), before.lastIndexOf('${'));
  if (openBrace !== -1 && before.indexOf('}', openBrace) === -1 && lit.inner.indexOf('}', at) !== -1) {
    return { ok: false, reason: 'split point lands inside a {…} placeholder' };
  }
  return { ok: true, reason: null };
}

/**
 * G2 — is `delim` a STRING delimiter in `lang`, and what operator joins two of
 * them?
 *
 * The two non-negotiable cases, both taken from canonicalizer.ts:
 *   * php concatenates with `.`; `+` would coerce to numbers.
 *   * go/csharp fold only `"`. `'a' + 'b'` there is 97 + 98 = 195, so splitting
 *     a single-quoted literal fabricates arithmetic, not a string.
 */
export function gateOperator(lang, delim) {
  const profile = LANG_PROFILES[lang];
  if (!profile) return { ok: false, reason: `no concatenation model for language ${lang}`, op: null };
  if (!profile.foldDelims.includes(delim)) {
    return {
      ok: false,
      op: null,
      reason:
        lang === 'go' || lang === 'csharp'
          ? `${delim} is a char/rune literal delimiter in ${lang}; '+' over it is integer addition, not concatenation`
          : `${delim} is not a string delimiter in ${lang}`,
    };
  }
  return { ok: true, reason: null, op: profile.concatOp };
}

/**
 * G3 — may a STATEMENT be inserted immediately above this line?
 *
 * b3 shipped three JavaScript files that failed `node --check` because a
 * declaration was injected in object-literal position (`{ apiKey: "…" }`), where
 * `const … ;` is a SyntaxError. A file that does not parse cannot demonstrate
 * evasion, so the shape is rejected up front. Conservative by design: the checks
 * below are line-local and will refuse some positions that would in fact be
 * legal.
 */
export function gateStatementPosition(line) {
  const t = line.trim();
  if (t === '') return { ok: false, reason: 'blank line' };
  if (/^(?:[A-Za-z_$][\w$]*|["'][^"']*["'])\s*:/.test(t) && !/^(?:default|case)\b/.test(t)) {
    return { ok: false, reason: 'object-literal / map-entry position: a statement is not valid here' };
  }
  // A decorator/attribute must stay adjacent to the definition it annotates, so
  // it can be neither wrapped nor split off from it. Measured: hoisting out of
  // `@app.route("/x")` and wrapping `@csrf_exempt` both produced Python files
  // that do not compile.
  if (/^@[A-Za-z_]/.test(t) || /^#\[/.test(t) || /^\[[A-Za-z_][\w.]*[\s(\]]/.test(t)) {
    return { ok: false, reason: 'decorator/attribute line: it must remain adjacent to the definition it annotates' };
  }
  if (/[,+.\-*/&|=([{]$/.test(t)) return { ok: false, reason: 'line is a continuation (ends mid-expression)' };
  if (/^[)\]}]/.test(t)) return { ok: false, reason: 'line closes an enclosing construct' };
  let depth = 0;
  const lits = scanLineLiterals(line, LANG_PROFILES.javascript);
  for (let i = 0; i < line.length; i++) {
    if (insideLiteral(lits, i)) continue;
    if ('([{'.includes(line[i])) depth += 1;
    else if (')]}'.includes(line[i])) depth -= 1;
  }
  if (depth !== 0) return { ok: false, reason: `unbalanced brackets on the line (net ${depth}): not a statement boundary` };
  return { ok: true, reason: null };
}

/**
 * G4 — may a Python/Ruby block wrapper be opened above this line?
 *
 * Indentation is syntax there, so a wrapper is only safe when the payload is a
 * single self-contained line whose indent we can read unambiguously. A tab/space
 * mixture, a block opener (`:` / `do`), or a payload that is itself continued
 * onto the next line all make the re-indent a guess.
 */
export function gateIndent(lines, at, lang) {
  if (lang !== 'python' && lang !== 'ruby') return { ok: true, reason: null };
  const line = lines[at];
  if (line == null) return { ok: false, reason: 'payload line out of range' };
  const pad = indentOf(line);
  if (pad.includes(' ') && pad.includes('\t')) return { ok: false, reason: 'mixed tab/space indentation: re-indent would be a guess' };
  const t = line.trim();
  if (t === '') return { ok: false, reason: 'blank payload line' };
  if (t.endsWith(':') || /\bdo\b\s*(\|[^|]*\|)?$/.test(t)) return { ok: false, reason: 'payload opens a block; wrapping it would capture the body' };
  if (t.endsWith('\\')) return { ok: false, reason: 'payload continues onto the next line' };
  const next = lines[at + 1];
  if (next != null && next.trim() !== '' && indentOf(next).length > pad.length) {
    return { ok: false, reason: 'following line is more deeply indented: payload is not a single statement' };
  }
  return { ok: true, reason: null };
}

/**
 * G5 — may an argument be hoisted out of this line into a temporary?
 *
 * Hoisting reorders evaluation. With one call and no short-circuit that
 * reordering is unobservable; with two calls, or with `&&` / `||` / `?.`, the
 * hoisted expression may now run when it previously would not have, which is a
 * change in program behaviour rather than in spelling.
 */
export function gateSideEffects(line) {
  if (/&&|\|\||\?\./.test(line)) return { ok: false, reason: 'short-circuit operator on the line: hoisting changes evaluation order' };
  const lits = scanLineLiterals(line, LANG_PROFILES.javascript);
  let calls = 0;
  const re = /[A-Za-z_$][\w$]*\s*\(/g;
  let m;
  while ((m = re.exec(line)) !== null) {
    const name = m[0].replace(/\s*\($/, '');
    if (CALL_KEYWORDS.has(name)) continue;
    if (insideLiteral(lits, m.index)) continue;
    calls += 1;
  }
  if (calls >= 2) return { ok: false, reason: `${calls} calls on the line: hoisting may reorder side effects` };
  return { ok: true, reason: null };
}

// ---------------------------------------------------------------------------
// Result construction
// ---------------------------------------------------------------------------

/**
 * Which output lines differ from the source they map to. Derived from the line
 * mapping rather than declared per transform, so an inserted line and an edited
 * line cannot be mislabelled by hand.
 */
function computeChangedLines(origLines, outLines, lineMap, insertAt, insertCount) {
  const changed = [];
  for (let i = 0; i < outLines.length; i++) {
    let src;
    if (lineMap) {
      const mapped = lineMap.get(i + 1);
      src = mapped == null ? null : mapped - 1;
    } else if (insertAt == null || insertCount === 0) {
      src = i;
    } else if (i < insertAt) src = i;
    else if (i < insertAt + insertCount) src = null;
    else src = i - insertCount;
    if (src == null || origLines[src] !== outLines[i]) changed.push(i + 1);
  }
  return changed;
}

function result(ctx, outLines, { lineMap = null, insertAt = null, insertCount = 0 } = {}) {
  return {
    content: outLines.join('\n'),
    lineMap,
    insertAt,
    insertCount,
    changedLines: computeChangedLines(ctx.lines, outLines, lineMap, insertAt, insertCount),
  };
}

/** Replace exactly one line, no geometry change. */
function replaceLine(ctx, at, text) {
  const out = ctx.lines.slice();
  out[at] = text;
  return result(ctx, out);
}

/** Insert `newLines` before index `at`, geometry described arithmetically. */
function insertAbove(ctx, at, newLines) {
  const out = [...ctx.lines.slice(0, at), ...newLines, ...ctx.lines.slice(at)];
  return result(ctx, out, { insertAt: at, insertCount: newLines.length });
}

// ---------------------------------------------------------------------------
// Shared payload-line analysis
// ---------------------------------------------------------------------------

/** The payload line plus its profile, or a rejection. */
function payloadContext(ctx) {
  const profile = LANG_PROFILES[ctx.language];
  if (!profile) return { err: `no profile for language ${ctx.language}` };
  const at = ctx.payloadLine - 1;
  const line = ctx.lines[at];
  if (line == null) return { err: `payloadLine ${ctx.payloadLine} out of range (${ctx.lines.length} lines)` };
  return { profile, at, line, lits: scanLineLiterals(line, profile) };
}

/**
 * The first literal on the payload line that can be split under G1+G2, with the
 * split point already chosen. `want` narrows the candidate set: 'plain' demands
 * an escape-free literal (so `N` would fold what we emit), 'escaped' demands the
 * opposite is achievable, 'double' demands `"` (escape processing).
 */
function pickSplittable(ctx, pc, want = 'plain') {
  const reasons = [];
  for (const lit of pc.lits) {
    const op = gateOperator(ctx.language, lit.delim);
    if (!op.ok) { reasons.push(op.reason); continue; }
    if (want === 'double' && lit.delim !== '"') {
      reasons.push(`literal uses ${lit.delim}; escape processing requires "`);
      continue;
    }
    if (want === 'plain' && lit.hasEscape) {
      reasons.push('literal contains an escape: N refuses to fold it, so it belongs to L4 not here');
      continue;
    }
    const candidate = { ...lit, splitAt: midpoint(lit.inner) };
    const g1 = gateLiteral(candidate, pc.profile);
    if (!g1.ok) { reasons.push(g1.reason); continue; }
    return { lit: candidate, op: op.op };
  }
  return { err: reasons.length ? reasons.join('; ') : 'no string literal on the payload line' };
}

/** Splice a replacement for `[lit.start, lit.end)` into `line`. */
const spliceLit = (line, lit, text) => line.slice(0, lit.start) + text + line.slice(lit.end);

// ---------------------------------------------------------------------------
// Transform implementations
// ---------------------------------------------------------------------------

// L1 — split one constant literal into two joined by the language's real
// concatenation operator, on one physical line.
function applyConstConcatSplit(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const p = pickSplittable(ctx, pc, 'plain');
  if (p.err) return reject(p.err);
  const { lit, op } = p;
  const d = lit.delim;
  const a = lit.inner.slice(0, lit.splitAt);
  const b = lit.inner.slice(lit.splitAt);
  return replaceLine(ctx, pc.at, spliceLit(pc.line, lit, `${d}${a}${d} ${op} ${d}${b}${d}`));
}

// L2 — adjacency concatenation, which needs no operator at all. Python and Ruby
// only: `"ev" "al"` is one literal there and a syntax error elsewhere.
function applyAdjacentConcat(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  if (!pc.profile.adjacencyConcat) return reject(`${ctx.language} has no adjacency concatenation`);
  const p = pickSplittable(ctx, pc, 'plain');
  if (p.err) return reject(p.err);
  const { lit } = p;
  const d = lit.delim;
  const a = lit.inner.slice(0, lit.splitAt);
  const b = lit.inner.slice(lit.splitAt);
  return replaceLine(ctx, pc.at, spliceLit(pc.line, lit, `${d}${a}${d} ${d}${b}${d}`));
}

// L3 — the same split, but with the operands on two physical lines. This is the
// canonical RESIDUAL: `foldConcatenations` breaks a run at `next.line !==
// prev.line` and refuses any span containing `\n` or `\r`, because a multi-line
// run has no single span to pad the folded literal into without moving offsets.
function applyMultilineConcat(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const p = pickSplittable(ctx, pc, 'plain');
  if (p.err) return reject(p.err);
  const { lit, op } = p;
  const d = lit.delim;
  const head = pc.line.slice(0, lit.start) + `${d}${lit.inner.slice(0, lit.splitAt)}${d} ${op}`;
  const tail = indentOf(pc.line) + '    ' + `${d}${lit.inner.slice(lit.splitAt)}${d}` + pc.line.slice(lit.end);
  const out = [...ctx.lines.slice(0, pc.at), head, tail, ...ctx.lines.slice(pc.at + 1)];
  // The continuation is inserted BELOW the payload, so nothing above it moves
  // and the payload keeps its line number: insertAt is the index after it.
  return result(ctx, out, { insertAt: pc.at + 1, insertCount: 1 });
}

// L4 — split so that one half CONTAINS AN ESCAPE. `\x4b` and `K` are the same
// character to the runtime, but `hasEscape` is one of the fold refusals, so the
// run stays unfolded even though it is on a single line. This is what separates
// "N did not see it" from "N saw it and declined".
//
// C# is excluded, for the same reason L6 excludes it: `\x` there is VARIABLE
// LENGTH (one to four hex digits), so the `"\x6d" + "…"` this emits merges with a
// following hex digit — `"\x6dd5"` is the single character U+6DD5, not `m` then
// `d5`, and the file stops being the same string. JS, Go and Python take exactly
// two digits; Ruby and PHP at most two.
function applyEscapedSplit(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const p = pickSplittable(ctx, pc, 'double');
  if (p.err) return reject(p.err);
  const { lit, op } = p;
  const b = lit.inner.slice(lit.splitAt);
  const first = b[0];
  if (first == null || first.charCodeAt(0) > 0x7e || first.charCodeAt(0) < 0x20 || first === '\\') {
    return reject('second half does not start with a plain ASCII character that can be hex-escaped');
  }
  const a = lit.inner.slice(0, lit.splitAt);
  const escaped = hexEscape(first) + b.slice(1);
  return replaceLine(ctx, pc.at, spliceLit(pc.line, lit, `"${a}" ${op} "${escaped}"`));
}

// L5 — a block comment BETWEEN the operands. `stripBlankableGap` removes comment
// text from the gap before `isConcatGap` reads it, so this is expected to fold:
// the transform exists to confirm that path is really wired, not to defeat it.
function applyOperatorBlockComment(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  if (!pc.profile.blockComment) return reject(`${ctx.language} has no /* */ block comment`);
  const p = pickSplittable(ctx, pc, 'plain');
  if (p.err) return reject(p.err);
  const { lit, op } = p;
  const d = lit.delim;
  const a = lit.inner.slice(0, lit.splitAt);
  const b = lit.inner.slice(lit.splitAt);
  return replaceLine(ctx, pc.at, spliceLit(pc.line, lit, `${d}${a}${d} /* b1 */ ${op} ${d}${b}${d}`));
}

// L6 — the literal is not split at all, it is RE-SPELLED as hex escapes. `N`
// performs no escape decoding whatsoever, so there is nothing here for it to
// collapse; the only defence would be constant evaluation, which is exactly the
// Rice-theorem wall canonicalizer.ts declines to walk into.
//
// C# is excluded: its `\x` escape takes ONE TO FOUR hex digits, so `"\x6d\x64"`
// is unambiguous but `"\x6d64"` would merge into a single character. Rather than
// reason about which neighbours are safe, the language is left out. JS, Go and
// Python take exactly two digits; Ruby and PHP take at most two.
function applyHexEncode(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  for (const lit of pc.lits) {
    if (lit.delim !== '"' || lit.hasEscape || lit.prefixed || lit.unterminated || lit.tripleQuoted) continue;
    if (lit.inner.length < 2) continue;
    if (!/^[\x20-\x7e]+$/.test(lit.inner) || lit.inner.includes('"')) continue;
    return replaceLine(ctx, pc.at, spliceLit(pc.line, lit, `"${hexEscape(lit.inner)}"`));
  }
  return reject('no escape-free double-quoted ASCII literal on the payload line');
}

// L7 — a JavaScript identifier respelled with a `\uXXXX` escape. The escape is
// resolved by the LEXER, so `crypto` and `crypto` are the same binding and
// every other reference in the file still resolves. JavaScript only: no other
// language in this population admits unicode escapes in identifiers.
function applyIdentifierUnicodeEscape(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const re = /[A-Za-z_$][\w$]*/g;
  let best = null;
  let m;
  while ((m = re.exec(pc.line)) !== null) {
    if (insideLiteral(pc.lits, m.index)) continue;
    if (JS_RESERVED.has(m[0])) continue;
    if (m[0].length < 2) continue;
    if (!/^[A-Za-z_$]/.test(m[0])) continue;
    if (best === null || m[0].length > best[0].length) best = m;
  }
  if (!best) return reject('no eligible identifier in code position on the payload line');
  const name = best[0];
  const idx = 1; // never the first character: keeps the token unambiguous
  const escaped = name.slice(0, idx) + `\\u${name.charCodeAt(idx).toString(16).padStart(4, '0')}` + name.slice(idx + 1);
  const out = pc.line.slice(0, best.index) + escaped + pc.line.slice(best.index + name.length);
  return replaceLine(ctx, pc.at, out);
}

// L8 — replace an interior space with U+00A0.
//
// Language set is narrow ON PURPOSE. U+00A0 is `WhiteSpace` in the ECMAScript
// grammar and a Unicode-Zs whitespace character in C#, so it is legal there.
// It is NOT whitespace in Python, Go, Ruby or PHP — those grammars enumerate
// space/tab/CR/LF — and inserting one is a syntax error, which would produce a
// file that fails to parse and a fake "evasion".
//
// Leading indentation is excluded as well: even where the character is legal,
// rewriting indentation is a separate (and in Python, fatal) change.
function applyExoticWhitespace(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const pad = indentOf(pc.line).length;
  for (let i = pad; i < pc.line.length; i++) {
    if (pc.line[i] !== ' ') continue;
    if (insideLiteral(pc.lits, i)) continue; // a space inside a literal is DATA
    return replaceLine(ctx, pc.at, pc.line.slice(0, i) + '\u00a0' + pc.line.slice(i + 1));
  }
  return reject('no interior code-position space on the payload line');
}

// L9 — a LINE comment inserted between the operands of a split concatenation.
// A line comment cannot sit inside one physical line, so this necessarily
// produces a multi-line run: `N` blanks the comment (leaving spaces, since it is
// length preserving) and is then left with exactly the L3 shape it already
// refuses. Predicted residual for that reason, not because comment removal fails.
function applyLineCommentInsert(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  if (!pc.profile.lineComment) return reject(`no line-comment syntax for ${ctx.language}`);
  const p = pickSplittable(ctx, pc, 'plain');
  if (p.err) return reject(p.err);
  const { lit, op } = p;
  const d = lit.delim;
  const head =
    pc.line.slice(0, lit.start) +
    `${d}${lit.inner.slice(0, lit.splitAt)}${d} ${op} ${pc.profile.lineComment} b1`;
  const tail = indentOf(pc.line) + '    ' + `${d}${lit.inner.slice(lit.splitAt)}${d}` + pc.line.slice(lit.end);
  const out = [...ctx.lines.slice(0, pc.at), head, tail, ...ctx.lines.slice(pc.at + 1)];
  return result(ctx, out, { insertAt: pc.at + 1, insertCount: 1 });
}

/** The `mod.` receiver a rule's pattern is anchored on, if the payload line has
 *  one in code position. Returns the bare module/receiver token. */
function leadingReceiver(pc) {
  const re = /\b([A-Za-z_][\w]*)\s*(\.|::)\s*[A-Za-z_]/g;
  let m;
  while ((m = re.exec(pc.line)) !== null) {
    if (insideLiteral(pc.lits, m.index)) continue;
    if (JS_RESERVED.has(m[1]) || CALL_KEYWORDS.has(m[1])) continue;
    return { name: m[1], sep: m[2], index: m.index };
  }
  return null;
}

/** The import/require line that binds `name`, and a rewrite of it that binds an
 *  alias instead. Only single-binding forms are handled; anything else is
 *  rejected rather than guessed at. */
function aliasImport(ctx, name, alias) {
  for (let i = 0; i < ctx.lines.length; i++) {
    const line = ctx.lines[i];
    if (ctx.language === 'python') {
      if (new RegExp(`^\\s*import\\s+${name}\\s*$`).test(line)) {
        return { at: i, text: line.replace(/\s*$/, '') + ` as ${alias}` };
      }
    } else if (ctx.language === 'go') {
      // Inside an import block, `alias "path"` is the aliased form.
      const m = line.match(/^(\s*)"([^"]*\/)?([A-Za-z_]\w*)"\s*$/);
      if (m && m[3] === name) return { at: i, text: `${m[1]}${alias} "${m[2] ?? ''}${m[3]}"` };
    } else {
      const req = new RegExp(`^(\\s*)(?:const|let|var)\\s+${name}\\s*=\\s*require\\(`);
      if (req.test(line)) return { at: i, text: line.replace(new RegExp(`(const|let|var)\\s+${name}\\b`), `$1 ${alias}`) };
      const imp = new RegExp(`^(\\s*)import\\s+${name}\\s+from\\b`);
      if (imp.test(line)) return { at: i, text: line.replace(new RegExp(`import\\s+${name}\\b`), `import ${alias}`) };
    }
  }
  return null;
}

/** Rewrite every code-position occurrence of the bare token `name` on one line,
 *  skipping BOTH string literals and comments. A receiver mentioned in a trailing
 *  line comment, or inside a block comment, is documentation: rewriting it desyncs
 *  the comment from the code while changing nothing that runs. `profile` is what
 *  locates the comment; without it, only strings are skipped. */
function renameOnLine(line, lits, name, replacement, profile) {
  const comments = profile ? scanLineComments(line, profile, lits) : [];
  const inComment = (idx) => comments.some((c) => idx >= c.start && idx < c.end);
  const re = new RegExp(`\\b${name}\\b`, 'g');
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(line)) !== null) {
    if (insideLiteral(lits, m.index) || inComment(m.index)) continue;
    out += line.slice(last, m.index) + replacement;
    last = m.index + name.length;
  }
  return out + line.slice(last);
}

// N1 — rename the IMPORT BINDING. `N` performs no name resolution at all: it is
// three lexical operations over one file, and knowing that `h.md5` is
// `hashlib.md5` requires a symbol table. Predicted residual with high confidence.
function applyImportAlias(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const recv = leadingReceiver(pc);
  if (!recv) return reject('no dotted receiver in code position on the payload line');
  const alias = `${VG}_${recv.name}`;
  const imp = aliasImport(ctx, recv.name, alias);
  if (!imp) return reject(`no single-binding import/require of \`${recv.name}\` found (aliasing a destructured or grouped import is not modelled)`);
  // Renaming the binding at the import site orphans EVERY other reference to the
  // old name, not only the one on the payload line: `N` holds no symbol table, so
  // a reference left behind is a runtime NameError, not a spelling difference.
  // Rewrite all code-position occurrences across the file (strings and comments
  // are left verbatim); the import line keeps the aliased form `aliasImport` built.
  const out = ctx.lines.slice();
  for (let i = 0; i < out.length; i++) {
    if (i === imp.at) { out[i] = imp.text; continue; }
    const lits = scanLineLiterals(out[i], pc.profile);
    out[i] = renameOnLine(out[i], lits, recv.name, alias, pc.profile);
  }
  return result(ctx, out);
}

// N2 — bind the receiver to a fresh local immediately above the payload and call
// through that. The binding holds the same object reference, so the method still
// receives the same `this`/`self`. Go is excluded (a package is not a value);
// PHP and C# are excluded (no package/module object to rebind).
function applyLocalAlias(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const g3 = gateStatementPosition(pc.line);
  if (!g3.ok) return reject(`G3: ${g3.reason}`);
  if (precededByAnnotation(ctx.lines, pc.at)) return reject('preceding line is a decorator/attribute: nothing may be inserted between it and this line');
  const g4 = gateIndent(ctx.lines, pc.at, ctx.language);
  if (!g4.ok) return reject(`G4: ${g4.reason}`);
  const recv = leadingReceiver(pc);
  if (!recv) return reject('no dotted receiver in code position on the payload line');
  const decl = DECL[ctx.language];
  if (!decl) return reject(`no declaration form for ${ctx.language}`);
  // The full receiver path, so `Digest::MD5.hexdigest` aliases the class and not
  // just its namespace.
  const path = pc.line.slice(recv.index).match(/^[A-Za-z_][\w]*(?:::[A-Za-z_]\w*)*/)[0];
  const alias = `${VG}Recv`;
  const pad = indentOf(pc.line);
  const rewritten =
    pc.line.slice(0, recv.index) + decl.ref(alias) + pc.line.slice(recv.index + path.length);
  const out = [...ctx.lines.slice(0, pc.at), pad + decl.decl(alias, path) + eolOf(pc.line), ...ctx.lines.slice(pc.at)];
  out[pc.at + 1] = rewritten;
  return result(ctx, out, { insertAt: pc.at, insertCount: 1 });
}

/** N3 member/function-name rewriting, shared by both variants. `splitName`
 *  decides whether the name is emitted as one literal or as a constant
 *  concatenation the canonicalizer could fold. */
function applyDynamicAttr(ctx, splitName) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const lang = ctx.language;
  const op = LANG_PROFILES[lang].concatOp;
  /** `"md5"` or `"m" + "d5"`, per variant. */
  const nameExpr = (name) => {
    if (!splitName || name.length < 2) return `"${name}"`;
    const k = midpoint(name);
    return `"${name.slice(0, k)}" ${op} "${name.slice(k)}"`;
  };

  if (lang === 'javascript' || lang === 'typescript') {
    const re = /\.([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = re.exec(pc.line)) !== null) {
      if (insideLiteral(pc.lits, m.index)) continue;
      const out = pc.line.slice(0, m.index) + `[${nameExpr(m[1])}](` + pc.line.slice(m.index + m[0].length);
      return replaceLine(ctx, pc.at, out);
    }
    return reject('no method call in code position on the payload line');
  }

  if (lang === 'python') {
    const re = /\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(/g;
    let m;
    while ((m = re.exec(pc.line)) !== null) {
      if (insideLiteral(pc.lits, m.index)) continue;
      if (CALL_KEYWORDS.has(m[1])) continue;
      const out =
        pc.line.slice(0, m.index) + `getattr(${m[1]}, ${nameExpr(m[2])})(` + pc.line.slice(m.index + m[0].length);
      return replaceLine(ctx, pc.at, out);
    }
    return reject('no attribute call in code position on the payload line');
  }

  if (lang === 'ruby') {
    // `send` needs the argument list to be non-empty: `.send(:x, )` is a syntax
    // error, so a zero-argument call is rejected rather than emitted broken.
    const re = /\.([a-z_]\w*[!?]?)\(([^()]*)\)/g;
    let m;
    while ((m = re.exec(pc.line)) !== null) {
      if (insideLiteral(pc.lits, m.index)) continue;
      if (m[2].trim() === '') continue;
      const sym = splitName && m[1].length >= 2
        ? `(${nameExpr(m[1])}).to_sym`
        : `:${m[1]}`;
      const out =
        pc.line.slice(0, m.index) + `.send(${sym}, ${m[2]})` + pc.line.slice(m.index + m[0].length);
      return replaceLine(ctx, pc.at, out);
    }
    return reject('no method call with arguments in code position on the payload line');
  }

  if (lang === 'php') {
    // Variable functions need somewhere to put the binding, so this variant is
    // statement-position only.
    const g3 = gateStatementPosition(pc.line);
    if (!g3.ok) return reject(`G3: ${g3.reason}`);
    if (precededByAnnotation(ctx.lines, pc.at)) return reject('preceding line is a decorator/attribute: nothing may be inserted between it and this line');
    const re = /(^|[^\w$>])([a-z_]\w*)\s*\(/g;
    let m;
    while ((m = re.exec(pc.line)) !== null) {
      const at = m.index + m[1].length;
      if (insideLiteral(pc.lits, at)) continue;
      if (CALL_KEYWORDS.has(m[2])) continue;
      const alias = `${VG}Fn`;
      const pad = indentOf(pc.line);
      const decl = `${pad}$${alias} = ${nameExpr(m[2]).replace(/"/g, "'")};${eolOf(pc.line)}`;
      const rewritten = pc.line.slice(0, at) + `$${alias}(` + pc.line.slice(m.index + m[0].length);
      const out = [...ctx.lines.slice(0, pc.at), decl, ...ctx.lines.slice(pc.at)];
      out[pc.at + 1] = rewritten;
      return result(ctx, out, { insertAt: pc.at, insertCount: 1 });
    }
    return reject('no bare function call in code position on the payload line');
  }

  // Go and C# have no dynamic member access that stays a one-line, dependency
  // free rewrite: Go would need `reflect` plus an import edit, C# `dynamic` plus
  // a package reference. Both would change the program, not its spelling.
  return reject(`${lang} has no dependency-free dynamic member access; a reflect/dynamic rewrite would change the program`);
}

// S1 — hoist a constant argument into a temporary. Nothing about the value
// changes; the rule's pattern simply no longer sees the callee and the literal
// adjacent to each other. `N` has no dataflow, so it cannot put them back.
function applyArgHoist(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const g3 = gateStatementPosition(pc.line);
  if (!g3.ok) return reject(`G3: ${g3.reason}`);
  if (precededByAnnotation(ctx.lines, pc.at)) return reject('preceding line is a decorator/attribute: nothing may be inserted between it and this line');
  const g4 = gateIndent(ctx.lines, pc.at, ctx.language);
  if (!g4.ok) return reject(`G4: ${g4.reason}`);
  const g5 = gateSideEffects(pc.line);
  if (!g5.ok) return reject(`G5: ${g5.reason}`);
  const decl = DECL[ctx.language];
  if (!decl) return reject(`no declaration form for ${ctx.language}`);
  // Only a literal in ARGUMENT position: preceded by `(` or `,`.
  const arg = pc.lits.find((l) => {
    if (l.tripleQuoted || l.unterminated || l.prefixed) return false;
    const before = pc.line.slice(0, l.start).trimEnd();
    if (!(before.endsWith('(') || before.endsWith(','))) return false;
    // In JS/TS a string FOLLOWED by `:` is an object-literal KEY (`{ a: 1, "b": 2 }`),
    // not a value. Hoisting it would emit `{ a: 1, _vgB1Arg: 2 }`, renaming the
    // property to the temporary's identifier instead of moving a value — the object
    // changes shape. A call argument is never followed by `:` in these languages, so
    // this excludes keys only. (Python dict keys ARE evaluated expressions, `{x: 2}`,
    // so they hoist correctly and stay eligible.)
    if (ctx.language === 'javascript' || ctx.language === 'typescript') {
      if (pc.line.slice(l.end).trimStart().startsWith(':')) return false;
    }
    return true;
  });
  if (!arg) return reject('no plain string literal in argument position on the payload line');
  const alias = `${VG}Arg`;
  const pad = indentOf(pc.line);
  const rewritten = spliceLit(pc.line, arg, decl.ref(alias));
  const out = [
    ...ctx.lines.slice(0, pc.at),
    pad + decl.decl(alias, pc.line.slice(arg.start, arg.end)) + eolOf(pc.line),
    ...ctx.lines.slice(pc.at),
  ];
  out[pc.at + 1] = rewritten;
  return result(ctx, out, { insertAt: pc.at, insertCount: 1 });
}

// S2 — wrap the payload in an always-true branch.
//
// Rejected for DECLARATIONS, and that rejection is load-bearing: `if (true) {
// const X = "…" }` makes `X` block-scoped, so every later reference to it breaks
// and the file stops being the same program. Same hazard in Go, where a `:=`
// inside the block leaves the outer use undefined.
//
// A sharper failure hides in the same family: `export` (and `import`) are legal
// ONLY at module top level, so `if (true) { export const X = … }` is not merely
// mis-scoped, it is a SyntaxError. Three tautology-wrap files shipped exactly
// that and passed a bare `node --check` (CommonJS goal) while failing
// `node --input-type=module --check` — which is why `export` must be in the
// reject list below. `enum`/`namespace`/`struct` join it on the same block-scope
// grounds that already exclude `class`. (Rust's `fn`/`let mut` are not in this
// language population, so they are deliberately absent rather than overlooked.)
function applyTautologyWrap(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const wrap = TAUTOLOGY[ctx.language];
  if (!wrap) return reject(`no tautology wrapper for ${ctx.language}`);
  const g3 = gateStatementPosition(pc.line);
  if (!g3.ok) return reject(`G3: ${g3.reason}`);
  if (precededByAnnotation(ctx.lines, pc.at)) return reject('preceding line is a decorator/attribute: nothing may be inserted between it and this line');
  const g4 = gateIndent(ctx.lines, pc.at, ctx.language);
  if (!g4.ok) return reject(`G4: ${g4.reason}`);
  // A comment is not a statement. `if True:` above a bare `# TODO` produces an
  // empty block and an IndentationError — measured, not assumed: it broke 31
  // Python files in the first self-check run of this module.
  if (isCommentOnly(pc.line, pc.profile)) return reject('payload line is comment-only: it cannot be the body of a wrapper');
  const t = pc.line.trim();
  if (/^(?:const|let|var|def|func|class|public|private|protected|static|internal|import|export|from|package|using|require|type|interface|enum|namespace|struct)\b/.test(t)) {
    return reject('payload is a declaration (or a top-level-only import/export): wrapping it would break later references or fail to parse inside a block');
  }
  if (/^[\w$]+\s*:=/.test(t)) return reject('payload is a Go short variable declaration: block-scoping it would break later references');
  const pad = indentOf(pc.line);
  const eol = eolOf(pc.line);
  const body = wrap.reindent > 0 ? ' '.repeat(wrap.reindent) + pc.line : pc.line;
  const out = [
    ...ctx.lines.slice(0, pc.at),
    pad + wrap.open + eol,
    body,
    ...(wrap.close ? [pad + wrap.close + eol] : []),
    ...ctx.lines.slice(pc.at + 1),
  ];
  // Two insertions straddling the payload: arithmetic on a single insertAt
  // cannot describe lines after the closer, so the mapping is given explicitly.
  const lineMap = new Map();
  for (let i = 0; i < pc.at; i++) lineMap.set(i + 1, i + 1);
  lineMap.set(pc.at + 2, pc.at + 1); // the payload, now one line lower
  const shift = wrap.close ? 2 : 1;
  for (let i = pc.at + 1; i < ctx.lines.length; i++) lineMap.set(i + 1 + shift, i + 1);
  return result(ctx, out, { lineMap, insertAt: pc.at, insertCount: 1 });
}

// S3 — break the call's argument list onto its own line. Every language here
// continues implicitly inside an unclosed `(`, and no newline is introduced
// AFTER the final argument, so Go's semicolon insertion and its trailing-comma
// requirement are both untouched.
function applyCallMultiline(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  const re = /[A-Za-z_$][\w$]*\s*\(/g;
  let m;
  let hit = null;
  while ((m = re.exec(pc.line)) !== null) {
    if (insideLiteral(pc.lits, m.index)) continue;
    const name = m[0].replace(/\s*\($/, '');
    if (CALL_KEYWORDS.has(name)) continue;
    hit = m;
    break;
  }
  if (!hit) return reject('no call in code position on the payload line');
  const open = hit.index + hit[0].length; // offset just after `(`
  const rest = pc.line.slice(open);
  if (rest.trim() === '' || rest.trimStart().startsWith(')')) return reject('call has no arguments to move');
  const head = pc.line.slice(0, open);
  const tail = indentOf(pc.line) + '    ' + rest.trimStart();
  const out = [...ctx.lines.slice(0, pc.at), head, tail, ...ctx.lines.slice(pc.at + 1)];
  return result(ctx, out, { insertAt: pc.at + 1, insertCount: 1 });
}

// ---------------------------------------------------------------------------
// NC1 — fix-real. The vulnerability is actually REMOVED, so the finding must
// disappear in both arms and must NOT be restored by the canonicalizer. It is
// the control for "the harness can tell a real repair from an evasion".
//
// The repair table is ordered and first-match-wins; anything it does not
// recognise is rejected with a reason rather than "repaired" by deleting code,
// which would fabricate a control out of a broken file.
// ---------------------------------------------------------------------------
const REPAIRS = [
  {
    id: 'weak-hash-algorithm-name',
    langs: ALL_LANGS,
    // `createHash("md5")`, `hashlib.new('sha1')` — the algorithm is named by a
    // string, so naming a strong one is the whole fix.
    test: (l) => /(["'])(?:md5|sha1)\1/i.test(l),
    fix: (l) => l.replace(/(["'])(?:md5|sha1)\1/i, '$1sha256$1'),
  },
  {
    id: 'python-hashlib-weak',
    langs: ['python'],
    test: (l) => /\bhashlib\.(?:md5|sha1)\s*\(/.test(l),
    fix: (l) => l.replace(/\bhashlib\.(?:md5|sha1)\s*\(/, 'hashlib.sha256('),
  },
  {
    id: 'ruby-digest-weak',
    langs: ['ruby'],
    test: (l) => /\bDigest::(?:MD5|SHA1)\b/.test(l),
    fix: (l) => l.replace(/\bDigest::(?:MD5|SHA1)\b/, 'Digest::SHA256'),
  },
  {
    id: 'csharp-weak-hash-create',
    langs: ['csharp'],
    test: (l) => /\b(?:MD5|SHA1)\.Create\s*\(/.test(l),
    fix: (l) => l.replace(/\b(?:MD5|SHA1)\.Create\s*\(/, 'SHA256.Create('),
  },
  {
    id: 'php-weak-hash-call',
    // `md5($x)` -> `hash('sha256', $x)`. Arity is preserved because the original
    // call's closing paren becomes the new call's.
    langs: ['php'],
    test: (l) => /(^|[^\w$>])(?:md5|sha1)\s*\(/.test(l),
    fix: (l) => l.replace(/(^|[^\w$>])(?:md5|sha1)\s*\(/, "$1hash('sha256', "),
  },
  {
    id: 'insecure-http-url',
    langs: ALL_LANGS,
    test: (l) => /(["'])http:\/\//.test(l),
    fix: (l) => l.replace(/(["'])http:\/\//g, '$1https://'),
  },
  {
    id: 'hardcoded-secret-literal',
    // The credential is removed outright. Reading it from the environment would
    // need an import this line cannot add in most of these languages, and an
    // empty literal is unambiguously not a leaked secret.
    langs: ALL_LANGS,
    test: (l, lits) => lits.some((x) => !x.tripleQuoted && !x.unterminated && !x.prefixed && x.inner.length >= 8),
    fix: (l, lits) => {
      const lit = lits.find((x) => !x.tripleQuoted && !x.unterminated && !x.prefixed && x.inner.length >= 8);
      return spliceLit(l, lit, `${lit.delim}${lit.delim}`);
    },
  },
];

function applyFixReal(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  for (const r of REPAIRS) {
    if (!r.langs.includes(ctx.language)) continue;
    if (!r.test(pc.line, pc.lits)) continue;
    const fixed = r.fix(pc.line, pc.lits);
    if (fixed === pc.line) continue;
    return replaceLine(ctx, pc.at, fixed);
  }
  return reject('no repair in the table matches this payload line; a real fix here needs more than a single-line rewrite');
}

// NC2 — the identity. Byte-identical output, so ER MUST be 0 in both arms. Any
// other result means the harness is manufacturing evasion out of its own
// pairing, re-scanning or path handling rather than out of the transform.
function applyNoopReformat(ctx) {
  const pc = payloadContext(ctx);
  if (pc.err) return reject(pc.err);
  return result(ctx, ctx.lines.slice());
}

// ---------------------------------------------------------------------------
// The table. Order is fixed and is the reporting order.
// ---------------------------------------------------------------------------
const RAW_TRANSFORMS = [
  {
    id: 'L1',
    name: 'const-concat-split',
    category: 'lexical',
    // php via `.`; go/csharp double-quoted only (gateOperator enforces both).
    languages: ALL_LANGS,
    // Single line, no escape, matching delimiters, gap is exactly the operator —
    // every condition foldConcatenations requires is met by construction.
    d2Predicted: 'covered',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyConstConcatSplit,
  },
  {
    id: 'L2',
    name: 'adjacent-concat',
    category: 'lexical',
    // adjacencyConcat is true for python and ruby only.
    languages: ['python', 'ruby'],
    // `isConcatGap` returns `profile.adjacencyConcat` for an empty gap.
    d2Predicted: 'covered',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyAdjacentConcat,
  },
  {
    id: 'L3',
    name: 'multiline-concat',
    category: 'lexical',
    // Python and Ruby are excluded: `"a" +\n"b"` outside parentheses is a syntax
    // error in Python, and this transform does not add the parentheses.
    languages: ['javascript', 'typescript', 'php', 'go', 'csharp'],
    // The run breaks at `next.line !== prev.line`, and the span guard refuses any
    // text containing `\n`/`\r`.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyMultilineConcat,
  },
  {
    id: 'L4',
    name: 'escaped-split',
    category: 'lexical',
    // csharp excluded (see applyEscapedSplit): its `\x` is variable-length, so
    // the escaped half can merge with a following hex digit into one character.
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'go'],
    // `hasEscape` is one of the `foldable` filter's rejections.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyEscapedSplit,
  },
  {
    id: 'L5',
    name: 'operator-block-comment',
    category: 'lexical',
    // blockComment is false for python and ruby.
    languages: ['javascript', 'typescript', 'php', 'go', 'csharp'],
    // `stripBlankableGap` strips `/* … */` before `isConcatGap` inspects the gap.
    d2Predicted: 'covered',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyOperatorBlockComment,
  },
  {
    id: 'L6',
    name: 'hex-escape-literal',
    category: 'lexical',
    // csharp excluded: `\x` there takes 1-4 digits and adjacent escapes merge.
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php', 'go'],
    // `N` decodes no escapes; there is not even a concatenation to fold.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyHexEncode,
  },
  {
    id: 'L7',
    name: 'identifier-unicode-escape',
    category: 'lexical',
    languages: ['javascript'],
    // `N` never rewrites identifiers.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyIdentifierUnicodeEscape,
  },
  {
    id: 'L8',
    name: 'exotic-whitespace',
    category: 'lexical',
    // U+00A0 is whitespace in the ECMAScript grammar and Unicode-Zs whitespace in
    // C#. It is a syntax error in python/go/ruby and not whitespace in php.
    languages: ['javascript', 'typescript', 'csharp'],
    // U+00A0 is in EXOTIC_WHITESPACE and is mapped to U+0020 in code regions.
    d2Predicted: 'covered',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyExoticWhitespace,
  },
  {
    id: 'L9',
    name: 'line-comment-insert',
    category: 'lexical',
    languages: ['javascript', 'typescript', 'php', 'go', 'csharp'],
    // Comment removal succeeds, but what is left is the L3 multi-line run that
    // folding refuses. Residual despite op (1) working exactly as intended.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyLineCommentInsert,
  },
  {
    id: 'N1',
    name: 'import-alias',
    category: 'name-resolution',
    // Single-binding import forms only. Ruby has no import aliasing; PHP's `use`
    // does not apply to the function-call payloads here; C# aliasing needs the
    // fully qualified type name.
    languages: ['javascript', 'typescript', 'python', 'go'],
    // `N` is three lexical ops over one file and holds no symbol table.
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: applyImportAlias,
  },
  {
    id: 'N2',
    name: 'local-alias-bind',
    category: 'name-resolution',
    // A package is not a value in Go; PHP and C# have no module object to rebind.
    languages: ['javascript', 'typescript', 'python', 'ruby'],
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: applyLocalAlias,
  },
  {
    id: 'N3a',
    name: 'dynamic-attr-plain',
    category: 'name-resolution',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    // The member name becomes a string; no concatenation exists to fold, and `N`
    // does not evaluate member access.
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: (ctx) => applyDynamicAttr(ctx, false),
  },
  {
    id: 'N3b',
    name: 'dynamic-attr-concat',
    category: 'name-resolution',
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    // Deliberately the interesting one. `N` DOES fold the inner `"cre" + "ate"`
    // back to `"create"` — that part is covered — but the surrounding shape is
    // still `obj["createHash"](…)`, which the rule patterns (anchored on
    // `.createHash(`) do not match. So the prediction is residual even though a
    // sub-part of the transform is collapsed; the two variants exist precisely so
    // that partial coverage is visible instead of being averaged away.
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: (ctx) => applyDynamicAttr(ctx, true),
  },
  {
    id: 'S1',
    name: 'arg-hoist',
    category: 'structural',
    languages: ALL_LANGS,
    // `N` has no dataflow; putting the literal back at the call site is constant
    // propagation, which is outside the three declared operations.
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: applyArgHoist,
  },
  {
    id: 'S2',
    name: 'tautology-wrap',
    category: 'structural',
    languages: ALL_LANGS,
    // Only indentation and line numbers move, and `N` preserves both.
    d2Predicted: 'residual',
    adversarialCost: 'R',
    payloadExecutableClaim: 'unverified',
    apply: applyTautologyWrap,
  },
  {
    id: 'S3',
    name: 'call-multiline',
    category: 'structural',
    languages: ALL_LANGS,
    // Whitespace normalization never touches `\n`/`\r` (the geometry contract
    // forbids it), so a construct split across lines stays split.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    payloadExecutableClaim: 'unverified',
    apply: applyCallMultiline,
  },
  {
    id: 'NC1',
    name: 'fix-real',
    category: 'negative-control',
    languages: ALL_LANGS,
    // The finding disappears because the bug is gone, and `N` must not resurrect
    // it. A `covered` measurement here would mean the canonicalizer is inventing
    // findings, which is the failure this control is here to catch.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    // Not an attack: the payload is deliberately no longer the vulnerability, so
    // it can never count toward hard-ER.
    payloadExecutableClaim: false,
    apply: applyFixReal,
  },
  {
    id: 'NC2',
    name: 'noop-reformat',
    category: 'negative-control',
    languages: ALL_LANGS,
    // Nothing changed, so nothing can be evaded and nothing can be covered.
    d2Predicted: 'residual',
    adversarialCost: 'M',
    // Byte-identical to the source, so its executability is whatever the source's
    // was — a claim this module cannot make on its own, hence 'unverified'
    // rather than a fabricated `true`.
    payloadExecutableClaim: 'unverified',
    apply: applyNoopReformat,
  },
];

/**
 * A thrown error inside one `apply` must not take the whole corpus run down, and
 * must not be silently swallowed either: it becomes a rejection whose reason
 * names it as an internal fault, so it shows up in the manifest's `rejections[]`
 * where it can be seen and fixed.
 */
export const TRANSFORMS = RAW_TRANSFORMS.map((t) => ({
  ...t,
  apply(ctx) {
    if (!t.languages.includes(ctx.language)) {
      return reject(`transform ${t.id} does not support ${ctx.language}`);
    }
    try {
      return t.apply(ctx);
    } catch (err) {
      return reject(`internal error in ${t.id}: ${String(err && err.message ? err.message : err)}`);
    }
  },
}));

/** Lookup by stable id, for the evaluator's prediction ledger. */
export const TRANSFORMS_BY_ID = new Map(TRANSFORMS.map((t) => [t.id, t]));
