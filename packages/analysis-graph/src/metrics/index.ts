// metrics-calculator (design addendum §8.2) — the numbers a design-smell finding
// carries so a reader can argue with it.
//
// WHAT THIS MODULE IS FOR
//
// A design smell has no offending substring. "This class is doing too much" is
// not falsifiable by looking at one line, which is exactly why `DesignMetrics`
// exists in `@vibeguard/findings-schema`: the finding ships the measurements it
// reached its verdict from, so a reader who disagrees argues about the threshold
// instead of about whether the tool is hallucinating. This module is where those
// measurements are produced, and it is the ONLY place they are produced — a rule
// that computes its own `loc` inline would give two findings in the same report
// two different definitions of a line of code.
//
// ★ ABSENT IS NOT ZERO. THIS IS THE LOAD-BEARING RULE OF THIS FILE.
//
// Every field of `DesignMetrics` is optional, and the schema is explicit that a
// missing field means NOT MEASURED rather than measured-as-zero. That
// distinction is the reason the type is shaped the way it is, and it is very
// easy to destroy from here: emitting `{ fanIn: 0 }` for a file the graph never
// looked at is a fabricated measurement, and it is indistinguishable downstream
// from a real "nothing imports this file" — which is a fact a reviewer might act
// on. So every function below OMITS a key it did not measure, and none of them
// initialise an accumulator to zero "to keep the shape uniform".
//
// The visible consequence is that callers must never write `m.fanIn ?? 0`. If a
// consumer needs a number, the honest fallback is to not render the metric.
// `mergeMetrics` enforces the same rule at the one place where metrics from
// different producers meet: an `undefined` never overwrites a measured value,
// and a key nobody measured never appears in the result at all — not even with
// value `undefined`, because `'fanIn' in metrics` is how a consumer asks the
// was-it-measured question and `{ fanIn: undefined }` answers it wrong.
//
// ★ WHICH OF THE ELEVEN ADDENDUM METRICS THIS PHASE ACTUALLY COMPUTES
//
// The addendum's metrics-calculator names eleven measurements. Ten of them are
// declared as fields on `DesignMetrics`; the eleventh, cyclomatic complexity, is
// deliberately NOT a schema field (see `branchCount` below). Phase 0.3.0-α
// computes six of the eleven. The rest are listed here rather than only in a
// plan document, because a gap recorded in a plan is a gap nobody reads at the
// call site:
//
//   COMPUTED HERE
//     loc                   fileMetrics, symbolMetrics
//     importCount           fileMetrics
//     methodCount           fileMetrics
//     fieldCount            fileMetrics (class files only — see below)
//     branchCount           symbolMetrics
//     nestingDepth          symbolMetrics
//     fanIn / fanOut        fanMetrics
//
//   NOT COMPUTED IN THIS PHASE — and never emitted as 0
//     cyclomaticComplexity  Not a `DesignMetrics` field at all. `branchCount` is
//                           its declared proxy: real cyclomatic complexity needs
//                           a control-flow graph, which needs a parser, which is
//                           the dependency this whole package exists to avoid
//                           (see the header of `types.ts`). Counting decision
//                           TOKENS gets the same ordering over real code for a
//                           fraction of the machinery, and calling the field
//                           `branchCount` keeps the approximation visible in the
//                           name instead of promising an exactness we do not
//                           have.
//     responsibilityCount   Requires clustering a class's members by what they
//                           touch. That is a judgement about meaning, and doing
//                           it badly (e.g. counting distinct verb prefixes in
//                           method names) would produce a number that LOOKS like
//                           a measurement and is really a guess about naming.
//                           Deferred rather than approximated.
//     duplicatedCheckCount  Owned by VG-SMELL-010, which computes it as part of
//                           deciding that the checks ARE duplicates. Computing
//                           it here would mean normalising and comparing check
//                           expressions a second time, in a second place, with
//                           no way to keep the two definitions in step.
//
// ★ HOW THE COUNTING IS DONE, AND WHY IT MIRRORS design-smells-single.ts
//
// Everything below counts on BLANKED text: `blankJsLiterals` / `blankPyLiterals`
// from `@vibeguard/rules`, which overwrite comment and string INTERIORS with
// spaces while preserving length, newlines, and indentation. A branch keyword
// inside a string literal or a comment is not a branch, and a metric that says
// otherwise inflates on exactly the files that contain the most prose — error
// messages, SQL, docstrings. This is the same discipline `VG-SMELL-003` already
// uses, and the token sets are deliberately identical to the ones proven there.

import type { DesignMetrics } from '@vibeguard/findings-schema';
import { blankJsLiterals, blankPyLiterals, isCommentLine } from '@vibeguard/rules';

import type { DependencyGraph, IndexedSymbol, SourceFile, StructureIndex } from '../types.js';

/**
 * Every key `DesignMetrics` declares, in a fixed order.
 *
 * An explicit allowlist rather than `Object.keys(part)` in `mergeMetrics`, for
 * two reasons that both bite in production:
 *
 *  - `mergeMetrics` copies values by computed key. A caller-supplied object with
 *    an own `__proto__` key — trivially produced by `JSON.parse` of anything, and
 *    the exact shape `VG-INJ-020` exists to warn about — would make
 *    `out[key] = value` reassign the result's prototype instead of setting a
 *    metric. Iterating a fixed list means a key that is not a metric cannot be
 *    reached at all, which is a structural fix rather than a filter someone can
 *    forget to apply to the next merge helper.
 *  - The output key order becomes a property of this constant instead of a
 *    property of whichever producer ran first. Findings are serialised to JSON
 *    and diffed against baselines; key order that depends on producer ordering
 *    turns an unrelated refactor into baseline churn.
 */
const METRIC_KEYS = [
  'loc',
  'methodCount',
  'fieldCount',
  'importCount',
  'branchCount',
  'nestingDepth',
  'fanIn',
  'fanOut',
  'responsibilityCount',
  'duplicatedCheckCount',
] as const;

/**
 * Compile-time proof that `METRIC_KEYS` covers every field of `DesignMetrics`.
 *
 * The allowlist above buys safety at the cost of a silent failure mode: adding a
 * field to the schema and forgetting it here would make `mergeMetrics` DROP that
 * field, and the drop would look exactly like "the producer did not measure it"
 * — the one thing this module promises to keep distinguishable. This alias makes
 * that mistake a type error in `analysis-graph`'s build rather than a metric that
 * quietly stops surviving a merge.
 */
type AssertNever<T extends never> = T;
type _MetricKeysAreExhaustive = AssertNever<Exclude<keyof DesignMetrics, (typeof METRIC_KEYS)[number]>>;

// Branch-ish tokens for the cyclomatic proxy.
//
// DELIBERATELY IDENTICAL to `BRANCH_WORD` / `BRANCH_OP` / `PY_BRANCH_OP` in
// `packages/rules/src/rules/design-smells-single.ts`. They are duplicated rather
// than imported because they are internal to that rule file and are not part of
// `@vibeguard/rules`' public surface; widening that surface so one internal
// consumer can share three regexes would make a rule's private heuristic into a
// published contract. The cost of the copy is that a change there must be
// mirrored here — `metrics.test.ts` pins the behaviour (`?` yes, `?.`/`??` no,
// `notify` no) so a divergence shows up as a failing assertion rather than as
// two rules quietly disagreeing about what a branch is.
//
// The negative lookarounds on the ternary are the whole reason `BRANCH_OP` is
// not just `/\?/`: `?.` (optional chaining) and `??` (nullish coalescing) are
// pervasive in AI-generated TypeScript and are not decisions.
const BRANCH_WORD = /\b(?:if|else\s+if|elif|for|while|case|when|catch|except)\b/g;
const BRANCH_OP = /&&|\|\||(?<![?.:])\?(?![.?:=])/g;
const PY_BRANCH_OP = /\b(?:and|or)\b/g;

/**
 * Languages whose block structure is INDENTATION, not braces.
 *
 * Only Python for 0.3.0-α. Everything else falls through to brace counting,
 * which is right for the C-family, TypeScript, Java, Go, PHP and Rust, and is
 * WRONG-BUT-QUIET for Ruby (`def`/`end`) — a Ruby method reports nesting 0
 * because there are no braces to count. Under-reporting a metric that thresholds
 * fire ABOVE means a missed finding, never a fabricated one, which is the side
 * of the error this package always takes.
 */
const INDENTATION_SCOPED = new Set(['python']);

/**
 * Languages whose comment syntax `blankPyLiterals` models better than
 * `blankJsLiterals` does — `#` line comments, and no `//`.
 *
 * The C-style blanker treats `#` as ordinary code, so a `# TODO: if the user is
 * admin` comment would contribute a branch and a line of code. It also reads the
 * apostrophe in `# don't` as a string opener and blanks real code up to the next
 * quote. Both are silent, so the language routing happens once, here.
 */
const HASH_COMMENT_LANGUAGES = new Set(['python', 'ruby', 'shell', 'yaml', 'toml']);

/**
 * Memoised blanked text, keyed by the `SourceFile` object itself.
 *
 * `symbolMetrics` is called once per symbol and blanking is O(file length), so
 * without this a 400-symbol file costs 400 full passes over its own text. A
 * `WeakMap` rather than a bounded LRU because the key is the file object the
 * caller already holds: entries die exactly when the `ProjectIndex` does, with no
 * eviction policy to tune and no way for a long-lived process to accumulate
 * scans it has finished with.
 *
 * This assumes `SourceFile` is immutable once built, which `ProjectIndex`
 * already promises ("built once per scan, then read-only"). The length check on
 * retrieval is a cheap tripwire for the case where it is not.
 */
const BLANKED_CACHE = new WeakMap<SourceFile, string>();

/**
 * Comment- and string-blanked text for `file`, length-identical to
 * `file.content` so any offset is valid in both.
 *
 * `provided` is `StructureIndex.blanked`, which the structure-indexer already
 * computed for the same file. Reusing it avoids a second pass, but it is
 * VALIDATED rather than trusted: a blanked string of a different length would
 * make every offset in `IndexedSymbol` point somewhere else, and the resulting
 * metrics would be plausible numbers computed over the wrong text — the failure
 * mode with no symptom. A length mismatch means the two disagree about the file,
 * so this recomputes from `file.content`, which is by definition the text the
 * offsets were taken against.
 */
function blankedOf(file: SourceFile, provided?: string): string {
  if (provided !== undefined && provided.length === file.content.length) return provided;

  const cached = BLANKED_CACHE.get(file);
  if (cached !== undefined && cached.length === file.content.length) return cached;

  const computed = HASH_COMMENT_LANGUAGES.has(file.language)
    ? blankPyLiterals(file.content)
    : blankJsLiterals(file.content);
  BLANKED_CACHE.set(file, computed);
  return computed;
}

/**
 * Split on either line ending.
 *
 * This repository is developed on Windows and tested on Linux CI, so CRLF input
 * is normal rather than exotic. Splitting on `\n` alone leaves a trailing `\r` on
 * every line, which does not break a `.trim()` check but does break anchored
 * patterns (`…;\s*$` still matches, `…;$` does not) and any width computed from
 * `line.length`. Splitting on `/\r?\n/` removes the class of bug once.
 */
function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

/**
 * Residual comment DELIMITERS left behind by the blankers.
 *
 * The blankers preserve delimiters and blank only interiors, so a comment-only
 * line does not become empty: `/** …` becomes `/*` plus spaces, ` * …` inside a
 * block comment becomes all spaces, and ` * /` (closing) becomes `* /`. Deleting
 * the delimiter tokens before the emptiness test is what makes a JSDoc header
 * contribute 0 lines of code instead of 2. Removal can only ever REDUCE the line
 * count, and every line it empties was a comment, so the direction of the error
 * is bounded.
 *
 * The triple quotes are here for the same reason: a Python docstring's opening
 * and closing lines survive blanking as a bare `"""`, and counting a docstring
 * as two lines of code would put every well-documented function two lines closer
 * to a size threshold than an undocumented one — a metric that punishes
 * documentation. A line with real code AND a triple quote (`sql = """…`) keeps
 * the code and is still counted.
 */
const COMMENT_RESIDUE = /\/\*|\*\/|\/\/|#|"""|'''|\//g;
// The trailing bare `\/` is not redundant with `\/\*`, and the reason is a real
// asymmetry between two blankers this module is fed by.
//
// `blankJsLiterals` enters the block-comment state and leaves BOTH delimiter
// characters intact, so an opening line blanks to `/*` + spaces and the `\/\*`
// alternative erases it. `blankCommentsAndStrings` — which the structure indexer
// uses for C and C++ — enters the same state without consuming the `*`, so on
// the next character it is already inside the comment and blanks the `*` as
// content. The opening delimiter survives as a LONE `/`, which `\/\*` cannot
// match, so the line failed the emptiness test and was counted as code.
//
// The visible effect was a C file's `loc` growing with its documentation while
// the byte-identical TypeScript file's did not — a metric that penalises exactly
// the house style this repository requires, and one that pushed C symbols toward
// size thresholds for having comments. It was found by an adversarial check
// comparing the two languages on the same text.
//
// Fixing it in `@vibeguard/rules` instead would be the tidier repair and is
// deliberately not done: `blankCommentsAndStrings` is shared by the 47 core
// rules and by the pinned E2/E6 fixed points, so changing its output is a
// detection change with a version bump attached. This module can absorb the
// difference on its own.
//
// Safe to remove unconditionally: a line carrying real code has more than
// slashes on it (`return a / b;` still leaves `return a  b;` non-empty), so the
// only lines this can empty are ones that were nothing but delimiters.

/**
 * Lines of code: non-blank, and not a comment.
 *
 * Three tests rather than one, because each catches a shape the others miss:
 * the raw line being blank, the raw line OPENING a line comment (`isCommentLine`,
 * the repository's single comment-line predicate — reused so `loc` and
 * `runRegex({ skipCommentLines })` cannot drift apart), and the blanked line
 * having nothing left but comment delimiters, which is how multi-line block
 * comments and docstrings are caught without modelling them here.
 *
 * A trailing comment on a real statement keeps its line: the blanked form still
 * contains the statement.
 */
function countCodeLines(rawLines: readonly string[], blankedLines: readonly string[], language: string | undefined): number {
  let count = 0;
  for (let i = 0; i < rawLines.length; i += 1) {
    const raw = rawLines[i] ?? '';
    if (raw.trim() === '') continue;
    if (isCommentLine(raw, language)) continue;
    const blanked = blankedLines[i] ?? '';
    if (blanked.replace(COMMENT_RESIDUE, '').trim() === '') continue;
    count += 1;
  }
  return count;
}

/** The syntactic kind of a symbol, seeing through a role that overrode it. */
function syntacticKind(symbol: IndexedSymbol): 'function' | 'method' | 'class' {
  if (symbol.declaredKind !== undefined) return symbol.declaredKind;
  // `route-handler` and `middleware` are roles attached to something that was
  // written as a function; when the indexer did not record `declaredKind`, a
  // function is the only thing they can have been.
  return symbol.kind === 'class' ? 'class' : symbol.kind === 'method' ? 'method' : 'function';
}

/**
 * A symbol's body text, with the outer braces removed if the indexer included
 * them.
 *
 * `IndexedSymbol` documents `bodyStart` as the offset AFTER the opening brace,
 * which makes the slice the body's contents and lets brace depth start at 0. The
 * normalisation exists because this module is consumed by an indexer maintained
 * separately from it, and the off-by-one-brace disagreement is silent: it does
 * not throw, it just adds exactly 1 to every `nestingDepth` in the report, which
 * is indistinguishable from real code being one level deeper.
 *
 * Only stripped when the slice is EXACTLY one balanced block — leading `{`, its
 * matching `}`, nothing but whitespace after. A body that merely happens to open
 * with a bare block statement keeps its braces.
 */
function stripOuterBraces(raw: string, blanked: string): { raw: string; blanked: string } {
  const open = blanked.search(/\S/);
  if (open < 0 || blanked[open] !== '{') return { raw, blanked };

  let depth = 0;
  for (let i = open; i < blanked.length; i += 1) {
    const c = blanked[i];
    if (c === '{') depth += 1;
    else if (c === '}') {
      depth -= 1;
      if (depth === 0) {
        if (blanked.slice(i + 1).trim() !== '') return { raw, blanked };
        return { raw: raw.slice(open + 1, i), blanked: blanked.slice(open + 1, i) };
      }
    }
  }
  return { raw, blanked };
}

/**
 * Drop a leading `class Foo:` header line from a Python class body slice.
 *
 * The Python counterpart of `stripOuterBraces`, and it exists for the same
 * reason: the indexer's span for a Python class starts AT the `class` keyword
 * (there is no opening brace to start after), so the slice's minimum
 * indentation is the header's, not the members'. Left in, every class attribute
 * would be judged "deeper than the base indent" — i.e. a method local — and
 * `fieldCount` would report only the `self.x` assignments. Removing the header
 * makes the base indentation the member level under either convention.
 */
function stripPythonClassHeader(blanked: string): string {
  const lines = splitLines(blanked);
  let i = 0;
  while (i < lines.length && (lines[i] ?? '').trim() === '') i += 1;
  if (!/^[^\S\r\n]{0,80}class\b/.test(lines[i] ?? '')) return blanked;
  return lines.slice(i + 1).join('\n');
}

/** Maximum brace nesting reached inside an already-blanked body. */
function maxBraceDepth(blankedBody: string): number {
  let depth = 0;
  let max = 0;
  for (let i = 0; i < blankedBody.length; i += 1) {
    const c = blankedBody[i];
    if (c === '{') {
      depth += 1;
      if (depth > max) max = depth;
    } else if (c === '}' && depth > 0) {
      depth -= 1;
    }
  }
  return max;
}

/**
 * Maximum indentation nesting reached inside an already-blanked Python body.
 *
 * The stack of indentation widths is the same construction `VG-SMELL-003` uses,
 * and the `- 1` at the end is what makes the number COMPARABLE to the brace
 * count: the body's own base indentation is stack depth 1 and corresponds to the
 * function's own braces, which the brace path does not count either.
 *
 * One deliberate difference from the rule: blankness is judged on the BLANKED
 * line, not the raw one. A docstring's interior lines are real, non-blank, often
 * deeply indented lines of prose; on the raw text they push the stack and report
 * nesting that no control flow produced.
 */
function maxIndentDepth(blankedLines: readonly string[]): number {
  const stack: number[] = [];
  let max = 0;
  for (const line of blankedLines) {
    if (line.trim() === '') continue;
    const width = line.length - line.trimStart().length;
    while (stack.length > 0 && (stack[stack.length - 1] ?? 0) >= width) stack.pop();
    stack.push(width);
    if (stack.length > max) max = stack.length;
  }
  return Math.max(0, max - 1);
}

function countMatches(text: string, pattern: RegExp): number {
  // `String.prototype.match` with a `/g` pattern resets `lastIndex`, so these
  // module-level regexes stay reusable across calls. `pattern.exec` in a loop
  // would not, and the resulting bug — every second call starting mid-string —
  // is intermittent by construction.
  return text.match(pattern)?.length ?? 0;
}

// Field-declaration shapes inside a class body. Bounded quantifiers throughout,
// and horizontal-whitespace classes (`[^\S\r\n]`) rather than `\s`, following the
// A1/D3 ReDoS discipline: `\s` spans newlines, and two adjacent variable-length
// runs that can each swallow blank lines are the exact shape that went
// super-linear in the rules package.
const JS_FIELD_DECL =
  /^(?:(?:public|private|protected|readonly|static|declare|abstract|override|accessor)[^\S\r\n]{1,4}){0,5}(#?[A-Za-z_$][\w$]{0,60})[^\S\r\n]{0,4}[?!]?[^\S\r\n]{0,4}(?::[^=;{}()\r\n]{0,160})?[^\S\r\n]{0,4}(?:=[^;\r\n]{0,200})?;?[^\S\r\n]{0,4}$/;
const JS_THIS_FIELD = /\bthis\.(#?[A-Za-z_$][\w$]{0,60})[^\S\r\n]{0,4}=(?!=)/g;
const PY_SELF_FIELD = /\bself\.([A-Za-z_]\w{0,60})[^\S\r\n]{0,4}=(?!=)/g;
const PY_CLASS_FIELD = /^[^\S\r\n]{0,80}([A-Za-z_]\w{0,60})[^\S\r\n]{0,4}(?::[^=\r\n]{0,120})?=(?!=)/;

/**
 * Field names declared by one class, best-effort and lexical.
 *
 * BY NAME, not by count, because the two ways a field appears must not both
 * count: TypeScript code routinely declares `private cache: Map<…>;` at the top
 * of the class AND assigns `this.cache = new Map()` in the constructor, and a
 * counter would report two fields where there is one. Collecting names and
 * returning the set makes the de-duplication automatic.
 *
 * Constructor assignments are counted at all, rather than only declarations,
 * because plain JavaScript has no declaration syntax to find — a class whose
 * fields are all assigned in the constructor would measure 0, and "this class has
 * no state" is a materially wrong thing to tell a reviewer of a god object.
 *
 * KNOWN LIMITS, all in the under-counting direction: fields declared across
 * multiple lines of type annotation, fields assigned through a destructuring
 * pattern (`{ a, b } = opts`), and fields introduced by `Object.assign(this, …)`
 * are not seen.
 */
function classFieldNames(blankedBody: string, language: string): Set<string> {
  const names = new Set<string>();
  const python = INDENTATION_SCOPED.has(language);

  const assignPattern = python ? PY_SELF_FIELD : JS_THIS_FIELD;
  assignPattern.lastIndex = 0;
  for (const m of blankedBody.matchAll(assignPattern)) {
    const name = m[1];
    if (name !== undefined) names.add(name);
  }

  const blankedLines = splitLines(python ? stripPythonClassHeader(blankedBody) : blankedBody);

  if (python) {
    // Class-level assignments only: the base indentation of the class body. A
    // deeper line is inside a method, where an assignment is a local variable
    // and emphatically not a field.
    let base = -1;
    for (const line of blankedLines) {
      if (line.trim() === '') continue;
      const width = line.length - line.trimStart().length;
      if (base < 0 || width < base) base = width;
    }
    for (const line of blankedLines) {
      if (line.trim() === '') continue;
      const width = line.length - line.trimStart().length;
      if (width !== base) continue;
      const m = PY_CLASS_FIELD.exec(line);
      const name = m?.[1];
      if (name !== undefined) names.add(name);
    }
    return names;
  }

  // Brace languages: only lines that START at brace depth 0 relative to the
  // class body are members. Everything deeper is inside a method body, where
  // `const x = 1;` matches the field shape perfectly and is a local.
  let depth = 0;
  for (const line of blankedLines) {
    const depthAtLineStart = depth;
    for (let i = 0; i < line.length; i += 1) {
      const c = line[i];
      if (c === '{') depth += 1;
      else if (c === '}' && depth > 0) depth -= 1;
    }
    if (depthAtLineStart !== 0) continue;
    const trimmed = line.trim();
    if (trimmed === '') continue;
    const m = JS_FIELD_DECL.exec(trimmed);
    const name = m?.[1];
    if (name !== undefined) names.add(name);
  }
  return names;
}

/**
 * File-level metrics: how big it is, how much it pulls in, how much it holds.
 *
 * `structure` supplies the counts (it already found the symbols and imports);
 * `file` supplies the text. The two are assumed to describe the same file —
 * the caller holds both from the same `ProjectIndex` entry — and nothing here
 * cross-checks `filePath`, because a mismatch is a caller bug that a silent
 * fallback would hide rather than fix.
 *
 * `fieldCount` is ABSENT for a file with no class, and that absence is the
 * point. A functional module has no fields to count, so `0` would be a claim
 * that it was checked for state and found stateless — which a rule about god
 * objects could reasonably act on. "The question does not apply here" and "the
 * answer is zero" are different answers and this returns different values for
 * them. A file that DOES declare a class and has no fields gets `fieldCount: 0`,
 * a genuine measurement.
 */
export function fileMetrics(structure: StructureIndex, file: SourceFile): DesignMetrics {
  const language = file.language || structure.language;
  const blanked = blankedOf(file, structure.blanked);

  const rawLines = splitLines(file.content);
  const blankedLines = splitLines(blanked);

  // Distinct MODULES, not import statements. Two `import` lines from `'react'`
  // are one dependency, and a file-level "this pulls in too much" judgement that
  // counted statements would rank a file by its author's import style (named vs
  // default split across lines) rather than by its coupling. Keying on the
  // resolved path when there is one also collapses `./auth` and `./auth.js` onto
  // the one file they both name. This is the same unit `fanOut` uses below, and
  // two metrics in one object counting the same thing differently is a trap
  // worth spending a paragraph to avoid.
  const modules = new Set<string>();
  for (const edge of structure.imports) modules.add(edge.resolvedFile ?? edge.specifier);

  let methodCount = 0;
  const classes: IndexedSymbol[] = [];
  for (const symbol of structure.symbols) {
    if (syntacticKind(symbol) === 'class') classes.push(symbol);
    else methodCount += 1;
  }

  const metrics: DesignMetrics = {
    loc: countCodeLines(rawLines, blankedLines, language),
    methodCount,
    importCount: modules.size,
  };

  if (classes.length > 0) {
    // Summed across classes, de-duplicated WITHIN each: two classes in one file
    // that both have a `name` field have two fields between them, but one class
    // that declares `name` and also assigns `this.name` has one.
    let fieldCount = 0;
    for (const cls of classes) {
      const start = Math.max(0, Math.min(cls.bodyStart, file.content.length));
      const end = Math.max(start, Math.min(cls.bodyEnd, file.content.length));
      const body = stripOuterBraces(file.content.slice(start, end), blanked.slice(start, end));
      fieldCount += classFieldNames(body.blanked, language).size;
    }
    metrics.fieldCount = fieldCount;
  }

  return metrics;
}

/**
 * Symbol-level metrics: how big this function is, how many decisions it makes,
 * how deep it goes.
 *
 * The three together are what `VG-SMELL-003` thresholds on, and they are
 * computed here so a cross-file rule reaches the same numbers the single-file
 * rule would — a report where the same method is "80 lines" in one finding and
 * "74 lines" in another is a report nobody trusts twice.
 *
 * An EMPTY body returns all three as 0 rather than omitting them. That is a
 * measurement: the body was read, and it contained no code, no branches and no
 * nesting. It is exactly the case the absent-is-not-zero rule is NOT about.
 */
export function symbolMetrics(symbol: IndexedSymbol, file: SourceFile): DesignMetrics {
  const language = file.language;
  const blanked = blankedOf(file);

  const start = Math.max(0, Math.min(symbol.bodyStart, file.content.length));
  const end = Math.max(start, Math.min(symbol.bodyEnd, file.content.length));
  const body = stripOuterBraces(file.content.slice(start, end), blanked.slice(start, end));

  const rawLines = splitLines(body.raw);
  const blankedLines = splitLines(body.blanked);

  const python = INDENTATION_SCOPED.has(language);
  const branchCount =
    countMatches(body.blanked, BRANCH_WORD) + countMatches(body.blanked, python ? PY_BRANCH_OP : BRANCH_OP);

  return {
    loc: countCodeLines(rawLines, blankedLines, language),
    branchCount,
    nestingDepth: python ? maxIndentDepth(blankedLines) : maxBraceDepth(body.blanked),
  };
}

/**
 * Coupling metrics for one file, read off the already-built dependency graph.
 *
 * AT FILE GRANULARITY. `DesignMetrics` documents `fanIn`/`fanOut` as counts of
 * symbols, and 0.3.0-α counts files: the dependency graph resolves import EDGES
 * between files, and reporting a symbol-level number computed from file-level
 * evidence would be a bigger lie than reporting a file-level one under a
 * symbol-level name. The unit is stated on every finding that carries it.
 *
 * ★ CALLER CONTRACT: only call this for a file the graph actually admitted. A
 * file dropped by the budget caps appears in neither map, and so does a file that
 * genuinely nothing imports and that imports nothing — the two are
 * indistinguishable from here, and this returns 0 for both. Calling it on a
 * dropped file therefore produces the one thing this module refuses to produce
 * elsewhere: a fabricated zero. The check belongs at the call site, which knows
 * the admission set; it cannot be made here, because `DependencyGraph` carries
 * edges rather than the roster of files that were read.
 */
export function fanMetrics(filePath: string, graph: DependencyGraph): DesignMetrics {
  // Windows callers hold `src\routes\admin.ts`; the graph is keyed on the
  // forward-slash repo-relative form `SourceFile.filePath` promises. Trying the
  // key as given first means a project that legitimately contains a backslash in
  // a path is not silently redirected to a different file's numbers.
  const alt = filePath.includes('\\') ? filePath.replace(/\\/g, '/') : undefined;
  const lookup = (m: Map<string, Set<string>>): number =>
    (m.get(filePath) ?? (alt !== undefined ? m.get(alt) : undefined))?.size ?? 0;

  return {
    fanIn: lookup(graph.importedBy),
    fanOut: lookup(graph.importsOf),
  };
}

/**
 * Combine metrics from several producers into the one object a finding carries.
 *
 * Later parts win, so a caller orders arguments from general to specific:
 * `mergeMetrics(fileMetrics(...), fanMetrics(...), symbolMetrics(...))` lets the
 * symbol's own `loc` replace the file's.
 *
 * ★ TWO RULES THAT ARE THE ENTIRE REASON THIS FUNCTION EXISTS rather than
 * `{ ...a, ...b }`:
 *
 *  1. An `undefined` NEVER overwrites a measured value. Object spread does the
 *     opposite — `{ ...{ loc: 12 }, ...{ loc: undefined } }` is `{ loc: undefined }`
 *     — so a producer that did not measure `loc` would erase the producer that
 *     did, and the finding would report "not measured" for a number that was in
 *     fact measured one line earlier. This is not hypothetical: every function in
 *     this module returns a partial object by design, so every merge here is
 *     exactly that shape.
 *  2. A key nobody measured is ABSENT, not present-and-undefined. Consumers ask
 *     "was this measured" with `'fanIn' in metrics` (and `JSON.stringify` drops
 *     `undefined` values, so the serialised form already behaves this way — the
 *     in-memory object must agree with it, or the same finding answers the
 *     question differently before and after a round-trip through a baseline file).
 */
export function mergeMetrics(...parts: (DesignMetrics | undefined)[]): DesignMetrics {
  const out: DesignMetrics = {};
  const sink = out as Record<string, number>;

  // Key-major, scanning the parts from LAST to first and stopping at the first
  // measured value. Part-major with later assignments overwriting earlier ones
  // would produce the same values, but the insertion order of the result would
  // then be the order the producers happened to run in — which is the baseline
  // churn `METRIC_KEYS` exists to prevent. Written this way the two loops give
  // both properties at once: later-wins, and a key order that is a property of
  // the schema rather than of the call site.
  for (const key of METRIC_KEYS) {
    for (let i = parts.length - 1; i >= 0; i -= 1) {
      const value = parts[i]?.[key];
      if (value === undefined) continue;
      sink[key] = value;
      break;
    }
  }

  return out;
}
