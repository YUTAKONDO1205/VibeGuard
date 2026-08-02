// VG-SMELL-041 — Temporal Security Coupling. The first rule in this package
// whose evidence is a DATAFLOW rather than a shape.
//
// WHAT IT CLAIMS
//
// A security operation the code already contains does not protect the value it
// was written for, because of ORDER. Two orders can be wrong, and this rule
// reports both:
//
//   INVERTED — the operation runs after the sink. `db.query(sql)` on line 9 and
//   `escapeLike(term)` on line 11: the statement has already executed, and the
//   escaping cannot have protected anything.
//
//   BYPASSED — the operation runs first, and its result is not what reached the
//   sink. `const safe = sanitizeFilename(raw)` on line 20 and
//   `fs.createReadStream(join(dir, raw))` on line 22: the page order is right
//   and the DATA order is not.
//
// The premise both share is what makes this a design smell rather than an
// injection report: the function demonstrably knows the value needs handling —
// it handles it, ten lines away — and nothing in the structure of the code makes
// the handling apply. That is a coupling between two statements that only the
// author's memory maintains, which is the definition of a temporal coupling and
// the reason the fix is structural rather than a one-line patch.
//
// ★ WHY THE DEFINITION IS TAINT-SHAPED AND NOT TEXT-SHAPED
//
// 実装設計手順書 §9.3 names the failure of the obvious version outright: today
// 041 "can only say that a `save` comes after a `validate` in the text, which is
// a false-positive source", and taint makes it evidence — "the argument of
// `save` is a tainted variable that does not pass through `validate`". A
// statement-order rule reports every handler that happens to call a validator
// late for an unrelated value, and reports nothing about whether the value at
// the sink is the checked one. Both halves of that are fixed by asking the
// question of a FLOW: which value, from where, through what.
//
// ★ THE THREE OTHER NATURAL DEFINITIONS, AND WHY NONE OF THEM IS THIS ONE
//
//  1. "A tainted value reaches a sink." That is injection, and `VG-INJ-004` /
//     `VG-INJ-006` already report it from the single-file engine on every one of
//     the four channels. Emitting it again here would put a second, design-smell
//     shaped copy of the same defect in the same report, under a category that
//     promises structural evidence it would not have. `smell-041-no-sanitizer/`
//     is the fixture that pins the boundary: a raw flow with no security
//     operation anywhere near it is not this rule's finding.
//
//  2. "A guard clause sits after the sink" — `res.send(row); if (!req.user)
//     return res.sendStatus(401);`. Refused because deciding it needs control
//     flow this layer does not have. Whether a guard protects a sink is a
//     question about DOMINANCE, not about offsets: an early return in one branch
//     legitimately follows a response written in another, and a lexical pass
//     cannot tell the two apart. Getting it wrong would fire on ordinary
//     multi-branch handlers, which is the failure mode this package treats as a
//     bug rather than a near miss.
//
//  3. "The function contains a sanitizer and a tainted flow." Refused: it fires
//     on any handler that validates an email address and also queries a
//     database. The sanitizer's ARGUMENT has to name a value on the flow's own
//     chain, which is what turns "a security operation exists nearby" into "a
//     security operation was written FOR THIS VALUE and did not apply to it".
//
// ★ WHY A TRANSFORMER AND A VALIDATOR ARE NOT THE SAME CALL
//
// This is the distinction the rule is built around, and getting it wrong is how
// the obvious implementation produces its worst false positive.
//
//   A TRANSFORMER (`escapeHtml`, `sanitizeFilename`, `encodeURIComponent`)
//   returns a SAFE COPY. Correct use requires the copy to be the value that
//   reaches the sink, so "the flow did not pass through it" is a real defect.
//
//   A VALIDATOR (`isValidHostname`, `validateTicketId`, `verifySignature`)
//   returns a VERDICT. It produces no new value, so the value reaching the sink
//   is BY CONSTRUCTION the same variable that was checked and no hop of the
//   chain can ever carry the validator's name. Reporting "the flow did not pass
//   through the validator" would therefore report every validate-then-use
//   handler in existence — the most common correct shape there is.
//
// So a validator can only be reported INVERTED (a check after the use is wrong
// under any control flow), and a validator positioned before the sink SILENCES
// the finding entirely. `smell-041-validate-first/` is that fixture.
//
// What that concession costs, stated rather than hidden: the rule cannot tell
// whether the failing branch short-circuits, so `if (!isValid(x)) log('bad');`
// followed by the sink is a FALSE NEGATIVE. Recovering it needs the same
// dominance analysis definition 2 was refused for.
//
// ★ WHY THIS RULE LIVES IN `analysis-graph` DESPITE NOT BEING CROSS-FILE
//
// It is not cross-file and does not claim to be — `hops` never leaves one
// function body, and the finding's `scope` is `symbol`. It is here because H1
// taint is here, and H1 is here because it cannot be anywhere else: the core
// engine's `RuleDefinition` takes one string and returns spans within it, which
// is the property that lets the same rule set run inside the Chrome extension
// over a textarea. A dataflow pass needs symbol bodies, so it needs the indexer,
// so it belongs on this side of the package boundary. The `cross-file` tag is
// deliberately NOT on this rule's findings for the same reason: it would claim
// evidence the finding does not have.
//
// ★★ MEASURED 2026-08-02 — THE FIRST VERSION OF THIS RULE SCORED PRECISION 0 ON
// REAL CODE, AND FOUR CONDITIONS ARE WHAT IT WAS MISSING
//
// Everything above this line was true of the rule as first written, and the rule
// as first written was wrong. Run over the 1,000 repositories in
// `paper_data/corpus1k` (777 seconds, every repository scanned, nothing sampled)
// it produced THREE findings and not one of them was a defect. All three are
// reproduced as negative fixtures in this group, because a rule whose only
// contact with real code was a false positive has to carry that contact in its
// corpus or the next edit reintroduces it.
//
// What went wrong, and what each failure bought:
//
//  1. TWO STATEMENTS THAT CANNOT BOTH RUN. `decolua__9router` writes
//     `if (isAdmin()) { fs.readFileSync(hostsFile) } else { … quotePs(hostsFile) … }`,
//     and the rule reported the `else` branch's call as "runs after the sink" —
//     twice. The INVERTED test was a comparison of two offsets, and an offset
//     comparison cannot tell "later on the same path" from "in the branch that
//     did not run". That is EXACTLY the failure definition 2 above was refused
//     for, arriving through a door nobody was watching: it was kept out of the
//     guard-clause reading and let straight into the sanitizer reading.
//
//     The fix is `sameBlock`. There is no CFG here, so the question "could these
//     two statements both execute, in this order" is not answerable; the question
//     "do these two statements sit in ONE brace block" is, from the blanked text,
//     and it is a strict under-approximation of the first. A guard in a sibling
//     branch is now unreportable, and so is a guard nested one level deeper —
//     recall this rule no longer has, stated rather than discovered.
//
//  2. A PARAMETERISED STATEMENT IS NOT A MIS-ORDERED ONE.
//     `const rows = await db.query('… WHERE id = $1', [id]); res.send(escapeHtml(id))`
//     is the ordinary correct Express shape — a placeholder for the database, an
//     HTML escape for the page — and the first version fired on it whichever
//     order the two lines were written in. Worse, the shape it fired on is the
//     one this rule's own `remediation.exampleFix` recommends.
//
//     The mistake was treating H1's flow as evidence that the value ARRIVED
//     unprotected. It is not: H1 reports a flow into `db.query` because `id`
//     appears in the argument list, and it has no opinion about whether it
//     appears as a bound parameter. `sinkIsParameterized` asks that question
//     directly, and it can answer it because blanking is length-preserving — a
//     `$1` that is a space in `StructureIndex.blanked` and a `$1` in the original
//     was inside a string literal, i.e. it is part of the statement rather than
//     part of the code.
//
//  3. A VOCABULARY WIDE ENOUGH TO CATCH `stripTrailingWhitespace`. See the
//     ★ MEASURED CORRECTION on `VALIDATOR_WORDS` — the claim written there was
//     falsified, not refined.
//
//  4. A GUARD WRITTEN FOR A DIFFERENT PROPERTY OF THE SAME OBJECT.
//     `JimLiu__baoyu-skills` reads `options` out of `process.argv`, opens
//     `options.changelogFile`, and later calls `validateSkillMetadataVersion(…,
//     options.version)`. Both mention `options`, so the premise "written for THIS
//     value" was satisfied by two statements about two different values. A hop
//     that names an OBJECT cannot carry the premise, and `mentionsBare` is the
//     narrowing: a chain name mentioned as `name.property` names a property, and
//     only a chain name mentioned as a bare token names the value that flowed.
//     Applied to the sink as well as to the guard, which is what closes it — the
//     sink there consumes `options.changelogFile`, never `options`.
//
// ★ WHY THE SOURCE'S POSITION IS NOT PART OF THE BLOCK TEST
//
// The obvious extension of `sameBlock` is to demand all three cited points —
// source, sink, guard — in one block. It is not done, and the reason is that the
// source's position cannot distinguish the failure the test exists for. Failure 1
// is entirely about whether the GUARD could have run on the path the SINK ran on;
// a source assigned inside a conditional (`if (a) { t = req.query.a } else { t =
// req.query.b }`) is on every path that reaches either, and demanding it share
// the sink's block would delete that shape for no precision gained. A condition
// added for symmetry rather than for a measured failure is a condition nobody can
// falsify.
//
// KNOWN GAPS, so nobody has to discover them by being wrong. Every one of them
// fails toward SILENCE, which is the direction a design smell has to fail in:
//   - Everything H1 cannot see, this cannot see. No property writes, no
//     interprocedural flow, no compound assignment. See `taint/index.ts`.
//   - A sanitizer whose name is not in the vocabulary below is invisible.
//   - A guard in a sibling branch, or nested deeper than the sink, is not
//     reported even when it really is dead protection. See `sameBlock`.
//   - A value consumed by the sink as `object.property` is not reported at all.
//     See `mentionsBare`.
//   - ★ MEASURED LIMIT, found by a mutation that would not die: a call written
//     as the DIRECT first argument of another call is invisible to
//     `guardCallsIn`. `CALL_RE` opens with `(?:^|[^\w$.])` and therefore CONSUMES
//     the `(` of the outer call, leaving the inner callee with no boundary
//     character to match against — so `db.query(escapeSql(x))` collects
//     `db.query` and not `escapeSql`. It is fail-safe in both directions that
//     matter (an unseen guard establishes no premise, so the shape is silent
//     either way, and the same shape is what `inSink` would have suppressed),
//     which is why it is recorded rather than repaired here: widening `CALL_RE`
//     would newly admit every nested call in the corpus as a candidate guard,
//     and that is a precision change to be measured on its own rather than
//     smuggled in beside four false-positive fixes.
//     `smell-041-inline-at-sink/` is unaffected because `${escapeHtml(…)}`
//     supplies the `{` as a boundary.
//   - Two statements on one line are indistinguishable to the on-path test,
//     which compares LINES because that is the resolution `TaintFlow.hops`
//     reports at. `const a = req.query.x; const c = escape(a);` written on one
//     line reads as sanitised. Reproduced, deliberately, by the bound test in
//     the suite — see the second MEASURED note there.
//   - A DIRECT flow from a dotted source (`db.query(req.query.id)`, no hops)
//     cannot establish the premise at all. See `chainNames`.
//   - A validator whose failing branch does not short-circuit still suppresses.
//     See the validator note above.

import type { CodeLocation, Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, mergeMetrics, symbolMetrics } from '../metrics/index.js';
import { analyzeProjectTaint, type SinkKind, type TaintFlow } from '../taint/index.js';
import type {
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  SourceFile,
  StructureIndex,
} from '../types.js';

/** Path segments whose contents are fixtures, not the service under review. */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata)(?:\/|$)|\.(?:test|spec)\.[\w]+$/i;

/** Any character that cannot appear inside an identifier word. */
const NON_WORD_CHAR = /[^A-Za-z0-9]/;

/** The camelCase seam: a lowercase or digit immediately followed by a capital. */
const CAMEL_SEAM = /([a-z0-9])([A-Z])/g;

/**
 * Split an identifier into lowercase words.
 *
 * ★ WORD MATCHING, NEVER SUBSTRING MATCHING — the same discipline `pathWords` in
 * `scattered-authorization.ts` is written out at length for, applied to callee
 * names instead of paths. `/valid/i.test(name)` matches `invalidateCache`, which
 * is a cache eviction and would make this rule treat every memoising handler as
 * one that validates its input. Splitting first means `invalidate` is a word
 * this vocabulary does not contain and the question stops being close.
 *
 * A third small copy rather than an import, for the reason the second one gave:
 * the symbol table's `tokenize` is private to a module that deliberately never
 * reads callee names, and widening its surface to share four lines would be the
 * more expensive change.
 *
 * Neither regex has a quantifier — a split on a single-character class, then one
 * substitution at a two-character seam — so neither can backtrack and the D3
 * three-second contract holds by construction rather than by measurement.
 */
function identifierWords(name: string): string[] {
  const out: string[] = [];
  for (const chunk of name.split(NON_WORD_CHAR)) {
    if (chunk.length === 0) continue;
    for (const word of chunk.replace(CAMEL_SEAM, '$1 $2').split(' ')) {
      if (word.length > 0) out.push(word.toLowerCase());
    }
  }
  return out;
}

/** What a recognised security call does with the value it is handed. */
type GuardKind = 'transformer' | 'validator';

/**
 * Words naming a call that returns a SAFE COPY.
 *
 * A closed list, and short on purpose — the same reasoning as the bundled
 * package table in `packages/rules/src/rules/ai-supply-chain-data.ts`: a false
 * positive is removed by editing one entry rather than by weakening a heuristic
 * everything else stands on.
 *
 * NOT here, each for a reason:
 *  - `normalize` — normalisation is not sanitisation. `path.normalize` is the
 *    textbook example of a call that looks protective and is not, and `normalize`
 *    is also the ordinary word for reshaping data. Including it would make the
 *    rule fire around routine munging and would tell readers that a normaliser
 *    counts as a defence.
 *  - `filter` — `Array.prototype.filter` is in every file, and its argument is a
 *    callback rather than the value.
 *  - `clean`, `check`, `safe` — each is the most common English word in its
 *    neighbourhood (`cleanupTempFiles`, `checkStock`, `safeMode`), and none has
 *    a security reading strong enough to survive being wrong.
 *
 * ★ MEASURED CORRECTION — `strip`, `quote` AND `encode` WERE HERE AND ARE GONE.
 *
 * `quote` cost this rule two of its three corpus findings: `quotePs` in
 * `decolua__9router` is a PowerShell argument quoter, and the value it quotes is
 * a path the code also reads with `fs`. `strip` cost a third shape,
 * `stripTrailingWhitespace`, which is text tidying. Both words name what a
 * function does to a STRING, and only sometimes why.
 *
 * `encode` went with them for the same reason rather than for a measured hit:
 * `encodeCursor`, `encodeState` and `encodeToken` are transport encodings, and
 * the two callees that carry the word and really are defences are named
 * explicitly in `EXACT_TRANSFORMER_CALLEES` instead. Losing `encodeHtml` — a
 * real sanitizer nobody here has a fixture for — is the recall this buys with.
 */
const TRANSFORMER_WORDS: ReadonlySet<string> = new Set([
  'sanitize',
  'sanitise',
  'sanitized',
  'sanitised',
  'sanitizer',
  'sanitiser',
  'escape',
  'escaped',
  'escaping',
  'purify',
  'purified',
]);

/**
 * Words naming a call that returns a VERDICT about the value.
 *
 * `check` is deliberately absent: `checkStock(itemId)` and `checkoutCart(id)`
 * are ordinary.
 *
 * ★ MEASURED CORRECTION — THE ASYMMETRY THIS SET WAS BUILT ON IS FALSE.
 *
 * What stood here was: "a validator is the kind of call that SUPPRESSES a
 * finding when it sits in front of a sink, so a word admitted here too freely
 * does not add false positives — it silently deletes true ones." That is only
 * half of what a validator does in `judge`. A validator BEFORE the sink
 * suppresses; a validator AFTER the sink is REPORTED, as the INVERTED ordering,
 * and it is the strongest report this rule makes. So a word admitted too freely
 * costs precision after the sink and recall before it, and the set is not
 * asymmetric at all.
 *
 * The measurement: `ensure` matched `ensureParentDirectory`, and
 * `validateSkillMetadataVersion` in `JimLiu__baoyu-skills` was reported as a
 * check that ran too late for a file read it has nothing to do with. `ensure`
 * and `assert` are gone — `ensure` is the ordinary word for "make this exist"
 * and `assert` is a Node builtin that appears in every test-adjacent file.
 */
const VALIDATOR_WORDS: ReadonlySet<string> = new Set([
  'validate',
  'validated',
  'validator',
  'valid',
  'verify',
  'verified',
  'allowlist',
  'whitelist',
]);

/**
 * Callees that are transformers without carrying a transformer WORD.
 *
 * The most common real sanitizer in JavaScript is a type coercion:
 * `const page = Number(req.query.page)` makes a value safe for a SQL statement
 * more reliably than most functions with `sanitize` in the name. Leaving them
 * out would not cost recall — a coercion alone establishes no premise, so the
 * rule would simply stay silent — it would cost PRECISION, because a function
 * that coerces one value and escapes another would look like it bypassed its own
 * escaper. Coercions belong here for the on-path test to be able to see them.
 *
 * `String` is deliberately absent. It is the one coercion that makes nothing
 * safe, and treating it as a sanitizer would silence the most ordinary injection
 * there is.
 *
 * `encodeURIComponent` and `encodeURI` join them as EXACT names rather than
 * through the word `encode`, which was removed from `TRANSFORMER_WORDS` above:
 * these two have one meaning, and every other `encodeX` in a codebase has to
 * earn its reading rather than inherit theirs.
 */
const EXACT_TRANSFORMER_CALLEES: ReadonlySet<string> = new Set([
  'number',
  'parseint',
  'parsefloat',
  'bigint',
  'boolean',
  'encodeuricomponent',
  'encodeuri',
]);

/**
 * Callees that carry a vocabulary word and are not the operation it names.
 *
 * `escapeRegExp` escapes a value so it can be embedded in a PATTERN; it says
 * nothing about whether the value is safe for a query, a shell, or a page.
 * Counting it would let an unrelated regex helper establish this rule's premise.
 * `encodeBase64` and friends are transport encodings — reversible by
 * construction, and therefore no defence at all.
 */
const NOT_A_GUARD: ReadonlySet<string> = new Set([
  'escaperegexp',
  'escaperegex',
  'escapestringregexp',
  'encodebase64',
  'base64encode',
  'encodehex',
  'hexencode',
]);

/**
 * Classify one callee.
 *
 * Only the LAST dotted segment is read, so `sanitizers.escapeSql`,
 * `DOMPurify.sanitize` and a bare `escapeSql` are one case rather than three —
 * a helper collected into a namespace object is how real projects hold these
 * functions, and a rule that only recognised bare calls would go quiet on every
 * codebase that tidied them up.
 *
 * Transformer beats validator when a name carries both (`validateAndEscape`),
 * because the transformer reading makes the stronger demand: it requires the
 * result to be the value that reaches the sink, and mis-reading a transformer as
 * a validator would silence a real bypass.
 */
function classifyGuard(callee: string): GuardKind | undefined {
  const last = callee.slice(callee.lastIndexOf('.') + 1);
  const lower = last.toLowerCase();
  if (NOT_A_GUARD.has(lower)) return undefined;
  if (EXACT_TRANSFORMER_CALLEES.has(lower)) return 'transformer';
  const words = identifierWords(last);
  if (words.some((w) => TRANSFORMER_WORDS.has(w))) return 'transformer';
  if (words.some((w) => VALIDATOR_WORDS.has(w))) return 'validator';
  return undefined;
}

/**
 * A call, with an optionally dotted receiver chain.
 *
 * Every quantifier is bounded and every whitespace class is HORIZONTAL
 * (`[^\S\r\n]`, never `\s`), for the reason recorded on `ASSIGN_RE` in
 * `taint/index.ts` and on `CMP` in `scattered-authorization.ts`: unbounded
 * whitespace next to another quantifier is the shape that made this repository's
 * rules super-linear once already (A1).
 */
const CALL_RE =
  /(?:^|[^\w$.])(?<callee>[A-Za-z_$][\w$]{0,60}(?:\.[A-Za-z_$][\w$]{0,60}){0,3})[^\S\r\n]{0,4}\(/g;

/** Calls read from one function body before collection stops. */
const MAX_CALLS_PER_FUNCTION = 400;

/** Characters of a call's argument list that are read. Mirrors taint's bound. */
const MAX_ARG_LENGTH = 600;

/** Characters scanned from a sink's head for the token that opens what it consumes. */
const MAX_SINK_HEAD_SCAN = 120;

/**
 * Hops a flow may carry and still be reported at `high` confidence.
 *
 * Taint's own comment on `TaintFlow.hops` is the argument: a direct flow is
 * almost certainly real, and a long chain is where that module's simplifications
 * are most likely to have lied. Two is "the source, one rename, and the sink",
 * which a reviewer can check against the file in a few seconds.
 */
const MAX_CONFIDENT_HOPS = 2;

/** One recognised security call inside one function body. */
interface GuardCall {
  kind: GuardKind;
  /** The callee as written, dotted receiver included. */
  callee: string;
  /** Offset of the callee's first character, in file content coordinates. */
  offset: number;
  line: number;
  column: number;
  /** The text between its parentheses, read from the blanked copy. */
  argText: string;
}

/** Byte offsets of each line start. Lines are delimited by `\n`. */
function computeLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/**
 * Offset of a 1-based line/column pair.
 *
 * The inverse of the position function in `taint/index.ts`, and it has to agree
 * with it exactly, because every position this rule receives was produced there.
 * Same definition of a line (delimited by `\n`, so a `\r` in CRLF input belongs
 * to the END of the previous line) and same 1-based column, so the round trip is
 * the identity. The test suite checks a reported sink position against the file
 * text rather than trusting this paragraph.
 */
function offsetAt(lineStarts: number[], line: number, column: number): number {
  const index = Math.min(Math.max(line, 1), lineStarts.length) - 1;
  return lineStarts[index]! + Math.max(0, column - 1);
}

function lineAt(lineStarts: number[], offset: number): number {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * The innermost symbol whose body contains `offset`.
 *
 * By CONTAINMENT rather than by `TaintFlow.symbolName`, and the difference
 * matters: an inline route handler is named `<anonymous@18>`, two files can hold
 * a `handler`, and a name lookup would silently pick the wrong body and search
 * the wrong text for sanitizers. Innermost, so a callback's own body wins over
 * the function that registers it — the same choice `analyzeProjectTaint` makes
 * when it attributes a flow.
 */
function enclosingSymbol(structure: StructureIndex, offset: number): IndexedSymbol | undefined {
  let best: IndexedSymbol | undefined;
  for (const symbol of structure.symbols) {
    if (symbol.bodyStart > offset || symbol.bodyEnd <= offset) continue;
    if (best === undefined || symbol.bodyEnd - symbol.bodyStart < best.bodyEnd - best.bodyStart) {
      best = symbol;
    }
  }
  return best;
}

/**
 * The text between a call's parentheses, balanced and bounded.
 *
 * Counted on the BLANKED copy, where a `(` inside a string or a comment is
 * already a space, so `run("(")` cannot desync the depth counter. Reuses the
 * indexer's `blanked` rather than deriving a mask: this function needs to know
 * which identifiers a call was handed, and the one thing the indexer's blanker
 * erases that taint's does not — the interior of a template literal — is a place
 * a sanitizer argument is not written.
 */
function argumentsAt(blanked: string, openParen: number, hardEnd: number): string {
  const start = openParen + 1;
  const limit = Math.min(blanked.length, hardEnd, start + MAX_ARG_LENGTH);
  let depth = 1;
  let i = start;
  for (; i < limit; i += 1) {
    const c = blanked[i];
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  return blanked.slice(start, i);
}

/**
 * The span of the expression a sink CONSUMES, in file content coordinates.
 *
 * Used to tell "the sanitizer is applied INSIDE the sink" from "the sanitizer
 * runs after the sink". Both sit at a greater offset than the sink's head, and
 * treating the first as the second would report `db.query(escapeSql(x))` as
 * sanitising after use — an accusation the code refutes on the same line.
 *
 * ★ TWO SINK FORMS, AND THE SECOND ONE IS NOT AN AFTERTHOUGHT.
 *
 * `SinkSpec.form` in `taint/index.ts` is `call` or `assign`, and the assign form
 * (`el.innerHTML = value`) is the one this function gets wrong if it only ever
 * looks for a parenthesis: the first `(` on that line belongs to the SANITIZER
 * (`el.innerHTML = escapeHtml(name)`), so the span would start after it and the
 * sanitizer would fall outside its own sink — reported as running "after" it.
 * That is a false positive on correctly written code, which is the failure this
 * repository treats as a bug. So the scan stops at whichever comes first, `(` or
 * `=`, and the assign form's span is the right-hand side, bounded the way
 * `taint` bounds it: at the first `;` or line terminator.
 *
 * A call sink cannot be mistaken for an assign one, because the parenthesis
 * follows the callee immediately (at most four horizontal spaces, per the sink
 * patterns) and there is nowhere for an `=` to appear in between.
 */
function sinkArgumentSpan(
  blanked: string,
  sinkOffset: number,
  bodyEnd: number,
): { start: number; end: number } {
  const headLimit = Math.min(blanked.length, bodyEnd, sinkOffset + MAX_SINK_HEAD_SCAN);
  let i = sinkOffset;
  while (i < headLimit && blanked[i] !== '(' && blanked[i] !== '=' && blanked[i] !== '\n') i += 1;
  if (i >= headLimit) return { start: sinkOffset, end: sinkOffset };
  if (blanked[i] === '(') {
    const args = argumentsAt(blanked, i, bodyEnd);
    return { start: i + 1, end: i + 1 + args.length };
  }
  if (blanked[i] !== '=') return { start: sinkOffset, end: sinkOffset };
  const start = i + 1;
  const limit = Math.min(blanked.length, bodyEnd, start + MAX_ARG_LENGTH);
  let end = start;
  while (end < limit && blanked[end] !== ';' && blanked[end] !== '\n') end += 1;
  return { start, end };
}

/**
 * Every recognised security call inside one function body.
 *
 * Read from the blanked copy so a call written inside a comment
 * (`// remember to escapeHtml(name)`) or quoted in a string is not evidence that
 * the code does anything. That is the conservative direction here: a comment is
 * not a call, and counting one would let a stale TODO establish this rule's
 * premise.
 *
 * What it does NOT see is recorded as the last KNOWN GAP in the header: a callee
 * written as the direct first argument of another call.
 */
function guardCallsIn(structure: StructureIndex, symbol: IndexedSymbol, lineStarts: number[]): GuardCall[] {
  const body = structure.blanked.slice(symbol.bodyStart, symbol.bodyEnd);
  const calls: GuardCall[] = [];
  CALL_RE.lastIndex = 0;
  let seen = 0;
  for (let m = CALL_RE.exec(body); m && seen < MAX_CALLS_PER_FUNCTION; m = CALL_RE.exec(body)) {
    seen += 1;
    if (CALL_RE.lastIndex === m.index) CALL_RE.lastIndex += 1;
    const callee = m.groups?.callee;
    if (callee === undefined) continue;
    const kind = classifyGuard(callee);
    if (kind === undefined) continue;
    // Anchored PAST the boundary character the pattern consumed, for the reason
    // `collectEvents` in taint/index.ts records: `(?:^|[^\w$.])` eats the newline
    // that ended the previous line, so an unadjusted index names the line ABOVE
    // the call — and this rule asks the reader to compare line numbers.
    const leading = m[0].length - m[0].replace(/^[^\w$.]/, '').length;
    const offset = symbol.bodyStart + m.index + leading;
    const openParen = symbol.bodyStart + m.index + m[0].length - 1;
    const line = lineAt(lineStarts, offset);
    calls.push({
      kind,
      callee,
      offset,
      line,
      column: offset - lineStarts[line - 1]! + 1,
      argText: argumentsAt(structure.blanked, openParen, symbol.bodyEnd),
    });
  }
  return calls;
}

/**
 * The names by which a flow's value can be referred to.
 *
 * Every hop, plus the source's own token WHEN THAT TOKEN IS A BARE IDENTIFIER.
 *
 * ★ A DOTTED SOURCE TOKEN IS EXCLUDED, AND A MUTATION IS WHY.
 *
 * `TaintSource.name` is the canonical source expression — `req.query`,
 * `process.env`, or the bare name of a parameter source. The first version of
 * this function included it unconditionally, and the mutation that removes the
 * whole "written for THIS value" premise (`qualifying = guards.slice()`) left
 * every test green, which means no fixture was pinning the premise. Writing the
 * fixture that should have — a sanitizer applied to a DIFFERENT request value —
 * showed why: `\breq\.query\b` matches inside `escapeHtml(req.query.label)`,
 * because the `.` after `query` satisfies the word boundary. A dotted token
 * names the OBJECT the value came off, so it cannot distinguish two values read
 * from the same request, and admitting it turned the premise back into
 * "a sanitizer exists nearby" — the mistake definition 3 in the header was
 * refused for.
 *
 * A parameter source (`input`, `userInput`) is a bare identifier and has no such
 * problem, so it stays.
 *
 * The cost is a false negative with a name: a DIRECT flow from a dotted source
 * (`db.query(req.query.id)`, no hops) can no longer establish the premise at
 * all, because nothing on its chain has a name. The shape that would have fired
 * — the same expression sanitised elsewhere in the function — is one where the
 * author wrote no variable for a value they use twice, and it is worth less than
 * the precision it costs. `smell-041-other-value/` is the fixture.
 */
function chainNames(flow: TaintFlow): string[] {
  const names = new Set<string>();
  if (!flow.source.name.includes('.')) names.add(flow.source.name);
  for (const hop of flow.hops) names.add(hop.name);
  return [...names].sort();
}

/**
 * Whether `text` uses `name` as a BARE token — the value itself, never a
 * property of it.
 *
 * ★ THE NARROWING THAT CLOSED THE FOURTH CORPUS FALSE POSITIVE, and the reason
 * `\b` was the wrong boundary to have used.
 *
 * `\boptions\b` matches inside `options.version`, because `.` is a non-word
 * character and satisfies a word boundary on both sides. So a chain whose hop is
 * an OBJECT — `options`, `opts`, `params`, `ctx`, every accumulator a CLI or a
 * handler builds — made every statement that touched any of its fields look like
 * a statement written for the value that flowed. `JimLiu__baoyu-skills` reads
 * `options.changelogFile` at the sink and validates `options.version` three lines
 * later, and the two have nothing to do with each other.
 *
 * A trailing `.` therefore disqualifies a mention: `options.version` names a
 * property, and this rule's premise is about a VALUE. The leading side uses the
 * `(?:^|[^\w$.])` idiom rather than a lookbehind, matching `SOURCE_RE` and
 * `ASSIGN_RE` in `taint/index.ts`, so `sanitized.term` does not match `term`
 * either.
 *
 * The cost is a false negative with a name: `escapeHtml(user.name)` protecting a
 * value the sink consumes as `user.name` is invisible, because H1 does not track
 * property flows and this rule will not pretend it can. Recovering it needs
 * property-sensitive taint, not a wider regex.
 *
 * Neither quantifier is unbounded and no whitespace class appears, so the D3
 * three-second contract holds by construction.
 */
function mentionsBare(text: string, name: string): boolean {
  // Every name reaching here is a bare identifier — `ASSIGN_RE` binds hop names
  // from `[A-Za-z_$][\w$]{0,60}` and `chainNames` drops dotted source tokens —
  // so nothing in this set carries a regex metacharacter today. The escape
  // stays, because building a pattern out of data without escaping is the habit
  // that eventually meets a name that does.
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(String.raw`(?:^|[^\w$.])${escaped}(?![\w$.])`).test(text);
}

/** Whether `text` uses any of `names` bare. */
function mentionsAnyBare(text: string, names: string[]): boolean {
  return names.some((n) => mentionsBare(text, n));
}

/**
 * Characters walked between two offsets before the block test gives up.
 *
 * A body is already capped at 50,000 by the indexer, so this is not a second
 * safety net against pathological input — it is a statement that two points
 * twenty thousand characters apart are not two statements a reader would call
 * adjacent, and the honest verdict for them is "cannot tell".
 */
const MAX_BLOCK_SCAN = 20_000;

/**
 * Whether two offsets sit inside the SAME brace block.
 *
 * ★ THE LEXICAL STAND-IN FOR "ON THE SAME EXECUTION PATH", and the condition
 * that removes the worst false positive this rule ever produced.
 *
 * There is no control-flow graph on this layer and there will not be one; see
 * `types.ts` on why no parser is taken. The question a finding needs answered is
 * "could the guard have run on the path the sink ran on", which is a question
 * about DOMINANCE. What can be answered from text is "do the two statements lie
 * in one block", and that is a strict under-approximation: two statements in one
 * block are sequenced, and two statements in different blocks may be in exclusive
 * branches. Under-approximating is the right direction — it costs findings and
 * cannot invent them.
 *
 * Counted on the BLANKED copy, where a brace inside a string or a comment is
 * already a space.
 *
 * ★ MEASURED — A TEMPLATE INTERPOLATION IS NOT A BLOCK, AND THE FIRST VERSION
 * OF THIS FUNCTION COUNTED IT AS ONE.
 *
 * The indexer's blanker erases a template's literal TEXT and leaves the `${…}`
 * expression intact, so `` res.send(`<h1>${escapeHtml(id)}</h1>`) `` contributes
 * a real `{` to this walk. A guard written inside an interpolation therefore
 * came out one level "deeper" than a sink that preceded it, and the function
 * answered "different block" for two statements that are plainly sequential.
 *
 * That was found by mutation rather than by reading: removing
 * `sinkIsParameterized` entirely left the whole suite GREEN, because
 * `smell-041-parameterized/` was being kept quiet by this bug instead of by the
 * condition it was written to pin. A check that passes for the wrong reason is a
 * check nobody is testing, so the brace stack below distinguishes an
 * interpolation brace (`{` immediately preceded by `$`) from a block brace and
 * counts only the second.
 *
 * An OBJECT-LITERAL brace is still counted as a block, and cannot be told apart
 * from one without a parser. `db.query(x); res.json({ safe: escape(x) })` is
 * therefore a false negative — the same direction as every other bound here.
 *
 * Returns false — "cannot tell", i.e. silence — when the walk exceeds its bound.
 */
function sameBlock(blanked: string, a: number, b: number): boolean {
  const from = Math.min(a, b);
  const to = Math.max(a, b);
  if (to - from > MAX_BLOCK_SCAN) return false;
  let depth = 0;
  // One entry per brace opened INSIDE the walk, recording whether it opened an
  // interpolation. Braces opened before `from` are not on it, which is why the
  // `}` branch falls back to treating an unmatched close as a block close — that
  // is exactly the "we left the enclosing block" case.
  const opened: boolean[] = [];
  for (let i = from; i < to; i += 1) {
    const c = blanked[i];
    if (c === '{') {
      const interpolation = i > 0 && blanked[i - 1] === '$';
      opened.push(interpolation);
      if (!interpolation) depth += 1;
    } else if (c === '}') {
      if (opened.length > 0 && opened.pop() === true) continue;
      // Left the block the earlier offset was in. Whatever the later offset is
      // in, it is not this one — a sibling branch, or the enclosing body.
      depth -= 1;
      if (depth < 0) return false;
    }
  }
  // Ending above zero means the later offset is NESTED inside a block the
  // earlier one merely preceded (`db.query(x); if (c) { escape(x); }`), which is
  // conditional protection this layer cannot reason about either.
  return depth === 0;
}

/**
 * Placeholder tokens a parameterised statement writes in place of a value.
 *
 * `?` (MySQL, SQLite, better-sqlite3), `$1` (Postgres, pg), `:name` (named
 * binds, Sequelize, Oracle). Every alternative is a fixed prefix followed by a
 * bounded run, so the pattern cannot backtrack.
 */
const PLACEHOLDER_RE = /\$\d{1,3}|\?|:[A-Za-z_][\w$]{0,40}/g;

/**
 * Whether the sink received the tainted value as a BOUND PARAMETER rather than
 * as part of the statement.
 *
 * ★ WHY THIS IS DECIDABLE HERE WHEN IT IS NOT DECIDABLE IN H1.
 *
 * `analyzeProjectTaint` reports a flow into `db.query('… WHERE id = $1', [id])`
 * because `id` appears in the argument list. That is correct for what H1
 * promises — the value reaches the call — and it is not what this rule needs to
 * know, which is whether the value reached the STATEMENT. Reading the sink's
 * first argument answers it:
 *
 *  - the argument list has a top-level comma, so there IS a second argument for
 *    parameters to be passed in;
 *  - no name on the flow's chain appears bare in the first argument, so the
 *    value was not interpolated or concatenated into the statement;
 *  - the first argument contains a placeholder token that was INSIDE a string
 *    literal.
 *
 * The last test is the one worth explaining. Blanking is length-preserving by
 * construction, so a character that is `$` in `SourceFile.content` and a space in
 * `StructureIndex.blanked` was inside a literal — which distinguishes the `?` of
 * `'WHERE id = ?'` from the `?` of a ternary, and the `:name` of a named bind
 * from the `:` of an object literal, without lexing anything. Neither text alone
 * can make that distinction; the pair can.
 *
 * A false answer here means silence on a genuinely mis-ordered statement, which
 * is this rule's accepted failure direction. A missing answer means the earlier
 * behaviour: reporting the single most common correct database call in the
 * ecosystem, whichever order its neighbours were written in.
 */
function sinkIsParameterized(
  blanked: string,
  content: string,
  span: { start: number; end: number },
  names: string[],
): boolean {
  const region = blanked.slice(span.start, span.end);
  let depth = 0;
  let comma = -1;
  for (let i = 0; i < region.length; i += 1) {
    const c = region[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) {
      comma = i;
      break;
    }
  }
  // One argument means there is nowhere for a bound parameter to be passed, so
  // the value is in the statement or it is not there at all.
  //
  // ★ AN EQUIVALENT MUTANT, AND THE PROOF RATHER THAN THE HOPE. Mutating this to
  // `comma = region.length` leaves the whole suite green, and it must: `judge`
  // has already established `mentionsAnyBare(sinkText, names)` before it calls
  // this, `sinkText` IS `region`, so a `head` covering the whole region satisfies
  // the very next line and returns `false` anyway. The early return is kept
  // because it makes this function's contract independent of its caller's gate
  // order, not because a test can tell the difference.
  if (comma < 0) return false;
  const head = region.slice(0, comma);
  if (mentionsAnyBare(head, names)) return false;

  const original = content.slice(span.start, span.start + comma);
  PLACEHOLDER_RE.lastIndex = 0;
  for (let m = PLACEHOLDER_RE.exec(original); m; m = PLACEHOLDER_RE.exec(original)) {
    if (PLACEHOLDER_RE.lastIndex === m.index) PLACEHOLDER_RE.lastIndex += 1;
    if (region[m.index] === ' ') return true;
  }
  return false;
}

/**
 * Severity by what the sink does.
 *
 * `query`/`exec`/`eval` hand the value to an interpreter, where an unsanitised
 * value is directly exploitable and the consequence is the whole process.
 * `response` and `file` are context-dependent — a response sink may be emitting
 * JSON, and a file sink may sit under a fixed base directory — so they stay at
 * `medium`. This is the same posture the Security Context Boost takes in
 * VG-SMELL-010: a severity that is `high` for everything the rule emits is not a
 * severity, and the safe direction for the field to be wrong in is downward.
 */
const HIGH_SEVERITY_SINKS: ReadonlySet<SinkKind> = new Set<SinkKind>(['query', 'exec', 'eval']);

/** Which ordering is wrong. */
type Ordering = 'inverted' | 'bypassed';

interface Verdict {
  ordering: Ordering;
  /** The calls that establish the premise, sorted by position. */
  guards: GuardCall[];
}

/**
 * Decide whether one flow is a finding, and which ordering it is.
 *
 * Written as one function returning `undefined` for "no claim" so that every
 * negative condition sits in one place and can be read top to bottom. Each
 * `return undefined` below is pinned by a directory under
 * `samples/crossfile-fixtures/smell-041-*`.
 */
function judge(
  flow: TaintFlow,
  guards: GuardCall[],
  sinkOffset: number,
  sinkSpan: { start: number; end: number },
  blanked: string,
  content: string,
): Verdict | undefined {
  const names = chainNames(flow);
  const inSink = (g: GuardCall): boolean => g.offset >= sinkSpan.start && g.offset < sinkSpan.end;
  const sinkText = blanked.slice(sinkSpan.start, sinkSpan.end);

  // ── The sink consumed THE VALUE, not a property of it. ─────────────────────
  //
  // ★ MEASURED. H1 reports a flow whenever a tainted identifier appears in the
  // sink's argument list, and `fs.readFile(path.resolve(options.changelogFile))`
  // qualifies because `options` is on the chain. What arrived there is a FIELD
  // of the value that flowed, which this layer knows nothing about: it does not
  // track property writes, so it cannot say the field is tainted and cannot say
  // it is clean. Reporting on it means reporting on a value the analysis never
  // followed. `smell-041-object-hop/` is the corpus case, reduced.
  if (!mentionsAnyBare(sinkText, names)) return undefined;

  // ── The value was BOUND, not interpolated. ────────────────────────────────
  //
  // A placeholder statement with the value passed alongside it is the correct
  // shape, not a mis-ordered one — and it is the shape this rule's own
  // `exampleFix` recommends, which is how badly the first version had this
  // backwards. `smell-041-parameterized/` holds both orders, because the first
  // version fired on both. See `sinkIsParameterized`.
  if (sinkIsParameterized(blanked, content, sinkSpan, names)) return undefined;

  // ── Premise: a security operation written FOR THIS VALUE. ──────────────────
  // Without one there is no ordering to be wrong, and the finding would be an
  // injection report wearing a design-smell hat.
  //
  // Two fixtures, because there are two ways to fail it and they fail it in
  // different places: `smell-041-no-sanitizer/` has no security operation at all
  // (caught earlier, by `guards.length === 0` in `analyze`), and
  // `smell-041-other-value/` has one that was written for a different value —
  // which is this line, and which nothing pinned until a mutation said so.
  const qualifying = guards.filter((g) => mentionsAnyBare(g.argText, names));
  if (qualifying.length === 0) return undefined;

  // ── The value is sanitised at the point of use. ────────────────────────────
  //
  // ★ THIS TEST WAS WRITTEN TWICE, AND THE FIRST VERSION RESTED ON A BELIEF
  // THAT MEASUREMENT CONTRADICTED.
  //
  // The header of `taint/index.ts` states that the indexer's blanker "blanks
  // template-literal interiors WHOLESALE", so that `` `... ${id}` `` loses the
  // `${id}`. If that were so, an inline sanitizer written inside a template —
  // `` res.send(`<p>${escapeHtml(name)}</p>`) `` — would be invisible to any
  // scan reading `StructureIndex.blanked`, and this check would have to read the
  // sink's ORIGINAL text off `TaintSink.expression` instead. It was implemented
  // that way first.
  //
  // MEASURED 2026-08-02, by dumping `structure.blanked` for
  // `smell-041-inline-at-sink/profile.ts`:
  //
  //   "res.send(`    ${escapeHtml(nickname)}     `);"
  //
  // The literal TEXT of the template is blanked and the `${…}` expression
  // survives intact — the current `blankJsLiterals` returns to `code` state
  // inside an interpolation (`tplReturnDepth` in `matcher-utils.ts`). So the
  // original-text fallback that belief justified was DEAD CODE dressed as a
  // safety net: mutating it out left the whole suite green (36 tests at the
  // time). It is deleted rather than kept "just in case", because an
  // unfalsifiable check is worse than no check — it makes the next reader
  // believe a case is covered.
  //
  // The record stays because the claim it corrects is still written in
  // `taint/index.ts`, whose own `restoreTemplateInterpolations` is presumably a
  // no-op for the same reason. Neither is this rule's file to edit; see the
  // handoff.
  //
  // `smell-041-inline-at-sink/` (call form) and `smell-041-inline-innerhtml/`
  // (assign form) are the two fixtures that start firing the day this one line
  // stops working — and they cover different halves of `sinkArgumentSpan`, so
  // neither can stand in for the other.
  if (guards.some((g) => inSink(g) && g.kind === 'transformer')) return undefined;

  // ── The flow passed THROUGH a transformer. ────────────────────────────────
  // `TaintFlow.hops` reports a line per assignment, so "the transformed copy
  // became a hop" is "a transformer sits on a hop's line". Every guard is
  // considered here, not only the qualifying ones: a call on a hop's line
  // produced that hop's value by construction, whatever its argument text
  // happens to name. `smell-041-sanitize-first/`, `smell-041-helper-guard/`.
  const hopLines = new Set(flow.hops.map((h) => h.line));
  if (guards.some((g) => g.kind === 'transformer' && hopLines.has(g.line))) return undefined;

  const outside = qualifying.filter((g) => !inSink(g));

  // ── A validator ran before the use. ───────────────────────────────────────
  // A verdict-returning call produces no value to route through, so its correct
  // wiring is exactly "it comes first" — and it does. See the header for why
  // this is a suppression rather than a finding. `smell-041-validate-first/`.
  //
  // The suppression is deliberately NOT subject to the block test below. A
  // suppressing guard in a sibling branch still means the author wrote the check
  // and this layer cannot prove it does not apply; refusing to accept it would
  // turn an uncertainty into a finding, and uncertainty here has to resolve to
  // silence. Only the guards a finding CITES have to survive `sameBlock`.
  if (outside.some((g) => g.kind === 'validator' && g.offset < sinkOffset)) return undefined;

  // ── The cited guard must sit in the sink's own block. ─────────────────────
  //
  // ★ THE CONDITION THAT MADE THIS RULE SHIPPABLE. Without it, an offset
  // comparison reports the `else` branch of an `if` as code that "runs after"
  // the `if` branch — measured twice in one file of `decolua__9router`, and the
  // very failure definition 2 in the header refuses guard-clause ordering for.
  // `smell-041-exclusive-branches/` is that file, reduced.
  const reportable = outside.filter((g) => sameBlock(blanked, sinkOffset, g.offset));

  const after = reportable.filter((g) => g.offset > sinkOffset);
  const bypassed = reportable.filter((g) => g.kind === 'transformer' && g.offset < sinkOffset);
  // The TOTALITY case of the filters above, and since `sameBlock` was added it
  // is the line that carries the exclusive-branch verdict: a guard the block test
  // rejected leaves both sets empty and the rule says nothing.
  // `smell-041-exclusive-branches/` is what turns red the day the filter above
  // stops filtering.
  if (after.length === 0 && bypassed.length === 0) return undefined;

  // INVERTED wins when both are present. "The security operation runs after the
  // sink, in the same block" is decidable from two offsets and a brace count,
  // while BYPASSED rests on the hop chain being complete — so when the evidence
  // supports both readings, the report makes the claim that needs less.
  const ordering: Ordering = after.length > 0 ? 'inverted' : 'bypassed';
  const cited = ordering === 'inverted' ? after : bypassed;
  return { ordering, guards: [...cited].sort((a, b) => a.offset - b.offset) };
}

function describe(flow: TaintFlow, verdict: Verdict): string {
  const path = flow.filePath;
  const guardList = verdict.guards
    .map((g) => `\`${g.callee}(…)\` at ${path}:${g.line}`)
    .join(', ');
  const chain =
    flow.hops.length === 0
      ? 'directly'
      : `through ${flow.hops.map((h) => `\`${h.name}\` (line ${h.line})`).join(' → ')}`;

  const opening =
    `The value read from \`${flow.source.name}\` at ${path}:${flow.source.line} reaches ` +
    `\`${flow.sink.name}\` at ${path}:${flow.sink.line} ${chain}. `;

  return verdict.ordering === 'inverted'
    ? opening +
        `The security operation written for that value — ${guardList} — runs AFTER the sink, so ` +
        `it cannot have protected this use of it. Nothing in the structure of \`${flow.symbolName}\` ` +
        `requires the two to be in the other order; only the order they were typed in does.`
    : opening +
        `A security operation written for that value — ${guardList} — runs first and produces a ` +
        `safe copy that this sink does not use: the value that arrives is the untransformed one. ` +
        `The statements are in the right order on the page and the data is not, which is why ` +
        `reading \`${flow.symbolName}\` top to bottom makes it look correct.`;
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project, budget } = ctx;

  // Checked at the phase boundary, before the dataflow pass rather than inside
  // it — and the call is not merely a guard. `createBudget().expired()` RECORDS
  // the deadline degradation on its way out, so an exhausted budget leaves a
  // scan that says "results are partial" instead of one that says "clean". A
  // silent `return []` here would produce exactly the failure `budget.ts` names
  // as the worse of the two.
  if (budget.expired()) return [];

  const sourceByPath = new Map(project.files.map((f) => [f.filePath, f]));
  const structures: StructureIndex[] = [];
  const files: SourceFile[] = [];

  // Sorted, so the flow list — and therefore every finding derived from it — is
  // the same on every run and every filesystem.
  for (const filePath of [...project.structures.keys()].sort()) {
    const structure = project.structures.get(filePath)!;
    // PER-FILE language filter, for the reason `collectScatteredAuthSites`
    // records: `runCrossFileRules` gates at the PROJECT level, which is the
    // right question for whether to run a rule and the wrong one for which files
    // it may read. A polyglot repository would otherwise hand this rule Python
    // files that H1 declines to analyse anyway — see `SUPPORTED_LANGUAGES` in
    // `taint/index.ts` for why that refusal is deliberate.
    if (!temporalSecurityCoupling.languages.includes(structure.language)) continue;
    if (TEST_PATH.test(filePath)) continue;
    const file = sourceByPath.get(filePath);
    if (!file) continue;
    structures.push(structure);
    files.push(file);
  }
  if (structures.length === 0) return [];

  const flows = analyzeProjectTaint(structures, files);
  if (flows.length === 0) return [];

  const structureByPath = new Map(structures.map((s) => [s.filePath, s]));
  const fileByPath = new Map(files.map((f) => [f.filePath, f]));
  const lineStartsByPath = new Map<string, number[]>();
  const guardsBySymbol = new Map<IndexedSymbol, GuardCall[]>();

  const findings: CrossFileFinding[] = [];

  for (const flow of flows) {
    const structure = structureByPath.get(flow.filePath);
    const file = fileByPath.get(flow.filePath);
    if (!structure || !file) continue;

    let lineStarts = lineStartsByPath.get(flow.filePath);
    if (!lineStarts) {
      lineStarts = computeLineStarts(file.content);
      lineStartsByPath.set(flow.filePath, lineStarts);
    }

    const sinkOffset = offsetAt(lineStarts, flow.sink.line, flow.sink.column);
    /**
     * UNREACHABLE BY CONSTRUCTION, AND KEPT ANYWAY — which is a different claim
     * from the dead check deleted in `judge`, so the difference is worth stating.
     *
     * `analyzeProjectTaint` only ever reports a sink from inside some symbol's
     * body, so a symbol containing this offset exists — UNLESS the round trip
     * from taint's line/column back to an offset disagrees with taint's own
     * definition of a line. That is a contract between two modules, not a belief
     * about a code shape, and it is pinned directly: the suite asserts a reported
     * sink line against the file text on CRLF input, where a disagreement would
     * first appear.
     *
     * The deleted check was written for a condition believed to occur and could
     * be shown never to; this one is a floor under a cross-module invariant whose
     * violation would otherwise be a wrong line number in a report that asks the
     * reader to check line numbers. Making no claim is the honest outcome:
     * searching an invented span for sanitizers would produce evidence nobody can
     * check.
     */
    const symbol = enclosingSymbol(structure, sinkOffset);
    if (!symbol) continue;

    let guards = guardsBySymbol.get(symbol);
    if (!guards) {
      guards = guardCallsIn(structure, symbol, lineStarts);
      guardsBySymbol.set(symbol, guards);
    }
    // ★ A SECOND EQUIVALENT MUTANT, also proven rather than assumed: a body with
    // no recognised security call produces an empty `qualifying` set inside
    // `judge` and no verdict, so deleting this line changes the output of
    // nothing. It is a short-circuit — `judge` does three text scans this skips —
    // and it is labelled so nobody adds a fixture trying to pin it.
    if (guards.length === 0) continue;

    const sinkSpan = sinkArgumentSpan(structure.blanked, sinkOffset, symbol.bodyEnd);
    // Both texts, because two of `judge`'s conditions can only be decided by
    // comparing them: a placeholder is a character that the blanker replaced and
    // the original kept. See `sinkIsParameterized`.
    const verdict = judge(flow, guards, sinkOffset, sinkSpan, structure.blanked, file.content);
    if (!verdict) continue;

    const severity: Severity = HIGH_SEVERITY_SINKS.has(flow.sink.kind) ? 'high' : 'medium';

    /**
     * Confidence, and the one place the two orderings are not treated alike.
     *
     * `high` is reserved for an INVERTED flow with a short chain, because that
     * is the only combination where the lexical uncertainty stops mattering:
     * two offsets decide the ordering, and a chain of at most two hops is one a
     * reviewer verifies by looking at the lines. BYPASSED is capped at `medium`
     * however short the chain, and the reason is specific rather than cautious —
     * its claim is "the transformed copy is not the value that arrived", which
     * is exactly what an INCOMPLETE chain also looks like. H1 does not follow
     * property writes or compound assignment, so a flow that really did pass
     * through the sanitizer by a route taint cannot see is indistinguishable
     * from one that dodged it. That is a stated gap in `taint/index.ts`, and a
     * `high` here would be this rule claiming past it.
     */
    const confidence: Confidence =
      verdict.ordering === 'inverted' && flow.hops.length <= MAX_CONFIDENT_HOPS ? 'high' : 'medium';

    const sinkLocation: CodeLocation = {
      filePath: flow.filePath,
      startLine: flow.sink.line,
      endLine: flow.sink.line,
      startColumn: flow.sink.column,
      evidence: `${flow.sink.kind} sink: ${flow.sink.expression}`,
    };

    /**
     * The taint path, as locations, in the order a reader follows it: where the
     * value entered, every assignment it travelled through, then the security
     * operation that missed it. `primaryLocation` is the SINK — the place the
     * damage happens and the place an editor should open — so it is not repeated
     * here, per `DesignSmellFinding.relatedLocations`.
     *
     * This list is the reason #26 (H1 taint) is load-bearing rather than
     * decorative: without it the finding says "this looks mis-ordered", and with
     * it the finding says "this value, from here, through here, arrived there",
     * which a reviewer can refute in three seconds if it is wrong.
     *
     * Deterministic by construction — the source, then the hops in flow order
     * (ascending by position, since a hop is an assignment the sweep passed),
     * then the guards sorted by offset — and asserted rather than assumed in the
     * test suite.
     */
    const relatedLocations: CodeLocation[] = [
      {
        filePath: flow.filePath,
        startLine: flow.source.line,
        startColumn: flow.source.column,
        evidence: `tainted source: ${flow.source.expression}`,
      },
      ...flow.hops.map((hop) => ({
        filePath: flow.filePath,
        startLine: hop.line,
        evidence: `assigned to \`${hop.name}\``,
      })),
      ...verdict.guards.map((g) => ({
        filePath: flow.filePath,
        startLine: g.line,
        startColumn: g.column,
        evidence:
          verdict.ordering === 'inverted'
            ? `${g.kind} \`${g.callee}\` runs after the sink`
            : `${g.kind} \`${g.callee}\` produces a value the sink does not use`,
      })),
    ];

    findings.push({
      ruleId: 'VG-SMELL-041',
      title: 'Temporal Security Coupling',
      description: describe(flow, verdict),
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      /**
       * `symbol`, not `project` or `line`. The finding is a statement about one
       * function — every location it cites lies inside one body, by H1's
       * construction — and the fix is a rewrite of that function's order, not an
       * edit at the sink line. That distinction is what tells a suppression
       * channel whether `vibeguard:disable-next-line` is even a coherent request
       * here; see `DesignSmellScope`.
       */
      scope: 'symbol',
      filePath: flow.filePath,
      startLine: flow.sink.line,
      endLine: flow.sink.line,
      startColumn: flow.sink.column,
      evidence: [
        `${flow.filePath}:${flow.source.line} source ${flow.source.name}`,
        ...flow.hops.map((h) => `${flow.filePath}:${h.line} hop ${h.name}`),
        `${flow.filePath}:${flow.sink.line} sink ${flow.sink.name} (${flow.sink.kind})`,
        ...verdict.guards.map(
          (g) =>
            `${flow.filePath}:${g.line} ${g.kind} ${g.callee} ` +
            `${verdict.ordering === 'inverted' ? 'after the sink' : 'bypassed'}`,
        ),
      ],
      primaryLocation: sinkLocation,
      relatedLocations,
      /**
       * `fanIn`/`fanOut` come from `metrics-calculator` and the body numbers from
       * `symbolMetrics`, for the reason VG-AISC-003 records: a reader comparing
       * this finding with any other must be reading one definition of each, and
       * a rule that counted privately is how two findings in one report end up
       * disagreeing about a number they both call `fanIn`.
       */
      metrics: mergeMetrics(fanMetrics(flow.filePath, project.graph), symbolMetrics(symbol, file)),
      /**
       * One flag, and only one. `containsValidationLogic` is established by the
       * rule's own premise — it found the validation or sanitisation call and
       * cites its line.
       *
       * `containsSensitiveDataFlow` is deliberately NOT set, although a dataflow
       * is precisely what this rule computed. The flag names the sensitivity of
       * the DATA; what was established here is the untrustworthiness of its
       * ORIGIN, which is a different property. Setting it would be this rule
       * asserting something about the value's contents that it never looked at,
       * and `SecurityContext` is explicit that absent means "did not look".
       */
      securityContext: { containsValidationLogic: true },
      /**
       * No `cross-file` tag. Every location cited here is inside one function
       * body — see the header for why the rule nonetheless lives in this
       * package. Claiming the tag would be claiming evidence.
       */
      tags: ['design-smell', 'taint', 'ai-prone', 'ordering'],
      remediation: {
        why:
          'A security operation whose effect depends on where it sits relative to another ' +
          'statement is protection that the next edit can remove without touching it. Both ' +
          'orderings read as correct code: the call is present, it is right, and the review ' +
          'artefacts all say the value is handled.',
        how:
          verdict.ordering === 'inverted'
            ? `Move \`${verdict.guards[0]!.callee}\` above ${flow.filePath}:${flow.sink.line} and pass ` +
              'its result — or its verdict — to the sink, so the protection cannot be reordered ' +
              'away. Where the check only rejects, return on failure before the sink runs.'
            : `Pass the result of \`${verdict.guards[0]!.callee}\` to ${flow.sink.name} instead of the ` +
              'raw value, and stop keeping both around: a function that holds a safe copy and an ' +
              'unsafe original next to each other will eventually use the wrong one again.',
        exampleFix:
          'const safe = sanitize(req.query.value);\n' +
          'db.query(`SELECT * FROM t WHERE c = ?`, [safe]);\n' +
          '// The sanitised value is the only one in scope at the sink.',
      },
    });
  }

  /**
   * Explicit total order over the output.
   *
   * The input is already deterministic — sorted structures, taint's own
   * deterministic walk — so this sort changes nothing today and is written
   * anyway: it makes the ordering a property of THIS file rather than a property
   * inherited from two others, and a baseline that tracks findings by position
   * cannot afford to depend on a guarantee that lives somewhere else.
   */
  findings.sort((a, b) => {
    if (a.filePath !== b.filePath) return (a.filePath ?? '') < (b.filePath ?? '') ? -1 : 1;
    if (a.startLine !== b.startLine) return (a.startLine ?? 0) - (b.startLine ?? 0);
    if (a.startColumn !== b.startColumn) return (a.startColumn ?? 0) - (b.startColumn ?? 0);
    const aSource = a.relatedLocations?.[0];
    const bSource = b.relatedLocations?.[0];
    return (aSource?.startLine ?? 0) - (bSource?.startLine ?? 0);
  });

  return findings;
}

/**
 * ONE FINDING PER FLOW, NOT PER SINK — and the alternative was written out
 * before it was rejected.
 *
 * Grouping by sink reads better when a sink is fed by two dodging values: one
 * place, one fix, one finding. It was refused because a group has to carry ONE
 * severity and ONE confidence for flows whose chains differ in length, and chain
 * length is exactly what this rule's confidence is derived from — so grouping
 * would either over-claim on the long flow or under-claim on the short one, and
 * a reader could not tell which. Per-flow findings keep every reported chain
 * paired with the confidence that chain earned. The cost is duplicate primary
 * lines in the rare two-source case, which a report can collapse and a scoring
 * model cannot un-merge.
 */
export const temporalSecurityCoupling: CrossFileRule = {
  ruleId: 'VG-SMELL-041',
  name: 'Temporal Security Coupling',
  description:
    'A tainted value reaches a sink without the sanitizer or validator written for it having ' +
    'applied — either because that operation runs after the sink, or because its result is not ' +
    'the value the sink received.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'high',
  defaultConfidence: 'medium',
  /**
   * TS/JS only, ENFORCED — both by `runCrossFileRules` at the project level and
   * per file in `analyze`.
   *
   * This is not a policy choice this rule gets to make. Its entire input is
   * `analyzeProjectTaint`, whose `SUPPORTED_LANGUAGES` is `javascript` and
   * `typescript` and which returns `[]` for everything else on purpose — the
   * sink vocabulary does not carry over to Python, where `execute` on a cursor
   * is the same word as `execute` on a thread pool. Listing a language here that
   * H1 declines to analyse would make the field a fiction of the kind
   * `runCrossFileRules` was changed to stop tolerating: a declaration that
   * creates a belief and does nothing.
   */
  languages: ['typescript', 'javascript'],
  /**
   * CWE-696 is the ordering claim itself ("Incorrect Behavior Order"), and it is
   * the reason this rule is not simply CWE-20 with extra steps: the defect is
   * not that validation is missing, it is that validation is present and
   * sequenced so that it does not apply. CWE-20 accompanies it because that is
   * the consequence at the sink.
   */
  cwe: ['CWE-696', 'CWE-20'],
  owasp: ['A03:2021 Injection'],
  remediation: {
    why: 'Protection whose effect depends on statement order is protection the next edit removes.',
    how: 'Sequence the check before the use, and pass its result to the sink instead of the raw value.',
  },
  analyze,
};
