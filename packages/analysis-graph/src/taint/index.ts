// H1 — taint-lite. INTRAPROCEDURAL ONLY, and that boundary is the product
// decision this module exists to express, not a limitation it apologises for.
//
// WHY A TAINT PASS AT ALL
//
// Everything else in this package is STRUCTURAL: a rule observes that a route
// has no guard, that authorization logic is scattered across four files, that a
// method is long and security-relevant. Those are real signals and they are also
// unfalsifiable from the finding alone — a reviewer reading "this handler looks
// under-protected" has no way to tell a true positive from a heuristic that
// misfired without re-deriving the analysis by hand. What this module produces
// is EVIDENCE for those findings: "this value came from `req.query` on line 12,
// was assigned to `sql` on line 15, and reached `db.query` on line 19". A
// reviewer can check that in three seconds against the file in front of them.
// The claim being made changes from "this looks wrong" to "this specific value
// travelled this specific path", which is the difference between a finding that
// gets triaged and a finding that gets muted.
//
// WHY IT STOPS AT THE FUNCTION BOUNDARY
//
// Full interprocedural dataflow is what CodeQL does, and it does it with a
// compiled database, a resolved call graph, and minutes of budget. Competing
// there would cost this package its defining property — zero third-party
// dependencies, no parser, no database, runnable from a CLI in the time a
// developer will actually wait — in exchange for a worse version of somebody
// else's tool. The honest position is that VibeGuard is not the tool you reach
// for when you want whole-program dataflow, and pretending otherwise by shipping
// a half-resolved call graph would produce the worst of both: the cost of
// interprocedural analysis and the reliability of a guess.
//
// So: source and sink must be in the SAME function body, and the flow between
// them must be simple assignment. Anything else is not reported. A missing flow
// costs a structural finding its evidence; a WRONG flow costs the reader their
// trust in every flow this module has ever printed, and the second is not
// recoverable. Precision first, and the false negatives are named rather than
// hidden — see KNOWN GAPS at the bottom of this comment block.
//
// WHY IT BUILDS ITS OWN MASK INSTEAD OF USING `StructureIndex.blanked`
//
// The indexer's `blanked` field is produced by the language-appropriate blanker,
// which blanks template-literal interiors WHOLESALE — `` `SELECT * FROM t WHERE
// id = ${id}` `` loses the `${id}` along with the SQL. That is correct for the
// indexer (it is looking for declarations, and a template is never one) and
// fatal here, because interpolation into a template is the single most common
// shape of the injection this module is meant to evidence. So this module
// derives its own mask: `blankJsLiterals` first, then the `${…}` regions are
// restored from the original and re-blanked in isolation, so an interpolated
// EXPRESSION is visible while any string literal inside it stays blanked. The
// restore is length-preserving by construction, which is what keeps every offset
// in this file interchangeable between mask and original (asserted in the tests
// rather than assumed).
//
// KNOWN GAPS, stated so nobody has to discover them by being wrong:
//   - No interprocedural flow. Deliberate, see above.
//   - No object property writes (`o.x = req.body`), array elements, closures, or
//     destructuring beyond flat `const { body } = req`.
//   - No compound assignment (`x += req.body`).
//   - No multi-line right-hand sides: an assignment's RHS ends at the first `;`
//     or newline.
//   - Python and every non-JS/TS language return `[]`. See `SUPPORTED_LANGUAGES`.
//   - Passes after the first are flow-INSENSITIVE in one direction. See
//     `MAX_PROPAGATION_PASSES`.

import type { IndexedSymbol, SourceFile, StructureIndex } from '../types.js';
import { blankJsLiterals } from '@vibeguard/rules';

/**
 * Where a tainted value entered the function.
 *
 * `name` is the canonical source token (`req.query`, `process.env`, or the bare
 * name of a parameter treated as a source), which is what a rule keys off.
 * `expression` is sliced from the ORIGINAL file content, not from the mask, so a
 * message built from it shows the developer the text they wrote — a mask slice
 * would show blanked-out strings and read as corruption.
 */
export interface TaintSource {
  name: string;
  line: number;
  column: number;
  expression: string;
}

/**
 * What kind of damage the sink does. Kept as a closed union rather than a free
 * string because the consumer of a flow is a rule that must decide a severity,
 * and a severity table over an open string set is a table with a silent default.
 */
export type SinkKind = 'query' | 'exec' | 'eval' | 'response' | 'file';

/** Where a tainted value was consumed. `expression` is original text, as above. */
export interface TaintSink {
  name: string;
  line: number;
  column: number;
  expression: string;
  kind: SinkKind;
}

/**
 * One source→sink path inside one function.
 *
 * `hops` is the load-bearing field. Two flows into the same sink from the same
 * source are not interchangeable if one is direct and one passes through three
 * assignments: the direct one is almost certainly real, the long one is where
 * this module's simplifications are most likely to have lied. Exposing the chain
 * lets a consumer weight confidence by path length instead of guessing, and lets
 * a human check the claim line by line.
 */
export interface TaintFlow {
  source: TaintSource;
  sink: TaintSink;
  /** Assignment hops between source and sink, in order. Empty = direct. */
  hops: { name: string; line: number }[];
  filePath: string;
  symbolName: string;
}

/** Optional inputs that only `analyzeProjectTaint` normally supplies. */
export interface AnalyzeFunctionOptions {
  /**
   * Symbols whose bodies lie INSIDE `symbol`'s body and must be excluded.
   *
   * Without this, an outer function containing two inner callbacks would connect
   * a source in the first to a sink in the second and call the result an
   * intraprocedural flow — the exact false positive the function boundary exists
   * to prevent, reintroduced by the fact that a lexical body span physically
   * contains its nested bodies. `analyzeProjectTaint` computes the containment
   * relation (it is the only caller that can see the other symbols) and passes
   * it here; the nested spans are then blanked out of the mask, which keeps every
   * offset valid because blanking preserves length.
   */
  nestedSymbols?: IndexedSymbol[];
}

/**
 * Languages this phase analyses.
 *
 * Python is absent ON PURPOSE and returns `[]` rather than a partial answer. The
 * sink vocabulary does not carry over: `execute` on a DB cursor is the same word
 * as `execute` on a thread pool, `eval`/`exec` are builtins reachable without a
 * receiver, `os.system` and `subprocess.run` have no JS analogue, and the
 * response sinks are framework-specific in a way Express's are not. A Python arm
 * built by renaming the JS one would fire on `pool.execute(user_task)` and be
 * confidently wrong, and this module's entire value proposition is that a printed
 * flow can be trusted. A Python arm is a separate piece of work with a separate
 * sink table, not a `||` added to a regex.
 */
const SUPPORTED_LANGUAGES = new Set(['javascript', 'typescript']);

/**
 * Hard ceiling on how much of a function body is read.
 *
 * Mirrors `REGEX_INPUT_CAP` in `@vibeguard/rules` in spirit — the number is not
 * imported because the two bound different things (that one bounds a whole file
 * for regex matching, this one bounds one symbol's body for event collection)
 * and coupling them would make a future change to either silently move the other.
 * A body larger than this is analysed in part; taint's failure mode for a partial
 * read is a missing flow, which degrades a finding's evidence rather than
 * inventing any.
 */
const MAX_BODY_LENGTH = 50_000;

/**
 * How many times the propagation pass sweeps the event list.
 *
 * WHY THERE IS A CAP AT ALL, AND WHY IT IS NOT A FIXPOINT. The obvious shape for
 * this loop is "iterate until the tainted set stops changing". That is safe only
 * when the transfer function is MONOTONE, and this one is not: reassignment KILLS
 * taint (`x = 'literal'` after `x = req.body` must remove x, or every rule built
 * on this drowns in false positives), so a program can be written whose lexical
 * event sequence makes the set grow on odd sweeps and shrink on even ones and
 * never settle. `x = y; y = 'lit'; y = x;` is already the shape. The input here
 * is an arbitrary file — in CI, frequently a file from a pull request opened by
 * somebody who is not on the team — so "iterate until it settles" is a loop whose
 * trip count is chosen by the attacker, which is how a security scanner becomes
 * the availability bug. A cap converts "may not terminate" into "may be
 * incomplete", and incomplete is the direction this module already fails in.
 *
 * WHY FOUR. One sweep resolves all straight-line code, which is the overwhelming
 * majority of real handlers. Additional sweeps exist for the loop-carried case —
 * a value aliased at the top of a loop body from a variable that is tainted lower
 * down — where the second sweep is what sees it. Three or more chained
 * loop-carried aliases is not a shape observed in the corpus, so four is chosen
 * as "two more than anything real", and the cost is bounded at 4 × events.
 *
 * THE COST, STATED PLAINLY. Sweeps after the first are flow-INSENSITIVE
 * backwards: they let an assignment at line 3 see a taint that is only
 * established at line 5. In a loop that is correct; in straight-line code that
 * reassigns after use it over-approximates. `originOffset` bounds the damage by
 * refusing any flow whose source does not textually precede its sink, so the
 * over-approximation can never produce a flow that reads backwards on the page.
 */
const MAX_PROPAGATION_PASSES = 4;

/**
 * Assignments, and separately sinks, read from one body before collection stops.
 *
 * TWO BUDGETS, NOT ONE, and the reason is a defect that a single shared budget
 * actually produced: assignments are collected before sinks, so a body with more
 * than the budget's worth of assignments consumed all of it and NO SINK WAS EVER
 * COLLECTED. The function then reported zero flows — not "too big to analyse
 * fully", just clean — for exactly the large generated files most likely to
 * contain something. A bound whose failure mode is "silently reports nothing" is
 * the failure mode this repository already rejected once for `runRegex`
 * (truncate and report, never skip), and the same reasoning applies here: the
 * two categories are separately bounded so exhausting one cannot erase the other.
 */
const MAX_ASSIGNMENTS_PER_FUNCTION = 400;
const MAX_SINKS_PER_FUNCTION = 200;

/** Flows emitted per function. A body that trips this is pathological, not interesting. */
const MAX_FLOWS_PER_FUNCTION = 32;

/** Flows emitted per project, so a whole-repo run cannot be turned into a memory bomb. */
const MAX_FLOWS_PER_PROJECT = 500;

/** Assignment hops followed before a chain is abandoned as noise. */
const MAX_HOPS = 8;

/** Characters of a call's argument list that are read. */
const MAX_ARG_LENGTH = 600;

/** Characters of original text kept in an `expression` field. */
const MAX_EXPRESSION_LENGTH = 160;

/** Parameters inspected on one declaration head. */
const MAX_PARAMETERS = 12;

/**
 * Tainted expressions that need no provenance — reading one IS the entry point.
 *
 * The leading `(?:^|[^\w$.])` is not decoration: without the `.` exclusion,
 * `sanitized.req.query` and `myRequest.body` would both match, and a source that
 * fires on a field of a value someone already wrapped is precisely the false
 * positive that makes a taint report unreadable.
 *
 * Property allowlists rather than `req\.\w+` for the same reason. `req.app`,
 * `req.socket`, and `req.method` are not attacker-controlled in any way that
 * matters, and `req.method` in particular appears in nearly every handler.
 */
const SOURCE_RE =
  /(?:^|[^\w$.])(?<expr>(?:ctx\.request|ctx\.req|req|request)\.(?:query|body|params|headers|cookies|rawBody|files)|process\.(?:argv|env)|event\.(?:body|headers|queryStringParameters|pathParameters))/g;

/**
 * Parameter names that are themselves sources.
 *
 * A name-based source, and therefore the weakest signal in this module — it is
 * inference from naming discipline, the same bet `SymbolRole` makes in types.ts,
 * and it is a good bet specifically for AI-generated code, whose identifiers are
 * conventional almost to a fault. Kept to five names that have no innocent
 * reading in a parameter position. `data`, `payload`, `params`, and `body` were
 * all considered and rejected: each is used at least as often for a value the
 * function itself constructed.
 */
const PARAMETER_SOURCE_NAMES = new Set(['req', 'request', 'event', 'input', 'userInput']);

/**
 * An assignment. One regex rather than three so the events come out already in
 * textual order, which the propagation sweep depends on for kill semantics.
 *
 * Every quantifier is bounded and every whitespace class is HORIZONTAL
 * (`[^\S\r\n]`, never `\s`). That is not style: `\s` matches line terminators, so
 * an unbounded `\s*` between two tokens lets a run of blank lines multiply the
 * backtracking search space, which is the measured cause of the super-linear rule
 * behaviour this repository already had to fix once (A1). The RHS deliberately
 * stops at `;` or a line terminator.
 *
 * `(?![=>])` after the `=` is what keeps `==`, `===`, and `=>` out. `<=`, `>=`,
 * `!=`, `+=` and friends are excluded from the other side: the character before
 * the identifier must not be a word character, `$`, or `.`, and the operator
 * characters sit between the identifier and the `=`, so the match simply fails.
 * The `.` exclusion is also what makes property writes (`o.x = req.body`)
 * invisible here, which is the documented scope boundary rather than an oversight.
 */
const ASSIGN_RE =
  /(?:^|[^\w$.])(?:const|let|var)?[^\S\r\n]{0,4}(?:\{(?<destructured>[^{}\r\n]{1,160})\}|(?<lhs>[A-Za-z_$][\w$]{0,60}))[^\S\r\n]{0,4}=(?![=>])(?<rhs>[^;\r\n]{0,400})/g;

/** An identifier in a value position — i.e. not immediately after a `.`. */
const IDENT_RE = /(?:^|[^\w$.])(?<ident>[A-Za-z_$][\w$]{0,60})/g;

/**
 * Receivers whose `.exec(` is a database call rather than a regex match.
 *
 * `re.exec(userInput)` is the textbook false positive for a naive sink list: it
 * is a READ of the tainted string, it is everywhere, and reporting it as SQL
 * injection would discredit every other flow in the report. So `.exec(` is a
 * sink only on a receiver that names a database, and the recall cost (an
 * unconventionally-named DB handle) is accepted.
 */
const DB_RECEIVER_RE = /(?:^|[^a-z])(?:db|conn|connection|pool|client|sequelize|knex|prisma|cursor)(?:[^a-z]|$)/i;

/** Receivers whose `.exec`/`.spawn` is process execution. */
const PROCESS_RECEIVER_RE = /^(?:child_?process|childProcess|cp|proc|execa)$/i;

/** Receivers whose `.send`/`.write`/`.end` is an HTTP response. */
const RESPONSE_RECEIVER_RE = /^(?:res|response|reply)$/i;

/** Receivers whose file methods are `fs`. */
const FS_RECEIVER_RE = /^(?:fs|fsp|fsPromises|fileSystem)$/i;

/**
 * How a sink consumes its tainted argument.
 *
 * `call` sinks take it inside `(…)`; `assign` sinks take it on the right of an
 * `=` (only `innerHTML`, but the form has to exist for it). Splitting on form
 * rather than special-casing `innerHTML` inside the extractor keeps the argument
 * extraction one function with one contract.
 */
interface SinkSpec {
  kind: SinkKind;
  form: 'call' | 'assign';
  re: RegExp;
  /** Additional constraint on the `recv` group, when the method name alone is ambiguous. */
  receiverTest?: RegExp;
}

/**
 * The sink table.
 *
 * ON `fs.*` AND "A JOINED PATH". The specification for this module described the
 * file sinks as firing on a JOINED path (`path.join(base, userValue)`). That
 * qualifier is subsumed here by the taint requirement and is deliberately not
 * implemented as a separate condition: a constant path contains no tainted
 * identifier and therefore cannot produce a flow at all, so the check would never
 * change a verdict in the direction it was meant to. Implemented literally — by
 * demanding a `join(` in the IMMEDIATE argument — it would instead delete the
 * most common real shape, `const p = path.join(base, req.query.f); fs.readFile(p)`,
 * where the joining happened one hop earlier and the evidence is strictly better.
 */
const SINK_SPECS: SinkSpec[] = [
  {
    kind: 'query',
    form: 'call',
    re: /(?:^|[^\w$.])(?<recv>[\w$]{1,40})\.(?:query|execute|raw)[^\S\r\n]{0,4}\(/g,
  },
  {
    kind: 'query',
    form: 'call',
    re: /(?:^|[^\w$.])(?<recv>[\w$]{1,40})\.exec[^\S\r\n]{0,4}\(/g,
    receiverTest: DB_RECEIVER_RE,
  },
  {
    kind: 'exec',
    form: 'call',
    re: /(?:^|[^\w$.])(?<recv>[\w$]{1,40})\.(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)[^\S\r\n]{0,4}\(/g,
    receiverTest: PROCESS_RECEIVER_RE,
  },
  {
    kind: 'exec',
    form: 'call',
    re: /(?:^|[^\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)[^\S\r\n]{0,4}\(/g,
  },
  {
    kind: 'eval',
    form: 'call',
    re: /(?:^|[^\w$.])eval[^\S\r\n]{0,4}\(/g,
  },
  {
    kind: 'eval',
    form: 'call',
    re: /(?:^|[^\w$.])new[^\S\r\n]{1,4}Function[^\S\r\n]{0,4}\(/g,
  },
  {
    kind: 'eval',
    form: 'call',
    re: /(?:^|[^\w$.])vm\.runInNewContext[^\S\r\n]{0,4}\(/g,
  },
  {
    kind: 'response',
    form: 'call',
    re: /(?:^|[^\w$.])(?<recv>[\w$]{1,40})\.(?:send|write|end)[^\S\r\n]{0,4}\(/g,
    receiverTest: RESPONSE_RECEIVER_RE,
  },
  {
    kind: 'response',
    form: 'assign',
    re: /\.innerHTML[^\S\r\n]{0,4}=(?![=>])(?<rhs>[^;\r\n]{0,400})/g,
  },
  {
    kind: 'file',
    form: 'call',
    re: /(?:^|[^\w$.])(?<recv>[\w$]{1,40})\.(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream)[^\S\r\n]{0,4}\(/g,
    receiverTest: FS_RECEIVER_RE,
  },
];

/** What is known about one variable at one point in the sweep. */
interface TaintState {
  source: TaintSource;
  hops: { name: string; line: number }[];
  /**
   * Offset of the SOURCE that started this chain, used to refuse any flow whose
   * source does not textually precede its sink. See `MAX_PROPAGATION_PASSES` for
   * why a later sweep can otherwise propose one.
   */
  originOffset: number;
}

/**
 * A tainted thing found inside one expression.
 *
 * `direct` distinguishes "the source expression is written right here" from "an
 * identifier here holds a value that was tainted earlier". Only the second kind
 * is subject to the precedes-the-sink guard: a source written INSIDE a sink's
 * argument list necessarily sits at a LATER offset than the sink's own head
 * (`db.query(` comes before `req.body`), so applying the guard to it would
 * delete every direct flow in the module — which is the most common and most
 * certain shape there is.
 */
interface TaintCandidate {
  source: TaintSource;
  hops: { name: string; line: number }[];
  originOffset: number;
  direct: boolean;
}

type BodyEvent =
  | { kind: 'assign'; offset: number; names: string[]; rhsOffset: number; rhsText: string }
  | { kind: 'sink'; offset: number; spec: SinkSpec; name: string; argOffset: number; argText: string };

/** Per-file derived state, computed once. */
interface FileMask {
  mask: string;
  lineStarts: number[];
}

/**
 * Cache of per-file derived state.
 *
 * A `WeakMap` keyed on the `SourceFile` OBJECT, which is sound only because
 * `ProjectIndex` is documented as read-only after construction (types.ts) — a
 * caller that mutated `content` on a file it had already been analysed with would
 * get a stale mask. That contract is worth relying on because the alternative,
 * re-running `blankJsLiterals` for every symbol, is O(file × symbols) on the
 * hottest path in the package: a 40-symbol file would be blanked forty times.
 */
const fileMaskCache = new WeakMap<SourceFile, FileMask>();

/**
 * The mask for `file`: JS-blanked, then with template `${…}` interpolations
 * restored (and independently re-blanked, so strings inside an interpolation stay
 * blanked).
 *
 * WHY RESTORING IS SAFE. `blankJsLiterals` preserves length and never touches
 * `\n` or `\r`; the restore writes original characters back into the same
 * positions and re-blanks the restored slice with the same length-preserving
 * function. So the result is character-for-character aligned with
 * `file.content`, and any offset computed on one is valid on the other. The tests
 * assert this rather than trusting the paragraph you are reading.
 */
function getFileMask(file: SourceFile): FileMask {
  const cached = fileMaskCache.get(file);
  if (cached) return cached;
  const blanked = blankJsLiterals(file.content);
  const mask = restoreTemplateInterpolations(file.content, blanked);
  const lineStarts = computeLineStarts(file.content);
  const built: FileMask = { mask, lineStarts };
  fileMaskCache.set(file, built);
  return built;
}

/**
 * Put `${…}` expressions back into an otherwise blanked template literal.
 *
 * The scan walks the BLANKED text to find backtick pairs, not the original: a
 * backtick inside a comment or a string has already become a space there, so the
 * remaining backticks are exactly the delimiters `blankJsLiterals` itself
 * believed in. Pairing them the same way it did means this function cannot
 * disagree with it about where a template starts, which is the only way the two
 * could produce a region that is unblanked when it should not be.
 */
function restoreTemplateInterpolations(original: string, blanked: string): string {
  if (!blanked.includes('`')) return blanked;
  const out = blanked.split('');
  let i = 0;
  while (i < blanked.length) {
    if (blanked[i] !== '`') {
      i += 1;
      continue;
    }
    let close = i + 1;
    while (close < blanked.length && blanked[close] !== '`') close += 1;
    if (close >= blanked.length) break;
    restoreInterpolationsInRange(original, out, i + 1, close);
    i = close + 1;
  }
  return out.join('');
}

/** Restore every `${…}` in `original[start, end)` into `out`, re-blanked. */
function restoreInterpolationsInRange(original: string, out: string[], start: number, end: number): void {
  let i = start;
  while (i < end - 1) {
    if (!(original[i] === '$' && original[i + 1] === '{')) {
      i += 1;
      continue;
    }
    // Brace-match over the ORIGINAL text. A brace inside a string inside the
    // interpolation can desync this; the failure mode is that the region is left
    // blanked, i.e. a missing flow, which is the direction this module fails in.
    let depth = 0;
    let j = i + 1;
    for (; j < end; j += 1) {
      const c = original[j];
      if (c === '{') depth += 1;
      else if (c === '}') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (j >= end) return;
    const inner = blankJsLiterals(original.slice(i + 2, j));
    for (let k = 0; k < inner.length; k += 1) out[i + 2 + k] = inner[k]!;
    i = j + 1;
  }
}

/**
 * Byte offsets of each line start, so a position lookup is O(log n) instead of
 * O(n).
 *
 * This is NOT a reimplementation of `indexToPosition` competing with it — it is
 * the same definition (lines are delimited by `\n`; a column counts characters
 * since the last one, so a `\r` in CRLF input belongs to the END of the previous
 * line and never shifts the next line's numbering) hoisted out of a per-call loop
 * because this module resolves dozens of offsets per function and `indexToPosition`
 * walks from the start of the file each time, which is quadratic. `taint.test.ts`
 * checks a reported position against `indexToPosition` on CRLF input — the case
 * where the two would first diverge, since `\r` belongs to the end of the
 * previous line — so a divergence there is a failing test rather than a wrong
 * line number in a report. That is a spot check on the shared boundary case, not
 * an exhaustive equivalence proof: this function is not exported, so a test
 * cannot walk it over every offset without widening the module's API.
 */
function computeLineStarts(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function positionAt(lineStarts: number[], offset: number): { line: number; column: number } {
  const clamped = Math.max(0, offset);
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= clamped) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: clamped - lineStarts[lo]! + 1 };
}

/** Original text for an `expression` field: bounded, single-line, trimmed. */
function sliceExpression(content: string, start: number, end: number): string {
  const raw = content.slice(Math.max(0, start), Math.min(content.length, Math.min(end, start + MAX_EXPRESSION_LENGTH)));
  return raw.replace(/[\r\n]+/g, ' ').replace(/[^\S\r\n]{2,}/g, ' ').trim();
}

/** Blank `[from, to)` in a mask, preserving length and line terminators. */
function blankRange(chars: string[], from: number, to: number): void {
  for (let i = Math.max(0, from); i < Math.min(chars.length, to); i += 1) {
    const c = chars[i];
    if (c !== '\n' && c !== '\r') chars[i] = ' ';
  }
}

/**
 * Intraprocedural taint flows inside one function body.
 *
 * Reads ONLY `[symbol.bodyStart, symbol.bodyEnd)` plus the declaration head (for
 * parameter sources). Nothing outside that span can be a source, a hop, or a
 * sink — which is the whole contract, and is why a source in one function and a
 * sink in another produce nothing even when they sit ten lines apart in the same
 * file.
 */
export function analyzeFunction(
  symbol: IndexedSymbol,
  file: SourceFile,
  options?: AnalyzeFunctionOptions,
): TaintFlow[] {
  if (!SUPPORTED_LANGUAGES.has(file.language)) return [];

  const { mask: baseMask, lineStarts } = getFileMask(file);
  const bodyStart = Math.max(0, Math.min(symbol.bodyStart, file.content.length));
  const bodyEnd = Math.max(bodyStart, Math.min(symbol.bodyEnd, file.content.length, bodyStart + MAX_BODY_LENGTH));
  if (bodyEnd <= bodyStart) return [];

  let mask = baseMask;
  const nested = options?.nestedSymbols?.filter(
    (n) => n !== symbol && n.bodyStart >= bodyStart && n.bodyEnd <= bodyEnd && n.bodyEnd > n.bodyStart,
  );
  if (nested && nested.length > 0) {
    const chars = baseMask.split('');
    for (const n of nested) blankRange(chars, n.bodyStart, n.bodyEnd);
    mask = chars.join('');
  }

  const body = mask.slice(bodyStart, bodyEnd);
  const state = new Map<string, TaintState>();
  seedParameterSources(symbol, file, mask, lineStarts, state);
  const events = collectEvents(body, bodyStart, bodyEnd, mask);
  if (events.length === 0 && state.size === 0) return [];

  const flows: TaintFlow[] = [];
  const seen = new Set<string>();

  for (let pass = 0; pass < MAX_PROPAGATION_PASSES; pass += 1) {
    let changed = false;
    for (const event of events) {
      if (event.kind === 'assign') {
        changed = applyAssignment(event, file, lineStarts, state) || changed;
      } else {
        collectSinkFlows(event, symbol, file, lineStarts, state, flows, seen);
        if (flows.length >= MAX_FLOWS_PER_FUNCTION) return flows;
      }
    }
    // A sweep that changed nothing means every later sweep would also change
    // nothing, so the remaining budget is not worth spending. Flows are already
    // deduplicated by `seen`, so re-walking the sinks costs nothing but time.
    if (!changed) break;
  }

  return flows;
}

/**
 * Seed the state with parameters that are themselves sources.
 *
 * The parameter list is read from the declaration HEAD — the text between the
 * symbol's start position and `bodyStart` — because that is where it lives and
 * `bodyStart` is defined as the first character after the opening brace. Failure
 * to locate a parameter list is silent and total: no parameter sources, every
 * other kind of source still works.
 */
function seedParameterSources(
  symbol: IndexedSymbol,
  file: SourceFile,
  mask: string,
  lineStarts: number[],
  state: Map<string, TaintState>,
): void {
  const headLine = symbol.startLine - 1;
  if (headLine < 0 || headLine >= lineStarts.length) return;
  const headOffset = lineStarts[headLine]! + Math.max(0, symbol.startColumn - 1);
  if (headOffset >= symbol.bodyStart) return;

  const head = mask.slice(headOffset, symbol.bodyStart);
  const open = head.indexOf('(');
  if (open < 0) return;
  let depth = 0;
  let close = -1;
  for (let i = open; i < head.length; i += 1) {
    const c = head[i];
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close < 0) return;

  // Split on TOP-LEVEL commas only, so a TS type argument or a default value
  // containing a comma does not split one parameter into two.
  let paramStart = open + 1;
  let nesting = 0;
  let count = 0;
  for (let i = open + 1; i <= close && count < MAX_PARAMETERS; i += 1) {
    const c = head[i];
    if (c === '(' || c === '[' || c === '{' || c === '<') nesting += 1;
    else if (c === ')' || c === ']' || c === '}' || c === '>') nesting -= 1;
    const atEnd = i === close;
    if ((c === ',' && nesting === 0) || atEnd) {
      const chunk = head.slice(paramStart, i);
      const named = /^[^\S\r\n]{0,8}(?<name>[A-Za-z_$][\w$]{0,60})/.exec(chunk);
      const name = named?.groups?.name;
      if (name && PARAMETER_SOURCE_NAMES.has(name)) {
        const nameOffset = headOffset + paramStart + chunk.indexOf(name);
        const pos = positionAt(lineStarts, nameOffset);
        state.set(name, {
          source: {
            name,
            line: pos.line,
            column: pos.column,
            expression: sliceExpression(file.content, nameOffset, nameOffset + name.length),
          },
          hops: [],
          originOffset: nameOffset,
        });
      }
      count += 1;
      paramStart = i + 1;
    }
  }
}

/**
 * Read the body once into an ordered event list.
 *
 * Ordering by offset is what makes kill semantics work: the sweep applies
 * assignments and consults sinks in the order they appear, so `x = req.body;
 * db.query(x); x = 'safe';` reports a flow and `x = req.body; x = 'safe';
 * db.query(x)` does not. Doing this with three independent regex walks and no
 * merge — the obvious first implementation — silently gets both cases wrong in
 * whichever direction the walks happened to run.
 */
function collectEvents(body: string, bodyStart: number, bodyEnd: number, mask: string): BodyEvent[] {
  const events: BodyEvent[] = [];

  ASSIGN_RE.lastIndex = 0;
  let assignments = 0;
  let m: RegExpExecArray | null;
  while (assignments < MAX_ASSIGNMENTS_PER_FUNCTION && (m = ASSIGN_RE.exec(body)) !== null) {
    if (m[0].length === 0) {
      ASSIGN_RE.lastIndex += 1;
      continue;
    }
    const rhs = m.groups?.rhs ?? '';
    const rhsOffset = bodyStart + m.index + m[0].length - rhs.length;
    const names: string[] = [];
    const destructured = m.groups?.destructured;
    if (destructured !== undefined) {
      // Only the flat `const { body } = req` form, per scope. A nested or
      // renamed pattern (`{ a: { b } }`, `{ a: b }`) yields names that do not
      // correspond to what is actually bound, so anything containing `:` or a
      // brace is dropped whole rather than half-understood.
      if (!/[:{}]/.test(destructured)) {
        for (const part of destructured.split(',').slice(0, MAX_PARAMETERS)) {
          const name = /^[^\S\r\n]{0,8}(?<name>[A-Za-z_$][\w$]{0,60})/.exec(part)?.groups?.name;
          if (name) names.push(name);
        }
      }
    } else if (m.groups?.lhs) {
      names.push(m.groups.lhs);
    }
    if (names.length === 0) continue;
    assignments += 1;
    // Anchored PAST the boundary character the pattern consumed. `(?:^|[^\w$.])`
    // eats the newline that ends the previous line, so `m.index` names the line
    // ABOVE the assignment — which would put every hop in a reported flow one
    // line too high, the single most embarrassing kind of wrong a report that
    // asks the reader to check a line number can be.
    const payload = m[0].length - m[0].replace(/^[^\w$.]/, '').length;
    events.push({
      kind: 'assign',
      offset: bodyStart + m.index + payload,
      names,
      rhsOffset,
      rhsText: rhs,
    });
  }

  const sinkSeen = new Set<number>();
  for (const spec of SINK_SPECS) {
    spec.re.lastIndex = 0;
    let s: RegExpExecArray | null;
    while (sinkSeen.size < MAX_SINKS_PER_FUNCTION && (s = spec.re.exec(body)) !== null) {
      if (s[0].length === 0) {
        spec.re.lastIndex += 1;
        continue;
      }
      const recv = s.groups?.recv;
      if (spec.receiverTest && (recv === undefined || !spec.receiverTest.test(recv))) continue;

      const leading = s[0].length - s[0].replace(/^[^\w$.]/, '').length;
      const headOffset = bodyStart + s.index + leading;
      let argOffset: number;
      let argText: string;
      if (spec.form === 'call') {
        const openParen = bodyStart + s.index + s[0].length - 1;
        // Bounded by `bodyEnd`, not just by MAX_ARG_LENGTH: a call whose closing
        // paren is missing (or merely far away) at the tail of a body must not
        // let the argument scan walk into the NEXT function and pick up an
        // identifier from it. That would be an interprocedural read through the
        // back door.
        const args = sliceCallArguments(mask, openParen, bodyEnd);
        argOffset = args.start;
        argText = args.text;
      } else {
        const rhs = s.groups?.rhs ?? '';
        argOffset = bodyStart + s.index + s[0].length - rhs.length;
        argText = rhs;
      }
      // Two specs can describe the same call site (`db.exec` is matched by the
      // generic query spec and the DB-receiver one). Deduplicate on where the
      // ARGUMENTS start, which is the same for both, rather than on the match
      // offset, which is not.
      if (sinkSeen.has(argOffset)) continue;
      sinkSeen.add(argOffset);

      events.push({
        kind: 'sink',
        offset: headOffset,
        spec,
        name: sinkName(s[0], spec.form),
        argOffset,
        argText,
      });
    }
  }

  events.sort((a, b) => a.offset - b.offset);
  return events;
}

/** `db.query(` → `db.query`; `.innerHTML =` → `innerHTML`. */
function sinkName(matched: string, form: 'call' | 'assign'): string {
  let name = matched.replace(/^[^\w$.]/, '');
  name = form === 'call' ? name.replace(/[^\S\r\n]{0,4}\($/, '') : name.replace(/[^\S\r\n]{0,4}=[\s\S]*$/, '');
  return name.replace(/^\./, '').trim();
}

/**
 * The text between a call's parentheses, balanced and bounded.
 *
 * Counted on the MASK, where a `(` inside a string or comment is already a space,
 * so a call like `run("(")` cannot desync the depth counter. Unbalanced or
 * over-long argument lists return what was read up to the bound rather than
 * nothing, because a truncated argument still contains the identifier the sweep
 * is looking for far more often than not.
 */
function sliceCallArguments(mask: string, openParen: number, hardEnd: number): { start: number; text: string } {
  const start = openParen + 1;
  const limit = Math.min(mask.length, hardEnd, start + MAX_ARG_LENGTH);
  let depth = 1;
  let i = start;
  for (; i < limit; i += 1) {
    const c = mask[i];
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  return { start, text: mask.slice(start, i) };
}

/**
 * Everything in `text` that is tainted, as (source, hops) candidates.
 *
 * Direct source expressions win over identifiers that overlap them: without that,
 * `db.query(req.query.id)` inside a handler whose parameter is also named `req`
 * would report the same flow twice, once attributed to `req.query` and once to
 * the parameter, and a reader has no way to tell that those are one fact.
 */
function taintedIn(
  text: string,
  textOffset: number,
  file: SourceFile,
  lineStarts: number[],
  state: Map<string, TaintState>,
): TaintCandidate[] {
  const found: TaintCandidate[] = [];
  const covered: [number, number][] = [];

  SOURCE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SOURCE_RE.exec(text)) !== null) {
    const expr = m.groups?.expr;
    if (expr === undefined) continue;
    const at = m.index + m[0].length - expr.length;
    covered.push([at, at + expr.length]);
    const offset = textOffset + at;
    const pos = positionAt(lineStarts, offset);
    found.push({
      source: {
        name: expr,
        line: pos.line,
        column: pos.column,
        expression: sliceExpression(file.content, offset, offset + expr.length),
      },
      hops: [],
      originOffset: offset,
      direct: true,
    });
  }

  if (state.size > 0) {
    IDENT_RE.lastIndex = 0;
    let ident: RegExpExecArray | null;
    while ((ident = IDENT_RE.exec(text)) !== null) {
      const name = ident.groups?.ident;
      if (name === undefined) continue;
      const at = ident.index + ident[0].length - name.length;
      if (covered.some(([lo, hi]) => at >= lo && at < hi)) continue;
      const known = state.get(name);
      if (!known) continue;
      found.push({ source: known.source, hops: known.hops, originOffset: known.originOffset, direct: false });
    }
  }

  return found;
}

/**
 * Apply one assignment. Returns whether the state changed.
 *
 * The `else` branch — deleting the LHS when the RHS is untainted — is the whole
 * reason this returns to a map rather than accumulating into a set. `x =
 * req.body` followed by `x = sanitize(y)` must leave `x` clean, and a taint
 * tracker that only ever adds is one that reports every sanitised value as
 * tainted for the rest of the function. That is the failure mode most likely to
 * make a user turn the feature off, so it is tested explicitly.
 */
function applyAssignment(
  event: Extract<BodyEvent, { kind: 'assign' }>,
  file: SourceFile,
  lineStarts: number[],
  state: Map<string, TaintState>,
): boolean {
  const candidates = taintedIn(event.rhsText, event.rhsOffset, file, lineStarts, state);
  let changed = false;
  for (const name of event.names) {
    // A self-referential assignment (`x = x + req.body`) must not append a hop
    // to `x` on every sweep, which would otherwise grow the chain without bound.
    const incoming = candidates.find((c) => !c.hops.some((h) => h.name === name));
    if (incoming === undefined) {
      if (state.delete(name)) changed = true;
      continue;
    }
    if (incoming.hops.length >= MAX_HOPS) continue;
    const line = positionAt(lineStarts, event.offset).line;
    const next: TaintState = {
      source: incoming.source,
      hops: [...incoming.hops, { name, line }],
      originOffset: incoming.originOffset,
    };
    const before = state.get(name);
    state.set(name, next);
    if (
      before === undefined ||
      before.originOffset !== next.originOffset ||
      before.hops.length !== next.hops.length
    ) {
      changed = true;
    }
  }
  return changed;
}

/** Emit flows for one sink, deduplicated across sweeps. */
function collectSinkFlows(
  event: Extract<BodyEvent, { kind: 'sink' }>,
  symbol: IndexedSymbol,
  file: SourceFile,
  lineStarts: number[],
  state: Map<string, TaintState>,
  out: TaintFlow[],
  seen: Set<string>,
): void {
  const candidates = taintedIn(event.argText, event.argOffset, file, lineStarts, state);
  if (candidates.length === 0) return;
  const pos = positionAt(lineStarts, event.offset);
  const sink: TaintSink = {
    name: event.name,
    line: pos.line,
    column: pos.column,
    kind: event.spec.kind,
    expression: sliceExpression(file.content, event.offset, event.argOffset + event.argText.length + 1),
  };
  for (const candidate of candidates) {
    // Refuse a flow whose source does not textually precede its sink. See
    // MAX_PROPAGATION_PASSES: a later sweep can otherwise propose one, and a
    // report that says a value reached line 9 from line 14 reads as a bug in the
    // tool even on the loop where it is technically true.
    if (!candidate.direct && candidate.originOffset > event.offset) continue;
    const key = `${candidate.source.line}:${candidate.source.column}:${candidate.source.name}>${sink.line}:${sink.column}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      source: candidate.source,
      sink,
      hops: candidate.hops,
      filePath: file.filePath,
      symbolName: symbol.name,
    });
    if (out.length >= MAX_FLOWS_PER_FUNCTION) return;
  }
}

/**
 * Every intraprocedural flow in the project.
 *
 * Symbols are analysed INNERMOST FIRST and each one is told which of the others
 * are nested inside it, so a callback's body is analysed as the callback's and
 * blanked out of its parent's. Without that, a file of the shape `function
 * routes() { app.get('/a', h1); app.get('/b', h2); }` would report a source in
 * `h1` reaching a sink in `h2` through the enclosing function — an
 * INTERPROCEDURAL flow, dressed up as an intraprocedural one because the two
 * bodies happen to sit inside a third. That is the one mistake this module must
 * not make, so the containment relation is computed here (the only place with
 * visibility of every symbol) rather than left to each caller to remember.
 */
export function analyzeProjectTaint(structures: StructureIndex[], files: SourceFile[]): TaintFlow[] {
  const byPath = new Map<string, SourceFile>();
  for (const file of files) byPath.set(file.filePath, file);

  const flows: TaintFlow[] = [];
  for (const structure of structures) {
    if (flows.length >= MAX_FLOWS_PER_PROJECT) break;
    const file = byPath.get(structure.filePath);
    if (!file || !SUPPORTED_LANGUAGES.has(file.language)) continue;

    // Innermost first, so the most specific `symbolName` is the one that reaches
    // the reader when two symbols could both claim a flow.
    const symbols = [...structure.symbols].sort(
      (a, b) => a.bodyEnd - a.bodyStart - (b.bodyEnd - b.bodyStart),
    );
    const seen = new Set<string>();
    for (const symbol of symbols) {
      if (flows.length >= MAX_FLOWS_PER_PROJECT) break;
      const nestedSymbols = symbols.filter(
        (other) =>
          other !== symbol &&
          other.bodyStart >= symbol.bodyStart &&
          other.bodyEnd <= symbol.bodyEnd &&
          other.bodyEnd - other.bodyStart < symbol.bodyEnd - symbol.bodyStart,
      );
      for (const flow of analyzeFunction(symbol, file, { nestedSymbols })) {
        const key = `${flow.filePath}|${flow.source.line}:${flow.source.column}|${flow.sink.line}:${flow.sink.column}`;
        if (seen.has(key)) continue;
        seen.add(key);
        flows.push(flow);
        if (flows.length >= MAX_FLOWS_PER_PROJECT) break;
      }
    }
  }
  return flows;
}
