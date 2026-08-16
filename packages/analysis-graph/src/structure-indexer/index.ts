// structure-indexer — what is inside one file.
//
// The first of the four submodules in design addendum §8.2. Its job list there:
// class, function, method, import/export, inheritance, decorator/annotation,
// route handler, middleware, public API, security-related symbol.
//
// HOW IT WORKS, AND THE HONEST LIMITS OF THAT
//
// One forward pass of head-pattern regexes over text whose strings and comments
// have been blanked (length-preservingly, so every offset stays valid in the
// original), then balanced-block extraction to find where each body ends. Both
// primitives come from `@vibeguard/rules` — `blankJsLiterals`/`blankPyLiterals`
// and `extractBlockAfter` — and are reused rather than reimplemented because
// they already carry the escape handling, the regex-vs-division disambiguation,
// and the ReDoS bounds that took real work to get right.
//
// What that CANNOT do, stated plainly rather than discovered later:
//  - It cannot resolve types, so `const h: RequestHandler = ...` is a function
//    to it and nothing more.
//  - It cannot follow aliases, so `const g = requireAdmin; router.get('/x', g)`
//    records `g` as the guard name, not `requireAdmin`.
//  - It has no notion of scope, so two functions with the same name in one file
//    are two entries distinguished only by their spans.
//  - Sufficiently exotic syntax (decorators with complex arguments spanning many
//    lines, deeply nested generics in a parameter list) will be missed.
//
// Every one of those is a MISS, not a mistake: the head patterns are anchored,
// and `extractBlockAfter` returns null rather than a truncated body when a block
// does not balance. Failing quiet is the required direction here, because the
// consumer is a design smell whose false positives land on well-factored code —
// the case the project's `samples/safe == 0 findings` gate exists to protect.
//
// WHY ROUTE DETECTION LIVES HERE AND NOT IN THE RULE
//
// "Is this function a route handler" is a structural question about the file,
// and VG-SMELL-010 is not the only consumer that will ask it. Putting it in the
// indexer means the rule reads a fact instead of re-deriving it, and means the
// derivation is tested once, here, against its own adversarial fixtures rather
// than only through whatever the rule happens to exercise.

import {
  blankJsLiterals,
  blankPyLiterals,
  blankCommentsAndStrings,
  extractBlockAfter,
  REGEX_INPUT_CAP,
} from '@vibeguard/rules';
import type {
  ImportEdge,
  IndexedSymbol,
  RouteBinding,
  SourceFile,
  StructureIndex,
} from '../types.js';

/** Languages this phase indexes. Everything else yields an empty index. */
const JS_LANGUAGES = new Set(['javascript', 'typescript']);
const C_LANGUAGES = new Set(['c', 'cpp']);

/**
 * Bound on how many head matches are processed per file.
 *
 * The same shape of protection as `REGEX_MATCH_LIMIT` in `@vibeguard/rules` and
 * for the same reason: a generated or minified file can present tens of
 * thousands of function heads, and each one costs a balanced-block scan. The cap
 * is per-file and generous for hand-written code; a file past it is one where a
 * design smell about human structure was never going to be meaningful anyway.
 */
const MAX_SYMBOLS_PER_FILE = 800;

/**
 * Turn a 0-based offset into a 1-based line number, counting `\n`.
 *
 * Hand-rolled rather than reusing `indexToPosition` from `@vibeguard/rules`
 * because this is called once per symbol per file and that helper rescans the
 * prefix each time — O(n²) over a file with hundreds of heads. The line table
 * below is built once and binary-searched.
 *
 * CRLF: `\r\n` contributes exactly one line break, because the `\n` is what is
 * counted and the `\r` is an ordinary character preceding it. That is the same
 * convention the rest of the codebase uses, so a line number computed here
 * matches one computed by a core rule on the same file — which matters, because
 * a design smell and a core finding can end up side by side in one report.
 */
function buildLineTable(content: string): number[] {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content[i] === '\n') starts.push(i + 1);
  }
  return starts;
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

function columnAt(lineStarts: number[], offset: number): number {
  const line = lineAt(lineStarts, offset);
  return offset - lineStarts[line - 1]! + 1;
}

/**
 * Function and method heads in a brace language.
 *
 * Adapted from the `JS_HEAD` pattern already shipping in
 * `packages/rules/src/rules/design-smells-single.ts`, deliberately: that pattern
 * has been through this project's adversarial review and its `samples/safe`
 * gate, and inventing a second dialect of the same idea would mean two patterns
 * drifting apart while both claim to answer "where do functions start".
 *
 * Named groups rather than positional, so adding an alternative later does not
 * silently renumber every consumer.
 *
 * All quantifiers are bounded. Unbounded `\s*` between tokens is the exact shape
 * that produced this project's A1 ReDoS findings, so horizontal whitespace is
 * matched as `[^\S\r\n]{0,N}` throughout.
 */
const JS_HEAD =
  /(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:async[^\S\r\n]{1,4})?function[^\S\r\n]{0,4}\*?[^\S\r\n]{0,4}(?<fnA>[\w$]{1,60})[^\S\r\n]{0,4}\(|(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:const|let|var)[^\S\r\n]{1,4}(?<fnB>[\w$]{1,60})[^\S\r\n]{0,4}(?::[^=\n]{0,120})?=[^\S\r\n]{0,4}(?:async[^\S\r\n]{0,4})?(?:function\b|\([^()\n]{0,300}\)[^\S\r\n]{0,4}(?::[^=>\n]{0,80})?=>|[\w$]{1,40}[^\S\r\n]{0,4}=>)|(?:^|[^\w$.])(?:public|private|protected|static|async|readonly|override|[^\S\r\n]){0,8}(?<fnC>(?!(?:if|for|while|switch|catch|return|function|await|typeof|do|else|new|delete|void|yield|in|of)\b)[\w$]{1,60})[^\S\r\n]{0,4}\([^()\n]{0,300}\)[^\S\r\n]{0,4}(?::[^{;\n]{0,120})?\{/g;

/** `class Foo`, optionally `extends Bar`. */
const JS_CLASS =
  /(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:abstract[^\S\r\n]{1,4})?class[^\S\r\n]{1,4}(?<cls>[\w$]{1,60})(?:[^\S\r\n]{1,4}extends[^\S\r\n]{1,4}(?<base>[\w$.]{1,80}))?/g;

/** ESM `import ... from '...'` and bare `import '...'`. */
const JS_IMPORT =
  /(?:^|\n)[^\S\r\n]{0,8}import[^\S\r\n]{0,4}(?:(?<names>[^;'"\n]{0,200})[^\S\r\n]{0,4}from[^\S\r\n]{0,4})?['"](?<spec>[^'"\n]{1,200})['"]/g;

/** CommonJS `require('...')`, with the binding names when it is an assignment. */
const JS_REQUIRE =
  /(?:(?:const|let|var)[^\S\r\n]{1,4}(?<names>[^=\n]{1,200})[^\S\r\n]{0,4}=[^\S\r\n]{0,4})?require[^\S\r\n]{0,4}\([^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g;

/** `export { a, b }` / `export const x` / `export default` / `module.exports.x`. */
const JS_EXPORT =
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{1,4}(?:(?:const|let|var|function|class|async)[^\S\r\n]{1,4}){0,2}(?<name>[\w$]{1,60})|(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{0,4}\{(?<list>[^}\n]{0,300})\}|module\.exports(?:\.(?<cjs>[\w$]{1,60}))?[^\S\r\n]{0,4}=/g;

/** Decorators: `@Get('/x')`, `@UseGuards(AuthGuard)`, Python `@login_required`. */
const DECORATOR = /(?:^|\n)[^\S\r\n]{0,20}@(?<dec>[\w$.]{1,80})/g;

/**
 * Route registrations in the Express / Koa / Fastify family.
 *
 * `app.get('/x', a, b, handler)` — the interesting part is not the handler but
 * everything BEFORE it. Those middle arguments are per-route guards, and their
 * presence is the direct evidence that authorization was delegated rather than
 * inlined. VG-SMELL-010's whole precision story rests on being able to see them,
 * so they are captured as a raw argument string here and split downstream.
 *
 * `use` is included as a "method" because `app.use(requireAuth)` is how
 * application-wide middleware is mounted, which is the strongest possible
 * evidence that a symbol is a guard.
 */
const JS_ROUTE =
  /(?:^|[^\w$.])(?<obj>[\w$]{1,40})\.(?<method>get|post|put|patch|delete|head|options|all|use)[^\S\r\n]{0,4}\(/g;

/**
 * `export default …`, up to but not including the expression.
 *
 * The Next.js Pages Router registers an API endpoint by DEFAULT-EXPORTING its
 * handler and writing no registration at all, so this is the only place the
 * binding between "this file is an endpoint" and "this function serves it" is
 * written. See `fileRouteConvention` for why that had to be read.
 *
 * Horizontal whitespace only after `default`: `export default\nhandler` is legal
 * and is not matched, which costs a rare formatting style and keeps the pattern
 * from running across a line into an unrelated statement.
 */
const JS_EXPORT_DEFAULT = /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{1,4}default[^\S\r\n]{1,8}/g;

/**
 * `const NAME = callee(…)` — a binding whose initializer is a CALL.
 *
 * ★ THE SHAPE THAT MADE VG-SMELL-013 UNREACHABLE ON REAL CODE.
 *
 * `JS_HEAD`'s `fnB` alternative accepts `const h = (req,res) => {}` and
 * `const h = function () {}` and nothing else, so
 * `const handler = withAnyRole(['admin'], async (req,res) => {…})` — the
 * dominant way a Next.js endpoint is written — produced NO symbol. Not a symbol
 * with a wrong span: no symbol at all, which is silent everywhere downstream.
 * `design-smells-crossfile/index.ts` records the consequence measured over 1,000
 * repositories: of 569 authorization-shaped decisions, exactly 1 sat inside an
 * indexed handler body.
 *
 * This pattern only finds the HEAD of such a binding. Whether the call actually
 * wraps a function, and which of its arguments that function is, is decided by
 * `peelHandlerExpression` — a regex cannot count the brackets.
 *
 * `callee` is `[\w$.]{1,80}` rather than an alternation with a bounded dotted
 * tail, matching `JS_ROUTE`'s house style; the last segment is what a consumer
 * resolves. It deliberately also matches `async` in `const h = async (…) => {}`,
 * and that case is refused downstream by requiring at least one wrapper — which
 * is a stronger test than a keyword blocklist, because it is derived from the
 * shape rather than from a list somebody has to remember to extend.
 */
const JS_WRAPPED_BINDING =
  /(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:const|let|var)[^\S\r\n]{1,4}(?<name>[\w$]{1,60})[^\S\r\n]{0,4}(?::[^=\n]{0,120})?=[^\S\r\n]{0,4}(?<callee>[\w$.]{1,80})[^\S\r\n]{0,4}\(/g;

/**
 * A function expression, anchored at the start of the text it is given.
 *
 * The three forms an inline handler is written in, and the `fname` group is
 * load-bearing rather than decorative: `export default function handler(…)` is
 * ALREADY indexed by `JS_HEAD`, so synthesising an `<anonymous@N>` symbol for it
 * would put two symbols with the same body span in one index and let a rule
 * count one handler twice.
 *
 * Every quantifier is bounded and none is nested under another, for the reason
 * stated on `JS_HEAD`.
 */
const FUNCTION_LITERAL_HEAD =
  /^(?:async[^\S\r\n]{1,4})?(?:function[^\S\r\n]{0,4}\*?[^\S\r\n]{0,4}(?<fname>[\w$]{1,60})?[^\S\r\n]{0,4}\(|\([^()\n]{0,300}\)[^\S\r\n]{0,4}(?::[^=>\n]{0,80})?=>|[\w$]{1,40}[^\S\r\n]{0,4}=>)/;

/** A bare (possibly dotted) identifier at the start of the text it is given. */
const HANDLER_IDENTIFIER = /^([\w$]{1,60}(?:\.[\w$]{1,60}){0,3})([^\S\r\n]{0,4})/;

/** Python `def` / `async def`, with the indentation that defines its block. */
const PY_DEF = /(?:^|\n)(?<indent>[^\S\r\n]{0,80})(?:async[^\S\r\n]{1,4})?def[^\S\r\n]{1,4}(?<fn>[\w]{1,60})[^\S\r\n]{0,4}\(/g;
const PY_CLASS = /(?:^|\n)(?<indent>[^\S\r\n]{0,80})class[^\S\r\n]{1,4}(?<cls>[\w]{1,60})[^\S\r\n]{0,4}(?:\((?<base>[^)\n]{0,120})\))?/g;
// `mod` is `[\w., \t]`, NOT `[\w.,\s]`. `\s` matches `\n`, so the greedy class
// ran straight through the end of the line and swallowed every following import
// statement into one match — `import os` on line 1 captured
// "os\nfrom .auth import require_admin". An import statement is a single line
// (continuations aside), so the character class has to be the one that says so.
const PY_IMPORT =
  /(?:^|\n)[^\S\r\n]{0,20}(?:from[^\S\r\n]{1,4}(?<from>[\w.]{1,120})[^\S\r\n]{1,4}import[^\S\r\n]{1,4}(?<names>[^\n]{1,200})|import[^\S\r\n]{1,4}(?<mod>[\w., \t]{1,200}))/g;

/** C/C++ `#include "..."` and `#include <...>`. */
const C_INCLUDE = /(?:^|\n)[^\S\r\n]{0,20}#[^\S\r\n]{0,8}include[^\S\r\n]{0,8}(?:"(?<q>[^"\n]{1,200})"|<(?<a>[^>\n]{1,200})>)/g;

/**
 * C/C++ function DEFINITIONS (not declarations).
 *
 * The trailing `\{` is what separates the two, and it matters more here than in
 * JS: `#20b` reasons about "defined but never called", and a prototype in a
 * header counted as a definition would make every declared-but-externally-called
 * function look defined-and-unused. `extractBlockAfter` stops at a `;` before
 * any `{` for the same reason, so the two mechanisms agree.
 */
// The `(?:\r?\n[^\S\r\n]{0,20})?` before `\{` is not optional decoration: C is
// written in both brace styles, and `int crypto_init(void)\n{` — the Allman
// form used throughout embedded codebases and by most code generators — puts the
// brace on its own line. Requiring it on the same line as the parameter list
// silently indexed ZERO functions in every such file, which made #20b report
// nothing on exactly the firmware it was written for.
//
// ★ THE SAME MISTAKE EXISTED ONE TOKEN EARLIER, AND A CORPUS SWEEP FOUND IT.
// The gap between the return type and the function NAME was horizontal
// whitespace only, so this form was invisible:
//
//     const char*
//     parse_number(const char* first, const char* last)
//     {
//
// That is the LLVM/libcxxabi house style — return type on its own line — and it
// is ordinary C++, not an exotic case. Every function written that way was
// missing from `symbols` entirely.
//
// It surfaced as a VG-AISC-002 false positive rather than as an absence, which
// is what made it findable: sweeping `paper_data/corpus1k`, that rule reported
// `parse_number` and `parse_substitution` in lucasg/Dependencies as calls to
// functions "defined nowhere in the project" — while pointing AT THE LINE OF
// THEIR OWN DEFINITION. A missing symbol is silent; a rule built on top of the
// missing symbol is not.
//
// The added alternative allows ONE line break with bounded indentation on either
// side. Every quantifier stays capped, so the D3 three-second contract still
// holds by construction.
const C_FUNC =
  /(?:^|\n)(?:[\w$]{1,40}[^\S\r\n]{1,8}){0,4}(?<ret>[\w$*]{1,60})(?:[^\S\r\n]{1,8}|[^\S\r\n]{0,20}\r?\n[^\S\r\n]{0,20})\*{0,3}(?<fn>[\w$]{1,80})[^\S\r\n]{0,4}\([^;{]{0,400}\)[^\S\r\n]{0,20}(?:\r?\n[^\S\r\n]{0,20})?\{/g;

/** Reserved words that a definition-shaped C pattern would otherwise catch. */
const C_NOT_A_FUNCTION = new Set([
  'if', 'for', 'while', 'switch', 'return', 'sizeof', 'do', 'else', 'catch',
  'struct', 'union', 'enum', 'typedef', 'case', 'default', 'goto',
]);

/** Split an import clause (`{ a, b as c }, d`) into the local binding names. */
function bindingNames(clause: string | undefined): string[] {
  if (!clause) return [];
  return clause
    .replace(/[{}]/g, ' ')
    .split(',')
    .map((part) => {
      const trimmed = part.trim();
      // `a as b` binds `b`; `* as ns` binds `ns`.
      const asMatch = /\bas\b[^\S\r\n]{1,4}([\w$]{1,60})/.exec(trimmed);
      if (asMatch) return asMatch[1]!;
      const plain = /^([\w$]{1,60})/.exec(trimmed);
      return plain ? plain[1]! : '';
    })
    .filter((n) => n.length > 0 && n !== 'type' && n !== 'from');
}

/**
 * Split a call's argument list at top-level commas.
 *
 * Needed because a route registration's guard arguments must be separated from
 * an inline handler that itself contains commas — `router.get('/x', requireAdmin,
 * (req, res) => {...})` has three arguments, not four. Counts bracket depth over
 * text that has already been blanked, so a comma inside a string is not a
 * separator.
 *
 * Returns offsets alongside the text so a caller can locate an inline handler in
 * the ORIGINAL content, which is what `IndexedSymbol.bodyStart` has to point at.
 */
function splitArgs(blanked: string, openParen: number): { text: string; start: number }[] {
  const args: { text: string; start: number }[] = [];
  let depth = 0;
  let start = openParen + 1;
  for (let i = openParen; i < blanked.length && i < openParen + 4000; i += 1) {
    const c = blanked[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) {
        args.push({ text: blanked.slice(start, i), start });
        return args;
      }
    } else if (c === ',' && depth === 1) {
      args.push({ text: blanked.slice(start, i), start });
      start = i + 1;
    }
  }
  return args;
}

// ---------------------------------------------------------------------------
// ROUTES DECLARED BY FILE PATH — the Next.js conventions
//
// ★ WHY A PATH PREDICATE IS IN AN INDEXER THAT OTHERWISE ONLY READS TEXT.
//
// Every other route in this file is found because somebody WROTE a registration
// — `router.get('/x', guard, handler)` — and the guards are visible because they
// are arguments. Next.js registers by FILE PATH: `pages/api/users.ts` is the
// `/api/users` endpoint and there is no call site anywhere in the repository
// that says so. A reader of the file knows it is an endpoint; the indexer, which
// only read the text, did not.
//
// That is not a cosmetic gap. `design-smells-crossfile/index.ts` records that
// VG-SMELL-013 reached its decision point 0 times in 1,000 real repositories,
// and that the cause was structural rather than a threshold: premise (a) needs
// a guard in a registration's middleware position and these files have no
// registration, so it could not form at all. LAION-AI/Open-Assistant carries
// exactly the shape 013 describes — a `withAnyRole` convention over 11 endpoints,
// one of which re-derives the role inline and returns 403 — and was invisible.
//
// ★ WHAT IS DELIBERATELY NOT CLAIMED HERE.
//
// This is a CONVENTION, not the framework's own resolution. `routePath` is
// derived from the segments and keeps `[id]`, `[...slug]` and `@slot` verbatim;
// route groups `(marketing)` are dropped because they provably contribute no URL
// segment. It is good enough for the two things a consumer does with a path —
// test it against `isPublicByDesignRoute`'s vocabulary and print it — and it is
// NOT a claim that the string is the URL Next.js will serve.
//
// ★ THE FALSE-POSITIVE DIRECTION, AND THE GATE THAT CLOSES IT.
//
// A directory called `app` is not proof of the App Router, and a file called
// `route.ts` under one is not proof of a route handler. So the path predicate is
// necessary and NOT sufficient: a binding is emitted only when the file also
// EXPORTS what the convention requires — a default export for `pages/api`, an
// export named for an HTTP method for `app/**/route.ts`. `app/router/route.ts`
// exporting `createRouter` yields nothing, and neither does `lib/api.ts` or
// `pages/index.tsx`, which do not match the path predicate in the first place.
// ---------------------------------------------------------------------------

/** Source extensions a Next.js convention file can carry. */
const NEXT_ROUTE_EXT = /\.(?:tsx?|jsx?|mjs|cjs)$/;

/** A declaration file has types and no handler, whatever it is called. */
const DECLARATION_FILE = /\.d\.[cm]?ts$/;

/**
 * App Router exports that ARE route handlers.
 *
 * Uppercase and exact. `app/api/x/route.ts` exporting `get` (lowercase) is a
 * helper, not a handler — Next.js matches the uppercase name — and admitting the
 * lowercase spelling would turn every `export const post = …` in the tree into a
 * route registration.
 */
const APP_ROUTE_METHOD: ReadonlySet<string> = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

interface RouteConvention {
  kind: 'pages-api' | 'app-route';
  /** URL path DERIVED from the file path. See the block comment above. */
  routePath: string;
}

/**
 * Which Next.js file-path routing convention, if any, this path follows.
 *
 * Returns `null` for everything else, which is every file in most repositories.
 */
export function fileRouteConvention(filePath: string): RouteConvention | null {
  if (DECLARATION_FILE.test(filePath)) return null;
  const ext = NEXT_ROUTE_EXT.exec(filePath);
  if (!ext) return null;

  const segments = filePath.split('/');
  if (segments.length < 2) return null;
  const fileName = segments[segments.length - 1]!;
  const stem = fileName.slice(0, fileName.length - ext[0].length);
  if (stem.length === 0) return null;

  // ── App Router: `app/**/route.{ts,tsx,js,…}` ─────────────────────────────
  //
  // `page.tsx` is deliberately absent: a page renders, it does not serve a
  // method, and treating one as a route would put every React component in the
  // tree into the handler population.
  if (stem === 'route') {
    for (let i = segments.length - 2; i >= 0; i -= 1) {
      if (segments[i] !== 'app') continue;
      const parts = segments
        .slice(i + 1, segments.length - 1)
        .filter((s) => !(s.startsWith('(') && s.endsWith(')')));
      return { kind: 'app-route', routePath: `/${parts.join('/')}` };
    }
    return null;
  }

  // ── Pages Router: `pages/api/**` ─────────────────────────────────────────
  //
  // `_app`, `_document` and the legacy `_middleware` are Next.js's own reserved
  // files and are not endpoints; the underscore is the framework's marker for
  // exactly that, so it is the test used rather than a list of names.
  if (stem.startsWith('_')) return null;
  for (let i = segments.length - 3; i >= 0; i -= 1) {
    if (segments[i] !== 'pages' || segments[i + 1] !== 'api') continue;
    const parts = segments.slice(i + 1, segments.length - 1);
    // `pages/api/users/index.ts` serves `/api/users`, not `/api/users/index`.
    if (stem !== 'index') parts.push(stem);
    return { kind: 'pages-api', routePath: `/${parts.join('/')}` };
  }
  return null;
}

/**
 * How many `wrapper(` layers are peeled before giving up.
 *
 * Four. `withSentry(withAuth(withValidation(handler)))` is three and is the
 * deepest stack that occurs in practice; the bound exists so a pathological or
 * generated expression costs a constant rather than being followed forever.
 */
const MAX_WRAPPER_DEPTH = 4;

/** Bound on the whitespace skipped between two tokens of one expression. */
const MAX_EXPRESSION_GAP = 200;

interface PeeledHandler {
  /**
   * Callee identifiers applied AROUND the handler, outermost first.
   *
   * ★ THESE ARE MIDDLEWARE, AND THE CLAIM IS THE POINT OF THE WHOLE CHANGE.
   *
   * `export default withAnyRole(['admin'], handler)` puts `withAnyRole` in
   * exactly the position `router.get('/x', requireAdmin, handler)` puts
   * `requireAdmin`: between the request and the handler, deciding whether the
   * handler runs. It is the same delegation written in the vocabulary of a
   * framework that has no registration call, so it lands in the same field.
   */
  wrappers: string[];
  /** The handler's name, when the innermost expression was an identifier. */
  handlerName?: string;
  /** The handler's span, when the innermost expression was written in place. */
  inline?: { headOffset: number; start: number; end: number };
}

/**
 * Read `withA(withB(handler))` / `withA(opts, async (req,res) => {…})` and say
 * what wraps what.
 *
 * Bracket counting, not a regex, because the argument that holds the handler is
 * the LAST one and finding it means balancing everything before it —
 * `splitArgs` already does that over blanked text and is reused rather than
 * reimplemented.
 *
 * Returns `null` rather than a guess whenever the expression is not one of the
 * three shapes it understands. A wrong answer here becomes a wrong
 * `middlewareNames`, which is a premise VG-SMELL-013 reasons FROM — so failing
 * quiet is the required direction, the same argument the file header makes about
 * `extractBlockAfter`.
 */
function peelHandlerExpression(blanked: string, at: number): PeeledHandler | null {
  let offset = at;
  const wrappers: string[] = [];

  for (let depth = 0; depth <= MAX_WRAPPER_DEPTH; depth += 1) {
    // Whitespace INCLUDING newlines: a wrapper call with three arguments is
    // routinely formatted one per line, and stopping at the first `\n` would
    // refuse the most readable spelling of the shape this exists to read.
    let skipped = 0;
    while (offset < blanked.length && skipped < MAX_EXPRESSION_GAP && /\s/.test(blanked[offset]!)) {
      offset += 1;
      skipped += 1;
    }
    const rest = blanked.slice(offset, offset + 420);

    const literal = FUNCTION_LITERAL_HEAD.exec(rest);
    if (literal) {
      const named = literal.groups?.fname;
      if (named) return { wrappers, handlerName: named };

      // ★ A CONCISE ARROW BODY IS REFUSED RATHER THAN GIVEN A GUESSED SPAN, AND
      // THIS IS THE ONE PLACE THIS FUNCTION COULD HAVE FABRICATED EVIDENCE.
      //
      // `extractBlockAfter` finds the first `{` within its head gap. Handed
      // `(x) => \`${a}\``, `(x) => ({ a })` or `(x) => f(x)`, the nearest `{` is
      // a template hole, an object literal, or — worst — the body of an
      // unrelated function four hundred characters further down. Each of those
      // is a symbol with a plausible name and a span that contains code it does
      // not contain, which is exactly the failure this file's header says the
      // anchored patterns exist to avoid.
      //
      // So the block has to be the arrow's OWN, and that is decidable: an arrow
      // whose body is a block writes `{` next. When it does not, nothing is
      // recorded — and the recall cost is nil, because a concise body holds one
      // expression and the consumers of this span are looking for a refusing
      // `if` statement.
      //
      // The `function (…)` form is exempt: the match ends at its parameter list
      // and `extractBlockAfter` walks past it, which is byte-for-byte what
      // `JS_HEAD` already does for every function declaration in the file.
      let blockFrom = offset + literal[0].length - 1;
      if (!literal[0].endsWith('(')) {
        let gap = 0;
        let i = offset + literal[0].length;
        while (i < blanked.length && gap < MAX_EXPRESSION_GAP && /\s/.test(blanked[i]!)) {
          i += 1;
          gap += 1;
        }
        if (blanked[i] !== '{') return null;
        blockFrom = i;
      }

      const block = extractBlockAfter(blanked, blockFrom, { maxHeadGap: 400 });
      if (!block) return null;
      return { wrappers, inline: { headOffset: offset, start: block.start, end: block.end } };
    }

    const id = HANDLER_IDENTIFIER.exec(rest);
    if (!id) return null;
    const after = offset + id[0].length;
    // Not a call: this is the innermost expression, and it names the handler.
    if (blanked[after] !== '(') return { wrappers, handlerName: id[1]!.split('.').pop()! };
    if (depth === MAX_WRAPPER_DEPTH) return null;

    // The LAST NON-EMPTY argument, not simply the last. A trailing comma —
    // which every formatter in this ecosystem emits on a multi-line call — makes
    // `splitArgs` produce a final entry that is pure whitespace, and reading
    // that as the handler position refused exactly the calls that are long
    // enough to be formatted across lines. That is the shape this exists to
    // read, so it is the shape it must not lose.
    const args = splitArgs(blanked, after);
    let last: { text: string; start: number } | undefined;
    for (let k = args.length - 1; k >= 0; k -= 1) {
      if (args[k]!.text.trim().length > 0) {
        last = args[k];
        break;
      }
    }
    if (!last) return null;
    wrappers.push(id[1]!.split('.').pop()!);
    offset = last.start;
  }
  return null;
}

/** Index a TypeScript/JavaScript file. */
function indexJs(file: SourceFile, blanked: string, lineStarts: number[]): StructureIndex {
  const symbols: IndexedSymbol[] = [];
  const imports: ImportEdge[] = [];
  const routes: RouteBinding[] = [];
  const exportedNames = new Set<string>();

  // ── classes (recorded first so methods can name their enclosing class) ─────
  const classSpans: { name: string; start: number; end: number }[] = [];
  JS_CLASS.lastIndex = 0;
  for (let m = JS_CLASS.exec(blanked); m; m = JS_CLASS.exec(blanked)) {
    const name = m.groups?.cls;
    if (!name) continue;
    const headAt = m.index + m[0].indexOf('class');
    const block = extractBlockAfter(blanked, m.index + m[0].length, { maxHeadGap: 300 });
    const start = block ? block.start : headAt;
    const end = block ? block.end : headAt;
    classSpans.push({ name, start, end });
    // `extends Base` — captured by JS_CLASS since 0.3.0-α and discarded until
    // VG-SMELL-030 needed it. `Repo<Item>` keeps only `Repo`: the type argument
    // is not part of the name a consumer resolves against the import graph, and
    // the `base` group's character class stops at `<` anyway.
    const jsBase = m.groups?.base?.trim();
    const baseClasses = jsBase ? [jsBase] : [];
    symbols.push({
      name,
      kind: 'class',
      declaredKind: 'class',
      filePath: file.filePath,
      startLine: lineAt(lineStarts, headAt),
      endLine: lineAt(lineStarts, end),
      startColumn: columnAt(lineStarts, headAt),
      bodyStart: start,
      bodyEnd: end,
      exported: /export[^\S\r\n]{1,4}(?:abstract[^\S\r\n]{1,4})?class/.test(m[0]),
      ...(baseClasses.length > 0 ? { baseClasses } : {}),
    });
    if (JS_CLASS.lastIndex === m.index) JS_CLASS.lastIndex += 1;
  }

  const enclosingClassOf = (offset: number): string | undefined =>
    classSpans.find((c) => offset > c.start && offset < c.end)?.name;

  // ── decorators, keyed by the line they sit above ──────────────────────────
  const decoratorsByLine = new Map<number, string[]>();
  DECORATOR.lastIndex = 0;
  for (let m = DECORATOR.exec(blanked); m; m = DECORATOR.exec(blanked)) {
    const dec = m.groups?.dec;
    if (!dec) continue;
    const line = lineAt(lineStarts, m.index + m[0].indexOf('@'));
    const list = decoratorsByLine.get(line) ?? [];
    list.push(dec);
    decoratorsByLine.set(line, list);
    if (DECORATOR.lastIndex === m.index) DECORATOR.lastIndex += 1;
  }

  /**
   * Decorators attached to a declaration, walking upward past other decorators.
   *
   * Anchored to lines rather than offsets because that is how they are written —
   * a stack of `@Get()` / `@UseGuards()` immediately above the method. Stops at
   * the first line that is neither blank nor a decorator, so a decorator
   * belonging to a previous member is never attributed to this one.
   */
  const decoratorsFor = (declLine: number): string[] => {
    const out: string[] = [];
    for (let line = declLine - 1; line >= 1; line -= 1) {
      const here = decoratorsByLine.get(line);
      if (here) {
        out.unshift(...here);
        continue;
      }
      const text = file.lines[line - 1] ?? '';
      if (text.trim().length === 0) continue;
      break;
    }
    const own = decoratorsByLine.get(declLine);
    if (own) out.push(...own);
    return out;
  };

  // ── functions and methods ─────────────────────────────────────────────────
  JS_HEAD.lastIndex = 0;
  for (let m = JS_HEAD.exec(blanked); m && symbols.length < MAX_SYMBOLS_PER_FILE; m = JS_HEAD.exec(blanked)) {
    const g = m.groups ?? {};
    const name = g.fnA ?? g.fnB ?? g.fnC;
    if (!name) {
      if (JS_HEAD.lastIndex === m.index) JS_HEAD.lastIndex += 1;
      continue;
    }
    const nameOffset = m.index + m[0].lastIndexOf(name);
    const block = extractBlockAfter(blanked, m.index + m[0].length - 1, { maxHeadGap: 400 });
    if (!block) {
      if (JS_HEAD.lastIndex === m.index) JS_HEAD.lastIndex += 1;
      continue;
    }
    const startLine = lineAt(lineStarts, nameOffset);
    const enclosing = enclosingClassOf(m.index);
    const decs = decoratorsFor(startLine);
    symbols.push({
      name,
      kind: enclosing ? 'method' : 'function',
      declaredKind: enclosing ? 'method' : 'function',
      filePath: file.filePath,
      startLine,
      endLine: lineAt(lineStarts, block.end),
      startColumn: columnAt(lineStarts, nameOffset),
      bodyStart: block.start,
      bodyEnd: block.end,
      exported: /(?:^|[^\w$])export[^\S\r\n]/.test(m[0]),
      ...(decs.length > 0 ? { decorators: decs } : {}),
      ...(enclosing ? { enclosingClass: enclosing } : {}),
    });
    if (JS_HEAD.lastIndex === m.index) JS_HEAD.lastIndex += 1;
  }

  // ── bindings whose initializer is a wrapper CALL around a function ────────
  //
  // `const handler = withAnyRole(['admin'], async (req,res) => {…})`.
  //
  // Two things come out of this and only one of them is a symbol. The symbol is
  // `handler`, spanning the arrow's body, which is what makes "is the check
  // written INSIDE this handler" an answerable question. The other is the
  // wrapper chain, which is kept in a LOCAL map rather than on `IndexedSymbol`:
  // its only consumer is the route synthesis twenty lines below, the field would
  // otherwise be a public part of the index with one reader, and adding one to
  // the shared type is a change every other producer of a `StructureIndex` would
  // then have to have an answer for.
  //
  // ★ `wrappers.length > 0` IS THE ADMISSION TEST, and it is doing more work
  // than it looks like. `const h = async (req,res) => {…}` reaches here (the
  // pattern's `callee` group happily matches `async`), and `peelHandlerExpression`
  // reports it as a function literal with NO wrappers — so requiring at least one
  // refuses it, and `JS_HEAD` keeps its existing, correct symbol for it rather
  // than gaining a duplicate.
  const wrapperChains = new Map<string, string[]>();
  const bindingAlias = new Map<string, string>();
  /** binding name → the line it is declared on, for a route that cites it. */
  const bindingLine = new Map<string, number>();
  JS_WRAPPED_BINDING.lastIndex = 0;
  for (
    let m = JS_WRAPPED_BINDING.exec(blanked);
    m && symbols.length < MAX_SYMBOLS_PER_FILE;
    m = JS_WRAPPED_BINDING.exec(blanked)
  ) {
    const g = m.groups ?? {};
    const name = g.name;
    const callee = g.callee;
    if (!name || !callee) {
      if (JS_WRAPPED_BINDING.lastIndex === m.index) JS_WRAPPED_BINDING.lastIndex += 1;
      continue;
    }
    const calleeOffset = m.index + m[0].lastIndexOf(callee);
    const peeled = peelHandlerExpression(blanked, calleeOffset);
    if (!peeled || peeled.wrappers.length === 0) {
      if (JS_WRAPPED_BINDING.lastIndex === m.index) JS_WRAPPED_BINDING.lastIndex += 1;
      continue;
    }

    const bindingNameOffset = m.index + m[0].lastIndexOf(name);
    wrapperChains.set(name, peeled.wrappers);
    bindingLine.set(name, lineAt(lineStarts, bindingNameOffset));
    if (peeled.handlerName) {
      // `const h = withAuth(realHandler)` — `h` has no body of its own; the body
      // belongs to `realHandler`, which is a symbol in its own right (here or in
      // another file). Recording an alias rather than a second symbol keeps one
      // function from being counted twice.
      bindingAlias.set(name, peeled.handlerName);
    } else if (peeled.inline) {
      const nameOffset = bindingNameOffset;
      symbols.push({
        name,
        kind: 'function',
        declaredKind: 'function',
        filePath: file.filePath,
        startLine: lineAt(lineStarts, nameOffset),
        endLine: lineAt(lineStarts, peeled.inline.end),
        startColumn: columnAt(lineStarts, nameOffset),
        bodyStart: peeled.inline.start,
        bodyEnd: peeled.inline.end,
        exported: /(?:^|[^\w$])export[^\S\r\n]/.test(m[0]),
      });
    }
    if (JS_WRAPPED_BINDING.lastIndex === m.index) JS_WRAPPED_BINDING.lastIndex += 1;
  }

  // ── imports ───────────────────────────────────────────────────────────────
  JS_IMPORT.lastIndex = 0;
  for (let m = JS_IMPORT.exec(blanked); m; m = JS_IMPORT.exec(blanked)) {
    const spec = m.groups?.spec;
    if (!spec) continue;
    // The specifier text was blanked (it is a string literal), so read the
    // ORIGINAL content at the same offsets — this is exactly the property
    // length-preserving blanking exists to provide.
    const specStart = m.index + m[0].lastIndexOf(spec);
    imports.push({
      fromFile: file.filePath,
      specifier: file.content.slice(specStart, specStart + spec.length),
      names: bindingNames(m.groups?.names),
      line: lineAt(lineStarts, m.index + Math.max(0, m[0].indexOf('import'))),
      syntax: 'esm',
    });
    if (JS_IMPORT.lastIndex === m.index) JS_IMPORT.lastIndex += 1;
  }
  JS_REQUIRE.lastIndex = 0;
  for (let m = JS_REQUIRE.exec(blanked); m; m = JS_REQUIRE.exec(blanked)) {
    const spec = m.groups?.spec;
    if (!spec) continue;
    const specStart = m.index + m[0].lastIndexOf(spec);
    imports.push({
      fromFile: file.filePath,
      specifier: file.content.slice(specStart, specStart + spec.length),
      names: bindingNames(m.groups?.names),
      line: lineAt(lineStarts, m.index),
      syntax: 'require',
    });
    if (JS_REQUIRE.lastIndex === m.index) JS_REQUIRE.lastIndex += 1;
  }

  // ── exports ───────────────────────────────────────────────────────────────
  JS_EXPORT.lastIndex = 0;
  for (let m = JS_EXPORT.exec(blanked); m; m = JS_EXPORT.exec(blanked)) {
    const g = m.groups ?? {};
    if (g.name) exportedNames.add(g.name);
    if (g.cjs) exportedNames.add(g.cjs);
    if (g.list) for (const n of bindingNames(g.list)) exportedNames.add(n);
    if (JS_EXPORT.lastIndex === m.index) JS_EXPORT.lastIndex += 1;
  }
  for (const s of symbols) if (s.exported) exportedNames.add(s.name);

  // ── route registrations ───────────────────────────────────────────────────
  JS_ROUTE.lastIndex = 0;
  for (let m = JS_ROUTE.exec(blanked); m; m = JS_ROUTE.exec(blanked)) {
    const method = m.groups?.method;
    if (!method) continue;
    const openParen = m.index + m[0].length - 1;
    const args = splitArgs(blanked, openParen);
    if (args.length === 0) {
      if (JS_ROUTE.lastIndex === m.index) JS_ROUTE.lastIndex += 1;
      continue;
    }

    // A leading string literal is the path. `use` may omit it.
    let pathArg: string | undefined;
    let rest = args;
    const firstText = args[0]!.text.trim();
    if (/^['"`]/.test(file.content.slice(args[0]!.start, args[0]!.start + args[0]!.text.length).trim())) {
      const raw = file.content.slice(args[0]!.start, args[0]!.start + args[0]!.text.length).trim();
      pathArg = raw.slice(1, -1);
      rest = args.slice(1);
    } else if (firstText.length === 0) {
      rest = args.slice(1);
    }

    const handlerArg = rest[rest.length - 1];
    const middlewareNames = rest
      .slice(0, Math.max(0, rest.length - 1))
      .map((a) => {
        // `requireRole('admin')` delegates just as much as `requireAdmin` does;
        // the guard is the callee, so take the identifier before any `(`.
        const t = a.text.trim();
        const id = /^([\w$.]{1,80})/.exec(t);
        return id ? id[1]!.split('.').pop()! : '';
      })
      .filter((n) => n.length > 0);

    let handlerName: string | undefined;
    let inlineHandler: IndexedSymbol | undefined;
    if (handlerArg) {
      const t = handlerArg.text.trim();
      const bare = /^([\w$.]{1,80})[^\S\r\n]{0,4}$/.exec(t);
      if (bare) {
        handlerName = bare[1]!.split('.').pop();
      } else if (/=>|function/.test(t)) {
        // An inline handler. Its body span is what a rule needs in order to ask
        // "is the authorization check written INSIDE this handler", so it is
        // recorded as a first-class symbol rather than left as text.
        const block = extractBlockAfter(blanked, handlerArg.start, { maxHeadGap: 400 });
        if (block) {
          const line = lineAt(lineStarts, handlerArg.start);
          inlineHandler = {
            name: `<anonymous@${line}>`,
            kind: 'route-handler',
            declaredKind: 'function',
            filePath: file.filePath,
            startLine: line,
            endLine: lineAt(lineStarts, block.end),
            startColumn: columnAt(lineStarts, handlerArg.start),
            bodyStart: block.start,
            bodyEnd: block.end,
            exported: false,
          };
          symbols.push(inlineHandler);
          handlerName = inlineHandler.name;
        }
      }
    }

    routes.push({
      filePath: file.filePath,
      line: lineAt(lineStarts, m.index),
      method: method.toLowerCase(),
      ...(pathArg !== undefined ? { path: pathArg } : {}),
      middlewareNames,
      ...(handlerName !== undefined ? { handlerName } : {}),
      ...(inlineHandler ? { inlineHandler } : {}),
    });
    if (JS_ROUTE.lastIndex === m.index) JS_ROUTE.lastIndex += 1;
  }

  // ── routes declared by FILE PATH (Next.js) ────────────────────────────────
  //
  // See the block comment above `fileRouteConvention` for why this exists and
  // what it does not claim. The path is necessary and not sufficient: nothing is
  // emitted unless the file also exports what the convention requires.
  const convention = fileRouteConvention(file.filePath);
  if (convention) {
    /** Emit one convention route, resolving a binding's own wrapper chain. */
    const recordConventionRoute = (
      method: string,
      line: number,
      peeled: PeeledHandler,
    ): void => {
      let wrappers = peeled.wrappers;
      let handlerName = peeled.handlerName;
      let inlineHandler: IndexedSymbol | undefined;

      if (handlerName) {
        // `const handler = withAnyRole(…, fn); export default handler;` writes
        // the guard on the BINDING and the registration on the export, so the
        // two halves have to be joined or the wrapper is lost — which is the
        // whole premise VG-SMELL-013 needs.
        const chain = wrapperChains.get(handlerName);
        if (chain) wrappers = [...wrappers, ...chain];
        handlerName = bindingAlias.get(handlerName) ?? handlerName;
      } else if (peeled.inline) {
        if (symbols.length >= MAX_SYMBOLS_PER_FILE) return;
        const headLine = lineAt(lineStarts, peeled.inline.headOffset);
        inlineHandler = {
          name: `<anonymous@${headLine}>`,
          kind: 'route-handler',
          declaredKind: 'function',
          filePath: file.filePath,
          startLine: headLine,
          endLine: lineAt(lineStarts, peeled.inline.end),
          startColumn: columnAt(lineStarts, peeled.inline.headOffset),
          bodyStart: peeled.inline.start,
          bodyEnd: peeled.inline.end,
          exported: true,
        };
        symbols.push(inlineHandler);
        handlerName = inlineHandler.name;
      }

      if (!handlerName) return;
      routes.push({
        filePath: file.filePath,
        line,
        method,
        path: convention.routePath,
        middlewareNames: wrappers,
        handlerName,
        ...(inlineHandler ? { inlineHandler } : {}),
      });
    };

    if (convention.kind === 'app-route') {
      // One binding per HTTP-method export. Walked over `symbols` in declaration
      // order rather than over `APP_ROUTE_METHOD`, so the emitted order is the
      // file's own and does not depend on a Set's iteration order. The second
      // walk picks up `export const GET = withAuth(handler)`, which produces no
      // symbol of its own because the body belongs to `handler`.
      const emitted = new Set<string>();
      const emitAppRoute = (name: string, line: number): void => {
        if (emitted.has(name)) return;
        emitted.add(name);
        // `wrappers: []`, NOT the chain: `recordConventionRoute` resolves the
        // binding's own chain from `handlerName`, and passing it here as well
        // would name the same guard twice in one registration.
        recordConventionRoute(name.toLowerCase(), line, { wrappers: [], handlerName: name });
      };
      for (const s of [...symbols]) {
        if (s.kind === 'class') continue;
        if (!APP_ROUTE_METHOD.has(s.name)) continue;
        if (!s.exported && !exportedNames.has(s.name)) continue;
        emitAppRoute(s.name, s.startLine);
      }
      for (const [name, line] of bindingLine) {
        if (!APP_ROUTE_METHOD.has(name)) continue;
        if (!exportedNames.has(name)) continue;
        emitAppRoute(name, line);
      }
    } else {
      // `pages/api`: ONE default export, one endpoint, and the method is
      // genuinely unknown — a single handler there serves every verb and
      // switches on `req.method` internally. `*` is the value `RouteBinding`
      // already documents for that, and it is the honest one: reporting `post`
      // would invent a fact, and reporting `get` would let VG-SMELL-011 reason
      // about a write it has no evidence of.
      JS_EXPORT_DEFAULT.lastIndex = 0;
      const m = JS_EXPORT_DEFAULT.exec(blanked);
      if (m) {
        const peeled = peelHandlerExpression(blanked, m.index + m[0].length);
        if (peeled) {
          recordConventionRoute('*', lineAt(lineStarts, m.index + m[0].indexOf('export')), peeled);
        }
      }
    }
  }

  // ── promote named handlers to the route-handler role ──────────────────────
  //
  // The role overrides the syntactic kind (see `SymbolKind`), so a consumer
  // asking "is this a handler" gets one answer from one field. `declaredKind`
  // keeps the fact that it was written as a plain function.
  const handlerNames = new Set(routes.map((r) => r.handlerName).filter((n): n is string => !!n));
  const middlewareNamesAll = new Set(routes.flatMap((r) => r.middlewareNames));
  for (const s of symbols) {
    if (s.kind === 'route-handler') continue;
    if (middlewareNamesAll.has(s.name)) s.kind = 'middleware';
    else if (handlerNames.has(s.name)) s.kind = 'route-handler';
  }

  return {
    filePath: file.filePath,
    language: file.language,
    symbols,
    imports,
    routes,
    exportedNames: [...exportedNames].sort(),
    blanked,
  };
}

/**
 * Index a Python file.
 *
 * Blocks are delimited by INDENTATION, so `extractBlockAfter` (which counts
 * braces) does not apply and the body span is computed by scanning forward to
 * the first non-blank line indented no further than the `def` itself. Blank
 * lines and comment-only lines never end a block, which is the rule the language
 * itself uses.
 *
 * Tabs are counted as one column, not expanded to eight. The comparison that
 * matters is "is this line indented further than the def", and mixing tabs and
 * spaces makes any expansion width a guess; treating each character as one unit
 * gives the right answer for consistently-indented files (all of them, since
 * Python 3 rejects the mixture) without pretending to know the tab stop.
 */
function indexPython(file: SourceFile, blanked: string, lineStarts: number[]): StructureIndex {
  const symbols: IndexedSymbol[] = [];
  const imports: ImportEdge[] = [];
  const exportedNames = new Set<string>();

  const indentOf = (line: string): number => {
    let n = 0;
    while (n < line.length && (line[n] === ' ' || line[n] === '\t')) n += 1;
    return n;
  };
  const isBlankOrComment = (line: string): boolean => {
    const t = line.trim();
    return t.length === 0 || t.startsWith('#');
  };

  const classRanges: { name: string; startLine: number; endLine: number }[] = [];

  /**
   * Last line belonging to the block opened at `declLine`.
   *
   * Tracks the last line that was actually PART of the block rather than
   * returning the line before the dedent, because the two differ whenever the
   * block is followed by blank lines: `def f(): ...` followed by two blank lines
   * and then a top-level `def` ends at the last statement, not at the last blank
   * line. Attributing trailing whitespace to the function would make its
   * reported span include code it does not contain — and for a finding that
   * renders a span, that is a wrong answer rather than a harmless one.
   */
  const blockEndLine = (declLine: number, declIndent: number): number => {
    let last = declLine;
    for (let i = declLine; i < file.lines.length; i += 1) {
      const text = file.lines[i] ?? '';
      if (isBlankOrComment(text)) continue;
      if (indentOf(text) <= declIndent) return last;
      last = i + 1;
    }
    return last;
  };

  PY_CLASS.lastIndex = 0;
  for (let m = PY_CLASS.exec(blanked); m; m = PY_CLASS.exec(blanked)) {
    const name = m.groups?.cls;
    if (!name) continue;
    const headOffset = m.index + m[0].indexOf('class');
    const startLine = lineAt(lineStarts, headOffset);
    const declIndent = indentOf(file.lines[startLine - 1] ?? '');
    const endLine = blockEndLine(startLine, declIndent);
    classRanges.push({ name, startLine, endLine });
    // `class Sub(Base, Mixin)` — Python's bases are a comma list, so unlike
    // JavaScript this is genuinely plural. Keyword arguments in the base list
    // (`class Meta(Base, metaclass=ABCMeta)`) are dropped: `metaclass` is not a
    // base and a consumer resolving it against the import graph would either
    // miss or, worse, match something unrelated.
    const pyBases = (m.groups?.base ?? '')
      .split(',')
      .map((b) => b.trim())
      .filter((b) => b.length > 0 && !b.includes('=') && !b.startsWith('*'));
    symbols.push({
      name,
      kind: 'class',
      declaredKind: 'class',
      filePath: file.filePath,
      startLine,
      endLine,
      startColumn: declIndent + 1,
      bodyStart: headOffset,
      bodyEnd: lineStarts[Math.min(endLine, lineStarts.length - 1)] ?? file.content.length,
      exported: !name.startsWith('_'),
      ...(pyBases.length > 0 ? { baseClasses: pyBases } : {}),
    });
    if (PY_CLASS.lastIndex === m.index) PY_CLASS.lastIndex += 1;
  }

  PY_DEF.lastIndex = 0;
  for (let m = PY_DEF.exec(blanked); m && symbols.length < MAX_SYMBOLS_PER_FILE; m = PY_DEF.exec(blanked)) {
    const name = m.groups?.fn;
    if (!name) continue;
    const nameOffset = m.index + m[0].lastIndexOf(name);
    const startLine = lineAt(lineStarts, nameOffset);
    const declIndent = indentOf(file.lines[startLine - 1] ?? '');
    const endLine = blockEndLine(startLine, declIndent);
    const enclosing = classRanges.find((c) => startLine > c.startLine && startLine <= c.endLine);

    // Decorators stack immediately above the def, same convention as JS.
    const decs: string[] = [];
    for (let line = startLine - 1; line >= 1; line -= 1) {
      const text = (file.lines[line - 1] ?? '').trim();
      if (text.length === 0) continue;
      if (text.startsWith('@')) {
        const d = /^@([\w.]{1,80})/.exec(text);
        if (d) decs.unshift(d[1]!);
        continue;
      }
      break;
    }

    symbols.push({
      name,
      kind: enclosing ? 'method' : 'function',
      declaredKind: enclosing ? 'method' : 'function',
      filePath: file.filePath,
      startLine,
      endLine,
      startColumn: declIndent + 1,
      bodyStart: lineStarts[Math.min(startLine, lineStarts.length - 1)] ?? file.content.length,
      bodyEnd: lineStarts[Math.min(endLine, lineStarts.length - 1)] ?? file.content.length,
      exported: !name.startsWith('_'),
      ...(decs.length > 0 ? { decorators: decs } : {}),
      ...(enclosing ? { enclosingClass: enclosing.name } : {}),
    });
    if (PY_DEF.lastIndex === m.index) PY_DEF.lastIndex += 1;
  }

  PY_IMPORT.lastIndex = 0;
  for (let m = PY_IMPORT.exec(blanked); m; m = PY_IMPORT.exec(blanked)) {
    const g = m.groups ?? {};
    const line = lineAt(lineStarts, m.index + 1);
    if (g.from) {
      imports.push({
        fromFile: file.filePath,
        specifier: g.from,
        names: (g.names ?? '')
          .split(',')
          .map((s) => s.trim().split(/\s+as\s+/).pop()!.trim())
          .filter((s) => s.length > 0 && s !== '*'),
        line,
        syntax: 'python',
      });
    } else if (g.mod) {
      for (const mod of g.mod.split(',').map((s) => s.trim()).filter(Boolean)) {
        imports.push({ fromFile: file.filePath, specifier: mod.split(/\s+as\s+/)[0]!.trim(), names: [], line, syntax: 'python' });
      }
    }
    if (PY_IMPORT.lastIndex === m.index) PY_IMPORT.lastIndex += 1;
  }

  for (const s of symbols) if (s.exported) exportedNames.add(s.name);

  return {
    filePath: file.filePath,
    language: file.language,
    symbols,
    imports,
    routes: [],
    exportedNames: [...exportedNames].sort(),
    blanked,
  };
}

/**
 * Index a C/C++ file.
 *
 * Narrower than the JS arm on purpose: its only consumer in this phase is #20b
 * (the include graph and the symbols reachable through it), which needs function
 * DEFINITIONS and `#include` edges and nothing else. Building out routes,
 * decorators, and export lists for a language where those concepts do not apply
 * would be inventing structure to fill a shape.
 */
function indexC(file: SourceFile, blanked: string, lineStarts: number[]): StructureIndex {
  const symbols: IndexedSymbol[] = [];
  const imports: ImportEdge[] = [];

  C_INCLUDE.lastIndex = 0;
  for (let m = C_INCLUDE.exec(blanked); m; m = C_INCLUDE.exec(blanked)) {
    const g = m.groups ?? {};
    const spec = g.q ?? g.a;
    if (!spec) continue;
    // `#include` targets are NOT string literals to the blankers (the C blanker
    // does blank `"..."`), so read from the original at the same offsets.
    const specStart = m.index + m[0].lastIndexOf(spec);
    imports.push({
      fromFile: file.filePath,
      specifier: file.content.slice(specStart, specStart + spec.length),
      names: [],
      line: lineAt(lineStarts, m.index + 1),
      syntax: g.q ? 'quoted' : 'angled',
    });
    if (C_INCLUDE.lastIndex === m.index) C_INCLUDE.lastIndex += 1;
  }

  C_FUNC.lastIndex = 0;
  for (let m = C_FUNC.exec(blanked); m && symbols.length < MAX_SYMBOLS_PER_FILE; m = C_FUNC.exec(blanked)) {
    const name = m.groups?.fn;
    if (!name || C_NOT_A_FUNCTION.has(name)) {
      if (C_FUNC.lastIndex === m.index) C_FUNC.lastIndex += 1;
      continue;
    }
    const nameOffset = m.index + m[0].lastIndexOf(name);
    const block = extractBlockAfter(blanked, m.index + m[0].length - 1, { maxHeadGap: 400 });
    if (!block) {
      if (C_FUNC.lastIndex === m.index) C_FUNC.lastIndex += 1;
      continue;
    }
    symbols.push({
      name,
      kind: 'function',
      declaredKind: 'function',
      filePath: file.filePath,
      startLine: lineAt(lineStarts, nameOffset),
      endLine: lineAt(lineStarts, block.end),
      startColumn: columnAt(lineStarts, nameOffset),
      bodyStart: block.start,
      bodyEnd: block.end,
      exported: !/\bstatic\b/.test(m[0]),
    });
    if (C_FUNC.lastIndex === m.index) C_FUNC.lastIndex += 1;
  }

  return {
    filePath: file.filePath,
    language: file.language,
    symbols,
    imports,
    routes: [],
    exportedNames: symbols.filter((s) => s.exported).map((s) => s.name).sort(),
    blanked,
  };
}

/**
 * Index one file.
 *
 * Truncates at `REGEX_INPUT_CAP` for parity with every rule in
 * `@vibeguard/rules`: no analysis in this project reads past that bound, and a
 * cross-file pass that did would create the situation where a symbol exists in
 * the graph but the core rules never saw the line it is on. Slicing a prefix
 * keeps every offset valid.
 */
export function indexFile(file: SourceFile): StructureIndex {
  const content =
    file.content.length > REGEX_INPUT_CAP ? file.content.slice(0, REGEX_INPUT_CAP) : file.content;
  const bounded: SourceFile =
    content === file.content ? file : { ...file, content, lines: content.split('\n') };

  const lineStarts = buildLineTable(content);

  if (JS_LANGUAGES.has(file.language)) {
    return indexJs(bounded, blankJsLiterals(content), lineStarts);
  }
  if (file.language === 'python') {
    return indexPython(bounded, blankPyLiterals(content), lineStarts);
  }
  if (C_LANGUAGES.has(file.language)) {
    return indexC(bounded, blankCommentsAndStrings(content, file.language), lineStarts);
  }
  // Not a language this phase indexes. An empty index is the honest answer —
  // NOT an error, because a project legitimately contains YAML and Markdown, and
  // NOT a partial guess, because a Go file run through the JS head patterns
  // would produce plausible-looking symbols with wrong spans.
  return {
    filePath: file.filePath,
    language: file.language,
    symbols: [],
    imports: [],
    routes: [],
    exportedNames: [],
    blanked: content,
  };
}

/** Whether this phase can say anything structural about a language. */
export function isIndexableLanguage(language: string): boolean {
  return JS_LANGUAGES.has(language) || language === 'python' || C_LANGUAGES.has(language);
}

/** Body text of a symbol, sliced from the original (unblanked) content. */
export function symbolBody(symbol: IndexedSymbol, file: SourceFile): string {
  return file.content.slice(symbol.bodyStart, symbol.bodyEnd);
}

/** Body text of a symbol, sliced from the blanked copy. */
export function symbolBodyBlanked(symbol: IndexedSymbol, structure: StructureIndex): string {
  return structure.blanked.slice(symbol.bodyStart, symbol.bodyEnd);
}
