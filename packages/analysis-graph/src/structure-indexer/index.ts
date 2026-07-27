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
const C_FUNC =
  /(?:^|\n)(?:[\w$]{1,40}[^\S\r\n]{1,8}){0,4}(?<ret>[\w$*]{1,60})[^\S\r\n]{1,8}\*{0,3}(?<fn>[\w$]{1,80})[^\S\r\n]{0,4}\([^;{]{0,400}\)[^\S\r\n]{0,20}(?:\r?\n[^\S\r\n]{0,20})?\{/g;

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
    return indexC(bounded, blankCommentsAndStrings(content), lineStarts);
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
