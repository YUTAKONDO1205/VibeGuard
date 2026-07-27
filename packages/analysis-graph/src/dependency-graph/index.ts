// dependency-graph-builder — what points at what, across files.
//
// The third submodule of design addendum §8.2. Its job list there: import graph,
// module dependency, class inheritance, interface implementation,
// route-to-handler mapping, handler-to-service mapping. This phase delivers the
// first two plus the C/C++ `#include` arm; inheritance and interface edges wait
// for the smells that need them (VG-SMELL-030/031, phase β), because an edge
// type with no consumer is a maintenance cost with no test that would notice it
// breaking.
//
// WHY RESOLUTION IS LEXICAL AND DELIBERATELY INCOMPLETE
//
// Resolving `./auth` to `src/middleware/auth.ts` is, done properly, the Node
// resolution algorithm plus `tsconfig` path mapping plus `package.json`
// `exports` — a substantial amount of behaviour whose correct implementation is
// somebody's whole library. What is done here instead is candidate extension
// probing against the set of files already admitted to the graph, which gets the
// overwhelmingly common cases (relative imports with or without an extension,
// directory index files) and gets nothing else.
//
// The important property is the DIRECTION of the incompleteness. An unresolved
// specifier produces an edge with no `resolvedFile`, which every consumer treats
// as "points outside the project" — and every consumer of this graph in this
// phase uses resolution to find EXCULPATORY evidence (a guard was imported from
// somewhere, an initializer was referenced). Missing an edge therefore makes a
// rule quieter, never louder. That is the direction a false-positive-sensitive
// analysis has to fail in, and it is the reason a partial resolver is acceptable
// here where it would not be in a compiler.
//
// The one place this asymmetry does NOT hold is VG-AISC-002 (a call to a symbol
// declared in no reachable header), where an unresolved include means the
// evidence is incomplete in the accusing direction. That rule therefore refuses
// to fire at all when any include failed to resolve — see `includeClosure`.

import type { DependencyGraph, ImportEdge, SourceFile, StructureIndex } from '../types.js';

/**
 * Extensions tried when a specifier omits one, in priority order.
 *
 * TypeScript before JavaScript because a project containing both `auth.ts` and
 * a compiled `auth.js` means the source is the one a design smell is a statement
 * about — flagging structure in generated output would be reporting a smell to
 * someone who cannot fix it.
 */
const JS_EXTENSIONS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];
const JS_INDEX_FILES = JS_EXTENSIONS.map((e) => `index${e}`);

/**
 * Normalise a path for use as a graph key.
 *
 * Backslashes become forward slashes, `./` segments collapse, `..` pops. This is
 * not cosmetic: the graph is keyed by path string, and on Windows the same file
 * arrives as `src\routes\a.ts` from a directory walk and as `src/routes/a.ts`
 * from an import specifier. Two spellings of one file is two nodes, and a
 * cross-file rule that needs to see them as one would silently find nothing —
 * on Windows only, which is the worst place for a bug to live because CI is
 * Linux and would stay green.
 */
export function normalizePath(p: string): string {
  const parts = p.replace(/\\/g, '/').split('/');
  const out: string[] = [];
  for (const part of parts) {
    if (part === '' && out.length > 0) continue;
    if (part === '.') continue;
    if (part === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else out.push('..');
      continue;
    }
    out.push(part);
  }
  return out.join('/');
}

/** Directory part of a normalised path (`''` for a top-level file). */
function dirname(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? '' : p.slice(0, i);
}

function join(dir: string, rel: string): string {
  return normalizePath(dir === '' ? rel : `${dir}/${rel}`);
}

/**
 * Resolve one specifier against the set of files in the project.
 *
 * `known` is the exact key space of the graph, so a resolution that succeeds is
 * guaranteed to name a node that exists. Resolving against the real filesystem
 * instead would be able to name files the scan excluded (ignored directories,
 * files past the budget), producing edges to nodes with no structure — which
 * every consumer would then have to defend against.
 */
export function resolveSpecifier(
  edge: ImportEdge,
  known: Set<string>,
): string | undefined {
  const spec = edge.specifier;

  if (edge.syntax === 'quoted' || edge.syntax === 'angled') {
    // C/C++ `#include`. A quoted include is relative to the including file
    // first, then to the project; an angled one is a search path we do not have,
    // so only a project-wide suffix match can resolve it.
    const relative = join(dirname(edge.fromFile), spec);
    if (known.has(relative)) return relative;
    const direct = normalizePath(spec);
    if (known.has(direct)) return direct;
    // Suffix match: `sdk/gpio.h` resolving to `vendor/sdk/gpio.h`. Only accepted
    // when it is UNAMBIGUOUS — two candidates mean the include path decides, and
    // the include path is exactly what is not available here. Guessing between
    // them would attribute declarations to the wrong header.
    const suffix = `/${direct}`;
    const candidates = [...known].filter((k) => k.endsWith(suffix));
    return candidates.length === 1 ? candidates[0] : undefined;
  }

  if (edge.syntax === 'python') {
    // `from .auth import x` / `import package.module`. Leading dots are relative
    // levels; the rest is a dotted path under the importing file's package.
    const dots = /^\.+/.exec(spec)?.[0].length ?? 0;
    const rest = spec.slice(dots).replace(/\./g, '/');
    let base = dirname(edge.fromFile);
    for (let i = 1; i < dots; i += 1) base = dirname(base);
    const roots = dots > 0 ? [base] : [base, ''];
    for (const root of roots) {
      const stem = rest === '' ? root : join(root, rest);
      if (known.has(`${stem}.py`)) return `${stem}.py`;
      if (known.has(join(stem, '__init__.py'))) return join(stem, '__init__.py');
    }
    return undefined;
  }

  // ESM / CommonJS. Bare specifiers are packages, not project files, and are
  // left unresolved rather than suffix-matched: `express` matching some
  // `vendor/express.ts` in the tree would be a fabricated edge.
  if (!spec.startsWith('.')) return undefined;

  const base = join(dirname(edge.fromFile), spec);
  if (known.has(base)) return base;
  // `./auth.js` in TypeScript source means `./auth.ts` — the ESM-mandated
  // extension on the emitted file, not on the source. Rewriting is why a project
  // written to the NodeNext convention resolves at all.
  const rewritten = base.replace(/\.(m|c)?js$/, '');
  for (const ext of JS_EXTENSIONS) {
    if (known.has(base + ext)) return base + ext;
    if (rewritten !== base && known.has(rewritten + ext)) return rewritten + ext;
  }
  for (const index of JS_INDEX_FILES) {
    const candidate = join(base, index);
    if (known.has(candidate)) return candidate;
  }
  return undefined;
}

/**
 * Build the project dependency graph.
 *
 * Mutates the `resolvedFile` field of the edges it is given rather than copying
 * them. The alternative — cloning every edge — would leave the structure indices
 * holding stale unresolved copies, and a consumer reading
 * `structure.imports[i].resolvedFile` (the natural thing to do, since that is
 * where the import is) would get `undefined` for an edge the graph resolved. One
 * edge object with one truth is worth the mutation.
 */
export function buildDependencyGraph(structures: StructureIndex[]): DependencyGraph {
  const known = new Set(structures.map((s) => s.filePath));
  const edges: ImportEdge[] = [];
  const importsOf = new Map<string, Set<string>>();
  const importedBy = new Map<string, Set<string>>();

  for (const s of structures) {
    importsOf.set(s.filePath, importsOf.get(s.filePath) ?? new Set());
    importedBy.set(s.filePath, importedBy.get(s.filePath) ?? new Set());
  }

  for (const s of structures) {
    for (const edge of s.imports) {
      const resolved = resolveSpecifier(edge, known);
      if (resolved !== undefined) edge.resolvedFile = resolved;
      edges.push(edge);
      if (resolved === undefined || resolved === edge.fromFile) continue;
      importsOf.get(edge.fromFile)?.add(resolved);
      let back = importedBy.get(resolved);
      if (!back) {
        back = new Set();
        importedBy.set(resolved, back);
      }
      back.add(edge.fromFile);
    }
  }

  return { edges, importsOf, importedBy };
}

/**
 * Promote symbols to their route roles ACROSS files.
 *
 * The structure indexer can only see one file, so it promotes a handler only
 * when the registration and the definition sit in the same file. Real services
 * — and the AI-generated ones this analysis is aimed at especially — put
 * `router.get('/', listUsers)` in `routes/user-routes.ts` and `listUsers` in
 * `controllers/user-controller.ts`. Without this pass, every handler in that
 * extremely common layout is invisible to a rule that filters on handlers, and
 * VG-SMELL-010 silently finds nothing on exactly the codebases it exists for.
 *
 * That failure was caught by a sample corpus written from the specification by
 * someone who had not seen the implementation, which is the argument for writing
 * fixtures and detectors separately.
 *
 * The binding is resolved through the IMPORT GRAPH rather than by matching names
 * project-wide. `listUsers` may be defined in three files; the one that was
 * registered is the one the registering file imported. Matching on the name
 * alone would promote all three, and a symbol wrongly promoted to `route-handler`
 * puts non-handler code into the population VG-SMELL-010 counts — a false
 * positive in the direction that matters. When no import names the symbol, it is
 * taken to be local to the registering file, which is the only remaining
 * possibility.
 *
 * Middleware is applied AFTER handlers so it wins on conflict: a symbol used in
 * a pre-handler position somewhere and as a handler elsewhere is a checkpoint,
 * and treating it as a handler would let a guard's own authorization check be
 * counted as scattered.
 */
export function linkRouteHandlers(
  structures: StructureIndex[],
  _graph: DependencyGraph,
): void {
  const byPath = new Map(structures.map((s) => [s.filePath, s]));

  /** Where a name used in `from` was defined, following its import if any. */
  const definingFile = (from: StructureIndex, name: string): StructureIndex | undefined => {
    for (const edge of from.imports) {
      if (edge.resolvedFile && edge.names.includes(name)) {
        const target = byPath.get(edge.resolvedFile);
        if (target?.symbols.some((s) => s.name === name)) return target;
      }
    }
    return from.symbols.some((s) => s.name === name) ? from : undefined;
  };

  const promote = (from: StructureIndex, name: string, kind: 'route-handler' | 'middleware'): void => {
    const target = definingFile(from, name);
    if (!target) return;
    for (const symbol of target.symbols) {
      if (symbol.name !== name) continue;
      if (symbol.kind === 'class') continue;
      // `declaredKind` was set by the indexer and is the syntactic fact; only
      // the role is being changed here.
      if (kind === 'route-handler' && symbol.kind === 'middleware') continue;
      symbol.kind = kind;
    }
  };

  for (const structure of structures) {
    for (const route of structure.routes) {
      if (route.handlerName && !route.inlineHandler) {
        promote(structure, route.handlerName, 'route-handler');
      }
    }
  }
  for (const structure of structures) {
    for (const route of structure.routes) {
      for (const name of route.middlewareNames) promote(structure, name, 'middleware');
      // `app.use(x)` puts the mounted guard in the handler position because
      // there is no path argument to shift it. It is a checkpoint, not a
      // handler, and treating it as one would count its own check as scattered.
      if (route.method === 'use' && route.handlerName && !route.inlineHandler) {
        promote(structure, route.handlerName, 'middleware');
      }
    }
  }
}

/**
 * Every file reachable from `entry` by following `#include` edges, `entry`
 * included.
 *
 * The "which declarations can this translation unit see" question for #20b. It
 * is a transitive closure because C headers include other headers, and a
 * declaration two levels down is just as visible as one at the top.
 *
 * `complete` is the field that decides whether VG-AISC-002 is allowed to speak
 * at all. It is false when any include on the path failed to resolve, which is
 * the normal state for anything using system or SDK headers the scan cannot
 * see. Firing "this function is declared nowhere" while holding an admittedly
 * incomplete view of where things are declared would produce a false positive on
 * every correct program that includes a header outside the repository — that is
 * to say, on essentially all of them. The rule stays silent instead, and the
 * finding it can still make (an initializer defined and never mentioned) does
 * not depend on the closure being complete.
 */
export function includeClosure(
  entry: string,
  structures: Map<string, StructureIndex>,
): { files: string[]; complete: boolean } {
  const seen = new Set<string>([entry]);
  const queue = [entry];
  let complete = true;

  while (queue.length > 0) {
    const current = queue.shift()!;
    const structure = structures.get(current);
    if (!structure) {
      complete = false;
      continue;
    }
    for (const edge of structure.imports) {
      if (edge.syntax !== 'quoted' && edge.syntax !== 'angled') continue;
      if (edge.resolvedFile === undefined) {
        complete = false;
        continue;
      }
      if (seen.has(edge.resolvedFile)) continue;
      seen.add(edge.resolvedFile);
      queue.push(edge.resolvedFile);
    }
  }

  return { files: [...seen].sort(), complete };
}

/** Distinct files importing `filePath`. */
export function fanIn(filePath: string, graph: DependencyGraph): number {
  return graph.importedBy.get(filePath)?.size ?? 0;
}

/** Distinct project files `filePath` imports. */
export function fanOut(filePath: string, graph: DependencyGraph): number {
  return graph.importsOf.get(filePath)?.size ?? 0;
}

/**
 * Turn a list of read files into the normalised `SourceFile` shape the rest of
 * the package expects.
 *
 * Centralised here rather than done at each call site because the normalisation
 * is the thing that has to be identical everywhere — see `normalizePath`. A
 * caller that forgot it would build a graph whose keys do not match its own
 * lookups, and the symptom would be an empty result rather than an error.
 */
export function toSourceFile(filePath: string, language: string, content: string): SourceFile {
  return {
    filePath: normalizePath(filePath),
    language,
    content,
    lines: content.split('\n'),
  };
}
