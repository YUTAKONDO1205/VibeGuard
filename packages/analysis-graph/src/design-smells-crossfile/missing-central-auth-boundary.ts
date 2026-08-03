// VG-SMELL-011 — Missing Central Auth Boundary.
//
// WHAT IT CLAIMS
//
// The project HAS an authorization boundary — one guard, named at the middleware
// position of several mutating route registrations — and that boundary is not a
// chokepoint: a file that applies it to its other writes registers a write
// without it. The accusation is never "this endpoint is unprotected" (nothing
// lexical can know that); it is "this project decided how writes are guarded,
// and this registration is outside the decision".
//
// The AI failure mode it is aimed at is not exotic. Ask a model for four admin
// endpoints and it produces four correct endpoints; ask for them in four turns
// and the fourth one is written without the middleware the first three carry,
// because nothing in the file is structurally incomplete without it. The diff
// looks like the ones before it, the handler is correct, and the omission is
// visible only by comparing the registration against its neighbours.
//
// ★ THE LITERAL READING OF THE NAME IS REJECTED, AND NOT NEGOTIABLE
//
// "This project has no central authorization boundary" is unimplementable, and
// it would be the wrong rule even if it were implementable. The absent boundary
// can live OUTSIDE the source: nginx, an API gateway, a Next.js `middleware.ts`
// that the scan root does not contain, a service mesh, cloud IAM. Absence is
// therefore not refutable from source, so a rule built on it fires on every demo
// app, every deliberately public API, and every service whose front door is
// somebody else's configuration file. That is the same shape as VG-SMELL-041's
// rejected "definition 2", and it dies the same way — 040-style, on a corpus,
// after the fixtures were all green.
//
// What replaces it is DIFFERENTIAL and rests only on POSITIVE evidence: the
// convention is visible in the source, the omission is visible in the source,
// and both are in the same routing surface. Nothing has to be assumed absent.
//
// ★ THE ERROR DIRECTION, WHICH DECIDES EVERY OPEN QUESTION BELOW
//
// This rule fires on an ABSENCE (no guard in a middleware list), which is the
// weak direction — the same one VG-SMELL-052 shipped three false positives in.
// So every predicate here has a side it is allowed to be wrong on, and they are
// not all the same side:
//
//   ADMITTING a guard as the project's convention   → narrow. A wrongly admitted
//     convention produces a finding about a boundary that was never one.
//   SILENCING on a mount / a decorator / a barrel   → wide. A wrongly admitted
//     silencer costs a finding nobody sees, which is the affordable error.
//
// `narrowGuardName` and the `isMountedGuard` predicate are therefore deliberately
// DIFFERENT predicates over the same question, and merging them "for consistency"
// is the single easiest way to break this rule.

import type { CodeLocation, Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { resolveSpecifier } from '../dependency-graph/index.js';
import { fanMetrics, mergeMetrics } from '../metrics/index.js';
import { guardKey } from '../symbol-table/index.js';
import {
  ELEVATED,
  isAuthnGuardName,
  isAuthzGuardName,
  isPublicByDesignRoute,
  isTestPath,
  pathWords,
} from './authz-lexicon.js';
import type {
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  ProjectIndex,
  RouteBinding,
  StructureIndex,
} from '../types.js';

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/**
 * How many guarded mutating registrations it takes before "a convention exists".
 *
 * Three, and it is the same number and the same argument as `MIN_SITES` in
 * `scattered-authorization.ts`: two is a coincidence. A create and a delete
 * endpoint guarded the same way is two lines a single commit produced; it is not
 * yet a decision the project has made, and treating it as one would let any
 * two-line habit convict the third route in the file.
 *
 * The routes counted here are MUTATING ones only, and that restriction is doing
 * work rather than decorating the threshold — see `MUTATING_METHOD`.
 */
const MIN_CONVENTION_ROUTES = 3;

/**
 * HTTP methods whose registration is a WRITE.
 *
 * The convention and the omission are both required to be of this class, and
 * they are required to be the SAME class on purpose. Plenty of correct services
 * guard every write and leave reads open — a public catalogue with an
 * authenticated checkout is not a defect — so a convention established on
 * `get` registrations says nothing about whether an unguarded `post` is a
 * mistake. Comparing like with like is what stops the rule from reporting a
 * deliberate read/write asymmetry as an omission.
 *
 * `head`, `options` and `all` are absent. The first two are not writes; `all`
 * registers every method at once and is most often a catch-all 404 or a CORS
 * pre-flight, which is neither a guarded surface nor an endpoint anyone would
 * mount a privilege check on.
 */
const MUTATING_METHOD: ReadonlySet<string> = new Set(['post', 'put', 'patch', 'delete']);

/**
 * How many convention sites the finding enumerates.
 *
 * The accusation is about the SET — "your other writes carry this guard" — so at
 * least three have to be printed or the reader is being asked to take the set on
 * trust. Four is three plus one: enough to show the pattern, few enough that the
 * related-location list stays a piece of evidence rather than a directory
 * listing. The TOTAL is stated in the description, so nothing is hidden by the
 * cap, only un-enumerated.
 */
const MAX_CITED_CONVENTION = 4;

/** How many sibling unguarded registrations in the same file are enumerated. */
const MAX_CITED_UNGUARDED = 2;

/**
 * A route path that is actually a route path.
 *
 * ★ TAKEN, DELIBERATELY UNCHANGED, FROM `generated-boilerplate-unintegrated.ts`,
 * INCLUDING THE MEASUREMENT BEHIND IT.
 *
 * The indexer's `JS_ROUTE` is `(?<obj>[\w$]{1,40})\.(?<method>get|post|…|use)\(`,
 * which is every `.post(` and every `.delete(` in the language. Running a rule
 * over a real fixture produced a `RouteBinding` for `req.get('authorization')`;
 * the mutating half of that same problem is worse, because the shapes are
 * commoner and they land on the PERMISSIVE side of this rule:
 *
 *   axios.post('/api/users', payload)      method `post`, path `/api/users`,
 *                                          middleware list EMPTY — byte-for-byte
 *                                          the shape of an unguarded endpoint,
 *                                          in a front end that registers nothing
 *   responseCache.delete(req.originalUrl)  method `delete`, no path literal
 *   map.delete(key)                        method `delete`, no path literal
 *
 * An Express path literal begins with `/`, or is the catch-all `*`. That kills
 * the last two outright. The first is killed by `resolvesToFunction` below, which
 * is why both tests exist rather than one: `axios.post('/api/users', payload)`
 * passes THIS test and fails that one.
 *
 * The cost is recall on `router.route('/x').post(handler)`, whose `.post(` has no
 * path argument of its own. Accepted: the failure is a missing finding.
 */
const ROUTE_PATH = /^(?:\/|\*$)/;

/**
 * Decorators that mean "this handler is behind a guard".
 *
 * FRAMEWORK KNOWLEDGE, stated as framework knowledge, in the same spirit as
 * `COMPACT_GUARD_NAMES` in the symbol table: none of these words is
 * authorization vocabulary in English, and no general rule over the shared
 * lexicon would ever admit `UseGuards`. Nest, Spring Security and the
 * `@casl`/`nest-access-control` family are where they come from.
 *
 * Matched against the lowercased, separator-free LAST dotted segment, so
 * `@Common.UseGuards`, `@UseGuards`, and `@use_guards` are one entry. The
 * lexicon is consulted as well (see `isDecoratorGuarded`), so `@RequireRole` and
 * `@AdminOnly` are covered without being listed.
 *
 * ★ WHAT IS NOT HERE: `AllowAnonymous`, `Public`, `SkipAuth`. They are the exact
 * opposite claim — a marker that the handler is deliberately outside the
 * boundary — and admitting them would silence the rule on the one annotation
 * that says a human made the decision on purpose. They are not needed for
 * silence either: a handler carrying them is one whose route is usually
 * public-by-design and exempt for that reason.
 */
const GUARD_DECORATOR: ReadonlySet<string> = new Set([
  'useguards',
  'guard',
  'guards',
  'roles',
  'role',
  'authorize',
  'authorized',
  'authorise',
  'preauthorize',
  'postauthorize',
  'secured',
  'rolesallowed',
  'requirepermissions',
  'requirespermissions',
  'permissions',
  'permission',
  'auth',
  'authenticated',
  'requireauth',
  'requireauthentication',
  'checkpolicies',
  'usepolicy',
  'acl',
]);

/**
 * `export * from './x'`, `export * as ns from './x'`, `export { a } from './x'`.
 *
 * ★ THIS PATTERN EXISTS BECAUSE THE IMPORT GRAPH DOES NOT CONTAIN THESE EDGES,
 *   AND VG-SMELL-052 SHIPPED A FALSE POSITIVE PROVING IT.
 *
 * The indexer's `JS_IMPORT` requires the statement to begin with `import`, so a
 * re-export produces no `ImportEdge` at all — `graph.importsOf` for a barrel
 * file is empty even though every symbol of the re-exported module passes
 * through it. 052's rework records the consequence: a correctly-mounted guard,
 * reached through an `export *` barrel, reported as unmounted. This rule follows
 * MOUNTS rather than symbols, so the same hole appears one level up: routes
 * registered in `routes/admin/billing.ts` and reached through
 * `routes/admin/index.ts` would look unmounted while sitting behind a parent
 * guard. `smell-011-neg-barrel-mount/` is the fixture that pins it.
 *
 * Run over the BLANKED copy so a commented-out re-export is not one; the
 * specifier is then read back from the ORIGINAL content at the same offsets,
 * because a specifier IS a string literal and blanking leaves spaces where its
 * characters were. Blanking is length-preserving, which is what makes that
 * transfer legal.
 *
 * Every quantifier is bounded and horizontal whitespace is `[^\S\r\n]{0,4}`
 * throughout — cross-file rule regexes sit outside the `sec-a1-catalog.mjs`
 * census (it reads `packages/rules` only), so the bound is the only thing
 * protecting the three-second contract here.
 */
const RE_EXPORT =
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{0,4}(?:\*(?:[^\S\r\n]{1,4}as[^\S\r\n]{1,4}[\w$]{1,60})?|\{[^}\r\n]{0,400}\})[^\S\r\n]{0,4}from[^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g;

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

/**
 * Whether a piece of text names an ELEVATED privilege, by WORD.
 *
 * `ELEVATED` from the lexicon is a word-bounded regex meant for the source text
 * of a check. Applying it to a whole path with `.test()` would silently become a
 * substring test over segments a reader never intended as words: `routes/roots/`
 * and `src/rootstock/` both carry `root` at a `\b` boundary that the path's own
 * punctuation created. Segmenting first with `pathWords` and testing each WORD is
 * the same discipline `pathWords` exists to enforce — see its doc comment and the
 * `src/authors/` counterexample there.
 */
function namesElevatedPrivilege(text: string): boolean {
  for (const word of pathWords(text)) {
    if (ELEVATED.test(word)) return true;
  }
  return false;
}

/**
 * Where a name used in `from` is defined, following the import that bound it.
 *
 * ★ A DELIBERATE RE-IMPLEMENTATION OF `definingFile` IN
 *   `dependency-graph/index.ts`, WHICH IS A CLOSURE AND NOT EXPORTED.
 *
 * Agreeing with it is the point rather than an accident: that function is how
 * `linkRouteHandlers` decides which symbol becomes `kind: 'route-handler'`, so a
 * rule that resolved names differently would reason about handlers the rest of
 * the package does not believe in. The resolution is through the IMPORT GRAPH
 * rather than by matching names project-wide, for the reason stated there —
 * `createUser` may be defined in three files, and the one that was registered is
 * the one the registering file imported.
 *
 * Returning `undefined` is a meaningful answer and is used as such twice below:
 * a guard with no definition in the project cannot satisfy condition (c), and a
 * "handler" with no definition in the project is usually not a handler at all.
 *
 * ★ MEASURED LIMIT — A WRAPPED IMPORT LIST RESOLVES TO NOTHING.
 *
 * The indexer's `JS_IMPORT` matches the binding clause with `[^;'"\n]{0,200}`,
 * and the excluded `\n` is not an oversight — the Python arm of the same file
 * once swallowed every following import into one match by allowing it. The
 * consequence is that a PRETTIER-WRAPPED import produces no `ImportEdge` at all.
 * Measured directly against `indexFile`, 2026-08-03:
 *
 *   import { createAccount, removeAccount } from './x';   → 1 edge, 2 names
 *   import {\n  createAccount,\n  removeAccount,\n} from './x';   → []
 *
 * Everything downstream inherits it: this function, `resolveMountTarget`, and
 * `graph.importsOf`. For this rule every one of those inheritances fails QUIET —
 * an unresolvable handler drops the unguarded registration, an unresolvable
 * guard fails condition (c), and an unresolvable mount target silences the whole
 * rule — so the limit costs recall on wrapped code and cannot manufacture a
 * finding. It is recorded because "the rule fired on the fixtures and not on the
 * corpus" is otherwise a mystery, and because the repair is one character in
 * `structure-indexer/index.ts`, which this rule does not own.
 */
function definingFile(
  from: StructureIndex,
  name: string,
  structures: ReadonlyMap<string, StructureIndex>,
): StructureIndex | undefined {
  for (const edge of from.imports) {
    if (edge.resolvedFile === undefined || !edge.names.includes(name)) continue;
    const target = structures.get(edge.resolvedFile);
    if (target?.symbols.some((s) => s.name === name)) return target;
  }
  return from.symbols.some((s) => s.name === name) ? from : undefined;
}

/**
 * The line a registration is actually written on.
 *
 * ★ COMPENSATES FOR AN OFF-BY-ONE IN `structure-indexer`, AND SHOULD NOT HAVE TO
 *   EXIST. The analysis and the two tests are VG-SMELL-052's; they are repeated
 *   here rather than shared because 052 keeps them private and this rule does not
 *   own `structure-indexer/index.ts`, where the one-line repair belongs.
 *
 * `JS_ROUTE` opens with `(?:^|[^\w$.])`, so it consumes the character BEFORE the
 * object identifier and `RouteBinding.line` is computed from that character's
 * offset. When the registration starts at column 1, the consumed character is the
 * newline ENDING THE PREVIOUS LINE and the recorded line is one too low. Every
 * location this rule emits is a route registration, so shipping the raw value
 * would mean every location it emits points at the wrong line — "the single most
 * embarrassing kind of wrong a report that asks the reader to check a line number
 * can be", as `../taint/` puts it about the same class of bug.
 *
 * The correction is exact rather than a guess, because the error has exactly one
 * shape: the recorded line is either right, or one less than right, and the
 * second case requires the identifier to begin at column 1 of the following line.
 * Anything that satisfies neither test is left alone — a wrong line is bad and a
 * confidently invented one is worse.
 */
function registrationLine(route: RouteBinding, lines: readonly string[]): number {
  const recorded = route.line;
  const here = lines[recorded - 1] ?? '';
  const next = lines[recorded] ?? '';
  // `method` comes from the indexer's closed alternation, so it carries no regex
  // metacharacter; `path` is only ever compared with `includes`.
  const head = new RegExp(String.raw`\.${route.method}[^\S\r\n]{0,4}\(`);
  const carriesPath = (text: string): boolean =>
    route.path === undefined || text.includes(route.path);

  if (head.test(here) && carriesPath(here)) return recorded;
  if (/^[\w$]{1,40}\./.test(next) && head.test(next) && carriesPath(next)) return recorded + 1;
  return recorded;
}

// ---------------------------------------------------------------------------
// ★ TWO PREDICATES OVER "IS THIS NAME A GUARD", POINTING OPPOSITE WAYS
// ---------------------------------------------------------------------------

/**
 * The NARROW one: may this name be the project's authorization convention?
 *
 * `isAuthzGuardName || isAuthnGuardName`, straight from the shared lexicon, and
 * nothing else. In particular NOT `project.symbols.guards`, which cannot
 * discriminate here at all: `buildSymbolTable` adds a key for every name ever
 * observed in a pre-handler argument position (`usedAsMiddleware`), so EVERY
 * middleware name in the project is a member. Condition (a) still asks for that
 * membership — it is the structural half of the definition and it is checked
 * where the route is read — but it is not what separates a boundary from a
 * pipeline stage, and pretending otherwise would hide that this predicate is the
 * only thing doing so.
 *
 * What it excludes is the whole point. A file whose three writes carry
 * `validateOrderBody`, `upload`, `asyncHandler` or `rateLimit` has a convention,
 * and it is not an AUTHORIZATION convention; accusing the fourth write of missing
 * an auth boundary on that evidence is a finding about a boundary that never
 * existed. `smell-011-neg-input-validator/` is the fixture.
 *
 * ★ MEASURED LIMIT — THE NAMES THIS DECLINES THAT A READER WILL EXPECT IT TO
 *   ADMIT, AND WHY THEY ARE NOT FIXED HERE.
 *
 * `requireAuth`, `authGuard`, `checkAuth`, `ensureAuth`, `verifyToken` and
 * `protect` all fall through: the lexicon holds `auth` in NEITHER set on purpose
 * (`authMiddleware` is authentication in most codebases and authorization in
 * some, so the word is evidence for neither), `guard` is in neither, and
 * `verifytoken` is listed as one word so the camelCase spelling misses it. That
 * is real recall lost on the single commonest guard name in Express code, and it
 * is left lost DELIBERATELY: widening belongs in `authz-lexicon.ts`, where
 * VG-SMELL-010's and VG-SMELL-013's fixtures move at the same time and the
 * corpus sweep that gates admission runs against all three. Widening it privately
 * here would recreate exactly the divergence that made VG-SMELL-041 ship with 0%
 * precision — two guard vocabularies in two files, neither mentioning the other.
 *
 * ★ EXPORTED so the negative fixtures can be pinned as REAL negatives.
 *
 * A directory asserting "this produces no finding" is worth nothing on its own:
 * it also passes when the rule declined the input for a reason the directory was
 * never built to test, and the easiest such reason is that the name never
 * qualified. `smell-011-neg-external-guard/` is silent because the guard has no
 * definition in the project, and its test says so by asserting that
 * `authenticate` IS in this vocabulary. Without that assertion the whole negative
 * corpus could be vacuous and every test in it would still be green — the failure
 * mode VG-SMELL-052 exports `classifyBoilerplateName` to prevent.
 */
export function narrowGuardName(name: string): boolean {
  return isAuthzGuardName(name) || isAuthnGuardName(name);
}

/**
 * The WIDE one: could this name be a guard SOMEBODY MOUNTED?
 *
 * Used only to silence, so it takes the union of every judgement available: the
 * lexicon's two, plus `SymbolTable.guards` asked at EVERY file rather than at the
 * one doing the mounting.
 *
 * ★ THE PROJECT-WIDE LOOKUP IS NOT PARANOIA, IT IS THE ONLY CORRECT LOOKUP.
 *
 * `guards` is keyed by (file, name) and a name is registered at every file where
 * it is KNOWN, with a different justification at each. `protect`, defined and
 * exported in `middleware/protect.ts`, is a guard THERE — by placement, since
 * `middleware` is in the symbol table's `SECURITY_PATH_WORDS` — and is nothing at
 * all in `app.ts`, where it arrives as an unremarkable import binding and matches
 * no name shape. Asking `guardKey(app.ts, 'protect')` therefore answers "no" for
 * the single most important mount in the application. Asking every file answers
 * "yes", which is the direction a silencer must fail in.
 *
 * Cached per name because the scan is O(files) and the number of distinct mounted
 * names is small.
 */
function mountedGuardPredicate(project: ProjectIndex): (name: string) => boolean {
  const files = [...project.structures.keys()];
  const cache = new Map<string, boolean>();
  return (name: string): boolean => {
    const cached = cache.get(name);
    if (cached !== undefined) return cached;
    let verdict = isAuthzGuardName(name) || isAuthnGuardName(name);
    if (!verdict) {
      for (const filePath of files) {
        if (project.symbols.guards.has(guardKey(filePath, name))) {
          verdict = true;
          break;
        }
      }
    }
    cache.set(name, verdict);
    return verdict;
  };
}

// ---------------------------------------------------------------------------
// ★ THE MOUNT SCAN — negative conditions 2 and 3, which share one traversal
// ---------------------------------------------------------------------------
//
// The two conditions read like a contradiction ("a mounted guard silences the
// rule" versus "a mounted guard protects a subtree"), and they are not: they are
// the same syntax with the guard in two different ARGUMENT POSITIONS, and the
// position is exactly what says whether the mount has a knowable target.
//
//   app.use(requireAuth)                  the guard is the last argument. It
//   app.use('/admin', requireAdmin)       applies to everything registered on
//                                         this router AFTER this line — and
//                                         "after" is source order, which is not
//                                         execution order for a router assembled
//                                         across files. Nothing lexical can know
//                                         what it covers. → SILENCE, whole rule.
//
//   app.use('/api', requireAuth, apiRouter)   the guard has a target: the trailing
//                                         argument. Everything that router can
//                                         reach is behind the guard, and the
//                                         import graph can say what that is.
//                                         → PROTECT that subtree, keep going.
//
// The remaining ambiguity is that `app.use('/admin', X)` puts X in the trailing
// position whether X is a guard or a router, and both are common. It is resolved
// STRUCTURALLY rather than by name: a guard is a function and the indexer records
// a symbol for it; `export const adminRouter = Router()` produces no symbol
// (`JS_HEAD` only takes a `const` whose initialiser is a function or an arrow).
// So "the trailing name resolves to a symbol" means guard, and "it resolves to a
// file with no such symbol" means router. `resolveMountTarget` is that question.
//
// Without that distinction the rule would silence on `app.use('/api/admin',
// adminRouter)` — because `adminRouter` carries the word `admin`, which IS in the
// lexicon's authorization vocabulary — and a plain router mount is present in
// essentially every Express application. That is not a hypothetical: it is what
// the first draft of this file did, and it made the rule unable to fire on its
// own positive fixture.

type MountTarget =
  /** A symbol with this name exists: a function, therefore a guard, not a router. */
  | { readonly kind: 'function' }
  /** An import edge names it and the target file has no such symbol: a router object. */
  | { readonly kind: 'module'; readonly filePath: string }
  /** Nothing in the project accounts for the name. */
  | { readonly kind: 'unknown' };

function resolveMountTarget(
  from: StructureIndex,
  name: string,
  structures: ReadonlyMap<string, StructureIndex>,
): MountTarget {
  if (definingFile(from, name, structures) !== undefined) return { kind: 'function' };
  for (const edge of from.imports) {
    if (edge.resolvedFile !== undefined && edge.names.includes(name)) {
      return { kind: 'module', filePath: edge.resolvedFile };
    }
  }
  return { kind: 'unknown' };
}

/** Every specifier this file RE-EXPORTS from, read back out of the original text. */
function reExportSpecifiers(structure: StructureIndex, content: string): string[] {
  const out: string[] = [];
  RE_EXPORT.lastIndex = 0;
  for (let m = RE_EXPORT.exec(structure.blanked); m; m = RE_EXPORT.exec(structure.blanked)) {
    const spec = m.groups?.spec;
    if (spec !== undefined) {
      // The specifier is immediately followed by the closing quote, so its offset
      // is fixed by the match end. Arithmetic rather than `lastIndexOf`, which
      // would search the blanked text for a run of spaces and could find an
      // indentation run instead.
      const at = m.index + m[0].length - 1 - spec.length;
      out.push(content.slice(at, at + spec.length));
    }
    if (RE_EXPORT.lastIndex === m.index) RE_EXPORT.lastIndex += 1;
  }
  return out;
}

/**
 * Every file a mounted router can reach, the router's own file included.
 *
 * Two edge kinds, because one of them does not exist in the graph:
 *  - `graph.importsOf`, the resolved import edges. A router barrel that writes
 *    `import { billingRouter } from './billing'` is covered here.
 *  - re-export specifiers, which produce NO import edge (see `RE_EXPORT`).
 *
 * Transitive, and deliberately over-approximating: a mounted router's `db.ts` is
 * marked protected too. Nothing is lost by that — `db.ts` registers no routes —
 * and the direction of the error is the one this rule is required to fail in.
 * Under-approximating would mean accusing a route that sits behind a parent
 * guard, which is a false positive on correct code.
 */
function mountedSubtree(
  root: string,
  project: ProjectIndex,
  contentOf: ReadonlyMap<string, string>,
  known: Set<string>,
): Set<string> {
  const reached = new Set<string>([root]);
  const queue: string[] = [root];
  while (queue.length > 0) {
    const current = queue.shift()!;
    const next: string[] = [...(project.graph.importsOf.get(current) ?? [])];
    const structure = project.structures.get(current);
    if (structure !== undefined) {
      // Falling back to `blanked` keeps this total when a structure has no
      // matching `SourceFile`: the specifier read out of it would be spaces,
      // which resolves to nothing, which is silence — the safe direction.
      const content = contentOf.get(current) ?? structure.blanked;
      for (const specifier of reExportSpecifiers(structure, content)) {
        const resolved = resolveSpecifier(
          { fromFile: current, specifier, names: [], line: 0, syntax: 'esm' },
          known,
        );
        if (resolved !== undefined) next.push(resolved);
      }
    }
    for (const file of next) {
      if (reached.has(file)) continue;
      reached.add(file);
      queue.push(file);
    }
  }
  return reached;
}

/** Silence for the whole rule, or the set of files a parent mount protects. */
type MountVerdict =
  | { readonly silent: true; readonly reason: string }
  | { readonly silent: false; readonly protectedFiles: ReadonlySet<string> };

/**
 * Read every `use` registration in the project and decide what it means.
 *
 * ★ SCANS EVERY FILE, INCLUDING THE TEST TREE AND FILES IN OTHER LANGUAGES.
 *
 * The opposite of what the route collection below does, and for the reason
 * VG-SMELL-052 gives for reading the test tree in its reference scan: a file this
 * scan is not allowed to look at is a file that could hold the mount which makes
 * the finding wrong. Every outcome of this function is either silence or more
 * protection, so widening its input can only quieten the rule.
 */
function scanMounts(project: ProjectIndex, contentOf: ReadonlyMap<string, string>): MountVerdict {
  const isMountedGuard = mountedGuardPredicate(project);
  const known = new Set(project.structures.keys());
  const protectedFiles = new Set<string>();

  for (const filePath of [...project.structures.keys()].sort()) {
    const structure = project.structures.get(filePath)!;
    for (const route of structure.routes) {
      if (route.method !== 'use') continue;
      // An inline `app.use((req, res, next) => …)` has no name to judge and no
      // module to follow. It is left alone: an anonymous mount is as likely to be
      // a logger as a guard, and silencing the whole rule on one would mean
      // almost never speaking.
      const trailing = route.inlineHandler ? undefined : route.handlerName;
      const leading = route.middlewareNames.filter((name) => isMountedGuard(name));

      if (leading.length > 0) {
        // A TARGETED mount: `app.use('/api', requireAuth, apiRouter)`.
        if (trailing === undefined) {
          return {
            silent: true,
            reason: `${filePath}:${route.line} mounts ${leading[0]} with a target this analysis cannot name`,
          };
        }
        const target = resolveMountTarget(structure, trailing, project.structures);
        if (target.kind !== 'module') {
          // Either a chain of two middlewares (`app.use('/x', requireAuth, audit)`),
          // which covers everything registered afterwards, or a target that
          // resolves to nothing. Both are mounts whose reach is unknown.
          return {
            silent: true,
            reason: `${filePath}:${route.line} mounts ${leading[0]} ahead of ${trailing}, which is not a router this analysis can follow`,
          };
        }
        for (const reached of mountedSubtree(target.filePath, project, contentOf, known)) {
          protectedFiles.add(reached);
        }
        continue;
      }

      if (trailing === undefined || !isMountedGuard(trailing)) continue;
      const target = resolveMountTarget(structure, trailing, project.structures);
      // `kind: 'module'` is a plain router mount (`app.use('/api/admin',
      // adminRouter)`) that happens to carry a privilege word in its name. It
      // attaches no guard, so it neither silences nor protects.
      if (target.kind === 'module') continue;
      return {
        silent: true,
        reason: `${filePath}:${route.line} mounts ${trailing}, whose reach this analysis cannot see`,
      };
    }
  }

  return { silent: false, protectedFiles };
}

// ---------------------------------------------------------------------------
// The route population
// ---------------------------------------------------------------------------

/** One mutating route registration, with its line corrected. */
interface Registration {
  filePath: string;
  line: number;
  method: string;
  path: string;
  middlewareNames: readonly string[];
  handlerName: string | undefined;
  inline: boolean;
}

/**
 * Whether the route's handler is something this project actually defines.
 *
 * The second half of the "is this a route registration at all" test — see
 * `ROUTE_PATH` for the first half and for why one test is not enough.
 * `axios.post('/api/users', payload)` has a path literal that begins with `/`
 * and an empty middleware list; what it does not have is a FUNCTION in the
 * handler slot. Requiring one turns "a call shaped like a registration" back into
 * "a registration".
 *
 * Applied to the UNGUARDED side only, and the asymmetry is deliberate: that side
 * is the accusation, and it is the side a spurious registration would be cited
 * on. The convention side is corroboration and has already had to carry a guard
 * name that resolves to a definition in the project, which no HTTP client call
 * ever does. Requiring a resolvable handler there as well would cost real
 * convention sites — `router.post('/x', requireAdmin, controller.create)` binds
 * the handler through a namespace object the lexical resolver cannot follow — in
 * exchange for nothing.
 */
function resolvesToFunction(
  registration: Registration,
  structure: StructureIndex,
  structures: ReadonlyMap<string, StructureIndex>,
): boolean {
  if (registration.inline) return true;
  if (registration.handlerName === undefined) return false;
  return definingFile(structure, registration.handlerName, structures) !== undefined;
}

function collectMutatingRoutes(
  structures: readonly StructureIndex[],
  linesOf: ReadonlyMap<string, readonly string[]>,
): Registration[] {
  const out: Registration[] = [];
  for (const structure of structures) {
    // Negative condition 5, applied to BOTH sides at once by excluding the file
    // from the population entirely. A test harness that mounts three guarded
    // routes and one unguarded one is describing a test, not an application, and
    // a fixture written to contain the smell is not a finding about the project.
    // Same `TEST_PATH` every rule in this directory uses, from the lexicon.
    if (isTestPath(structure.filePath)) continue;
    const lines = linesOf.get(structure.filePath) ?? [];
    for (const route of structure.routes) {
      if (!MUTATING_METHOD.has(route.method)) continue;
      if (route.path === undefined) continue;
      if (!ROUTE_PATH.test(route.path)) continue;
      out.push({
        filePath: structure.filePath,
        line: registrationLine(route, lines),
        method: route.method,
        path: route.path,
        middlewareNames: route.middlewareNames,
        handlerName: route.inlineHandler ? undefined : route.handlerName,
        inline: route.inlineHandler !== undefined,
      });
    }
  }
  out.sort((a, b) => (a.filePath === b.filePath ? a.line - b.line : a.filePath < b.filePath ? -1 : 1));
  return out;
}

/**
 * Negative condition 4 — the handler is behind a framework guard annotation.
 *
 * Both the method's own decorators and its CLASS's are consulted. Nest's
 * `@UseGuards(AdminGuard)` on a controller class covers every route in it, and a
 * rule that only read the method would report every correctly guarded Nest
 * controller whose handlers are also reachable through an Express adapter.
 *
 * The class is looked up by `enclosingClass` in the SAME structure, which is the
 * only place it can be: a method's class is written above it in the same file.
 */
function isDecoratorGuarded(symbol: IndexedSymbol, structure: StructureIndex): boolean {
  const own = symbol.decorators ?? [];
  const enclosing =
    symbol.enclosingClass === undefined
      ? []
      : (structure.symbols.find(
          (s) => s.kind === 'class' && s.name === symbol.enclosingClass,
        )?.decorators ?? []);

  for (const decorator of [...own, ...enclosing]) {
    const last = decorator.split('.').pop() ?? '';
    const compact = last.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (GUARD_DECORATOR.has(compact)) return true;
    // The lexicon covers the project-specific annotations no framework list can
    // enumerate — `@RequireRole`, `@AdminOnly`, `@Permission('orders:write')`.
    if (narrowGuardName(last)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/** One accused file, after every negative condition has been applied. */
interface Accusation {
  filePath: string;
  guard: string;
  guardDefinedIn: string;
  guardDefinitionLine: number;
  /** Every convention site of this guard, project-wide, in citation order. */
  convention: readonly Registration[];
  /** Convention sites that sit in the accused file itself. */
  conventionHere: readonly Registration[];
  /** Files the convention spans. Drives confidence. */
  conventionFiles: number;
  unguarded: readonly Registration[];
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;

  // Deterministic file order everywhere, for the reason
  // `collectScatteredAuthSites` states: an unsorted walk makes a finding's
  // primary location depend on filesystem enumeration order, and a finding that
  // appears to move on its own is one no baseline can track.
  const structures = [...project.structures.keys()]
    .sort()
    .map((key) => project.structures.get(key)!)
    // PER-FILE language enforcement, on top of the project-level gate
    // `runCrossFileRules` applies. A polyglot repository passes that gate and
    // would otherwise hand this rule Python and C files, whose routing and guard
    // conventions none of the vocabulary here understands — the exact defect that
    // made VG-SMELL-010 emit a finding citing only Python sites.
    .filter((structure) => missingCentralAuthBoundary.languages.includes(structure.language));
  if (structures.length === 0) return [];

  const contentOf = new Map(project.files.map((f) => [f.filePath, f.content]));
  const linesOf = new Map<string, readonly string[]>(project.files.map((f) => [f.filePath, f.lines]));

  // Negative conditions 2 and 3, first, because condition 2 can end the analysis.
  const mounts = scanMounts(project, contentOf);
  if (mounts.silent) return [];

  const byPath = new Map(structures.map((s) => [s.filePath, s]));
  const routes = collectMutatingRoutes(structures, linesOf);
  if (routes.length === 0) return [];

  // ── (a) the convention: one guard on >= 3 mutating registrations ───────────
  const conventionByGuard = new Map<string, Registration[]>();
  for (const registration of routes) {
    for (const name of registration.middlewareNames) {
      // The narrow predicate. See `narrowGuardName` for what it refuses and why
      // widening it belongs in the lexicon rather than here.
      if (!narrowGuardName(name)) continue;
      // Condition (a)'s literal requirement: the symbol table judges this a
      // guard. It is satisfied by construction for anything observed in a
      // pre-handler position — `usedAsMiddleware` — so it discriminates nothing
      // on its own. It is asked anyway, at the file where the route is written,
      // because it is the structural half of the definition and because a future
      // symbol table that stops admitting middleware names by observation would
      // silently change this rule's population without this line to notice it.
      if (!project.symbols.guards.has(guardKey(registration.filePath, name))) continue;
      const sites = conventionByGuard.get(name) ?? [];
      sites.push(registration);
      conventionByGuard.set(name, sites);
    }
  }

  const accusations: Accusation[] = [];

  for (const guard of [...conventionByGuard.keys()].sort()) {
    const convention = conventionByGuard.get(guard)!;
    if (convention.length < MIN_CONVENTION_ROUTES) continue;

    const conventionFiles = new Set(convention.map((c) => c.filePath));

    for (const filePath of [...conventionFiles].sort()) {
      const structure = byPath.get(filePath);
      if (structure === undefined) continue;

      // Negative condition 3, applied: a file behind a parent mount has no
      // unguarded routes, whatever its registrations look like.
      if (mounts.protectedFiles.has(filePath)) continue;

      // ── (c) the guard is DEFINED somewhere else ────────────────────────────
      //
      // Two refusals in one lookup, and they are different refusals:
      //
      //  - `undefined` means the project does not define this guard at all. The
      //    commonest shape by far is `router.post('/x', passport.authenticate('jwt'),
      //    h)`, whose middleware name is `authenticate` and whose implementation
      //    is in `node_modules`. Nothing here can say what that guard covers, so
      //    the convention is not this project's to have broken.
      //  - the accused file itself means this is a SINGLE-FILE observation. The
      //    whole justification for this package is the sentence single-file
      //    analysis cannot form (see `MIN_FILES` in `scattered-authorization.ts`),
      //    and a finding a single-file rule could have produced does not get to
      //    borrow it.
      const definition = definingFile(structure, guard, project.structures);
      if (definition === undefined) continue;
      if (definition.filePath === filePath) continue;

      // ── (b) a further mutating registration with NO guard at all ───────────
      const unguarded = routes.filter((registration) => {
        if (registration.filePath !== filePath) return false;
        // "No guard AT ALL" is read as an EMPTY middleware list, not as "no
        // middleware this rule recognises as a guard". `router.post('/items',
        // validateBody, create)` has a middleware the author put there on
        // purpose; something this analysis does not understand may well be the
        // check, and the empty-slot reading is the one VG-SMELL-052 arrived at
        // for its `OpenRegistration` after the same argument.
        if (registration.middlewareNames.length > 0) return false;
        // Negative condition 1. Without it the rule fires on every correct
        // application ever written: the login endpoint is unguarded in all of
        // them, and so is registration, the health probe, and the payment
        // provider's webhook (which authenticates by signature). See the
        // lexicon's `PUBLIC_BY_DESIGN_ROUTE_WORD`, which names this rule as its
        // reason for existing.
        if (isPublicByDesignRoute(registration.path)) return false;
        if (!resolvesToFunction(registration, structure, project.structures)) return false;
        // Negative condition 4.
        if (registration.handlerName !== undefined) {
          const handlerFile = definingFile(structure, registration.handlerName, project.structures);
          const handler = handlerFile?.symbols.find((s) => s.name === registration.handlerName);
          if (handler !== undefined && handlerFile !== undefined && isDecoratorGuarded(handler, handlerFile)) {
            return false;
          }
        }
        return true;
      });
      if (unguarded.length === 0) continue;

      /**
       * ★ THE CONDITION THAT IS NOT IN THE SPECIFICATION, AND WITHOUT WHICH THIS
       *   RULE FIRES ON A LARGE FRACTION OF CORRECT APPLICATIONS.
       *
       * The accused file must itself apply the guard to at least one of its own
       * mutating registrations. It is guaranteed here by construction — the loop
       * only visits files that hold a convention site — and it is stated as a
       * condition because deleting the surrounding loop structure would delete it
       * silently.
       *
       * The counterexample it exists for is not exotic, it is the DEFAULT layout
       * of an Express service:
       *
       *   routes/admin.ts    adminRouter.post('/users', requireAdmin, createUser)
       *                      adminRouter.put('/users/:id', requireAdmin, updateUser)
       *                      adminRouter.delete('/users/:id', requireAdmin, dropUser)
       *   routes/public.ts   publicRouter.post('/feedback', submitFeedback)
       *
       * Every condition (a), (b) and (c) holds, and there is nothing wrong with
       * this code: `/feedback` is a public endpoint in a public router that has
       * never heard of `requireAdmin`. A rule that reports it is reporting "not
       * every route in your project is an admin route", which is true of every
       * project and is not a defect. `smell-011-neg-separate-router/` is the
       * fixture.
       *
       * What survives the condition is the shape the rule is actually about: one
       * file, one router, three writes carrying the guard and a fourth that does
       * not. There the omission is legible as an omission, because the file's own
       * other lines are the standard it fails.
       *
       * The recall cost is real and is accepted: a whole router file that forgot
       * the guard everywhere is invisible to this rule. That failure is a missed
       * finding, and this repository's stated contract makes the other error —
       * a design smell firing on well-factored code — the one that is a bug.
       */
      const conventionHere = convention.filter((c) => c.filePath === filePath);
      if (conventionHere.length === 0) continue;

      accusations.push({
        filePath,
        guard,
        guardDefinedIn: definition.filePath,
        guardDefinitionLine:
          definition.symbols.find((s) => s.name === guard)?.startLine ?? 1,
        // In-file sites first, then the rest: the claim being made is about this
        // file's own standard, so the citations a reader checks first should be
        // the ones they can see from the accused line. Both halves stay in
        // (file, line) order, so the list is fully determined.
        convention: [
          ...conventionHere,
          ...convention.filter((c) => c.filePath !== filePath),
        ],
        conventionHere,
        conventionFiles: conventionFiles.size,
        unguarded,
      });
    }
  }

  if (accusations.length === 0) return [];

  /**
   * One finding per accused FILE, not per guard and not per unguarded route.
   *
   * Per route would turn a file that forgot the guard on three registrations
   * into three findings that a reviewer fixes with one edit each and triages
   * three times. Per (guard, file) is worse in a different way: a project with
   * both `requireAdmin` and `requireOwner` conventions in one file would report
   * the same unguarded registration twice with two different sets of evidence,
   * and a reader comparing them would reasonably conclude the tool had found two
   * problems. The strongest convention wins — most sites, ties broken by name so
   * the choice is stable across runs.
   */
  const byFile = new Map<string, Accusation>();
  for (const accusation of accusations) {
    const held = byFile.get(accusation.filePath);
    if (
      held === undefined ||
      accusation.convention.length > held.convention.length ||
      (accusation.convention.length === held.convention.length && accusation.guard < held.guard)
    ) {
      byFile.set(accusation.filePath, accusation);
    }
  }

  const findings: CrossFileFinding[] = [];

  for (const filePath of [...byFile.keys()].sort()) {
    const accusation = byFile.get(filePath)!;
    const primary = accusation.unguarded[0]!;

    /**
     * Severity, ∃ over the unguarded registrations in the file.
     *
     * The same aggregation `scattered-authorization.ts` uses for its boost
     * conditions and for the same reason: a finding is one statement about one
     * routing surface, and the dangerous property of that surface is the worst
     * thing any one of its open registrations does. Requiring unanimity would let
     * a single unremarkable endpoint cancel the observation.
     *
     * The FILE counts as well as the path, because `routes/admin-routes.ts`
     * registering `POST /users/:id/promote` names the privilege in the only place
     * it appears — this is the layout where the router's mount prefix carries the
     * word and the route literal does not. Both are read as WORDS; see
     * `namesElevatedPrivilege` for why a bare `ELEVATED.test(path)` is not the
     * same test.
     */
    const elevated =
      namesElevatedPrivilege(filePath) ||
      accusation.unguarded.some((registration) => namesElevatedPrivilege(registration.path));
    const severity: Severity = elevated ? 'high' : 'medium';

    /**
     * Confidence, and the one thing that moves it.
     *
     * `high` is not reachable and must not become reachable. The evidence is
     * structural — a lexical index decided that these were route registrations
     * and that this name was a guard — and the design addendum §10.2's "cross-file
     * confirmation earns high" would, read literally, make every finding this rule
     * emits `high`, since cross-file confirmation is its firing condition. A field
     * that is constant carries no information.
     *
     * What separates the two remaining bands is whether the convention is a
     * PROJECT decision or a FILE habit. Three guarded writes spread over two or
     * more files is a standard the project applies; three in the single file being
     * accused may be one router's local style, and "you did it three times here
     * and not a fourth" is a weaker sentence than "your project does this and this
     * file skipped it". The second case is reported at `low`, which the default
     * `--fail-on high` gate does not fail on — the same band, for the same kind of
     * reason, that VG-SMELL-052 reserves for a symbol whose module something else
     * imports.
     */
    const confidence: Confidence = accusation.conventionFiles >= 2 ? 'medium' : 'low';

    const citedConvention = accusation.convention.slice(0, MAX_CITED_CONVENTION);
    const citedUnguarded = accusation.unguarded.slice(1, 1 + MAX_CITED_UNGUARDED);

    const describe = (registration: Registration): string =>
      `${registration.method.toUpperCase()} ${registration.path}`;

    const conventionLocation = (registration: Registration): CodeLocation => ({
      filePath: registration.filePath,
      startLine: registration.line,
      evidence: `${describe(registration)} carries \`${accusation.guard}\``,
    });

    /**
     * `securityContext`, and why only one flag is set.
     *
     * The lexicon separates the two questions a guard name can answer — WHO YOU
     * ARE and WHAT YOU MAY DO — and this rule knows which one it found, because
     * that distinction is what `narrowGuardName` is built out of. A name that
     * carries both (`requireAdminSession`) is authorization, following
     * `isAuthzGuardName`'s stated asymmetry: the privilege word is the specific
     * claim and the session word is the generic one.
     *
     * Nothing else is set. `containsSensitiveDataFlow` would be a claim about the
     * data, which this rule never looked at, and the schema is explicit that an
     * absent flag means "did not look" rather than "looked and found nothing".
     */
    const authorization = isAuthzGuardName(accusation.guard);

    const remaining = accusation.convention.length - citedConvention.length;

    findings.push({
      ruleId: 'VG-SMELL-011',
      title: 'Missing Central Auth Boundary',
      description:
        `\`${accusation.guard}\` guards ${accusation.convention.length} mutating route ` +
        `registration${accusation.convention.length === 1 ? '' : 's'} in this project, ` +
        `${accusation.conventionHere.length} of them in this file — so the project has ` +
        `decided how writes are authorized. ` +
        `${describe(primary)} is registered here with no guard at all` +
        (accusation.unguarded.length > 1
          ? `, and so ${accusation.unguarded.length === 2 ? 'is' : 'are'} ` +
            `${accusation.unguarded.length - 1} other write${accusation.unguarded.length === 2 ? '' : 's'} in the same file. `
          : '. ') +
        `The boundary exists and is not a chokepoint: it is applied per registration, so ` +
        `omitting it is a line nobody has to write and nothing structural makes visible. ` +
        `\`${accusation.guard}\` is defined in \`${accusation.guardDefinedIn}\`.` +
        (elevated
          ? ` Reported at ${severity} because the unguarded registration names an ` +
            `administrator-level surface.`
          : '') +
        (remaining > 0
          ? ` ${citedConvention.length} of the ${accusation.convention.length} guarded ` +
            `registrations are listed below.`
          : ''),
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      // `project`, not `line`: the fix is one line, but WHICH line is decided by
      // a convention that lives in three other places and a guard that lives in a
      // fourth. A line pragma here would silence the report of an omission
      // without the omission changing, which is the case `DesignSmellScope`
      // documents as the reason the field exists.
      scope: 'project',
      filePath: primary.filePath,
      startLine: primary.line,
      evidence: [
        `${primary.filePath}:${primary.line} ${describe(primary)} registered with no guard`,
        ...citedUnguarded.map(
          (registration) =>
            `${registration.filePath}:${registration.line} ${describe(registration)} registered with no guard`,
        ),
        ...citedConvention.map(
          (registration) =>
            `${registration.filePath}:${registration.line} ${describe(registration)} carries ${accusation.guard}`,
        ),
        `${accusation.guardDefinedIn}:${accusation.guardDefinitionLine} ${accusation.guard} defined here`,
      ],
      primaryLocation: {
        filePath: primary.filePath,
        startLine: primary.line,
        evidence: `${describe(primary)} registered with no guard`,
      },
      // The convention sites come FIRST, and that ordering is the finding's
      // argument rather than a presentation choice: the accusation is about the
      // SET, and a reader who is shown only the unguarded line is being asked to
      // judge a claim the rule did not make.
      relatedLocations: [
        ...citedConvention.map(conventionLocation),
        {
          filePath: accusation.guardDefinedIn,
          startLine: accusation.guardDefinitionLine,
          evidence: `definition of ${accusation.guard}`,
        },
        ...citedUnguarded.map((registration) => ({
          filePath: registration.filePath,
          startLine: registration.line,
          evidence: `${describe(registration)} is also registered with no guard`,
        })),
      ],
      /**
       * `fanIn` on the guard's own module, from the shared `metrics-calculator`
       * rather than a private edge count, so a reader comparing this against
       * VG-SMELL-010's or VG-SMELL-021's `fanIn` is reading one definition of it.
       * It is the number that says how widely the boundary is already adopted,
       * which is exactly what makes one more omission notable.
       *
       * `duplicatedCheckCount` is deliberately NOT set, although the convention
       * count would fit its shape. That field is documented as "the measurement
       * behind VG-SMELL-010" and means "how many places repeat the same check" —
       * inline duplication, the thing this rule's subject is the CURE for. Two
       * findings in one report disagreeing about what a shared field counts is
       * the failure the shared metrics module exists to prevent.
       */
      metrics: mergeMetrics(fanMetrics(accusation.guardDefinedIn, project.graph)),
      securityContext: authorization
        ? { containsAuthorizationLogic: true }
        : { containsAuthLogic: true },
      tags: ['design-smell', 'cross-file', 'authorization'],
      remediation: {
        why:
          'A guard applied per registration is a guard that can be left off, and leaving it ' +
          'off looks exactly like a route that legitimately needs no guard. The next endpoint ' +
          'added to this file is one edit away from the same omission, and nothing in the ' +
          'structure of the code will point it out.',
        how:
          `Mount \`${accusation.guard}\` once for this router — \`router.use(${accusation.guard})\`, ` +
          'or on the parent mount — so membership of the protected surface is the default and ' +
          'an exception has to be written down. If this registration is meant to be public, ' +
          'say so where it is registered rather than by omission.',
        exampleFix:
          `router.use(${accusation.guard});\n` +
          `router.${primary.method}('${primary.path}', ${primary.handlerName ?? 'handler'});\n` +
          '// the surface is guarded by default; an exception now needs a line of its own.',
      },
    });
  }

  return findings;
}

export const missingCentralAuthBoundary: CrossFileRule = {
  ruleId: 'VG-SMELL-011',
  name: 'Missing Central Auth Boundary',
  description:
    'A guard is applied at several mutating route registrations but omitted at another in the ' +
    'same file, so the authorization boundary exists without being a chokepoint.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  /**
   * `medium`, and the rule never reaches `high` confidence. The evidence is
   * structural rather than semantic — a lexical index decided what a route is and
   * a name decided what a guard is — and both inferences are strong rather than
   * certain. See the confidence block in `analyze` for what moves it down.
   */
  defaultConfidence: 'medium',
  /**
   * TS/JS only, and enforced per file in `analyze` as well as per project by
   * `runCrossFileRules`.
   *
   * Not a placeholder for a wider list. Every negative condition in this file is
   * expressed in Express/Nest vocabulary: `app.use` mounting, the middleware
   * argument position, `export *` barrels, `@UseGuards`. Flask's `@login_required`
   * decorator, FastAPI's `Depends(require_admin)` parameter and Django's URLconf
   * wrappers are three different mechanisms, and none of them is recognised by
   * anything here — so a Python project would present its correctly guarded
   * routes as unguarded ones. That is the precise mistake VG-SMELL-010 recorded
   * when it removed Python from this same list: the detection half worked and the
   * SILENCE half had never been exercised, and shipping it would have made the
   * rule's first contact with Python users a false positive on correct code.
   */
  languages: ['typescript', 'javascript'],
  cwe: ['CWE-306', 'CWE-862'],
  owasp: ['A01:2021 Broken Access Control'],
  remediation: {
    why: 'A per-registration guard can be omitted, and an omission is indistinguishable from a route that needs no guard.',
    how: 'Mount the guard once for the router or at the parent mount, so being protected is the default.',
  },
  analyze,
};
