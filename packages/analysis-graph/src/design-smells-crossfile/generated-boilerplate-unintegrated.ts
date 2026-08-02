// VG-SMELL-052 — Generated Boilerplate Without Integration.
//
// WHAT IT CLAIMS
//
// A security-purpose function was written — a validator, a sanitizer, an
// authentication or authorization guard — it was exported so that something else
// could use it, and nothing in the project ever names it. Meanwhile the routing
// layer is live: there are registrations that mount no guard at all, and
// attacker-controlled data demonstrably reaches a sink inside a registered
// handler. The protection exists in the repository and is not in the request
// path.
//
// WHY THIS IS THE AI FAILURE MODE AND NOT AN ORDINARY DEAD-CODE REPORT
//
// Ask a model for "an endpoint that accepts comments, with input validation" and
// it produces two artefacts: the endpoint, and `validateInput`. Both are correct.
// The one line that joins them — adding `validateInput` to the argument list of
// `app.post` — is a third artefact, it is boring, and it is the one that gets
// dropped, because nothing in either file looks incomplete without it. The
// resulting repository passes every review that reads code rather than wiring:
// the validator is present, exported, and even unit-tested, and the endpoint it
// was written for is unprotected.
//
// This is precisely why the finding must NOT be phrased as "unused export".
// Every project has unused exports and almost none of them are security defects.
// What makes this one a security defect is the conjunction with the request
// path, and the request path is what the rule is required to observe rather than
// assume.
//
// ★ WHY TAINT IS A REQUIREMENT AND NOT AN ORNAMENT
//
// The implementation plan is explicit that 041 and 052 must rest on taint
// evidence rather than a structural heuristic (§5.3, §5.4, and the risk table
// entry "041/052 は taint 根拠必須"). The temptation is to satisfy that on paper
// by printing a flow next to a finding that was decided structurally. This rule
// makes the flow a FIRING CONDITION: with no taint flow reaching a sink inside a
// registered route handler, there is no finding, whatever the rest of the
// structure looks like. `samples/crossfile-fixtures/smell-052-neg-no-untrusted-
// input/` is the fixture that holds that line — an unwired, exported, correctly
// named validator, unguarded routes, and total silence, because nothing in that
// service reads anything a client controls.
//
// The reason to want it that way is not compliance with a plan. It is that
// "exported function nobody calls" is a maintainability observation, and the
// difference between that and a security finding is entirely whether untrusted
// data is flowing past the place the protection should have stood. Taint is the
// only thing in this package that can answer that question with a path a
// reviewer can check line by line instead of a heuristic they have to trust.
//
// ★ HOW THIS DIFFERS FROM VG-AISC-003, WHICH MAKES A SIMILAR-LOOKING JUDGEMENT
//
// `unintegrated-security-init.ts` also reports "generated, and never wired up",
// and half of its mechanism (count identifier occurrences over blanked project
// text; zero occurrences outside the definition means nobody named it) is the
// same idea. The two are deliberately not merged, and the differences are not
// cosmetic:
//
//   - LANGUAGE. That rule is C/C++ only; this one is TS/JS only. The two
//     populations are disjoint by construction, enforced through `languages`, so
//     no file can produce both findings.
//   - WHAT MAKES IT MATTER. There, the evidence that the initializer was meant
//     to be called is a DECLARATION IN A PROJECT HEADER — a static fact about
//     intent. Here it is a live TAINT FLOW — a dynamic fact about consequence. C
//     firmware has no route table to point at; a web service has no header to
//     point at.
//   - WHERE THE MISSING LINE GOES. There the remediation is "call it from your
//     start-up path". Here it is "add it to the argument list of a registration",
//     and the finding cites the specific registrations where it would have gone.
//   - EXPORT SHAPES. C export is `static` or not. JS has four spellings
//     (`export function`, `export const`, `export { … }`, `module.exports = { … }`)
//     and two of them put the symbol's name in the file a SECOND time, which a
//     naive occurrence count reads as a use. That machinery has no C analogue.
//
// The shared half is roughly twenty lines of regex counting, and the version
// here has to carry export-surface and self-recursion exclusions the C version
// has no concept of. Two callers asking different questions, not one abstraction
// waiting to be extracted.
//
// ★ THE ERROR DIRECTION IS REVERSED FROM EVERY OTHER RULE IN THIS DIRECTORY, AND
//   THAT IS THE SINGLE MOST IMPORTANT THING TO UNDERSTAND BEFORE EDITING IT
//
// VG-SMELL-010 fires on the PRESENCE of code, so anything that widens its view
// can only cost recall; the symbol table's deliberate over-admission of guards
// (`checkStock` is judged a guard, on purpose — see `isGuardShapedName`) is safe
// there because an over-admitted guard silences a finding.
//
// This rule fires on the ABSENCE of a reference. Every heuristic that admits one
// extra name, and every file the reference scan is not allowed to read, produces
// a FALSE POSITIVE on correct code. So:
//
//   - the vocabulary below is written from scratch and narrower than
//     `inferRoles`, because inheriting a vocabulary tuned for over-admission
//     would inherit `checkStock` and `ensureDirectory` as security boilerplate;
//   - the reference scan reads the ENTIRE project including the test tree, which
//     is the opposite of what VG-SMELL-010's `TEST_PATH` does, for the reason
//     spelled out on `TEST_PATH` below;
//   - every judgement is an under-approximation: a mention this analysis cannot
//     see makes the finding vanish, never appear.
//
// ★ MEASURED CORRECTION — WHAT THE FIRST IMPLEMENTATION OF THIS RULE GOT WRONG
//
// The paragraph above states the safety argument. The first implementation did
// not actually satisfy it, and an adversarial review found three ways in, each
// reproduced on a real input rather than argued from the source. They are
// recorded here rather than quietly repaired because every one of them is a
// mistake the next author will be tempted to make again, and because two of the
// three were already contradicted by comments elsewhere in this same file — a
// comment claiming a property is not the property.
//
//  1. NO LOCALITY. The three firing conditions were each computed over the WHOLE
//     scan root, so an unreferenced helper in one package, an unguarded route in
//     a second, and a taint flow in a third satisfied the conjunction between
//     them. In a monorepo that is a retired module being convicted by a live
//     service it has never been part of. The old comment "Drop (4) and the rule
//     degenerates into a dead-code report wearing a CWE" was true and the rule
//     was in that state, because condition (4) was being supplied by unrelated
//     code. `APP UNITS` below is the repair.
//
//  2. `export *` DEFEATED THE REFERENCE SCAN. `security/index.ts` writing
//     `export * from './require-admin'`, with `app.ts` doing
//     `import * as guards from './security'` and mounting `Object.values(guards)`,
//     is a construction in which EVERY guard is necessarily mounted — and the
//     confidence comment below asserted that with no inbound import "no namespace
//     object, re-export, or computed lookup can reach the symbol". That assertion
//     was checked against `fanIn`, and `export *` produces no import edge at all
//     (the indexer's `JS_IMPORT` requires the `import` keyword), so `fanIn` was 0
//     and the correctly-mounted guard was reported at `high`. `MODULE_HANDLE` is
//     the repair, and it silences rather than downgrades: a module somebody else
//     holds whole is a module whose symbols this analysis cannot claim to have
//     counted.
//
//  3. `app.use(require('./security/require-auth'))` WAS READ AS "NOBODY USES IT".
//     Mounting a module wholesale never spells the symbol's name, so a purely
//     lexical scan cannot see it — and the rule had the import graph in its hand
//     the entire time and consulted it only for a confidence band. Same repair as
//     (2); the CJS arm additionally has to tell `const { requireAuth } = require(x)`
//     (a named binding, which the lexical scan CAN see) from
//     `const requireAuth = require(x)` and from an inline `require` with no
//     binding at all (both whole-module handles, which it cannot).
//
// ★ APP UNITS: what "the same application" means here, and why not the obvious
//   alternatives
//
// Locality needs a unit, and the unit has to be inferable from source alone —
// this package never reads `package.json`, because `collectProjectFiles` admits
// only files in languages the indexer understands and a manifest is not one of
// them. Three candidates were considered:
//
//   - DIRECTORY DEPTH ("the evidence must share N leading path segments").
//     Rejected: it is a guess about someone else's layout. `middleware/x.ts` and
//     `app.ts` share zero segments and are the same program; `packages/api/**`
//     and `packages/legacy/**` share one and are not.
//   - A CONVENTIONAL CONTAINER LIST (`packages/`, `apps/`, `services/`, …).
//     Rejected as the primary mechanism: it works exactly as far as the list
//     does, and a repository laid out as `frontend/` + `backend/` — which needs
//     no convention to be obviously two products — is not on it.
//   - THE IMPORT GRAPH'S CONNECTED COMPONENTS, which is what is implemented.
//     A component is a set of files that actually reach each other, which is the
//     closest thing to "one program" available without a build system.
//
// The candidate itself is usually NOT in the component — that is the whole
// premise of the finding — so component membership cannot be asked of it
// directly. What is asked instead is whether it sits in the component's
// TERRITORY: the union of the directory subtrees that directly contain a file of
// that component. An unmounted validator in `middleware/` is inside the
// territory of an app whose `request-logger.ts` lives in `middleware/`; a helper
// in `packages/legacy/src/` is not inside the territory of an app whose files
// are all under `packages/api/src/`.
//
// The consequence worth stating in advance, because it looks like a bug the
// first time it is seen: when an application's entry point sits at the scan root
// its territory is the whole tree, and locality stops constraining anything.
// That is correct rather than a hole — a repository whose `app.ts` is at the top
// level IS one application, and every file below it is its territory.

import type { CodeLocation, Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { resolveSpecifier } from '../dependency-graph/index.js';
import { fanMetrics, mergeMetrics, symbolMetrics } from '../metrics/index.js';
import { analyzeProjectTaint, type SinkKind, type TaintFlow } from '../taint/index.js';
import type {
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  DependencyGraph,
  IndexedSymbol,
  RouteBinding,
  SourceFile,
  StructureIndex,
} from '../types.js';

// ---------------------------------------------------------------------------
// ★ The vocabulary: which identifiers are "generated security boilerplate"
//
// Word matching, never substring matching, for the reason written out at length
// on `tokenize` in `../symbol-table/index.ts` and again on `pathWords` in
// `./scattered-authorization.ts`: `/auth/i` matches `author`, `/token/i` matches
// `tokenizer`, `/valid/i` matches `invalidate`. This is the third small word
// splitter in the package and it is not imported from either of the other two —
// the symbol-table one is private to a module that never touches file content
// and exposes only `inferRoles`, whose ANSWER is the thing this rule must not
// reuse (see the header). Sharing six lines of splitting while deliberately not
// sharing the vocabulary built on them would suggest the vocabularies agree.
// ---------------------------------------------------------------------------

/**
 * One word of an identifier: an all-caps acronym run, a Capitalised word, a
 * lowercase run, or a digit run.
 *
 * Every branch is a bounded character class with no nested quantifier, so it is
 * linear on any input and the D3 three-second contract holds by construction
 * rather than by measurement — the property this repository checks for every
 * regex it adds since the A1 ReDoS repair.
 */
const IDENTIFIER_WORD = /[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+/g;

/**
 * Longest identifier this rule will read.
 *
 * Same argument as `NAME_LENGTH_CAP` in the symbol table: past this length there
 * is no naming convention left to read, and a match inside machine-mangled
 * output would be noise wearing the costume of evidence. The indexer already
 * bounds captured names well below this, so the cap is a belt on top of a brace.
 */
const NAME_LENGTH_CAP = 200;

function identifierWords(name: string): string[] {
  const capped = name.length > NAME_LENGTH_CAP ? name.slice(0, NAME_LENGTH_CAP) : name;
  const out: string[] = [];
  IDENTIFIER_WORD.lastIndex = 0;
  for (let m = IDENTIFIER_WORD.exec(capped); m; m = IDENTIFIER_WORD.exec(capped)) {
    out.push(m[0].toLowerCase());
  }
  return out;
}

/**
 * Words that mean "this function CLEANS a value", with no innocent reading.
 *
 * These qualify on their own, without a noun partner, because nothing that is
 * not a sanitizer is called `sanitize`. That is not true of the other verbs:
 * `escape` is `escapeRegExp`, `strip` is `stripAnsi`, `filter` is every array in
 * JavaScript. Those three are in `GATE_WORD` below and need a noun to qualify,
 * so `escapeHtml` is admitted and `escapeRegExp` is not.
 */
const CLEANER_WORD: ReadonlySet<string> = new Set([
  'sanitize',
  'sanitise',
  'sanitized',
  'sanitised',
  'sanitizer',
  'sanitiser',
  'sanitization',
  'sanitisation',
  'purify',
  'purifier',
  'purified',
]);

/**
 * Words that make the identifier a CHECKPOINT rather than a description.
 *
 * `requireX`, `checkX`, `verifyX`, `guardX`, `protectX` are statements that
 * execution should not continue unless X holds. `isX` / `hasX` / `canX` are the
 * predicate form of the same thing.
 *
 * A gate word alone is never enough here, and that is the whole difference from
 * `isGuardShapedName` in the symbol table, which admits `require*` and `check*`
 * on the head word alone and says so explicitly. That over-admission is correct
 * there (an over-admitted guard suppresses a VG-SMELL-010 finding) and is a
 * false positive here (an over-admitted candidate becomes a finding on
 * `checkStock`). Same shape, opposite consequence, so: gate word AND noun.
 */
const GATE_WORD: ReadonlySet<string> = new Set([
  'require',
  'requires',
  'required',
  'ensure',
  'ensures',
  'check',
  'checks',
  'checked',
  'verify',
  'verifies',
  'verified',
  'validate',
  'validates',
  'validated',
  'validation',
  'validator',
  'assert',
  'asserts',
  'guard',
  'guards',
  'protect',
  'protects',
  'protection',
  'enforce',
  'enforces',
  'escape',
  'escapes',
  'strip',
  'strips',
  'filter',
  'filters',
  'reject',
  'rejects',
  'is',
  'has',
  'can',
  'middleware',
  'interceptor',
]);

/** Nouns naming a value that arrived from outside the process. */
const UNTRUSTED_NOUN: ReadonlySet<string> = new Set([
  'input',
  'inputs',
  'request',
  'requests',
  'req',
  'body',
  'payload',
  'payloads',
  'param',
  'params',
  'query',
  'queries',
  'form',
  'forms',
  'upload',
  'uploads',
  'html',
  'sql',
  'xss',
  'script',
  'scripts',
  'url',
]);

/** Nouns naming an IDENTITY claim: who the caller says they are. */
const AUTHENTICATION_NOUN: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authenticate',
  'authenticated',
  'authentication',
  'token',
  'tokens',
  'jwt',
  'jwts',
  'session',
  'sessions',
  'login',
  'signin',
  'credential',
  'credentials',
  'csrf',
  'xsrf',
]);

/** Nouns naming a PRIVILEGE: what an already-identified caller may do. */
const AUTHORIZATION_NOUN: ReadonlySet<string> = new Set([
  'authz',
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'authorization',
  'authorisation',
  'permission',
  'permissions',
  'perm',
  'perms',
  'privilege',
  'privileges',
  'role',
  'roles',
  'acl',
  'access',
  'admin',
  'admins',
  'owner',
  'ownership',
  'scope',
  'scopes',
  'tenant',
]);

/**
 * Whole identifiers that are checkpoints without a partner word.
 *
 * `authorize` and `authenticate` are verbs that name the act itself, so unlike
 * `auth` (equally at home in `authService`, `authReducer`, `useAuth`) there is
 * nothing else they could be describing. Matched against the compact,
 * separator-free lowercase form, so `authorize`, `Authorize`, and `AUTHORIZE`
 * are one entry.
 */
const COMPACT_CHECKPOINT: ReadonlyMap<string, 'authentication' | 'authorization'> = new Map([
  ['authorize', 'authorization'],
  ['authorise', 'authorization'],
  ['authenticate', 'authentication'],
]);

/**
 * ★ REFUSED VOCABULARY, and why each refusal is the cheaper mistake.
 *
 * Recorded rather than omitted, because every one of them is a plausible
 * suggestion that will be made again by whoever reads this next.
 *
 *  - Bare `validate` / `check` / `verify` with no noun. Every codebase has
 *    `validateConfig`, `checkStock`, `verifyChecksum`. Reporting an unused one as
 *    a missing security control is the shape that gets a linter switched off.
 *  - `rateLimit` / `rateLimiter` / `throttle`. Real controls, and availability
 *    ones: the words carry no security noun, so admitting them means admitting
 *    `limit`, which brings `limitResults` and `paginationLimiter` with it.
 *  - `encrypt` / `hash` / `sign` / `mask`. A crypto helper genuinely can be
 *    unreferenced after a refactor, and — the decisive argument — this finding's
 *    own evidence would not apply to it. The rule cites ROUTE REGISTRATIONS as
 *    the places the symbol should have appeared, and a hashing helper does not
 *    belong at a route registration. A finding whose evidence does not fit its
 *    subject is a finding that should not be made. VG-AISC-003 owns the
 *    "generated crypto setup nobody switched on" shape, in C, where the wiring
 *    point is the start-up path and can be named.
 *  - `log` / `audit`. Observability, and an unused logger is not a vulnerability.
 */

/** What kind of protection the identifier names. Drives `securityContext`. */
export type BoilerplateKind = 'sanitizer' | 'validator' | 'authentication' | 'authorization';

/**
 * Whether `name` reads as generated security boilerplate, and of what kind.
 *
 * ★ EXPORTED so the falsification fixtures can be pinned as real negatives.
 *
 * A negative fixture asserting "this directory produces no finding" is worth
 * nothing on its own: it also passes when the rule declined the symbol for a
 * reason the fixture was not built to test — most easily, because the name never
 * qualified in the first place. The tests call this to assert that each negative
 * directory's symbol IS in the vocabulary, so the silence provably comes from
 * the wiring condition the directory is named for. Without that assertion the
 * whole negative corpus could be vacuous and every test in it would still be
 * green, which is the failure mode this repository has already had to repair
 * once elsewhere.
 */
export function classifyBoilerplateName(name: string): BoilerplateKind | undefined {
  const words = identifierWords(name);
  if (words.length === 0) return undefined;

  const compact = COMPACT_CHECKPOINT.get(words.join(''));
  if (compact) return compact;

  // Cleaners first: they qualify alone, so no partner search is needed.
  for (const word of words) {
    if (CLEANER_WORD.has(word)) return 'sanitizer';
  }

  let gate = false;
  let untrusted = false;
  let authn = false;
  let authz = false;
  for (const word of words) {
    if (GATE_WORD.has(word)) gate = true;
    if (UNTRUSTED_NOUN.has(word)) untrusted = true;
    if (AUTHENTICATION_NOUN.has(word)) authn = true;
    if (AUTHORIZATION_NOUN.has(word)) authz = true;
  }
  if (!gate) return undefined;

  // Privilege outranks identity when a name carries both (`requireAdminSession`):
  // the stronger claim is the one the finding should be filed under, and the
  // order has to be fixed rather than incidental so the `securityContext` flag a
  // consumer sees does not depend on word order.
  if (authz) return 'authorization';
  if (authn) return 'authentication';
  if (untrusted) return 'validator';
  return undefined;
}

// ---------------------------------------------------------------------------
// Export surface, and why one function answers two questions
// ---------------------------------------------------------------------------

/**
 * The four spellings of "this file offers this symbol to other files".
 *
 * Run over the BLANKED copy, so a commented-out `export { validateInput }` is
 * not an export surface and a `module.exports` written inside a template string
 * is not either.
 *
 * ★ THE SAME SPANS ANSWER TWO QUESTIONS, AND THAT IS THE DESIGN.
 *
 *  1. IS IT EXPORTED? `IndexedSymbol.exported` is set from the declaration head,
 *     so it is false for `function f() {}` + `export { f }`, and
 *     `StructureIndex.exportedNames` misses `module.exports = { f }` entirely
 *     (the indexer's `JS_EXPORT` only names the `module.exports.f =` form). A
 *     symbol whose name appears inside one of these spans is offered to other
 *     modules whatever its declaration looked like.
 *  2. IS THIS OCCURRENCE A USE? No. `export { validateInput }` writes the name a
 *     second time without calling anything, and an occurrence count that does not
 *     subtract it concludes that every symbol exported at the bottom of its file
 *     is wired. `samples/crossfile-fixtures/smell-052-orphan-sanitizer/` is the
 *     fixture that fails the moment this is forgotten.
 *
 * Both questions are about the same characters, so they are answered from the
 * same scan rather than from two predicates that could disagree about what an
 * export looks like.
 *
 * Every quantifier is bounded and every whitespace class is horizontal
 * (`[^\S\r\n]`, never `\s`), for the A1 reasons documented across this package.
 */
const EXPORT_SURFACE: readonly RegExp[] = [
  // export { a, b as c }   /   export { a } from './x'
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{0,4}\{[^}\r\n]{0,400}\}/g,
  // export default someName   /   export default function someName(…)
  //
  // ★ MEASURED CORRECTION. The first version stopped at the first identifier
  // after `default`, which for `export default function validateInput(…)` is the
  // KEYWORD `function` — so the span ended before the name. The consequences
  // compounded: `IndexedSymbol.exported` is false for that head (`JS_HEAD` looks
  // for `export` immediately before `function`, and `default` is in the way),
  // `StructureIndex.exportedNames` records the literal string `default` (the
  // indexer's `JS_EXPORT` captures the first word it finds), and this span was
  // the last of the three chances to notice. A genuinely unwired default-exported
  // validator was therefore not a candidate at all. Consuming the optional
  // `async` / `function` / `class` keywords is what puts the NAME inside the span.
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{1,4}default[^\S\r\n]{1,4}(?:async[^\S\r\n]{1,4})?(?:(?:function[^\S\r\n]{0,4}\*?|class)[^\S\r\n]{0,4})?[\w$]{1,80}/g,
  // module.exports = { a, b }   /   module.exports.a = a
  /module\.exports(?:\.[\w$]{1,60})?[^\S\r\n]{0,4}=[^;\r\n]{0,400}/g,
  // exports.a = a
  /(?:^|\n)[^\S\r\n]{0,8}exports\.[\w$]{1,60}[^\S\r\n]{0,4}=[^;\r\n]{0,400}/g,
];

type Span = readonly [number, number];

function exportSurfaceSpans(blanked: string): Span[] {
  const spans: Span[] = [];
  for (const pattern of EXPORT_SURFACE) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(blanked); m; m = pattern.exec(blanked)) {
      spans.push([m.index, m.index + m[0].length]);
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
  }
  return spans;
}

function withinAnySpan(offset: number, spans: readonly Span[]): boolean {
  for (const [from, to] of spans) {
    if (offset >= from && offset < to) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The reference scan
// ---------------------------------------------------------------------------

/**
 * Path segments whose contents are fixtures rather than the service under review.
 *
 * ★ USED TO EXCLUDE CANDIDATES AND DELIBERATELY NOT USED TO EXCLUDE REFERENCES.
 *
 * VG-SMELL-010 excludes test paths from everything, and is right to: a
 * duplicated authorization check in a test is not a duplicated authorization
 * check in the product. Copying that here would be a defect, because the two
 * rules fail in opposite directions. A file this rule is not allowed to read is
 * a file that could be holding the reference which makes the finding wrong, so
 * excluding the test tree from the reference scan can only INVENT findings —
 * specifically, on the extremely common shape where a generated validator has a
 * generated unit test and no wiring.
 *
 * A validator referenced only by its own test is still unwired, and a reviewer
 * might reasonably want to hear about it. This rule declines to say so, because
 * the cost of being wrong in that direction is a false positive on a project
 * that did nothing wrong except write a test, and this repository's precision
 * contract makes that the unaffordable error.
 * `samples/crossfile-fixtures/smell-052-neg-test-only/` pins it.
 */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata)(?:\/|$)|\.(?:test|spec)\.[\w]+$/i;

/** A whole-word occurrence pattern for an identifier, with metacharacters escaped. */
function wordPattern(name: string): RegExp {
  // The name comes from a matched identifier and cannot contain a metacharacter
  // today. Escaping anyway is the habit that survives the day the indexer starts
  // capturing something else.
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(String.raw`\b${escaped}\b`, 'g');
}

function countOccurrences(pattern: RegExp, text: string): number {
  pattern.lastIndex = 0;
  let n = 0;
  for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
    n += 1;
    if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
  }
  return n;
}

/** A symbol that reads as security boilerplate, before the wiring test. */
interface BoilerplateCandidate {
  symbol: IndexedSymbol;
  structure: StructureIndex;
  kind: BoilerplateKind;
  /** Export-surface spans of the defining file, computed once. */
  exportSpans: Span[];
}

/**
 * Whether anything in the project names this symbol.
 *
 * Counts whole-word occurrences over BLANKED text project-wide, so a mention in
 * a comment (`// TODO: mount validateInput`) or inside a string is not wiring —
 * the same conservative reading VG-AISC-003 takes, and for the same reason: a
 * comment is not a call, and treating it as one would suppress a real finding.
 *
 * In the DEFINING file, three kinds of occurrence are not uses and are subtracted:
 *
 *  - the declaration head itself, which every symbol has exactly once. Rather
 *    than locating it by offset arithmetic against `startLine`/`startColumn`,
 *    the test is "more than one occurrence survives", which is the same
 *    statement with nothing to get wrong;
 *  - occurrences inside the symbol's OWN BODY, which is recursion. A validator
 *    that calls itself has not been wired to anything;
 *  - occurrences inside an export surface. See `EXPORT_SURFACE`.
 *
 * In every OTHER file, ANY occurrence counts as a reference — including a bare
 * `import { validateInput } from './validators'` with no call, and including
 * anything under the test tree. Both are deliberate under-approximations: an
 * import with no call is arguably still this smell, and this rule declines to
 * make that claim because a lexical scan cannot distinguish it from a call the
 * pattern did not recognise.
 *
 * ★ WHAT THIS FUNCTION IS NOT ALLOWED TO BE ASKED ON ITS OWN.
 *
 * Its answer is "no file spelled the name", and the first implementation read
 * that as "no file uses it". The two differ for every import form that does not
 * spell names — a re-export chain, a namespace object, a whole-module `require`
 * — and the difference was two of the three defects this rule shipped with. The
 * caller must therefore consult `opaquelyHeldFiles` FIRST and decline the
 * candidate outright; there is no occurrence count that recovers the answer
 * afterwards.
 */
function isReferencedAnywhere(
  candidate: BoilerplateCandidate,
  structures: readonly StructureIndex[],
): boolean {
  const { symbol, structure } = candidate;
  const pattern = wordPattern(symbol.name);

  for (const other of structures) {
    if (other.filePath !== structure.filePath) {
      if (countOccurrences(pattern, other.blanked) > 0) return true;
      continue;
    }
    pattern.lastIndex = 0;
    let surviving = 0;
    for (let m = pattern.exec(other.blanked); m; m = pattern.exec(other.blanked)) {
      const at = m.index;
      const inOwnBody = at >= symbol.bodyStart && at < symbol.bodyEnd;
      if (!inOwnBody && !withinAnySpan(at, candidate.exportSpans)) surviving += 1;
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
    if (surviving > 1) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// ★ Module handles: the forms in which another file holds a module WHOLE
//
// The reference scan above asks "does any file spell this symbol's name". That
// question has an answer only for the import forms that name what they take.
// Five forms do not, and each of them hands the importing file the module
// itself rather than a binding out of it:
//
//   export * from './x'          the barrel; nothing is named, everything passes
//   import * as ns from './x'    a namespace object; `ns[k]` reaches any export
//   import x from './x'          the default binding — which may BE the candidate
//   import './x'                 side-effect only; the module registers itself
//   require('./x')               undestructured, including inline as an argument
//
// A file reached by any of these is a file whose symbols this analysis has not
// counted, and the rule's whole safety argument is that it under-claims. So the
// response is SILENCE on every candidate defined in such a file, not a lowered
// confidence: `low` is still a finding, and a finding that says "this guard is
// not mounted" about `app.use(require('./security/require-auth'))` is wrong
// rather than uncertain.
//
// ★ WHY THIS IS NOT READ OFF `StructureIndex.imports`
//
// The import edges are already built, already resolved, and carry a `names`
// array — the obvious move is to call an edge opaque when `names` is empty. It
// does not work, and the reason is worth recording so it is not re-attempted:
// `bindingNames` in the indexer flattens all three ESM shapes onto the same
// output. `import * as ns from './x'` yields `['ns']`, `import def from './x'`
// yields `['def']`, and `import { def } from './x'` also yields `['def']`. The
// distinction this needs is exactly the one that array has already discarded, so
// the syntax has to be re-read. `export *` is worse than ambiguous there: it
// produces no edge at all, which is the defect that shipped.
//
// The specifier is read from the ORIGINAL content at the matched offsets, not
// from the blanked copy, because a specifier IS a string literal and the blanked
// copy holds spaces where its characters were. Blanking is length-preserving, so
// the offsets transfer — the same property `structure-indexer` relies on.
// Resolution goes through `resolveSpecifier`, the dependency graph's own
// resolver, so an edge this rule follows and an edge the graph drew agree by
// construction rather than by two implementations happening to match.
// ---------------------------------------------------------------------------

const MODULE_HANDLE: readonly RegExp[] = [
  // export * from './x'   /   export * as ns from './x'
  /(?:^|\n)[^\S\r\n]{0,8}export[^\S\r\n]{0,4}\*[^\S\r\n]{0,4}(?:as[^\S\r\n]{1,4}[\w$]{1,60}[^\S\r\n]{1,4})?from[^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g,
  // import * as ns from './x'   /   import def, * as ns from './x'
  /(?:^|\n)[^\S\r\n]{0,8}import[^\S\r\n]{1,4}(?:[\w$]{1,60}[^\S\r\n]{0,4},[^\S\r\n]{0,4})?\*[^\S\r\n]{1,4}as[^\S\r\n]{1,4}[\w$]{1,60}[^\S\r\n]{1,4}from[^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g,
  // import def from './x'. The `type` lookahead keeps `import type X from './x'`
  // out: a type-only binding is erased at compile time and can reach no value.
  /(?:^|\n)[^\S\r\n]{0,8}import[^\S\r\n]{1,4}(?!type[^\S\r\n])[\w$]{1,60}[^\S\r\n]{1,4}from[^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g,
  // import './x'   (side-effect import: the module wires itself up on load)
  /(?:^|\n)[^\S\r\n]{0,8}import[^\S\r\n]{1,4}['"](?<spec>[^'"\n]{1,200})['"]/g,
  // await import('./x')
  /\bimport[^\S\r\n]{0,4}\([^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g,
];

/**
 * `require('./x')`, with the binding clause when there is one.
 *
 * Separate from `MODULE_HANDLE` because it is the one form that can be either:
 * `const { requireAuth } = require('./x')` names what it takes and the lexical
 * scan sees it, while `const auth = require('./x')` and a bare
 * `app.use(require('./x'))` do not. The brace in the captured clause is the
 * whole test, and an absent clause means the module was consumed as an
 * expression — the shape that shipped as a false positive.
 *
 * `[^=\n]` rather than `[^=]` in the clause: an import statement is one line, and
 * letting the class cross a newline is how the Python arm of `structure-indexer`
 * once swallowed every following import into one match.
 */
const REQUIRE_HANDLE =
  /(?<bind>(?:const|let|var)[^\S\r\n]{1,4}[^=\n]{1,200}=[^\S\r\n]{0,4})?require[^\S\r\n]{0,4}\([^\S\r\n]{0,4}['"](?<spec>[^'"\n]{1,200})['"]/g;

/**
 * Files that some other file in the project holds a whole-module handle on.
 *
 * Computed over EVERY structure including the test tree, for the same reason
 * `isReferencedAnywhere` reads the test tree: a file this scan is not allowed to
 * look at is a file that could be holding the handle which makes the finding
 * wrong.
 */
function opaquelyHeldFiles(
  structures: readonly StructureIndex[],
  files: readonly SourceFile[],
): Set<string> {
  const known = new Set(structures.map((s) => s.filePath));
  const contentOf = new Map(files.map((f) => [f.filePath, f.content]));
  const held = new Set<string>();

  for (const structure of structures) {
    // Falling back to `blanked` keeps this total when a structure has no
    // matching `SourceFile`; the specifier read from it would be spaces, which
    // resolves to nothing — silence, which is the safe direction.
    const content = contentOf.get(structure.filePath) ?? structure.blanked;

    const record = (specifier: string): void => {
      const resolved = resolveSpecifier(
        { fromFile: structure.filePath, specifier, names: [], line: 0, syntax: 'esm' },
        known,
      );
      // ★ MEASURED CORRECTION. This used to read
      // `resolved !== undefined && resolved !== structure.filePath`, on the
      // reasoning that a module holding a handle on itself says nothing about
      // who else can reach its symbols. A 31-mutation audit found the extra
      // term unkillable, and writing a fixture for it means writing a file that
      // imports itself — pathological code invented to justify a check. The
      // term was deleted rather than excused: without it a self-importing file
      // goes quiet, which is the direction this rule is required to fail in.
      if (resolved !== undefined) held.add(resolved);
    };

    // The specifier is the last capture in every pattern and is immediately
    // followed by the closing quote, so its offset is fixed by the match end.
    // Arithmetic rather than `lastIndexOf`, which searches for a run of spaces
    // in the blanked text and can find an indentation run instead.
    const readSpec = (match: RegExpExecArray, spec: string): string => {
      const at = match.index + match[0].length - 1 - spec.length;
      return content.slice(at, at + spec.length);
    };

    for (const pattern of MODULE_HANDLE) {
      pattern.lastIndex = 0;
      for (let m = pattern.exec(structure.blanked); m; m = pattern.exec(structure.blanked)) {
        const spec = m.groups?.spec;
        if (spec !== undefined) record(readSpec(m, spec));
        if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
      }
    }

    REQUIRE_HANDLE.lastIndex = 0;
    for (let m = REQUIRE_HANDLE.exec(structure.blanked); m; m = REQUIRE_HANDLE.exec(structure.blanked)) {
      const spec = m.groups?.spec;
      const destructured = (m.groups?.bind ?? '').includes('{');
      if (spec !== undefined && !destructured) record(readSpec(m, spec));
      if (REQUIRE_HANDLE.lastIndex === m.index) REQUIRE_HANDLE.lastIndex += 1;
    }
  }

  return held;
}

// ---------------------------------------------------------------------------
// ★ App units: the locality the three conditions have to agree on
//
// See the header for why the unit is an import-graph connected component and
// why the candidate is attached to it by directory rather than by membership.
// ---------------------------------------------------------------------------

/** Directory part of a repo-relative path; `''` for a file at the scan root. */
function directoryOf(filePath: string): string {
  const cut = filePath.lastIndexOf('/');
  return cut === -1 ? '' : filePath.slice(0, cut);
}

/** Whether `dir` is `root` or lies inside it. The scan root contains everything. */
function isWithin(dir: string, root: string): boolean {
  return root === '' || dir === root || dir.startsWith(`${root}/`);
}

/**
 * Undirected connected components of the resolved import graph.
 *
 * UNDIRECTED on purpose. `app.ts → routes/search.ts` and
 * `server.ts → app.ts` are the same program read from two ends, and a directed
 * reachability from either one alone would split it: an entry point imports its
 * routes and is imported by nothing, so following edges forwards from a route
 * file finds no app and following them backwards from the app finds no routes.
 *
 * Only edges the graph RESOLVED participate, so a shared third-party package
 * does not fuse two services into one component — `express` has no
 * `resolvedFile` and therefore no node.
 *
 * Deterministic by construction: `files` arrives sorted, members are sorted, and
 * components come out in the order of their lowest-sorting member.
 */
function connectedComponents(files: readonly string[], graph: DependencyGraph): string[][] {
  const inScope = new Set(files);
  const seen = new Set<string>();
  const components: string[][] = [];

  for (const start of files) {
    if (seen.has(start)) continue;
    seen.add(start);
    const members: string[] = [];
    const queue: string[] = [start];
    while (queue.length > 0) {
      const current = queue.shift()!;
      members.push(current);
      for (const neighbours of [graph.importsOf.get(current), graph.importedBy.get(current)]) {
        for (const next of neighbours ?? []) {
          if (!inScope.has(next) || seen.has(next)) continue;
          seen.add(next);
          queue.push(next);
        }
      }
    }
    members.sort();
    components.push(members);
  }

  return components;
}

/**
 * One application: a component of the import graph that both registers an
 * unguarded endpoint and carries untrusted data into a sink behind one.
 *
 * A component missing either half is not a unit this rule can speak about, and
 * dropping it here rather than filtering later is what stops one service's
 * routing table from vouching for another service's dangling helper — the exact
 * behaviour `generated-boilerplate-unintegrated.test.ts` recorded as a surprise
 * when the conditions were project-wide.
 */
interface AppUnit {
  /** Directory subtrees this component occupies. Sorted. */
  territory: string[];
  open: OpenRegistration[];
  flows: TaintFlow[];
}

function liveUnits(
  structures: readonly StructureIndex[],
  graph: DependencyGraph,
  open: readonly OpenRegistration[],
  flows: readonly TaintFlow[],
): AppUnit[] {
  const units: AppUnit[] = [];

  for (const members of connectedComponents(structures.map((s) => s.filePath), graph)) {
    const files = new Set(members);
    const ownOpen = open.filter((entry) => files.has(entry.filePath));
    if (ownOpen.length === 0) continue;
    const ownFlows = flows.filter((flow) => files.has(flow.filePath));
    if (ownFlows.length === 0) continue;
    units.push({
      territory: [...new Set(members.map(directoryOf))].sort(),
      open: ownOpen,
      flows: ownFlows,
    });
  }

  return units;
}

/** The unit whose territory contains `filePath`, if any. */
function unitFor(units: readonly AppUnit[], filePath: string): AppUnit | undefined {
  const dir = directoryOf(filePath);
  return units.find((unit) => unit.territory.some((root) => isWithin(dir, root)));
}

// ---------------------------------------------------------------------------
// The routing evidence
// ---------------------------------------------------------------------------

/**
 * A route path that is actually a route path.
 *
 * ★ MEASURED, ON THIS RULE'S OWN FIXTURES: `RouteBinding` IS NOT AN ENDPOINT.
 *
 * The indexer's `JS_ROUTE` is `(?<obj>[\w$]{1,40})\.(?<method>get|post|…|use)\(`,
 * which is every `.get(` in the language. Running the rule over
 * `smell-052-neg-all-routes-guarded/security/require-admin.ts` produced a
 * `RouteBinding` for `req.get('authorization')` — method `get`, path
 * `authorization`. `map.get(key)`, `cache.get(id)` and `headers.get(name)` all
 * parse the same way, and `map.get(key)` in particular comes out with an empty
 * middleware list and `key` in the handler slot, which is byte-for-byte the
 * shape of an unguarded endpoint.
 *
 * That matters here more than it does anywhere else in this package, because
 * "an unguarded registration exists" is a PERMISSIVE condition: a spurious one
 * makes the rule more willing to fire, and it would be cited in the finding as
 * the place the validator should have gone. So a registration has to look like
 * an HTTP endpoint before it counts as one, and an Express path literal begins
 * with `/` (or is the catch-all `*`). `map.get(key)` has no literal first
 * argument at all and `req.get('authorization')` has one that is not a path.
 *
 * The cost is recall on `router.route('/x').get(handler)`, whose `.get(` has no
 * path argument. Accepted: the failure is a missing finding.
 */
const ROUTE_PATH = /^(?:\/|\*$)/;

/**
 * Route registrations that mount no guard at all: the empty slots.
 *
 * These are what the finding points at when it says "this is where it should
 * have gone", and requiring at least one of them is a precision condition rather
 * than decoration. In a project where every registration already carries a
 * guard, an unreferenced security helper is far more likely to be a leftover
 * from a refactor than a protection that was never connected — and a finding
 * whose evidence section would be empty is a finding making a claim it cannot
 * support. `samples/crossfile-fixtures/smell-052-neg-all-routes-guarded/` is the
 * fixture that keeps this honest.
 *
 * ★ `use` REGISTRATIONS ARE NOT EMPTY SLOTS, AND THE DISTINCTION IS SUBTLE.
 *
 * `app.use(requireAdmin)` parses as a registration whose middleware list is
 * empty and whose handler slot holds a named function — structurally identical
 * to an unguarded endpoint, and semantically its exact opposite: the "handler"
 * IS the guard, mounted for every route beneath it. Counting it as an empty slot
 * would make the rule cite the application's own guard as the place its guard is
 * missing. The `neg-all-routes-guarded` fixture contains one specifically to
 * catch that.
 *
 * A registration with no handler name at all (`app.use(express.json())`, where
 * the argument is a call rather than an identifier) is dropped too: there is no
 * endpoint there to protect.
 */
interface OpenRegistration {
  route: RouteBinding;
  filePath: string;
  /** Corrected 1-based line. See `registrationLine`. */
  line: number;
}

/**
 * The line a registration is actually written on.
 *
 * ★ THIS COMPENSATES FOR AN OFF-BY-ONE IN `structure-indexer`, AND IT SHOULD NOT
 *   HAVE TO EXIST.
 *
 * `JS_ROUTE` opens with `(?:^|[^\w$.])`, so it consumes the character BEFORE the
 * object identifier, and `RouteBinding.line` is computed from `m.index` — which
 * is the offset of that consumed character. For a registration written at the
 * start of its line, the consumed character is the newline ENDING THE PREVIOUS
 * LINE, and the recorded line is one too low. Measured on
 * `smell-052-unwired-validator/app.ts`: `app.get('/search', …)` is on line 11 and
 * is recorded as 10, which is blank.
 *
 * The correct repair is one line in `structure-indexer/index.ts` — anchor past
 * the consumed boundary character, exactly as `collectEvents` in `../taint/`
 * already does for `ASSIGN_RE`, under a comment calling a one-line-off hop "the
 * single most embarrassing kind of wrong a report that asks the reader to check
 * a line number can be". This rule does not own that file, and shipping the raw
 * value would mean every related location it emits points at the wrong line, so
 * the value is corrected here and the defect is reported upstream rather than
 * absorbed silently.
 *
 * The correction is exact rather than a guess, because the error has exactly one
 * shape: the recorded line is either right, or one less than right, and the
 * second case requires the identifier to begin at column 1 of the following
 * line. Two tests decide it, and the second is what makes adjacent registrations
 * unambiguous:
 *
 *   - does the recorded line itself carry this registration (`.method(` plus,
 *     when there is one, this route's own path literal)? If so it is right, and
 *     nothing is changed.
 *   - failing that, does the NEXT line begin with `identifier.method(` and carry
 *     this route's path? Then the boundary character was that newline.
 *
 * Anything else leaves the recorded value alone: a wrong line is bad and a
 * confidently invented one is worse.
 */
function registrationLine(route: RouteBinding, lines: readonly string[]): number {
  const recorded = route.line;
  const here = lines[recorded - 1] ?? '';
  const next = lines[recorded] ?? '';
  // `method` comes from the indexer's closed alternation (`get|post|…|use`), so
  // it carries no regex metacharacter; `path` is only ever compared with
  // `includes`, so it needs no escaping either.
  const head = new RegExp(String.raw`\.${route.method}[^\S\r\n]{0,4}\(`);
  const carriesPath = (text: string): boolean =>
    route.path === undefined || text.includes(route.path);

  if (head.test(here) && carriesPath(here)) return recorded;
  if (/^[\w$]{1,40}\./.test(next) && head.test(next) && carriesPath(next)) return recorded + 1;
  return recorded;
}

function collectOpenRegistrations(
  structures: readonly StructureIndex[],
  files: readonly SourceFile[],
): OpenRegistration[] {
  const linesOf = new Map(files.map((f) => [f.filePath, f.lines]));
  const open: OpenRegistration[] = [];
  for (const structure of structures) {
    if (TEST_PATH.test(structure.filePath)) continue;
    const lines = linesOf.get(structure.filePath) ?? [];
    for (const route of structure.routes) {
      if (route.method === 'use') continue;
      if (route.handlerName === undefined) continue;
      // Two statements rather than one `||`, because they exclude two different
      // shapes and each has its own fixture: `store.get(key, fallback)` has no
      // literal first argument at all, and `config.get('database.url', DEFAULT)`
      // has one that is a settings key. Folded together, either check could be
      // deleted while the other kept every test green.
      if (route.path === undefined) continue;
      if (!ROUTE_PATH.test(route.path)) continue;
      if (route.middlewareNames.length > 0) continue;
      open.push({ route, filePath: structure.filePath, line: registrationLine(route, lines) });
    }
  }
  open.sort((a, b) =>
    a.filePath === b.filePath ? a.line - b.line : a.filePath < b.filePath ? -1 : 1,
  );
  return open;
}

// ---------------------------------------------------------------------------
// The taint evidence
// ---------------------------------------------------------------------------

/**
 * Sinks whose reachability from untrusted input is an injection.
 *
 * The one condition allowed to raise severity, and the only one. `response` and
 * `file` are real sinks and are deliberately outside the set: reflecting a query
 * parameter into a response body is a different order of consequence from
 * concatenating it into a statement an interpreter will run, and a severity that
 * cannot tell those apart is not a severity.
 *
 * ★ THE CONDITION THAT WAS CONSIDERED AND REFUSED: the candidate's own kind.
 *
 * "An unmounted `requireAuth` means every endpoint is anonymous, so authorization
 * boilerplate should be `high` regardless of sink" is a good argument and it is
 * not implemented, because it cannot partition. Every candidate of that kind
 * would take the boost, so the severity field would become a restatement of the
 * `securityContext` flag already on the finding. `ROUTING_LAYER_TOKEN` in
 * `scattered-authorization.ts` was dropped from severity for exactly this reason
 * with a corpus measurement behind it (95.4% of sites). There is no comparable
 * measurement for this rule yet — it has never been run over `paper_data` — so
 * the honest position is to ship the one condition that demonstrably splits the
 * fixture corpus and record this one as unmeasured rather than to assume.
 */
const INJECTION_SINK: ReadonlySet<SinkKind> = new Set<SinkKind>(['query', 'exec', 'eval']);

/**
 * Taint flows that end inside a REGISTERED route handler.
 *
 * The restriction to registered handlers is what makes the flow evidence for
 * THIS rule rather than a general observation about the project. A flow inside a
 * background job says nothing about whether a route-level validator was
 * connected; a flow inside a handler that a router points at is untrusted data
 * travelling the exact path the missing middleware would have stood in.
 *
 * Handler membership comes from `IndexedSymbol.kind`, which `linkRouteHandlers`
 * assigns by resolving registrations through the import graph — so a handler
 * written in `controllers/` and registered in `routes/` is included, which is the
 * layout most affected projects actually have.
 */
function routeHandlerFlows(
  structures: readonly StructureIndex[],
  files: readonly SourceFile[],
): TaintFlow[] {
  const handlersByFile = new Map<string, Set<string>>();
  for (const structure of structures) {
    if (TEST_PATH.test(structure.filePath)) continue;
    for (const symbol of structure.symbols) {
      if (symbol.kind !== 'route-handler') continue;
      const names = handlersByFile.get(structure.filePath) ?? new Set<string>();
      names.add(symbol.name);
      handlersByFile.set(structure.filePath, names);
    }
  }
  if (handlersByFile.size === 0) return [];

  const flows = analyzeProjectTaint([...structures], [...files]).filter((flow) =>
    handlersByFile.get(flow.filePath)?.has(flow.symbolName) ?? false,
  );

  // Explicit total order. `analyzeProjectTaint` walks symbols shortest-body-first
  // and its output order is therefore an implementation detail of that module;
  // the finding cites `flows[0]`, so inheriting that order would make this rule's
  // primary evidence move whenever the taint module's traversal changed.
  flows.sort(
    (a, b) =>
      (a.filePath < b.filePath ? -1 : a.filePath > b.filePath ? 1 : 0) ||
      a.sink.line - b.sink.line ||
      a.sink.column - b.sink.column ||
      a.source.line - b.source.line ||
      a.source.column - b.source.column ||
      (a.sink.name < b.sink.name ? -1 : a.sink.name > b.sink.name ? 1 : 0),
  );
  return flows;
}

/** `req.query at routes/search.ts:5 → term:5 → db.query at routes/search.ts:6 [query]`. */
function describeFlow(flow: TaintFlow): string {
  const hops = flow.hops.map((h) => ` → ${h.name}:${h.line}`).join('');
  return (
    `${flow.filePath}:${flow.source.line} ${flow.source.name}${hops}` +
    ` → ${flow.filePath}:${flow.sink.line} ${flow.sink.name} [${flow.sink.kind}]`
  );
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/**
 * How many empty registrations the finding lists.
 *
 * A service with forty unguarded endpoints would otherwise produce a finding
 * with forty related locations, which is not evidence, it is a directory
 * listing. The TOTAL is stated in the description, so the number is not lost —
 * only the enumeration is truncated, and the reader is told that it was.
 */
const MAX_CITED_REGISTRATIONS = 3;

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;

  // Deterministic file order, everywhere, for the reason spelled out in
  // `collectScatteredAuthSites`: an unsorted walk makes a finding's primary
  // location depend on filesystem enumeration order, and a finding that appears
  // to move on its own is one no baseline can track.
  const structures = [...project.structures.keys()]
    .sort()
    .map((key) => project.structures.get(key)!)
    // PER-FILE language enforcement, not just the project-level gate
    // `runCrossFileRules` applies. A polyglot repository passes that gate and
    // would otherwise hand this rule Python and C files, whose export and
    // routing conventions none of the vocabulary above understands.
    .filter((structure) => generatedBoilerplateUnintegrated.languages.includes(structure.language));

  if (structures.length === 0) return [];

  const candidates: BoilerplateCandidate[] = [];
  for (const structure of structures) {
    // Candidates never come from the test tree; references always may. See
    // `TEST_PATH`.
    if (TEST_PATH.test(structure.filePath)) continue;
    const exportSpans = exportSurfaceSpans(structure.blanked);

    for (const symbol of structure.symbols) {
      // Classes are excluded, and not for tidiness. A class is reached by
      // construction, and the mechanisms that construct one without naming it
      // — a DI container reading decorator metadata, a string provider token, a
      // framework that discovers guards by globbing the directory — are exactly
      // this analysis's blind spot. `smell-052-neg-class-guard/` is a fixture in
      // which deleting this line reports a correctly registered guard class.
      if (symbol.kind === 'class') continue;
      // Class MEMBERS, for the neighbouring reason: a method is invoked through
      // the interface it implements (Nest's `canActivate`, class-validator's
      // `validate`), so its name appearing nowhere else is the normal state of a
      // correctly wired framework guard.
      //
      // ★ MEASURED LIMIT — THIS LINE IS UNREACHABLE, AND IS KEPT ANYWAY.
      //
      // A 33-mutation audit deletes it and every test stays green. Two separate
      // facts make that so, and neither is fixable by writing a better fixture:
      //
      //  1. The two terms are the same predicate. `structure-indexer` sets
      //     `kind: enclosing ? 'method' : 'function'` and `enclosingClass` from
      //     the same `enclosing`, in both its JS and its Python arm, so they
      //     hold of exactly the same symbols. They diverge only when
      //     `linkRouteHandlers` re-labels a method as `middleware`, which
      //     happens only when a registration NAMES it — and a named symbol is
      //     referenced, so it never arrives here. Written as one statement to
      //     say that, rather than as two that would look independently tested.
      //  2. The `exported` gate below already excludes every method. A method
      //     head never carries `export`, `JS_EXPORT` only records top-level
      //     names, and the export-surface spans cover the file's export
      //     statements — none of which a class member appears in. Constructing a
      //     counterexample means writing a file that re-exports a name its own
      //     class happens to reuse, which is not code, it is a fixture arguing
      //     with itself.
      //
      // Kept because the reasoning is entirely about what the INDEXER does
      // today. An indexer that starts marking class members exported — a
      // TypeScript `declare module` block would be the obvious way in — makes
      // this the line standing between the rule and a finding on every correctly
      // wired Nest guard. Deleting a check because the current producer makes it
      // unreachable is how the producer's next change becomes a false positive.
      if (symbol.kind === 'method' || symbol.enclosingClass !== undefined) continue;

      const kind = classifyBoilerplateName(symbol.name);
      if (kind === undefined) continue;

      // Exported, by any of the four spellings. A file-local helper was never
      // offered to anyone, so "nobody else uses it" is not evidence that a
      // connection is missing — it is how a private function behaves.
      const exported =
        symbol.exported ||
        structure.exportedNames.includes(symbol.name) ||
        (() => {
          const pattern = wordPattern(symbol.name);
          pattern.lastIndex = 0;
          for (let m = pattern.exec(structure.blanked); m; m = pattern.exec(structure.blanked)) {
            if (withinAnySpan(m.index, exportSpans)) return true;
            if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
          }
          return false;
        })();
      if (!exported) continue;

      candidates.push({ symbol, structure, kind, exportSpans });
    }
  }
  if (candidates.length === 0) return [];

  // Note what is NOT excluded here: symbols whose `kind` is `middleware` or
  // `route-handler`. Both roles are assigned by `linkRouteHandlers` from a route
  // binding, and a binding is a place where the name is written — so the
  // reference scan below already sees every one of them. An explicit `kind`
  // check would be a second mechanism answering the same question, free to drift
  // from the first. `smell-052-neg-mounted/` is the fixture that asserts the
  // equivalence instead of this comment merely claiming it.
  // The defining module must not be one that somebody else holds WHOLE. See
  // `MODULE_HANDLE`: a barrel re-export, a namespace import, a default binding,
  // a side-effect import or an undestructured `require` all reach a symbol
  // without ever spelling its name, so the reference scan's answer for such a
  // file is "did not see one", not "there is none".
  const opaquelyHeld = opaquelyHeldFiles(structures, project.files);
  const unwired = candidates.filter((candidate) => {
    if (opaquelyHeld.has(candidate.structure.filePath)) return false;
    if (isReferencedAnywhere(candidate, structures)) return false;
    return true;
  });
  if (unwired.length === 0) return [];

  const open = collectOpenRegistrations(structures, project.files);
  // ★ A COST SHORT-CIRCUIT, NOT A DECISION, and the same is true of the flow
  // guard below. `liveUnits` reaches the identical verdict from an empty list —
  // no component can hold an open registration if there are none — so deleting
  // either line changes no output. Both survived a mutation audit for exactly
  // that reason, and they are kept and labelled rather than removed because the
  // early return on `open` is what stops a repository with no unguarded
  // endpoints from paying for a whole-project taint pass. A survivor that is
  // genuinely equivalent should say so, instead of looking like an untested
  // check that nobody noticed.
  if (open.length === 0) return [];

  // Taint LAST, because it is the only phase whose cost is proportional to the
  // whole project rather than to the candidate set. A repository with no
  // security-named exports never pays for it.
  const flows = routeHandlerFlows(structures, project.files);
  if (flows.length === 0) return [];

  // ★ And the two of them have to belong to ONE application. See the APP UNITS
  // section of the header: before this existed, an unguarded route in one
  // package and a taint flow in another satisfied the conjunction between them.
  const units = liveUnits(structures, project.graph, open, flows);
  if (units.length === 0) return [];

  const registrationLocation = (entry: OpenRegistration, name: string): CodeLocation => ({
    filePath: entry.filePath,
    startLine: entry.line,
    evidence:
      `${entry.route.method.toUpperCase()} ${entry.route.path}` +
      ` registered with no guard — \`${name}\` would have gone here`,
  });

  const findings: CrossFileFinding[] = [];

  // Candidates are already in (file, symbol) discovery order because both loops
  // above walk sorted structures and the indexer emits symbols in source order.
  // Sorted again anyway: the guarantee should be stated where it is relied on,
  // not inferred from two other modules' behaviour.
  const ordered = [...unwired].sort(
    (a, b) =>
      (a.structure.filePath < b.structure.filePath
        ? -1
        : a.structure.filePath > b.structure.filePath
          ? 1
          : 0) ||
      a.symbol.startLine - b.symbol.startLine ||
      (a.symbol.name < b.symbol.name ? -1 : a.symbol.name > b.symbol.name ? 1 : 0),
  );

  for (const candidate of ordered) {
    const { symbol, structure, kind } = candidate;

    /**
     * ★ THE LOCALITY CONDITION, applied per candidate rather than once.
     *
     * It has to be per candidate because a scan root can hold several
     * applications, and the question "is this helper part of a live request
     * path" has a different answer for each of them. A candidate outside every
     * live unit's territory is dropped in silence: the evidence that would be
     * cited against it belongs to a program it is not part of, and a finding
     * whose evidence comes from somewhere else is the failure mode this rule
     * shipped with.
     */
    const unit = unitFor(units, structure.filePath);
    if (unit === undefined) continue;

    /**
     * Severity aggregates over the unit's flows with ∃, and the CITED flow is
     * the one that justified it.
     *
     * ∃ is the same aggregation `scattered-authorization.ts` uses for its boost
     * conditions, and for the same reason: the dangerous property of a service is
     * the worst thing any one of its endpoints does, and requiring unanimity
     * would let a single read-only handler cancel the observation.
     *
     * What is easy to get wrong is which flow the finding then PRINTS. Reporting
     * `high` while citing a `response` flow — because that one happened to sort
     * first — leaves the reader unable to reconstruct the verdict from the
     * evidence, which is the whole point of carrying a flow. So the cited flow is
     * the first flow in the total order that CARRIES the reason for the severity.
     * `smell-052-two-flows/` is the fixture in which the two differ.
     */
    const injection = unit.flows.some((f) => INJECTION_SINK.has(f.sink.kind));
    const severity: Severity = injection ? 'high' : 'medium';
    const flow =
      (injection ? unit.flows.find((f) => INJECTION_SINK.has(f.sink.kind)) : unit.flows[0]) ??
      unit.flows[0]!;
    const open = unit.open;
    const cited = open.slice(0, MAX_CITED_REGISTRATIONS);

    const source: SourceFile | undefined = project.files.find((f) => f.filePath === symbol.filePath);

    /**
     * Confidence, and the one thing that genuinely moves it.
     *
     * The evidence is a lexical ABSENCE, which is the weakest kind there is: it
     * says the analysis looked in the files it was given and found no mention.
     * A computed member access (`handlers[name]`), a DI container resolving by
     * string token, a build step that generates the wiring, or a source file
     * outside the scanned tree would all produce this pattern with nothing
     * wrong. So `high` is not reachable and must not become reachable.
     *
     * What separates the two remaining bands is whether any such mechanism has a
     * HANDLE on the module at all. If nothing in the project imports the
     * defining file, then no namespace object, re-export, or computed lookup can
     * reach the symbol either — the absence is structural rather than merely
     * lexical, and `medium` is warranted. If something does import the file
     * while never naming this symbol, a dynamic reference is possible and the
     * finding drops to `low`, which the default CI gate does not fail on.
     *
     * `fanMetrics` supplies the number rather than a private edge count, so a
     * reader comparing this against any other finding's `fanIn` is reading one
     * definition of it.
     */
    const fan = fanMetrics(structure.filePath, project.graph);
    const confidence: Confidence = (fan.fanIn ?? 0) === 0 ? 'medium' : 'low';

    const securityContext =
      kind === 'authorization'
        ? { containsAuthorizationLogic: true }
        : kind === 'authentication'
          ? { containsAuthLogic: true }
          : { containsValidationLogic: true };

    const role =
      kind === 'sanitizer'
        ? 'sanitizer'
        : kind === 'validator'
          ? 'input validator'
          : kind === 'authentication'
            ? 'authentication guard'
            : 'authorization guard';

    findings.push({
      ruleId: 'VG-SMELL-052',
      title: 'Generated Boilerplate Without Integration',
      description:
        `\`${symbol.name}\` is an exported ${role} whose name appears nowhere else in the ` +
        `scanned project — not at a route registration, not in an import, not as a call. ` +
        `Meanwhile ${open.length} route registration${open.length === 1 ? ' mounts' : 's mount'} ` +
        `no guard at all, and untrusted input reaches \`${flow.sink.name}\` (a ${flow.sink.kind} ` +
        `sink) inside the registered handler \`${flow.symbolName}\`: ` +
        `${describeFlow(flow)}. The protection was written and the request path it was ` +
        `written for is live; the line that joins them is missing.` +
        (injection
          ? ` Reported at ${severity} because the value reaches an injection sink rather than ` +
            `only a response body.`
          : '') +
        (open.length > cited.length
          ? ` ${cited.length} of the ${open.length} unguarded registrations are listed below.`
          : ''),
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      // `project`, not `symbol`: no edit at the definition resolves this. The fix
      // is a line in a different file, at a registration, which is precisely why
      // the smell is invisible to every single-file rule in this repository.
      scope: 'project',
      filePath: symbol.filePath,
      startLine: symbol.startLine,
      endLine: symbol.endLine,
      startColumn: symbol.startColumn,
      evidence: [
        `${symbol.filePath}:${symbol.startLine} ${symbol.name} defined and exported, referenced nowhere`,
        ...cited.map(
          (entry) =>
            `${entry.filePath}:${entry.line} ${entry.route.method.toUpperCase()} ` +
            `${entry.route.path} registered with no guard`,
        ),
        `taint: ${describeFlow(flow)}`,
      ],
      primaryLocation: {
        filePath: symbol.filePath,
        startLine: symbol.startLine,
        endLine: symbol.endLine,
        startColumn: symbol.startColumn,
        evidence: `definition of ${symbol.name}`,
      },
      relatedLocations: [
        ...cited.map((entry) => registrationLocation(entry, symbol.name)),
        {
          filePath: flow.filePath,
          startLine: flow.source.line,
          startColumn: flow.source.column,
          evidence: `untrusted input enters here: ${flow.source.expression}`,
        },
        {
          filePath: flow.filePath,
          startLine: flow.sink.line,
          startColumn: flow.sink.column,
          evidence:
            `and reaches ${flow.sink.name} here without passing through ${symbol.name}: ` +
            flow.sink.expression,
        },
      ],
      /**
       * `fanIn` on the defining file is the measurement the confidence band is
       * derived from, so it travels with the finding rather than being recomputed
       * by a reader who wants to check the band. `symbolMetrics` describes the
       * boilerplate itself — a substantial `loc`/`branchCount` is what separates
       * "somebody wrote a real validator and forgot to mount it" from an empty
       * stub, and a reader triaging the finding wants that number.
       */
      metrics: mergeMetrics(fan, source ? symbolMetrics(symbol, source) : undefined),
      securityContext,
      tags: ['design-smell', 'cross-file', 'ai-prone', 'taint'],
      remediation: {
        why:
          'Generated security code that is never connected is worse than its absence. The ' +
          'validator is in the diff, in the file listing, and in the tests, so every artefact a ' +
          'reviewer looks at says the endpoint is protected — which is exactly what stops anyone ' +
          'from noticing that it is not.',
        how:
          `Apply \`${symbol.name}\` where the requests it was written for arrive — as a route ` +
          'argument, as an `app.use` mount, or as an explicit call at the top of the handler — ' +
          'and confirm the flow above now passes through it. If it is genuinely obsolete, delete ' +
          'it, so the code stops advertising a protection it does not provide.',
        exampleFix:
          `router.post('/comments', ${symbol.name}, createComment);\n` +
          `// the registration is now where the protection is visible, not just where it exists.`,
      },
    });
  }

  return findings;
}

export const generatedBoilerplateUnintegrated: CrossFileRule = {
  ruleId: 'VG-SMELL-052',
  name: 'Generated Boilerplate Without Integration',
  description:
    'A security validator, sanitizer, or guard is exported but referenced nowhere, while ' +
    'unguarded route registrations exist and untrusted input reaches a sink inside a route ' +
    'handler.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  /**
   * TS/JS only, and enforced per file in `analyze` as well as per project by
   * `runCrossFileRules`.
   *
   * Not a placeholder for a wider list. The taint module this rule's firing
   * condition depends on returns `[]` for every language but these two, on the
   * stated grounds that a Python arm needs its own sink table rather than a `||`
   * added to a regex (`SUPPORTED_LANGUAGES` in `../taint/index.ts`). Listing
   * Python here would therefore not make the rule work in Python — it would make
   * it silently never fire there, which is the worst of the three options
   * because it looks like coverage.
   *
   * The C/C++ shape of this same idea is already shipped, separately, as
   * VG-AISC-003; see the header for why the two are not one rule.
   */
  languages: ['typescript', 'javascript'],
  cwe: ['CWE-1188', 'CWE-20'],
  owasp: ['A04:2021 Insecure Design'],
  remediation: {
    why: 'A validator that is never applied leaves the endpoint unprotected while every review artefact says otherwise.',
    how: 'Mount it at the route registration, or delete it.',
  },
  analyze,
};
