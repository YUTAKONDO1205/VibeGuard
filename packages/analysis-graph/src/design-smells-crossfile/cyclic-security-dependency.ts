// VG-SMELL-020 — Cyclic Security Dependency.
//
// WHAT IT CLAIMS
//
// A module that performs authentication, authorization, cryptography or token
// handling sits inside an import CYCLE: it depends, through some chain of
// resolved project imports, on a module that depends back on it. The harm is not
// the tangle as such — plenty of codebases have cycles and survive them — it is
// that a cycle makes module INITIALISATION ORDER a property of which file the
// runtime happened to load first. In CommonJS the second module in the cycle
// receives a partially-populated `exports` object; in ESM the bindings exist but
// are in the temporal dead zone; in Python the second import sees a
// half-executed module. So a top-level `const key = loadSigningKey()` in the
// security module can legitimately read `undefined`, and the failure surfaces as
// "the token verified against a key that was not set yet" rather than as an
// import error. That is a security defect whose cause is a graph property, which
// is exactly the kind of thing this package exists to see.
//
// ★ WHY AN SCC AND NOT A CYCLE
//
// The natural implementation is "enumerate the cycles". It is the wrong one, on
// two independent grounds.
//
// The first is cost: enumerating simple cycles is Johnson's algorithm, whose
// output can be exponential in the number of nodes — a dense component of thirty
// modules has more cycles than anyone will ever read, and a rule that emits one
// finding per cycle would bury a report under a single tangled directory.
//
// The second is IDENTITY, and it is the one that decided this. A cycle written as
// a path has no canonical form: `a → b → c → a`, `b → c → a → b` and
// `c → a → b → c` are the same fact, and which one a traversal produces depends
// on where it started, which depends on iteration order, which — with `Map` and
// `Set` keyed on file paths — depends on insertion order. A finding whose
// identity rotates between runs cannot be baselined, and `stableId` in
// `project.ts` hashes the primary location precisely so that an unchanged finding
// keeps its id. A strongly connected component is a SET, so it has no rotation to
// normalise away; two runs that disagree about traversal order still produce the
// same component. Tarjan's algorithm computes them in O(V+E) with no enumeration
// at all.
//
// The concrete path a reader needs is then recovered separately, as the SHORTEST
// cycle through the module the finding is filed under, found by breadth-first
// search over lexicographically sorted adjacency. That is a canonical rotation by
// construction: the anchor is chosen by sorting, not by traversal.
//
// ★ THE PRECISION CONTRACT — WHY THIS IS NOT A CIRCULAR-DEPENDENCY LINTER
//
// `madge --circular` exists, is better at finding cycles than this is, and is not
// what this rule is. Reporting every cycle as a security finding would be the
// failure mode this project's `samples/safe == 0` gate exists to prevent: an
// ordinary React application has cycles between its component modules and none of
// them is a security problem. So the population is narrowed twice before a cycle
// is even looked at — see `SECURITY_MODULE_WORD` for what counts as a security
// module and why BOTH placement and surface are required — and the edges are
// narrowed as well, to the ones that actually run at module load. Every
// narrowing below is a negative condition with a fixture under
// `samples/crossfile-fixtures/smell-020-*` that must stay silent.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, mergeMetrics } from '../metrics/index.js';
import { type ExportKinds, importsOnlyTypes, isTypeOnlyImport } from './type-erasure.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  ImportEdge,
  ProjectIndex,
  SourceFile,
  StructureIndex,
} from '../types.js';

/**
 * The security vocabulary, and the whole precision story of this rule.
 *
 * ★ SCOPED TO FOUR FAMILIES, FROM THE SPECIFICATION, NOT WIDENED.
 *
 * The implementation plan §5.4 names this rule "Cyclic SECURITY Dependency" and
 * the addendum describes the population as modules handling 認可 / 認証 / 暗号 /
 * トークン — authorization, authentication, cryptography, tokens. Those four
 * families are what is here and nothing else is, because every plausible
 * extension makes the rule worse in the same way:
 *
 *  - `user` / `users`. The most common noun in a REST service. `models/user.ts`
 *    in a cycle with `models/post.ts` is an ORM back-reference, not a security
 *    problem, and admitting `user` would make this rule fire on that shape in
 *    essentially every application that has one.
 *  - `admin`. Names an admin PANEL far more often than an authorization
 *    mechanism, and an admin panel is exactly the kind of feature area whose
 *    components import each other.
 *  - `policy` / `policies`. Retention policy, refund policy, pricing policy. The
 *    security sense is a minority of the uses in ordinary business code.
 *  - `role` / `roles`. VG-SMELL-010 has a MEASURED finding about this word: in
 *    the corpus this project targets, `role` is at least as likely to be an
 *    OpenAI chat-message role as a privilege level, because a codebase that
 *    calls an LLM is a codebase written with LLM help. See `CHAT_ROLE_LITERAL`
 *    in `scattered-authorization.ts`. It is left out here rather than re-fought.
 *  - `validate` / `sanitize`. Real security concepts and the wrong ones for this
 *    rule: a sanitizer holds no load-time state, so a cycle through it does not
 *    produce the "verified with a key that was not set yet" failure this finding
 *    is about. Recall lost there is recall this rule never had a mechanism for.
 *
 * Every entry below is a word that is a security term in more or less all of its
 * uses. `cert`/`certs` are the shortest and were kept after checking that
 * tokenisation makes them whole words — `certain` tokenises to `certain`, not to
 * `cert`, so the substring hazard that `auth` has inside `author` does not arise.
 *
 * ★★ MEASURED CORRECTION — `session`, `token` AND `signature` WERE HERE AND ARE
 * NOT ANY MORE.
 *
 * All three are in the specification's four families and all three were in the
 * first draft. MEASURED 2026-08-02 over the first 100 repositories of
 * `paper_data/corpus1k` (66 of them containing indexable source): the draft
 * produced 6 findings, and the words above accounted for the majority of the
 * wrong ones.
 *
 *   Crosstalk-Solutions/project-nomad  admin/app/models/chat_session.ts
 *                                      ↔ chat_message.ts
 *   D4Vinci/Scrapling                  scrapling/spiders/session.py — an HTTP
 *                                      client session (`requests.Session`)
 *   Gitlawb/openclaude                 src/services/compact/sessionMemoryCompact.ts
 *                                      → …/tokenEstimation.ts → …
 *
 * Not one of them is a security session or a security token. A CHAT session, an
 * HTTP client session, a database session, an LLM context window measured in
 * TOKENS, and a lexer's token stream are all ordinary uses of those two words,
 * and they are CONCENTRATED in the population this project targets: a corpus of
 * AI-adjacent repositories is full of code that counts tokens and stores chat
 * sessions. VG-SMELL-010 discovered the identical collision from the other
 * direction and wrote it up on `CHAT_ROLE_LITERAL`; this is the same fact
 * arriving through the module vocabulary instead of through a property name.
 *
 * `signature` went for a quieter reason: in code the word most often means a
 * FUNCTION signature. `utils/signature.ts` is as likely to be a reflection helper
 * as a verifier.
 *
 * What replaces them is the set of spellings those families have that are NOT
 * ambiguous — `jwt`, `jws`, `jwe`, `oauth`, `oidc`, `saml`, `sso` for tokens;
 * `hmac`, `keystore`, `keychain`, `keyring` for signing material. The token
 * family is therefore still represented, by the names that only ever mean the
 * security thing. The recall cost is real: a project whose module is honestly
 * called `token-service.ts` is no longer in the population. That is the direction
 * this rule accepts losing in, because the alternative measured out as three
 * false positives in sixty-six repositories on a vocabulary of two words.
 */
const SECURITY_MODULE_WORD: ReadonlySet<string> = new Set([
  // authentication / authorization
  'auth',
  'authn',
  'authz',
  'authentication',
  'authenticate',
  'authenticated',
  'authenticator',
  'authorization',
  'authorisation',
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'oauth',
  'oidc',
  'saml',
  'sso',
  'rbac',
  'acl',
  'acls',
  'permission',
  'permissions',
  'guard',
  'guards',
  'csrf',
  'xsrf',
  'security',
  // tokens — only the unambiguous spellings; see the MEASURED CORRECTION above
  'jwt',
  'jws',
  'jwe',
  // cryptography and the material it protects
  'crypto',
  'cryptography',
  'encrypt',
  'encrypted',
  'encryption',
  'decrypt',
  'decryption',
  'cipher',
  'ciphers',
  'hmac',
  'keystore',
  'keychain',
  'keyring',
  'secret',
  'secrets',
  'credential',
  'credentials',
  'password',
  'passwords',
  'passphrase',
  'tls',
  'ssl',
  'mtls',
  'cert',
  'certs',
  'certificate',
  'certificates',
  'x509',
]);

/** Any character that cannot appear inside an identifier word. */
const NON_WORD_CHAR = /[^A-Za-z0-9]/;

/** The camelCase seam: a lowercase or digit immediately followed by a capital. */
const CAMEL_SEAM = /([a-z0-9])([A-Z])/g;

/**
 * Split a path or an identifier into lowercase words.
 *
 * ★ WORD MATCHING, NEVER SUBSTRING MATCHING — the same argument `pathWords` in
 * `scattered-authorization.ts` makes at length, and for the same counterexample:
 * `src/authors/list.ts`, `content/authoring/draft.ts` and `lib/authority.ts` are
 * ordinary directory names that all contain `auth`. A substring test would put
 * every blog and CMS in this rule's population. Segmenting first means `authors`
 * is a word this vocabulary does not contain.
 *
 * This is a third small implementation of that idea (the symbol table has its own
 * `tokenize`, which is private to a module that deliberately never reads file
 * content, and VG-SMELL-010's is private too). Sharing it would mean widening one
 * of those module surfaces to export four lines, and the two existing copies
 * already document why they did not. The property that matters is that all three
 * split the same way, which is asserted here by a test rather than assumed.
 *
 * Neither regex carries a quantifier — a split on a single-character class and
 * one substitution at a two-character seam — so neither can backtrack, and the D3
 * three-second contract holds by construction rather than by measurement.
 */
function moduleWords(text: string): string[] {
  const out: string[] = [];
  for (const chunk of text.split(NON_WORD_CHAR)) {
    if (chunk.length === 0) continue;
    for (const word of chunk.replace(CAMEL_SEAM, '$1 $2').split(' ')) {
      if (word.length > 0) out.push(word.toLowerCase());
    }
  }
  return out;
}

/** Path segments whose contents are fixtures, not the service under review. */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata|examples?|samples?|stories)(?:\/|$)|\.(?:test|spec|stories)\.[\w]+$/i;

/**
 * TypeScript declaration files, excluded as NODES entirely.
 *
 * A `.d.ts` file emits no JavaScript, so a cycle through one cannot have an
 * initialisation order to get wrong. Ambient declaration files reference each
 * other freely and correctly; treating that as a runtime cycle would be reporting
 * a fact about the type system as a fact about the program.
 */
const DECLARATION_FILE = /\.d\.[cm]?ts$/i;

/**
 * ORM and schema DECLARATION directories, excluded as nodes.
 *
 * ★ MEASURED CORRECTION, from the same 100-repository run:
 *
 *   Dokploy/dokploy   packages/server/src/db/schema/certificate.ts
 *                     ↔ packages/server/src/db/schema/server.ts
 *
 * Two Drizzle table definitions that reference each other, because the rows
 * reference each other — a certificate belongs to a server and a server has
 * certificates. Expressing a bidirectional relation as a pair of imports is what
 * every schema-first ORM (Drizzle, TypeORM, Prisma's generated client, SQLAlchemy)
 * tells its users to do, and the modules involved hold table METADATA rather than
 * the runtime security state this rule is about. The word that put
 * `certificate.ts` in the population is a column name.
 *
 * The second finding this kills is `admin/app/models/chat_session.ts`, which was
 * already wrong for a different reason (`session` has since left the vocabulary).
 * Two independent filters catching the same case is not redundancy here: the
 * vocabulary change is about which words mean security, and this is about which
 * FILES can carry initialisation order at all.
 *
 * `migrations` is in the list for the same reason and one more: a migration is
 * historical, so a cycle between two of them describes a schema that no longer
 * exists.
 */
const DECLARATION_PATH =
  /(?:^|\/)(?:models?|entities|schemas?|migrations?)(?:\/|$)/i;

/**
 * View components, excluded as nodes.
 *
 * ★ MEASURED CORRECTION, from the 630-repository run:
 *
 *   henrygd/beszel  internal/site/src/components/login/auth-form.tsx
 *                   ↔ …/components/login/otp-forms.tsx
 *
 * A React login form and an OTP form importing each other. The cycle is real and
 * the file is called `auth-form`, so both halves of the security test pass — and
 * the finding is still wrong, because a view component holds no load-time
 * security state. What a cycle costs here is a component that renders as
 * `undefined`, which is a rendering bug that the first run of the page makes
 * obvious. The mechanism this rule names — a key or an algorithm read at module
 * load before it was assigned — has nothing to attach to in a form.
 *
 * ★ `views`, `pages` AND `ui` ARE DELIBERATELY NOT HERE, and the reason is that
 * the same word means the opposite thing in other stacks: `views.py` is where a
 * Django request handler lives, and `pages/api/auth/[...nextauth].ts` is where a
 * Next.js application puts its actual authentication endpoint. Excluding those
 * would silence the rule on real server code. `components/` is the one segment
 * that means presentation in every framework that uses it.
 *
 * One observation is thin evidence for a filter, and that is stated rather than
 * dressed up: this entry rests on a single repository, plus a general argument
 * about what a component module can and cannot hold.
 */
const VIEW_COMPONENT_PATH = /(?:^|\/)components?(?:\/|$)/i;

/**
 * Import syntaxes that create a LOAD-TIME dependency.
 *
 * ★ `quoted` AND `angled` — THE C `#include` FORMS — ARE DELIBERATELY ABSENT.
 *
 * C header cycles are ubiquitous, expected, and harmless: `#pragma once` and
 * include guards make a mutually-including pair of headers compile exactly once
 * each, and a translation unit has no per-header initialisation order to
 * indeterminate in the first place. Reporting them would mean firing on
 * essentially every embedded project this analyser has ever been pointed at,
 * every one of them a false positive, and it would drown the arm of the catalogue
 * (`VG-AISC-003`, `VG-EMB-*`) that does have something true to say about firmware.
 *
 * What is left — ESM, CommonJS `require`, and Python `import` — are the three
 * forms where a cycle really does hand the second module a partially initialised
 * first one. That is the mechanism this finding names, so it is the only set of
 * edges allowed to establish one.
 */
const RUNTIME_SYNTAX: ReadonlySet<ImportEdge['syntax']> = new Set(['esm', 'require', 'python']);


/**
 * Python's `if TYPE_CHECKING:` — the same erasure as `import type`, written in
 * the one language where the compiler cannot do it for you.
 *
 * ★★ MEASURED CORRECTION. This function exists because of a false positive, and
 * the false positive was the FIRST finding the draft produced on
 * `paper_data/corpus1k`:
 *
 *   9001/copyparty   copyparty/cert.py → util.py → broker_util.py → svchub.py
 *                    → copyparty/cert.py
 *
 * `cert.py` really is a TLS certificate module and the four edges really are in
 * the index. Two of them are inside `if TYPE_CHECKING:` blocks:
 *
 *   util.py:257        if TYPE_CHECKING:
 *   util.py:259            from .broker_util import BrokerCli
 *   broker_util.py:17  if TYPE_CHECKING:
 *   broker_util.py:19      from .svchub import SvcHub
 *
 * `typing.TYPE_CHECKING` is `False` at run time, so neither import ever executes.
 * The cycle does not exist in the running program — and worse, this is the
 * DOCUMENTED Python remedy for a circular import, the exact idiom PEP 484
 * recommends. Reporting it means telling a project that applied the fix that it
 * has the defect, which is the failure mode that got VG-SMELL-041 withdrawn.
 *
 * The test walks up the enclosing blocks by indentation rather than checking only
 * the immediately preceding line, so an import nested inside a `try:` inside the
 * guard is still recognised. It gives up at column zero, which is the only place
 * an unguarded module-level import can be.
 */
const PY_TYPE_CHECKING =
  /^[^\S\r\n]{0,200}(?:el)?if[^\S\r\n]{1,4}(?:typing[^\S\r\n]{0,2}\.[^\S\r\n]{0,2})?TYPE_CHECKING[^\S\r\n]{0,4}:/;

/** Width of a line's leading whitespace, in characters. */
function indentWidth(line: string): number {
  let n = 0;
  while (n < line.length && (line[n] === ' ' || line[n] === '\t')) n += 1;
  return n;
}

function isTypeCheckingGuarded(edge: ImportEdge, file: SourceFile): boolean {
  if (edge.syntax !== 'python') return false;
  const own = file.lines[edge.line - 1];
  if (own === undefined) return false;
  let level = indentWidth(own);
  // Column zero is module scope: there is no enclosing block to be guarded by.
  if (level === 0) return false;

  for (let i = edge.line - 2; i >= 0; i -= 1) {
    const line = file.lines[i]!;
    if (line.trim() === '' || line.trimStart().startsWith('#')) continue;
    const width = indentWidth(line);
    if (width >= level) continue;
    if (PY_TYPE_CHECKING.test(line)) return true;
    level = width;
    if (level === 0) return false;
  }
  return false;
}

/**
 * Offsets at which each 1-based line begins.
 *
 * Recomputed here rather than carried on `SourceFile` because `SourceFile.lines`
 * already exists and is what the rest of the package uses; adding a parallel
 * array to a shared type for one rule's convenience is how shared types rot.
 */
function lineStartsOf(file: SourceFile): number[] {
  const starts: number[] = [0];
  for (let i = 0; i < file.content.length; i += 1) {
    if (file.content[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/**
 * Whether an import statement sits inside a function body.
 *
 * ★ THE LAZY `require` IS THE STANDARD FIX FOR A CYCLE, NOT AN INSTANCE OF ONE.
 *
 *     function verify(token) {
 *       const { getKey } = require('./keystore');   // deferred on purpose
 *       ...
 *     }
 *
 * Moving a `require` inside the function that needs it is the documented Node
 * remedy for a circular dependency: by the time the call happens both modules
 * have finished loading, so the partially-initialised-exports hazard — the entire
 * mechanism this finding names — is gone. Counting it would mean reporting the
 * repair as the defect, which is the mistake VG-SMELL-041 was withdrawn for in
 * the previous wave and the one this rule is written in the shadow of.
 *
 * The same applies to a Python `import` written inside a function, which is that
 * language's version of the identical workaround.
 *
 * ESM `import` declarations are hoisted and can only appear at the top level, so
 * this test can never exclude one — it is applied uniformly anyway rather than
 * special-cased by syntax, because a filter that is a no-op for one input class
 * costs nothing and a special case invites the next reader to wonder which
 * syntaxes it covers.
 */
function isDeferredImport(edge: ImportEdge, structure: StructureIndex, file: SourceFile): boolean {
  const starts = lineStartsOf(file);
  const offset = starts[edge.line - 1];
  if (offset === undefined) return false;
  for (const symbol of structure.symbols) {
    if (symbol.kind === 'class') continue;
    if (offset >= symbol.bodyStart && offset < symbol.bodyEnd) return true;
  }
  return false;
}

/**
 * Maximum number of strongly connected components examined.
 *
 * Tarjan itself is linear and needs no cap; the per-component work does. Each
 * component costs a breadth-first search per candidate security module, and a
 * repository that is one giant tangle could hold hundreds of components with
 * security modules in them. The cap is a work bound, not a findings bound: hitting
 * it means the analysis stopped looking, and it says so through the degradation
 * channel rather than returning a short list that reads as a clean one.
 */
const MAX_COMPONENTS = 200;

/**
 * Maximum length of the cycle path written into a finding.
 *
 * A cycle of forty modules is a true statement nobody can act on. The finding
 * still reports the component's real size in prose; what is truncated is only the
 * illustrative path, and the truncation is stated in the evidence rather than
 * silently applied.
 */
const MAX_PATH_SHOWN = 12;

/**
 * Which of the three families a security word belongs to.
 *
 * Exists so the finding's `securityContext` is DERIVED rather than asserted. The
 * lazy version sets `containsAuthorizationLogic: true` on every finding, which
 * would be a claim the rule did not make about `crypto/cipher.ts` — a module that
 * encrypts and decides nothing. The schema's flags describe what a finding's code
 * CONTAINS, and the only thing this rule knows about the module's contents is
 * which words its path and its exports are made of, so that is what the flags are
 * computed from. Words that belong to no family (`security`, `guards`) set none
 * of them, which is the honest answer: they say the module is security-relevant
 * without saying which mechanism it implements.
 */
const WORD_FAMILY: ReadonlyMap<string, 'authorization' | 'token' | 'crypto'> = new Map([
  ...(['auth', 'authn', 'authz', 'authentication', 'authenticate', 'authenticated',
    'authenticator', 'authorization', 'authorisation', 'authorize', 'authorise',
    'authorized', 'authorised', 'oauth', 'oidc', 'saml', 'sso', 'rbac', 'acl', 'acls',
    'permission', 'permissions', 'csrf', 'xsrf'] as const).map(
    (w) => [w, 'authorization'] as const,
  ),
  ...(['jwt', 'jws', 'jwe'] as const).map((w) => [w, 'token'] as const),
  ...(['crypto', 'cryptography', 'encrypt', 'encrypted', 'encryption', 'decrypt',
    'decryption', 'cipher', 'ciphers', 'hmac', 'keystore',
    'keychain', 'keyring', 'secret', 'secrets', 'credential', 'credentials', 'password',
    'passwords', 'passphrase', 'tls', 'ssl', 'mtls', 'cert', 'certs', 'certificate',
    'certificates', 'x509'] as const).map((w) => [w, 'crypto'] as const),
]);

/** One module the rule is willing to build a finding around. */
interface SecurityModule {
  filePath: string;
  /** Path words that put the module in the security vocabulary. */
  placement: string[];
  /** Declared or exported names carrying a security word, sorted, capped. */
  surface: string[];
  /** Every security word seen, in path or surface — the input to the flags. */
  words: string[];
}

/**
 * Whether a module is SECURITY-RELEVANT, and why both halves are required.
 *
 * ★ PLACEMENT **AND** SURFACE. Either one alone is a name; together they are a
 * module.
 *
 * Placement alone — "the file is under `auth/`" — admits `auth/types.ts`,
 * `auth/constants.ts`, and `auth/index.ts`, which are the files most likely to be
 * in a cycle and least likely to hold a key. That is the worst possible bias for
 * this rule: it would concentrate findings on exactly the members of a security
 * directory that have no load-time state.
 *
 * Surface alone — "the file declares something called `verifyToken`" — admits any
 * module that happens to touch a security concept in passing, which in a service
 * of any size is most of them.
 *
 * Requiring both asks two independent questions: what is this module FOR (its
 * placement in the tree, which is a human's declaration of intent) and what does
 * it DO (the names it declares and exports). A module that answers "security" to
 * both is one where a load-order defect has something to damage.
 *
 * `exportedNames` is consulted alongside the indexed symbols, and that is not
 * redundancy. A module whose entire security surface is
 * `export const SIGNING_KEY = process.env.KEY` declares no SYMBOL — the indexer
 * records functions, methods and classes — yet a constant initialised at module
 * load is the purest form of the hazard this rule is about. The export list is
 * where that module is visible.
 */
function securityModule(structure: StructureIndex): SecurityModule | undefined {
  const placement = moduleWords(structure.filePath).filter((w) => SECURITY_MODULE_WORD.has(w));
  if (placement.length === 0) return undefined;

  const names = new Set<string>();
  const words = new Set<string>(placement);
  const consider = (name: string): void => {
    let matched = false;
    for (const word of moduleWords(name)) {
      if (!SECURITY_MODULE_WORD.has(word)) continue;
      words.add(word);
      matched = true;
    }
    if (matched) names.add(name);
  };
  for (const symbol of structure.symbols) consider(symbol.name);
  for (const name of structure.exportedNames) consider(name);
  if (names.size === 0) return undefined;

  return {
    filePath: structure.filePath,
    // Deduplicated and sorted: `placement` goes into a finding's prose, and a
    // path with `auth` twice would print it twice in an order decided by the
    // path's own spelling.
    placement: [...new Set(placement)].sort(),
    surface: [...names].sort().slice(0, 5),
    words: [...words].sort(),
  };
}

/** The runtime import graph: node → sorted successors, plus the edge that made each. */
interface RuntimeGraph {
  nodes: string[];
  successors: Map<string, string[]>;
  /** `from\0to` → the earliest import statement carrying that dependency. */
  edgeOf: Map<string, ImportEdge>;
}

/**
 * Build the subgraph of edges that exist when the program RUNS.
 *
 * Everything the rule excludes is excluded here rather than at reporting time, so
 * a component that only exists because of an erased import is never formed in the
 * first place. Deciding after the fact — form all components, then check whether
 * each one survives the filters — would be both slower and wrong: an SCC computed
 * over type-only edges can merge two genuinely separate value cycles into one
 * component, and no post-hoc filter can split them again.
 */
function buildRuntimeGraph(project: ProjectIndex): RuntimeGraph {
  const filesByPath = new Map(project.files.map((f) => [f.filePath, f]));
  // Sorted key iteration. `Map` iteration order is insertion order, which is
  // directory-walk order, which is not a promise this package makes.
  //
  // ★ REDUNDANT FOR THE RESULT, and a mutation pass proved it: `graph.nodes` is
  // sorted independently below, and everything built in this loop is keyed by
  // path rather than positional, so the order this walk happens in changes
  // nothing observable. It stays because "the graph is built in path order" is
  // the property a reader needs in order to trust the traversal, and because the
  // redundancy holds only while the loop body stays order-free.
  const paths = [...project.structures.keys()].sort();

  const admitted = new Set<string>();
  for (const path of paths) {
    if (TEST_PATH.test(path)) continue;
    if (DECLARATION_FILE.test(path)) continue;
    if (DECLARATION_PATH.test(path)) continue;
    if (VIEW_COMPONENT_PATH.test(path)) continue;
    admitted.add(path);
  }

  const successors = new Map<string, string[]>();
  const edgeOf = new Map<string, ImportEdge>();
  const exportCache = new Map<string, ExportKinds>();

  for (const path of paths) {
    if (!admitted.has(path)) continue;
    const structure = project.structures.get(path)!;
    const file = filesByPath.get(path);
    const seen = new Set<string>();
    const out: string[] = [];

    for (const edge of structure.imports) {
      if (!RUNTIME_SYNTAX.has(edge.syntax)) continue;
      // No `resolvedFile` means the specifier points outside the project (a
      // package, a system header, a path the lexical resolver could not follow).
      // A cycle through a node the analysis cannot see is a cycle the analysis
      // cannot claim.
      const target = edge.resolvedFile;
      if (target === undefined) continue;
      // A self-import is deliberately NOT filtered here. It cannot produce a
      // finding — `stronglyConnectedComponents` drops components of size one and
      // `shortestCycleThrough` refuses to leave its own start node — so a guard
      // for it would be a line no test could ever make fail, which is the kind of
      // line that rots. The invariant is stated where it holds instead.
      // ★ NOT INDEPENDENTLY OBSERVABLE, and recorded as such after a mutation
      // pass. Removing this line leaves every test green: a non-admitted file is
      // skipped by the outer loop too, so it has no successor list, so Tarjan
      // finds it in a component of one and drops it. The line is kept because it
      // states the invariant at the point it holds — `successors` and `edgeOf`
      // only ever mention admitted files — and because the argument above is a
      // property of the CURRENT loop structure rather than of the algorithm.
      if (!admitted.has(target)) continue;
      if (file !== undefined) {
        const lineText = file.lines[edge.line - 1] ?? '';
        if (isTypeOnlyImport(lineText)) continue;
        if (isTypeCheckingGuarded(edge, file)) continue;
        if (isDeferredImport(edge, structure, file)) continue;
      }
      const targetStructure = project.structures.get(target);
      if (targetStructure && importsOnlyTypes(edge, targetStructure, exportCache)) continue;
      const key = `${path}\0${target}`;
      if (!edgeOf.has(key)) edgeOf.set(key, edge);
      if (seen.has(target)) continue;
      seen.add(target);
      out.push(target);
    }

    out.sort();
    successors.set(path, out);
  }

  return { nodes: [...admitted].sort(), successors, edgeOf };
}

/**
 * Tarjan's strongly connected components, ITERATIVE.
 *
 * The recursive formulation is shorter and is not usable here. Import chains in a
 * real repository run hundreds of files deep — a barrel importing a barrel
 * importing a feature module is the normal shape — and the recursion depth of
 * this algorithm is the depth of the DFS tree, so the textbook version can
 * overflow the JavaScript stack on an ordinary monorepo. A rule that throws is
 * caught by `runCrossFileRules` and reported as a degradation, which is honest
 * but useless; not throwing is better.
 *
 * Only components of size two or more are returned. A single node is an SCC of
 * every graph, and a self-loop cannot occur because `buildDependencyGraph` never
 * records an edge from a file to itself and `buildRuntimeGraph` drops it again.
 * So "size ≥ 2" is exactly "there is a cycle here".
 *
 * Members are sorted within a component and components are sorted by their first
 * member, which is what makes the result a canonical object rather than a
 * traversal artefact.
 */
function stronglyConnectedComponents(graph: RuntimeGraph): string[][] {
  const index = new Map<string, number>();
  const low = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const out: string[][] = [];
  let counter = 0;

  for (const root of graph.nodes) {
    if (index.has(root)) continue;
    index.set(root, counter);
    low.set(root, counter);
    counter += 1;
    stack.push(root);
    onStack.add(root);
    const work: { node: string; next: number }[] = [{ node: root, next: 0 }];

    while (work.length > 0) {
      const frame = work[work.length - 1]!;
      const succ = graph.successors.get(frame.node) ?? [];
      if (frame.next < succ.length) {
        const child = succ[frame.next]!;
        frame.next += 1;
        if (!index.has(child)) {
          index.set(child, counter);
          low.set(child, counter);
          counter += 1;
          stack.push(child);
          onStack.add(child);
          work.push({ node: child, next: 0 });
        } else if (onStack.has(child)) {
          low.set(frame.node, Math.min(low.get(frame.node)!, index.get(child)!));
        }
        continue;
      }

      work.pop();
      if (low.get(frame.node) === index.get(frame.node)) {
        const component: string[] = [];
        for (;;) {
          const popped = stack.pop()!;
          onStack.delete(popped);
          component.push(popped);
          if (popped === frame.node) break;
        }
        if (component.length > 1) out.push(component.sort());
      }
      const parent = work[work.length - 1];
      if (parent) {
        low.set(parent.node, Math.min(low.get(parent.node)!, low.get(frame.node)!));
      }
    }
  }

  out.sort((a, b) => (a[0]! < b[0]! ? -1 : a[0]! > b[0]! ? 1 : 0));
  return out;
}

/**
 * The shortest cycle starting and ending at `start`, staying inside `component`.
 *
 * Returned as the node sequence `[start, …, last]`, where `last → start` closes
 * it; the closing edge is left implicit so the path has no repeated element.
 *
 * BREADTH-FIRST, over successor lists that were sorted when the graph was built.
 * Both properties are load-bearing. Breadth-first gives the SHORTEST cycle, which
 * is the one a reader can actually follow and — more usefully — the one least
 * likely to be an artefact of an unrelated module happening to sit in the same
 * component. Sorted adjacency makes the tie-break between two cycles of equal
 * length lexicographic rather than insertion-ordered, so the illustrated path is
 * a function of the graph and not of how it was walked.
 *
 * `start` is chosen by the caller as the lexicographically first security module
 * in the component, which is the canonical rotation this file's header promises:
 * the anchor comes from sorting the component's members, never from where a
 * traversal happened to enter it.
 *
 * A component of size ≥ 2 always contains a cycle through every one of its
 * members, so the empty return is unreachable for the inputs this rule produces.
 * It is still written, because "unreachable" is a claim about the caller and this
 * function does not get to assume it.
 */
function shortestCycleThrough(
  start: string,
  graph: RuntimeGraph,
  component: ReadonlySet<string>,
): string[] {
  const previous = new Map<string, string>();
  const queue: string[] = [];
  const seen = new Set<string>([start]);

  for (const first of graph.successors.get(start) ?? []) {
    if (!component.has(first) || seen.has(first)) continue;
    seen.add(first);
    previous.set(first, start);
    queue.push(first);
  }

  for (let head = 0; head < queue.length; head += 1) {
    const node = queue[head]!;
    for (const next of graph.successors.get(node) ?? []) {
      // ★ A WORK BOUND, NOT A CORRECTNESS CONDITION — and a mutation pass says so:
      // deleting it leaves every test green. Anything reachable from `start` that
      // is NOT in the component cannot reach `start` back (that is what being
      // outside the component means), so no path through it ever closes a cycle.
      // What the test buys is a bound: without it the search fans out across the
      // whole reachable graph on every call instead of staying inside a component.
      if (!component.has(next)) continue;
      if (next === start) {
        const path: string[] = [];
        for (let cursor: string | undefined = node; cursor !== undefined; cursor = previous.get(cursor)) {
          path.push(cursor);
          if (cursor === start) break;
        }
        return path.reverse();
      }
      if (seen.has(next)) continue;
      seen.add(next);
      previous.set(next, node);
      queue.push(next);
    }
  }

  return [];
}

/**
 * Every cycle in the RUNTIME subgraph, before the security vocabulary is applied.
 *
 * ★ EXPORTED SO THAT SILENCE CAN BE EARNED RATHER THAN ASSUMED.
 *
 * A negative fixture that asserts `findings === []` proves nothing on its own: an
 * empty directory passes it, and so does a fixture that decayed into one after a
 * rename. This repository has already had to reject that vacuous pass once, and
 * `temporal-security-coupling.test.ts` documents the discipline that replaced it
 * — every negative states its PREMISE before it states the silence.
 *
 * For this rule the premise splits in two, and both halves need a witness:
 *
 *  - "there is a cycle here, and it is not reported because the modules are not
 *    security modules" — asserted with this function, which must return a
 *    non-empty list.
 *  - "these ARE security modules, and nothing is reported because there is no
 *    cycle" — asserted with `securityModulesIn` below, together with this
 *    function returning an EMPTY list.
 *
 * Without both, a fixture that lost its cycle and a fixture that lost its
 * security module are indistinguishable from a fixture that is working.
 */
export function runtimeCycles(project: ProjectIndex): string[][] {
  return stronglyConnectedComponents(buildRuntimeGraph(project));
}

/** Every module the security vocabulary admits, sorted. See `runtimeCycles`. */
export function securityModulesIn(project: ProjectIndex): string[] {
  const out: string[] = [];
  for (const path of [...project.structures.keys()].sort()) {
    if (securityModule(project.structures.get(path)!)) out.push(path);
  }
  return out;
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project, budget } = ctx;
  // ★ Redundant for the RESULT and not for the COST. The per-component check
  // below already stops an expired scan before any finding is built, so a
  // mutation pass finds no test that this line changes — but without it an
  // already-expired budget still pays for a full graph build and a Tarjan pass
  // over the whole project before discovering it had no time.
  if (budget.expired()) return [];

  const graph = buildRuntimeGraph(project);
  if (graph.nodes.length === 0) return [];

  const components = stronglyConnectedComponents(graph);
  if (components.length === 0) return [];

  if (components.length > MAX_COMPONENTS) {
    // Loud, not silent. A truncated search that returns a short list is
    // indistinguishable from a clean project, and `budget.ts` states that the
    // partial result which looks clean is the worse of the two failures.
    budget.report({
      kind: 'graph-deadline',
      detail:
        `VG-SMELL-020 examined the first ${MAX_COMPONENTS} of ${components.length} import cycles ` +
        `(sorted by path) and stopped. Results are PARTIAL: a cyclic security dependency in the ` +
        `remaining cycles was not reported.`,
    });
  }

  const findings: CrossFileFinding[] = [];
  const examined = components.slice(0, MAX_COMPONENTS);

  for (const component of examined) {
    // Between components, not inside one: a component that has started should
    // finish, so a half-built finding never reaches a report.
    if (budget.expired()) break;
    const finding = findingForComponent(component, graph, project);
    if (finding) findings.push(finding);
  }

  return findings;
}

/**
 * One strongly-connected component of the runtime import graph, turned into a
 * finding — or `null` when it is not one.
 *
 * ★ WHY THIS IS A SEPARATE FUNCTION. It was the body of `analyze`'s loop, and
 * `analyze` was 214 lines deep enough to trip this project's own VG-SMELL-003.
 * Splitting it is the remedy that rule recommends, applied to the rule's own
 * source: a long body is where an unwritten branch hides, and a detector that
 * exempts itself from its own advice is making an argument it does not believe.
 *
 * The seam is chosen so the split cannot change a verdict. Every `continue` in
 * the original loop body was a decision about THIS component alone and becomes
 * `return null`; nothing accumulated across components was read here; the budget
 * check stays in the caller, because it is a decision about whether to start a
 * component rather than about the component itself.
 */
function findingForComponent(
  component: string[],
  graph: RuntimeGraph,
  project: ProjectIndex,
): CrossFileFinding | null {
    const members = new Set(component);
    const secure: SecurityModule[] = [];
    for (const member of component) {
      const memberStructure = project.structures.get(member);
      if (!memberStructure) continue;
      const found = securityModule(memberStructure);
      if (found) secure.push(found);
    }
    if (secure.length === 0) return null;

    // `component` is sorted, and `secure` was filled in that order, so the first
    // element is the lexicographically first security module — the canonical
    // anchor, chosen by sorting rather than by traversal.
    const primary = secure[0]!;
    const cycle = shortestCycleThrough(primary.filePath, graph, members);
    // ★ UNREACHABLE FOR THIS CALLER, and a mutation pass confirms no test
    // distinguishes it: a component of size ≥ 2 contains a cycle through every
    // member. It is written because `shortestCycleThrough` documents an empty
    // return and a caller that assumes an invariant without checking it is how a
    // later refactor turns a changed precondition into an out-of-bounds read.
    if (cycle.length < 2) return null;

    const shown = cycle.slice(0, MAX_PATH_SHOWN);
    const truncated = cycle.length > shown.length;

    /** The import statement carrying each step of the illustrated cycle. */
    const steps: { from: string; to: string; edge: ImportEdge }[] = [];
    for (let i = 0; i < cycle.length; i += 1) {
      const from = cycle[i]!;
      const to = cycle[(i + 1) % cycle.length]!;
      const edge = graph.edgeOf.get(`${from}\0${to}`);
      if (edge) steps.push({ from, to, edge });
    }
    // Every step of a cycle that BFS just walked has an edge by construction, so
    // a short list means `successors` and `edgeOf` disagree — a broken invariant,
    // not a project shape. Report nothing rather than a cycle whose cited lines
    // do not spell out the cycle. ★ Unreachable today and recorded as such: a
    // mutation pass finds no test that this line changes.
    if (steps.length !== cycle.length) return null;

    const primaryStep = steps[0]!;
    const securityOnPath = cycle.filter((p) => secure.some((s) => s.filePath === p));
    const onPathWords = new Set(
      secure.filter((s) => members.has(s.filePath) && cycle.includes(s.filePath)).flatMap((s) => s.words),
    );

    /**
     * `high` when the illustrated cycle runs through TWO OR MORE security
     * modules, `medium` otherwise.
     *
     * The distinction is a difference in what is indeterminate. One security
     * module tangled with application code means the security module's own
     * load-time state may not be ready when the application reaches it — bad, and
     * bounded by the fact that the application module is not itself making a
     * security decision. Two security modules that depend on each other means the
     * ORDER WITHIN the security subsystem is undefined: which of the key store
     * and the token verifier initialises first is decided by whichever the
     * runtime happened to reach, and that is the shape where "verified against a
     * key that was not set yet" actually happens.
     *
     * Keyed to the ILLUSTRATED cycle rather than to the whole component, because
     * the illustrated cycle is the evidence the finding shows. A severity that
     * came from modules outside the cited path would be a claim the reader cannot
     * check against what is in front of them.
     */
    const severity: Severity = securityOnPath.length >= 2 ? 'high' : 'medium';

    /**
     * `medium`, capped, and it stays capped.
     *
     * The CYCLE is a hard structural fact — resolved project imports only, no
     * guessing. What is inferred is the other half of the claim: that these
     * modules are security modules, which is read off their path words and their
     * declared names. That is nominal evidence, exactly the kind `SymbolRole` in
     * `types.ts` says is "as reliable as the naming discipline of the codebase",
     * and no amount of cycle length makes it stronger. `high` would claim the
     * naming inference had become a fact. Same posture as VG-AISC-003, and for
     * the same reason.
     */
    const confidence: Confidence = 'medium';

    const arrow = [...shown, truncated ? '…' : shown[0]!].join(' → ');
    const structure = project.structures.get(primary.filePath);

    const relatedLocations: CodeLocation[] = steps.slice(1, MAX_PATH_SHOWN).map((step) => ({
      filePath: step.from,
      startLine: step.edge.line,
      evidence: `imports '${step.edge.specifier}' → ${step.to}`,
    }));

    return {
      ruleId: 'VG-SMELL-020',
      title: 'Cyclic Security Dependency',
      description:
        `\`${primary.filePath}\` handles security (${primary.placement.join(', ')} by placement; ` +
        `declares ${primary.surface.map((n) => `\`${n}\``).join(', ')}) and sits inside an import ` +
        `cycle: ${arrow}. Module initialisation order inside a cycle is decided by which file the ` +
        `runtime loads first, so a value this module computes at load time — a signing key, a ` +
        `configured algorithm, a policy table — can be read by another member of the cycle before ` +
        `it exists. The failure does not look like an import error; it looks like a token that ` +
        `verified against an undefined key.` +
        (securityOnPath.length >= 2
          ? ` ${securityOnPath.length} of the modules on this cycle are security modules, so the ` +
            `order WITHIN the security subsystem is what is undefined.`
          : '') +
        (component.length > cycle.length
          ? ` The cycle shown is the shortest through this module; ${component.length} modules in ` +
            `total are mutually dependent here.`
          : '') +
        (truncated ? ` The path is truncated at ${MAX_PATH_SHOWN} modules.` : ''),
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      scope: 'module',
      filePath: primaryStep.from,
      startLine: primaryStep.edge.line,
      evidence: steps
        .slice(0, MAX_PATH_SHOWN)
        .map((step) => `${step.from}:${step.edge.line} imports '${step.edge.specifier}' → ${step.to}`),
      primaryLocation: {
        filePath: primaryStep.from,
        startLine: primaryStep.edge.line,
        evidence: `imports '${primaryStep.edge.specifier}' → ${primaryStep.to}, which depends back on this module`,
      },
      relatedLocations,
      /**
       * `fanIn`/`fanOut` come from `metrics-calculator` rather than being counted
       * from the runtime subgraph this rule just built, and the difference is the
       * point: a reader comparing this finding with a VG-SMELL-010 finding must be
       * reading ONE definition of fan-in. This rule's own subgraph is narrower
       * (runtime edges, non-test files) and reporting its numbers under the shared
       * names would make two findings in one report disagree about a quantity they
       * both call `fanOut`.
       *
       * `importCount` is this rule's own measurement and is the statement count,
       * including the imports the subgraph dropped — which is what makes the pair
       * informative: `importCount` well above `fanOut` says most of this module's
       * dependencies leave the project.
       */
      metrics: mergeMetrics(fanMetrics(primary.filePath, project.graph), {
        importCount: structure ? structure.imports.length : 0,
      }),
      securityContext: {
        // Derived from the words actually seen on the cited cycle. See
        // `WORD_FAMILY` for why this is not a constant `true`.
        ...([...onPathWords].some((w) => WORD_FAMILY.get(w) === 'authorization')
          ? { containsAuthorizationLogic: true }
          : {}),
        ...([...onPathWords].some((w) => WORD_FAMILY.get(w) === 'token')
          ? { containsTokenLogic: true }
          : {}),
        ...([...onPathWords].some((w) => WORD_FAMILY.get(w) === 'crypto')
          ? { containsCryptoLogic: true }
          : {}),
      },
      tags: ['design-smell', 'cross-file', 'dependency-cycle'],
      remediation: {
        why:
          'A security module inside an import cycle has no defined initialisation order. Whichever ' +
          'member the runtime loads first sees the others half-built, so a key, an algorithm ' +
          'choice, or a policy read at module load can be undefined at the moment it is used — ' +
          'and the resulting check fails open rather than throwing.',
        how:
          'Break the cycle at the security module. Move the shared types or constants into a leaf ' +
          'module both sides import, invert the dependency so the security module is imported and ' +
          'imports nothing back, or — if the dependency is genuinely needed only at call time — ' +
          'defer it into the function that uses it so it resolves after both modules have loaded.',
        exampleFix:
          `// ${primaryStep.from}\n` +
          `// before: import { thing } from '${primaryStep.edge.specifier}'  // ${primaryStep.to} imports this file back\n` +
          '// after:  move `thing` into a leaf module that both files import, so neither depends on the other.',
      },
    };
}

/**
 * ★ WHY THERE IS NO "IGNORE CYCLES THE BUNDLER ALREADY HANDLES" OPTION.
 *
 * Webpack, Vite and esbuild all tolerate cycles, and it is tempting to conclude
 * that a bundled application is exempt. It is not: tolerating a cycle means
 * emitting code that runs in SOME order, not in a defined one, and the order a
 * bundler picks is a function of its module graph traversal — which changes with
 * the bundler version, with the entry point, and with code splitting. A cycle
 * that works today because the chunker happened to place the key store first is a
 * cycle that breaks on an unrelated refactor. The finding is about the absence of
 * a guarantee, and no bundler supplies one.
 */
export const cyclicSecurityDependency: CrossFileRule = {
  ruleId: 'VG-SMELL-020',
  name: 'Cyclic Security Dependency',
  description:
    'An authentication, authorization, cryptography or token module participates in an import ' +
    'cycle, so its load-time initialisation order relative to the rest of the cycle is undefined.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  /**
   * The three languages whose module systems have the failure mode.
   *
   * C/C++ are absent although the indexer produces `#include` edges for them: see
   * `RUNTIME_SYNTAX`. Python is present, unlike in VG-SMELL-010, and the reason
   * the two differ is worth stating. VG-SMELL-010 dropped Python because its
   * negative conditions were framework-specific (a Flask decorator, a FastAPI
   * `Depends`) and none of them were implemented for Python, so the rule could not
   * be shown to stay silent on well-factored Python. Nothing here is
   * framework-specific: a cycle is a cycle, `import` inside a function is the same
   * workaround in both languages, and the security vocabulary reads path words and
   * declared names identically. The negative fixtures include Python for that
   * reason rather than on the assumption that it generalises.
   */
  languages: ['typescript', 'javascript', 'python'],
  cwe: ['CWE-665', 'CWE-1047'],
  owasp: ['A05:2021 Security Misconfiguration'],
  remediation: {
    why: 'A cycle makes the security module’s initialisation order undefined.',
    how: 'Break the cycle at the security module, or defer the import into the function that uses it.',
  },
  analyze,
};
