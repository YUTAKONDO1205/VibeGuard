// symbol-table-builder — "what do the identifiers in this project mean?"
// (design addendum §8.2, the third of the four submodules behind `ProjectIndex`).
//
// WHAT THIS MODULE IS ALLOWED TO CLAIM
//
// Nothing here reads code. It reads NAMES: the symbols the structure-indexer
// found, the bindings the imports named, and the identifiers that appeared in a
// pre-handler argument position. From those it produces two very different kinds
// of statement, and keeping them apart is the entire design of this file:
//
//   `roles`  — a GUESS from the identifier text. `hasRole` probably concerns a
//              role; `accessToken` probably concerns a token. Nothing observed
//              the program doing anything. See the doc comment on `SymbolRole`
//              in ../types.ts: this feeds confidence and candidate exclusion and
//              is never on its own the reason a finding fires.
//   `guards` — a judgement that a particular (file, name) pair refers to an
//              authorization CHECKPOINT. Two of the three ways in are still name
//              shapes, but the third — "this name was used as route middleware
//              somewhere in the project" — is observed behaviour.
//
// WHY NAME INFERENCE IS WORTH DOING AT ALL
//
// It looks like the weakest possible evidence, and in a hand-written legacy
// codebase it would be. The target of this product is AI-generated code, where
// naming is conventional almost to a fault: a generated Express app calls its
// guard `requireAuth`, its request `req`, and its token `accessToken`, because
// that is what the training distribution overwhelmingly contains. The signal is
// strong precisely in the population the tool is aimed at, and it degrades
// gracefully — a project with idiosyncratic naming yields fewer roles, which
// lowers confidence and suppresses candidates rather than inventing findings.
//
// WHY NOT AN AST / TYPE-BASED ANSWER INSTEAD
//
// Because the honest version of that question ("is this value the authenticated
// principal") needs types, cross-module resolution, and framework knowledge, and
// the package constraint (see ../index.ts) forbids the dependency that would buy
// the first two — and even a full type checker would not tell you that
// `requireAdmin` is an authorization boundary rather than a function returning
// void. The name is the only place that intent is written down. So this module
// commits to the lexical answer and to being loud about what it therefore is.
//
// WHY NO TEXT-SCANNING PRIMITIVES ARE IMPORTED HERE
//
// `@vibeguard/rules` exports the blanking / block-extraction / deadline helpers
// that every lexical rule in this repository reuses, and deliberately none of
// them are used below: this module never touches file CONTENT. Its input is
// already-extracted identifiers, so there is no string to blank, no block to
// balance, and no regex run over untrusted length to bound (`REGEX_INPUT_CAP`'s
// job is done here by `NAME_LENGTH_CAP`, which is four orders of magnitude
// smaller because an identifier is not a file). Importing them "for consistency"
// would add a package boundary crossing that buys nothing.

import type { StructureIndex, SymbolRole, SymbolTable } from '../types.js';

/**
 * Maximum identifier length considered for inference.
 *
 * A work bound in the same spirit as `REGEX_INPUT_CAP` — minified and generated
 * sources carry pathological identifiers, and every name that reaches this
 * module is walked, lowercased, and cached — but the load-bearing argument is
 * semantic rather than performance. An identifier past this length has no naming
 * convention left to read. Names carry intent because humans and models write
 * them for humans to read; a 4,000-character mangled identifier is machine
 * output, and inferring "this is a token" from some substring of it would be
 * noise dressed as evidence. Truncating rather than skipping keeps the common
 * near-miss (a long but real name) working, since the meaningful words are at
 * the front.
 */
const NAME_LENGTH_CAP = 200;

/**
 * The `SymbolTable.guards` key separator.
 *
 * NUL, because it is the one character that cannot occur in a path or an
 * identifier on any platform this runs on, so `a/b.ts` + `c` can never collide
 * with some other file/name pair spelled differently.
 *
 * Built with `String.fromCharCode` rather than written as a literal on purpose.
 * A literal NUL in source is an invisible byte: it survives copy-paste, renders
 * as nothing in most editors, turns the file "binary" to `grep`, and a
 * maintainer who accidentally deletes it gets a key space that silently
 * concatenates instead of a syntax error. A unicode escape in a string literal
 * would also be visible, but the named constant additionally means the answer to
 * "what separates these two halves" is a word rather than a character nobody can
 * see, at every use site.
 */
const GUARD_KEY_SEPARATOR = String.fromCharCode(0);

/**
 * Memoised tokenisation, bounded and cleared wholesale when full.
 *
 * Identifier repetition across a project is extreme — `req`, `res`, `next`,
 * `user` recur in every file — so the hit rate is high and the cache pays for
 * itself on any project bigger than a handful of files.
 *
 * Cleared entirely at the cap rather than evicted LRU-style, and that is the
 * point of the comment: an LRU needs a recency structure to maintain on every
 * hit, which costs more than re-splitting a 12-character string, and the access
 * pattern here has no long tail worth protecting. The cap exists so a
 * long-running host process cannot accumulate one entry per identifier of every
 * project it ever scanned; it is a leak bound, not a hit-rate optimisation.
 *
 * The returned arrays are shared. Callers inside this module treat them as
 * read-only; nothing outside this module ever receives one.
 */
const TOKEN_CACHE = new Map<string, readonly string[]>();
const TOKEN_CACHE_MAX = 20_000;

/**
 * One word of an identifier: an all-caps acronym run, a Capitalised word, a
 * lowercase run, or a digit run. Anything else (`_`, `-`, `.`, `$`, `/`,
 * whitespace) is a separator by virtue of matching nothing.
 *
 * Written as a MATCH rather than a split so there is no sentinel character to
 * inject and no empty-string bookkeeping, and so the acronym rule can be stated
 * directly: `[A-Z]+(?![a-z])` takes `JWT` out of `JWTToken` by refusing to eat
 * the capital that starts the next word. Every branch is a bounded character
 * class with no nested quantifier, so it is linear on any input — see the A1
 * ReDoS work in this repository for why that property is checked rather than
 * assumed for every regex added here.
 *
 * Digits are a word boundary rather than part of the run they touch, which
 * matters more than it looks: generated and hand-disambiguated code is full of
 * `mw7`, `user2`, `token1`, and fusing the digit into the letters would make
 * every one of them an unrecognised word. No vocabulary entry in this file
 * contains a digit, so splitting them out can only add matches, never move one.
 */
const IDENTIFIER_WORD = /[A-Z]+(?![a-z])|[A-Z][a-z]*|[a-z]+|[0-9]+/g;

/**
 * Split an identifier into lowercase words, respecting camelCase boundaries.
 *
 * WHY WORD SEGMENTATION RATHER THAN SUBSTRING SEARCH
 *
 * This is the single most important decision in the file. `/can/i.test(name)`
 * is one character shorter and matches `cancel`, `canvas`, `candidate`, and
 * `scan`; `/token/i.test(name)` matches `tokenizer`; `/role/i.test(name)`
 * matches `roleplay`. Every one of those is a false role that would go on to
 * raise the confidence of a finding, and confidence inflation on a security tool
 * is how users learn to ignore it. Segmenting first means a match is a WORD
 * match, and `cancel` simply has no word `can` in it.
 *
 * Dots separate like any other punctuation, so a member path such as `req.user`
 * — which is how the interesting bindings are actually written in Express code —
 * yields both `req` and `user` instead of one meaningless blob.
 */
function tokenize(name: string): readonly string[] {
  const cached = TOKEN_CACHE.get(name);
  if (cached) return cached;

  const out: string[] = [];
  const capped = name.length > NAME_LENGTH_CAP ? name.slice(0, NAME_LENGTH_CAP) : name;
  IDENTIFIER_WORD.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = IDENTIFIER_WORD.exec(capped)) !== null) {
    out.push(match[0].toLowerCase());
  }

  if (TOKEN_CACHE.size >= TOKEN_CACHE_MAX) TOKEN_CACHE.clear();
  TOKEN_CACHE.set(name, out);
  return out;
}

/**
 * Canonicalise an identifier before it becomes a map key or a guard key.
 *
 * Does two small things that both prevent a silent whole-project miss:
 *
 *  - Trims surrounding whitespace, which on this repository means CARRIAGE
 *    RETURNS. Everything upstream splits files into lines, and a producer that
 *    splits a CRLF file on `\n` leaves `\r` welded to the last token on every
 *    line. `requireAdmin\r` and `requireAdmin` are different map keys, so on
 *    Windows-authored sources the table would look populated while every lookup
 *    from a consumer that spelled the name normally missed. Normalising at the
 *    single point where names enter is cheaper and far more robust than auditing
 *    every producer, and it costs nothing when the input is already clean.
 *  - Strips the key separator. A name containing NUL could otherwise forge a key
 *    for a different file — contrived as an attack, but the defence is one
 *    `split`/`join` and the alternative is a key space in which parsing a key
 *    back apart is ambiguous.
 */
function normalizeName(raw: string): string {
  return raw.split(GUARD_KEY_SEPARATOR).join('').trim();
}

/**
 * The key shape used by `SymbolTable.guards`: `filePath`, NUL, `name`.
 *
 * Exported so that no consumer hand-builds the string. A guard lookup that
 * spells the separator wrong does not throw and does not fail loudly — it
 * returns `false`, which reads as "authorization was not centralised here", the
 * exact wrong answer in the exact direction that produces a false finding. One
 * function, one place to be wrong.
 */
export function guardKey(filePath: string, name: string): string {
  return `${filePath}${GUARD_KEY_SEPARATOR}${normalizeName(name)}`;
}

// ---------------------------------------------------------------------------
// Word vocabularies
//
// All matching below is against whole tokenised WORDS, never substrings, so
// these sets can stay short and readable: `token` covers `accessToken`,
// `csrfToken`, `refresh_token`, and `TOKEN_TTL` without listing any of them,
// and does NOT cover `tokenizer`, which is a single word that happens to start
// with the same five letters.
// ---------------------------------------------------------------------------

const ROLE_WORDS = new Set(['role', 'roles']);

/**
 * Permission vocabulary. `authorize`/`authz` live here as well as in the guard
 * shapes below: "authorize" names the act of deciding a permission, so a symbol
 * called `authorizeUpload` genuinely concerns permissions, and a consumer asking
 * "does anything here talk about permissions" should see it.
 */
const PERMISSION_WORDS = new Set([
  'permission',
  'permissions',
  'perm',
  'perms',
  'privilege',
  'privileges',
  'acl',
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'authorization',
  'authorisation',
  'authz',
]);

const TOKEN_WORDS = new Set(['token', 'tokens', 'jwt', 'jwts', 'bearer']);

/**
 * User vocabulary. `username` is listed explicitly because it is conventionally
 * written as one word and therefore tokenises to one word — `userName` splits,
 * `username` does not — and leaving it out would make the role depend on the
 * casing habits of whoever typed it.
 */
const USER_WORDS = new Set(['user', 'users', 'username', 'usernames']);

const SESSION_WORDS = new Set(['session', 'sessions', 'sess']);

const REQUEST_WORDS = new Set(['request', 'requests', 'req']);

const RESPONSE_WORDS = new Set(['response', 'responses', 'res']);

const MIDDLEWARE_WORDS = new Set(['middleware', 'middlewares', 'mw', 'interceptor', 'interceptors']);

/**
 * Words that make an `isX` / `hasX` / `canX` predicate a SECURITY predicate.
 *
 * `isValid` is a validity check, `isAdmin` is an authorization check, and only
 * the second one is a checkpoint whose presence means authorization was
 * centralised. This set is what separates them.
 */
const SECURITY_WORDS = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authenticated',
  'authentication',
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'authorization',
  'authorisation',
  'admin',
  'admins',
  'superuser',
  'root',
  'sudo',
  'owner',
  'owned',
  'permission',
  'permissions',
  'perm',
  'perms',
  'privilege',
  'privileged',
  'role',
  'roles',
  'acl',
  'token',
  'jwt',
  'session',
  'allow',
  'allowed',
  'grant',
  'granted',
  'member',
  'membership',
  'staff',
  'login',
  'logged',
  'signin',
  'signed',
  'tenant',
]);

/**
 * Imperative heads that make the whole identifier a precondition.
 *
 * `requireX`, `ensureX`, `assertX`, `checkX`, `verifyX` are not descriptions of
 * a value; they are statements that execution should not continue unless X
 * holds. That shape is guard-ish on its own, WITHOUT a security word attached —
 * see the note on over-admission in `isGuardShapedName` for why that asymmetry
 * against the `isX`/`hasX` treatment is deliberate rather than sloppy.
 */
const IMPERATIVE_HEADS = new Set(['require', 'ensure', 'assert', 'check', 'verify']);

const PREDICATE_HEADS = new Set(['is', 'has', 'can']);

/**
 * Words that make an identifier an authorization decision by themselves.
 *
 * `authorize` in any spelling or inflection: unlike `auth` (which is equally at
 * home in `authService`, `authReducer`, and `useAuth`), the verb names the act
 * of deciding, so wherever it appears in a name a decision is being made.
 */
const AUTHORIZE_WORDS = new Set([
  'authorize',
  'authorise',
  'authorized',
  'authorised',
  'authorization',
  'authorisation',
  'authz',
]);

/**
 * Names whose guard-ness is a framework convention rather than English.
 *
 * `canActivate` is Angular's route-guard interface method. Word-wise it is
 * `can` + `activate`, and `activate` carries no security meaning at all, so
 * every general rule below correctly declines it — yet in an Angular project it
 * is *the* authorization checkpoint. Matching the compact (separator-free,
 * lowercased) form keeps the general rules honest and puts the framework
 * knowledge somewhere it can be read as framework knowledge.
 */
const COMPACT_GUARD_NAMES = new Set(['canactivate']);

/**
 * Path words that make an EXPORTED symbol a guard by placement.
 *
 * Matched against the tokenised path, which gives the "path segments, not
 * substrings" property for free: `src/authors/list.ts` tokenises to
 * `src`,`authors`,`list`,`ts`, and the word `authors` is not in this set, so the
 * `auth` bucket does not swallow a blog's author directory. That case is not
 * hypothetical — `author`, `authoring`, and `authority` are all common directory
 * names and all contain `auth`.
 */
const SECURITY_PATH_WORDS = new Set([
  'middleware',
  'middlewares',
  'guard',
  'guards',
  'auth',
  'authn',
  'authz',
  'authentication',
  'authorization',
  'authorisation',
  'authorize',
  'authorise',
  'policy',
  'policies',
  'acl',
  'acls',
]);

/**
 * Canonical emission order for roles.
 *
 * Roles are collected in a `Set` (dedup) and emitted in this fixed order rather
 * than insertion order, because the array ends up in finding evidence and in
 * assertions. Insertion order would make the same project produce
 * `['guard','role']` or `['role','guard']` depending on which clause happened to
 * run first after an unrelated refactor, and a diff that moves for no reason is
 * a diff nobody reads. Mirrors the declaration order of `SymbolRole`.
 */
const ROLE_ORDER: readonly SymbolRole[] = [
  'role',
  'permission',
  'token',
  'user',
  'session',
  'request',
  'response',
  'validator',
  'sanitizer',
  'guard',
  'middleware',
];

function hasAny(words: readonly string[], vocabulary: ReadonlySet<string>): boolean {
  for (const word of words) {
    if (vocabulary.has(word)) return true;
  }
  return false;
}

/**
 * Whether the identifier's SHAPE says "authorization checkpoint".
 *
 * ON DELIBERATE OVER-ADMISSION
 *
 * `checkStock` and `ensureDirectory` are admitted by the imperative-head clause
 * and are not authorization anything. That is a considered trade, not an
 * oversight, and the direction matters:
 *
 * `guards` is consumed as evidence that authorization was CENTRALISED. A
 * cross-file smell such as "authorization is scattered across handlers" fires
 * when the guards are missing. So an over-admitted guard costs a missed finding
 * (a false negative) while a missed guard costs a fired finding on well-factored
 * code (a false positive) — and this repository ships a hard
 * `samples/safe == 0 findings` gate precisely because false positives are the
 * failure that gets a security tool uninstalled. Between two errors, take the
 * quiet one.
 *
 * Requiring a security word after `require`/`check` would fix `checkStock` and
 * break `requireLogin` for every project that names its guard after the thing it
 * protects rather than after security. The predicate heads (`is`/`has`/`can`) do
 * carry the security-word requirement, because `isEmpty`, `hasChildren`, and
 * `canRetry` are ordinary and enormously more common than their imperative
 * counterparts — there, the same trade points the other way.
 */
function isGuardShapedName(name: string): boolean {
  const words = tokenize(name);
  if (words.length === 0) return false;

  if (COMPACT_GUARD_NAMES.has(words.join(''))) return true;
  if (words.includes('guard') || words.includes('guards')) return true;
  if (hasAny(words, AUTHORIZE_WORDS)) return true;

  const head = words[0];
  if (head !== undefined && IMPERATIVE_HEADS.has(head) && words.length > 1) return true;
  if (head !== undefined && PREDICATE_HEADS.has(head) && hasAny(words.slice(1), SECURITY_WORDS)) return true;

  // `authMiddleware`, `permissionInterceptor`: a middleware word plus a security
  // word is the same claim as `requireAuth` made in framework vocabulary instead
  // of English. Neither word alone qualifies — `loggingMiddleware` is not a
  // checkpoint, and `authService` is not one either.
  if (hasAny(words, MIDDLEWARE_WORDS) && hasAny(words, SECURITY_WORDS)) return true;

  return false;
}

/**
 * `can` used as a VERB — `canEdit`, `user_can_delete` — which is the English
 * form of a permission question.
 *
 * Requires a following word, and that requirement is the whole reason this is a
 * function instead of a set entry. `can` standing alone is a noun as often as a
 * modal, and — the case that matters — a bare substring test for `can` matches
 * `cancel`, `canvas`, and `candidate`. Tokenisation already kills the substring
 * problem; this kills the remaining ambiguity of the standalone word.
 */
function hasCanVerb(words: readonly string[]): boolean {
  for (let i = 0; i < words.length - 1; i += 1) {
    if (words[i] === 'can') return true;
  }
  return false;
}

/**
 * User evidence, with `userAgent` deliberately excluded.
 *
 * THE DECISION, SINCE IT WAS A REAL CHOICE: `userAgent` does NOT get the `user`
 * role, and neither does `USER_AGENT` nor `user_agent`.
 *
 * The `user` role means "this identifier concerns the authenticated principal" —
 * that is what makes it useful to a rule reasoning about whose data a handler
 * touched. `User-Agent` is an HTTP request header: fully attacker-controlled,
 * present on unauthenticated requests, and semantically the opposite of a
 * principal. Letting it in would put `user` on a value any anonymous client
 * chooses, and a rule that treats identity as established when it came off the
 * wire is the shape of an actual authorization bug, not merely a noisy one.
 *
 * The exclusion is narrow on purpose: only the adjacent pair `user`+`agent` is
 * suppressed, so `userAgentOfCurrentUser` still yields `user` from its second
 * occurrence. A broader "drop `user` whenever `agent` appears" would lose real
 * cases for no gain. `userAgent` is not reclassified as a `request` role either
 * — inventing a role out of an exclusion would be a second guess stacked on the
 * first.
 */
function hasUserEvidence(words: readonly string[]): boolean {
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (word === undefined || !USER_WORDS.has(word)) continue;
    if (word === 'user' && words[i + 1] === 'agent') continue;
    return true;
  }
  return false;
}

/** Whether an exported symbol's file placement is itself security evidence. */
function isSecurityPath(filePath: string): boolean {
  return hasAny(tokenize(filePath), SECURITY_PATH_WORDS);
}

/**
 * Infer the roles an identifier suggests. Zero or more, deduplicated, ordered.
 *
 * Exported alongside `buildSymbolTable` because it is the unit the adversarial
 * cases are written against: `cancel`, `tokenizer`, `userAgent`, and `resource`
 * are assertions about this function, and routing them through a whole
 * `StructureIndex` to state them would obscure what is being claimed.
 */
export function inferRoles(rawName: string): SymbolRole[] {
  const name = normalizeName(rawName);
  if (!name) return [];
  const words = tokenize(name);
  if (words.length === 0) return [];

  const found = new Set<SymbolRole>();

  if (hasAny(words, ROLE_WORDS)) found.add('role');
  if (hasAny(words, PERMISSION_WORDS) || hasCanVerb(words)) found.add('permission');
  if (hasAny(words, TOKEN_WORDS)) found.add('token');
  if (hasUserEvidence(words)) found.add('user');
  if (hasAny(words, SESSION_WORDS)) found.add('session');
  if (hasAny(words, REQUEST_WORDS)) found.add('request');
  if (hasAny(words, RESPONSE_WORDS)) found.add('response');
  // Stem matches rather than set membership: `valid`, `validate`, `validator`,
  // `validation`, `validates`, and `validity` are one idea with six spellings,
  // and the stem is unambiguous — no common identifier starts with `valid` and
  // means something else. `escap*`, `sanitiz*`/`sanitis*`, and `purif*` (which
  // catches `DOMPurify`) are the same story. `invalid` is NOT matched, because
  // the stem is tested against the whole word, not searched inside it.
  if (words.some((w) => w.startsWith('valid'))) found.add('validator');
  if (
    words.some(
      (w) => w.startsWith('sanitiz') || w.startsWith('sanitis') || w.startsWith('escap') || w.startsWith('purif'),
    )
  ) {
    found.add('sanitizer');
  }
  if (isGuardShapedName(name)) found.add('guard');
  if (hasAny(words, MIDDLEWARE_WORDS)) found.add('middleware');

  if (found.size === 0) return [];
  return ROLE_ORDER.filter((role) => found.has(role));
}

/**
 * Build the project-wide symbol table.
 *
 * TWO PASSES, AND WHY IT CANNOT BE ONE
 *
 * The strongest guard signal is cross-file by nature: `requireAdmin` is defined
 * in `src/auth/guards.ts` and used as `router.get('/x', requireAdmin, handler)`
 * in `src/routes/admin.ts`. Deciding whether the definition is a guard therefore
 * requires having already seen every route in the project, which a single pass
 * over `structures` cannot guarantee — with one pass the answer would depend on
 * whether the routes file happened to come before the definition file. Pass one
 * collects names and the project-wide set of names ever used as middleware; pass
 * two decides. The cost is a second walk over an in-memory array.
 *
 * WHY "USED AS ROUTE MIDDLEWARE" IS THE STRONGEST EVIDENCE
 *
 * Every other signal in this file is a guess about what a programmer MEANT by a
 * name. This one is a record of what the program DOES: the identifier was passed
 * in a pre-handler argument position, so the framework will invoke it before the
 * handler and it can refuse the request. That is the definition of a checkpoint,
 * observed rather than inferred, and it holds for a guard named `mw7` in a
 * project with no naming discipline at all — which is exactly the population
 * where every naming heuristic above quietly returns nothing. It is also the
 * only signal that cannot be produced by a rename, which is why it is included
 * even when the name looks like nothing at all.
 *
 * WHAT A `guards` KEY MEANS
 *
 * `guardKey(file, name)` asserts: *in this file, this name refers to something
 * we judge to be an authorization checkpoint*. It is NOT "this file defines the
 * guard". A name is registered at every file where it is known — defined,
 * exported, imported, or used at a route — because consumers look up the pair
 * they are holding, and a consumer standing at a route registration in
 * `routes/admin.ts` holds the name as it appears THERE. Definition-site-only
 * keying would answer `false` for that lookup, and it would also lose the guard
 * entirely whenever the defining file fell outside the budget's admitted set
 * (see `admitFiles`) — a partial scan is exactly when a spurious "authorization
 * is scattered" finding is least welcome.
 */
export function buildSymbolTable(structures: StructureIndex[]): SymbolTable {
  const roles = new Map<string, SymbolRole[]>();
  const guards = new Set<string>();
  // Names already run through `inferRoles`. Separate from `roles` because the
  // majority of identifiers in a project (`i`, `data`, `fetchAll`) infer nothing
  // and are therefore absent from `roles` by contract — without this set, every
  // repeat of a roleless name would re-tokenise and re-test every vocabulary.
  const inferred = new Set<string>();

  const noteName = (raw: string): string | undefined => {
    const name = normalizeName(raw);
    if (!name) return undefined;
    if (!inferred.has(name)) {
      inferred.add(name);
      const found = inferRoles(name);
      // The empty array is never stored: `SymbolTable.roles` documents absence
      // as the representation of "no role inferred", so a consumer writing
      // `roles.get(n)?.length` and a consumer writing `roles.has(n)` must agree.
      // Storing `[]` would make the first say "no" and the second say "yes".
      if (found.length > 0) roles.set(name, found);
    }
    return name;
  };

  // ---- Pass 1: every identifier the project mentions, plus route usage. -----
  const usedAsMiddleware = new Set<string>();
  for (const structure of structures) {
    for (const symbol of structure.symbols) noteName(symbol.name);
    for (const edge of structure.imports) {
      for (const binding of edge.names) noteName(binding);
    }
    for (const exportedName of structure.exportedNames) noteName(exportedName);
    for (const route of structure.routes) {
      for (const middlewareName of route.middlewareNames) {
        const name = noteName(middlewareName);
        if (name) usedAsMiddleware.add(name);
      }
      if (route.handlerName) noteName(route.handlerName);
      if (route.inlineHandler) noteName(route.inlineHandler.name);
    }
  }

  // ---- Pass 2: decide guards, now that route usage is known project-wide. ---
  for (const structure of structures) {
    const securityPath = isSecurityPath(structure.filePath);

    // name → is it exported FROM THIS FILE. The flag gates the placement rule
    // only: a file under `src/middleware/` is full of local helpers, and
    // `formatDuration` in `src/middleware/logging.ts` is not an authorization
    // checkpoint because of where it happens to live. Being exported from such a
    // file is what turns placement into a statement about the module's role.
    const known = new Map<string, boolean>();
    const note = (raw: string, exported: boolean): void => {
      const name = normalizeName(raw);
      if (!name) return;
      known.set(name, (known.get(name) ?? false) || exported);
    };

    for (const symbol of structure.symbols) note(symbol.name, symbol.exported);
    for (const exportedName of structure.exportedNames) note(exportedName, true);
    for (const edge of structure.imports) {
      for (const binding of edge.names) note(binding, false);
    }
    for (const route of structure.routes) {
      for (const middlewareName of route.middlewareNames) note(middlewareName, false);
    }

    for (const [name, exported] of known) {
      const isGuard = usedAsMiddleware.has(name) || isGuardShapedName(name) || (exported && securityPath);
      if (isGuard) guards.add(guardKey(structure.filePath, name));
    }
  }

  return { roles, guards };
}
