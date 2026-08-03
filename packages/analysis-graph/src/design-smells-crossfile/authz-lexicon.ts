// The authorization vocabulary, shared by every cross-file rule that has to
// recognise "this line decides whether a subject is allowed to do something".
//
// WHY THIS FILE EXISTS — AND WHY IT IS AN EXTRACTION RATHER THAN A NEW SET
//
// Every regex and every word list below was written for, tuned against, and
// measured on VG-SMELL-010 (`scattered-authorization.ts`). Nothing here is new
// vocabulary. It moved out of that file when a second and third rule needed the
// same answer to the same question, and the alternative was three copies.
//
// Three copies is not a style problem, it is the 041 failure mode with a longer
// fuse. VG-SMELL-041's first submission fired on real code because its guard
// vocabulary had drifted wider than 010's — it accepted `strip`, `quote`,
// `ensure`, `assert` and `encode` as authorization verbs, which 010 had already
// rejected — and nobody could see the drift because the two lists were in
// different files and neither mentioned the other. The rule shipped with forty
// passing tests and 0% precision over 630 repositories. A shared module makes
// that particular mistake impossible to make silently: widening the vocabulary
// now changes every consumer's fixtures at once, and the corpus sweep that
// gates admission runs against all of them.
//
// ★ WHAT IS IN HERE AND WHAT IS NOT
//
// In: the patterns that recognise an authorization DECISION in a body of code
// (`CMP`, `FLAG`, `MEMBERSHIP`), the privilege words that raise severity
// (`ELEVATED`), the path-word splitter both use, and the guard-NAME vocabulary
// that separates authentication from authorization.
//
// Not in: anything a single rule decides for itself. Thresholds (`MIN_SITES`),
// severity boosts, the mutation-verb list, and the route-shape heuristics all
// stay with their rule, because they encode that rule's judgement rather than
// the project's definition of the word "authorization". Moving those here would
// turn a vocabulary into a rule engine and every consumer would inherit
// decisions it never made.
//
// ★ THE ONE THING TO KNOW BEFORE ADDING A WORD
//
// The regexes here run over the BLANKED copy of the source (strings and
// comments replaced character-for-character with spaces), except `ELEVATED`,
// which runs over the ORIGINAL text because the privilege word usually lives
// inside the string literal being compared against. Consumers must keep that
// distinction; it is the difference between `user.role === 'admin'` scoring as
// elevated and scoring as nothing at all.
//
// Every quantifier below has a ceiling and horizontal whitespace is matched as
// `[^\S\r\n]{0,N}` rather than `\s*`. That is not style — unbounded whitespace
// adjacent to another quantifier is the exact shape that produced this
// project's A1 ReDoS findings.
//
// ★ UPDATED 2026-08-03. This comment used to end "...and these patterns are
// outside the reach of the `sec-a1-catalog.mjs` census (it reads
// `packages/rules` only, MEASURED LIMIT 8), so the bound is the only thing
// protecting the three-second contract here." Both halves are now stale:
// `scripts/sec-a1-crossfile-catalog.mjs` measures this layer, and the three
// patterns below are its REQUIRED positive controls — they are CONSTRUCTED at
// run time from an interpolated template, so a literal scan cannot see them and
// only the runtime hook can prove they executed. If this file's patterns stop being
// observed, `a1:crossfile-probe-liveness` fails by name. The bound is no longer
// the only protection; it is now the protection plus a measurement. (The old
// note's "8 cross-file rules" was also wrong by then — the registry is 11.)

/**
 * Properties whose comparison IS an authorization decision.
 *
 * Deliberately a closed list of property names rather than a keyword search over
 * the line. `/admin/i` over handler bodies would match `adminEmail`,
 * `res.render('admin')`, and a comment, and the resulting rule would fire
 * somewhere in almost every web application — which is the failure mode that
 * makes teams turn a linter off. The check has to be shaped like a decision
 * about a subject's privilege, and reading a named privilege field off an
 * object is what that looks like.
 */
export const AUTHZ_PROPERTY =
  '(?:role|roles|userRole|user_role|isAdmin|is_admin|isOwner|is_owner|isSuperuser|is_superuser|isRoot|permissions|permission|privileges|privilege|scopes|accessLevel|access_level)';

/**
 * A privilege comparison: `user.role !== 'admin'`, `req.user.role === ROLE_ADMIN`.
 *
 * The receiver is bounded (`[\w$.]{0,40}`) and horizontal whitespace uses
 * `[^\S\r\n]{0,4}` rather than `\s*` throughout. See the file header.
 *
 * ★ A FRESH RegExp PER CALL, NOT A SHARED CONSTANT.
 *
 * These carry the `g` flag, so they carry `lastIndex`, and a module-level
 * instance shared by three rules is a mutable global that two of them will
 * eventually read mid-iteration. VG-SMELL-010 got away with module constants
 * because it was the only consumer and every loop reset `lastIndex` itself. The
 * moment there are three, "every loop remembers" stops being a property anyone
 * can check. Factory functions cost one allocation per analysis and remove the
 * whole class of bug.
 */
export function authzComparisonPattern(): RegExp {
  return new RegExp(
    String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>${AUTHZ_PROPERTY})\b[^\S\r\n]{0,4}(?<op>===|!==|==|!=|<|>|<=|>=)`,
    'g',
  );
}

/** A boolean privilege flag used directly: `if (!user.isAdmin)`, `if (user.isAdmin)`. */
export function authzFlagPattern(): RegExp {
  return new RegExp(
    String.raw`(?:!|\bnot[^\S\r\n]{1,4}|\bif[^\S\r\n]{0,4}\(?[^\S\r\n]{0,4})(?<recv>[\w$][\w$.]{0,40})\.(?<prop>isAdmin|is_admin|isOwner|is_owner|isSuperuser|is_superuser|isRoot|hasAccess)\b`,
    'g',
  );
}

/** A membership test over a privilege collection: `user.permissions.includes('x')`. */
export function authzMembershipPattern(): RegExp {
  return new RegExp(
    String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>permissions|roles|scopes|privileges)\b[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}(?<call>includes|indexOf|has|contains|some)[^\S\r\n]{0,4}\(`,
    'g',
  );
}

/** All three decision shapes, in the order VG-SMELL-010 has always scanned them. */
export function authzDecisionPatterns(): RegExp[] {
  return [authzComparisonPattern(), authzFlagPattern(), authzMembershipPattern()];
}

/**
 * Privilege words that make a finding `high` rather than `medium`.
 *
 * From design addendum §7.2: "medium; high when it involves administrator or
 * owner privilege". Matched against the ORIGINAL source text of the check, not
 * the blanked copy, because the word usually lives inside the string literal
 * being compared against — which blanking, by design, erases.
 */
export const ELEVATED = /\b(admin|administrator|owner|superuser|super_user|root|sudo)\b/i;

/** Any character that cannot appear inside an identifier word. */
const NON_WORD_CHAR = /[^A-Za-z0-9]/;

/** The camelCase seam: a lowercase or digit immediately followed by a capital. */
const CAMEL_SEAM = /([a-z0-9])([A-Z])/g;

/**
 * Split a path (or one segment of one, or an identifier) into lowercase words.
 *
 * ★ WORD MATCHING, NEVER SUBSTRING MATCHING. This is the whole reason the
 * function exists rather than `/auth/i.test(filePath)`, and the counterexample
 * is not hypothetical: `src/authors/list.ts`, `content/authoring/draft.ts`, and
 * `lib/authority.ts` are ordinary directory names that all contain `auth`. A
 * substring test promotes every blog and CMS in existence on the strength of
 * the word "author". Segmenting first means `authors` is a word this vocabulary
 * does not contain, and the question stops being close.
 *
 * Neither regex has a quantifier at all — `split` on a single-character class,
 * then one substitution at a two-character seam — so neither can backtrack and
 * the D3 three-second contract is satisfied by construction rather than by
 * measurement.
 */
export function pathWords(text: string): string[] {
  const out: string[] = [];
  for (const chunk of text.split(NON_WORD_CHAR)) {
    if (chunk.length === 0) continue;
    for (const word of chunk.replace(CAMEL_SEAM, '$1 $2').split(' ')) {
      if (word.length > 0) out.push(word.toLowerCase());
    }
  }
  return out;
}

/**
 * Guard names that decide WHO YOU ARE (authentication).
 *
 * ★ THE SPLIT BETWEEN THIS SET AND `AUTHZ_GUARD_WORD` IS LOAD-BEARING FOR 013.
 *
 * `SymbolTable.guards` answers "is this symbol a guard" and deliberately does
 * not answer "a guard against what" — an over-admitted guard there costs a
 * missed finding rather than a false one, which is the safe direction for 010.
 * VG-SMELL-013 cannot use that set unrefined, because its accusation is "the
 * project has a role-checking guard and this handler re-implemented it inline",
 * and the single most common CORRECT design in web applications is exactly the
 * layered one: an authentication middleware mounted globally, and per-handler
 * authorization written where the resource is known.
 *
 * Firing on that shape would be worse than the 041 regression, because 041's
 * false positives were rare and this one is the default architecture of most
 * Express applications. So 013 requires that the mounted guard be an
 * AUTHORIZATION guard, and this pair of sets is how that question is asked.
 *
 * Membership is by whole word against `pathWords`, so `authenticateUser`,
 * `authenticate_user` and `isLoggedIn` all reduce to words in this set.
 */
export const AUTHN_GUARD_WORD: ReadonlySet<string> = new Set([
  'authenticate',
  'authenticated',
  'authentication',
  'authn',
  'login',
  'loggedin',
  'signin',
  'session',
  'jwt',
  'bearer',
  'passport',
  'verifytoken',
  'validatetoken',
  'checktoken',
]);

/**
 * Guard names that decide WHAT YOU MAY DO (authorization).
 *
 * The complement of `AUTHN_GUARD_WORD` for the purpose described there. A guard
 * whose name contains one of these words is making a privilege decision, and a
 * handler that re-derives the same privilege inline is duplicating a decision
 * the project has already centralised.
 *
 * `authorize`/`authorise`/`authz` are here and `auth` is NOT, on purpose. `auth`
 * is the single most ambiguous token in this domain — `authMiddleware` is
 * authentication in most codebases and authorization in some — and a consumer
 * that has to choose a side is better served by the word being absent from both
 * sets, which makes it evidence for neither.
 */
export const AUTHZ_GUARD_WORD: ReadonlySet<string> = new Set([
  'authorize',
  'authorized',
  'authorise',
  'authorised',
  'authorization',
  'authorisation',
  'authz',
  'permission',
  'permissions',
  'permit',
  'role',
  'roles',
  'admin',
  'isadmin',
  'requireadmin',
  'privilege',
  'privileges',
  'scope',
  'scopes',
  'acl',
  'rbac',
  'can',
  'ability',
  'policy',
  'policies',
  'owner',
  'ownership',
]);

/**
 * Whether a guard name is an AUTHORIZATION guard rather than an authentication one.
 *
 * Asymmetric on purpose, and in the quiet direction: a name that carries words
 * from both sets (`requireAdminSession`) counts as authorization, because the
 * privilege word is the specific claim and the session word is the generic one.
 * A name that carries neither (`guard`, `check`, `middleware`) counts as
 * NEITHER — it returns false — so a consumer that needs authorization evidence
 * gets none from it rather than getting a guess.
 */
export function isAuthzGuardName(name: string): boolean {
  const words = pathWords(name);
  if (words.length === 0) return false;
  let sawAuthz = false;
  for (const w of words) {
    if (AUTHZ_GUARD_WORD.has(w)) sawAuthz = true;
  }
  return sawAuthz;
}

/** Whether a guard name is recognisably an AUTHENTICATION guard. See `isAuthzGuardName`. */
export function isAuthnGuardName(name: string): boolean {
  const words = pathWords(name);
  if (words.length === 0) return false;
  for (const w of words) {
    if (AUTHN_GUARD_WORD.has(w)) return true;
  }
  return false;
}

/**
 * Route paths that are public by design and must never be accused of missing a guard.
 *
 * ★ WITHOUT THIS SET, VG-SMELL-011 FIRES ON EVERY CORRECT APPLICATION.
 *
 * 011's evidence is "the project guards routes of this kind, and this one is
 * unguarded". The login endpoint is unguarded in every correct application that
 * has ever been written — it is where authentication is obtained — and so is
 * registration, so is the health probe, so is the payment provider's webhook
 * (which authenticates by signature, not by the project's own middleware).
 * Accusing those is not a tuning problem, it is the rule being wrong about what
 * it is looking at.
 *
 * Matched by whole word against `pathWords` of the route path, so `/api/v1/auth/login`
 * and `/healthz` both land. Kept here rather than in 011 because 013 and any
 * future boundary rule need the identical exemption, and two lists would drift.
 */
export const PUBLIC_BY_DESIGN_ROUTE_WORD: ReadonlySet<string> = new Set([
  'login',
  'signin',
  'signup',
  'register',
  'registration',
  'logout',
  'signout',
  'auth',
  'oauth',
  'callback',
  'token',
  'refresh',
  'forgot',
  'reset',
  'verify',
  'confirm',
  'health',
  'healthz',
  'healthcheck',
  'livez',
  'readyz',
  'ping',
  'status',
  'metrics',
  'version',
  'webhook',
  'webhooks',
  'hook',
  'hooks',
  'public',
  'docs',
  'swagger',
  'openapi',
  'graphql',
  'static',
  'assets',
  'favicon',
  'robots',
]);

/** Whether a route path literal names an endpoint that is public by design. */
export function isPublicByDesignRoute(path: string | undefined): boolean {
  if (path === undefined || path.length === 0) return false;
  for (const w of pathWords(path)) {
    if (PUBLIC_BY_DESIGN_ROUTE_WORD.has(w)) return true;
  }
  return false;
}

/**
 * Paths that are test scaffolding rather than shipped code.
 *
 * Every rule in this directory excludes them, for the reason 010 wrote down: a
 * fixture that deliberately contains the smell is not a finding about the
 * project, and a test harness that mounts routes without guards is describing a
 * test, not an application.
 *
 * ★ BYTE-IDENTICAL TO THE PATTERN VG-SMELL-010 HAS ALWAYS USED. Widening it
 * here — `examples?`, `samples?`, `demos?` were all candidates — would change
 * the flagship rule's population as a side effect of a refactor, which is
 * exactly the kind of silent behaviour change an extraction is supposed to be
 * incapable of. A rule that needs a wider exclusion states it itself, and
 * carries its own measurement for why.
 */
export const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata)(?:\/|$)|\.(?:test|spec)\.[\w]+$/i;

/** Whether a repo-relative path is test scaffolding. */
export function isTestPath(filePath: string): boolean {
  return TEST_PATH.test(filePath);
}
