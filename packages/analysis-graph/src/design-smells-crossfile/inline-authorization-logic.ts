// VG-SMELL-013 — Inline Authorization Logic (implementation plan §5.4, appendix
// B's 0.3.0-β cross-file block).
//
// WHAT IT CLAIMS
//
// The project has an authorization guard. It is written, it is exported, and it
// is mounted on several routes — the convention exists and the team follows it.
// And then one file's handlers make the same class of decision by hand, in the
// handler body, refusing the request themselves instead of letting the guard
// refuse it. The policy now lives in two places that cannot be changed together:
// widening `requireRole('admin')` to `requireRole('admin', 'owner')` fixes every
// route that uses the guard and silently misses the handler that re-derived it.
//
// This is the shape VG-SMELL-010's labelling rubric calls 二重化 (duplication)
// and explicitly labels a true positive for 010 when 010's thresholds are met:
// "ガードが存在してハンドラにも適用済みなのにインラインでも判定している場合は
// 「二重化」であり、TP でよい（policy が1箇所に無いという主張は依然成立する）"
// (`docs/smell010-labeling-rubric.md`, §1 D). 013 is the rule for the case where
// those thresholds are NOT met — one file, one or two handlers — and where the
// existence of the guard is what makes a single site accusable at all.
//
// ★ WHY THIS IS A CROSS-FILE RULE, THOUGH THE SPEC SAYS 「単一/cross-file」
//
// `docs/VibeGuard_実装設計手順書.md` §5.4 lists 013 as 単一/cross-file. It is
// implemented HERE, in the cross-file package, and the sentence is read as
// "detected with single-file vocabulary, adjudicated on cross-file evidence".
// Three reasons, all of them already settled elsewhere in this repository rather
// than argued afresh:
//
//  - `scattered-authorization.ts`'s own header states that the single-file
//    design-smell rules 003 / 012 / 004 deliberately do NOT report a lone inline
//    check, and that "a finding that a single file could have produced does not
//    get to use" this package's justification. A single-file 013 would flag
//    `if (user.role !== 'admin') return res.status(403)` — one of the most
//    common correct lines in web programming — and would contradict a precision
//    decision this project has already made and shipped.
//  - The only evidence that makes 013 precise is "a role guard already exists
//    and is used", and that is cross-file by construction: the guard is in
//    `middleware/`, the handler is in `controllers/`, and the mounting is in
//    `routes/`. No single file contains the sentence.
//  - Single-file rules ship inside the Chrome and VS Code bundles, where the
//    input can be a pasted textarea fragment with no project around it. A rule
//    whose premise is "your project already centralised this" cannot evaluate
//    its premise there, and a premise that cannot be evaluated is a premise that
//    gets assumed.
//
// ★★ THE NEGATIVE CONDITION THAT DECIDES WHETHER THIS RULE IS SHIPPABLE
//
// LAYERED authentication plus inline authorization is CORRECT, and it is the
// default architecture of most Express applications: `authenticate` mounted
// globally so every request has a principal, and the privilege decision written
// in the handler where the resource id is finally known. A rule that fires on
// that is not slightly noisy — it is wrong about the majority of correct code,
// which is worse than the VG-SMELL-041 regression this directory's registry
// records (041's false positives were rare; this shape is everywhere).
//
// That is precisely why `authz-lexicon.ts` splits `AUTHN_GUARD_WORD` from
// `AUTHZ_GUARD_WORD`, and its comment names this rule as the reason. Condition
// (a) below therefore requires `isAuthzGuardName()`: a project whose only
// mounted guard is `authenticate` / `requireLogin` / `verifyToken` produces
// NOTHING here, ever. `samples/crossfile-fixtures/smell-013-neg-authn-only` is
// that fixture, it was written before the positive one, and it is the first test
// in the suite.
//
// ★ HOW THE REST OF THE PRECISION IS BOUGHT — negatives before positives
//
// 010 can afford a loose per-site test because it needs three sites across two
// files before it speaks; the arithmetic of "three independent coincidences" is
// itself evidence. 013 speaks about ONE handler, so each site has to carry the
// weight alone. Four conditions do that, and each one is a fixture:
//
//  1. THE RECEIVER MUST NAME A SUBJECT. `req.user.role`, `session.user.role`,
//     `claims.role` are privilege reads; `m.role`, `element.role`, `node.role`,
//     `row.role` are not. See `SUBJECT_WORD`.
//  2. THE CHECK MUST REFUSE. A 401/403, or a Forbidden/Unauthorized error,
//     within `DENIAL_WINDOW` characters after the check. Branching on privilege
//     to shape a response (`if (user.role === 'admin') return allRows(); return
//     ownRows();`) is not a re-implementation of a guard and is not reported.
//     See `DENIAL_WINDOW`.
//  3. NO OWNERSHIP DECISION IN THE NEIGHBOURHOOD. `doc.ownerId !== req.user.id
//     && !req.user.isAdmin` is a per-resource decision that no route-level guard
//     could have made, because it needs the loaded resource. See
//     `IDENTITY_COMPARISON`.
//  4. A METHOD CALL IS DELEGATION, NOT AN INLINE CHECK. `auth.isAdmin(user)` is
//     the shape this rule recommends. Byte-identical to the exclusion
//     `scattered-authorization.ts`'s `checksIn` already implements.
//
// ★★ MEASURED 2026-08-03, BEFORE SUBMISSION — where a real repository leaves
//
// `design-smells-crossfile/index.ts` records that a green suite is not evidence,
// and that both β taint rules were rejected after a corpus sweep. So this rule
// was swept before it was submitted, over BOTH corpora, and the funnel was
// instrumented rather than only the outcome — a zero-finding sweep says nothing
// at all unless you can say which condition emptied it.
//
//                                     corpus1k   corpus1k_vibe
//   repositories                          1,000          1,683
//   with TypeScript/JavaScript              484            877
//   with any named route middleware         187            274
//   with an AUTHZ-named one (a¹)              4 ⚠          23
//   … mounted on ≥ 3 routes (a²)              1 ⚠          13
//   … whose definition resolved (a³)          0             13
//   with any inline decision (b)              0              3
//   with BOTH                                 0              1
//   … where VG-SMELL-010 spoke first          0              1
//   FINDINGS                                  0              0
//
// Zero findings, zero crashes, zero errored repositories. What that establishes
// and what it does not, stated as plainly as the registry states it for 041 and
// 052: the rule does not fire on 2,683 repositories nobody here wrote, which is
// what `samples/safe == 0` generalises. It establishes NOTHING about recall — no
// true positive was produced either, so the only evidence of usefulness is this
// rule's own fixtures.
//
// ⚠ THE TWO MARKED corpus1k CELLS WERE CORRECTED 2026-08-03. They previously
// read 6 and 2. Those were counted over ALL languages including test paths; the
// rule itself is TS/JS-only and drops `isTestPath` files, and applying its own
// filters gives 4 and 1. The distinction matters here more than the arithmetic
// does: `rohitg00__agentmemory`, named below as a project (a³) refused, does not
// actually survive to (a²) under the rule's filters — its `BM25_SCOPE` mounts
// exist only in `test/index-persistence.test.ts`. A funnel measured more loosely
// than the rule attributes refusals to the wrong condition, which is the exact
// error VG-SMELL-011's registry note also made. Count premises THROUGH the
// rule's own predicates or the funnel argues for something else.
//
// The funnel is the useful part, and two rows in it are worth reading twice:
//
//  - (a¹) → (a²) → (a³) IS THE RULE. Only 23 of 877 TS/JS repositories in the
//    AI-generated corpus mount anything with an authorization NAME at all. That
//    single number is why this rule is safe and also why it is quiet: the
//    premise it needs is rare in real code, and every project that lacks it —
//    including every `authenticate`-only project, which is the majority — is
//    unreachable by construction rather than by a threshold.
//    ⚠ IN corpus1k, "rare" is the wrong word — the honest word is UNREACHABLE.
//    The decision point was reached 0 times in 1,000 human-written
//    repositories, and both arms fail for structural reasons rather than
//    threshold ones: Next.js `pages/api` endpoints emit no route registration,
//    so (a) cannot form, and their `const handler = withX(..., async (req,res)
//    => {…})` arrows are not indexed as symbols, so (b) cannot form — of 569
//    authorization-shaped decisions in that corpus, exactly 1 lay inside an
//    indexed handler body. LAION-AI/Open-Assistant carries this rule's target
//    shape (a `withAnyRole` convention over 11 endpoints, one of which
//    re-derives the role inline and returns 403) and is invisible to both arms.
//    Adding fixtures does not move this; extending the route/handler model does.
//  - THE ONE PROJECT WITH BOTH is `webaz-protocol__webaz`: `requireAgentGrantScope`
//    mounted on 23 routes, and thirteen inline decisions in thirteen route files.
//    VG-SMELL-010 fires there and 013 defers, which is the disjointness clause
//    doing what it was written for, on real code, once.
//    ⚠ This used to say VG-SMELL-010 fires there "correctly". That word is
//    withdrawn: the only support for it is the entry in
//    `paper_data/smell010_labels.json`, whose own `labeledBy` field reads
//    "AI-prepared draft, NOT human-reviewed" and whose `humanConfirmed` is
//    false — and `paper_data/` is gitignored, so a reader of this repository
//    cannot see that caveat. What is observable here is that 010 spoke and 013
//    deferred. Whether 010 was right is unadjudicated. The registry's old
//    "spot-checked, real cycles" line was wrong in exactly this way (two of
//    those nine findings were false), so this is a known failure mode of this
//    codebase, not a hypothetical one.
//
// ★ THE TWO PROJECTS THAT (a³) REFUSED, AND WHY THE CONDITION IS NOT OPTIONAL
//
//  - `rohitg00__agentmemory` mounts `scope` and `BM25_SCOPE`. Both satisfy
//    `isAuthzGuardName` — `scope` is a word in `AUTHZ_GUARD_WORD` — and neither
//    is a guard; they are ordinary identifiers that landed in a pre-handler
//    argument position of something the route pattern matched. Requiring the
//    definition to RESOLVE is what refused them, so a bare lexicon word cannot
//    on its own manufacture this rule's premise.
//  - `sahat__hackathon-starter` mounts `isAuthorized` on 7 routes and
//    `authorize` on 4 — a genuine, textbook convention — and (a³) refused it
//    too, because the guards are written `passportConfig.isAuthorized` and the
//    indexer keeps only the last segment while the import binds `passportConfig`.
//    That is a REAL recall miss and it is the price of the previous bullet. It
//    cost nothing here (that project has no inline decision either), and the fix
//    is in the indexer's handling of namespace imports, not in loosening this.
//
// ★ WHAT THIS RULE DELIBERATELY DOES NOT USE
//
// `isPublicByDesignRoute()` from the lexicon is NOT consulted. 011 needs it
// because its accusation ("this route has no guard") is false by construction on
// a login endpoint. 013's accusation is "the decision written here already has a
// home elsewhere", which is equally true on a public route, and the offending
// handler is usually in a different file from its registration so the path is
// frequently unavailable anyway. Skipping it is a smaller claim, not a laxer one.

import type { CodeLocation, Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, mergeMetrics } from '../metrics/index.js';
import { guardKey } from '../symbol-table/index.js';
import { ELEVATED, authzDecisionPatterns, isAuthzGuardName, isTestPath, pathWords } from './authz-lexicon.js';
import { scatteredAuthorization } from './scattered-authorization.js';
import type {
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  ProjectIndex,
  StructureIndex,
} from '../types.js';

// ---------------------------------------------------------------------------
// Thresholds and windows
// ---------------------------------------------------------------------------

/**
 * How many route registrations must name the guard before it is a CONVENTION.
 *
 * Three, matching the "three or more occurrences" shape VG-SMELL-010 takes from
 * design addendum §7.2, and for the mirror-image reason. 010 needs three sites
 * before scattering is a pattern rather than a coincidence; 013 needs three
 * mounts before centralisation is a pattern rather than one route that happened
 * to get a guard. At two the accusation collapses into a matter of taste — a
 * project with `requireAdmin` on two routes and an inline check on a third has
 * not obviously established anything, and telling it that it broke its own
 * convention is telling it about a convention it does not have.
 *
 * Counted as distinct REGISTRATIONS (`filePath` + line), not distinct paths and
 * not distinct files. `router.get('/a', requireAdmin, h)` and
 * `router.delete('/a/:id', requireAdmin, h)` are two decisions to use the guard
 * even though they concern one resource, and two files each mounting it once is
 * the same evidence as one file mounting it twice. What is being counted is how
 * many times somebody chose the guard.
 */
const MIN_GUARDED_ROUTES = 3;

/**
 * How far after the check a refusal may sit and still belong to it.
 *
 * ★ THE REFUSAL REQUIREMENT IS THE SINGLE MOST IMPORTANT DIFFERENCE BETWEEN
 * THIS RULE AND VG-SMELL-010, AND IT IS WHAT MAKES A ONE-SITE FINDING HONEST.
 *
 * Consider the code this rule must never report:
 *
 *     export function listReports(req, res) {
 *       if (req.user.role === 'admin') return res.json(allReports());
 *       return res.json(reportsFor(req.user.id));
 *     }
 *
 * Every positive condition holds — a privilege property, a subject receiver, a
 * registered handler, a guard convention elsewhere in the project — and the code
 * is correct and unremarkable. It BRANCHES on privilege; it does not decide
 * admission. A route-level guard could not replace it, because the guard's only
 * vocabulary is "continue" or "refuse" and this handler wants neither.
 *
 * What 013 accuses is the handler that duplicates the guard's own verb: it
 * refuses. So a 401/403 or a Forbidden/Unauthorized error is REQUIRED, and it
 * has to be close enough that the two are plainly one statement.
 *
 * 400 characters, forward only. Forward because a refusal is the consequence of
 * the check and consequences follow; both `if (bad) return res.status(403)` and
 * `const bad = user.role !== 'admin'; if (bad) return res.status(403)` read
 * forwards. 400 rather than "the enclosing block" because this package has no
 * parser and reconstructing the block from braces here would duplicate
 * `extractBlockAfter` at a granularity it was not written for; 400 characters is
 * four or five lines of formatted TypeScript, which is a refusing `if` with room
 * to log first, and past that the two statements stop obviously belonging to
 * each other. Erring long costs precision, erring short costs recall, and this
 * is the one window where the number is a judgement rather than a measurement —
 * it is written down so a corpus pass can argue with it.
 */
const DENIAL_WINDOW = 400;

/**
 * How far either side of the check an ownership decision suppresses it.
 *
 * ★ THE FAILURE THIS PREVENTS IS THE MOST DANGEROUS ONE LEFT AFTER THE
 * AUTHN/AUTHZ SPLIT.
 *
 *     const doc = await load(req.params.id);
 *     if (doc.ownerId !== req.user.id && !req.user.isAdmin) {
 *       return res.status(403).json({ error: 'forbidden' });
 *     }
 *
 * `!req.user.isAdmin` is a privilege flag on a subject receiver, it refuses, the
 * project has a mounted `requireRole`, and the handler is in another file. Every
 * condition holds and the code is RIGHT: the decision needs `doc`, which does
 * not exist until the handler runs, so no route-level guard can make it. The
 * privilege term is the escape hatch on an ownership rule, not a re-implemented
 * guard.
 *
 * The discriminator is the identity comparison sitting next to it, so the
 * exclusion is a NEIGHBOURHOOD test rather than a same-line test: the ownership
 * term and the privilege term are routinely on different lines of one `if`.
 *
 * 200 characters either side — deliberately smaller than `DENIAL_WINDOW`,
 * because this window is a suppressor and a suppressor that reaches too far
 * silences unrelated code. Two hundred characters is roughly the multi-line
 * condition itself plus its opening brace.
 *
 * ★ THE `isOwner` TRAP, AND WHICH SIDE OF IT THIS RULE CHOSE.
 *
 * `AUTHZ_PROPERTY` in the lexicon contains `isOwner`/`is_owner`, so the FLAG
 * pattern matches both `if (!user.isOwner)` — a boolean privilege flag on the
 * subject, which is exactly what this rule is about — and the identity shape
 * above. THE PRIVILEGE FLAG IS KEPT. The exclusion is written against the
 * id-vs-id COMPARISON (`IDENTITY_COMPARISON`), never against the property name,
 * because dropping `isOwner` from the vocabulary would be divergence from the
 * shared lexicon of exactly the kind that made VG-SMELL-041 fail — and it would
 * discard the true case in order to avoid a false one that a more specific test
 * already catches. `if (!doc.isOwner)` is excluded too, but by `SUBJECT_WORD`
 * rather than here: `doc` does not name a subject.
 */
const OWNERSHIP_NEIGHBOURHOOD = 200;

// ---------------------------------------------------------------------------
// Vocabularies
// ---------------------------------------------------------------------------

/**
 * Receiver words that make the thing being read a SUBJECT.
 *
 * ★ A POSITIVE REQUIREMENT WHERE VG-SMELL-010 USES A BLOCKLIST, AND THE SWAP IS
 * DELIBERATE.
 *
 * 010 discovered by evaluation over real repositories that `role` is also the
 * OpenAI chat-completion message field, and defends itself with
 * `CHAT_ROLE_LITERAL` (`assistant`/`system`/`tool`/…) plus a `MESSAGE_RECEIVER`
 * blocklist. That vocabulary stayed in 010 rather than moving to
 * `authz-lexicon.ts`, so a second consumer has two options: copy it, or ask a
 * different question. Copying is what the lexicon's own header describes as "the
 * 041 failure mode with a longer fuse" — two lists in two files, drifting, with
 * neither mentioning the other — so this file asks the different question.
 *
 * Requiring the receiver to NAME a subject subsumes the blocklist and is
 * strictly narrower: `m.role`, `msg.role`, `choice.delta.role`, `element.role`
 * (ARIA), `node.role` (state machines), `row.role` (a database column) all fail
 * it without any of them having to be enumerated, and so does every chat-shaped
 * receiver nobody has thought of yet. What it costs is `entry.role !== 'admin'`
 * inside `for (const entry of users)` — a real privilege check whose receiver is
 * a loop variable. 010 restored that case on purpose after an over-eager
 * receiver test discarded it; 013 gives it up on purpose, because 010 needs
 * three sites to speak and 013 needs one, and a rule that accuses a single line
 * has to be sure which line it is looking at.
 *
 * Matched by whole word through `pathWords`, so `currentUser` → `current`+`user`
 * lands, `req.user` lands twice over, and `userAgent` — which the symbol table
 * documents as attacker-controlled and semantically the opposite of a principal
 * — lands on `user` as well. That last one is accepted: `userAgent.role` is not
 * a construction that occurs, and narrowing the set to exclude it would cost
 * more than it buys.
 */
const SUBJECT_WORD: ReadonlySet<string> = new Set([
  'user',
  'users',
  'req',
  'request',
  'session',
  'account',
  'principal',
  'actor',
  'caller',
  'subject',
  'requester',
  'member',
  'viewer',
  'profile',
  'identity',
  'claims',
  'auth',
  'token',
  'jwt',
  'me',
  'self',
]);

/**
 * Path words that mean "authorization is SUPPOSED to be written here".
 *
 * A check inside a middleware, a guard, a policy or an ACL module is the
 * centralised design this rule is recommending; reporting it would accuse the
 * codebases that did the right thing, which is the mistake
 * `scattered-authorization.ts` calls "the single most important exclusion in the
 * file". 013 needs the same exclusion for the same reason and additionally
 * because its own premise creates the hazard: the guard whose existence licenses
 * the finding is itself a body full of privilege comparisons that refuse
 * requests.
 *
 * Matched against EVERY word of the path, file name included, not only the
 * directory segments. 010's `isRoutingLayer` drops the last segment because it
 * is reading PLACEMENT (`src/userRoutes.ts` declares routes without being a
 * routing layer). This set is an EXCLUSION, and an exclusion that misses
 * `src/authMiddleware.ts` in a flat project fires on the guard itself. Whole-path
 * matching is the quiet direction; the recall it costs is a handler that happens
 * to live under `src/auth/`, which is a handler nobody is surprised to see doing
 * authorization.
 *
 * `pathWords` gives word matching for free, so `src/authors/list.ts` and
 * `lib/authority.ts` are untouched — see the counterexample on that function.
 */
const AUTHORIZATION_HOME_WORD: ReadonlySet<string> = new Set([
  'middleware',
  'middlewares',
  'guard',
  'guards',
  'policy',
  'policies',
  'permission',
  'permissions',
  'auth',
  'authn',
  'authz',
  'authentication',
  'authorization',
  'authorisation',
  'authorize',
  'authorise',
  'acl',
  'acls',
  'rbac',
  'security',
  'interceptor',
  'interceptors',
]);

// ---------------------------------------------------------------------------
// Patterns
//
// Every quantifier below has a ceiling and horizontal whitespace is
// `[^\S\r\n]{0,4}` rather than `\s*`, for the reason `authz-lexicon.ts` states
// at length: unbounded whitespace next to another quantifier is the shape that
// produced this project's A1 ReDoS findings, and `scripts/sec-a1-catalog.mjs`
// censuses `packages/rules` only — cross-file rule patterns are outside it, so
// the bound is the only protection the three-second contract has here.
// ---------------------------------------------------------------------------

/**
 * A refusal expressed as an HTTP status number.
 *
 * `401` and `403` only. `400` and `422` are validation, `404` is the shape a
 * careful handler uses to avoid confirming that a resource exists — and while
 * that IS an authorization outcome, it is indistinguishable from an ordinary
 * "not found" and admitting it would make almost every handler in existence
 * satisfy this condition.
 *
 * Deliberately NOT anchored to `res.status(` / `sendStatus(` / `reply.code(`.
 * The framework surface is large (`throw new HttpException(msg, 403)`,
 * `createError(403)`, `ctx.throw(403)`, `res.statusCode = 401`) and an
 * enumeration of it would be a list of the frameworks whose users get a finding.
 * A bare `401`/`403` inside a handler body, within four lines of a privilege
 * check on a subject, is a refusal; the word boundaries keep `1403`, `4031` and
 * `HTTP_403` out, which is enough to stop it matching arbitrary numbers.
 *
 * Read from the BLANKED body, so a status code inside a user-facing string or a
 * comment does not count.
 */
const DENIAL_STATUS = /\b(?:401|403)\b/;

/**
 * A refusal expressed as a named error, exception, or status constant.
 *
 * Two spellings of one idea: PascalCase for the class (`ForbiddenError`,
 * `UnauthorizedException`, `AccessDeniedError`, and bare `Forbidden` for
 * `HttpStatus.Forbidden`), SCREAMING_CASE for the constant
 * (`StatusCodes.FORBIDDEN`, `ACCESS_DENIED`).
 *
 * Case-SENSITIVE on purpose, and this is the whole reason there are two patterns
 * instead of one with an `i` flag. Case-insensitively, `forbiddenTags`,
 * `unauthorizedUsers` and any ordinary lowercase identifier containing the word
 * would satisfy a condition that is REQUIRED for the finding to fire — a loose
 * positive condition is a false positive, not a missed one. The two casings
 * above are the ones a refusal is actually written in.
 *
 * The optional suffix group is a single bounded alternation with nothing nested
 * under a quantifier.
 */
const DENIAL_NAME =
  /\b(?:Forbidden|Unauthorized|Unauthorised|AccessDenied|PermissionDenied|NotAuthorized|NotAuthorised|NotPermitted)(?:Error|Exception|Response|Result|Fault)?\b|\b(?:FORBIDDEN|UNAUTHORIZED|UNAUTHORISED|ACCESS_DENIED|PERMISSION_DENIED|NOT_AUTHORIZED|NOT_PERMITTED)\b/;

/**
 * An identity comparison: the shape of an OWNERSHIP decision.
 *
 * Two patterns because the id can be on either side — `doc.ownerId !==
 * req.user.id` and `req.user.id !== doc.ownerId` are one idea written twice —
 * and one pattern with an alternation over both sides would need an unbounded
 * middle to join them.
 *
 * The property list is closed for the same reason `AUTHZ_PROPERTY` is: a
 * substring test for `id` matches `valid`, `paid`, `uuid`, `hidden`, and every
 * identifier that happens to end in those two letters, which would suppress the
 * whole rule. `\b` after the property is what keeps `ownerIdentity` out.
 *
 * See `OWNERSHIP_NEIGHBOURHOOD` for why this suppresses rather than reports.
 */
const OWNERSHIP_PROPERTY =
  '(?:id|_id|uid|guid|uuid|userId|user_id|ownerId|owner_id|authorId|author_id|creatorId|creator_id|createdBy|created_by|accountId|account_id|tenantId|tenant_id|orgId|org_id|memberId|member_id)';

const IDENTITY_COMPARISON: readonly RegExp[] = [
  new RegExp(String.raw`[\w$][\w$.]{0,40}\.${OWNERSHIP_PROPERTY}\b[^\S\r\n]{0,4}(?:===|!==|==|!=)`),
  new RegExp(String.raw`(?:===|!==|==|!=)[^\S\r\n]{0,4}[\w$][\w$.]{0,40}\.${OWNERSHIP_PROPERTY}\b`),
];

/**
 * Decorator names that register a route.
 *
 * Byte-identical to the list in `scattered-authorization.ts`'s `handlersOf`.
 * Nest (`@Get()`), Flask (`@app.route`) and FastAPI register handlers with no
 * call site to observe, so without this the population would be "Express only"
 * while the rule's `languages` claims otherwise.
 */
const ROUTE_DECORATOR = /^(?:get|post|put|patch|delete|head|options|all|route|api_route|websocket)$/i;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/** 1-based line/column of an offset. Same convention as every other producer. */
function positionOf(content: string, offset: number): { line: number; column: number } {
  let line = 1;
  let lastBreak = -1;
  for (let i = 0; i < offset && i < content.length; i += 1) {
    if (content[i] === '\n') {
      line += 1;
      lastBreak = i;
    }
  }
  return { line, column: offset - lastBreak };
}

/** Trim the source text at an offset to something printable next to a path. */
function evidenceAt(content: string, offset: number): string {
  const lineEnd = content.indexOf('\n', offset);
  const end = lineEnd === -1 ? content.length : lineEnd;
  return content.slice(offset, Math.min(end, offset + 120)).replace(/\r$/, '').trim();
}

/** Whether any word of a path says "authorization belongs here". */
function isAuthorizationHome(filePath: string): boolean {
  for (const word of pathWords(filePath)) {
    if (AUTHORIZATION_HOME_WORD.has(word)) return true;
  }
  return false;
}

/** Whether a receiver expression names a subject. See `SUBJECT_WORD`. */
function isSubjectReceiver(receiver: string): boolean {
  for (const word of pathWords(receiver)) {
    if (SUBJECT_WORD.has(word)) return true;
  }
  return false;
}

/**
 * Where a name used in `from` is defined, following its import if there is one.
 *
 * ★ A DELIBERATE MIRROR OF `linkRouteHandlers`'s PRIVATE `definingFile`, and the
 * duplication is the lesser evil rather than an oversight.
 *
 * That function is not exported, and exporting it would mean editing
 * `dependency-graph/index.ts`. The reasoning it carries is what matters and is
 * reproduced here so it cannot be lost: the binding is resolved through the
 * IMPORT GRAPH rather than by matching names project-wide, because `requireRole`
 * may be defined in three files and the one that was mounted is the one the
 * mounting file imported. Matching on the name alone would attribute the guard
 * to a file that has nothing to do with it, and this rule then asks whether the
 * handler sits in that file — so a wrong answer here is a wrong condition (c),
 * which is a false positive.
 *
 * Returning `undefined` when nothing resolves is load-bearing: a guard imported
 * from an npm package (`import { requirePermission } from '@acme/authz'`) is
 * certainly defined in a different file from the handler, and this rule still
 * goes silent about it, because "certainly" is not the same as "checked" and the
 * finding would cite a location that does not exist in the repository.
 */
function definingFile(
  from: StructureIndex,
  name: string,
  project: ProjectIndex,
): StructureIndex | undefined {
  for (const edge of from.imports) {
    if (edge.resolvedFile && edge.names.includes(name)) {
      const target = project.structures.get(edge.resolvedFile);
      if (target?.symbols.some((s) => s.name === name)) return target;
    }
  }
  return from.symbols.some((s) => s.name === name) ? from : undefined;
}

/**
 * Handler bodies to search, per file.
 *
 * Byte-for-byte the same population `scattered-authorization.ts` uses, and
 * reproduced rather than shared for the same reason `definingFile` is: the
 * original is private. The three ways in are structural — written inline at a
 * registration, named as the handler argument of one, or carrying a routing
 * decorator — and the two exclusions are the ones that keep a guard's own body
 * out of a rule about handlers.
 *
 * The `isInsideGuard` exclusion is the important one and it uses the symbol
 * table, whose strongest signal is behavioural: a symbol observed in a route's
 * pre-handler position anywhere in the project is a guard whatever it is called.
 */
function handlersOf(structure: StructureIndex, project: ProjectIndex): IndexedSymbol[] {
  return structure.symbols.filter((s) => {
    if (project.symbols.guards.has(guardKey(s.filePath, s.name))) return false;
    if (s.kind === 'middleware') return false;
    if (s.kind === 'route-handler') return true;
    const decorators = s.decorators ?? [];
    return decorators.some((d) => ROUTE_DECORATOR.test(d.split('.').pop() ?? ''));
  });
}

// ---------------------------------------------------------------------------
// Condition (a) — the project already centralised this
// ---------------------------------------------------------------------------

/**
 * An authorization guard the project has demonstrably adopted.
 *
 * ★ EXPORTED so a negative fixture can assert its PREMISE before it asserts
 * silence. `design-smells-crossfile/index.ts` records that VG-SMELL-041 shipped
 * with forty passing tests and 0% precision; a negative test that passes because
 * the fixture stopped containing what it was written to contain is how that
 * happens. A test for `smell-013-neg-authn-only` can now state "this project
 * mounts one guard on four routes and NONE of them is an authorization guard",
 * which fails loudly if somebody renames `authenticate` to `authorize`.
 */
export interface EstablishedGuard {
  /** The identifier as it appears in the middleware position. */
  name: string;
  /** Repo-relative path of the file that defines it. */
  definitionFile: string;
  /** 1-based line of the definition. */
  definitionLine: number;
  /** Source text of the definition head, for the finding's related location. */
  definitionEvidence: string;
  /** How many route registrations name it. See `MIN_GUARDED_ROUTES`. */
  routeCount: number;
}

/**
 * Every authorization guard this project has adopted as a convention.
 *
 * Condition (a) of the rule, and the one that makes it safe. Four requirements,
 * in the order they are cheapest to refuse:
 *
 *  1. The name is an AUTHORIZATION guard name (`isAuthzGuardName`), not an
 *     authentication one. This is the condition the whole rule stands on; see
 *     the file header and `AUTHN_GUARD_WORD` in the lexicon.
 *  2. It appears in the middleware position of at least `MIN_GUARDED_ROUTES`
 *     route registrations, outside test paths.
 *  3. Its definition resolves through the import graph to a file in this
 *     project, and every mount agrees on which file that is.
 *  4. The symbol table also judges the definition to be a guard.
 *
 * ★ (3) IS NOT PLUMBING — IT IS WHAT STOPS A BARE LEXICON WORD FROM BECOMING A
 * PREMISE, and the corpus is why it is written down here rather than treated as
 * an implementation detail. `rohitg00__agentmemory` in `paper_data/corpus1k`
 * puts `scope` and `BM25_SCOPE` in a pre-handler argument position four and six
 * times. `scope` is a word in `AUTHZ_GUARD_WORD`, so `isAuthzGuardName` says yes
 * and conditions (1) and (2) both hold on a project that has no guard at all.
 * Requiring the name to resolve to a definition in this repository is the only
 * thing that refused it. The full funnel is in the file header.
 *
 * ★ WHY (4) IS HERE EVEN THOUGH IT IS NEARLY ALWAYS IMPLIED.
 *
 * `buildSymbolTable` admits a name as a guard wherever it is known once it has
 * been used as middleware anywhere, so (2) very nearly implies (4). It is
 * checked anyway because the two are answers to different questions — "was this
 * mounted" versus "does the project's symbol table call this a checkpoint" — and
 * a future change to either producer that made them disagree should make this
 * rule go quiet rather than silently start reasoning from a fact that is no
 * longer true. The cost is one set lookup.
 *
 * ★ WHAT IS KNOWN TO BE MISSED, stated rather than discovered later.
 *
 * `app.use(requireAdmin)` and `router.use('/admin', requireAdmin)` do NOT count.
 * The structure indexer puts the last argument of a registration in the HANDLER
 * position, so a guard mounted with no handler after it never reaches
 * `middlewareNames` — `linkRouteHandlers` compensates by promoting it to the
 * `middleware` ROLE, but the count this function needs is not recoverable from
 * that. A project that mounts its authorization guard globally therefore
 * produces no findings here. That is the quiet direction and it is a real miss:
 * global mounting is arguably the strongest possible form of the convention this
 * rule wants to see. Fixing it means teaching `RouteBinding` to distinguish
 * "mounted alone" from "registered as a handler", which is an indexer change and
 * belongs to whoever needs it, not to a rule working around it.
 */
export function establishedAuthzGuards(project: ProjectIndex): EstablishedGuard[] {
  /** guard name → the `filePath:line` of every registration that names it. */
  const mounts = new Map<string, Set<string>>();
  /** guard name → the structures that mounted it, for import resolution. */
  const mountedFrom = new Map<string, StructureIndex[]>();

  // Deterministic order: the resolution below takes the first agreeing answer,
  // and an unsorted walk would make which file that was depend on Map insertion
  // order, which depends on the filesystem.
  for (const filePath of [...project.structures.keys()].sort()) {
    if (isTestPath(filePath)) continue;
    const structure = project.structures.get(filePath)!;
    // PER-FILE language filter, the lesson `scattered-authorization.ts` records:
    // `runCrossFileRules` gates at the PROJECT level, which is the right
    // question for whether to run a rule and the wrong one for which files it
    // may read. A polyglot repository would otherwise hand this rule Python.
    if (!inlineAuthorizationLogic.languages.includes(structure.language)) continue;

    for (const route of structure.routes) {
      for (const name of route.middlewareNames) {
        if (!isAuthzGuardName(name)) continue;
        let seen = mounts.get(name);
        if (!seen) {
          seen = new Set();
          mounts.set(name, seen);
          mountedFrom.set(name, []);
        }
        seen.add(`${filePath}:${route.line}`);
        mountedFrom.get(name)!.push(structure);
      }
    }
  }

  const established: EstablishedGuard[] = [];
  for (const [name, registrations] of [...mounts.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    if (registrations.size < MIN_GUARDED_ROUTES) continue;

    let definition: StructureIndex | undefined;
    let ambiguous = false;
    for (const from of mountedFrom.get(name) ?? []) {
      const resolved = definingFile(from, name, project);
      if (!resolved) continue;
      if (definition && definition.filePath !== resolved.filePath) {
        // One name, two definitions, mounted from two places. That is not one
        // convention, it is two guards that happen to share a spelling, and
        // condition (c) — "the guard is defined in a different file from the
        // handler" — has no single answer. Refuse rather than pick.
        ambiguous = true;
        break;
      }
      definition ??= resolved;
    }
    if (ambiguous || !definition) continue;
    if (!project.symbols.guards.has(guardKey(definition.filePath, name))) continue;

    const symbol = definition.symbols.find((s) => s.name === name);
    if (!symbol) continue;
    const source = project.files.find((f) => f.filePath === definition!.filePath);
    if (!source) continue;

    established.push({
      name,
      definitionFile: definition.filePath,
      definitionLine: symbol.startLine,
      definitionEvidence: (source.lines[symbol.startLine - 1] ?? '').trim().slice(0, 120),
      routeCount: registrations.size,
    });
  }

  return established;
}

// ---------------------------------------------------------------------------
// Condition (b) — an inline authorization decision inside a handler
// ---------------------------------------------------------------------------

/**
 * One inline authorization decision, after every per-site negative has run.
 *
 * ★ EXPORTED, with `inlineAuthorizationDecisions`, for the same reason
 * `EstablishedGuard` is: a negative fixture has to be able to say WHICH half of
 * the rule refused it. `smell-013-neg-authn-only` asserts that the decision was
 * found and the guard premise failed; `smell-013-neg-no-denial` asserts that the
 * guard premise held and the decision was not found. Two fixtures asserting only
 * "no findings" would pass identically if the rule stopped working altogether.
 */
export interface InlineDecision {
  filePath: string;
  /** 1-based line of the start of the matched check. */
  line: number;
  column: number;
  /** Source text of the check, from the original content. */
  evidence: string;
  /** Receiver + property + operator, for reporting how many spellings appear. */
  signature: string;
  /** A privilege word in the text of the check. Raises severity to `high`. */
  elevated: boolean;
  handlerName: string;
}

/** Whether a refusal follows the check closely enough. See `DENIAL_WINDOW`. */
function refusesAfter(blanked: string, checkStart: number, bodyEnd: number): boolean {
  const window = blanked.slice(checkStart, Math.min(bodyEnd, checkStart + DENIAL_WINDOW));
  return DENIAL_STATUS.test(window) || DENIAL_NAME.test(window);
}

/** Whether an ownership decision sits next to the check. See `OWNERSHIP_NEIGHBOURHOOD`. */
function decidesOwnershipNear(
  blanked: string,
  checkStart: number,
  bodyStart: number,
  bodyEnd: number,
): boolean {
  const from = Math.max(bodyStart, checkStart - OWNERSHIP_NEIGHBOURHOOD);
  const to = Math.min(bodyEnd, checkStart + OWNERSHIP_NEIGHBOURHOOD);
  const window = blanked.slice(from, to);
  for (const pattern of IDENTITY_COMPARISON) {
    if (pattern.test(window)) return true;
  }
  return false;
}

/**
 * Every inline authorization decision in the project that survives the per-site
 * negatives, BEFORE the guard premise and condition (c) are applied.
 *
 * ★ THE SPLIT IS THE CONTRACT. Everything decided here is a property of the SITE
 * — is it a privilege read, on a subject, that refuses, and is it in a place
 * where authorization does not belong. Everything decided in `analyze` is a
 * property of the PROJECT — is there a guard, is it an authorization guard, is
 * it somewhere else. A negative fixture can therefore pin exactly one of the two
 * halves, which is what stops a negative from passing vacuously.
 *
 * The scan reads the BLANKED body, so a privilege comparison written in a
 * comment or inside a string is not evidence of anything. Offsets from the
 * blanked copy are valid in the original because every blanker in
 * `@vibeguard/rules` is length-preserving, so `evidence` and the elevated-word
 * test read the real text at the same positions.
 */
export function inlineAuthorizationDecisions(project: ProjectIndex): readonly InlineDecision[] {
  const found: InlineDecision[] = [];

  for (const filePath of [...project.structures.keys()].sort()) {
    // ── Negative: test scaffolding. ────────────────────────────────────────
    // A fixture that deliberately contains the smell is not a finding about the
    // project, and a test harness that re-derives an admin check is describing a
    // test. Shared with every rule in this directory through the lexicon.
    if (isTestPath(filePath)) continue;
    // ── Negative: authorization's own home. See `AUTHORIZATION_HOME_WORD`. ──
    if (isAuthorizationHome(filePath)) continue;

    const structure = project.structures.get(filePath)!;
    if (!inlineAuthorizationLogic.languages.includes(structure.language)) continue;
    const source = project.files.find((f) => f.filePath === filePath);
    if (!source) continue;

    for (const handler of handlersOf(structure, project)) {
      const body = structure.blanked.slice(handler.bodyStart, handler.bodyEnd);
      const seenOffsets = new Set<number>();

      for (const pattern of authzDecisionPatterns()) {
        pattern.lastIndex = 0;
        for (let m = pattern.exec(body); m; m = pattern.exec(body)) {
          if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
          const groups = m.groups ?? {};
          const prop = groups.prop;
          if (!prop) continue;

          const propOffsetInMatch = m[0].lastIndexOf(prop);
          const propOffset = handler.bodyStart + m.index + Math.max(0, propOffsetInMatch);
          // The three patterns overlap — `user.isAdmin === false` matches both
          // the comparison and the flag shape — and counting one check twice
          // would inflate the number a reviewer is being asked to trust.
          if (seenOffsets.has(propOffset)) continue;
          seenOffsets.add(propOffset);

          // ── Negative: a method CALL is delegation, not an inline check. ────
          //
          // `auth.isAdmin(user)` is the well-factored shape this rule exists to
          // recommend; counting it inverts the rule's meaning. Byte-identical to
          // the test `scattered-authorization.ts`'s `checksIn` performs, down to
          // the six-character lookahead, because the two rules must agree about
          // what delegation looks like — 010 found this one by evaluation on a
          // real repository whose handlers all delegate to one `auth_mgr`.
          const afterProp = propOffset + prop.length;
          if (/^[^\S\r\n]{0,4}\(/.test(structure.blanked.slice(afterProp, afterProp + 6))) continue;

          // ── Negative: the receiver must name a subject. `SUBJECT_WORD`. ────
          const receiver = groups.recv ?? '';
          if (!isSubjectReceiver(receiver)) continue;

          const checkStart = handler.bodyStart + m.index;

          // ── Negative: no ownership decision alongside. See the constant. ───
          if (
            decidesOwnershipNear(structure.blanked, checkStart, handler.bodyStart, handler.bodyEnd)
          ) {
            continue;
          }

          // ── Positive, and last because it is the most expensive: the check
          //    has to REFUSE. See `DENIAL_WINDOW` for the correct code this
          //    keeps the rule away from.
          if (!refusesAfter(structure.blanked, checkStart, handler.bodyEnd)) continue;

          const text = evidenceAt(source.content, checkStart);
          const { line, column } = positionOf(source.content, checkStart);
          const shortReceiver = receiver.split('.').pop() ?? '';
          found.push({
            filePath,
            line,
            column,
            evidence: text,
            signature: `${shortReceiver}.${prop}${groups.op ? ` ${groups.op}` : ''}${
              groups.call ? `.${groups.call}()` : ''
            }`,
            // Matched against the ORIGINAL text, not the blanked copy: the
            // privilege word almost always lives inside the string literal being
            // compared against, which blanking erases by design.
            elevated: ELEVATED.test(text),
            handlerName: handler.name,
          });
        }
      }
    }
  }

  return found;
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;

  // ── (a) THE PREMISE, FIRST AND CHEAPEST. ─────────────────────────────────
  //
  // A project with no adopted authorization guard has nothing for a handler to
  // have duplicated, and this is where the layered `authenticate`-only
  // architecture — the majority of correct Express code — leaves. Routes are
  // already indexed, so this costs a walk over an array and returns empty for
  // almost every repository.
  const guards = establishedAuthzGuards(project);
  if (guards.length === 0) return [];

  // ── MUTUAL EXCLUSION WITH VG-SMELL-010. ──────────────────────────────────
  //
  // ★ ASKED BY CALLING 010, NOT BY COPYING ITS THRESHOLDS.
  //
  // 010 fires when authorization is decided inline in ≥ 3 handlers across ≥ 2
  // files. When it does, it has already told the user that the policy has no
  // single home, and a 013 finding on one of the same lines adds nothing except
  // a second marker in the same gutter — which reads as two problems where there
  // is one. So 013 goes silent whenever 010 speaks.
  //
  // `MIN_SITES` and `MIN_FILES` are private to 010, and the obvious alternative
  // was to write `3` and `2` here. That is two copies of a threshold in two
  // files with neither mentioning the other, which is the divergence the
  // `authz-lexicon.ts` extraction exists to make impossible; the day 010 moves a
  // threshold, the copy would make the two rules overlap again with every test
  // still green. Calling `analyze` asks the actual question and cannot drift.
  //
  // The cost is that 010's site scan runs twice per project. It is paid only
  // after the premise above has held, which on real corpora is rare, and 010's
  // scan is bounded by the same handler bodies this rule is about to read
  // anyway.
  //
  // ★ WHAT THIS GIVES UP: a project where authorization is scattered in one
  // area AND a guard convention exists in another gets 010's finding only. That
  // is the quiet direction, and 010's message is the more urgent of the two.
  //
  // ★ WHAT IT BUYS BEYOND TIDINESS: it BOUNDS this rule's output. Every site
  // this rule can cite is also a site 010 would have counted (the population
  // here is `handlersOf` ∩ `authzDecisionPatterns` minus four extra negatives),
  // so surviving 010's silence means < 3 sites, or any number of sites confined
  // to a single file. Findings are emitted per file, so a project can receive at
  // most two of them.
  if (scatteredAuthorization.analyze(ctx).length > 0) return [];

  // ── (b) THE SITES. ───────────────────────────────────────────────────────
  const decisions = inlineAuthorizationDecisions(project);
  if (decisions.length === 0) return [];

  // ── Group by file, then apply (c). ───────────────────────────────────────
  //
  // ★ ONE FINDING PER FILE, NOT PER SITE AND NOT PER HANDLER.
  //
  // Per site would report the same duplicated policy twice for a handler that
  // checks `role` and `permissions` in one condition. Per handler is defensible
  // — the fix is local to a handler — and was rejected on the bound above: a
  // single controller with six inline checks would produce six findings, and
  // 010's silence guarantees nothing about how many handlers one file holds.
  // Per file, the maximum a project can receive is two, and the sentence the
  // finding makes ("this file decides authorization by hand although the project
  // has a guard") is true at exactly that granularity.
  const byFile = new Map<string, InlineDecision[]>();
  for (const decision of decisions) {
    const list = byFile.get(decision.filePath);
    if (list) list.push(decision);
    else byFile.set(decision.filePath, [decision]);
  }

  const findings: CrossFileFinding[] = [];

  for (const [filePath, sites] of [...byFile.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    // ── (c) The guard must be defined SOMEWHERE ELSE. ──────────────────────
    //
    // A privilege comparison inside the file that defines the guard is the guard
    // doing its job. `isAuthorizationHome` already excluded the conventional
    // placements (`middleware/`, `guards/`, `auth/`); this catches the guard
    // that lives somewhere unconventional, and it is the condition the lane
    // specification names explicitly.
    //
    // Among the guards defined elsewhere, the one with the most mounts is cited:
    // it is the convention the project follows most, and ties break on the name
    // so the citation cannot move between runs.
    const elsewhere = guards
      .filter((g) => g.definitionFile !== filePath)
      .sort((a, b) => (b.routeCount - a.routeCount) || (a.name < b.name ? -1 : 1));
    const guard = elsewhere[0];
    if (!guard) continue;

    sites.sort((a, b) => a.line - b.line || a.column - b.column);
    const primary = sites[0]!;

    /**
     * Severity, per the lane specification: `high` on elevated privilege,
     * `medium` otherwise.
     *
     * ∃ over the file's sites, the same aggregation VG-SMELL-010 uses and for
     * the same reason: one finding is a statement about a policy written in N
     * places, and the dangerous property of that policy is the worst thing any
     * one of its sites does. A file that re-derives an `admin` decision in one
     * handler and a `scopes` decision in another is exactly as bad as if both
     * were `admin`.
     *
     * The Security Context Boost conditions VG-SMELL-010 carries (`securityPath`
     * / `mutatesData`) are deliberately NOT reproduced. 010's own comments
     * record that `securityPath` measures 20.4% and `routingLayer` 95.4% of its
     * sites — the second being "a constant with five exceptions" — and this
     * rule's population is narrower still: `isAuthorizationHome` has already
     * removed every file whose path carries `auth`, `permission`, `security` or
     * `middleware`, so condition ① would be false by construction for nearly
     * every site that reaches here. A boost that cannot fire is a severity field
     * pretending to have two values.
     */
    const elevated = sites.some((s) => s.elevated);
    const severity: Severity = elevated ? 'high' : 'medium';

    /**
     * Confidence: `medium`, always, and the flatness is the decision.
     *
     * Design addendum §10.2 grants `high` for cross-file confirmation, and
     * cross-file confirmation is this rule's firing condition — so read
     * literally, every finding would be `high` and the field would carry no
     * information. That is the same argument `scattered-authorization.ts` makes
     * before reserving `high` for a pattern emphatic enough that lexical
     * uncertainty stops mattering (five sites over three files). 013 has no such
     * band available: its output is bounded at two files by the 010 exclusion
     * above, so any "emphatic" threshold would either never fire or fire always.
     *
     * The alternative considered and refused was `high` when the offending
     * handler's own route registration was located and found not to name the
     * guard — a complete cross-file picture. It is refused because locating the
     * registration is itself an inference (`definingFile` can fail, and fails
     * silently on namespace imports and dynamic routers), so the confidence
     * would encode how well the indexer resolved the project rather than how
     * likely the finding is to be true.
     */
    const confidence: Confidence = 'medium';

    const handlers = [...new Set(sites.map((s) => s.handlerName))];
    const spellings = new Set(sites.map((s) => s.signature));

    const toLocation = (s: InlineDecision): CodeLocation => ({
      filePath: s.filePath,
      startLine: s.line,
      startColumn: s.column,
      evidence: s.evidence,
    });

    /**
     * The guard's definition is cited as a related location.
     *
     * Not decoration: the whole finding is a relationship between two places,
     * and a reader who cannot see the second one has to take on trust that it
     * exists. `CodeLocation` is what SARIF links and what the VS Code extension
     * offers "go to related location" for, so this is the difference between
     * "there is a guard somewhere" and one click.
     */
    const guardLocation: CodeLocation = {
      filePath: guard.definitionFile,
      startLine: guard.definitionLine,
      evidence: guard.definitionEvidence,
    };

    findings.push({
      ruleId: 'VG-SMELL-013',
      title: 'Inline Authorization Logic',
      description:
        `${sites.length} authorization ${sites.length === 1 ? 'decision is' : 'decisions are'} ` +
        `made inline in ${handlers.length === 1 ? 'the handler' : `${handlers.length} handlers`} of ` +
        `this file, and ${sites.length === 1 ? 'it refuses' : 'they refuse'} the request directly. ` +
        `The project already centralises that decision: \`${guard.name}\`, defined in ` +
        `${guard.definitionFile}, is mounted on ${guard.routeCount} route registrations. ` +
        `The policy therefore exists in ${1 + spellings.size} places that cannot be changed ` +
        `together — widening \`${guard.name}\` leaves ` +
        `${sites.length === 1 ? 'this check' : 'these checks'} behind, and the divergence is ` +
        `invisible at the place routes are declared.`,
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      /**
       * `file`, not `project` and not `symbol`.
       *
       * `DesignSmellScope` is documented as "the unit the finding would have to
       * be fixed at". Not `project`: unlike VG-SMELL-010 this is resolved by one
       * edit — delete the checks and name the existing guard at the
       * registration. Not `symbol`: the finding aggregates every handler in the
       * file, so a symbol-scoped suppression would silence a claim wider than
       * the symbol. `file` is also what makes `vibeguard:disable-next-line` a
       * coherent request here, which it explicitly is not for a project-scoped
       * finding.
       */
      scope: 'file',
      filePath: primary.filePath,
      startLine: primary.line,
      startColumn: primary.column,
      evidence: [
        ...sites.map((s) => `${s.filePath}:${s.line} ${s.evidence}`),
        `${guard.definitionFile}:${guard.definitionLine} ${guard.definitionEvidence}`,
      ],
      primaryLocation: toLocation(primary),
      relatedLocations: [...sites.slice(1).map(toLocation), guardLocation],
      /**
       * `duplicatedCheckCount` counts the inline sites PLUS the guard.
       *
       * The field is documented as "how many places repeat the same check", and
       * the guard is one of those places — it is the place the check is supposed
       * to live. Reporting only the inline sites would say `1` for the canonical
       * finding, which reads as "one place" and is the opposite of the claim.
       * The count stays equal to the number of locations the finding carries, so
       * a reader can check it by counting the rows, which is the invariant
       * VG-SMELL-010's test asserts for its own findings.
       *
       * The fan numbers come from `metrics-calculator` rather than being counted
       * here, so that a report carrying both a 010 and an 021 finding cannot
       * disagree with itself about what `fanIn` means.
       */
      metrics: mergeMetrics(fanMetrics(primary.filePath, project.graph), {
        duplicatedCheckCount: sites.length + 1,
      }),
      /**
       * `containsAuthorizationLogic` is the only flag set, and the restraint is
       * the same one VG-SMELL-010 documents: the other five flags in the schema
       * describe what the implicated code CONTAINS, and this rule established
       * exactly one of those things.
       */
      securityContext: { containsAuthorizationLogic: true },
      tags: ['design-smell', 'cross-file', 'authorization'],
      remediation: {
        why:
          'The same authorization decision now exists in the guard and in this file. ' +
          'Nothing keeps them in agreement: widening or tightening the guard changes ' +
          'every route that uses it and silently leaves this handler on the old policy, ' +
          'and a reader auditing the route table cannot see that this endpoint decides ' +
          'anything at all.',
        how:
          `Delete the inline check and name \`${guard.name}\` in the middleware position of ` +
          'this endpoint\'s registration, so the endpoint\'s policy is visible where the ' +
          'routes are declared. If the decision genuinely needs data the guard cannot ' +
          'have, give the guard a parameter rather than re-deriving the privilege.',
        exampleFix:
          `router.get('/reports', ${'requireRole'}('admin'), listReports);\n` +
          '// listReports no longer decides authorization; the registration does.',
      },
    });
  }

  return findings;
}

/**
 * ★ TS/JS ONLY, AND ENFORCED — `runCrossFileRules` reads this field.
 *
 * The same decision VG-SMELL-010 arrived at the hard way and wrote down: its
 * Python arm worked, fired correctly on a Flask fixture, and was removed anyway,
 * because not one negative fixture was written in Python and the untested half
 * was the half that matters — whether the rule stays SILENT on well-factored
 * code. That argument is stronger here, not weaker. Every framework-specific
 * mechanism 013 depends on is expressed differently outside TS/JS: FastAPI
 * centralises authorization through `Depends(require_admin)`, Django through a
 * decorator or a URLconf wrapper, Flask through `before_request`. None of them
 * put a name in `RouteBinding.middlewareNames`, so condition (a) — the premise
 * that makes this rule safe — would be unsatisfiable, and the rule would be
 * silent everywhere while looking implemented.
 */
export const inlineAuthorizationLogic: CrossFileRule = {
  ruleId: 'VG-SMELL-013',
  name: 'Inline Authorization Logic',
  description:
    'A route handler decides authorization inline although the project already has an ' +
    'authorization guard mounted on its routes.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  languages: ['typescript', 'javascript'],
  /**
   * `CWE-284` (Improper Access Control) only.
   *
   * `CWE-862` (Missing Authorization) is on VG-SMELL-010 and is deliberately NOT
   * here: nothing is missing in the code this rule reports — the check is
   * present and, as written, correct. The defect is that the decision has two
   * homes, which is an access-control STRUCTURE problem, and claiming a missing
   * authorization would misdescribe the finding to every consumer that maps CWEs
   * to a compliance report.
   */
  cwe: ['CWE-284'],
  owasp: ['A01:2021 Broken Access Control'],
  remediation: {
    why: 'A policy written in the guard and again in the handler cannot be changed in one place.',
    how: 'Name the existing guard at the route registration and delete the inline check.',
  },
  analyze,
};
