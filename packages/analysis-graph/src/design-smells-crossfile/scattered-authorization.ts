// VG-SMELL-010 — Scattered Authorization. The flagship cross-file rule.
//
// WHAT IT CLAIMS
//
// Authorization decisions are written inline inside individual route handlers,
// in several places across several files, instead of in one guard the routes
// share. The danger is not any one of those checks — each may be perfectly
// correct — it is that the NEXT endpoint someone adds will be the one that
// forgets, and nothing in the structure of the code makes that omission visible.
// That failure mode is over-represented in AI-generated services specifically,
// because a model asked for "an endpoint that only admins can use" produces a
// correct endpoint with a correct inline check, and produces it again, and
// again, with no memory that it has now written the same policy four times.
//
// WHY IT CANNOT BE A SINGLE-FILE RULE
//
// Every individual site looks correct. `if (user.role !== 'admin') return 403`
// inside one handler is not a finding and must never be reported as one — the
// project already ships `VG-SMELL-003`/`012`/`004` for single-file design
// smells and they deliberately do not flag this. The finding exists only in the
// relationship between sites in DIFFERENT files, which is a sentence no
// single-file rule can form. That is the entire argument for this package
// existing, and this rule is where the argument is cashed in.
//
// ★ THE PRECISION CONTRACT
//
// This project ships a hard gate: `samples/safe` must produce ZERO findings. A
// design smell that fires on well-factored code is a bug, not a near miss, and
// the well-factored version of this exact code — one `requireRole` middleware
// applied at route registration — is the shape a reviewer would be MOST annoyed
// to see flagged. So the rule is built out of negative conditions first; the
// positive pattern is the easy half. Each exclusion below is named, justified,
// and covered by a fixture under `samples/crossfile-fixtures/` that must stay
// silent.

import type { CodeLocation, Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, mergeMetrics } from '../metrics/index.js';
// The authorization vocabulary moved to `authz-lexicon.ts` when VG-SMELL-011
// and VG-SMELL-013 needed the identical patterns. It is a pure extraction: the
// regexes, the privilege words and `pathWords` are byte-identical to what this
// file used to define, and the existing tests are what pins that. See the
// header of that file for why three copies of this vocabulary was the 041
// failure mode with a longer fuse.
import {
  ELEVATED,
  TEST_PATH,
  authzDecisionPatterns,
  isAuthnGuardName,
  isAuthzGuardName,
  pathWords,
} from './authz-lexicon.js';
// The Python arm resolves `include_router(items.router, dependencies=[…])` back
// to the file that router lives in, and it does that with the SAME resolver the
// graph used rather than a private path-joining routine. A second resolver would
// answer differently for exactly the inputs that are hard — package `__init__`
// files, relative levels — and the consequence of a disagreement here is a
// silencer that fails to silence, which is a false positive.
import { resolveSpecifier } from '../dependency-graph/index.js';
import type {
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  ProjectIndex,
  StructureIndex,
} from '../types.js';

/**
 * Minimum number of inline checks before the shape is a smell.
 *
 * Three, from the design addendum §7.2 ("three or more occurrences in the same
 * project"). Two is a coincidence and a very common one — a create and a delete
 * endpoint guarded the same way is not yet a policy scattered across a codebase,
 * and firing there would put this rule in front of every small service in
 * existence on its first day.
 */
const MIN_SITES = 3;

/**
 * Minimum number of distinct files.
 *
 * Not in the addendum's numbered list, and added deliberately. "Three checks in
 * one file" is a single-file observation, and reporting it from the cross-file
 * engine would (a) duplicate whatever the single-file rules say about that file
 * and (b) claim cross-file evidence the finding does not have. The whole
 * justification for this package is the sentence single-file analysis cannot
 * form; a finding that a single file could have produced does not get to use it.
 */
const MIN_FILES = 2;

// ── AUTHZ_PROPERTY / CMP / FLAG / MEMBERSHIP now live in `authz-lexicon.ts`. ──
//
// They were defined here first and moved out unchanged when VG-SMELL-011 and
// VG-SMELL-013 needed the same three shapes. The arguments for each — why the
// property list is closed, why a method CALL is delegation rather than an
// inline check, why every quantifier carries a ceiling — moved with them and
// are not repeated here.
//
// One difference survives the move and is deliberate: the lexicon hands out
// FRESH RegExp objects from `authzDecisionPatterns()` rather than exporting
// three module constants. A `g`-flagged regex carries `lastIndex`, and a
// constant shared by three rules is a mutable global that one of them will
// eventually read mid-iteration. `checksIn` below still resets `lastIndex`
// explicitly, which is now belt and braces rather than the only thing holding
// it together.

// `ELEVATED` — the privilege words that make a finding `high` rather than
// `medium` — also moved to `authz-lexicon.ts`, along with the reminder that it
// is matched against the ORIGINAL source text rather than the blanked copy.

// ---------------------------------------------------------------------------
// SECURITY CONTEXT BOOST (#22d) — the three conditions beyond the privilege word
//
// Design addendum §10.3 lists five conditions that raise a design smell's
// severity. `ELEVATED` above is the first. Three more are implemented below:
// the check sits on a security-ish PATH, the check sits in the routing LAYER,
// and the handler MUTATES data. The fifth — "the code is newly added in a PR
// diff" — is not implemented and never will be; see the note above the rule
// export for why §5.4 overrides §10.3 there.
//
// ★ WHAT IS DETECTED IS NOT THE SAME AS WHAT MOVES SEVERITY.
//
// All three are computed for every site and exposed on `CheckSite`, because the
// recall/sensitivity analysis (#22e) needs the raw observations. Only two of
// them are allowed to change the verdict, and the third is held back on
// MEASURED grounds rather than on taste — see `ROUTING_LAYER_TOKEN`. Keeping
// detection and consequence separate is what makes that decision reviewable: the
// number that justifies it can be recomputed from the exported sites at any
// time, by anyone who doubts it.
// ---------------------------------------------------------------------------

// `pathWords` — word matching rather than substring matching, and the
// `src/authors/list.ts` counterexample that forces it — moved to
// `authz-lexicon.ts` unchanged. Every rule in this directory that reasons about
// a path or an identifier now segments it the same way, which is the point.

/**
 * Condition ① — path words that make the FILE a security surface.
 *
 * The addendum's list is `auth | security | token | permission | admin | user`.
 * Spelled out here as whole words, with the plural and the -n/-z/-ation
 * inflections that a path actually uses, because the match is a word match and
 * `permissions/` would otherwise miss. Same convention as `SECURITY_PATH_WORDS`
 * in the symbol table: enumerate rather than stem, so the set can be read.
 *
 * ★ `user` / `users` ARE IN THE SET, AND THAT WAS THE HARDEST CALL HERE.
 *
 * `controllers/user-controller.ts` is the single most common file name in a REST
 * service, so a `user` entry looked like it would boost nearly every finding and
 * collapse the severity field into a constant — the exact failure this whole
 * block is written to avoid. It is included, and the reason is a measurement
 * rather than the spec text.
 *
 * MEASURED 2026-07-28 over every check site the rule finds, thresholds not
 * applied (`collectScatteredAuthSites`):
 *
 *   corpus                            sites   `user` is the ONLY path word
 *   paper_data/corpus1k     (1,000 repos)   1   0
 *   paper_data/corpus1k_vibe (1,683 repos) 108   1   (0.9%)
 *   samples/crossfile-* pre-#22d            13   2   (15.4%)
 *
 * One site in 108. The intuition was simply wrong about where handlers with
 * inline authorization checks live — `user`-named files are common in a
 * repository and rare in this rule's population, because the handler that
 * re-derives an admin check tends to sit in the feature it guards rather than in
 * `users/`.
 *
 * Stronger still, and the figure that actually settled it: NO PROJECT IN EITHER
 * CORPUS CHANGES VERDICT BECAUSE OF THIS ENTRY. Six of the nine `corpus1k_vibe`
 * projects with sites satisfy condition ①, and the same six satisfy it through a
 * non-`user` word, so dropping `user` and `users` would move nothing. The two
 * fixture sites are both in `crossfile-vulnerable/controllers/user-controller.ts`,
 * which is already `high` on the privilege word. The entry costs ~1% of sites,
 * changes no verdict, and covers a case the addendum explicitly asked for;
 * removing it would be a deviation with no evidence behind it.
 *
 * The general corpus contributes almost nothing to this table — ONE site in a
 * thousand repositories — which is itself worth recording: rates over that
 * corpus cannot be computed at all, and any figure quoted from it would be noise
 * with a denominator attached. `routes`/`controllers` failed a much more
 * decisive version of this same test and were dropped from severity; see below.
 *
 * ★ WHAT THIS SET COLLIDES WITH, MEASURED.
 *
 * `auth` (and its inflections) is also in the symbol table's
 * `SECURITY_PATH_WORDS`, where it means something almost opposite: an EXPORTED
 * symbol in such a file is judged a guard, and guards are excluded from this
 * rule's population before any boost runs. So for the ordinary named-export
 * handler shape, `auth/` produces no sites for this condition to boost — the
 * word is only reachable when the handler is written inline at the route
 * registration. That is pinned by a test rather than left as a belief
 * (`the boost vocabulary versus the symbol table's`), and the entries stay,
 * because the inline shape is common and the cost of keeping them is zero.
 *
 * NOT in the set, deliberately: `author`, `authors`, `authoring`, `authority`,
 * `authorities` — see `pathWords`.
 */
const SECURITY_PATH_TOKEN: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authz',
  'authentication',
  'authorization',
  'authorisation',
  'security',
  'token',
  'tokens',
  'permission',
  'permissions',
  'admin',
  'admins',
  'user',
  'users',
]);

/**
 * Condition ② — the routing layer: `routes/`, `controllers/`, `middleware/`.
 *
 * ★ DETECTED, REPORTED, AND DELIBERATELY NOT WIRED TO SEVERITY.
 *
 * The suspicion that made this worth measuring rather than assuming: the rule's
 * population is ALREADY restricted to registered route handlers (see
 * `handlersOf`), so "is this handler in the routing layer" largely re-asks the
 * membership question that got the site into the population in the first place.
 *
 * MEASURED 2026-07-28, over every check site the rule finds:
 *
 *   corpus                             sites   routingLayer
 *   paper_data/corpus1k_vibe (1,683 repos) 108   103   (95.4%)
 *   samples/crossfile-* pre-#22d            13    10   (76.9%)
 *
 * 95% is not a condition, it is a constant with five exceptions. Scoring it
 * would move the rule's `high` share to nearly everything it emits, and a
 * severity that is `high` for almost every finding stops being a severity: the
 * default `--fail-on high` gate then fires on the whole category, and the field
 * a reviewer triages by carries no information. Compare the two conditions that
 * ARE scored on the same 108 sites — `securityPath` 20.4%, `mutatesData` 37.0% —
 * and the difference in kind is visible without any argument about taste.
 *
 * (`paper_data/corpus1k`, the general corpus, produced ONE site across 1,000
 * repositories and so cannot support a rate for this or any other condition.
 * Recorded because "we measured it on both corpora" would otherwise imply two
 * usable denominators when there is one.)
 *
 * The third entry is the sharpest case: `middleware` is in the symbol table's
 * `SECURITY_PATH_WORDS`, so an exported symbol under `middleware/` is judged a
 * guard and excluded from the population outright. That third of the condition
 * is not merely weak, it is unreachable in the shape it was written for.
 *
 * It is still detected and still on `CheckSite`, because #22e's sensitivity
 * analysis needs to be able to recompute this decision instead of trusting it,
 * and because a future rule that is not restricted to handlers would find it
 * informative.
 */
const ROUTING_LAYER_TOKEN: ReadonlySet<string> = new Set([
  'route',
  'routes',
  'router',
  'routers',
  'controller',
  'controllers',
  'middleware',
  'middlewares',
]);

/**
 * Condition ③ — method names whose call is a WRITE to a data store.
 *
 * A closed list, and short on purpose. The three obvious additions are refused:
 *
 *  - `create` — `createServer`, `createElement`, `createHash`, `document.
 *    createRange`. The word is the most common verb in JavaScript and names a
 *    write to a database in a minority of its uses.
 *  - `save` — `save()` on an ORM document is a write; `editor.save()`,
 *    `canvas.save()`, and `config.save()` are not, and nothing at this layer can
 *    tell them apart.
 *  - `remove` — `element.remove()`, `list.remove()`, `cache.remove()`.
 *
 * Each of them would raise severity on ordinary handlers, and severity inflation
 * is the failure mode this whole block is trying not to cause. Recall lost to
 * their absence is recoverable — the SQL arm below catches the statement an ORM
 * ultimately issues whenever it is written out — and precision lost to their
 * presence is not.
 *
 * ★ THE BARE VERBS WERE CUT, AND THE CORPUS IS WHY.
 *
 * An earlier revision of this set also carried `update`, `delete`, `insert` and
 * `destroy`. The comment here said of `delete` that it was "the one entry with a
 * known false-positive shape … if the corpus ever shows this costing more than
 * it earns, this is the line to cut". It cost more than it earned, so it is cut,
 * along with the other three bare verbs that fail the same way.
 *
 * MEASURED 2026-07-28. Each line below was added on its own to
 * `samples/crossfile-fixtures/boost-none` — the medium sentinel — and flipped
 * that fixture's severity from `medium` to `high`:
 *
 *   createHash('sha256').update(String(req.headers['x-api-key'])).digest('hex')
 *   req.session.destroy(() => undefined)
 *   responseCache.delete(req.originalUrl)
 *   progressBar.update(1)
 *
 * None of the four writes to a data store. A crypto digest, a session teardown,
 * a cache eviction and a progress bar are the ordinary furniture of a read-only
 * handler, and a severity that `high`s on their presence is not reporting on
 * data mutation — it is reporting on the handler being written in JavaScript.
 *
 * What is left is the set of names that are unambiguous BECAUSE they are
 * disambiguated: nobody calls a progress bar's method `updateOne`, and
 * `deleteMany` has no meaning outside a data store. The cost of the cut is
 * recall — a handler that mutates only through a bare `.delete(` no longer
 * boosts — and that is the direction this project accepts losing in, because a
 * missed boost leaves the finding at `medium` while a wrong boost destroys the
 * severity field for every consumer of the rule.
 */
const MUTATING_METHOD: ReadonlySet<string> = new Set([
  'updateOne',
  'updateMany',
  'findByIdAndUpdate',
  'findOneAndUpdate',
  'deleteOne',
  'deleteMany',
  'insertOne',
  'insertMany',
  'upsert',
  'bulkWrite',
  'executeUpdate',
]);

/**
 * Any `.name(` in a body. The name is checked against the set above rather than
 * being baked into the pattern.
 *
 * Written this way instead of one big alternation because alternation order is a
 * silent correctness hazard here: `\.(?:update|updateOne)\b\(` on `.updateOne(`
 * only works because the engine backtracks out of the first branch, and the day
 * someone adds an entry without thinking about prefixes the pattern starts
 * matching the wrong length. A `Set` lookup has no order.
 */
const METHOD_CALL = /\.(?<method>[A-Za-z_$][\w$]{0,40})[^\S\r\n]{0,4}\(/g;

/**
 * SQL statements that WRITE, as verb pairs.
 *
 * Verb PAIRS rather than single verbs: `update` alone is an English word that
 * appears in every handler that touches a UI, and `insert`/`delete` are little
 * better. `update … set`, `delete from`, and `insert into` are syntax.
 *
 * The gap in `update … set` is bounded at 200 characters, which covers the
 * column list of any realistic statement, and it is the only quantifier of any
 * size in these three patterns — no nesting, no alternation under a quantifier,
 * so there is nothing for the D3 contract to be violated by.
 *
 * ★ VERB PAIRS ARE NOT ENOUGH, AND THE CORPUS IS WHY.
 *
 * The pairs were chosen because "`update` alone is an English word". The pairs
 * are English too. MEASURED 2026-07-28, each added alone to the `boost-none`
 * medium sentinel and each flipping it to `high`:
 *
 *   res.status(409).json({ error: 'You cannot delete from an empty catalogue' })
 *   res.setHeader('X-Notice', 'Update your plan to set a higher listing limit')
 *
 * Both sit inside string literals, which is exactly where the `inLiteral` guard
 * expects SQL to be, so that guard cannot separate them — it was written to
 * exclude code, and the problem is prose. English contains `delete … from` and
 * `update … set` as ordinary phrases, and user-facing error strings are the one
 * kind of literal a handler is guaranteed to have.
 *
 * A first attempt required the match to carry "a token statements have and
 * sentences do not" — `?`, `=`, `$1`, `where`, `values`. That was still too
 * weak, and the counter-examples are as ordinary as the first two:
 *
 *   'Are you sure you want to delete from this list?'      (the `?` qualified it)
 *   'Update your plan to set a higher limit = more listings' (the `=` did)
 *
 * What actually separates the two is GRAMMAR, not vocabulary: a real statement
 * names exactly ONE table between its verbs. `update price_book set` has one
 * identifier; "Update your plan to set" has three words there. So the table
 * position is written into the pattern — one identifier, optionally
 * schema-qualified, optionally quoted — and for `delete`/`insert` the clause
 * that must follow it is required too. Prose fails on the token AFTER the
 * table: "delete from this list" continues with a second bare word where SQL
 * would have `where`, `;`, `(`, or the end of the string.
 *
 * Quantifiers stay small and fixed and nothing nests, so the D3 contract is
 * unaffected. Everything here fails toward `medium`, which is the safe way for
 * a severity booster to be wrong.
 */
/** One table reference: `tbl`, `sch.tbl`, `` `tbl` ``, `"tbl"`, `[tbl]`. */
const SQL_TABLE = '[`"\\[]{0,1}[A-Za-z_][\\w$]{0,63}[`"\\]]{0,1}';

const SQL_MUTATION: readonly RegExp[] = [
  // update <table> set
  new RegExp(
    `\\bupdate[^\\S\\r\\n]{1,4}${SQL_TABLE}(?:[^\\S\\r\\n]{0,2}\\.[^\\S\\r\\n]{0,2}${SQL_TABLE})?[^\\S\\r\\n]{1,4}set\\b`,
    'gi',
  ),
  // delete from <table> (where | ; | ) | end)
  new RegExp(
    `\\bdelete[^\\S\\r\\n]{1,4}from[^\\S\\r\\n]{1,4}${SQL_TABLE}(?:[^\\S\\r\\n]{0,2}\\.[^\\S\\r\\n]{0,2}${SQL_TABLE})?[^\\S\\r\\n]{0,4}(?:\\bwhere\\b|\\breturning\\b|[;)]|['"\`]|$)`,
    'gi',
  ),
  // insert into <table> ( | values | select | set
  new RegExp(
    `\\binsert[^\\S\\r\\n]{1,4}into[^\\S\\r\\n]{1,4}${SQL_TABLE}(?:[^\\S\\r\\n]{0,2}\\.[^\\S\\r\\n]{0,2}${SQL_TABLE})?[^\\S\\r\\n]{0,4}(?:\\(|\\bvalues\\b|\\bselect\\b|\\bset\\b)`,
    'gi',
  ),
];

/**
 * Whether an offset in the blanked copy is inside a comment.
 *
 * ★ THIS FUNCTION EXISTS BECAUSE THE OBVIOUS TEST IS WRONG.
 *
 * The SQL patterns above have to run over the ORIGINAL text: a statement lives
 * inside a string literal, and blanking — by design — replaces string CONTENTS
 * with spaces, so the blanked body a method-name scan reads has nothing in it.
 * Reading the original brings back everything blanking was protecting against,
 * so the position is then required to be blank in the blanked copy, which proves
 * the characters were erased rather than being code.
 *
 * The tempting conclusion is that "blank in the blanked copy" already means
 * "inside a string". It does not. `blankJsLiterals` erases COMMENT bodies to
 * spaces too, so `// TODO: delete from orders once the migration lands` passes
 * that test exactly as a real statement does — and a commented-out write is the
 * one thing that most reliably is NOT a write. Hence this second test.
 *
 * It reads the blanked copy rather than the original, which is what makes it
 * cheap and correct at the same time: the blanker preserves the comment
 * DELIMITERS themselves while erasing everything between them, so a comment
 * opener visible in the blanked text is always a real one — an opener written
 * inside a string or a regex would have been erased along with the rest.
 */
function insideComment(blanked: string, position: number): boolean {
  const lineStart = blanked.lastIndexOf('\n', position) + 1;
  if (blanked.lastIndexOf('//', position) >= lineStart) return true;
  const opened = blanked.lastIndexOf('/*', position);
  if (opened === -1) return false;
  return blanked.lastIndexOf('*/', position) < opened;
}

/** Condition ① for one file. */
function isSecurityPath(filePath: string): boolean {
  return pathWords(filePath).some((w) => SECURITY_PATH_TOKEN.has(w));
}

/**
 * Condition ② for one file.
 *
 * DIRECTORY segments only — the addendum says "under `route`/`controller`/
 * `middleware`", and `src/userRoutes.ts` is a file that declares routes rather
 * than a routing layer the handler was filed into. Dropping the last segment is
 * how that distinction is expressed, and it is the difference between reading
 * placement and reading a file name.
 */
function isRoutingLayer(filePath: string): boolean {
  const segments = filePath.split('/');
  return segments
    .slice(0, Math.max(0, segments.length - 1))
    .some((segment) => pathWords(segment).some((w) => ROUTING_LAYER_TOKEN.has(w)));
}

/**
 * Condition ③ for one handler: does its body write to a data store?
 *
 * Two mechanisms, because the two shapes live on opposite sides of blanking.
 * Method calls are code and are read from the blanked body, so a call named in a
 * comment is already gone. SQL is a string and is read from the original, then
 * proved to have been inside a literal and not inside a comment.
 */
function mutatesData(handler: IndexedSymbol, structure: StructureIndex, content: string): boolean {
  const body = structure.blanked.slice(handler.bodyStart, handler.bodyEnd);

  METHOD_CALL.lastIndex = 0;
  for (let m = METHOD_CALL.exec(body); m; m = METHOD_CALL.exec(body)) {
    if (MUTATING_METHOD.has(m.groups?.method ?? '')) return true;
    if (METHOD_CALL.lastIndex === m.index) METHOD_CALL.lastIndex += 1;
  }

  const original = content.slice(handler.bodyStart, handler.bodyEnd);
  const inLiteral = (position: number): boolean =>
    structure.blanked[position] === ' ' && !insideComment(structure.blanked, position);

  for (const pattern of SQL_MUTATION) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(original); m; m = pattern.exec(original)) {
      const start = handler.bodyStart + m.index;
      // BOTH ends, not just the start. `update … set` allows 200 characters of
      // gap, which is enough for the two halves to come from different places —
      // the word `update` inside a user-facing message and a real `set` in code
      // twenty characters later. Requiring the last character of the match to be
      // inside a literal as well means the whole statement was one string.
      // For the other two patterns the ends are adjacent and the extra test is
      // free; it is applied uniformly rather than special-cased.
      //
      // Being inside a literal is necessary and NOT sufficient: user-facing
      // error strings are literals too, and English contains `delete … from`.
      // The constraint that separates the two is GRAMMAR and now lives in the
      // patterns themselves (see `SQL_MUTATION`), so what is left here is the
      // original question: did the whole statement sit in one string?
      if (inLiteral(start) && inLiteral(start + m[0].length - 1)) return true;
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
  }
  return false;
}

/**
 * `role` values that belong to a CHAT MESSAGE, not to a person's privilege.
 *
 * ★ FOUND BY EVALUATION OVER REAL REPOSITORIES, NOT BY REVIEW. A share of the
 * findings from that run were all the same mistake:
 *
 *     m.role === 'assistant' ? 'assistant' : 'user'
 *     DbChatMessage.role == 'assistant'
 *
 * The OpenAI-style chat completion API names its message field `role` and fills
 * it with `system` / `user` / `assistant` / `tool`. That is the same property
 * name this rule reads as a privilege level, and the collision is not a rare
 * coincidence — it is concentrated in exactly the population this whole project
 * targets, because a codebase that calls an LLM is a codebase written with LLM
 * help. Left unfixed it would have made the flagship rule least reliable on the
 * corpus the paper is about, which is the worst possible place for it.
 *
 * `user` is deliberately NOT in this set. It is a legitimate privilege level
 * (`role !== 'user'` is a real authorization check) as well as a chat role, so
 * excluding it would trade two false positives for an unknown number of false
 * negatives on the rule's core case. The other four are unambiguous: nobody
 * grants a person the `assistant` role.
 *
 * The receiver check below covers the residual `'user'` case by shape instead.
 */
const CHAT_ROLE_LITERAL = /^['"`](?:assistant|system|tool|function|developer|model)['"`]$/i;

/**
 * Receivers that name a MESSAGE rather than a subject.
 *
 * The second half of the chat-role exclusion, for `m.role === 'user'` where the
 * literal alone cannot decide. A privilege check reads the role off something
 * that represents a person — `user`, `req.user`, `actor`, `currentUser`,
 * `caller`, `target`. A chat-role check reads it off something that represents a
 * turn in a conversation. Those vocabularies barely overlap, so the receiver is
 * a usable discriminator where the value is not.
 */
const MESSAGE_RECEIVER =
  /^(?:m|msg|message|messages|prev|turn|chat|completion|choice|delta)$|(?:message|chatmsg|chatmessage|conversation|prompt|completion)/i;
// `entry`, `item`, `h`, `history`, `next` were in this set and are deliberately
// NOT any more: they are generic iteration and callback names, so excluding them
// discarded real authorization checks. The ordering fix in `checksIn` is the
// real repair — this set now only has to cover the residual case where no
// literal is available to decide.

// `TEST_PATH` — path segments whose contents are fixtures, not the service
// under review — moved to `authz-lexicon.ts` byte-identical. Widening it there
// was considered and refused, precisely so that this rule's population cannot
// change as a side effect of a refactor.

/**
 * One inline authorization check found inside one handler.
 *
 * ★ EXPORTED for the recall / sensitivity analysis (#22e), together with
 * `collectScatteredAuthSites`. The four boost fields are the reason the type is
 * worth exposing rather than the analysis re-deriving sites from
 * `finding.relatedLocations`: a finding carries ONE severity for N sites, so
 * "how many of the sites were on a security path" is not recoverable from it,
 * and neither is anything about the sites that never reached a finding at all.
 */
export interface CheckSite {
  filePath: string;
  line: number;
  column: number;
  /** Source text of the check, from the original content. */
  evidence: string;
  /** Receiver + property, normalised, for reporting how many spellings appear. */
  signature: string;
  /** A privilege word (`admin`, `owner`, …) in the text of the check itself. */
  elevated: boolean;
  /** Boost ①: the file's path carries a security word. `SECURITY_PATH_TOKEN`. */
  securityPath: boolean;
  /** Boost ②: the file sits under a routing-layer directory. Detected, not scored. */
  routingLayer: boolean;
  /** Boost ③: the enclosing handler writes to a data store. `MUTATING_METHOD`. */
  mutatesData: boolean;
  handlerName: string;
}

/**
 * Symbols that are the RIGHT place for an authorization check.
 *
 * A check inside a guard is the centralised design this rule wants people to
 * have; counting it as evidence of scattering would mean the rule fires hardest
 * on codebases that did exactly what it asks. This is the single most important
 * exclusion in the file and the one `samples/crossfile-safe` exists to pin.
 *
 * Membership comes from the symbol table, whose strongest signal is behavioural
 * rather than nominal: a symbol OBSERVED in a route's pre-handler argument
 * position anywhere in the project is a guard, regardless of what it is called.
 */
function isInsideGuard(symbol: IndexedSymbol, project: ProjectIndex): boolean {
  return project.symbols.guards.has(`${symbol.filePath}\0${symbol.name}`);
}

/**
 * Names that mark a decorator as a ROUTE registration, in either arm.
 *
 * Hoisted out of `handlersOf` when the Python arm arrived and left otherwise
 * byte-identical — four places consult it now. No `g` flag, so `test` carries no
 * `lastIndex` between those callers; that is the property that makes hoisting a
 * shared regex safe here where `authz-lexicon` had to hand out fresh objects.
 */
const ROUTE_DECORATOR =
  /^(?:get|post|put|patch|delete|head|options|all|route|api_route|websocket)$/i;

/** `@app.route` / `@router.get` / `@Get` — the last dotted segment decides. */
function isRouteDecorator(decorator: string): boolean {
  return ROUTE_DECORATOR.test(decorator.split('.').pop() ?? '');
}

// ═══════════════════════════════════════════════════════════════════════════
// THE PYTHON ARM (#27b)
//
// ★ WHY THIS IS ALMOST ENTIRELY NEGATIVE CONDITIONS
//
// Python was in `languages` in 0.3.0-α and the DETECTION worked — a Flask
// `@app.route` handler containing `request.user.role != 'admin'` fired
// correctly. It was removed anyway, and the note above the rule export records
// why: not one negative fixture was written in Python, and Flask, FastAPI and
// Django each centralise authorization through a mechanism none of the negative
// conditions recognised. A well-factored FastAPI service was therefore
// indistinguishable from a scattered one, and in a product whose contract is
// `samples/safe == 0` that is not a tuning gap, it is the rule being wrong about
// what it is looking at.
//
// So everything below is the missing half. It recognises the CENTRALISED shapes
// and removes the handlers they cover from the population; it adds exactly one
// thing to the population (Django URLconf views), and only because the Django
// centralisation lives at the URLconf and cannot be read without reading it.
//
// ★ THE DIRECTION EVERY DECISION IN THIS SECTION FAILS IN
//
// Quiet. When a mechanism cannot be read — an unbalanced call, an unresolvable
// router import, a signature that does not parse, a class whose bases are not
// visible — the handler, the file, or the project goes silent rather than
// staying in the population. That asymmetry is deliberate and it is the reason
// the Python arm's recall is materially worse than the TS/JS arm's:
//
//  - a handler whose signature names ANY security-shaped `Depends(...)` is out,
//    even though the dependency might inject a database session and decide
//    nothing;
//  - a handler carrying ANY decorator with `required` in its name is out, so
//    `@require_http_methods(["GET"])` silences a genuinely scattered handler;
//  - one `dependencies=[…]` on an `APIRouter(...)` silences the whole FILE,
//    including handlers that router does not own.
//
// Each of those is a missed finding. The alternative in each case is a fired
// finding on a correct application, which is the failure that gets a security
// tool uninstalled — and, for Python specifically, it would be a user's FIRST
// contact with this rule.
//
// ★ WHAT THIS ARM DOES DIFFERENTLY FROM THE TS/JS ARM, AND WHY IT HAD TO
//
// In TS/JS a guard is evidence about the GUARD's symbol: `handlersOf` excludes
// symbols that ARE guards, and `router.get('/x', requireAdmin, handler)` leaves
// `handler` in the population — the layered design (mounted guard plus
// resource-level check) still produces sites there. Python inverts it: a guard
// decorator or dependency excludes the GUARDED handler. The inversion is forced,
// not chosen. `StructureIndex.routes` is ALWAYS EMPTY for Python — the indexer
// builds no route bindings for it — so `RouteBinding.middlewareNames`, which is
// where TS/JS keeps "this route has a pre-handler guard", does not exist to
// consult. The decorator stack and the signature are the only places the
// relationship is written down, and both are attached to the handler.
//
// The consequence is stated rather than buried: a Flask application that puts
// `@login_required` on every route and then re-derives `current_user.role` in
// four handlers produces NOTHING from this rule. That is a real class of missed
// finding, and it is the price of not accusing the same application when the
// four handlers are checking object ownership, which is correct code and looks
// identical from here.
//
// ★ WHAT THIS ARM DOES ON REAL CODE, MEASURED — AND WHY BOTH NUMBERS ARE HERE
//
// `paper_data/corpus1k`, 1,000 repositories, 630 with source, 236 containing
// Python (`scripts/crossfile-corpus-sweep.mjs --rule VG-SMELL-010`):
//
//   route-decorated Python defs found                       2,608
//   sites with EVERY negative condition switched off           52   in 3 repos
//   sites as shipped                                            0
//   findings as shipped                                         0
//
// The first and second lines are why the third is not evidence that the arm is
// dead. 2,608 handlers entered the population mechanism, so it works at scale;
// 52 of them contained a privilege comparison; all 52 were then read:
//
//   fastapi/full-stack-fastapi-template   11   layered — see PY_DEPENDENCY_ALIAS
//   LAION-AI/Open-Assistant                5   `m.role == "assistant"`
//   odysseus-dev/odysseus                 36   `msg.role == 'assistant'`
//
// The last two are the CHAT-ROLE collision this rule already documents
// (`CHAT_ROLE_LITERAL`), found on the TS/JS side by the same kind of sweep, and
// they are correctly discarded by machinery that predates this arm. The first is
// the false positive this arm's first submission produced and the reason the
// alias arm exists. Zero is the right answer for this corpus.
//
// A zero establishes NOTHING about recall — the registry's own note about
// VG-SMELL-041 and 052 says so, and the same honesty applies here. No true
// positive was produced on `corpus1k` either, so the only evidence that this arm
// can fire is `samples/crossfile-fixtures/smell-010-py-positive` and the
// falsification half of each negative fixture's test.
// ═══════════════════════════════════════════════════════════════════════════

/**
 * How far a scan will follow one call's argument list.
 *
 * A work bound in the same spirit as `REGEX_INPUT_CAP`, and the number is chosen
 * against the shapes actually being read: an `APIRouter(prefix=…, tags=[…],
 * dependencies=[…], responses={…})` head and a `urlpatterns` entry are both far
 * inside it, while a generated file that opens a paren and never closes it costs
 * one bounded walk instead of a scan to end-of-file per call site.
 */
const CALL_SCAN_CAP = 4000;

/** How many lines of a `def` head are read looking for the end of its signature. */
const SIGNATURE_LINE_CAP = 24;

/** How many lines above a `def` are read looking for its decorator block. */
const DECORATOR_BLOCK_LINE_CAP = 20;

/**
 * Arguments of the call whose `(` is at `open`, split at top-level commas.
 *
 * Returns `undefined` when the call does not close inside `CALL_SCAN_CAP`, and
 * every caller treats that as "assume the guard is there" rather than "assume it
 * is not" — see the quiet-direction note above.
 *
 * Bracket depth is counted over BLANKED text, so a comma or a paren inside a
 * string literal is a space and cannot split an argument. That is the same
 * reason `structure-indexer`'s own `splitArgs` reads the blanked copy; this is a
 * second implementation rather than an import only because that one is private
 * to the indexer and returns offsets this arm has no use for.
 */
function callArguments(blanked: string, open: number): string[] | undefined {
  const args: string[] = [];
  let depth = 0;
  let start = open + 1;
  const end = Math.min(blanked.length, open + CALL_SCAN_CAP);
  for (let i = open; i < end; i += 1) {
    const c = blanked[i];
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) {
        args.push(blanked.slice(start, i));
        return args;
      }
    } else if (c === ',' && depth === 1) {
      args.push(blanked.slice(start, i));
      start = i + 1;
    }
  }
  return undefined;
}

/** `dependencies=[…]` as a keyword argument, tested against a trimmed argument. */
const DEPENDENCIES_KWARG = /^dependencies[^\S\r\n]{0,4}=/;

/**
 * Words that make a DECORATOR on a route handler a guard.
 *
 * ★ A RULE-LOCAL WIDENING OF `authz-lexicon`, AND ONLY IN THE SILENT DIRECTION.
 *
 * `isAuthzGuardName` / `isAuthnGuardName` are consulted first and cover
 * `@permission_required`, `@roles_required`, `@require_admin`, `@login_required`
 * and `@jwt_required`. They do NOT cover `@requires_auth` (the shape Auth0's
 * Flask quickstart ships), `@auth_required`, `@token_required`, or Django's
 * `@staff_member_required` — because the lexicon deliberately keeps bare `auth`
 * out of both sets, and `staff`/`token` are not guard words there either.
 *
 * The lexicon's header says a rule needing a wider vocabulary states it itself.
 * This is that statement, and the reason it is safe to widen HERE and not there
 * is that this set can only ever remove a handler from the population. A word
 * admitted in error costs a missed finding; the same word admitted into the
 * lexicon would change what VG-SMELL-011 and 013 accuse.
 *
 * `required` / `requires` / `require` are in the set on their own, which is the
 * broadest entry and the one worth defending. Python's convention for a
 * precondition decorator is the SUFFIX (`login_required`) where English-language
 * guard naming in TS/JS uses a prefix (`requireLogin`), so the suffix is the only
 * token many real guards share. It over-admits: `@require_http_methods(["GET"])`
 * and `@requires_csrf_token` are not authorization anything, and a handler
 * carrying either goes silent. Both mistakes are missed findings.
 */
const PY_GUARD_DECORATOR_WORD: ReadonlySet<string> = new Set([
  'auth',
  'authenticate',
  'authenticated',
  'require',
  'required',
  'requires',
  'protect',
  'protected',
  'secure',
  'secured',
  'restricted',
  'staff',
  'superuser',
  'member',
  'membership',
  'verified',
  'access',
  'guard',
  'guarded',
]);

/**
 * Words that make a FastAPI dependency a SECURITY dependency.
 *
 * ★ THE ALTERNATIVE — "any `Depends(...)` at all silences the handler" — WAS
 * REJECTED, AND NOT ON RECALL GROUNDS ALONE.
 *
 * Virtually every FastAPI handler takes at least one injected dependency, so
 * silencing on the bare presence of `Depends(` would make the FastAPI arm
 * incapable of firing on anything, which is a rule that cannot be wrong because
 * it cannot speak. Worse, it would be invisible: the negative fixture would pass,
 * the positive would have to avoid FastAPI entirely, and nothing in the test
 * suite could tell that state apart from a working arm.
 *
 * So the dependency's ARGUMENT decides. `Depends(get_current_active_user)` — the
 * name FastAPI's own security tutorial uses — carries `user`; `Security(...)`
 * exists in FastAPI only to carry scopes and is accepted unconditionally;
 * `Depends(RoleChecker(["admin"]))`, the common RBAC idiom, carries `role` and
 * `admin`. `Depends(get_db)` and `Depends(common_parameters)` carry none of
 * these and do NOT silence, so a service that injects a database handle and then
 * decides authorization inline in four handlers is still reachable.
 *
 * Matched against the words of the ARGUMENT ONLY, never the parameter's name or
 * annotation. `db: Session = Depends(get_db)` was the case that forced that:
 * `session` is an authentication guard word in the lexicon, and reading the
 * annotation would have silenced every handler that opens a database session.
 *
 * ★ THE OVER-SILENCE THAT SURVIVES, MEASURED ON THE FIXTURE RATHER THAN GUESSED.
 *
 * `session` is absent from the set above for the reason just given, and it
 * reaches the decision anyway through the SECOND test in
 * `declaresSecurityDependency`: `isAuthnGuardName('get_session')` is true, so
 * `get_session` lands in `guardNames` and silences the handler that injects it.
 * That was found by writing the "a non-security dependency must not silence"
 * test with `Depends(get_session)` and watching it stay quiet.
 *
 * It is left alone. The word belongs in `AUTHN_GUARD_WORD` — `session` really is
 * how most applications spell authentication — and removing it there to fix a
 * FastAPI database dependency would change what VG-SMELL-011 and VG-SMELL-013
 * accuse, which is a much larger blast radius than one missed finding in one
 * framework. The test uses `common_parameters` instead and says why.
 */
const PY_SECURITY_DEPENDENCY_WORD: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authenticated',
  'authentication',
  'authorize',
  'authorized',
  'authorization',
  'user',
  'users',
  'principal',
  'identity',
  'subject',
  'actor',
  'caller',
  'token',
  'tokens',
  'jwt',
  'bearer',
  'apikey',
  'credential',
  'credentials',
  'permission',
  'permissions',
  'role',
  'roles',
  'scope',
  'scopes',
  'privilege',
  'privileges',
  'acl',
  'rbac',
  'policy',
  'admin',
  'superuser',
  'staff',
  'owner',
  'member',
  'tenant',
  'guard',
  'protect',
  'protected',
  'secure',
  'secured',
  'security',
  'require',
  'required',
  'requires',
  'verify',
  'verified',
  'login',
  'signin',
]);

/**
 * Words that make a MIDDLEWARE entry an authorization checkpoint.
 *
 * Used for two things: Django's `MIDDLEWARE` setting and Starlette's
 * `add_middleware(...)`. Both silence the whole PROJECT when they hit, because
 * both are genuinely application-wide — a middleware runs before every view
 * there is, so no per-file scoping would be honest.
 *
 * ★ THE SET IS NOT "ANY PROJECT-LOCAL ENTRY", WHICH IS WHAT THE BRIEF ASKED FOR,
 * AND THE REASON IS THE SHAPE OF A REAL `MIDDLEWARE` LIST.
 *
 * Django's default `MIDDLEWARE` is seven `django.*` entries, and essentially
 * every real project appends something: `corsheaders.middleware.CorsMiddleware`,
 * `whitenoise.middleware.WhiteNoiseMiddleware`, `debug_toolbar…`. Silencing on
 * "an entry not under `django.`" would therefore silence the Django arm on
 * nearly every real project — the arm would be dead in the wild while looking
 * alive in the fixtures, which is precisely the failure the paragraph above
 * `PY_SECURITY_DEPENDENCY_WORD` refuses.
 *
 * `django.`-prefixed entries are excluded from consideration for the opposite
 * reason: `django.contrib.auth.middleware.AuthenticationMiddleware` is in every
 * Django project ever generated, and it establishes WHO the request is, not what
 * it may do. Treating it as centralised authorization would silence the arm
 * universally on a component that decides nothing.
 */
const PY_MIDDLEWARE_SECURITY_WORD: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authz',
  'authenticate',
  'authenticated',
  'authentication',
  'authorization',
  'authorisation',
  'login',
  'session',
  'permission',
  'permissions',
  'role',
  'roles',
  'jwt',
  'token',
  'security',
  'guard',
  'access',
  'staff',
  'admin',
  'superuser',
  'tenant',
  'user',
  'users',
  'acl',
  'rbac',
  'policy',
  'principal',
  'identity',
  'sso',
  'oauth',
]);

/**
 * Evidence, read from a def's BODY, that the def refuses requests.
 *
 * This is the arm that catches a guard nobody named helpfully — a decorator
 * called `@ensure_can_edit` or a dependency called `_check` — and it is the one
 * mechanism here that reads behaviour rather than identifiers.
 *
 * All five run over the BLANKED body, which is what makes them cheap and safe at
 * the same time: the numbers survive blanking (they are code) while the message
 * strings do not, so `abort(403)` is visible and
 * `raise ValueError("call abort(403) first")` is not. Every quantifier is
 * bounded and none is adjacent to another, so nothing here can backtrack.
 */
const GUARD_BODY_EVIDENCE: readonly RegExp[] = [
  // Flask and Django: `abort(403)` / `abort(401)`.
  /\babort[^\S\r\n]{0,4}\([^\S\r\n]{0,4}(?:401|403)\b/,
  // FastAPI and Starlette: `HTTPException(status_code=403, …)`, and the same
  // number written through `status.HTTP_403_FORBIDDEN`.
  /\bstatus_code[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:401|403)\b/,
  /\bHTTP_40[13]_[A-Z_]{0,24}/,
  // Django and DRF: exception classes whose whole meaning is "refused".
  /\b(?:PermissionDenied|NotAuthenticated|AuthenticationFailed)\b/,
  // Flask-Login's own refusal, and the `unauthorized` handler it calls.
  /\b(?:current_user\.is_authenticated|login_manager|unauthorized)\b/,
];

/**
 * Base classes that make a Django class-based view centrally guarded.
 *
 * The word-based test below catches `LoginRequiredMixin` (`login`, `required`),
 * `PermissionRequiredMixin` (`permission`) and a project's own
 * `StaffRequiredMixin` (`staff`, `required`). It does NOT catch
 * `UserPassesTestMixin` — `user`, `passes`, `test`, `mixin` are four ordinary
 * words — and that mixin is the third of Django's three, so the name is listed.
 * `AccessMixin` is their shared base and appears when a project subclasses it
 * directly.
 */
const DJANGO_GUARD_MIXIN: ReadonlySet<string> = new Set([
  'UserPassesTestMixin',
  'AccessMixin',
  'LoginRequiredMixin',
  'PermissionRequiredMixin',
]);

/**
 * Methods whose OVERRIDE is itself the centralisation, on a class-based view.
 *
 * A CBV that overrides `dispatch` is doing exactly what this rule tells people to
 * do — deciding once, before the verb methods run — and `test_func` /
 * `has_permission` are the hooks the mixins call. A class carrying any of them
 * has one place where authorization is decided, so its methods leave the
 * population even when no mixin is named in the bases (which is the case for a
 * project that wrote the check by hand instead of importing the mixin).
 */
const DJANGO_CENTRALISING_METHOD: ReadonlySet<string> = new Set([
  'dispatch',
  'test_func',
  'has_permission',
  'get_permission_required',
  'handle_no_permission',
]);

/**
 * Decorators applied to a CBV CLASS that mount a guard on its methods.
 *
 * `@method_decorator(login_required, name='dispatch')` is the documented way to
 * put a function-view decorator on a class-based view, and the decorator NAME the
 * indexer captures is `method_decorator` — the guard is in the argument, which is
 * a different line's worth of parsing. Treating the wrapper itself as guard
 * evidence is the coarse answer and the right one: `method_decorator` exists
 * only to apply another decorator to a view, and the overwhelming majority of
 * its uses in Django code apply `login_required` or `permission_required`.
 */
const DJANGO_CLASS_GUARD_DECORATOR: ReadonlySet<string> = new Set([
  'method_decorator',
  'permission_required',
  'login_required',
  'staff_member_required',
]);

/** Scope declarations this arm reads out of FastAPI / Starlette source. */
const PY_SCOPE_CALL = /\b(?<callee>FastAPI|APIRouter|include_router|add_middleware)[^\S\r\n]{0,4}\(/g;

/** Django URLconf entries. `url` is the pre-2.0 spelling and still very common. */
const DJANGO_URL_CALL = /\b(?<callee>path|re_path|url)[^\S\r\n]{0,4}\(/g;

/** `MIDDLEWARE = [` / `MIDDLEWARE_CLASSES = [` in a settings module. */
const DJANGO_MIDDLEWARE_SETTING = /\bMIDDLEWARE(?:_CLASSES)?[^\S\r\n]{0,4}=[^\S\r\n]{0,4}\[/;

/** `Depends(x)` / `Security(x)` anywhere in a signature. */
const PY_DEPENDENCY_CALL = /\b(?<kind>Depends|Security)[^\S\r\n]{0,4}\(/g;

/**
 * A module-level dependency ALIAS: `CurrentUser = Annotated[User, Depends(…)]`.
 *
 * ★ THE SHAPE THAT PRODUCED THE ONLY FALSE POSITIVE IN A 1,000-REPOSITORY SWEEP.
 *
 * MEASURED over `paper_data/corpus1k` (630 repositories with source, 236 of them
 * containing Python) with the first version of this arm: ONE finding, and it was
 * `fastapi/full-stack-fastapi-template` — FastAPI's own official project
 * template, six `current_user.is_superuser` checks across two router files. That
 * is a 0% precision result by exactly the standard that rejected VG-SMELL-041,
 * on exactly the population ("a well-factored FastAPI application") this arm was
 * built to stay silent on.
 *
 * The cause is that the template does not write `Depends(...)` in its handlers
 * at all. `backend/app/api/deps.py` declares
 *
 *     SessionDep  = Annotated[Session, Depends(get_db)]
 *     CurrentUser = Annotated[User, Depends(get_current_user)]
 *
 * and every handler then reads `current_user: CurrentUser`. The dependency is
 * declared once and referred to by a type name, which is the layout FastAPI's
 * "Bigger Applications" guidance encourages and which a scan of the SIGNATURE
 * TEXT for `Depends(` cannot see. Two mechanisms answer it, and both are quiet:
 * the alias is resolved back to its right-hand side (this pattern), and the
 * parameter ANNOTATIONS are read for security words (`signatureAnnotations`).
 *
 * The alias's right-hand side is stored rather than judged here, because judging
 * it needs `guardNames`, which pass 2 has not built yet when pass 1 runs.
 */
const PY_DEPENDENCY_ALIAS =
  /(?:^|\n)[^\S\r\n]{0,8}(?<alias>[A-Za-z_]\w{0,60})[^\S\r\n]{0,4}(?::[^=\n]{0,120})?=[^\S\r\n]{0,4}(?:Annotated[^\S\r\n]{0,4}\[|Depends[^\S\r\n]{0,4}\(|Security[^\S\r\n]{0,4}\()/g;

/** `dependencies=` appearing in a route decorator's own argument list. */
const PY_DECORATOR_DEPENDENCIES = /\bdependencies[^\S\r\n]{0,4}=/;

/** A view reference written as a plain (possibly dotted) name. */
const PY_BARE_VIEW = /^[A-Za-z_][\w.]{0,120}$/;

/** `SomeView.as_view()`, with nothing wrapped around it. */
const PY_AS_VIEW = /^(?<cls>[A-Za-z_][\w.]{0,120})\.as_view[^\S\r\n]{0,4}\([^\S\r\n]{0,4}\)$/;

/** Every identifier in an expression, for the "wrapped, so guarded" case. */
const PY_IDENTIFIER = /[A-Za-z_][\w]{0,80}/g;

/** Whether any word of `name` is in `vocabulary`, word-wise via `pathWords`. */
function nameCarriesWord(name: string, vocabulary: ReadonlySet<string>): boolean {
  return pathWords(name).some((w) => vocabulary.has(w));
}

/** The last dotted segment: `views.OrderList` → `OrderList`. */
function lastSegment(dotted: string): string {
  return dotted.split('.').pop() ?? '';
}

/** Leading whitespace width, tabs counted as one — the indexer's convention. */
function indentWidth(line: string): number {
  let n = 0;
  while (n < line.length && (line[n] === ' ' || line[n] === '\t')) n += 1;
  return n;
}

/**
 * A Python file's blanked text, split once and indexed by line.
 *
 * Built once per file and carried on the context, because the alternative is
 * splitting a file per symbol: `MAX_SYMBOLS_PER_FILE` is 800, so that is 800
 * splits of the same string for a large module.
 *
 * `lineStarts[i]` is the offset of line `i` (0-based). It has one entry more
 * than `lines` — the position one past the end — so `lineStarts[last + 1]` is
 * always defined for a valid `last`.
 */
interface PythonFileText {
  lines: string[];
  lineStarts: number[];
}

function pythonFileText(structure: StructureIndex): PythonFileText {
  const lines = structure.blanked.split('\n');
  const lineStarts: number[] = [0];
  let at = 0;
  for (const line of lines) {
    at += line.length + 1;
    lineStarts.push(at);
  }
  return { lines, lineStarts };
}

/**
 * The body span of a Python `def`, RECOMPUTED rather than taken from the symbol.
 *
 * ★ THIS EXISTS BECAUSE `IndexedSymbol.bodyStart` IS WRONG FOR A MULTI-LINE
 * SIGNATURE, AND THE FIRST DRAFT OF THIS ARM SHIPPED A FIXTURE THAT PROVED
 * NOTHING BECAUSE OF IT.
 *
 * The Python indexer sets `bodyStart` to the start of the line after the `def`
 * head line, and finds `bodyEnd` by scanning for the first line indented no
 * further than the `def`. For FastAPI's documented signature style —
 *
 *     async def read_reports(
 *         current_user: Annotated[User, Depends(get_current_active_user)],
 *     ):
 *         ...
 *
 * — the closing `):` sits at the `def`'s own indentation, so the scan stops
 * there and the recorded body is the PARAMETER LIST and nothing else. The real
 * body is entirely outside the span.
 *
 * That was caught by the falsification half of the FastAPI test and not by the
 * silence half, which is the whole argument for testing negatives in pairs: the
 * fixture was silent with the dependency and silent without it, because there
 * was no body to find a check in either way. Asserting only silence would have
 * shipped a negative condition that had never once been exercised.
 *
 * The correction is applied UNIFORMLY, not only to multi-line signatures: for a
 * one-line `def` it reproduces the indexer's span exactly, so there is no second
 * code path whose agreement with the first has to be maintained.
 *
 * The indexer is not changed, deliberately. `bodyStart` is read by every other
 * consumer of the Python index — the single-file metrics, VG-SMELL-020's package
 * arm — and widening it here would move their numbers as a side effect of a fix
 * to this rule. A corrected COPY of the symbol is what leaves this function; the
 * shared index is never mutated.
 */
function pythonBodySpan(
  file: PythonFileText,
  symbol: IndexedSymbol,
  signatureEndLine: number,
  contentLength: number,
): { bodyStart: number; bodyEnd: number } | undefined {
  const declIndent = symbol.startColumn - 1;
  const first = signatureEndLine + 1;
  let last = first - 1;
  for (let i = first; i < file.lines.length; i += 1) {
    const text = file.lines[i] ?? '';
    const trimmed = text.trim();
    // Blank and comment-only lines never end a block — the rule the language
    // itself uses, and the same one `indexPython` applies.
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    if (indentWidth(text) <= declIndent) break;
    last = i;
  }
  if (last < first) return undefined;
  const bodyStart = Math.min(file.lineStarts[first] ?? contentLength, contentLength);
  const bodyEnd = Math.min(file.lineStarts[last + 1] ?? contentLength, contentLength);
  return { bodyStart, bodyEnd };
}

/**
 * A Python def with its signature read and its body span corrected.
 *
 * `undefined` when either could not be established — an unreadable signature or
 * an empty body — and every caller drops the symbol, which is the quiet
 * direction: a body that could not be located cannot be shown to contain a
 * scattered check.
 */
function pythonDef(
  file: PythonFileText,
  structure: StructureIndex,
  symbol: IndexedSymbol,
): { signature: string; body: IndexedSymbol } | undefined {
  const signature = pythonSignature(file, symbol);
  if (signature === undefined) return undefined;
  const span = pythonBodySpan(file, symbol, signature.endLine, structure.blanked.length);
  if (span === undefined) return undefined;
  return { signature: signature.text, body: { ...symbol, ...span } };
}

/**
 * What the Python arm learned about the project as a whole, computed once.
 *
 * Everything here is a NEGATIVE fact except `urlconfFunctionViews` /
 * `urlconfClassViews`, which are the one place this arm adds to the population.
 * They are separated from `urlconfGuardedNames` rather than being one map,
 * because "bound in a URLconf" and "bound through a wrapper" are different
 * claims and the second one wins: a name that appears both ways is guarded.
 */
interface PythonProjectContext {
  /** An application-wide checkpoint was found. No Python file may produce sites. */
  projectSilenced: boolean;
  /** Files covered by a router-level or `include_router`-level dependency list. */
  silencedFiles: ReadonlySet<string>;
  /** Defs judged to be guards, by name or by what their body does. Bare names. */
  guardNames: ReadonlySet<string>;
  /** Function views bound directly in a URLconf, by bare name. */
  urlconfFunctionViews: ReadonlySet<string>;
  /** Classes bound directly through `.as_view()` in a URLconf, by bare name. */
  urlconfClassViews: ReadonlySet<string>;
  /** Every identifier inside a WRAPPED URLconf view expression. */
  urlconfGuardedNames: ReadonlySet<string>;
  /**
   * `CurrentUser` → `Annotated[User, Depends(get_current_user)]`, project-wide.
   *
   * The right-hand SIDE, not a verdict, because deciding whether a dependency is
   * security-shaped may consult `guardNames`, which is built in a later pass.
   */
  dependencyAliases: ReadonlyMap<string, string>;
  /** Each Python file's blanked text, split once. Keyed by `filePath`. */
  texts: ReadonlyMap<string, PythonFileText>;
}

/** Whether a def's body contains evidence that it refuses requests. */
function hasGuardBodyEvidence(body: string): boolean {
  for (const pattern of GUARD_BODY_EVIDENCE) {
    if (pattern.test(body)) return true;
  }
  // A privilege comparison in a def that is NOT a route handler is a decision
  // about who may proceed, made in one place — which is the design this rule
  // recommends. Callers must therefore exclude route-decorated and URLconf-bound
  // defs BEFORE asking, or every scattered handler would silence itself on the
  // strength of the very check being reported, and the rule could never fire.
  for (const pattern of authzDecisionPatterns()) {
    pattern.lastIndex = 0;
    if (pattern.test(body)) return true;
  }
  return false;
}

/**
 * Resolve the file an `include_router(x.router, …)` argument refers to.
 *
 * Two shapes, in the order they occur in FastAPI's own "Bigger Applications"
 * layout. `from .routers import items` + `include_router(items.router)` needs the
 * MODULE `items` under the imported package, which is `.routers.items` — a
 * specifier the import statement never wrote, so it is composed here and handed
 * to the graph's resolver. `from .routers.items import router` +
 * `include_router(router)` already resolved to the right file at import time, so
 * the edge's own `resolvedFile` answers.
 *
 * `undefined` means the caller must silence the whole project instead: a router
 * carrying an application-level dependency list exists, and not knowing which
 * file it covers is not a reason to assume it covers none.
 */
function routerSourceFile(
  head: string,
  structure: StructureIndex,
  known: Set<string>,
): string | undefined {
  for (const edge of structure.imports) {
    if (edge.syntax !== 'python' || !edge.names.includes(head)) continue;
    const submodule = resolveSpecifier(
      { ...edge, specifier: `${edge.specifier}.${head}`, resolvedFile: undefined },
      known,
    );
    if (submodule !== undefined) return submodule;
    if (edge.resolvedFile !== undefined) return edge.resolvedFile;
  }
  return undefined;
}

/**
 * Read the Django `MIDDLEWARE` list out of a settings module.
 *
 * Reads the ORIGINAL content, not the blanked copy, and that is the whole reason
 * this is a function rather than one regex: the entries are STRING LITERALS, so
 * the blanked copy has a list of empty quotes in exactly the place the answer
 * lives. The offsets are interchangeable because every blanker in
 * `@vibeguard/rules` is length-preserving, so the `[` located in the blanked text
 * is the same `[` in the original.
 */
function middlewareDeclaresGuard(blanked: string, content: string): boolean {
  const opened = DJANGO_MIDDLEWARE_SETTING.exec(blanked);
  if (!opened) return false;
  const open = opened.index + opened[0].length - 1;
  const args = callArguments(blanked, open);
  // An unreadable list is treated as declaring a guard, for the reason stated at
  // the top of this section: a settings file whose middleware list does not close
  // inside the scan bound is not evidence that the project has no middleware.
  if (!args) return true;
  // Entries are read POSITIONALLY out of the original. `callArguments` returns
  // contiguous slices starting at `open + 1`, separated by exactly one comma
  // each, so advancing the cursor by `length + 1` per argument lands on the real
  // text of the next one. Re-splitting the original on commas instead would
  // break on a comma inside an entry — which the blanked copy has already
  // handled correctly, and is the reason the split happens there.
  let cursor = open + 1;
  for (const arg of args) {
    const text = content.slice(cursor, cursor + arg.length);
    cursor += arg.length + 1;
    const entry = text.trim().replace(/^[uUbBrRfF]{0,2}['"]/, '').replace(/['"],?$/, '');
    if (entry.length === 0) continue;
    // `django.`-prefixed entries decide nothing this rule cares about — see
    // `PY_MIDDLEWARE_SECURITY_WORD`.
    if (entry.startsWith('django.')) continue;
    if (nameCarriesWord(entry, PY_MIDDLEWARE_SECURITY_WORD)) return true;
  }
  return false;
}

/**
 * Everything the Python arm needs to know about the project, in two passes.
 *
 * TWO PASSES, AND WHY IT CANNOT BE ONE: pass two asks "is this def a guard?", and
 * one of the disqualifiers is "it is a URLconf-bound view" — which is a fact
 * produced by pass one, from a DIFFERENT file (`urls.py` names views in
 * `views.py`). With one pass the answer would depend on directory order.
 */
function buildPythonContext(project: ProjectIndex): PythonProjectContext {
  const silencedFiles = new Set<string>();
  const guardNames = new Set<string>();
  const urlconfFunctionViews = new Set<string>();
  const urlconfClassViews = new Set<string>();
  const urlconfGuardedNames = new Set<string>();
  const dependencyAliases = new Map<string, string>();
  const texts = new Map<string, PythonFileText>();
  let projectSilenced = false;

  const known = new Set(project.structures.keys());
  const contentOf = new Map(project.files.map((f) => [f.filePath, f.content]));
  const pythonFiles = [...project.structures.keys()]
    .sort()
    .map((p) => project.structures.get(p)!)
    .filter((s) => s.language === 'python');

  /** A def's real body, blanked, via the corrected span. `''` when unreadable. */
  const bodyOf = (structure: StructureIndex, symbol: IndexedSymbol): string => {
    const def = pythonDef(texts.get(structure.filePath)!, structure, symbol);
    return def ? structure.blanked.slice(def.body.bodyStart, def.body.bodyEnd) : '';
  };

  // ── Pass 1: scope declarations, URLconfs, and application-wide middleware ──
  for (const structure of pythonFiles) {
    const blanked = structure.blanked;
    texts.set(structure.filePath, pythonFileText(structure));

    PY_SCOPE_CALL.lastIndex = 0;
    for (let m = PY_SCOPE_CALL.exec(blanked); m; m = PY_SCOPE_CALL.exec(blanked)) {
      const callee = m.groups?.callee ?? '';
      const open = m.index + m[0].length - 1;
      const args = callArguments(blanked, open);
      const declares = args === undefined || args.some((a) => DEPENDENCIES_KWARG.test(a.trim()));

      if (callee === 'FastAPI') {
        // `FastAPI(dependencies=[Depends(verify_token)])` is genuinely
        // application-wide, so the scope of the silence matches the scope of the
        // guard exactly. No coarsening involved.
        if (declares) projectSilenced = true;
      } else if (callee === 'APIRouter') {
        // Router-level. The honest scope is "the routes registered on this
        // router", and nothing lexical can enumerate those — a router object can
        // be passed anywhere. The file it is constructed in is the scope FastAPI's
        // own layout puts them in (one router per module), so the file is
        // silenced and the over-reach is a handler in the same file registered on
        // some other router. That is a missed finding.
        if (declares) silencedFiles.add(structure.filePath);
      } else if (callee === 'include_router') {
        if (declares) {
          const head = /^[A-Za-z_][\w]{0,80}/.exec((args?.[0] ?? '').trim())?.[0];
          const target = head === undefined ? undefined : routerSourceFile(head, structure, known);
          if (target === undefined) projectSilenced = true;
          else silencedFiles.add(target);
        }
      } else if (callee === 'add_middleware') {
        if (args === undefined) projectSilenced = true;
        else if (nameCarriesWord(args[0] ?? '', PY_MIDDLEWARE_SECURITY_WORD)) projectSilenced = true;
      }
      if (PY_SCOPE_CALL.lastIndex === m.index) PY_SCOPE_CALL.lastIndex += 1;
    }

    // Dependency aliases. The right-hand side is captured whole — brackets or
    // parens, whichever the alias opened — so `declaresDependencyCall` can be
    // run over it later with `guardNames` in hand.
    PY_DEPENDENCY_ALIAS.lastIndex = 0;
    for (let m = PY_DEPENDENCY_ALIAS.exec(blanked); m; m = PY_DEPENDENCY_ALIAS.exec(blanked)) {
      const alias = m.groups?.alias;
      const args = alias === undefined ? undefined : callArguments(blanked, m.index + m[0].length - 1);
      if (alias !== undefined && args !== undefined) {
        // A name bound twice project-wide keeps the FIRST binding. Collisions are
        // possible across files and the alternative — concatenating them — would
        // let an unrelated module's `Dep = Annotated[str, Depends(get_db)]` turn
        // into evidence about this one.
        if (!dependencyAliases.has(alias)) dependencyAliases.set(alias, args.join(','));
      }
      if (PY_DEPENDENCY_ALIAS.lastIndex === m.index) PY_DEPENDENCY_ALIAS.lastIndex += 1;
    }

    const content = contentOf.get(structure.filePath);
    if (content !== undefined && middlewareDeclaresGuard(blanked, content)) projectSilenced = true;

    // A `before_request` hook, or a Starlette `@app.middleware("http")`, that
    // refuses requests is application-wide by construction. The guard evidence is
    // required — a `before_request` that only populates `g.user` decides nothing,
    // and silencing on the hook's mere existence would silence every Flask app.
    for (const symbol of structure.symbols) {
      const decs = symbol.decorators ?? [];
      if (!decs.some((d) => /^(?:before_request|before_app_request|middleware)$/.test(lastSegment(d)))) {
        continue;
      }
      if (
        isAuthzGuardName(symbol.name) ||
        isAuthnGuardName(symbol.name) ||
        nameCarriesWord(symbol.name, PY_GUARD_DECORATOR_WORD) ||
        hasGuardBodyEvidence(bodyOf(structure, symbol))
      ) {
        projectSilenced = true;
      }
    }

    // ── The Django URLconf ──────────────────────────────────────────────────
    //
    // The one place this arm ADDS to the population, and it is added because the
    // centralisation cannot be read without reading it: `login_required(view)` in
    // `urls.py` is Django's documented way to guard a function view, and the view
    // itself carries no trace of it. A rule that read only `views.py` would see
    // an unguarded function either way.
    //
    // Two conditions before a file counts as a URLconf, and the second one is the
    // cheap precision: it must name `django`. Real URLconfs import `path` from
    // `django.urls` without exception, and requiring it keeps a `urlpatterns`
    // list in some unrelated framework from promoting arbitrary functions into a
    // population this rule then accuses.
    const isUrlconf =
      /\bdjango\b/.test(blanked) &&
      (structure.filePath.endsWith('/urls.py') ||
        structure.filePath === 'urls.py' ||
        /\burlpatterns[^\S\r\n]{0,4}=/.test(blanked));
    if (!isUrlconf) continue;

    DJANGO_URL_CALL.lastIndex = 0;
    for (let m = DJANGO_URL_CALL.exec(blanked); m; m = DJANGO_URL_CALL.exec(blanked)) {
      const open = m.index + m[0].length - 1;
      const args = callArguments(blanked, open);
      const view = args?.[1]?.trim();
      if (view === undefined || view.length === 0) {
        if (DJANGO_URL_CALL.lastIndex === m.index) DJANGO_URL_CALL.lastIndex += 1;
        continue;
      }
      const asView = PY_AS_VIEW.exec(view);
      if (view.startsWith('include')) {
        // A nested URLconf. The views live in the included module and are read
        // there; recording anything here would be recording the module name.
      } else if (asView) {
        urlconfClassViews.add(lastSegment(asView.groups?.cls ?? ''));
      } else if (PY_BARE_VIEW.test(view)) {
        urlconfFunctionViews.add(lastSegment(view));
      } else {
        // ANYTHING ELSE IS A WRAPPED VIEW AND EVERY NAME IN IT IS GUARDED.
        //
        // `login_required(views.results)` and
        // `permission_required("polls.change")(views.edit)` are the documented
        // shapes, but the test is not "is the wrapper one we recognise" — it is
        // "is the view handed to `path()` unwrapped". `cache_page(60)(view)` is
        // not a guard and silences anyway, which is a missed finding and the
        // correct direction: the alternative is a vocabulary of wrapper names,
        // and a wrapper this rule has not heard of would then leave a correctly
        // guarded view in the population.
        PY_IDENTIFIER.lastIndex = 0;
        for (let id = PY_IDENTIFIER.exec(view); id; id = PY_IDENTIFIER.exec(view)) {
          urlconfGuardedNames.add(id[0]);
          if (PY_IDENTIFIER.lastIndex === id.index) PY_IDENTIFIER.lastIndex += 1;
        }
      }
      if (DJANGO_URL_CALL.lastIndex === m.index) DJANGO_URL_CALL.lastIndex += 1;
    }
  }

  // ── Pass 2: defs that are themselves guards ───────────────────────────────
  for (const structure of pythonFiles) {
    for (const symbol of structure.symbols) {
      if (symbol.kind === 'class') continue;
      // A route handler cannot silence itself. Its body holds the very check
      // being reported, so admitting it here would make the rule structurally
      // incapable of firing — the failure would be total and completely silent.
      if ((symbol.decorators ?? []).some(isRouteDecorator)) continue;
      if (urlconfFunctionViews.has(symbol.name)) continue;
      if (symbol.enclosingClass !== undefined && urlconfClassViews.has(symbol.enclosingClass)) continue;
      if (
        isAuthzGuardName(symbol.name) ||
        isAuthnGuardName(symbol.name) ||
        nameCarriesWord(symbol.name, PY_GUARD_DECORATOR_WORD) ||
        hasGuardBodyEvidence(bodyOf(structure, symbol))
      ) {
        guardNames.add(symbol.name);
      }
    }
  }

  return {
    projectSilenced,
    silencedFiles,
    guardNames,
    urlconfFunctionViews,
    urlconfClassViews,
    urlconfGuardedNames,
    dependencyAliases,
    texts,
  };
}

/**
 * The text of a `def`'s signature, from `def` to the paren that closes it.
 *
 * ★ WHY THE SIGNATURE HAS TO BE RE-READ RATHER THAN SLICED FROM `bodyStart`.
 *
 * The Python indexer sets `bodyStart` to the start of the line AFTER the `def`
 * head line, which for a one-line signature puts the whole signature outside the
 * body — and for FastAPI's documented multi-line signatures puts the SECOND line
 * of the signature INSIDE it. Neither span is the signature, so it is walked here
 * from the head line with paren depth, which is the only reading that is right
 * for both.
 *
 * `undefined` when the signature does not close within `SIGNATURE_LINE_CAP`
 * lines, and the caller drops the handler: an unreadable signature is exactly the
 * case where a `Depends(...)` could be sitting in the part that was not read.
 */
function pythonSignature(
  file: PythonFileText,
  symbol: IndexedSymbol,
): { text: string; endLine: number } | undefined {
  let text = '';
  let depth = 0;
  let opened = false;
  const first = symbol.startLine - 1;
  for (let i = first; i < file.lines.length && i < first + SIGNATURE_LINE_CAP; i += 1) {
    const line = file.lines[i] ?? '';
    text += `${line}\n`;
    for (let k = 0; k < line.length; k += 1) {
      const c = line[k];
      if (c === '(') {
        depth += 1;
        opened = true;
      } else if (c === ')') depth -= 1;
    }
    if (opened && depth <= 0) return { text, endLine: i };
  }
  return undefined;
}

/**
 * Whether a piece of text contains a security-shaped `Depends(…)`/`Security(…)`.
 *
 * Runs over a signature and, unchanged, over the right-hand side of a dependency
 * alias — the two places FastAPI lets the declaration live. Sharing one function
 * is the point: an alias that would have silenced a handler if written inline
 * must silence it when written once and named.
 */
function declaresDependencyCall(text: string, ctx: PythonProjectContext): boolean {
  PY_DEPENDENCY_CALL.lastIndex = 0;
  for (let m = PY_DEPENDENCY_CALL.exec(text); m; m = PY_DEPENDENCY_CALL.exec(text)) {
    // `Security(...)` exists in FastAPI only to carry OAuth2 scopes. There is no
    // non-authorization use of it, so the argument is not consulted.
    if (m.groups?.kind === 'Security') return true;
    const args = callArguments(text, m.index + m[0].length - 1);
    // `Depends()` with no argument infers the dependency from the parameter's
    // ANNOTATION, which is a type this lexical layer cannot follow. Unknown
    // means quiet.
    if (args === undefined || (args[0] ?? '').trim().length === 0) return true;
    const argument = args[0]!;
    if (nameCarriesWord(argument, PY_SECURITY_DEPENDENCY_WORD)) return true;
    if (ctx.guardNames.has(lastSegment(argument.trim()))) return true;
    if (PY_DEPENDENCY_CALL.lastIndex === m.index) PY_DEPENDENCY_CALL.lastIndex += 1;
  }
  return false;
}

/**
 * The ANNOTATION of each parameter in a signature — the `: X` part, without the
 * parameter name and without the default.
 *
 * ★ THE NAME IS DELIBERATELY NOT READ, AND THAT IS WHAT KEEPS THE FLASK ARM
 * ALIVE.
 *
 * Reading parameter NAMES for security words was the obvious version of this and
 * it is wrong for a reason that shows up immediately outside FastAPI:
 * `def delete_post(post_id)` and `def get_profile(user_id)` are ordinary Flask
 * and Django route parameters, `user_id` carries the word `user`, and the arm
 * would have silenced most handlers in both frameworks.
 *
 * An ANNOTATION is different in kind. Flask and Django route parameters are
 * conventionally unannotated or annotated with `int` / `str`; a FastAPI handler
 * that receives an authenticated principal names its TYPE, and that type is
 * either `Annotated[User, Depends(…)]` or an alias for it. So the annotation is
 * where the dependency shows through and the name is not.
 *
 * The residual over-silence is real and named: `user_in: UserUpdate` is a
 * request BODY model, carries `user`, and silences the handler. That costs
 * recall on user-management endpoints, which is where authorization checks
 * concentrate — the worst place to lose it. It is accepted because the
 * alternative was the finding on FastAPI's own template.
 */
function signatureAnnotations(signature: string): string[] {
  const open = signature.indexOf('(');
  if (open === -1) return [];
  const params = callArguments(signature, open);
  if (params === undefined) return [];
  const out: string[] = [];
  for (const param of params) {
    let depth = 0;
    let colon = -1;
    let end = param.length;
    for (let i = 0; i < param.length; i += 1) {
      const c = param[i];
      if (c === '(' || c === '[' || c === '{') depth += 1;
      else if (c === ')' || c === ']' || c === '}') depth -= 1;
      else if (depth === 0 && c === ':' && colon === -1) colon = i;
      else if (depth === 0 && c === '=') {
        end = i;
        break;
      }
    }
    if (colon === -1) continue;
    out.push(param.slice(colon + 1, end));
  }
  return out;
}

/** Whether a signature declares a security-shaped FastAPI dependency. */
function declaresSecurityDependency(signature: string, ctx: PythonProjectContext): boolean {
  if (declaresDependencyCall(signature, ctx)) return true;
  for (const annotation of signatureAnnotations(signature)) {
    if (nameCarriesWord(annotation, PY_SECURITY_DEPENDENCY_WORD)) return true;
    // The alias arm: an annotation naming `CurrentUser` is a dependency
    // declaration written somewhere else in the project. See
    // `PY_DEPENDENCY_ALIAS` for the sweep result that made this necessary.
    PY_IDENTIFIER.lastIndex = 0;
    for (let id = PY_IDENTIFIER.exec(annotation); id; id = PY_IDENTIFIER.exec(annotation)) {
      const rhs = ctx.dependencyAliases.get(id[0]);
      if (rhs !== undefined && declaresDependencyCall(rhs, ctx)) return true;
      if (PY_IDENTIFIER.lastIndex === id.index) PY_IDENTIFIER.lastIndex += 1;
    }
  }
  return false;
}

/**
 * Whether the decorator block above a `def` carries `dependencies=[…]`.
 *
 * `IndexedSymbol.decorators` records decorator NAMES only, so the route-level
 * `@router.get("/x", dependencies=[Depends(verify_token)])` form is invisible
 * there — the guard is in an argument. The block is therefore re-read from the
 * blanked lines.
 *
 * The upward walk tracks bracket depth because a decorator call is routinely
 * written across several lines, and a naive "walk up while the line starts with
 * `@`" stops at the closing `)` and never sees the `dependencies=` above it.
 * That is the same limitation the indexer's own `decoratorsFor` has; it is
 * repaired here rather than there because changing the indexer would move every
 * other consumer's decorator lists.
 */
function decoratorBlockDeclaresDependencies(lines: string[], symbol: IndexedSymbol): boolean {
  let depth = 0;
  for (
    let i = symbol.startLine - 2;
    i >= 0 && i > symbol.startLine - 2 - DECORATOR_BLOCK_LINE_CAP;
    i -= 1
  ) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    const open = (line.match(/[([{]/g) ?? []).length;
    const close = (line.match(/[)\]}]/g) ?? []).length;
    const isContinuation = depth > 0 || /^[)\]}]/.test(trimmed);
    if (!isContinuation && trimmed.length === 0) continue;
    if (!isContinuation && !trimmed.startsWith('@')) return false;
    if (PY_DECORATOR_DEPENDENCIES.test(line)) return true;
    depth += close - open;
    if (depth < 0) depth = 0;
  }
  return false;
}

/**
 * Whether a Django class-based view decides authorization in one place.
 *
 * Returns TRUE — guarded, so quiet — when the class cannot be found or names no
 * bases at all. A `path("x/", Something.as_view())` whose class is not in this
 * file is a class this arm has not read, and a class with no bases is not a
 * Django view (every CBV descends from `View`), so both are cases where the
 * evidence for accusing is missing rather than absent.
 */
function classViewIsGuarded(
  className: string,
  structure: StructureIndex,
): boolean {
  const cls = structure.symbols.find((s) => s.kind === 'class' && s.name === className);
  if (!cls) return true;
  if ((cls.decorators ?? []).some((d) => DJANGO_CLASS_GUARD_DECORATOR.has(lastSegment(d)))) return true;
  const bases = cls.baseClasses ?? [];
  if (bases.length === 0) return true;
  for (const base of bases) {
    const tail = lastSegment(base.trim());
    if (DJANGO_GUARD_MIXIN.has(tail)) return true;
    if (isAuthzGuardName(tail) || isAuthnGuardName(tail)) return true;
    if (nameCarriesWord(tail, PY_GUARD_DECORATOR_WORD)) return true;
  }
  return structure.symbols.some(
    (s) => s.enclosingClass === className && DJANGO_CENTRALISING_METHOD.has(s.name),
  );
}

/**
 * Handler bodies to search in one PYTHON file.
 *
 * Ordered so that every NEGATIVE condition is asked before the symbol is
 * admitted, which is the shape the 041 post-mortem asks for. The two membership
 * tests in the middle are the only positive ones.
 */
function pythonHandlersOf(
  structure: StructureIndex,
  project: ProjectIndex,
  ctx: PythonProjectContext,
): IndexedSymbol[] {
  if (ctx.projectSilenced) return [];
  if (ctx.silencedFiles.has(structure.filePath)) return [];

  const file = ctx.texts.get(structure.filePath);
  if (!file) return [];
  const lines = file.lines;
  const handlers: IndexedSymbol[] = [];

  for (const symbol of structure.symbols) {
    if (symbol.kind === 'class') continue;
    if (isInsideGuard(symbol, project)) continue;
    if (ctx.guardNames.has(symbol.name)) continue;

    const owner = symbol.enclosingClass;
    if (ctx.urlconfGuardedNames.has(symbol.name)) continue;
    if (owner !== undefined && ctx.urlconfGuardedNames.has(owner)) continue;

    const decorators = symbol.decorators ?? [];
    const routeDecorated = decorators.some(isRouteDecorator);
    // A URLconf-bound FUNCTION view is top-level by definition; a method with the
    // same name as some module-level view is not that view.
    const functionView = owner === undefined && ctx.urlconfFunctionViews.has(symbol.name);
    const classViewMethod = owner !== undefined && ctx.urlconfClassViews.has(owner);
    if (!routeDecorated && !functionView && !classViewMethod) continue;

    if (decorators.some((d) => isPythonGuardDecorator(d, ctx))) continue;
    if (classViewMethod && classViewIsGuarded(owner!, structure)) continue;

    // The signature and the CORRECTED body span come together, because both are
    // derived from where the signature ends — see `pythonBodySpan`.
    const def = pythonDef(file, structure, symbol);
    if (def === undefined) continue;
    if (declaresSecurityDependency(def.signature, ctx)) continue;
    if (decoratorBlockDeclaresDependencies(lines, symbol)) continue;

    handlers.push(def.body);
  }

  return handlers;
}

/** Whether a decorator stacked on a route handler is a guard. */
function isPythonGuardDecorator(decorator: string, ctx: PythonProjectContext): boolean {
  const tail = lastSegment(decorator);
  if (tail.length === 0) return false;
  // The route decorator itself is not a guard, and `@app.delete` would otherwise
  // land in the `PY_GUARD_DECORATOR_WORD` net through no word of its own.
  if (isRouteDecorator(decorator)) return false;
  if (isAuthzGuardName(tail) || isAuthnGuardName(tail)) return true;
  if (nameCarriesWord(tail, PY_GUARD_DECORATOR_WORD)) return true;
  // The last resort, and the only one that reads behaviour: the decorator names a
  // project-local def whose body refuses requests. This is what catches a guard
  // called `@ensure_can_edit`, which no vocabulary would have.
  return ctx.guardNames.has(tail);
}

/**
 * Handler bodies to search, per file.
 *
 * Condition (d) of the spec — "concentrated in API route / controller / handler
 * code". A privilege comparison in a model, a helper, or a serializer is not
 * this smell: it may be the single place authorization is decided, which is the
 * opposite of scattered. Restricting the population to registered handlers is
 * what keeps the rule from becoming "you compared a role somewhere".
 *
 * Three ways a symbol qualifies in TS/JS, all of them structural:
 *  - it was written inline at a route registration (`router.get('/x', () => …)`)
 *  - it was named as the handler argument of a registration
 *  - it carries a routing decorator (`@Get()`, `@app.route()`), which is how
 *    Nest and Flask register handlers with no call site to observe
 *
 * Python takes a different path entirely, because `StructureIndex.routes` is
 * always empty for it — see `pythonHandlersOf`.
 */
function handlersOf(
  structure: StructureIndex,
  project: ProjectIndex,
  python: PythonProjectContext | undefined,
): IndexedSymbol[] {
  if (structure.language === 'python') {
    // `python` is undefined only when no Python file reached this rule, in which
    // case this branch is unreachable. Failing quiet rather than asserting keeps
    // a future caller that forgets the context from getting findings instead of
    // an error.
    return python ? pythonHandlersOf(structure, project, python) : [];
  }
  return structure.symbols.filter((s) => {
    if (isInsideGuard(s, project)) return false;
    if (s.kind === 'middleware') return false;
    if (s.kind === 'route-handler') return true;
    return (s.decorators ?? []).some(isRouteDecorator);
  });
}

/** 1-based line/column of an offset, using the file's own line starts. */
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

/** Trim the source text of a check to something printable next to a path. */
function evidenceAt(content: string, offset: number): string {
  const lineEnd = content.indexOf('\n', offset);
  const end = lineEnd === -1 ? content.length : lineEnd;
  return content.slice(offset, Math.min(end, offset + 120)).replace(/\r$/, '').trim();
}

/**
 * Find every inline authorization check inside one handler.
 *
 * Scans the BLANKED body so a privilege comparison written in a comment
 * (`// if (user.role !== 'admin') …`) or inside a string is not evidence of
 * anything. Offsets from the blanked copy are valid in the original because
 * every blanker in `@vibeguard/rules` is length-preserving, so `evidence` and
 * the elevated-privilege test read the real text at the same positions.
 */
function checksIn(
  handler: IndexedSymbol,
  structure: StructureIndex,
  content: string,
  boost: { securityPath: boolean; routingLayer: boolean; mutatesData: boolean },
): CheckSite[] {
  const body = structure.blanked.slice(handler.bodyStart, handler.bodyEnd);
  const sites: CheckSite[] = [];
  const seenOffsets = new Set<number>();

  for (const pattern of authzDecisionPatterns()) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(body); m; m = pattern.exec(body)) {
      const g = m.groups ?? {};
      const prop = g.prop;
      if (!prop) continue;
      const propOffsetInMatch = m[0].lastIndexOf(prop);
      const absolute = handler.bodyStart + m.index + Math.max(0, propOffsetInMatch);

      // The three patterns overlap: `!user.isAdmin` matches FLAG, and
      // `user.isAdmin === false` matches both CMP and FLAG. Counting one check
      // twice would inflate `duplicatedCheckCount`, which is the number a
      // reviewer is being asked to trust, so dedupe on the property's position.
      if (seenOffsets.has(absolute)) continue;
      seenOffsets.add(absolute);

      // ── A method CALL is delegation, not an inline check. ─────────────────
      //
      // `not auth_mgr.is_admin(current_user)` is the well-factored shape this
      // rule exists to recommend: the decision lives in `auth_mgr`, and the
      // handler asks it. Counting it as a scattered inline check inverts the
      // rule's meaning — it accuses the codebases that did the right thing.
      //
      // Found by evaluation, on a real repository whose handlers all delegate
      // to one `auth_mgr`. The property-name patterns cannot see the difference
      // because `is_admin` is both a plausible boolean field and a plausible
      // predicate method; what separates them is the `(` that follows.
      const afterProp = handler.bodyStart + m.index + propOffsetInMatch + prop.length;
      if (/^[^\S\r\n]{0,4}\(/.test(structure.blanked.slice(afterProp, afterProp + 6))) continue;

      const startOfMatch = handler.bodyStart + m.index;
      const text = evidenceAt(content, startOfMatch);
      const { line, column } = positionOf(content, startOfMatch);
      const recv = (g.recv ?? '').split('.').pop() ?? '';

      // ── Chat-message role, not privilege role. See CHAT_ROLE_LITERAL. ──────
      //
      // Read the literal being compared against from the ORIGINAL text: the
      // blanked copy has spaces where the string contents were, which is
      // exactly the information needed here. `text` is sliced from `content`,
      // so it still carries it.
      if (prop === 'role' || prop === 'roles') {
        const compared = /(?:===|!==|==|!=)\s{0,4}(['"`][^'"`\n]{0,40}['"`])/.exec(text)?.[1];
        if (compared && CHAT_ROLE_LITERAL.test(compared)) {
          // Unambiguous: nobody grants a person the `assistant` role.
          continue;
        }
        // ORDER MATTERS, and getting it wrong cost real detections. The receiver
        // name is the WEAKER signal and may only decide when the stronger one is
        // unavailable. An earlier version applied it unconditionally, so
        // `entry.role !== 'admin'` — a textbook privilege check that happens to
        // sit inside a `for (const entry of users)` loop — was discarded on the
        // strength of the loop variable's name. A comparison against a literal
        // that is NOT a chat role is a privilege check whatever the receiver is
        // called, so the receiver gets no vote in that case.
        if (!compared && MESSAGE_RECEIVER.test(recv)) continue;
      }
      sites.push({
        filePath: handler.filePath,
        line,
        column,
        evidence: text,
        signature: `${recv}.${prop}${g.op ? ` ${g.op}` : ''}${g.call ? `.${g.call}()` : ''}`,
        elevated: ELEVATED.test(text),
        // Per-SITE, even though two of the three are per-file and the third is
        // per-handler. The rule aggregates them with ∃ anyway, so carrying them
        // per site costs three booleans and buys the analysis in #22e the only
        // form of the data it can actually count.
        securityPath: boost.securityPath,
        routingLayer: boost.routingLayer,
        mutatesData: boost.mutatesData,
        handlerName: handler.name,
      });
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
  }

  return sites;
}

/**
 * Every inline authorization check in the project, BEFORE `MIN_SITES` and
 * `MIN_FILES` are applied.
 *
 * ★ EXPORTED FOR THE SENSITIVITY ANALYSIS (#22e), and the threshold-free part
 * of that sentence is the contract.
 *
 * The analysis has to answer "how many findings would this rule produce at a
 * lower threshold" — and the only honest way to answer it is with the shipped
 * thresholds untouched, because a study that moves the numbers it is studying
 * measures its own edit. So the thresholds stay exactly where they are, in
 * `analyze` below, and the population is exposed here for anyone who wants to
 * re-slice it. Callers that want the shipped verdict call the rule; callers that
 * want to know what the rule is standing on call this.
 *
 * What this does NOT relax is the negative conditions. Guards, delegated calls,
 * chat-message roles, non-handlers, test paths, and non-TS/JS files are excluded
 * here exactly as they are for a shipped finding. Those are not thresholds and
 * lowering them would not be a sensitivity analysis — it would be a different
 * rule, whose numbers say nothing about this one.
 */
export function collectScatteredAuthSites(project: ProjectIndex): readonly CheckSite[] {
  const sites: CheckSite[] = [];

  // Deterministic order. The finding's primary location is the first site, and
  // `relatedLocations` follows scan order, so an unsorted walk would produce a
  // different primary between runs — a finding that appears to move on its own
  // is one no baseline can track.
  const files = [...project.structures.keys()].sort();

  // Built once, for the whole project, and only when there is Python to reason
  // about. The Python arm's silencers are project-wide facts (an application-wide
  // middleware, a `FastAPI(dependencies=…)`) and its Django URLconf pass is
  // cross-file by nature — `urls.py` names views defined in `views.py` — so a
  // per-file computation would give a different answer depending on which file
  // was reached first. Skipping it entirely for a TS-only project keeps this
  // rule's cost on its existing population exactly where it was.
  const python = [...project.structures.values()].some((s) => s.language === 'python')
    ? buildPythonContext(project)
    : undefined;

  for (const filePath of files) {
    if (TEST_PATH.test(filePath)) continue;
    const structure = project.structures.get(filePath)!;
    // PER-FILE language filter. `runCrossFileRules` gates at the PROJECT level
    // ("does this project contain any language the rule handles"), which is the
    // right question for whether to run the rule at all and the wrong one for
    // which files it may read. A polyglot repository — TS front end, Python
    // back end — passes the project gate and then handed this rule every `.py`
    // file, whose authorization idioms it was explicitly descoped from
    // understanding. Evaluation over real repositories caught it: a finding
    // that reached the report cited only Python sites.
    if (!scatteredAuthorization.languages.includes(structure.language)) continue;
    const source = project.files.find((f) => f.filePath === filePath);
    if (!source) continue;
    // Conditions ① and ② are properties of the FILE, so they are decided once
    // here rather than per handler or per site. ③ is per handler and is decided
    // inside the loop.
    const securityPath = isSecurityPath(filePath);
    const routingLayer = isRoutingLayer(filePath);
    for (const handler of handlersOf(structure, project, python)) {
      sites.push(
        ...checksIn(handler, structure, source.content, {
          securityPath,
          routingLayer,
          mutatesData: mutatesData(handler, structure, source.content),
        }),
      );
    }
  }

  return sites;
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
  const sites = [...collectScatteredAuthSites(project)];

  if (sites.length < MIN_SITES) return [];
  const distinctFiles = new Set(sites.map((s) => s.filePath));
  if (distinctFiles.size < MIN_FILES) return [];

  // Sites are already in file order; within a file, put them in line order so
  // the report reads top to bottom.
  sites.sort((a, b) =>
    a.filePath === b.filePath ? a.line - b.line : a.filePath < b.filePath ? -1 : 1,
  );

  const [primary, ...related] = sites;

  /**
   * Severity, and the Security Context Boost (#22d, design addendum §10.3).
   *
   * ∃ over the sites, the same aggregation `elevated` has always used. The
   * alternative — require the boost to hold for EVERY site — was rejected: a
   * finding is one statement about a policy spread over N places, and the
   * dangerous property of that policy is the worst thing any one of its sites
   * does. A policy that is enforced ad hoc in four handlers, one of which
   * deletes rows, is exactly as bad as if all four did; requiring unanimity
   * would let a single read-only endpoint cancel the observation.
   *
   * ★ THREE CONDITIONS ARE DETECTED, TWO ARE SCORED, AND THE SPLIT IS MEASURED.
   *
   * `routingLayer` is left out on evidence, not on taste: it holds for 103 of
   * the 108 check sites in `paper_data/corpus1k_vibe` (95.4%). The full table and
   * the reasoning are on `ROUTING_LAYER_TOKEN`; the short version is that a
   * condition true of 19 sites in 20 cannot partition a severity.
   *
   * Note what that decision does NOT rest on: `boost-none` has `routingLayer`
   * false, so the sentinel fixture would still pass if the condition WERE scored.
   * The fixtures cannot stand in for the prevalence figure, which is exactly why
   * the figure is written down rather than the intuition.
   *
   * The two that are scored measure 20.4% (`securityPath`) and 37.0%
   * (`mutatesData`) over those same 108 sites. `mutatesData` is kept for what it
   * is a proxy FOR: authorization scattered across endpoints that only read is a
   * disclosure risk, and the same shape across endpoints that write is a
   * corruption risk as well. That is a difference in CONSEQUENCE, which is the
   * thing severity is supposed to encode.
   *
   * ★★ THE MEASUREMENT THAT ARGUED AGAINST ALL OF THIS — AND WHAT IT CHANGED
   *
   * This block used to record `mutatesData` at 58.3% of sites, and to admit the
   * consequence: ∃-aggregation turns a per-site rate p into a per-finding rate of
   * 1 − (1 − p)^n over at least three sites, which at p = 0.583 is ≥ 93%. The
   * corpus agreed — all 9 projects with any site had a mutating handler, and all
   * 5 findings came out `high`. Every `medium` in the real corpus disappeared.
   * That is the same disease `routingLayer` was rejected for, and the honest
   * record of it is what made the next step obvious.
   *
   * The next step was not to drop the condition. It was to notice that the rate
   * was inflated by a vocabulary that did not mean what it said: `.update(`,
   * `.delete(`, `.insert(`, `.destroy(` and a SQL verb pair unaccompanied by any
   * SQL syntax. Six shapes, each of which raised the `boost-none` sentinel to
   * `high` on its own, are listed on `MUTATING_METHOD` and `SQL_MUTATION`. With
   * the vocabulary narrowed to names that only a data store uses:
   *
   *   site level     58.3% → 37.0%   (108 sites, corpus1k_vibe)
   *   finding level  5 of 5 → 3 of 5
   *   severity       5 high / 0 medium → 4 high / 1 medium
   *
   * The medium band is back, and the finding that left the `high` band is the one
   * of the five whose own draft TP/FP label is FP. The condition now partitions
   * instead of saturating, which is what the design addendum wanted from it.
   *
   * ★ THE TRIGGER TO REVISIT, stated so it is not a matter of remembering: if a
   * labelled corpus ever shows the medium band empty across ≥ 20 findings, the
   * fix is NOT to delete this condition — it is to stop aggregating it with ∃.
   * "A majority of the sites mutate" is the shape to try first, because it keeps
   * the consequence argument and drops the arithmetic that ruins it.
   * `samples/crossfile-fixtures/boost-none` is the fixture that will still be
   * `medium` either way, which is why it exists.
   *
   * What is NOT here: the diff condition. See the note above the rule export.
   */
  const elevated = sites.some((s) => s.elevated);
  const securityPath = sites.some((s) => s.securityPath);
  const dataMutation = sites.some((s) => s.mutatesData);
  const severity: Severity = elevated || securityPath || dataMutation ? 'high' : 'medium';

  /**
   * Why the boost does NOT add `securityContext` flags.
   *
   * The obvious move is to set `containsSensitiveDataFlow` when a handler
   * mutates, or `containsTokenLogic` when the path says `token`. Both would be
   * claims this rule did not make. The six flags in the schema describe what a
   * finding's code CONTAINS; the boost's evidence is about where the file sits
   * and what else the handler happens to call, and neither observation licenses
   * a statement about the data being sensitive or about token handling being
   * present. `containsAuthorizationLogic` stays the only one set, because it is
   * the only one the rule actually established.
   *
   * The boost reason is therefore reported in prose, in `description` below,
   * where it can be qualified. A consumer that needs it structurally can read
   * the per-site flags through `collectScatteredAuthSites`.
   */
  const boostReason = elevated
    ? 'the checks name an administrator-level privilege'
    : securityPath && dataMutation
      ? 'the checks sit on a security-named path and the handlers write to a data store'
      : securityPath
        ? 'the checks sit on a security-named path'
        : dataMutation
          ? 'the handlers guarded this way write to a data store'
          : '';

  /**
   * Confidence, per design addendum §10.2 read honestly against what this
   * implementation actually knows.
   *
   * §10.2 says cross-file confirmation earns `high`. Taken literally every
   * finding this rule emits would be `high`, since cross-file confirmation is
   * its firing condition — which would make the field carry no information. The
   * evidence here is also structural rather than semantic: the indexer is
   * lexical, so "this is a handler" and "this is a privilege comparison" are
   * both strong inferences rather than facts. `medium` is therefore the floor,
   * and `high` is reserved for the case where the pattern is emphatic enough
   * that the lexical uncertainty stops mattering — five or more sites spread
   * over three or more files.
   */
  const confidence: Confidence =
    sites.length >= 5 && distinctFiles.size >= 3 ? 'high' : 'medium';

  const toLocation = (s: CheckSite): CodeLocation => ({
    filePath: s.filePath,
    startLine: s.line,
    startColumn: s.column,
    evidence: s.evidence,
  });

  const spellings = new Set(sites.map((s) => s.signature));

  return [
    {
      ruleId: 'VG-SMELL-010',
      title: 'Scattered Authorization',
      description:
        `Authorization is decided inline in ${sites.length} route handlers across ` +
        `${distinctFiles.size} files, rather than in one guard the routes share. ` +
        `Each check may be correct; the risk is the endpoint added next, which has ` +
        `nothing structural to remind anyone that a check belongs there. ` +
        (spellings.size > 1
          ? `The ${sites.length} checks are written ${spellings.size} different ways, so they ` +
            `cannot be audited or changed as one policy.`
          : `The same check is repeated verbatim, which is a policy with no single home.`) +
        (boostReason === '' ? '' : ` Reported at ${severity} because ${boostReason}.`),
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      scope: 'project',
      filePath: primary!.filePath,
      startLine: primary!.line,
      startColumn: primary!.column,
      evidence: sites.map((s) => `${s.filePath}:${s.line} ${s.evidence}`),
      primaryLocation: toLocation(primary!),
      relatedLocations: related.map(toLocation),
      /**
       * `duplicatedCheckCount` is this rule's own measurement — no shared module
       * can count "inline authorization checks", because the definition of one
       * IS the rule. The fan numbers are the opposite case and come from
       * `metrics-calculator`, which is the module the design addendum §8.2 makes
       * responsible for them.
       *
       * Routing them through the shared module rather than counting edges here
       * is the point: `fanIn` on the file holding the primary check answers "how
       * many other modules depend on the file where authorization is being
       * decided ad hoc", and a reader comparing this finding against a future
       * VG-SMELL-021 (High Fan-out Security Module) must be reading the same
       * definition of fan-in in both. Two rules computing it privately is how
       * two findings in one report end up disagreeing about a number they both
       * call `fanIn`.
       */
      metrics: mergeMetrics(fanMetrics(primary!.filePath, project.graph), {
        duplicatedCheckCount: sites.length,
      }),
      securityContext: { containsAuthorizationLogic: true },
      tags: ['design-smell', 'cross-file', 'authorization'],
      remediation: {
        why:
          'Authorization written per handler has no single place to audit and no ' +
          'structural reminder for the next endpoint. Every added route is an ' +
          'opportunity to omit the check, and an omission looks exactly like a ' +
          'route that legitimately needs no check.',
        how:
          'Extract the check into one middleware or policy function and apply it at ' +
          'route registration, so an unprotected route is visible at the place routes ' +
          'are declared rather than only by reading each handler body.',
        exampleFix:
          "router.get('/admin/users', requireRole('admin'), listUsers);\n" +
          '// listUsers no longer decides authorization; the registration does.',
      },
    },
  ];
}

/**
 * `severity` and `confidence` above depend only on the code being analysed —
 * never on the diff it arrived in.
 *
 * Design addendum §10.3 lists "code newly added in a PR diff" among the Security
 * Context Boost conditions, and the implementation plan §5.4 forbids it. §5.4 is
 * the later decision and is the correct one: a severity that depends on which
 * diff a file was scanned in gives the same code two different verdicts on the
 * branch and on `main`, which breaks reproducibility and every baseline built on
 * it. The conflict is resolved here, in code, rather than left as a note — and
 * the schema declines to carry diff provenance at all, so the boost is not
 * merely unimplemented but unexpressible.
 */
export const scatteredAuthorization: CrossFileRule = {
  ruleId: 'VG-SMELL-010',
  name: 'Scattered Authorization',
  description:
    'Authorization checks are written inline across multiple route handlers and files ' +
    'instead of in a shared guard.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  /**
   * TS/JS in 0.3.0-α; Python readmitted in 0.3.0-β (#27b). This list is ENFORCED
   * by `runCrossFileRules` rather than being documentation, so the entry below is
   * what makes the Python arm run at all.
   *
   * ★ WHAT WAS WRONG THE FIRST TIME, AND WHAT HAD TO EXIST BEFORE IT CAME BACK.
   *
   * Python was listed here in α and the DETECTION genuinely worked — a review
   * pass built a Flask fixture (`@app.route` handlers with inline
   * `request.user.role != 'admin'` checks) and the rule fired on it correctly.
   * It was removed anyway, because working is not the bar. Not one negative
   * fixture under `samples/crossfile-fixtures/` was written in Python, so the
   * only thing never exercised was the half that matters: whether the rule stays
   * SILENT on well-factored Python. Flask, FastAPI and Django each centralise
   * authorization through a different mechanism — a stacked decorator, a
   * `Depends(...)` parameter, a URLconf wrapper, a CBV mixin — and none of the
   * negative conditions recognised any of them. A guard expressed as
   * `Depends(get_current_active_user)` was invisible, so the well-factored
   * FastAPI service looked exactly like the scattered one.
   *
   * What changed is not the detection, which is unaltered: it is the negative
   * side, which now exists (`THE PYTHON ARM`, above) and is pinned by three
   * negative fixtures built from the shape of each framework's own documentation
   * — `smell-010-py-neg-flask`, `-neg-fastapi`, `-neg-django`. Each is asserted
   * silent AND asserted to FIRE once its centralising element is removed from a
   * copy, because a negative fixture that would have been silent anyway pins
   * nothing; `smell-010-py-positive` is the control that the arm is alive rather
   * than disabled by accident.
   *
   * The order that produced this entry is the order the evidence has to arrive
   * in: negatives, then the tests pinning silence, then the positive, then this
   * line. Adding this line first is what shipped the α regression.
   */
  languages: ['typescript', 'javascript', 'python'],
  cwe: ['CWE-284', 'CWE-862'],
  owasp: ['A01:2021 Broken Access Control'],
  remediation: {
    why: 'Duplicated authorization has no single place to audit, so the next endpoint is the one that forgets.',
    how: 'Centralise the check in a middleware or policy applied at route registration.',
  },
  analyze,
};
