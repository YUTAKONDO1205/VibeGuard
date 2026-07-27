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
const AUTHZ_PROPERTY =
  '(?:role|roles|userRole|user_role|isAdmin|is_admin|isOwner|is_owner|isSuperuser|is_superuser|isRoot|permissions|permission|privileges|privilege|scopes|accessLevel|access_level)';

/**
 * A privilege comparison: `user.role !== 'admin'`, `req.user.role === ROLE_ADMIN`.
 *
 * The receiver is bounded (`[\w$.]{0,40}`) and horizontal whitespace uses
 * `[^\S\r\n]{0,4}` rather than `\s*` throughout this file. That is not style.
 * Unbounded whitespace sitting next to another quantifier is the shape that
 * makes a pattern super-linear on adversarial input, and this project has
 * already had to repair rules written that way — the bounds in
 * `@vibeguard/rules` (`REGEX_DEADLINE_MS`, `REGEX_INPUT_CAP`) exist because of
 * it. Every quantifier here has a ceiling, and new ones must too.
 */
const CMP = new RegExp(
  String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>${AUTHZ_PROPERTY})\b[^\S\r\n]{0,4}(?<op>===|!==|==|!=|<|>|<=|>=)`,
  'g',
);

/** A boolean privilege flag used directly: `if (!user.isAdmin)`, `if (user.isAdmin)`. */
const FLAG = new RegExp(
  String.raw`(?:!|\bnot[^\S\r\n]{1,4}|\bif[^\S\r\n]{0,4}\(?[^\S\r\n]{0,4})(?<recv>[\w$][\w$.]{0,40})\.(?<prop>isAdmin|is_admin|isOwner|is_owner|isSuperuser|is_superuser|isRoot|hasAccess)\b`,
  'g',
);

/** A membership test over a privilege collection: `user.permissions.includes('x')`. */
const MEMBERSHIP = new RegExp(
  String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>permissions|roles|scopes|privileges)\b[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}(?<call>includes|indexOf|has|contains|some)[^\S\r\n]{0,4}\(`,
  'g',
);

/**
 * Privilege words that make the finding `high` rather than `medium`.
 *
 * From design addendum §7.2: "medium; high when it involves administrator or
 * owner privilege". Matched against the ORIGINAL source text of the check, not
 * the blanked copy, because the word usually lives inside the string literal
 * being compared against — which blanking, by design, erases.
 */
const ELEVATED = /\b(admin|administrator|owner|superuser|super_user|root|sudo)\b/i;

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

/** Any character that cannot appear inside an identifier word. */
const NON_WORD_CHAR = /[^A-Za-z0-9]/;

/** The camelCase seam: a lowercase or digit immediately followed by a capital. */
const CAMEL_SEAM = /([a-z0-9])([A-Z])/g;

/**
 * Split a path (or one segment of one) into lowercase words.
 *
 * ★ WORD MATCHING, NEVER SUBSTRING MATCHING. This is the whole reason the
 * function exists rather than `/auth/i.test(filePath)`, and the counterexample
 * is not hypothetical: `src/authors/list.ts`, `content/authoring/draft.ts`, and
 * `lib/authority.ts` are ordinary directory names that all contain `auth`. A
 * substring test promotes every blog and CMS in existence to `high` on the
 * strength of the word "author". Segmenting first means `authors` is a word this
 * vocabulary does not contain, and the question stops being close.
 *
 * The same argument, made about identifiers rather than paths, is already
 * written out at length on `tokenize` in `../symbol-table/index.ts`. This is a
 * second, small implementation rather than an import because that one is private
 * to a module that deliberately never touches file content, and widening its
 * surface to share four lines would be the more expensive change.
 *
 * Neither regex has a quantifier at all — `split` on a single-character class,
 * then one substitution at a two-character seam — so neither can backtrack and
 * the D3 three-second contract is satisfied by construction rather than by
 * measurement.
 */
function pathWords(text: string): string[] {
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

/** Path segments whose contents are fixtures, not the service under review. */
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|e2e|testdata)(?:\/|$)|\.(?:test|spec)\.[\w]+$/i;

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
 * Handler bodies to search, per file.
 *
 * Condition (d) of the spec — "concentrated in API route / controller / handler
 * code". A privilege comparison in a model, a helper, or a serializer is not
 * this smell: it may be the single place authorization is decided, which is the
 * opposite of scattered. Restricting the population to registered handlers is
 * what keeps the rule from becoming "you compared a role somewhere".
 *
 * Three ways a symbol qualifies, all of them structural:
 *  - it was written inline at a route registration (`router.get('/x', () => …)`)
 *  - it was named as the handler argument of a registration
 *  - it carries a routing decorator (`@Get()`, `@app.route()`), which is how
 *    Nest and Flask register handlers with no call site to observe
 */
function handlersOf(structure: StructureIndex, project: ProjectIndex): IndexedSymbol[] {
  const decoratorRoute = /^(?:get|post|put|patch|delete|head|options|all|route|api_route|websocket)$/i;
  return structure.symbols.filter((s) => {
    if (isInsideGuard(s, project)) return false;
    if (s.kind === 'middleware') return false;
    if (s.kind === 'route-handler') return true;
    const decs = s.decorators ?? [];
    return decs.some((d) => decoratorRoute.test(d.split('.').pop() ?? ''));
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

  for (const pattern of [CMP, FLAG, MEMBERSHIP]) {
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
    for (const handler of handlersOf(structure, project)) {
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
   * TS/JS only in 0.3.0-α, and this list is now ENFORCED by `runCrossFileRules`
   * rather than being documentation.
   *
   * Python was listed here first, and the detection genuinely worked — a review
   * pass built a Flask fixture (`@app.route` handlers with inline
   * `request.user.role != 'admin'` checks) and the rule fired on it correctly.
   * It is removed anyway, because working is not the bar. Not one of the
   * negative fixtures under `samples/crossfile-fixtures/` is written in Python,
   * so the only thing never exercised was the half that matters: whether the
   * rule stays SILENT on well-factored Python. Flask, FastAPI, and Django each
   * centralise authorization through a different mechanism — a decorator, a
   * `Depends(...)` parameter, a URLconf-level wrapper — and none of the negative
   * conditions in this file recognise any of them. A guard expressed as
   * `Depends(require_admin)` is invisible to `handlersOf`, so the well-factored
   * FastAPI service would look exactly like the scattered one.
   *
   * Shipping that would have meant the flagship rule's first contact with Python
   * users was a false positive on correct code, in a project whose stated
   * contract is that a design smell firing on well-factored code is a bug. The
   * structure indexer's Python arm is real and tested and stays; what waits for
   * β is this rule's Python fixtures and the framework-specific guard detection
   * they would pin.
   */
  languages: ['typescript', 'javascript'],
  cwe: ['CWE-284', 'CWE-862'],
  owasp: ['A01:2021 Broken Access Control'],
  remediation: {
    why: 'Duplicated authorization has no single place to audit, so the next endpoint is the one that forgets.',
    how: 'Centralise the check in a middleware or policy applied at route registration.',
  },
  analyze,
};
