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

/** One inline authorization check found inside one handler. */
interface CheckSite {
  filePath: string;
  line: number;
  column: number;
  /** Source text of the check, from the original content. */
  evidence: string;
  /** Receiver + property, normalised, for reporting how many spellings appear. */
  signature: string;
  elevated: boolean;
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
        handlerName: handler.name,
      });
      if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
    }
  }

  return sites;
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
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
    for (const handler of handlersOf(structure, project)) {
      sites.push(...checksIn(handler, structure, source.content));
    }
  }

  if (sites.length < MIN_SITES) return [];
  const distinctFiles = new Set(sites.map((s) => s.filePath));
  if (distinctFiles.size < MIN_FILES) return [];

  // Sites are already in file order; within a file, put them in line order so
  // the report reads top to bottom.
  sites.sort((a, b) =>
    a.filePath === b.filePath ? a.line - b.line : a.filePath < b.filePath ? -1 : 1,
  );

  const [primary, ...related] = sites;
  const elevated = sites.some((s) => s.elevated);
  const severity: Severity = elevated ? 'high' : 'medium';

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
          : `The same check is repeated verbatim, which is a policy with no single home.`),
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
