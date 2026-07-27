// vibeguard:disable-file VG-SMELL-012 VG-SMELL-004 VG-SMELL-003
// This file *defines* the single-file design-smell rules; the literal role
// strings ("admin", "root"), utility names, and security keywords appear inside
// the rule regexes, descriptions, and remediation text by design. Scanning this
// file with its own rules would self-flag those, so it is exempt.
//
// 0.2.x — SECOND DEFENCE LINE (single-file design smells), category
// "security-design-smell". These are LEXICAL heuristics computed inside match()
// from ctx.content/ctx.lines: no AST, no cross-file, no new finding schema (that
// is 0.3.0's analysis-graph). Each rule favours PRECISION over recall — the
// project ships a hard `samples/safe == 0 findings` gate, so a design smell that
// fires on well-factored code is a bug, not a near-miss.
import type { RuleContext, RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  blankCommentsAndStrings,
  blankJsLiterals,
  blankPyLiterals,
  extractBlockAfter,
  indexToPosition,
  runRegex,
  REGEX_INPUT_CAP,
} from '../matcher-utils.js';
import { isTestPath } from '../confidence.js';

// D3 — the hand-rolled scans below (unlike runRegex) do not truncate on their
// own, so cap here for parity with every runRegex-based rule: no rule reads past
// REGEX_INPUT_CAP. Slicing a prefix keeps all offsets valid.
function capped(ctx: RuleContext): { content: string; lines: string[] } {
  if (ctx.content.length <= REGEX_INPUT_CAP) return { content: ctx.content, lines: ctx.lines };
  const content = ctx.content.slice(0, REGEX_INPUT_CAP);
  return { content, lines: content.split('\n') };
}

// A security-relevant token anywhere in a method body/name promotes the method
// from "long" to "long AND security-relevant" — the whole point of the smell.
const SECURITY_KW = /auth|login|permission|role|token|session|validate|sanitiz|encrypt|hash|password|credential|access/i;
// The subset that makes a long method an AUTHORIZATION method (spec: high). Split
// so the word tokens match case-insensitively (`checkUserPermissions` escalates)
// while `canX` stays camelCase-specific (so it does not fire on `cancel`).
const AUTHZ_WORDS = /permission|\brole\b|authoriz|access[-_ ]?control|isallowed|\bgrant|privilege/i;
const AUTHZ_CAMEL = /\bcan[A-Z]/;
const isAuthz = (s: string): boolean => AUTHZ_WORDS.test(s) || AUTHZ_CAMEL.test(s);

// Branch-ish tokens for the cyclomatic proxy. Counted on the blanked body so a
// keyword inside a string/comment never inflates the count.
const BRANCH_WORD = /\b(?:if|else\s+if|elif|for|while|case|when|catch|except)\b/g;
const BRANCH_OP = /&&|\|\||(?<![?.:])\?(?![.?:=])/g; // ternary `?`, not `?.`/`??`/`?:`?=
const PY_BRANCH_OP = /\b(?:and|or)\b/g;

// Thresholds: a security method is "long AND deeply nested AND branchy" when its
// body is >= 80 lines, nests >= 4 blocks deep, and has >= 10 decision points.
const MIN_LINES = 80;
const MIN_NESTING = 4;
const MIN_BRANCHES = 10;
const MAX_HEADS = 200;

/**
 * Function/method heads in a brace language, each with the name it binds.
 *
 * Four alternatives, in order: `function` declarations (fnA), `const f = …`
 * bindings (fnB), a method head whose `)` is followed directly by `{` (fnC), and
 * — 17z-f-lite — a method head separated from its `{` by a TYPE ANNOTATION (fnD).
 *
 * 17z-f-lite (the TypeScript recall gap). §17z-f parked this on "AST in 0.3.0
 * resolves it naturally"; 0.3.0-α shipped WITHOUT an AST, so the premise expired
 * and the lexically-reachable part is taken here. Two shapes were invisible:
 *
 *  - `authorize(user: User): Promise<boolean> {` — fnC requires `)` `{` adjacency,
 *    so every annotated method in a TS codebase was skipped. (An annotated
 *    `function` declaration was already fine: fnA stops at `(` and lets
 *    `extractBlockAfter` walk to the brace.) That is now fnD.
 *  - `fetchAll<T>(…)` — a generic parameter list sits between the name and `(`,
 *    which none of the alternatives allowed. Now an OPTIONAL group on fnA/fnC/fnD.
 *
 * BOTH ARE WRITTEN AROUND FIXED ANCHORS (`<`…`>` and `:`…`{`) so no two
 * variable-length runs are ever adjacent — the D3 rule. The generics group is one
 * bounded run inside literal angle brackets that the run itself cannot contain;
 * fnD's return type is one bounded run that cannot contain `{`, so it is pinned
 * against the literal `{` that ends it, and it excludes `?`, `;`, `=`, `(` and `)`
 * so it cannot walk across a ternary, a statement boundary, an assignment or a
 * function-type annotation into an unrelated block. Because the group is optional
 * and can only start at a literal `<`, a head with no generics matches EXACTLY the
 * text it matched before this change.
 *
 * STILL OUT OF REACH, and deliberately (each needs balanced-delimiter or
 * multi-line reasoning, i.e. the parser this file refuses to become). The list
 * below was CORRECTED on 2026-07-28 after the regex was executed against each
 * shape instead of reasoned about; the previous version claimed three things
 * that are in fact detected, which is the opposite error but the same kind — a
 * drop-list nobody re-measured.
 *
 *   NOT detected (true false negatives):
 *     - a parameter list containing parentheses:
 *         `verify(cb: (x: number) => void) {`   `verify(a = makeDefault()) {`
 *       fnC/fnD both scan the list with `[^()\n]`, so any inner paren ends it.
 *     - a parameter list broken across lines, for the METHOD forms (fnC/fnD).
 *     - nested generics in the TYPE-PARAMETER position:
 *         `verify<T extends Map<string, number>>(a: T) {`
 *     - object-literal and function return types: `: { ok: boolean }`,
 *       `: (x: number) => void`  — fnD's run excludes `{`, `(` and `)`.
 *     - return-type-annotated arrow bindings: `const f = (x): T => {` (fnB).
 *
 *   DETECTED, contrary to what this comment used to claim:
 *     - single-line destructured parameters — `verify({ user, ctx }) {` — the
 *       braces carry no parentheses, so fnC's `\([^()\n]{0,200}\)` swallows them.
 *     - nested generics in the RETURN position — `: Promise<Map<string, X>> {`
 *       — fnD's return run permits `<` and `>`.
 *     - multi-line parameter lists on a `function` DECLARATION, because fnA
 *       ends at the opening `(` and never looks at the list.
 *
 * Everything in the first list is a false NEGATIVE, which is the side a
 * precision-first rule is allowed to be wrong on.
 */
const JS_HEAD =
  /(?:^|[^\w$.])(?:async[^\S\r\n]{1,4})?function[^\S\r\n]{0,4}(?<fnA>[\w$]{0,60})(?:<[^<>()\n]{0,80}>)?[^\S\r\n]{0,4}\(|(?:const|let|var)[^\S\r\n]{1,4}(?<fnB>[\w$]{1,60})[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:async[^\S\r\n]{0,4})?(?:function\b|\([^()\n]{0,200}\)[^\S\r\n]{0,4}=>|[\w$]{1,40}[^\S\r\n]{0,4}=>)|(?:^|[^\w$.])(?:public|private|protected|static|async|readonly|[^\S\r\n]){0,6}(?<fnC>(?!(?:if|for|while|switch|catch|return|function|await|typeof|do|else)\b)[\w$]{1,60})(?:<[^<>()\n]{0,80}>)?[^\S\r\n]{0,4}\([^()\n]{0,200}\)[^\S\r\n]{0,4}\{|(?:^|[^\w$.])(?:public|private|protected|static|async|readonly|[^\S\r\n]){0,6}(?<fnD>(?!(?:if|for|while|switch|catch|return|function|await|typeof|do|else)\b)[\w$]{1,60})(?:<[^<>()\n]{0,80}>)?[^\S\r\n]{0,4}\([^()\n]{0,200}\)[^\S\r\n]{0,4}:[^\S\r\n]{0,4}[A-Za-z_$][^{}()?;=\n]{0,120}\{/g;

interface BodyMetrics {
  lines: number;
  nesting: number;
  branches: number;
}

/** Metrics of a brace-language body (already comment/string-blanked). */
function jsBodyMetrics(body: string): BodyMetrics {
  let depth = 0;
  let maxDepth = 0;
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i];
    if (c === '{') {
      depth += 1;
      if (depth > maxDepth) maxDepth = depth;
    } else if (c === '}') {
      if (depth > 0) depth -= 1;
    }
  }
  // The body includes its own outer `{ }`, so nesting depth of the CONTENTS is
  // maxDepth - 1.
  const nesting = Math.max(0, maxDepth - 1);
  const lines = (body.match(/\n/g)?.length ?? 0) + 1;
  const branches = (body.match(BRANCH_WORD)?.length ?? 0) + (body.match(BRANCH_OP)?.length ?? 0);
  return { lines, nesting, branches };
}

/** Long-security-method matches in a brace language. */
function jsLongMethods(content: string): RuleMatch[] {
  const blanked = blankJsLiterals(content);
  const out: RuleMatch[] = [];
  let emittedEnd = 0; // outermost-wins: skip heads inside an already-flagged block
  let heads = 0;
  let h: RegExpExecArray | null;
  JS_HEAD.lastIndex = 0;
  while (heads < MAX_HEADS && (h = JS_HEAD.exec(blanked)) !== null) {
    heads += 1;
    if (h[0].length === 0) {
      JS_HEAD.lastIndex += 1;
      continue;
    }
    if (h.index < emittedEnd) continue;
    // Distinct group names per alternative, not one reused `fn`: duplicate named
    // capture groups across alternatives are an ES2025 addition and a SyntaxError
    // on the Node 18 floor this package declares.
    const name = h.groups?.fnA ?? h.groups?.fnB ?? h.groups?.fnC ?? h.groups?.fnD ?? '';
    const block = extractBlockAfter(blanked, h.index + h[0].length - 1);
    if (!block) continue;
    const m = jsBodyMetrics(block.body);
    if (m.lines < MIN_LINES || m.nesting < MIN_NESTING || m.branches < MIN_BRANCHES) continue;
    if (!SECURITY_KW.test(block.body) && !SECURITY_KW.test(name)) continue;
    emittedEnd = block.end;
    const pos = indexToPosition(content, block.start);
    const authz = isAuthz(block.body) || isAuthz(name);
    out.push({
      startLine: pos.line,
      endLine: indexToPosition(content, block.end).line,
      startColumn: 1,
      endColumn: 1,
      evidence: `${name || 'function'} — ${m.lines} lines, nesting ${m.nesting}, ${m.branches} branches`,
      severity: authz ? 'high' : undefined,
      confidence: authz ? 'high' : undefined,
      variables: { lines: String(m.lines), nesting: String(m.nesting), branches: String(m.branches) },
    });
  }
  return out;
}

const PY_DEF = /^([^\S\r\n]*)(?:async[^\S\r\n]+)?def[^\S\r\n]+([A-Za-z_]\w{0,60})/;

/** Long-security-method matches in Python (indentation-scoped bodies). */
function pyLongMethods(content: string, rawLines: string[]): RuleMatch[] {
  // Blank `#` comments and string/docstring interiors so their keywords cannot
  // inflate metrics, then re-split — geometry is preserved so line numbers still
  // line up with `rawLines`.
  const blankedLines = blankPyLiterals(content).split('\n');
  const out: RuleMatch[] = [];
  let emittedEnd = 0;
  for (let i = 0; i < blankedLines.length; i += 1) {
    if (i < emittedEnd) continue;
    // Detect the `def` head on the BLANKED line, so a `def` that only appears
    // inside a docstring/string is not mistaken for a real function head. The
    // blanked line keeps real code (only string/comment interiors are spaces)
    // and preserves leading indentation, so name and indent are unaffected.
    const def = PY_DEF.exec(blankedLines[i] ?? '');
    if (!def) continue;
    const indent = def[1]!.length;
    const name = def[2]!;
    // Body = the maximal following run of lines that are blank or indented deeper
    // than the def.
    let j = i + 1;
    let lastNonBlank = i;
    for (; j < blankedLines.length; j += 1) {
      const raw = rawLines[j] ?? '';
      if (raw.trim() === '') continue;
      const curIndent = raw.length - raw.trimStart().length;
      if (curIndent <= indent) break;
      lastNonBlank = j;
    }
    const bodyLineCount = lastNonBlank - i; // excludes the def line itself
    if (bodyLineCount < MIN_LINES) continue;
    // Nesting: distinct indentation widths seen in the body (relative depth).
    const indentStack: number[] = [];
    let maxNesting = 0;
    let branches = 0;
    let hasSecurity = SECURITY_KW.test(name);
    let hasAuthz = isAuthz(name);
    for (let k = i + 1; k <= lastNonBlank; k += 1) {
      const raw = rawLines[k] ?? '';
      const blanked = blankedLines[k] ?? '';
      if (raw.trim() === '') continue;
      const w = raw.length - raw.trimStart().length;
      while (indentStack.length && indentStack[indentStack.length - 1]! >= w) indentStack.pop();
      indentStack.push(w);
      if (indentStack.length > maxNesting) maxNesting = indentStack.length;
      branches += (blanked.match(BRANCH_WORD)?.length ?? 0) + (blanked.match(PY_BRANCH_OP)?.length ?? 0);
      if (!hasSecurity && SECURITY_KW.test(blanked)) hasSecurity = true;
      if (!hasAuthz && isAuthz(blanked)) hasAuthz = true;
    }
    // Align with the JS convention (jsBodyMetrics counts contents as maxDepth-1,
    // excluding the function's own outer block): the body's base indent is level
    // 1 in `indentStack`, so a statement one block deep sits at stack depth 2.
    // Subtract 1 so "nesting" means blocks-deep, matching the brace count.
    const nesting = Math.max(0, maxNesting - 1);
    if (nesting < MIN_NESTING || branches < MIN_BRANCHES || !hasSecurity) continue;
    emittedEnd = lastNonBlank + 1;
    out.push({
      startLine: i + 1,
      endLine: lastNonBlank + 1,
      startColumn: 1,
      endColumn: 1,
      evidence: `${name} — ${bodyLineCount} lines, nesting ${nesting}, ${branches} branches`,
      severity: hasAuthz ? 'high' : undefined,
      confidence: hasAuthz ? 'high' : undefined,
      variables: { lines: String(bodyLineCount), nesting: String(nesting), branches: String(branches) },
    });
  }
  return out;
}

export const longSecurityMethod: RuleDefinition = {
  ruleId: 'VG-SMELL-003',
  name: 'Long Security Method',
  description:
    'A security-relevant method (authentication, authorization, validation, token handling) is excessively long and deeply nested. Long security methods hide missed branches, missed early returns, and missed exception handling.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'security-design-smell',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-1120'],
  tags: ['design-smell', 'ai-prone'],
  remediation: {
    why: 'A method over ~80 lines with deep nesting and many branches is hard to review for authorization gaps; an AI often generates one monolithic handler that validates, authorizes, mutates, and responds in a single body.',
    how: 'Extract the authorization decision into a guard/policy function, split validation and response formatting out of the handler, and flatten nesting with early returns so each security branch is individually reviewable.',
    exampleFix: 'const decision = authorize(user, resource); if (!decision.allowed) return forbidden(decision.reason);',
  },
  match: (ctx) => {
    const { content, lines } = capped(ctx);
    if (ctx.language === 'python') return pyLongMethods(content, lines);
    return jsLongMethods(content);
  },
};

// --- VG-SMELL-012: Primitive Role Check ---------------------------------------
//
// A role/permission is decided by comparing an identifier against a HARDCODED
// string literal ("admin"/"root"/…). Typo-prone, scatter-prone, and a classic
// privilege-escalation seam. Fires only when THREE OR MORE distinct sites occur
// in one file AND no enum/constant/policy layer is present — the ≥3 threshold and
// the mitigation veto are what keep this off well-factored code.
//
// Deliberately NOT in the identifier list: `scope`. `scope === "user"` is a
// legitimate OAuth-scope comparison (GitHub's scope literal is "user"); including
// it is an FP fountain. Revisit only with an admin-family-literal restriction.

// Forward: `user.role === "admin"`. Lazy dotted-identifier run is bounded ({0,40})
// and adjacent to a fixed keyword alternation, so it is linear (redos corpus
// covers it). The trailing `s?` accepts `roles`/`permissions`.
const ROLE_ID = '[a-z_$][\\w$.]{0,40}?(?:role|permission|authority|access_?level|user_?type|priv(?:ilege)?)s?';
const ROLE_LIT =
  'admin|administrator|superadmin|super_admin|superuser|root|owner|guest|member|moderator|editor|viewer|staff|manager|operator|user|read|write|delete|execute';
const ROLE_FWD = new RegExp(
  `\\b(?<id>${ROLE_ID})\\b[^\\S\\r\\n]{0,6}(?:===|!==|==|!=)[^\\S\\r\\n]{0,6}(?<q>["'\`])(?<lit>${ROLE_LIT})\\k<q>`,
  'gi',
);
// Yoda: `"admin" === user.role`.
const ROLE_YODA = new RegExp(
  `(?<q>["'\`])(?<lit>${ROLE_LIT})\\k<q>[^\\S\\r\\n]{0,6}(?:===|!==|==|!=)[^\\S\\r\\n]{0,6}\\b(?<id>${ROLE_ID})\\b`,
  'gi',
);

// 17z-e — the JAVA/KOTLIN string-comparison idiom. `==` on a Java String is a
// reference comparison, so real Java writes `user.getRole().equals("admin")`;
// shipping the java arm with only the `==` shapes above would detect a form that
// competent Java never uses and miss the one it always uses, i.e. it would look
// like coverage without being coverage. The `.equals(` / `.equalsIgnoreCase(`
// token is a FIXED anchor between two bounded runs, so the shape costs the same
// as the forward one. The optional `(\s*)` accepts a getter call
// (`getRole().equals(…)`) as well as a bare field.
//
// Kotlin gets it too: `==` there already compiles to `equals`, so the idiomatic
// Kotlin form is caught by ROLE_FWD — but `.equals(` is legal Kotlin and costs
// nothing to accept. NOT enabled for js/ts/python: `.equals(` is not a JS string
// method, and adding it there would change three shipped languages for no recall.
const ROLE_EQUALS = new RegExp(
  `\\b(?<id>${ROLE_ID})\\b(?:[^\\S\\r\\n]{0,4}\\([^\\S\\r\\n]{0,4}\\))?[^\\S\\r\\n]{0,4}\\.[^\\S\\r\\n]{0,4}(?:equalsIgnoreCase|equals)[^\\S\\r\\n]{0,4}\\([^\\S\\r\\n]{0,4}"(?<lit>${ROLE_LIT})"`,
  'gi',
);
// Yoda-equals: `"admin".equals(user.getRole())`. This is the NULL-SAFE form every
// Java style guide recommends, so it is the most likely one to appear — a
// primitive role check does not stop being one because it is written safely.
const ROLE_EQUALS_YODA = new RegExp(
  `"(?<lit>${ROLE_LIT})"[^\\S\\r\\n]{0,4}\\.[^\\S\\r\\n]{0,4}(?:equalsIgnoreCase|equals)[^\\S\\r\\n]{0,4}\\([^\\S\\r\\n]{0,4}\\b(?<id>${ROLE_ID})\\b`,
  'gi',
);

// The escape hatch: if the file ALREADY has an enum / constant set / policy layer
// / helper, the raw comparisons are legacy or incidental — suppress the whole
// file. Conservative by design (a false negative here, never a false positive).
const ROLE_MITIGATION =
  /\benum[^\S\r\n]{1,4}\w{0,30}(?:role|permission)|\bclass[^\S\r\n]{1,4}\w{0,30}(?:role|permission)\w{0,20}[^\S\r\n]{0,4}\((?:\w{0,10}\.)?(?:str|int)?enum\)|\btype[^\S\r\n]{1,4}\w{0,30}role\w{0,20}[^\S\r\n]{0,4}=|\bhas_?(?:role|permission|authority)[^\S\r\n]{0,2}\(|\b(?:roles?|permissions?|scopes?)\.[A-Z][A-Z0-9_]{1,30}\b|Object[^\S\r\n]{0,2}\.[^\S\r\n]{0,2}freeze[^\S\r\n]{0,2}\(/i;

// 17z-e — the PER-LANGUAGE half of the mitigation veto.
//
// ROLE_MITIGATION above is the portable half (a `Roles.ADMIN` constant reference,
// a `hasRole(` helper, an `Object.freeze` table). What "the roles are already
// aggregated" LOOKS like is not portable: Java says `enum Role`, Go says
// `type Role string` + a `const (… iota)` block, Kotlin says `enum class Role`.
// Those forms are added HERE, per language, instead of being folded into the
// shared pattern — widening the shared one would change what js/ts/python veto
// on, and this arm must not be able to move a single existing finding.
//
// The direction is deliberate and matches the shared veto: a miss here is a
// FALSE NEGATIVE (the file stays silent although its roles really are scattered),
// never a false positive. That is why each entry is generous — `\biota\b`
// anywhere in a Go file, any `@PreAuthorize` in a Java one — rather than tied to
// the exact declaration the comparisons reference. Proving that linkage lexically
// needs the cross-file graph, which is 0.3.0's job, not a regex's.
const ROLE_MITIGATION_BY_LANGUAGE: Record<string, RegExp> = {
  // `public enum Role {`, `enum Authority`; Spring's declarative policy layer
  // (`@PreAuthorize("hasRole('ADMIN')")`, `@RolesAllowed`, `@Secured`); and a
  // `static final String ROLE_ADMIN = …` constant table.
  java: /\benum[^\S\r\n]{1,6}\w{0,30}?(?:role|permission|authority|access|scope)|@(?:PreAuthorize|PostAuthorize|RolesAllowed|Secured)\b|\bfinal[^\S\r\n]{1,6}String[^\S\r\n]{1,6}\w{0,24}?(?:role|permission|authority|admin)/i,
  // `type Role string` / `type Permission int` (a named role type), `const RoleAdmin
  // = …`, and `iota` — the Go idiom for a constant enumeration. `iota` is accepted
  // file-wide on purpose: a file that declares ANY const enumeration and also
  // compares roles is far more likely mid-migration than genuinely unaggregated.
  go: /\btype[^\S\r\n]{1,6}\w{0,30}?(?:role|permission|authority|access)\w{0,20}[^\S\r\n]{1,6}(?:string|u?int(?:8|16|32|64)?|byte|struct|interface)\b|\bconst[^\S\r\n]{1,6}\w{0,24}?(?:role|permission|authority)|\biota\b/i,
  // `enum class Role`, `sealed class Role` / `sealed interface Role` (the Kotlin
  // ADT spelling of the same thing), `const val ROLE_ADMIN = …`, and the Spring
  // annotations again (Kotlin services use them unchanged).
  kotlin: /\b(?:enum|sealed|value)[^\S\r\n]{1,6}(?:class|interface)[^\S\r\n]{1,6}\w{0,30}?(?:role|permission|authority|access)|\bconst[^\S\r\n]{1,6}val[^\S\r\n]{1,6}\w{0,24}?(?:role|permission|authority|admin)|@(?:PreAuthorize|PostAuthorize|RolesAllowed|Secured)\b/i,
};

/**
 * 17z-e — languages whose RAW-STRING syntax no blanker in this repo models, and
 * the delimiter that proves the file uses it.
 *
 * MEASURED, not assumed. Feeding `String doc = """\n if (user.role == "admin")…`
 * to both blankers shows each one desyncing: `blankCommentsAndStrings` reads the
 * three quotes as open-close-open, so the text block's interior alternates
 * between "string" and "code" on every quote inside it, and `blankJsLiterals`
 * does the same. Either way a role comparison written INSIDE a Java text block or
 * a Kotlin raw string can come back classified as code — a false positive on text
 * that is not code at all.
 *
 * The fix is to stay silent on the whole file, not to teach the blanker triple
 * quotes: the blankers are shared with the C/C++ rules and with E7's pinned
 * output, so changing one to serve this arm risks moving findings that have
 * nothing to do with roles. A file-level skip costs recall in exactly the files
 * we cannot reason about, which is the same trade `extractBlockAfter` makes when
 * a block does not balance.
 *
 * GO IS DELIBERATELY ABSENT. Its raw string is the backtick, and
 * `blankJsLiterals` already models backticks (JS template literals): the same
 * probe shows a Go raw string's interior fully blanked and the following real
 * comparison intact. Skipping every Go file containing a backtick would have
 * silenced the arm on almost all real Go, because struct tags (`json:"role"`) put
 * a backtick in nearly every file. The one residual divergence — Go raw strings
 * have no escapes, so a trailing `\` before the closing backtick makes the JS
 * blanker read past it — over-blanks and therefore only ever drops a site.
 */
const UNMODELLED_RAW_STRING: Record<string, string> = {
  java: '"""',
  kotlin: '"""',
};

/**
 * The blanker whose string/comment model matches `language`.
 *
 * js/ts (and any unknown language) keep `blankJsLiterals` exactly as before —
 * this arm must not change what the three shipped languages do. Java and Kotlin
 * get the C-family blanker: they have no regex literals, and Kotlin's backtick is
 * an IDENTIFIER quote (`` `is` ``), so the JS blanker would read one as a template
 * literal and blank the real code after it. Go gets the JS blanker for the
 * opposite reason — its backtick IS a string quote.
 */
function blankFor(content: string, language: string | undefined): string {
  if (language === 'python') return blankPyLiterals(content);
  if (language === 'java' || language === 'kotlin') return blankCommentsAndStrings(content);
  return blankJsLiterals(content);
}

/**
 * Own-property lookup for the two language-keyed maps above.
 *
 * `Object.hasOwn`, not a bare index, for the reason `getLineCommentSpec` in
 * matcher-utils.ts spells out: `ctx.language` reaches `match()` from a caller —
 * `scan({ …, language })` takes whatever string it is given — so a language of
 * `'constructor'` or `'toString'` would resolve to an INHERITED function, dodge
 * the `?? undefined` fallback, and then `langVeto.test(…)` throws. That throw is
 * swallowed by the analyzer's per-rule try/catch, i.e. it would silently delete
 * every finding this rule had produced: the undeclared-suppression failure mode,
 * arrived at through a prototype chain rather than a bug in the rule.
 */
function ownEntry<T>(map: Record<string, T>, language: string | undefined): T | undefined {
  if (language == null || !Object.hasOwn(map, language)) return undefined;
  return map[language];
}

// Lines that are test assertions, not production role checks.
const ASSERT_LINE = /^[^\S\r\n]*(?:assert\b|expect[^\S\r\n]{0,2}\(|it[^\S\r\n]{0,2}\(|test[^\S\r\n]{0,2}\()/;
const ADMIN_FAMILY = /^(?:admin|administrator|superadmin|super_admin|superuser|root)$/i;

function primitiveRoleChecks(content: string, lines: string[], language: string | undefined): RuleMatch[] {
  if (ROLE_MITIGATION.test(content)) return [];
  // 17z-e — per-language veto and raw-string skip, both no-ops for js/ts/python
  // (neither map has an entry for them), so those three languages take exactly
  // the path they took before this arm existed.
  const langVeto = ownEntry(ROLE_MITIGATION_BY_LANGUAGE, language);
  if (langVeto?.test(content)) return [];
  const rawDelimiter = ownEntry(UNMODELLED_RAW_STRING, language);
  if (rawDelimiter !== undefined && content.includes(rawDelimiter)) return [];
  const raw = [
    ...runRegex(content, ROLE_FWD, { skipCommentLines: true, language }),
    ...runRegex(content, ROLE_YODA, { skipCommentLines: true, language }),
    ...(language === 'java' || language === 'kotlin'
      ? [
          ...runRegex(content, ROLE_EQUALS, { skipCommentLines: true, language }),
          ...runRegex(content, ROLE_EQUALS_YODA, { skipCommentLines: true, language }),
        ]
      : []),
  ];
  // Blank comment/string interiors so a role comparison written INSIDE a string
  // literal (a lint-rule doc, a codemod fixture, an i18n catalog) is rejected —
  // the comparison's identifier start then sits on a blanked (space) position.
  const blankedLines = blankFor(content, language).split('\n');
  // Drop test-assertion / string-embedded sites and dedupe by line.
  const byLine = new Map<number, RuleMatch>();
  for (const m of raw) {
    const lineText = lines[m.startLine - 1] ?? '';
    if (ASSERT_LINE.test(lineText)) continue;
    const col = (m.startColumn ?? 1) - 1;
    const bl = blankedLines[m.startLine - 1] ?? '';
    // Identifier start blanked (inside a string) while the raw char is not → skip.
    if (bl[col] === ' ' && lineText[col] !== ' ') continue;
    if (!byLine.has(m.startLine)) byLine.set(m.startLine, m);
  }
  const sites = [...byLine.values()];
  if (sites.length < 3) return [];
  return sites.map((m) => {
    const lit = m.variables?.lit ?? '';
    const admin = ADMIN_FAMILY.test(lit);
    return {
      ...m,
      severity: admin ? ('high' as const) : undefined,
      confidence: admin ? ('high' as const) : undefined,
    };
  });
}

export const primitiveRoleCheck: RuleDefinition = {
  ruleId: 'VG-SMELL-012',
  name: 'Primitive Role Check',
  description:
    'Authorization is decided by comparing a role/permission identifier against hardcoded string literals ("admin", "root") in three or more places, with no enum/constant/policy layer. String-based role checks invite typos, drift, and privilege-escalation bugs.',
  // 17z-e — java/go/kotlin added. The forward/yoda comparison SHAPE is portable
  // across the C family; what each language needed was its own mitigation veto
  // (see ROLE_MITIGATION_BY_LANGUAGE) and its own string model (see blankFor).
  // Languages are NOT added without a negative corpus: samples/design-safe holds
  // an "already aggregated" file per language, pinned at zero findings.
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'kotlin'],
  category: 'security-design-smell',
  severity: 'medium',
  defaultConfidence: 'medium',
  cwe: ['CWE-286'],
  owasp: ['A01:2021'],
  tags: ['design-smell', 'access-control', 'ai-prone'],
  remediation: {
    why: 'Scattered string comparisons for roles have no single source of truth: a typo ("admn") silently denies or grants, and adding a role means hunting every comparison. AI-generated handlers reproduce this pattern across every endpoint.',
    how: 'Define roles as an enum/frozen constant set and compare against it (Role.ADMIN), or centralise the decision behind a policy/RBAC helper (can(user, action)). Then a missing or mistyped role is a compile/lint error, not a silent auth hole.',
    exampleFix: 'if (user.role === Role.ADMIN) { /* … */ }',
  },
  match: (ctx) => {
    const { content, lines } = capped(ctx);
    return primitiveRoleChecks(content, lines, ctx.language);
  },
};

// --- VG-SMELL-004: Security Swiss Army Knife ----------------------------------
//
// A generic Utils/Helper/Common class accretes unrelated security AND non-security
// functions (hashPassword, generateJwt, sanitizeHtml, parseCsv, calculateTax…).
// Fires only when a NAME GATE passes AND the collected function names span ≥3
// responsibility domains mixing security with non-security. Precision levers: the
// name gate exits early on non-utility files; the ≥3-domain + security-and-non-
// security requirement keeps cohesive single-purpose utils silent.

const NAME_GATE_FILE = /(?:^|[-_.])(?:utils?|helpers?|common|misc|shared|toolbox|security[-_]?utils?)(?:[-_.]|$)/i;
const NAME_GATE_CLASS = /\bclass[^\S\r\n]{1,4}\w{0,40}(?:Utils?|Helpers?|Common|Misc|Kit|Toolbox)\b/;

// Function-name collectors (run on blanked content so commented-out code is out).
const FN_DECL = /(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:async[^\S\r\n]{1,4})?function[^\S\r\n]{1,4}(?<fn>[\w$]{1,60})/g;
const FN_ARROW =
  /(?:^|[^\w$.])(?:export[^\S\r\n]{1,4})?(?:const|let|var)[^\S\r\n]{1,4}(?<fn>[\w$]{1,60})[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:async[^\S\r\n]{0,4})?(?:\([^()\n]{0,120}\)[^\S\r\n]{0,4}=>|function\b)/g;
const FN_METHOD_MOD =
  /(?:^|[^\w$.])(?:public|private|protected|static|readonly)[^\S\r\n]{1,4}(?:async[^\S\r\n]{1,4})?(?<fn>[\w$]{1,60})[^\S\r\n]{0,4}\(/g;
const FN_METHOD_BARE =
  /^[^\S\r\n]{2,}(?:async[^\S\r\n]{1,4})?(?<fn>(?!(?:if|for|while|switch|catch|return|function|constructor|await|do|else)\b)[\w$]{1,60})[^\S\r\n]{0,4}\([^()\n]{0,120}\)[^\S\r\n]{0,4}\{/gm;
const FN_PY = /^[^\S\r\n]{0,40}(?:async[^\S\r\n]+)?def[^\S\r\n]{1,4}(?<fn>\w{1,60})/gm;

// Ordered domain table — first keyword hit wins, so a name is charged to exactly
// one domain.
const DOMAINS: Array<{ domain: string; kw: RegExp }> = [
  { domain: 'crypto', kw: /hash|encrypt|decrypt|hmac|cipher|digest|\bsign|jwt|\bsalt|bcrypt|scrypt|pbkdf/i },
  { domain: 'auth', kw: /login|logout|\bauth|session|password|\brole|permission|token|authoriz|authentic|oauth|\bsso\b/i },
  { domain: 'validation', kw: /validate|sanitiz|escape/i },
  { domain: 'parsing', kw: /parse|serial|deserial|\bcsv|\bxml|\bformat|stringify|marshal/i },
  { domain: 'business', kw: /calculate|compute|\btax\b|price|total|render|report|invoice|\border|notify|\bemail/i },
];

// A LEADING verb that makes the function a parser/serializer regardless of the
// noun it operates on. Fixes the "parseToken / parseAuthHeader charged to auth
// from the parsed noun" false positive: a decoder that merely handles auth-shaped
// strings holds no security logic.
const PARSING_VERB = /^(?:parse|serialize|deserialize|stringify|marshal|unmarshal|format|tokenize|encode|decode)/;

function tokenize(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toLowerCase();
}

function classifyDomain(name: string): string | null {
  // Split camelCase / snake_case / kebab-case into space-separated tokens so the
  // word-boundary anchors in the domain regexes fire on a glued identifier
  // (`checkAdminRole` → `check admin role`, so `\brole` matches) while still
  // rejecting incidental substrings (`design` never reads as `\bsign`).
  const tokenized = tokenize(name);
  // Leading parsing/serialization verb wins over any noun (parseToken → parsing).
  if (PARSING_VERB.test(tokenized.replace(/\s.*$/, ''))) return 'parsing';
  for (const d of DOMAINS) if (d.kw.test(tokenized)) return d.domain;
  return null;
}

// A HIGH-SIGNAL security token. The rule requires at least one function name to
// carry one of these before firing, so a Utils class whose only "security" signal
// is an ambiguous noun (`hashKey` for a hashmap, `parseToken` for a string split)
// stays silent. `hash`/`salt`/`token` alone are deliberately NOT here — they are
// the ambiguous ones; a genuine security helper also names the concrete primitive
// (hashPassword, generateJwt, encrypt, login, session, permission).
const STRONG_SECURITY =
  /encrypt|decrypt|cipher|hmac|\bjwt\b|bcrypt|scrypt|pbkdf|password|login|logout|authenticat|authoriz|session|permission|\brole\b|credential|signature|oauth|\bsso\b|csrf|\bcors\b|sanitiz/i;

function swissArmyMatches(content: string, lines: string[], filePath: string | undefined): RuleMatch[] {
  if (filePath && isTestPath(filePath)) return [];
  const base = filePath ? (filePath.split(/[\\/]/).pop() ?? '').replace(/\.[^.]+$/, '') : '';
  const nameGate = (base !== '' && NAME_GATE_FILE.test(base)) || NAME_GATE_CLASS.test(content);
  if (!nameGate) return [];

  const blanked = blankJsLiterals(content);
  const names = new Set<string>();
  for (const re of [FN_DECL, FN_ARROW, FN_METHOD_MOD, FN_METHOD_BARE, FN_PY]) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let n = 0;
    while (n < MAX_HEADS && (m = re.exec(blanked)) !== null) {
      n += 1;
      if (m[0].length === 0) {
        re.lastIndex += 1;
        continue;
      }
      const fn = m.groups?.fn;
      if (fn) names.add(fn);
    }
  }
  if (names.size < 5) return [];

  const domains = new Set<string>();
  for (const fn of names) {
    const d = classifyDomain(fn);
    if (d) domains.add(d);
  }
  if (domains.size < 3) return [];
  const securityDomains = ['crypto', 'auth', 'validation'].filter((d) => domains.has(d));
  const nonSecurity = ['parsing', 'business'].filter((d) => domains.has(d));
  if (securityDomains.length === 0 || nonSecurity.length === 0) return [];
  // Require a HIGH-SIGNAL security token, not just an ambiguous noun. Without
  // this, a `CacheUtils.hashKey` (hashmap) or a `DecoderUtils.parseToken` (string
  // split) is enough to trip the security side — the dominant false positive.
  if (![...names].some((n) => STRONG_SECURITY.test(tokenize(n)))) return [];

  const high = domains.has('crypto') && domains.has('auth');
  const sortedDomains = [...domains].sort();
  const sortedNames = [...names].sort();
  const severity = high ? ('high' as const) : domains.size >= 4 ? ('medium' as const) : undefined;
  return [
    {
      startLine: 1,
      endLine: Math.max(1, lines.length),
      startColumn: 1,
      endColumn: 1,
      evidence: `${sortedNames.length} functions span ${sortedDomains.join('/')} (security and non-security mixed)`,
      severity,
      variables: { domains: sortedDomains.join(','), functionCount: String(sortedNames.length) },
    },
  ];
}

export const securitySwissArmyKnife: RuleDefinition = {
  ruleId: 'VG-SMELL-004',
  name: 'Security Swiss Army Knife',
  description:
    'A generic Utils/Helper/Common module mixes security-critical functions (crypto, auth, validation) with unrelated concerns (parsing, business logic). The grab-bag has no cohesive responsibility, so security code hides among incidental helpers and is easy to change unsafely.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'security-design-smell',
  severity: 'low',
  defaultConfidence: 'low',
  cwe: ['CWE-1061'],
  tags: ['design-smell', 'ai-prone'],
  remediation: {
    why: 'When cryptography, authentication, and validation share a Utils bucket with CSV parsing and tax math, the security surface is undiscoverable and a careless edit to a "helper" can weaken a security primitive.',
    how: 'Split the module by responsibility: a crypto module, an auth module, a validation module, each with a single clear purpose. Keep security primitives out of the generic Utils grab-bag.',
    exampleFix: '// crypto.ts — hashPassword, verifyPassword\n// auth.ts — login, issueToken\n// (no more SecurityUtils grab-bag)',
  },
  match: (ctx) => {
    const { content, lines } = capped(ctx);
    return swissArmyMatches(content, lines, ctx.filePath);
  },
};

export const designSmellSingleRules: RuleDefinition[] = [
  longSecurityMethod,
  primitiveRoleCheck,
  securitySwissArmyKnife,
];
