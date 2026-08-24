// vibeguard:disable-file VG-AUTH-001 VG-AUTH-003 VG-AUTH-004 VG-AUTH-006
// This file defines the auth rules; dummy-token, TLS-disable, and the
// "secure: false" / "httpOnly: false" literals appear inside regex
// patterns and remediation prose by design.
//
// VG-AUTH-001 joined the list with VG-AUTH-009. That rule's doc comment has to
// state the polarity it is NOT — a debug branch that SKIPS a check, quoted as
// the one-line example — and VG-AUTH-001 reads the quotation as the bypass it
// describes. Same exemption class as the two design-smell files that quote an
// unfinished-authorization marker: prose quoting the pattern the rule detects.
// Named rather than wildcarded, so a real bypass written into this file's own
// code still reports at critical.
import type { RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  runRegex,
  blankCommentsAndStrings,
  indexToPosition,
  isCommentLine,
  REGEX_INPUT_CAP,
  REGEX_MATCH_LIMIT,
} from '../matcher-utils.js';

export const debugBypass: RuleDefinition = {
  ruleId: 'VG-AUTH-001',
  name: 'Authentication bypass when DEBUG is enabled',
  description:
    'Code path that skips auth when a debug or development flag is set. Easy to leave on accidentally in production.',
  languages: ['*'],
  category: 'auth',
  severity: 'critical',
  defaultConfidence: 'medium',
  cwe: ['CWE-489'],
  tags: ['ai-prone'],
  remediation: {
    why: 'A debug bypass that ships to production silently disables authentication. AI-assisted code frequently leaves these in.',
    how: 'Remove the bypass entirely, or gate it behind an explicit non-production environment check that fails closed.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      // Bounded whitespace (`\s{0,20}`), not horizontal-only. `if (debug)\n{` (Allman)
      // and `if (\n  DEBUG\n) {` are ordinary formattings that a horizontal-only
      // rewrite silently stopped matching — on a CRITICAL rule. Bounding the
      // quantifier is what removes the quadratic; banning line breaks was
      // over-correction. Verified to recover both shapes AND stay linear by
      // scripts/sec-a1-shape-check.mjs.
      /if\s{0,20}(?:\(\s{0,20})?(?:DEBUG|isDev|IS_DEV|process\.env\.NODE_ENV\s{0,20}===?\s{0,20}["']development["']|debug)\s{0,20}(?:\)\s{0,20})?[:{][^}]{0,800}?(?:return\s{0,20}true|skip[_\s]?auth|bypass|allow|permit)/gi,
      { skipCommentLines: false },
    ),
};

export const todoSecurity: RuleDefinition = {
  ruleId: 'VG-AUTH-002',
  name: 'TODO comment near security-critical code',
  description:
    'TODO / FIXME / XXX comment that mentions auth, validation, or security. AI-generated code often emits placeholders for the dangerous parts.',
  languages: ['*'],
  category: 'ai-quality',
  severity: 'medium',
  defaultConfidence: 'medium',
  // The comment IS the signal here, so context-confidence must not down-rank a
  // match for being inside a comment (it always is).
  contextConfidence: 'off',
  tags: ['ai-prone'],
  remediation: {
    why: 'A TODO next to security-critical logic typically means the safety check was deferred and may never be implemented.',
    how: 'Implement the missing check, or track the gap as a blocking issue before this code reaches production.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /(?:\/\/|#|\/\*)[^\S\r\n]*(?:TODO|FIXME|XXX|HACK)\b[^\n]{0,200}?(?:auth|valid|sanit|escape|secur|permission|role|token|password|encrypt|verif)/gi,
    ),
};

export const dummyToken: RuleDefinition = {
  ruleId: 'VG-AUTH-003',
  name: 'Dummy or placeholder credential string',
  description:
    'Hard-coded placeholder values like "dummy_token", "test_password", "changeme" frequently survive the trip to production.',
  languages: ['*'],
  category: 'secrets',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-798'],
  tags: ['ai-prone'],
  remediation: {
    why: 'Placeholder credentials in source are easy to forget about and disclose what the surrounding system trusts.',
    how: 'Move the value to a configuration / secret store and fail loudly when the placeholder is detected at startup.',
  },
  match: (ctx) =>
    runRegex(
      ctx.content,
      /["'](?:changeme|dummy[_-]?(?:token|key|secret)|test[_-]?(?:password|token|secret)|placeholder[_-]?(?:token|key|secret)|your[_-]?(?:api)?[_-]?key[_-]?here|xxxxxxxx+)["']/gi,
    ),
};

export const tlsVerifyDisabled: RuleDefinition = {
  ruleId: 'VG-AUTH-004',
  name: 'TLS certificate verification disabled',
  description:
    'verify=False, rejectUnauthorized: false, InsecureSkipVerify: true — all disable TLS validation, defeating MITM protection.',
  languages: ['python', 'javascript', 'typescript', 'go'],
  category: 'crypto',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-295'],
  remediation: {
    why: 'Disabling certificate verification turns TLS into a bare encrypted channel with no authentication of the peer. Active MITM is trivial.',
    how: 'Remove the flag. If a self-signed cert is needed, install it as a trusted CA for the relevant client only.',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /verify\s*=\s*False\b/g, { skipCommentLines: true, language: ctx.language }),
    ...runRegex(ctx.content, /rejectUnauthorized\s*:\s*false\b/g, { skipCommentLines: true, language: ctx.language }),
    ...runRegex(ctx.content, /InsecureSkipVerify\s*:\s*true\b/g, { skipCommentLines: true, language: ctx.language }),
  ],
};

export const csrfExemptDecorator: RuleDefinition = {
  ruleId: 'VG-AUTH-005',
  name: 'Django @csrf_exempt decorator disables CSRF protection',
  description:
    'Marking a Django view with @csrf_exempt opts out of CSRF token validation. Routinely added to make POST endpoints "just work" during development and forgotten.',
  languages: ['python'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-352'],
  owasp: ['A01:2021'],
  tags: ['django', 'ai-prone'],
  remediation: {
    why: 'Without CSRF validation, an attacker can trigger state-changing requests from a victim\'s browser using forged forms or fetch calls.',
    how: 'Remove @csrf_exempt and submit a CSRF token (Django will inject {% csrf_token %} into forms / require X-CSRFToken on fetch). For pure JSON APIs, use Django REST Framework\'s SessionAuthentication or token auth which handles CSRF correctly.',
  },
  match: (ctx) =>
    runRegex(ctx.content, /^[^\S\r\n]*@csrf_exempt\b/gm, { skipCommentLines: true, language: ctx.language }),
};

export const insecureSessionCookie: RuleDefinition = {
  ruleId: 'VG-AUTH-006',
  name: 'Express session cookie missing secure / httpOnly flag',
  description:
    'express-session config with cookie.secure: false or cookie.httpOnly: false leaves session IDs readable by JavaScript or transmittable over plain HTTP.',
  languages: ['javascript', 'typescript'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-614', 'CWE-1004'],
  tags: ['express', 'ai-prone'],
  remediation: {
    why: 'cookie.secure: false sends the session ID over plain HTTP where any network observer can capture it. cookie.httpOnly: false lets injected scripts read document.cookie and exfiltrate the session.',
    how: 'Set cookie: { secure: true, httpOnly: true, sameSite: "lax" } in the session() options. In local dev only, gate secure on NODE_ENV.',
    exampleFix: 'session({ cookie: { secure: true, httpOnly: true, sameSite: "lax" } })',
  },
  match: (ctx) => [
    ...runRegex(ctx.content, /\b(?:secure|httpOnly)\s*:\s*false\b/g, {
      skipCommentLines: true,
      language: ctx.language,
    }),
  ],
};

/**
 * The predicate shapes that make an assertion an AUTHORIZATION decision rather
 * than an invariant. Kept to named auth predicates and explicit role/permission
 * comparisons: `assert(ptr != NULL)` and `assert(len < cap)` are invariants and
 * must stay silent.
 */
const AUTHORIZATION_PREDICATE =
  /\b(?:is_admin|is_root|is_owner|is_superuser|is_authori[sz]ed|is_authenticated|is_allowed|is_permitted|has_permission|has_role|has_access|has_privilege|check_auth|check_access|check_permission|authori[sz]ed|admin_only)\b|\b(?:role|permission|privilege|uid)[ \t]{0,4}==/i;

/**
 * VG-AUTH-008 — authorization decided inside `assert()`.
 *
 * `assert` is defined away by the preprocessor when NDEBUG is set, and release
 * builds set it (CMake's Release/RelWithDebInfo add `-DNDEBUG`; so does the
 * conventional `-O2 -DNDEBUG` line). An authorization check written as an
 * assertion therefore holds in the developer's build and IS NOT PRESENT in the
 * build that ships — the check does not fail, it ceases to exist.
 *
 * C/C++ ONLY, on purpose. `assert user.is_admin` in Python is the same mistake
 * (python -O removes it), but Python asserts are everywhere in test code, and
 * widening this rule to Python would put it in front of the corpora where the
 * E3=0 false-positive invariant is measured. If that widening is ever wanted it
 * is a separate rule with its own baseline, not a `languages` edit here.
 */
export const assertBasedAuthorization: RuleDefinition = {
  ruleId: 'VG-AUTH-008',
  name: 'Authorization decided by assert()',
  description:
    'An assert() whose condition is an authorization predicate. assert compiles to nothing when NDEBUG is defined — which release builds do by convention — so the check is enforced in debug builds and absent from the binary users run.',
  languages: ['c', 'cpp'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-285', 'CWE-489'],
  tags: ['embedded', 'ai-prone'],
  remediation: {
    why: 'assert() is removed by the preprocessor under NDEBUG, so an authorization check written as an assertion disappears from the release build. The source keeps showing a check that the shipped binary does not perform.',
    how: 'Make the decision ordinary control flow that fails closed, and keep assert for invariants that are not security decisions.',
    exampleFix: 'if (!is_admin(user)) { return -EPERM; }',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    // Blank comments and strings first: a commented-out assert and the token
    // inside a string are not code. Length-preserving, so positions still hold.
    const scanText = blankCommentsAndStrings(raw, ctx.language);
    // `static_assert` is excluded by the lookbehind (`_` is a word character).
    // The condition run is a bounded negated class — no nested quantifier.
    const assertRe = /(?<![\w.>])assert[ \t]{0,8}\(([^;{}]{0,200})\)/g;
    const out: RuleMatch[] = [];
    let m: RegExpExecArray | null;
    while ((m = assertRe.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      const condition = m[1]!;
      if (!AUTHORIZATION_PREDICATE.test(condition)) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + m[0].length,
        evidence: `assert(${condition.trim()})`,
      });
    }
    return out;
  },
};

/**
 * The same idea as `AUTHORIZATION_PREDICATE`, widened to camelCase.
 *
 * WHY A SECOND CONSTANT RATHER THAN AN EDIT. `AUTHORIZATION_PREDICATE` is
 * snake_case only, which is defensible where it is used — VG-AUTH-008 is
 * `languages: ['c', 'cpp']` and snake_case is the C convention. Measured
 * 2026-08-23: `assert(is_admin(u))` matches and `assert(u->isAdmin)` does not.
 * The rules below are JavaScript and TypeScript, where camelCase is not a
 * variant spelling but the dominant one, so a rule that inherited that constant
 * would miss the ordinary form of everything it is looking for.
 *
 * Widening the shared constant in place would move VG-AUTH-008's behaviour, and
 * that rule's matches are part of a measured corpus baseline. Adding a second,
 * strictly wider constant for new rules keeps the existing baseline where it is
 * and puts the widening behind rules that have no baseline yet.
 */
const AUTHORIZATION_PREDICATE_ANY_CASE =
  /\b(?:is_?admin|is_?root|is_?owner|is_?superuser|is_?authori[sz]ed|is_?authenticated|is_?allowed|is_?permitted|has_?permission|has_?permissions|has_?role|has_?access|has_?privilege|check_?auth|check_?access|check_?permission|require_?auth|require_?admin|require_?role|authori[sz]ed|admin_?only|can_?edit|can_?delete|can_?access)\b|\b(?:role|permission|privilege|uid|scope)[ \t]{0,4}==/i;

/**
 * Something in a block that makes the block REFUSE rather than merely notice.
 *
 * The distinction carries the rule below. A development-only block that logs a
 * warning is a development-only warning, which is what warnings are for. A
 * development-only block that throws is an access control decision that exists
 * in one build and not the other.
 */
const ENFORCEMENT_TOKEN =
  /\bthrow\b|\breject\s*\(|\babort\s*\(|\bdeny\b|\bforbidden\b|\bunauthori[sz]ed\b|\breturn\s+(?:false|null)\b|\.status\s*\(\s*(?:401|403)\s*\)|\bexit\s*\(\s*[1-9]/i;

/** A test that is only true outside a production build. */
const DEV_MODE_TEST =
  /process\.env\.NODE_ENV\s{0,8}(?:!==?\s{0,8}["'`]production["'`]|===?\s{0,8}["'`](?:development|dev|test)["'`])|import\.meta\.env\.(?:DEV|MODE\s{0,8}!==?\s{0,8}["'`]production["'`])|\b__DEV__\b|\bprocess\.env\.DEBUG\b|\b(?:isDev|isDevelopment|IS_DEV|inDevelopment)\b|![ \t]{0,4}(?:isProd|isProduction|IS_PROD)\b/;

/**
 * VG-AUTH-009 — an access control decision that only exists in development.
 *
 * ── HOW THIS DIFFERS FROM VG-AUTH-001, WHICH IS THE OPPOSITE POLARITY ────────
 *
 * VG-AUTH-001 looks for a development branch that SKIPS a check:
 * `if (DEBUG) { return true; }`. That is a bypass, and it is dangerous because
 * the flag might be on in production.
 *
 * This rule looks for a development branch that PERFORMS a check:
 * `if (process.env.NODE_ENV !== 'production') { if (!user.isAdmin) throw; }`.
 * That is dangerous for the reverse reason, and it is the reason a source
 * scanner alone cannot see the problem: the code is correct in the build the
 * author runs, and the check is not present at all in the build everyone else
 * runs. Nothing fails. Nothing logs. The function simply stops asking.
 *
 * Measured 2026-08-23 on esbuild 0.21.5, with no flags beyond `--minify` and
 * the default browser platform: the branch above is substituted and eliminated,
 * and `deleteUser(session, id)` compiles to `function o(s,e){return db.remove(e)}`
 * — the session parameter is never read. Both the source and that output were
 * reported clean by this scanner before this rule existed.
 *
 * The rule is a source-level rule and it does not know what the build will do.
 * It reports the shape; `@vibeguard/artifact-integrity` is what can say whether
 * a given build actually removed it.
 */
export const developmentOnlyEnforcement: RuleDefinition = {
  ruleId: 'VG-AUTH-009',
  name: 'Access control that only runs in development',
  description:
    'An authorization check placed inside a development-mode conditional. Production builds substitute the condition to false and eliminate the branch, so the check holds while you develop and is absent from what you ship — the opposite polarity to VG-AUTH-001.',
  languages: ['javascript', 'typescript'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-285', 'CWE-489'],
  tags: ['ai-prone', 'build-fragile'],
  remediation: {
    why: 'Bundlers replace process.env.NODE_ENV with "production" and then delete the branch. The authorization check is enforced on your machine and does not exist in the deployed bundle, so no request is ever refused in production.',
    how: 'Move the decision out of the development conditional so it runs unconditionally. Keep development-only code for logging and diagnostics, never for refusing access.',
    exampleFix: 'if (!session.isAdmin) throw new Error("forbidden");',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const scanText = blankCommentsAndStrings(raw, ctx.language);
    // Bounded body run. Not a nested quantifier: one bounded negated class.
    const guardRe = /\bif\s{0,8}\(([^)]{0,160})\)\s{0,8}\{([^}]{0,600})/g;
    const out: RuleMatch[] = [];
    let m: RegExpExecArray | null;
    while ((m = guardRe.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      // ── Why the semantic tests read `raw` and the structural one reads
      // `scanText` ──────────────────────────────────────────────────────────
      // `blankCommentsAndStrings` is what keeps a commented-out guard from
      // matching, so the SEARCH has to run over it. But it also blanks
      // `'production'`, and the condition this rule exists to recognise is
      // `NODE_ENV !== 'production'` — testing the blanked text can never
      // match it. The transform is length-preserving (stated at its
      // definition and relied on elsewhere for positions), so the same
      // offsets address the original text.
      //
      // Group 1 starts one character after the first `(` of the match; group 2
      // ends where the match ends, because it is the last thing in the pattern.
      // Both are exact, not searched for.
      const openParen = m[0].indexOf('(');
      const testStart = m.index + openParen + 1;
      const test = raw.slice(testStart, testStart + (m[1] ?? '').length);
      const bodyEnd = m.index + m[0].length;
      const body = raw.slice(bodyEnd - (m[2] ?? '').length, bodyEnd);
      if (!DEV_MODE_TEST.test(test)) continue;
      // Both halves are required. A development block that enforces nothing is
      // a development block; a block that enforces something unrelated to
      // access control is a development assertion about program state, which is
      // what development assertions are for.
      if (!ENFORCEMENT_TOKEN.test(body)) continue;
      if (!AUTHORIZATION_PREDICATE_ANY_CASE.test(body)) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + Math.min(test.length + 4, 80),
        // ── WHY THE BODY'S PREDICATE IS IN THE EVIDENCE ────────────────────
        // The condition alone reads well and is useless downstream. Every
        // identifier in `process.env.NODE_ENV !== 'production'` is a language
        // or environment name, so `--after-build` could extract no witness
        // from it and had to report the claim NOT_OBSERVED — on the one
        // specimen the whole feature was built around. The predicate the
        // branch actually guards on is the token that exists, or does not,
        // in the shipped bytes, so it belongs in what the finding carries.
        evidence: `if (${test.trim()}) { … ${(body.match(AUTHORIZATION_PREDICATE_ANY_CASE) ?? [''])[0].trim()} … }`,
      });
    }
    return out;
  },
};

/**
 * VG-AUTH-010 — an access control decision written as `console.assert`.
 *
 * Wrong twice, and the second one is worse than the first.
 *
 * 1. Bundlers remove it. `esbuild --drop:console` and terser's `drop_console`
 *    are standard production settings, recommended in the documentation of both.
 * 2. It never enforced anything in the first place. `console.assert(false)`
 *    prints to the console and RETURNS. Execution continues into whatever the
 *    author believed was being guarded. So unlike VG-AUTH-008 and VG-AUTH-009,
 *    this one is not "correct in one build and absent in the other" — it is
 *    absent in the build that ships and decorative in the build that does not.
 *
 * That is why this is `high` with `high` confidence rather than medium: there
 * is no configuration under which the code does what it appears to do.
 */
export const consoleAssertAuthorization: RuleDefinition = {
  ruleId: 'VG-AUTH-010',
  name: 'Authorization decided by console.assert',
  description:
    'console.assert used with an authorization predicate. It does not stop execution when the assertion fails — it logs and returns — and production bundlers drop console calls entirely, so the line is decorative in development and absent in the shipped bundle.',
  languages: ['javascript', 'typescript'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'high',
  cwe: ['CWE-285', 'CWE-617'],
  tags: ['ai-prone', 'build-fragile'],
  remediation: {
    why: 'console.assert never throws, so the code after it runs whether or not the condition held; and drop_console / --drop:console remove the call from production builds. The check is doing nothing in either build.',
    how: 'Replace with control flow that refuses: throw, or return an error response.',
    exampleFix: 'if (!session.isAdmin) throw new Error("forbidden");',
  },
  match: (ctx) => {
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const scanText = blankCommentsAndStrings(raw, ctx.language);
    const re = /\bconsole\s{0,4}\.\s{0,4}assert\s{0,4}\(([^;)]{0,200})/g;
    const out: RuleMatch[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      const condition = m[1] ?? '';
      if (!AUTHORIZATION_PREDICATE_ANY_CASE.test(condition)) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + Math.min(condition.length + 16, 80),
        evidence: `console.assert(${condition.trim()})`,
      });
    }
    return out;
  },
};

/**
 * VG-AUTH-011 — Python authorization decided by `assert`.
 *
 * The widening VG-AUTH-008's comment declined to make as a `languages` edit,
 * made the way that comment said it should be: a separate rule with its own
 * baseline. Its reasoning was that Python assertions are everywhere in test
 * code and that widening in place would put the rule in front of the corpora
 * where the false-positive invariant is measured.
 *
 * Two things keep that from happening here. The condition must contain an
 * authorization predicate, which a test assertion about a return value does
 * not; and files whose path says they are tests are skipped outright. The
 * second is crude and deliberately so — a rule that has to be right about
 * whether a file is a test should not be guessing from content.
 *
 * `python -O` and `PYTHONOPTIMIZE=1` remove assertions. Reproduced 2026-08-23
 * on CPython 3.14.3: with a bare `assert is_admin(user)` guard, `co_names`
 * contains `is_admin` at optimize=0 and does not contain it at optimize=1 —
 * the call is not merely skipped, it is gone from the code object.
 */
export const pythonAssertAuthorization: RuleDefinition = {
  ruleId: 'VG-AUTH-011',
  name: 'Authorization decided by assert (Python)',
  description:
    'An assert statement whose condition is an authorization predicate. python -O and PYTHONOPTIMIZE remove assert statements, so the check is enforced when you run the file directly and absent under an optimised interpreter.',
  languages: ['python'],
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  cwe: ['CWE-285', 'CWE-489'],
  tags: ['ai-prone', 'build-fragile'],
  remediation: {
    why: 'assert is compiled out when the interpreter runs with -O, so an authorization check written as an assertion is not present in an optimised run. The source keeps showing a check that the process does not perform.',
    how: 'Raise explicitly so the decision survives optimisation.',
    exampleFix: 'if not is_admin(user):\n    raise PermissionError("admin required")',
  },
  match: (ctx) => {
    // Path-based, not content-based. See the note above: a rule that guesses
    // whether a file is a test from its contents is a rule that will be wrong
    // about somebody's production module named `test_harness.py`, and being
    // wrong in that direction means staying quiet about a real finding.
    const path = (ctx.filePath ?? '').replace(/\\/g, '/');
    if (/(?:^|\/)(?:tests?|testing)\//i.test(path)) return [];
    if (/(?:^|\/)(?:test_[^/]*|[^/]*_test)\.py$/i.test(path)) return [];
    if (/(?:^|\/)conftest\.py$/i.test(path)) return [];
    const raw =
      ctx.content.length > REGEX_INPUT_CAP ? ctx.content.slice(0, REGEX_INPUT_CAP) : ctx.content;
    const scanText = blankCommentsAndStrings(raw, ctx.language);
    // Python has no `assert(` requirement — `assert x, "msg"` is the statement
    // form — so the condition run ends at a comma or end of line.
    const re = /(?<![\w.])assert[ \t]+([^\n,]{0,200})/g;
    const out: RuleMatch[] = [];
    let m: RegExpExecArray | null;
    while ((m = re.exec(scanText)) !== null && out.length < REGEX_MATCH_LIMIT) {
      const condition = m[1] ?? '';
      if (!AUTHORIZATION_PREDICATE_ANY_CASE.test(condition)) continue;
      const pos = indexToPosition(scanText, m.index);
      if (isCommentLine(ctx.lines[pos.line - 1] ?? '', ctx.language)) continue;
      out.push({
        startLine: pos.line,
        endLine: pos.line,
        startColumn: pos.column,
        endColumn: pos.column + Math.min(condition.length + 7, 80),
        evidence: `assert ${condition.trim()}`,
      });
    }
    return out;
  },
};

export const authRules: RuleDefinition[] = [
  debugBypass,
  todoSecurity,
  dummyToken,
  tlsVerifyDisabled,
  csrfExemptDecorator,
  insecureSessionCookie,
  assertBasedAuthorization,
  developmentOnlyEnforcement,
  consoleAssertAuthorization,
  pythonAssertAuthorization,
];
