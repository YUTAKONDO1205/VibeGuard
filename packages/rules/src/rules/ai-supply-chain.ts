// vibeguard:disable-file VG-AISC-001 VG-AUTH-003 VG-QUAL-007
// This file *defines* the AI supply-chain rules; the hallucinated-package names
// and near-miss examples appear inside the rule data and descriptions by design.
//
// VG-AUTH-003 and VG-QUAL-007 joined the list when VG-AISC-004 landed, for the
// same reason auth.ts and quality.ts carry theirs: `'changeme'` is a literal
// entry in this rule's MARKER_WORDS data, and `const mockWord = …` is how the
// detector names the word it matched. Both are the rule's subject matter, and
// measured — they are 5 of the findings a self-scan reports on this file.
//
// VG-AISC-004 ITSELF IS DELIBERATELY NOT IN THE PRAGMA. Its whole design premise
// is that a repository full of the words "mock", "dummy" and "fake" in prose and
// in rule data must stay silent, so exempting the one file that contains the
// most of them would hide exactly the failure the rule has to survive. Measured
// on this tree: `node apps/cli/dist/index.js packages --ignore dist --ignore
// node_modules` reports 0 VG-AISC-004 findings with no pragma protecting it.
//
// 0.2.x — FOURTH DEFENCE LINE entry point (AI supply chain), category
// "supply-chain". VG-AISC-001 Hallucinated Dependency: an import names a package
// that is a NEAR MISS of a popular one (the slopsquatting seam) — LOCAL match
// against a bundled known-good set, ZERO network (see ai-supply-chain-data.ts).
//
// THE PRECISION CONTRACT (do not weaken): an unknown package that is NOT a near
// miss is SILENT. "Not popular" is never, on its own, a finding — internal and
// niche packages are unknowable to a bundled list, and flagging them is the FP
// flood that would break the safe-corpus gate on real projects. Only a name that
// collides-modulo-separators with, or is edit-distance-1 from, a popular package
// (or is on the curated hallucination list) is flagged.
import type { RuleContext, RuleDefinition, RuleMatch } from '../rule-types.js';
import {
  blankJsLiterals,
  blankPyLiterals,
  extractBlockAfter,
  indexToPosition,
  runRegex,
  REGEX_INPUT_CAP,
} from '../matcher-utils.js';
import { isTestPath } from '../confidence.js';
import {
  KNOWN_NPM,
  KNOWN_PYPI,
  NODE_BUILTINS,
  PY_STDLIB,
  ALIAS_STOPLIST,
  CURATED_HALLUCINATIONS,
} from './ai-supply-chain-data.js';

const normKey = (s: string): string => s.toLowerCase().replace(/[-_.]/g, '');

interface KnownIndex {
  set: ReadonlySet<string>;
  normKeys: ReadonlyMap<string, string>; // normalized key -> canonical name
  byLen: ReadonlyMap<number, string[]>;
}

function buildIndex(names: readonly string[]): KnownIndex {
  const set = new Set<string>();
  const normKeys = new Map<string, string>();
  const byLen = new Map<number, string[]>();
  for (const raw of names) {
    const n = raw.toLowerCase();
    set.add(n);
    if (!normKeys.has(normKey(n))) normKeys.set(normKey(n), n);
    const bucket = byLen.get(n.length);
    if (bucket) bucket.push(n);
    else byLen.set(n.length, [n]);
  }
  return { set, normKeys, byLen };
}

// Built once at module load — the known sets are constant, so there is nothing
// per-scan to recompute (and nothing per-scan is read from the filesystem).
const NPM_INDEX = buildIndex(KNOWN_NPM);
const PYPI_INDEX = buildIndex(KNOWN_PYPI);

/** True when the optimal string alignment distance between a and b is ≤ 1. */
function withinEditDistance1(a: string, b: string): boolean {
  if (a === b) return true;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    // Substitution (1 diff) or one adjacent transposition.
    let diffs = 0;
    let firstDiff = -1;
    for (let i = 0; i < la; i += 1) {
      if (a[i] !== b[i]) {
        diffs += 1;
        if (diffs === 1) firstDiff = i;
        if (diffs > 2) return false;
      }
    }
    if (diffs <= 1) return true;
    if (diffs === 2 && firstDiff >= 0) {
      // Exactly two diffs: a transposition of adjacent chars is distance 1.
      return a[firstDiff] === b[firstDiff + 1] && a[firstDiff + 1] === b[firstDiff];
    }
    return false;
  }
  // Lengths differ by 1 — one insertion/deletion. Walk with a single allowed skip.
  const shorter = la < lb ? a : b;
  const longer = la < lb ? b : a;
  let i = 0;
  let j = 0;
  let skipped = false;
  while (i < shorter.length && j < longer.length) {
    if (shorter[i] === longer[j]) {
      i += 1;
      j += 1;
    } else {
      if (skipped) return false;
      skipped = true;
      j += 1; // consume one extra char from the longer string
    }
  }
  return true;
}

interface Candidate {
  pkg: string; // lowercased package name
  line: number;
}

/** JS/TS import specifiers → candidate package names. */
function jsCandidates(content: string, language: string | undefined): Candidate[] {
  const forms = [
    // `require(` and dynamic `import(` must NOT be a member access: a method
    // literally named `import`/`require` (`registry.import('expresss')`) is a
    // call, not a module load. The `(?:^|[^\w$.])` guard excludes a leading `.`.
    /(?:^|[^\w$.])require[^\S\r\n]{0,2}\([^\S\r\n]{0,2}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /\bfrom[^\S\r\n]{1,4}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /(?:^|[^\w$.])import[^\S\r\n]{0,2}\([^\S\r\n]{0,2}(["'])(?<spec>[^"'\n]{1,120})\1/g,
    /(?:^|[^\w$.])import[^\S\r\n]{1,4}(["'])(?<spec>[^"'\n]{1,120})\1/g,
  ];
  const out: Candidate[] = [];
  for (const re of forms) {
    for (const m of runRegex(content, re, { skipCommentLines: true, language })) {
      const spec = m.variables?.spec;
      if (!spec) continue;
      // Skip relative / absolute / scoped / protocol specifiers. Scoped packages
      // (@org/name) are skipped in v1: private-org scopes are unknowable and
      // near-missing on a scope is FP-rich.
      if (/^[.@/~#]/.test(spec) || spec.includes(':')) continue;
      const pkg = spec.split('/')[0]!.toLowerCase();
      if (pkg) out.push({ pkg, line: m.startLine });
    }
  }
  return out;
}

/** Python import statements → candidate top-level module names. */
function pyCandidates(content: string, language: string | undefined): Candidate[] {
  const out: Candidate[] = [];
  // Anchor at the LINE START (m flag) and take only the module after the leading
  // `import`/`from` keyword. Without the anchor, the `import Y` clause of a
  // `from X import Y` statement was matched too, turning imported SYMBOLS into
  // package candidates — `from flask import request` flagged `request` as a
  // near-miss of `requests`, a false positive on nearly every Flask/FastAPI file.
  const re = /^[^\S\r\n]*(?:import|from)[^\S\r\n]+(?<spec>[A-Za-z_][\w.]{0,80})/gm;
  for (const m of runRegex(content, re, { skipCommentLines: true, language })) {
    const spec = m.variables?.spec;
    if (!spec) continue;
    const pkg = spec.split('.')[0]!.toLowerCase();
    if (pkg) out.push({ pkg, line: m.startLine });
  }
  return out;
}

/**
 * The classification core: given an ALREADY-NORMALIZED (lowercased, no
 * surrounding whitespace) candidate package name, decide whether it is a
 * finding and, if it is a near miss, which popular name it is a near miss OF.
 *
 * Split out of `hallucinatedDeps` for one reason: the CLI's rename fixer
 * (`remediation-engine/fixers.ts`, VG-AISC-001) has to answer exactly the same
 * question — "what did this import mean?" — and `RuleMatch.variables` does NOT
 * survive into a `Finding`, so the fixer cannot read the `didYouMean` the
 * detector already computed; it must recompute it from the file bytes.
 * Recomputing it by COPYING this logic into the fixer is the drift that would
 * eventually rename an import to something the detector never suggested. One
 * exported function (`nearestKnownPackage`) that both sides call makes that
 * class of drift structurally impossible rather than merely discouraged.
 *
 * The exemption order (builtin → alias stoplist → literally known → curated →
 * separator collision → edit distance) is load-bearing and deliberately
 * identical to what it replaced; see the precision contract in the file header.
 */
function classifyImportName(
  pkg: string,
  isPy: boolean,
): { didYouMean?: string; confidence?: 'high' | 'medium' } {
  const index = isPy ? PYPI_INDEX : NPM_INDEX;
  const builtins = isPy ? PY_STDLIB : NODE_BUILTINS;
  // Cheap exemptions first.
  if (builtins.has(pkg)) return {};
  if (ALIAS_STOPLIST.has(pkg)) return {};
  if (index.set.has(pkg)) return {};

  if (CURATED_HALLUCINATIONS.has(pkg)) {
    // Documented hallucination: a finding, but with NO suggestion — the name
    // does not exist and nothing in the bundled data says what was meant.
    return { confidence: 'high' };
  }
  // Normalized-key collision: same name modulo -/_/. separators (pip/npm
  // separator confusion), but not literally equal to a known name.
  const canon = index.normKeys.get(normKey(pkg));
  if (canon && canon !== pkg) return { didYouMean: canon, confidence: 'medium' };
  if (pkg.length >= 5) {
    // Edit-distance-1 of a popular name (length band avoids comparing against
    // everything; the ≥5 floor stops short names from colliding constantly).
    for (const len of [pkg.length - 1, pkg.length, pkg.length + 1]) {
      const bucket = index.byLen.get(len);
      if (!bucket) continue;
      const hit = bucket.find((known) => withinEditDistance1(pkg, known));
      if (hit) return { didYouMean: hit, confidence: 'medium' };
    }
  }
  return {};
}

/**
 * The popular package `importName` is a near miss of, or `null`.
 *
 * PUBLIC because the deterministic rename fixer needs it (see above). The
 * contract is deliberately narrow and fail-closed:
 *   - `null` for anything the detector would not flag at all (a Node/Python
 *     builtin, an import-name alias like `cv2`, a literally-known package),
 *     so a fixer that walks every specifier on a line cannot rename an import
 *     that was never the finding.
 *   - `null` for a CURATED hallucination too: those are flagged with no
 *     `didYouMean`, and inventing a target for them is exactly the "do not
 *     invent data" line the fixer table refuses to cross.
 *   - never a same-name result: a name equal to a known package is exempted
 *     above, so the caller can treat a non-null return as a real edit.
 *
 * `language` is the analyzer's language string; only 'python' selects the PyPI
 * index, mirroring `hallucinatedDeps` (js/ts and anything else → npm).
 */
export function nearestKnownPackage(importName: string, language: string): string | null {
  const pkg = importName.trim().toLowerCase();
  if (!pkg) return null;
  return classifyImportName(pkg, language === 'python').didYouMean ?? null;
}

function hallucinatedDeps(content: string, lines: string[], language: string | undefined): RuleMatch[] {
  const isPy = language === 'python';
  const candidates = isPy ? pyCandidates(content, language) : jsCandidates(content, language);

  const out: RuleMatch[] = [];
  const seen = new Set<string>();
  let processed = 0;
  for (const { pkg, line } of candidates) {
    if (processed >= 100) break;
    processed += 1;
    if (seen.has(pkg)) continue;

    const { didYouMean, confidence } = classifyImportName(pkg, isPy);

    if (!confidence) continue; // unknown-but-not-near-miss → SILENT (the contract)
    seen.add(pkg);
    const lineText = lines[line - 1] ?? pkg;
    out.push({
      startLine: line,
      endLine: line,
      startColumn: 1,
      // Span the whole line rather than a zero-width point: the canonical-pass
      // dedup (analyzer `overlaps`) treats a degenerate startCol==endCol span as
      // non-overlapping, so a zero-width match is reported twice (original +
      // canonical). A real span collapses the pair to one finding.
      endColumn: Math.max(2, lineText.length + 1),
      evidence: lineText.trim().slice(0, 200),
      confidence,
      variables: didYouMean ? { package: pkg, didYouMean } : { package: pkg },
    });
  }
  return out;
}

export const hallucinatedDependency: RuleDefinition = {
  ruleId: 'VG-AISC-001',
  name: 'Hallucinated Dependency',
  description:
    'An import names a package that is a near miss of a popular one (edit-distance-1 or separator-confusion) or a documented LLM-hallucinated name. AI code generators fabricate plausible-but-nonexistent package names; an attacker who registers one ("slopsquatting") gets code execution on install.',
  languages: ['javascript', 'typescript', 'python'],
  category: 'supply-chain',
  severity: 'medium',
  defaultConfidence: 'medium',
  // contextConfidence 'off': a hallucinated import in a comment is still worth
  // surfacing, and the import extractor already skips comment lines, so the
  // context layer has nothing useful to add here.
  contextConfidence: 'off',
  cwe: ['CWE-1104'],
  owasp: ['A08:2021'],
  tags: ['supply-chain', 'slopsquatting', 'ai-prone'],
  remediation: {
    why: 'A generated import of a nonexistent-but-plausible package name is a slopsquatting target: register the name and every `npm install` / `pip install` of the generated code runs attacker code. The near-miss to a real package is the tell.',
    how: 'Confirm the package exists and is the one you intend before installing: check the registry page, download counts, and repository. If you meant the popular near-neighbour, fix the name; if the package is genuinely internal, it will not be flagged (only near-misses are).',
    exampleFix: "// meant 'express', not 'expresss' — correct the import specifier",
  },
  match: (ctx) => hallucinatedDeps(ctx.content, ctx.lines, ctx.language),
};

// ===========================================================================
// VG-AISC-004 — Mock / Dummy Security Leftover
// ===========================================================================
//
// WHAT IT CLAIMS. A callable whose NAME says it is scaffolding (mock/fake/dummy/
// stub/placeholder/example/sample/test) AND says it makes a security decision
// (auth/token/password/secret/key/credential/verify/validate/permission/session/
// login/encrypt/sign/jwt), whose ENTIRE body is a permissive constant
// (`return true` / `return True` / `return { ok: true }`), sitting outside every
// test/mock/example path — i.e. the placeholder never got replaced and the
// placeholder IS the live security decision.
//
// This rule ships in packages/rules, which means it runs in the Chrome panel and
// the VS Code extension on ONE file with no project context. It therefore cannot
// ask "who calls this?" of a graph; everything below is decidable from a single
// file's bytes, and every place where that is not enough, the rule goes silent.
//
// -- THE NEGATIVE CONDITIONS, WRITTEN FIRST ---------------------------------
//
// Order matters here, and it is the order the code runs in. Each of these was
// derived by asking "what CORRECT code satisfies the positive conditions?" —
// which is the question VG-SMELL-041's first submission did not ask and was
// rejected for.
//
//  N1. The file is a test/spec/fixture path (`isTestPath`, shared with
//      VG-QUAL-007 so there is one definition). A mock in a test file is doing
//      its job. Without this the rule fires on every test suite in existence.
//  N2. ANY path segment, or the file's own basename, SEGMENTS to a scaffold
//      word (mock, fake, stub, fixture, test, spec, example, demo, sample,
//      story, seed, benchmark, playground, doc…). This is much wider than N1 on
//      purpose: `src/mocks/handlers.ts` (MSW), `src/test-utils/auth.ts`,
//      `stories/AuthDecorator.tsx`, `authStubs.py` and `auth.mock.ts` are all
//      correctly-placed test doubles that live OUTSIDE a `tests/` directory, and
//      they are the single largest population of code that satisfies (a)+(b)+(c).
//      The cost is real and accepted: a genuine leftover that happens to live in
//      `examples/` is now invisible. A false negative there is cheaper than
//      being the rule that flags every mock server in every repository.
//  N3. The file looks like a test module by CONTENT — it imports or calls a test
//      framework (vitest/jest/mocha/chai/sinon/testing-library/msw/supertest,
//      pytest/unittest). This closes N1+N2's blind spot (a test file parked in a
//      production path) and, more importantly, it is the only gate that works in
//      the Chrome panel when the "path" is a GitHub blob path the user chose.
//  N4. A boolean-PREDICATE name (`is…`, `has…`, `should…`, `can…`, `will…`,
//      `did…`, `are…`, `was…`) is not a finding. `isTestSessionEnabled = () =>
//      true` satisfies (a)+(b)+(c) exactly and is a feature flag, not a security
//      stub; a flag pinned on is VG-QUAL-008's subject, not this rule's.
//  N5. The symbol must be REACHABLE: exported, or referenced somewhere else in
//      the same file (Python: a module-level `def` with no leading underscore
//      counts, since that IS the module's API). A private helper that nothing
//      names is dead code, not a live security decision.
//  N6. Everything is decided over the BLANKED copy (`blankJsLiterals` /
//      `blankPyLiterals`), so a declaration written inside a comment, a
//      docstring, a template literal or a regex literal does not exist. This is
//      what lets this very file — which contains the word lists in source — stay
//      clean under the repository's own self-scan.
//
// -- WHAT WAS REFUSED, AND WHY ----------------------------------------------
//
// * "returns a hardcoded credential-shaped literal" (part of the original brief)
//   IS NOT IMPLEMENTED. Two reasons, both concrete. First, the shape is already
//   owned twice over: VG-AUTH-003 fires on `"dummy_token"` / `"test_password"` /
//   `"changeme"` at high, and VG-SEC-003 on a ≥20-char literal bound to a
//   secret-named variable at high — a third rule on the same line adds a
//   duplicate finding, not information. Second, the residue the two miss
//   (`const mockJwtSecret = "s3cr3t"`) cannot be separated lexically from
//   `const exampleKeyName = "x-api-key"`, `const sampleTokenType = "Bearer"`,
//   `const testKeyId = "kid-1"` — short lowercase identifiers assigned to
//   credential-NAMED constants are overwhelmingly protocol vocabulary, not
//   credentials. The recall gap is deliberate and documented rather than paid
//   for with that false-positive class.
//
// * "or is empty" IS NOT IMPLEMENTED. An empty body is a no-op, not a permissive
//   grant: `function mockAuth() {}` returns undefined, which every caller reads
//   as falsy/denied. The population that actually has empty bodies is interface
//   conformance and no-op adapters, and in Python `pass` / `...` bodies are
//   overwhelmingly `Protocol` / `@abstractmethod` declarations. Accepting them
//   would trade the rule's only sharp signal — "the answer is always yes" — for
//   its noisiest one.
//
// * A DATA const (`const mockUser = { role: "admin" }`) is not a finding here.
//   VG-QUAL-007 already owns `const mock*|fake*|dummy* =` at low severity. This
//   rule only escalates to high when the mock is a CALLABLE that returns a
//   security verdict, which is the thing a caller mistakes for a real check.
//   (This boundary is also why samples/vulnerable/ai_artifacts.js — which has
//   both `const mockUser = …` and `function authenticate(req) { return true; }`
//   — stays at exactly 51 findings: the first has no security word, the second
//   has no mock word, and neither is this rule's shape.)
//
// * `todo` / `fixme` / `xxx` / `changeme` are accepted as mock words ONLY when
//   the identifier segment is SHOUTED (`TODO_TOKEN`, `CHANGEME_KEY`). In
//   camelCase they are domain vocabulary far more often than markers — a
//   todo-list application is one of the most common AI-generated projects there
//   is, and `todoValidateItem(t) { return true }` in one is not a security
//   leftover. Markers are written in capitals; that is the discrimination.

/**
 * D3 parity. The scans below use raw `exec` and hand-rolled line walks rather
 * than `runRegex`, so nothing truncates for them; slice here so this rule reads
 * no further into a file than every `runRegex`-based rule does. Offsets stay
 * valid because a prefix is taken. Same helper, same argument, as
 * design-smells-single.ts — duplicated rather than exported across rule files
 * because `capped` is three lines and a shared "misc rule helpers" module is how
 * unrelated rules start depending on each other's edits.
 */
function cappedContext(ctx: RuleContext): { content: string; lines: string[] } {
  if (ctx.content.length <= REGEX_INPUT_CAP) return { content: ctx.content, lines: ctx.lines };
  const content = ctx.content.slice(0, REGEX_INPUT_CAP);
  return { content, lines: content.split('\n') };
}

/**
 * Split an identifier into WORDS. This is the discipline that separates
 * `mockAuth` from `mockingbird` and `signToken` from `designToken`, and it is
 * the reason nothing below ever does a substring test on an identifier.
 *
 * Three transformations, in this order:
 *   1. `([a-z0-9])([A-Z])`   — fooBar → foo Bar
 *   2. `([A-Z]{2,})([A-Z][a-z])` — JWTToken → JWT Token, XXXKey → XXX Key
 *   3. `[_\-$.]` runs → space — snake_case, kebab-case, `$`, and dotted members
 *
 * CASE IS PRESERVED. Callers need the raw segment to ask whether it was SHOUTED
 * (see MARKER_WORDS); lowercasing happens at membership-test time in
 * `normalizeSegment`. Returning `string[]` rather than a space-joined string —
 * which is what design-smells-single.ts's `tokenize` does for its regex-based
 * domain table — is deliberate: this rule tests SET MEMBERSHIP of whole words,
 * and a joined string would put `\b`-anchored regexes back in play, which is
 * exactly the substring-adjacent matching the brief forbids.
 */
function segmentIdentifier(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]{2,})([A-Z][a-z])/g, '$1 $2')
    .replace(/[_\-$.]{1,16}/g, ' ')
    .split(' ')
    .filter((s) => s.length > 0);
}

/**
 * A segment reduced to its lookup key: lowercase, trailing digits removed.
 *
 * The digit strip is what makes `mockToken2` → `token` and `testKey1` → `key`
 * work. It can only ever REMOVE characters, so the failure direction is a missed
 * lookup (`sha256` → `sha`, `base64` → `base` — neither is in any list here),
 * never an invented one.
 */
function normalizeSegment(raw: string): string {
  return raw.toLowerCase().replace(/\d{1,8}$/, '');
}

/**
 * Membership with a naive singular fallback: `tokens` → `token`, `keys` → `key`,
 * `permissions` → `permission`, `mocks` → `mock`.
 *
 * Over-stripping is harmless by construction — the sets below contain no word
 * that is another word plus an `s`, so a wrong strip produces a key that is in
 * no set and the test simply fails. The ≥4 length floor keeps two- and
 * three-letter segments (`is`, `as`, `us`) out of it.
 */
function inWordSet(set: ReadonlySet<string>, key: string): boolean {
  if (set.has(key)) return true;
  return key.length >= 4 && key.endsWith('s') && set.has(key.slice(0, -1));
}

/** True when the raw segment was written in capitals, i.e. as a marker. */
function isShoutedSegment(raw: string): boolean {
  return /^[A-Z][A-Z0-9]{1,19}$/.test(raw);
}

/**
 * Scaffolding words that may appear in any casing. Singular forms only — the
 * `inWordSet` fallback covers the plurals, and listing both would make the two
 * mechanisms disagree the first time someone adds a word to one of them.
 *
 * `mocking` is absent on purpose: as a whole segment it is vanishingly rare, and
 * including it buys nothing while inviting the `mockingbird` confusion this
 * file's segmentation exists to prevent.
 */
const MOCK_WORDS: ReadonlySet<string> = new Set([
  'mock', 'mocked', 'fake', 'faked', 'dummy', 'stub', 'stubbed',
  'placeholder', 'example', 'sample', 'test',
]);

/**
 * Marker words accepted ONLY in a shouted segment. See the header for the
 * todo-list-application argument; `changeme` and `fixme` are also reachable as
 * the bigram of two shouted segments (`CHANGE_ME`, `FIX_ME`).
 */
const MARKER_WORDS: ReadonlySet<string> = new Set(['todo', 'fixme', 'xxx', 'changeme']);

/**
 * The security vocabulary. This is the brief's list plus its unavoidable
 * morphological variants; nothing beyond it. In particular `hash`, `admin`,
 * `role`, `csrf` and `cors` are NOT here — `role`/`admin` belong to VG-SMELL-012
 * and `hash` is the ambiguous noun VG-SMELL-004 explicitly refuses to treat as a
 * security signal (a hashmap key is not a credential).
 *
 * `key` is the weakest entry and is kept knowingly: a `mockCacheKey` is a real
 * shape. What stops it being a false-positive source is not the word list but
 * the conjunction — a function called "get cache key" whose entire body is
 * `return true` is not a cache key function.
 */
const SECURITY_WORDS: ReadonlySet<string> = new Set([
  'auth', 'authn', 'authz', 'authorize', 'authorise', 'authorized', 'authorised',
  'authorization', 'authorisation', 'authenticate', 'authenticated', 'authentication',
  'token', 'password', 'passwd', 'secret', 'key', 'credential',
  'verify', 'verified', 'verification', 'validate', 'validated', 'validation',
  'permission', 'session', 'login', 'logon', 'signin',
  'encrypt', 'encrypted', 'encryption', 'sign', 'signed', 'signature', 'jwt',
]);

/**
 * The subset that makes the finding unambiguous enough for per-match `high`
 * confidence. It is the authentication/authorization/credential core; the
 * generic ones (`key`, `sign`, `validate`, `verify`) are excluded because each
 * has a large non-security population behind it.
 */
const STRONG_SECURITY_WORDS: ReadonlySet<string> = new Set([
  'auth', 'authn', 'authz', 'authorize', 'authorise', 'authorized', 'authorised',
  'authorization', 'authorisation', 'authenticate', 'authenticated', 'authentication',
  'token', 'password', 'passwd', 'secret', 'credential', 'permission', 'session',
  'login', 'logon', 'signin', 'jwt',
]);

/** Mock words that are never ambiguous, used with the above to reach `high`. */
const STRONG_MOCK_WORDS: ReadonlySet<string> = new Set([
  'mock', 'mocked', 'fake', 'faked', 'dummy', 'stub', 'stubbed', 'placeholder',
]);

/**
 * N4 — leading segments that make the identifier a PREDICATE or a flag rather
 * than an operation. See the header: `isTestSessionEnabled = () => true` is a
 * feature flag and VG-QUAL-008's subject, not a security stub.
 *
 * `get`, `use`, `create` and `make` are deliberately NOT here: `useMockAuth()`
 * (a React hook) and `getMockToken()` really are the operation, just named with
 * a verb.
 */
const PREDICATE_PREFIXES: ReadonlySet<string> = new Set([
  'is', 'has', 'should', 'can', 'will', 'did', 'are', 'was',
]);

/**
 * The word in `segments` that makes the identifier scaffolding, or null.
 *
 * Bigrams of ADJACENT segments are tested as well as single segments, which is
 * how `PlaceHolder` reaches `placeholder` and `CHANGE_ME` reaches `changeme`. A
 * bigram of two marker segments requires BOTH to be shouted, so `changeMe` in
 * ordinary camelCase is still not a marker.
 */
function findMockWord(segments: readonly string[]): string | null {
  for (let i = 0; i < segments.length; i += 1) {
    const raw = segments[i]!;
    const key = normalizeSegment(raw);
    if (inWordSet(MOCK_WORDS, key)) return key;
    if (MARKER_WORDS.has(key) && isShoutedSegment(raw)) return key;
    const nextRaw = segments[i + 1];
    if (nextRaw === undefined) continue;
    const bigram = raw.toLowerCase() + nextRaw.toLowerCase();
    if (inWordSet(MOCK_WORDS, bigram)) return bigram;
    if (MARKER_WORDS.has(bigram) && isShoutedSegment(raw) && isShoutedSegment(nextRaw)) {
      return bigram;
    }
  }
  return null;
}

/**
 * Words that, standing immediately BEFORE a security word, mean it is not one.
 *
 * MEASURED, not guessed: `mockDesignToken` was flagged by the first working
 * version of this rule. "Design token" is core design-system vocabulary and
 * appears in a large share of front-end repositories; so do "cache key", "sort
 * key", "primary key", "partition key" and "lexer token". `token` and `key` are
 * the two weakest entries in SECURITY_WORDS and this is where their ambiguity
 * actually lands, so the qualifier is checked at the point of use rather than by
 * removing the two words (which would cost `mockAuthToken` and `dummyApiKey`,
 * the shapes the rule exists for).
 *
 * Only the IMMEDIATELY preceding segment is consulted. `mockAuthCacheKey` still
 * fires, because the strong pass finds `auth` — which is preceded by `mock`, not
 * by a qualifier — before it ever reaches `key`.
 *
 * `api`, `access`, `private`, `public`, `signing`, `master` and `secret` are
 * deliberately ABSENT: each of those before `key` makes it more of a credential,
 * not less.
 */
const NON_SECURITY_QUALIFIERS: ReadonlySet<string> = new Set([
  'design', 'style', 'styling', 'css', 'theme', 'color', 'colour', 'font',
  'spacing', 'layout', 'cache', 'map', 'dict', 'hash', 'sort', 'row', 'column',
  'group', 'shard', 'partition', 'primary', 'foreign', 'composite', 'index',
  'lexer', 'lexical', 'parser', 'parse', 'csv', 'xml', 'json', 'react', 'list',
  'item', 'dom', 'idempotency', 'correlation', 'trace', 'locale', 'i18n',
]);

/** True when the segment before position `i` disqualifies the word at `i`. */
function hasNonSecurityQualifier(segments: readonly string[], i: number): boolean {
  if (i === 0) return false;
  return NON_SECURITY_QUALIFIERS.has(normalizeSegment(segments[i - 1]!));
}

/**
 * The word in `segments` that makes the identifier security-relevant, or null.
 *
 * TWO PASSES, and the order is load-bearing for the reported confidence rather
 * than for detection. `mockVerifyToken` contains both `verify` (generic) and
 * `token` (a credential); returning the first hit in reading order would report
 * `verify` and drop the finding to `medium`, so a name that says exactly what it
 * mocks would be trusted LESS than `mockAuth`. Scanning STRONG_SECURITY_WORDS
 * first makes the reported word the most specific one present, which is both the
 * more useful evidence and the more honest confidence.
 */
function findSecurityWord(segments: readonly string[]): string | null {
  for (const set of [STRONG_SECURITY_WORDS, SECURITY_WORDS]) {
    for (let i = 0; i < segments.length; i += 1) {
      if (hasNonSecurityQualifier(segments, i)) continue;
      const key = normalizeSegment(segments[i]!);
      if (inWordSet(set, key)) return key;
      const nextRaw = segments[i + 1];
      if (nextRaw === undefined) continue;
      const bigram = segments[i]!.toLowerCase() + nextRaw.toLowerCase();
      if (inWordSet(set, bigram)) return bigram;
    }
  }
  return null;
}

/** N2 — a path/basename word that says the file is scaffolding by location. */
const SCAFFOLD_PATH_WORDS: ReadonlySet<string> = new Set([
  'test', 'tests', 'testing', 'testdata', 'spec', 'specs', 'e2e', 'cypress',
  'playwright', 'karma', 'jasmine', 'mock', 'mocks', 'fake', 'fakes', 'dummy',
  'stub', 'stubs', 'fixture', 'fixtures', 'story', 'stories', 'storybook',
  'example', 'examples', 'demo', 'demos', 'sample', 'samples', 'doc', 'docs',
  'documentation', 'benchmark', 'benchmarks', 'bench', 'playground', 'sandbox',
  'scaffold', 'scaffolding', 'template', 'templates', 'seed', 'seeds', 'tutorial',
]);

/**
 * N1 + N2 — the file is scaffolding by LOCATION.
 *
 * Every path segment AND the basename are word-segmented with the same
 * `segmentIdentifier` used on symbols, so `test-utils`, `__mocks__`,
 * `authStubs.py`, `auth.mock.ts` and `AuthDecorator.stories.tsx` all resolve
 * without a per-spelling list. Extensions are dropped first so `.spec.ts` and
 * `.stories.tsx` contribute their middle part rather than `ts`/`tsx`.
 *
 * Generous by design. This gate can only SUPPRESS, so a word that is too broad
 * costs recall and never precision — the direction a rule that has to survive a
 * 630-repository sweep should be wrong in.
 */
function isScaffoldPath(filePath: string | undefined): boolean {
  if (filePath === undefined || filePath === '') return false;
  if (isTestPath(filePath)) return true;
  const parts = filePath.split(/[\\/]/);
  for (let i = 0; i < parts.length; i += 1) {
    const part = parts[i]!;
    // The last component is a file name: strip the extension chain so the
    // segmentation sees `auth.mock`, not `auth.mock.ts`.
    const bare = i === parts.length - 1 ? part.replace(/\.[A-Za-z0-9]{1,8}$/, '') : part;
    for (const seg of segmentIdentifier(bare)) {
      if (inWordSet(SCAFFOLD_PATH_WORDS, normalizeSegment(seg))) return true;
    }
  }
  return false;
}

/**
 * N3 — the file is scaffolding by CONTENT: it imports or drives a test
 * framework.
 *
 * RUN AGAINST THE RAW CONTENT, NOT THE BLANKED COPY, and that is a correction
 * rather than an oversight. The first version tested the blanked text and did
 * not fire on `import { vi } from 'vitest'` at all, because the blanker hollows
 * out string literals and a module specifier IS a string literal — the one place
 * a framework is always named. Testing the raw text means a framework mentioned
 * in a COMMENT also silences the file, which is accepted for the same reason
 * `isScaffoldPath` is generous: this gate can only SUPPRESS, so being too eager
 * costs recall and never precision.
 *
 * Note what is NOT in here: bare `describe(` / `it(` / `test(`. `x.test(s)` is
 * `RegExp.prototype.test` and appears in nearly every rule file in this
 * repository, and `it` is a legal variable name. `responses`, `nose` and
 * `hypothesis` were dropped for the same reason after being written down —
 * `responses` in particular is an ordinary identifier in any HTTP client, and a
 * file-wide suppression keyed on it would silence real handlers. The tokens that
 * remain all name a framework explicitly, which is a claim about the file that
 * ordinary code does not accidentally make.
 *
 * Bounded on both sides of every variable run; the only quantified runs are
 * `[^\S\r\n]{0,4}` around fixed tokens.
 */
const TEST_FRAMEWORK_MARKER =
  /(?:^|[^\w$.])(?:vitest|jest|mocha|chai|sinon|jasmine|supertest|nock|testing-library|msw|enzyme|pytest|unittest|factory_boy)\b|\b(?:jest|vi|sinon|td)[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}(?:mock|fn|spyOn|stub|fake)\b|@(?:pytest|mock)\.[\w.]{1,40}|\bdef[^\S\r\n]{1,4}test_[\w]{1,60}[^\S\r\n]{0,4}\(|\bpatch[^\S\r\n]{0,4}\([^\S\r\n]{0,4}["']/;

/** N3 evaluated once per file, over the RAW (capped) content — see above. */
function looksLikeTestModule(content: string): boolean {
  return TEST_FRAMEWORK_MARKER.test(content);
}

/**
 * A body/expression stripped of a trailing line comment and a trailing `;`.
 *
 * The blankers keep comment DELIMITERS (they are length-preserving), so a body
 * that reads `return true; //` in the blanked copy has to have the `//` removed
 * before it can be compared against `return true`. Bounded `[^\n]{0,400}`, never
 * `.*`.
 */
function stripTrailingNoise(text: string): string {
  return text
    .replace(/(?:\/\/|#)[^\n]{0,400}$/, '')
    .trim()
    .replace(/;{1,4}$/, '')
    .trim();
}

/**
 * True when `text` is an object literal whose EVERY property value is the
 * boolean true — `{ ok: true }`, `{ authorized: true, valid: true }`,
 * `{"ok": True}`. This is the `return { ok: true }`-shaped arm.
 *
 * The split on `,` cannot understand nesting, and does not need to: a nested
 * object makes some part fail the per-property test and the whole thing returns
 * false. Failing closed on anything it cannot parse is the point — the claim
 * being made is "this returns an unconditional yes", and a body it cannot read
 * does not support that claim.
 */
function isAllTruePropertyBag(text: string): boolean {
  const unwrapped = text.trim().replace(/^\({1,2}/, '').replace(/\){1,2}$/, '').trim();
  if (!unwrapped.startsWith('{') || !unwrapped.endsWith('}')) return false;
  const inner = unwrapped.slice(1, -1);
  if (inner.length > 200) return false;
  const parts = inner.split(',');
  if (parts.length > 6) return false;
  let properties = 0;
  for (const part of parts) {
    const property = part.trim();
    if (property === '') continue; // trailing comma
    // The KEY may be a bare identifier or a quoted string, and a quoted key
    // arrives here BLANKED (`{"ok": True}` reads as `{"  ": True}`), so the
    // quoted form must accept any interior. That costs nothing: the discriminator
    // is the VALUE, which has to be the literal `true`/`True` either way.
    if (
      !/^(?:["'][^"'\n]{0,40}["']|[A-Za-z_$][\w$]{0,40})[^\S\r\n]{0,4}:[^\S\r\n]{0,4}(?:true|True)$/
        .test(property)
    ) {
      return false;
    }
    properties += 1;
  }
  // `{}` is not permissive — it is empty, and "empty" is refused (see header).
  return properties > 0;
}

/**
 * True when a JS/TS expression is an unconditional permissive constant.
 * `trueLiteral` is `true` for JS and `True` for Python so the two never accept
 * each other's spelling — a JS `True` is an undefined identifier, not a boolean.
 */
function isPermissiveExpression(expression: string, trueLiteral: 'true' | 'True'): boolean {
  const expr = stripTrailingNoise(expression);
  if (expr === trueLiteral) return true;
  return isAllTruePropertyBag(expr);
}

/**
 * The expression of a `return <expr>` statement, or null when `statement` is not
 * exactly one such return.
 *
 * Written with string operations rather than `/^return[^\S\r\n]{1,4}(.{0,220})$/`
 * on purpose: in that pattern the bounded whitespace run and the payload run
 * OVERLAP (a space matches both), which is the adjacent-variable-run shape the
 * A1 audit exists to keep out of this package. Both forms are bounded and both
 * are fast, but one of them is a shape nobody has to re-argue about.
 */
function returnedExpression(statement: string): string | null {
  if (!statement.startsWith('return')) return null;
  const rest = statement.slice('return'.length);
  // `returnValue` is not a return statement; `return` must be followed by space.
  if (rest === '' || !/^[^\S\r\n]/.test(rest)) return null;
  const expression = rest.trim();
  return expression.length > 0 && expression.length <= 240 ? expression : null;
}

/**
 * True when a `{ … }` block (braces included, already blanked) contains exactly
 * one statement and that statement returns a permissive constant.
 *
 * `trim()` on the interior removes the newlines a formatted body carries, so a
 * one-statement body collapses to a single line here. A body with two statements
 * keeps its interior newline and matches nothing — which is the intent: a mock
 * with real logic is a test double, not a leftover.
 */
function isPermissiveBlock(block: string, trueLiteral: 'true' | 'True'): boolean {
  if (!block.startsWith('{') || !block.endsWith('}')) return false;
  const expression = returnedExpression(stripTrailingNoise(block.slice(1, -1).trim()));
  if (expression === null) return false;
  return isPermissiveExpression(expression, trueLiteral);
}

/**
 * N5 — is this symbol reachable by anything?
 *
 * Two ways to say yes, both single-file:
 *  - the declaration line carries `export` / `module.exports` / `exports.`, or
 *  - the name occurs a second time anywhere in the blanked file.
 *
 * Lookarounds rather than `\b` because a JS identifier may contain `$`, which is
 * not a word character: `\bmock$Auth\b` would anchor in the wrong places. The
 * name is matched from `[A-Za-z_$][\w$]{0,60}` so `$` is the only metacharacter
 * that can appear and escaping it is the whole of the escaping needed.
 *
 * The occurrence scan is capped at 2 hits — it only ever has to answer "more
 * than one?", and stopping there keeps this O(file) rather than O(file × uses).
 */
function isReachable(blanked: string, declarationLine: string, name: string): boolean {
  if (/(?:^|[^\w$.])(?:export|exports|module\.exports)\b/.test(declarationLine)) return true;
  const escaped = name.replace(/\$/g, '\\$');
  const occurrence = new RegExp(`(?<![\\w$])${escaped}(?![\\w$])`, 'g');
  let hits = 0;
  let m: RegExpExecArray | null;
  while (hits < 2 && (m = occurrence.exec(blanked)) !== null) {
    hits += 1;
    if (m[0].length === 0) occurrence.lastIndex += 1;
  }
  return hits >= 2;
}

/**
 * A callable head followed by a `{` block: `function mockAuth(req) {`,
 * `async mockVerifyToken() {`, `public mockCheckPermission(u) {`.
 *
 * ONE pattern covers the declaration, the class method and the object method,
 * because after the leading `(?:^|[^\w$.])` guard they are lexically identical.
 * That guard is doing two jobs: it excludes a member call (`svc.mockAuth(x) {`
 * is not a declaration) and it makes `function mockAuth(` match with
 * `name = mockAuth` rather than `name = function`.
 *
 * It also matches `if (x) {`, `catch (e) {` and every other keyword-led block —
 * and that is fine, because the name gate rejects them before any work happens.
 * Filtering keywords inside the pattern (what design-smells-single.ts's fnC
 * does) buys nothing here and costs a lookahead.
 *
 * The second branch before the `{` is the TypeScript RETURN TYPE
 * (`mockVerifyToken(t: string): boolean {`). Without it every annotated method
 * in a TS codebase is invisible — the recall gap §17z-f-lite closed for
 * VG-SMELL-003, reproduced here rather than rediscovered. The type run is pinned
 * directly against the literal `{` and excludes `{`, `}`, `(`, `)`, `?`, `;`,
 * `=` and newline, so it cannot walk across a statement boundary, a ternary, or
 * a function-type annotation into an unrelated block.
 *
 * BOUNDS: every quantified run is bounded and every pair of them is separated by
 * a literal (`(`, `)`, `:`, `{`), so no two variable-length runs are adjacent —
 * the A1 shape. `[^()\n]{0,200}` cannot cross a line or a nested paren, so a
 * parameter list containing a call or a function type is a MISS (fail-quiet).
 */
const JS_CALLABLE_HEAD =
  /(?:^|[^\w$.])(?<name>[A-Za-z_$][\w$]{0,60})[^\S\r\n]{0,4}\([^()\n]{0,200}\)(?:[^\S\r\n]{0,4}|[^\S\r\n]{0,4}:[^\S\r\n]{0,4}[A-Za-z_$][^{}()?;=\n]{0,120})\{/g;

/**
 * A `const`/`let`/`var` bound to a function expression or an arrow.
 *
 * The three initialiser shapes are `function (…)`, `(…) =>` and `x =>`, each
 * with an optional TypeScript RETURN type before the `=>`. That alternative is
 * spelled out as a separate branch rather than as an optional group, so the type
 * run `[^{}()?;=\n]{0,120}` is pinned directly against the literal `=>` and no
 * two variable-length runs ever sit next to each other — the same construction
 * design-smells-single.ts's fnD uses, and the reason `=` is excluded from the
 * run is that it must not be able to swallow the arrow itself.
 *
 * A type annotation between the NAME and the `=` (`const mockAuth: () => boolean
 * = …`) is still not accepted: that annotation can contain `=`, `>` and `(`, so
 * any pattern loose enough to skip it is loose enough to walk across the
 * assignment. That is a miss, and a miss is the side this rule is allowed to be
 * wrong on.
 */
const JS_CALLABLE_BINDING =
  /(?:^|[^\w$.])(?:const|let|var)[^\S\r\n]{1,4}(?<name>[A-Za-z_$][\w$]{0,60})[^\S\r\n]{0,4}=[^\S\r\n]{0,4}(?:async[^\S\r\n]{1,4})?(?:function[^\S\r\n]{0,4}\([^()\n]{0,200}\)|\([^()\n]{0,200}\)[^\S\r\n]{0,4}=>|\([^()\n]{0,200}\)[^\S\r\n]{0,4}:[^\S\r\n]{0,4}[A-Za-z_$][^{}()?;=\n]{0,120}=>|[A-Za-z_$][\w$]{0,40}[^\S\r\n]{0,4}=>)/g;

/** Python function heads, with the indent that defines their body's scope. */
const PY_DEF_HEAD =
  /^(?<indent>[^\S\r\n]{0,60})(?:async[^\S\r\n]{1,4})?def[^\S\r\n]{1,4}(?<name>[A-Za-z_]\w{0,60})[^\S\r\n]{0,4}\(/gm;

/**
 * How many declaration heads are examined per file. `JS_CALLABLE_HEAD` matches
 * every braced block in the file, so on a large file this is the loop that has
 * to be bounded; the name gate makes each iteration cheap but not free.
 */
const MAX_DECLARATION_HEADS = 400;

/** Offset of the first non-`[ \t]` character at or after `from`, crossing at most one newline. */
function skipInlineGap(text: string, from: number): number {
  let k = from;
  let newlines = 0;
  while (k < text.length) {
    const c = text[k];
    if (c === ' ' || c === '\t' || c === '\r') {
      k += 1;
    } else if (c === '\n' && newlines === 0) {
      newlines += 1;
      k += 1;
    } else {
      break;
    }
  }
  return k;
}

interface LeftoverHit {
  name: string;
  mockWord: string;
  securityWord: string;
  offset: number;
}

/**
 * The name gate, shared by every language arm. Returns the two words that made
 * the identifier interesting, or null.
 *
 * Cheap on purpose and checked FIRST at every call site: it rejects `if`,
 * `catch`, `constructor` and every ordinary identifier in one pass over a short
 * string, before any block extraction happens.
 */
function classifyLeftoverName(name: string): { mockWord: string; securityWord: string } | null {
  const segments = segmentIdentifier(name);
  if (segments.length < 2) return null; // a bare `mock` names nothing security-related
  if (PREDICATE_PREFIXES.has(normalizeSegment(segments[0]!))) return null; // N4
  const mockWord = findMockWord(segments);
  if (mockWord === null) return null;
  const securityWord = findSecurityWord(segments);
  if (securityWord === null) return null;
  // The same segment must not satisfy both halves. No word is in both sets
  // today, so this is a guard against a future edit that puts one there.
  if (mockWord === securityWord) return null;
  return { mockWord, securityWord };
}

/**
 * Offset of the DECLARATION inside a `JS_CALLABLE_HEAD` / `JS_CALLABLE_BINDING`
 * match.
 *
 * Both patterns open with `(?:^|[^\w$.])`, which consumes ONE character when the
 * match is not at offset 0 — routinely the newline that ends the PREVIOUS line.
 * Reporting `m.index` directly therefore puts the finding on the line above the
 * declaration, and on CRLF input `indexToPosition` (which counts `\n`) and the
 * regex engine disagree about which line that even is. This is the same defect
 * `runRegex` corrects with its leading-whitespace anchor and `confidence.ts`
 * with `inspectedLine`; here the guard is exactly one optional character, so the
 * correction is exact rather than heuristic.
 */
function declarationOffsetOf(match: RegExpExecArray, startsWithPayload: RegExp): number {
  return startsWithPayload.test(match[0]) ? match.index : match.index + 1;
}

/** JS/TS arm. `blanked` is `blankJsLiterals(content)`; offsets are content offsets. */
function jsLeftovers(blanked: string, lines: string[]): LeftoverHit[] {
  const out: LeftoverHit[] = [];
  const seen = new Set<number>();

  const consider = (name: string, declarationOffset: number, permissive: boolean): void => {
    if (!permissive) return;
    const classified = classifyLeftoverName(name);
    if (classified === null) return;
    const line = indexToPosition(blanked, declarationOffset).line;
    if (seen.has(line)) return;
    if (!isReachable(blanked, lines[line - 1] ?? '', name)) return; // N5
    seen.add(line);
    out.push({ name, ...classified, offset: declarationOffset });
  };

  JS_CALLABLE_HEAD.lastIndex = 0;
  let heads = 0;
  let m: RegExpExecArray | null;
  while (heads < MAX_DECLARATION_HEADS && (m = JS_CALLABLE_HEAD.exec(blanked)) !== null) {
    heads += 1;
    if (m[0].length === 0) {
      JS_CALLABLE_HEAD.lastIndex += 1;
      continue;
    }
    const name = m.groups?.name ?? '';
    // Name gate before block extraction: `JS_CALLABLE_HEAD` matches every `if (…)
    // {` in the file and extracting each of those bodies would be the whole cost
    // of this rule.
    if (classifyLeftoverName(name) === null) continue;
    const braceIndex = m.index + m[0].length - 1;
    const block = extractBlockAfter(blanked, braceIndex, { maxHeadGap: 2, maxBodyLength: 4_000 });
    consider(
      name,
      declarationOffsetOf(m, /^[A-Za-z_$]/),
      block !== null && isPermissiveBlock(block.body, 'true'),
    );
  }

  JS_CALLABLE_BINDING.lastIndex = 0;
  heads = 0;
  while (heads < MAX_DECLARATION_HEADS && (m = JS_CALLABLE_BINDING.exec(blanked)) !== null) {
    heads += 1;
    if (m[0].length === 0) {
      JS_CALLABLE_BINDING.lastIndex += 1;
      continue;
    }
    const name = m.groups?.name ?? '';
    if (classifyLeftoverName(name) === null) continue;
    const offset = declarationOffsetOf(m, /^(?:const|let|var)/);
    const after = skipInlineGap(blanked, m.index + m[0].length);
    if (blanked[after] === '{') {
      // `= function (…) {` and `= (…) => {` — a braced body.
      const block = extractBlockAfter(blanked, after, { maxHeadGap: 2, maxBodyLength: 4_000 });
      consider(name, offset, block !== null && isPermissiveBlock(block.body, 'true'));
    } else {
      // `= (…) => <expression>` — read to the statement end. Bounded slice, and
      // the terminator is whichever of `;` / newline comes first, so a
      // multi-statement arrow body cannot be read as one expression.
      const tail = blanked.slice(after, after + 240);
      const end = Math.min(
        ...[tail.indexOf(';'), tail.indexOf('\n')].filter((i) => i >= 0).concat([tail.length]),
      );
      consider(name, offset, isPermissiveExpression(tail.slice(0, end), 'true'));
    }
  }

  return out;
}

/**
 * Python arm. Bodies are indentation-scoped, so the block is walked line by line
 * over the BLANKED lines (docstring interiors are already spaces there).
 *
 * A body qualifies only when, after dropping blank lines and the delimiter-only
 * lines of a docstring, exactly ONE statement remains and it is `return True`.
 * `pass` and `...` are refused (see header).
 */
function pyLeftovers(blanked: string, blankedLines: string[]): LeftoverHit[] {
  const out: LeftoverHit[] = [];
  PY_DEF_HEAD.lastIndex = 0;
  let heads = 0;
  let m: RegExpExecArray | null;
  while (heads < MAX_DECLARATION_HEADS && (m = PY_DEF_HEAD.exec(blanked)) !== null) {
    heads += 1;
    if (m[0].length === 0) {
      PY_DEF_HEAD.lastIndex += 1;
      continue;
    }
    const name = m.groups?.name ?? '';
    if (classifyLeftoverName(name) === null) continue;
    const indent = (m.groups?.indent ?? '').length;
    const defLine = indexToPosition(blanked, m.index).line; // 1-based

    // Find the line that ENDS the signature: the first line from the def onward
    // whose trailing non-comment character is `:`. Bounded to 8 lines — a
    // security stub with a signature longer than that is not the population
    // this rule is about, and an unbounded search would walk the whole file
    // whenever a `def` head has no colon (a syntax error, or a truncated file).
    let signatureEnd = -1;
    for (let i = defLine - 1; i < Math.min(blankedLines.length, defLine + 7); i += 1) {
      const text = stripTrailingNoise(blankedLines[i] ?? '');
      if (text.endsWith(':')) {
        signatureEnd = i;
        break;
      }
      // A same-line body (`def mock_auth(): return True`) ends the signature at
      // the colon that is NOT the last character.
      const colon = text.indexOf('):');
      if (colon >= 0) {
        signatureEnd = i;
        break;
      }
    }
    if (signatureEnd < 0) continue;

    const statements: string[] = [];
    const signatureText = stripTrailingNoise(blankedLines[signatureEnd] ?? '');
    const inlineColon = signatureText.lastIndexOf('):');
    if (inlineColon >= 0 && inlineColon + 2 < signatureText.length) {
      statements.push(signatureText.slice(inlineColon + 2).trim());
    } else {
      for (let i = signatureEnd + 1; i < blankedLines.length; i += 1) {
        const raw = blankedLines[i] ?? '';
        if (raw.trim() === '') continue;
        const width = raw.length - raw.trimStart().length;
        if (width <= indent) break;
        const text = stripTrailingNoise(raw);
        if (text === '') continue;
        // Delimiter-only line of a blanked docstring (`"""` on its own line).
        if (/^(?:"""|''')[^\S\r\n]{0,200}(?:"""|''')?$/.test(text)) continue;
        statements.push(text);
        if (statements.length > 1) break; // more than one statement — real logic
      }
    }

    if (statements.length !== 1) continue;
    const returned = returnedExpression(statements[0]!);
    if (returned === null) continue;
    if (!isPermissiveExpression(returned, 'True')) continue;

    // N5 for Python: a module-level `def` with no leading underscore IS the
    // module's public surface, whether or not anything in this file calls it.
    const publicAtModuleLevel = indent === 0 && !name.startsWith('_');
    if (!publicAtModuleLevel && !isReachable(blanked, blankedLines[defLine - 1] ?? '', name)) {
      continue;
    }

    const classified = classifyLeftoverName(name)!;
    out.push({ name, ...classified, offset: m.index });
  }
  return out;
}

function mockSecurityLeftovers(ctx: RuleContext): RuleMatch[] {
  // N1 + N2 — location. Cheapest gate, and the one that removes the largest
  // population of correct code, so it runs before the file is even blanked.
  if (isScaffoldPath(ctx.filePath)) return [];
  const { content, lines } = cappedContext(ctx);
  const isPy = ctx.language === 'python';
  // N3 — content. A test module in a production path, and the only gate that
  // still works when the caller supplies no path at all.
  if (looksLikeTestModule(content)) return [];
  const blanked = isPy ? blankPyLiterals(content) : blankJsLiterals(content);

  const hits = isPy ? pyLeftovers(blanked, blanked.split('\n')) : jsLeftovers(blanked, lines);

  return hits.map((hit) => {
    const position = indexToPosition(content, hit.offset);
    const lineText = lines[position.line - 1] ?? hit.name;
    const strong =
      STRONG_MOCK_WORDS.has(hit.mockWord) && STRONG_SECURITY_WORDS.has(hit.securityWord);
    return {
      startLine: position.line,
      endLine: position.line,
      startColumn: 1,
      // Span the whole line for the reason VG-AISC-001 does: the analyzer's
      // canonical-pass dedup treats a zero-width span as non-overlapping and
      // reports the match twice.
      endColumn: Math.max(2, lineText.length + 1),
      evidence: lineText.trim().slice(0, 200),
      confidence: strong ? ('high' as const) : undefined,
      variables: { symbol: hit.name, mockWord: hit.mockWord, securityWord: hit.securityWord },
    };
  });
}

export const mockSecurityLeftover: RuleDefinition = {
  ruleId: 'VG-AISC-004',
  name: 'Mock / Dummy Security Leftover',
  description:
    'A function whose name says it is scaffolding (mock/fake/dummy/stub/placeholder) AND names a security operation (auth, token, permission, session, verify) returns an unconditional true. The placeholder was never replaced, so the mock IS the live security decision.',
  // js/ts/python only. Each has a blanker in matcher-utils that models its
  // comment and string syntax; a language without one would have its rule data
  // and prose read as code, which is the precise failure this rule must not
  // have (see the self-scan note in the file header).
  languages: ['javascript', 'typescript', 'python'],
  // 'auth', not the file's 'supply-chain'. registry.test.ts states the rule-ID
  // prefix and the category are separate taxonomies — the prefix says which
  // family the rule was written in, the category says what kind of risk it is —
  // and cites VG-AUTH-003 ('secrets') as the precedent. A consumer filtering for
  // authentication problems wants this finding; a consumer filtering for
  // dependency risk does not.
  category: 'auth',
  severity: 'high',
  defaultConfidence: 'medium',
  // contextConfidence left at the default 'auto'. The comment case is already
  // handled structurally — everything is decided over the blanked copy, so a
  // declaration inside a comment does not exist — and the test-path case is
  // handled by N1/N2/N3, which go silent rather than down-rank. `auto` therefore
  // costs nothing and keeps the rule inside the central chokepoint rather than
  // asserting its own certainty, which is what 'off' would mean.
  cwe: ['CWE-489', 'CWE-287'],
  owasp: ['A01:2021', 'A07:2021'],
  tags: ['ai-prone', 'placeholder', 'access-control'],
  remediation: {
    why: 'A stub that always returns true is indistinguishable from a real check at the call site: every caller reads "authorized" and skips its own defensive handling. AI assistants emit these to make a flow compile before the real logic exists, and the name is the only thing that ever said it was temporary.',
    how: 'Replace the body with the real check, or delete the symbol and wire the caller to the real implementation. If it genuinely is a test double, move it under a test/mock path (or a *.mock.* file) so it cannot be imported by production code by accident.',
    exampleFix: 'export function verifyToken(token) { return jwt.verify(token, publicKey); }',
  },
  match: (ctx) => mockSecurityLeftovers(ctx),
};

export const aiSupplyChainRules: RuleDefinition[] = [hallucinatedDependency, mockSecurityLeftover];
