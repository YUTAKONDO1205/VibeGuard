// vibeguard:disable-file VG-AUTH-002
// The doc comment below quotes `// TODO: implement real authorization` as the
// EXAMPLE of the weakened override this rule detects. VG-AUTH-002 reads that
// quotation as a real unimplemented auth check. One rule id, not a wildcard.
// VG-SMELL-030 — Refused Security Inheritance (design addendum §7, the
// "継承解析" row; appendix B lists it in the 0.3.0-β cross-file block alongside
// VG-SMELL-031).
//
// WHAT IT CLAIMS
//
// A base class in this project makes an access-control decision in a named
// method — `authorize`, `hasPermission`, `isAllowed` — and one subclass
// overrides that method with a body that is nothing but `return true`. The
// inherited decision has been replaced by the constant "yes". Every call site
// that holds the base type still believes a decision is being made; the
// subclass is where it stopped being made, and nothing at the call site says so.
//
// This is Martin's Refused Bequest applied to the one method where refusing the
// bequest is not a maintainability problem but an authorization bypass. It is
// also a shape AI code generation produces readily: asked to add a subclass, a
// model that cannot see what the base's `authorize` was checking will stub the
// override permissively so the code runs, and the stub then ships.
//
// WHY IT CANNOT BE A SINGLE-FILE RULE
//
// `authorize() { return true; }` in isolation is not a finding and must never
// be one. It is a finding only if (i) it OVERRIDES something, (ii) the thing it
// overrides actually decided something, and (iii) the rest of the family did
// not do the same. None of the three is visible in the file that contains the
// override. (i) needs the base's declaration, which is in another file; (ii)
// needs the base's body; (iii) needs every other subclass in the project. A
// single-file rule would be reduced to "a method called authorize returns true",
// which fires on `NullAuthorizer`, on test doubles, and on every deliberately
// open policy object ever written.
//
// ★★ THE "継承解析" CONTRADICTION, AND WHY IT IS NOT ONE
//
// The spec row for 030 asks for inheritance analysis, and this package has no
// AST parser and will not acquire one (see the header of `../types.ts`). The
// resolution is that 030 does not need TYPE analysis, it needs one EDGE, and
// the edge is lexical: `class S extends B` and `class S(B):` both name the base
// in the declaration head, which the structure indexer already reads into
// `IndexedSymbol.baseClasses` (0.3.0-β, added for this rule).
//
// What the lexical layer cannot do is resolve the name, and this rule's answer
// to that is SILENCE rather than a guess:
//
//  - a dotted base (`extends mod.Base`, `class V(base.Model)`) is not resolved,
//    because resolving it means following a namespace import, which is the
//    alias-following the indexer's header says it cannot do;
//  - a base imported from a package (`extends Controller` from `@nestjs/common`)
//    resolves to no project file, so the base's body is unreadable and there is
//    nothing to have refused;
//  - a base reached through an `export *` barrel resolves to the barrel, which
//    declares no class of that name, so it is unresolved too. That is the exact
//    shape VG-SMELL-052 shipped a false positive on, and here it fails closed.
//
// Every one of those is a MISS. A rule about a subclass neutering an inherited
// check has to be able to read the check, and a rule that guesses which class it
// is reading is worse than one that says nothing.
//
// ★★ WHY DIFFERENTIAL EVIDENCE IS REQUIRED, AND WHAT IT IS MEASURED AGAINST
//
// Conditions (a)-(c) — resolved base, security-role method, `return true`
// override — describe both a bypass and a perfectly ordinary design. A policy
// family whose default answer is permissive, or one written so that each
// subclass answers a constant, is not refusing anything: it is a table of
// constants that happens to be spelled with classes. Nothing in the SUBCLASS
// separates the two.
//
// What separates them is the FAMILY. If a sibling subclass overrides the same
// method with a real decision, then this project's convention for this method is
// that subclasses decide — and the one that returns `true` is the odd one out.
// If no sibling does, there is no convention to be the odd one out of. This is
// the same "compare against a sibling" construction VG-AISC-002 and VG-AISC-003
// use, for the same reason: an accusation that rests on one site is an
// accusation about a style, and an accusation that rests on the difference
// between two sites is an accusation about this site.
//
// ★★ MEASURED — `paper_data/corpus1k`, all 1000 repositories walked
//
// Two throwaway mining passes were run before a line of this rule was written
// (the second pass widened the vocabulary and dropped the inheritance
// requirement, to bound the population from above rather than from the shape
// this rule happens to look for):
//
//   security-role methods DECLARED INSIDE A CLASS, closed list, both spellings
//                                                              27  (16 repos)
//   of those, bodies that are `return true`                      0
//   base classes declaring one AND having >= 2 subclasses        2  (2 repos)
//   widened survey: a security-named method implemented by
//     >= 2 distinct classes of one repository                   11 families,
//                                                              26 implementations
//                                                               (9 repos, 0.9%)
//   of those 26 implementations, bodies that are `return true`   1
//
// The single `return true` in the entire corpus is
// `ashishps1__awesome-low-level-design/solutions/python/onlinestockbrokeragesystem/
// execution_strategy.py:26` — `MarketOrderStrategy.can_execute` returning True
// with the comment "Market orders can always execute". It is a STOCK ORDER
// strategy, not an access-control decision, and it is excluded here three times
// over: `can_execute` is not on the closed method list at all, its base is
// `@abstractmethod def can_execute(...): pass` which is the Template Method
// silence below, and the family carries no authorization vocabulary.
//
// ★★ AND THE RULE ITSELF, SWEPT OVER THE SAME 1000 REPOSITORIES
//
//   repositories walked                                        1000
//   with TS/JS/Python source the graph admitted                  602
//   inheritance edges the rule RESOLVED in-project             7,495
//   findings                                                       0
//   wall clock                                                  112 s
//
// The 7,495 is the number that makes the 0 worth quoting. A zero produced by a
// resolver that never resolved anything would be indistinguishable from a
// broken rule — the failure mode the "no empty stubs" doctrine in
// `design-smells-crossfile/index.ts` exists to prevent — and 041 and 052's
// zeroes are open to exactly that reading. Here the rule read seven and a half
// thousand real `extends` / base-list edges, classified both bodies on each one,
// and said nothing about any of them.
//
// So: THIS RULE REPORTS ZERO ON corpus1k, stated up front rather than presented
// as precision. What the sweep establishes is that the rule does not fire on a
// large body of real code, and that its resolution and classification arms both
// ran while it did not. It establishes NOTHING about recall, because the corpus
// contains no true positive either. The evidence that the rule detects anything
// at all is its fixtures.
//
// ★ THE COLLISIONS THE SAME MEASUREMENT FOUND, AND WHAT THEY CHANGED
//
// Of the 27 in-class declarations, four are the security vocabulary used for
// something that is not security:
//
//   yamadashy__repomix   website/server/src/utils/rateLimit.ts:16
//       RateLimiter.isAllowed          — a request-rate window
//   rohitg00__agentmemory  src/providers/circuit-breaker.ts:32
//       CircuitBreaker.isAllowed       — a failure-count breaker
//   algorithm-visualizer  src/components/Header/index.js:85
//       Header.hasPermission           — a React header component
//   vuejs__devtools-v6  packages/app-backend-api/src/api.ts:395
//       DevtoolsPluginApiInstance.hasPermission — a devtools plugin capability
//
// Two of eleven method names carry most of that: `isAllowed` and `canAccess`
// say nothing about WHO is being allowed. `authorize` has a second industry
// meaning that the corpus does not happen to contain but that is not hypothetical
// — `gateway.authorize(amount)` is a card authorization, and a `SandboxGateway`
// that always approves is a normal thing to write. So the four ambiguous names
// are marked `selfEvident: false` in `SECURITY_ROLE_METHOD` and require the
// FAMILY to carry authorization vocabulary (`familyNamesAuthorization`) before
// they are read as access control at all; the remaining seven are read on their
// own. That is a family-level test rather than a
// per-name denylist, because the collisions come from four unrelated
// vocabularies (rate limiting, circuit breaking, UI capabilities, payments) and
// enumerating them is the losing game `SUBJECT_WORD` in
// `high-fanout-security-module.ts` already documents losing.
//
// ★ WHAT "NO SENSITIVE SURFACE" DOES HERE: DOWN-WEIGHT, NOT EXCLUDE
//
// The commissioning note allowed either. Excluding a subclass that owns no
// mutating route and sits on no elevated path was rejected, for two reasons that
// point the same way. First, it would exclude the true positives and keep the
// wrong ones: the correct architecture puts the decision in a policy class that
// owns no route at all, so "has a mutating route" selects controllers — the
// subset where the smell is least likely to be the interesting one. Second, the
// false positive that test was aimed at is the vocabulary collision above, and
// that is answered at the FAMILY level by `familyNamesAuthorization`, where
// the evidence is about what the family IS rather than about what the subclass
// happens to sit next to. What survives is the severity band: `high` on an
// elevated path, `medium` otherwise, which is the down-weight and is pinned by
// `smell-030-python-policy` (medium) against `smell-030-admin-controller`
// (high).

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import {
  ELEVATED,
  isAuthnGuardName,
  isAuthzGuardName,
  isTestPath,
  pathWords,
} from './authz-lexicon.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  IndexedSymbol,
  ProjectIndex,
  StructureIndex,
} from '../types.js';

// ---------------------------------------------------------------------------
// The closed method list
// ---------------------------------------------------------------------------

/** Which kind of security work a method name names, for `securityContext`. */
type MethodFamily = 'authorization' | 'authentication' | 'token';

interface SecurityRoleMethod {
  /** TypeScript / JavaScript spelling. */
  readonly camel: string;
  /** Python spelling of the SAME name. Not a stem, not a variant — see below. */
  readonly snake: string;
  /**
   * Whether the name alone establishes that this family decides access.
   *
   * `false` means the family must carry authorization vocabulary somewhere else
   * before the name is believed. See the collision measurement in the header.
   */
  readonly selfEvident: boolean;
  readonly family: MethodFamily;
}

/**
 * The eleven names, and nothing else.
 *
 * ★ A CLOSED LIST, NOT A PATTERN. `/(?:check|has|can|is)[A-Z]\w*(Permission|
 * Access|Allowed)/` would be shorter and would admit `canAccessCache`,
 * `isAllowedCharacter`, `hasPermissionToRetry` and every other application's
 * private use of four extremely common English words. This rule's accusation is
 * that an inherited SECURITY decision was neutered; if the name is not one this
 * project is prepared to name in a list, the evidence that the method is a
 * security decision does not exist.
 *
 * ★ TWO SPELLINGS OF ONE NAME IS NOT STEMMING. `checkPermission` and
 * `check_permission` are the same identifier written in the case convention each
 * language mandates; a Python codebase cannot spell it the other way and remain
 * idiomatic. The list is still closed — `check_permissions_for` is absent from
 * both columns and stays absent. Which column applies is decided by the FILE's
 * language, never by trying both, so a JavaScript `check_permission` (which
 * would be a deliberate oddity) is not matched and neither is a Python
 * `checkPermission`.
 *
 * `authorize`, `authorise` and `authenticate` are identical in both columns
 * because they are single words; the duplication is kept rather than special-
 * cased so every row reads the same way.
 */
const SECURITY_ROLE_METHOD: readonly SecurityRoleMethod[] = [
  { camel: 'authorize', snake: 'authorize', selfEvident: false, family: 'authorization' },
  { camel: 'authorise', snake: 'authorise', selfEvident: false, family: 'authorization' },
  { camel: 'authenticate', snake: 'authenticate', selfEvident: true, family: 'authentication' },
  { camel: 'checkPermission', snake: 'check_permission', selfEvident: true, family: 'authorization' },
  { camel: 'checkPermissions', snake: 'check_permissions', selfEvident: true, family: 'authorization' },
  { camel: 'hasPermission', snake: 'has_permission', selfEvident: true, family: 'authorization' },
  { camel: 'canAccess', snake: 'can_access', selfEvident: false, family: 'authorization' },
  { camel: 'isAllowed', snake: 'is_allowed', selfEvident: false, family: 'authorization' },
  { camel: 'isAuthorized', snake: 'is_authorized', selfEvident: true, family: 'authorization' },
  { camel: 'verifyToken', snake: 'verify_token', selfEvident: true, family: 'token' },
  { camel: 'validateAccess', snake: 'validate_access', selfEvident: true, family: 'authorization' },
];

/**
 * Words that make a permissive subclass a DELIBERATE, NAMED idiom.
 *
 * ★ THE NULL OBJECT PATTERN IS NOT A REFUSAL, IT IS AN ANSWER.
 *
 * `class PublicPolicy extends Policy { canAccess() { return true; } }` is a
 * design in which the permissive case has been given a name, a file and a
 * type, so that every call site that selects it has said out loud which policy
 * it wants. That is the opposite of the smell: the smell is a decision that
 * disappeared without anyone deciding, and this is a decision that was made
 * explicit enough to be typed. Reporting it would be telling a team that the
 * clearest thing they wrote is the problem.
 *
 * Matched by whole word (`pathWords`) against the class name AND the file's
 * BASENAME, so `NoopAuthorizer`, `noop-authorizer.ts` and `AnonymousUser` all
 * land. The basename rather than the whole path deliberately: a directory
 * called `public/` is a static-asset tree and would silence anything under it.
 *
 * ★ THE KNOWN COST OF `open`, PAID ON PURPOSE. `pathWords` splits at the
 * camelCase seam, so `OpenAIAuthorizer` tokenises to `open` + `aiauthorizer`
 * and is silenced. That is a false negative on a real class name shape, and the
 * word stays because the commissioning list named it and because `OpenPolicy` /
 * `open-access-policy.ts` are the far more common spellings of the idiom this
 * set exists for.
 */
const NULL_OBJECT_WORD: ReadonlySet<string> = new Set([
  // Named by the commissioning note.
  'public',
  'anonymous',
  'guest',
  'open',
  'unauthenticated',
  'noop',
  'null',
  'dummy',
  // Same idiom, spellings the note did not enumerate. Each of these is a name
  // whose whole content is "this one deliberately does not decide"; none of
  // them is a word an application would use for a policy that DOES decide.
  'anon',
  'unauth',
  'noauth',
  'nop',
  'none',
  'fake',
  'stub',
  'mock',
  'sandbox',
  'always',
  'permissive',
  'unrestricted',
  'insecure',
  'everyone',
  'anyone',
  'bypass',
  'passthrough',
  'disabled',
]);

// ---------------------------------------------------------------------------
// Body classification
// ---------------------------------------------------------------------------

/**
 * What one method body IS, as far as this rule can tell lexically.
 *
 * ★ A TOTAL, NAMED CLASSIFICATION RATHER THAN A BOOLEAN, and that is what makes
 * the negative fixtures worth anything. `expect(findings).toEqual([])` cannot
 * tell "the rule saw the override and correctly judged it a delegation" from
 * "the rule never found the override at all" — the vacuous pass that
 * `high-fanout-security-module.test.ts` records this repository having had to
 * reject once. Every negative below asserts the SHAPE first and the silence
 * second, so a fixture that drifts stops testing what it was written for
 * loudly instead of quietly.
 */
export type OverrideShape =
  /** The subclass does not override the method at all. */
  | 'absent'
  /** Calls `super.m(...)` / `super().m(...)` / `Base.m(self, ...)`. */
  | 'delegates'
  /** Contains a `throw` / `raise`. */
  | 'throws'
  /** The whole body is `return true` (TS/JS) or `return True` (Python). */
  | 'permissive'
  /** The whole body returns a constant falsy value. */
  | 'falsy'
  /** The whole body is nothing, `pass`, or `...`. */
  | 'empty'
  /** Anything else — i.e. an actual implementation. */
  | 'other';

/**
 * Shapes that count as a sibling NOT neutering the method.
 *
 * ★ `falsy` AND `empty` ARE DELIBERATELY ABSENT, and they are absent for
 * different reasons.
 *
 * `empty` (a Python `pass`, a `...`) says nothing at all about whether this
 * family's convention is to decide. It is a stub. Counting a stub as evidence
 * that the siblings decide would let the rule fire on a family in which nobody
 * has implemented anything yet.
 *
 * `falsy` (`return False`) is a real answer and a fail-closed one, but a family
 * in which one sibling constantly denies and another constantly allows is a
 * TABLE OF CONSTANTS — the shape `NULL_OBJECT_WORD` exists for, only without
 * the naming discipline. Accepting `falsy` as differential evidence would make
 * the rule fire on exactly that shape whenever the permissive member happened
 * not to be named for it, which is the most likely false positive this rule has.
 * The corpus contains one of these families and it is correct code:
 * `getredash__redash/redash/models/users.py` — `User.has_access` computes,
 * `ApiUser.has_access` is `return False`, `AnonymousUser.permissions` is `[]`.
 * Both constant members are fail-closed, and a rule that read the constant
 * members as a convention would have had a live opinion about that file.
 */
const DIFFERENTIAL_SHAPE: ReadonlySet<OverrideShape> = new Set<OverrideShape>([
  'other',
  'delegates',
  'throws',
]);

/** `throw` (TS/JS) or `raise` (Python). No quantifier, so nothing to backtrack. */
const THROW_KEYWORD = /\b(?:throw|raise)\b/;

/** Escape a source-derived identifier for interpolation into a pattern. */
function escapeForPattern(name: string): string {
  return name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Collapse a body to a single space-separated statement string, WITHOUT a regex.
 *
 * The obvious spelling is `body.replace(/[\s;]+/g, ' ').trim()`, and it is not
 * used. A single character class with `+` is linear and would in fact be safe,
 * but the constraint this package works under is "every quantifier is bounded"
 * with no case-by-case exemptions, precisely so that nobody has to re-derive
 * whether a given quantifier is the dangerous kind — that re-derivation is what
 * produced the A1 findings. Cross-file rule regexes are also outside the
 * `sec-a1-catalog.mjs` census (it reads `packages/rules` only), so nothing would
 * catch a mistake here. One forward pass over the characters has no quantifier
 * at all, and the property is then true by construction rather than by argument.
 *
 * `;` is folded in with the whitespace so `return true;` and `return true`
 * produce the same string, which is the whole point: the comparison downstream
 * is against an exact, closed set of body texts.
 */
function flattenStatements(body: string): string {
  const out: string[] = [];
  let pendingSpace = false;
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ';') {
      pendingSpace = out.length > 0;
      continue;
    }
    if (pendingSpace) out.push(' ');
    pendingSpace = false;
    out.push(ch);
  }
  return out.join('');
}

/**
 * Remove the DELIMITERS of comments and docstrings, length-preservingly.
 *
 * ★★ WITHOUT THIS THE RULE MISSES ITS OWN HEADLINE CASE, AND THE REASON IS ONE
 * SENTENCE IN `matcher-utils.ts` THAT IS EASY TO READ PAST.
 *
 * `blankJsLiterals` and `blankPyLiterals` blank the INTERIOR of a comment or a
 * literal and keep the delimiters — the doc comment says so explicitly
 * ("delimiters kept"). So this body, which is the single most likely spelling of
 * this smell in generated code:
 *
 *   authorize(req) {
 *     // TODO: implement real authorization
 *     return true;
 *   }
 *
 * arrives from the blanked copy as `//` followed by spaces, a newline, and
 * `return true;` — and flattens to `// return true`, which is not the exact
 * text the classifier compares against. The rule would have been silent on
 * every permissive override that carried a comment, which is most of them.
 *
 * The Python case is worse, because it is not optional style: an idiomatic
 * override is a docstring and then the statement, and the docstring's `"""`
 * pairs survive blanking the same way. `"""""" return True` is not
 * `return True`, so the entire Python arm would have been blind to the
 * language's house style.
 *
 * ★ ONLY COMMENT AND DOCSTRING DELIMITERS, NOT QUOTES IN GENERAL. Stripping
 * every `"` too would be simpler and would misclassify `return "true"` — a
 * body that returns a truthy STRING — as `falsy`, because what survives is
 * `return` alone. The tag would be wrong even though the verdict (silence) is
 * right, and a classifier that is wrong in a way no test notices is how the
 * next rule inherits a bug.
 *
 * A character pass rather than a regex, for the same reason `flattenStatements`
 * is: no quantifier, nothing to bound, nothing to re-derive. The three JS
 * sequences — a double slash, a slash-star, and a star-slash, spelled out here
 * because writing the last one inside this comment would end it — are
 * unambiguous in code that has already been blanked: a double slash cannot be an
 * empty regex literal, and a star-slash cannot be multiplication followed by
 * division. Python's `#` and its triple quotes are unambiguous outright.
 */
function withoutCommentDelimiters(body: string, python: boolean): string {
  const out: string[] = [];
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i]!;
    const next = body[i + 1];
    if (python) {
      if (ch === '#') {
        out.push(' ');
        continue;
      }
      if ((ch === '"' || ch === "'") && next === ch && body[i + 2] === ch) {
        out.push(' ', ' ', ' ');
        i += 2;
        continue;
      }
      out.push(ch);
      continue;
    }
    if ((ch === '/' && (next === '/' || next === '*')) || (ch === '*' && next === '/')) {
      out.push(' ', ' ');
      i += 1;
      continue;
    }
    out.push(ch);
  }
  return out.join('');
}

/**
 * The text of a method body, from the BLANKED copy.
 *
 * Blanked, so a `return true` inside a comment or a string is not a body.
 *
 * The two backends hand back different spans and the difference is not
 * cosmetic. `extractBlockAfter` reports the block INCLUDING its braces, so a
 * TS/JS body arrives as `{ … }`; the Python indexer reports the lines after the
 * `def` head, so it arrives without delimiters. Stripping a matched outer pair
 * is what makes both readable by one classifier.
 */
function methodBodyText(structure: StructureIndex, method: IndexedSymbol): string {
  const raw = structure.blanked.slice(method.bodyStart, method.bodyEnd);
  const inner = raw.length >= 2 && raw.startsWith('{') && raw.endsWith('}') ? raw.slice(1, -1) : raw;
  return withoutCommentDelimiters(inner, structure.language === 'python');
}

/**
 * Whether a body hands the decision back to the base.
 *
 * Three spellings, because the languages spell it three ways: JavaScript's
 * `super.m(...)`, Python 3's `super().m(...)`, and Python's explicit
 * `Base.m(self, ...)` — the last of which needs the base's NAME, which is why
 * this takes one. Every quantifier is bounded and horizontal whitespace is
 * `[^\S\r\n]{0,4}`; the argument list in the Python `super(...)` form is capped
 * at 80 non-newline characters, which covers `super(Sub, self)` with room to
 * spare and refuses to scan a line-long expression.
 */
function delegatesToBase(
  body: string,
  methodName: string,
  baseClassName: string,
  python: boolean,
): boolean {
  const m = escapeForPattern(methodName);
  if (python) {
    const zeroArg = new RegExp(
      String.raw`\bsuper[^\S\r\n]{0,4}\([^)\n]{0,80}\)[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}${m}\b`,
    );
    const explicit = new RegExp(
      String.raw`\b${escapeForPattern(baseClassName)}[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}${m}[^\S\r\n]{0,4}\(`,
    );
    return zeroArg.test(body) || explicit.test(body);
  }
  return new RegExp(String.raw`\bsuper[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}${m}\b`).test(body);
}

/**
 * Bodies whose ENTIRE text is a permissive constant return.
 *
 * ★ LANGUAGE-SPECIFIC AND CASE-SENSITIVE, WHICH IS NOT PEDANTRY. `return True`
 * in a JavaScript file is a reference to an undeclared identifier `True` and
 * throws at runtime; it is a bug, but it is not the bug this rule is about, and
 * classifying it as "always allows" would be wrong about what the code does.
 * `return true` in Python is a `NameError` for the same reason. Each language
 * gets its own literal and neither gets the other's.
 */
const PERMISSIVE_BODY: Record<'js' | 'py', string> = {
  js: 'return true',
  py: 'return True',
};

/**
 * Bodies whose ENTIRE text is a constant FALSY return — i.e. fail-closed.
 *
 * A bare `return` is here because it yields `undefined` / `None`, which every
 * caller treating the result as a decision reads as "no". It is fail-closed by
 * accident rather than by intent, but the direction is what matters to a rule
 * about a check that stopped saying no.
 */
const FALSY_BODY: Record<'js' | 'py', ReadonlySet<string>> = {
  js: new Set(['return false', 'return null', 'return undefined', 'return 0', 'return']),
  py: new Set(['return False', 'return None', 'return 0', 'return']),
};

/** Bodies that are not an implementation at all. */
const EMPTY_BODY: ReadonlySet<string> = new Set(['', 'pass', '...']);

/**
 * Classify one method body.
 *
 * ★ EXPORTED FOR THE TESTS, for the reason `securityOperations` is exported
 * from `high-fanout-security-module.ts`: this is the half of the rule that can
 * be wrong, and a negative fixture that only asserts silence cannot say which
 * half produced it.
 *
 * ORDER IS PART OF THE MEANING. `delegates` is checked before `throws` because
 * a body that calls `super.authorize()` and throws when it says no is extending
 * the inherited decision, and "extends" is the more specific true statement
 * about it. `throws` is checked before the exact-text table because a body
 * containing a `throw` is never one of the table's entries anyway, and putting
 * the cheap total test first would only obscure that.
 */
export function classifyOverride(
  structure: StructureIndex,
  method: IndexedSymbol | undefined,
  methodName: string,
  baseClassName: string,
): OverrideShape {
  if (method === undefined) return 'absent';
  const python = structure.language === 'python';
  const dialect = python ? 'py' : 'js';
  const body = methodBodyText(structure, method);
  if (delegatesToBase(body, methodName, baseClassName, python)) return 'delegates';
  if (THROW_KEYWORD.test(body)) return 'throws';
  const flat = flattenStatements(body);
  if (EMPTY_BODY.has(flat)) return 'empty';
  if (flat === PERMISSIVE_BODY[dialect]) return 'permissive';
  if (FALSY_BODY[dialect].has(flat)) return 'falsy';
  return 'other';
}

// ---------------------------------------------------------------------------
// The inheritance edge
// ---------------------------------------------------------------------------

/** A subclass and the project-local base class its declaration named. */
export interface InheritanceEdge {
  subclass: IndexedSymbol;
  subclassStructure: StructureIndex;
  base: IndexedSymbol;
  baseStructure: StructureIndex;
  /** The base name exactly as the subclass wrote it. */
  baseName: string;
}

/** `filePath\0className`, the key both maps below are built on. */
function symbolKey(filePath: string, name: string): string {
  return `${filePath}\u0000${name}`;
}

/**
 * Classes declared in one file, first declaration winning.
 *
 * First rather than last, and rather than refusing on a duplicate: two classes
 * with the same name in one file is either a conditional definition or a lexical
 * artefact of the indexer having no scope, and in both cases the first one is
 * the file's own top-level declaration. Refusing outright would be quieter
 * still, but the shape is common enough in JavaScript (a class inside an `if`,
 * a class inside a factory) that it would cost real coverage for a case where
 * the two bodies are almost always the same code.
 */
function classesOf(structure: StructureIndex): Map<string, IndexedSymbol> {
  const out = new Map<string, IndexedSymbol>();
  for (const symbol of structure.symbols) {
    if (symbol.kind !== 'class') continue;
    if (!out.has(symbol.name)) out.set(symbol.name, symbol);
  }
  return out;
}

/**
 * Methods of one file keyed by `enclosingClass\0name`.
 *
 * `declaredKind` is consulted as well as `kind` because `linkRouteHandlers`
 * PROMOTES symbols to `route-handler` / `middleware` across files, and a class
 * method registered as middleware somewhere would otherwise stop being a method
 * here — silently, and only in projects that mount it, which is the worst
 * possible distribution for a bug.
 */
function methodsOf(structure: StructureIndex): Map<string, IndexedSymbol> {
  const out = new Map<string, IndexedSymbol>();
  for (const symbol of structure.symbols) {
    if (symbol.enclosingClass === undefined) continue;
    if (symbol.kind !== 'method' && symbol.declaredKind !== 'method') continue;
    const key = symbolKey(symbol.enclosingClass, symbol.name);
    if (!out.has(key)) out.set(key, symbol);
  }
  return out;
}

/**
 * The files this rule will look at, in deterministic order.
 *
 * Test paths are excluded from the POPULATION and not merely from the findings,
 * which has a consequence worth stating: a base class that only lives under
 * `__tests__/` resolves to nothing, so a production subclass of a test-only base
 * is silent rather than reported. That is the right direction — a base the
 * shipped code cannot import is not a bequest the shipped code refused — and it
 * is why the exclusion is here rather than at the emit site.
 */
function population(project: ProjectIndex): StructureIndex[] {
  return [...project.structures.keys()]
    .sort()
    .map((key) => project.structures.get(key)!)
    .filter((s) => refusedSecurityInheritance.languages.includes(s.language))
    .filter((s) => !isTestPath(s.filePath));
}

/**
 * Every `extends` / base-list edge whose base resolves to a class in this
 * project.
 *
 * ★ EXPORTED FOR THE TESTS. The negatives that turn on resolution — the
 * package base, the barrel base, the dotted base — have to be able to assert
 * that the EDGE is missing, because "no findings" is also what a fixture with a
 * typo in it produces.
 *
 * Resolution is import-first and same-file second, which is the same order and
 * the same reasoning as `definingFile` inside `linkRouteHandlers`: a name may be
 * declared in three files, and the one this file means is the one this file
 * imported. Matching project-wide by name would attribute the subclass to
 * whichever `Base` the iteration order reached first, and reading the wrong
 * base's body is how this rule would produce a confident wrong answer rather
 * than a quiet one.
 */
export function resolvedInheritanceEdges(project: ProjectIndex): InheritanceEdge[] {
  const structures = population(project);
  const byPath = new Map(structures.map((s) => [s.filePath, s]));
  const classIndex = new Map(structures.map((s) => [s.filePath, classesOf(s)]));

  const edges: InheritanceEdge[] = [];
  for (const structure of structures) {
    for (const symbol of structure.symbols) {
      if (symbol.kind !== 'class') continue;
      const bases = symbol.baseClasses;
      if (bases === undefined) continue;
      for (const baseName of bases) {
        // A dotted base names something reached through a namespace, and
        // following a namespace is alias resolution the indexer's own header
        // says it does not do. `Repo<Item>` never gets here — the indexer's
        // `base` group stops at `<` — so a generic base arrives already bare.
        if (baseName.includes('.')) continue;

        let base: IndexedSymbol | undefined;
        let baseStructure: StructureIndex | undefined;
        for (const edge of structure.imports) {
          if (edge.resolvedFile === undefined) continue;
          if (!edge.names.includes(baseName)) continue;
          const candidate = classIndex.get(edge.resolvedFile)?.get(baseName);
          if (candidate === undefined) continue;
          base = candidate;
          baseStructure = byPath.get(edge.resolvedFile);
          break;
        }
        if (base === undefined) {
          const local = classIndex.get(structure.filePath)?.get(baseName);
          // `!== symbol` guards the degenerate self-edge a duplicate class name
          // would otherwise produce; a class is not its own base.
          if (local !== undefined && local !== symbol) {
            base = local;
            baseStructure = structure;
          }
        }
        if (base === undefined || baseStructure === undefined) continue;

        // A JavaScript class cannot extend a Python one. The pair only ever
        // arises from a resolution accident, and the method-name spelling below
        // is chosen from ONE of the two languages, so a mixed pair would have
        // the rule reading the base with the subclass's conventions.
        if ((baseStructure.language === 'python') !== (structure.language === 'python')) continue;

        edges.push({
          subclass: symbol,
          subclassStructure: structure,
          base,
          baseStructure,
          baseName,
        });
      }
    }
  }
  return edges;
}

// ---------------------------------------------------------------------------
// Family-level tests
// ---------------------------------------------------------------------------

/**
 * Whether anything about the family says this is about access control.
 *
 * Consulted only for the four names in `NEEDS_FAMILY_CORROBORATION`. The four
 * texts asked are the base's class name, the base's path, the subclass's class
 * name and the subclass's path — the entire lexical context a rule with no
 * types has. `isAuthzGuardName` and `isAuthnGuardName` come from the shared
 * lexicon rather than from a private word list here, which is the whole reason
 * `authz-lexicon.ts` exists: VG-SMELL-041 shipped a false positive because its
 * private copy of this vocabulary had drifted wider than VG-SMELL-010's and
 * nobody could see the drift.
 *
 * Checked against the collisions the corpus produced: `.../utils/rateLimit.ts`
 * with `RateLimiter`, and `.../providers/circuit-breaker.ts` with
 * `CircuitBreaker`, tokenise to no word in either set, so both are refused. The
 * one real `can_access` in the corpus — `9001__copyparty/copyparty/authsrv.py`
 * — carries `authsrv`… which does NOT tokenise to `auth` (the seam splitter
 * produces the single word `authsrv`), so it would be refused too. That is a
 * false negative on a genuine access-control file and it is recorded rather
 * than fixed by adding `authsrv` to the lexicon: a shared vocabulary that grows
 * one repository's abbreviation at a time is the drift the lexicon exists to
 * prevent.
 */
function familyNamesAuthorization(edge: InheritanceEdge): boolean {
  const texts = [
    edge.base.name,
    edge.baseStructure.filePath,
    edge.subclass.name,
    edge.subclassStructure.filePath,
  ];
  for (const text of texts) {
    if (isAuthzGuardName(text) || isAuthnGuardName(text)) return true;
  }
  return false;
}

/** Whether the subclass is a named, deliberate permissive implementation. */
function isDeliberatelyPermissive(subclass: IndexedSymbol): boolean {
  const slash = subclass.filePath.lastIndexOf('/');
  const basename = slash === -1 ? subclass.filePath : subclass.filePath.slice(slash + 1);
  for (const word of [...pathWords(subclass.name), ...pathWords(basename)]) {
    if (NULL_OBJECT_WORD.has(word)) return true;
  }
  return false;
}

/**
 * Whether the subclass sits on an elevated-privilege path or carries an
 * elevated-privilege name.
 *
 * `ELEVATED` is applied per WORD rather than to the raw path, which is the
 * `pathWords` discipline the lexicon argues for at length: `\brooted\b` does not
 * match `root`, but a substring test over `src/rootReducer.ts` would. The regex
 * carries no `g` flag, so `test` is stateless and the shared constant is safe to
 * call in a loop.
 */
function isElevated(subclass: IndexedSymbol): boolean {
  for (const word of [...pathWords(subclass.filePath), ...pathWords(subclass.name)]) {
    if (ELEVATED.test(word)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
  const edges = resolvedInheritanceEdges(project);
  if (edges.length === 0) return [];

  const methodIndex = new Map<string, Map<string, IndexedSymbol>>();
  const methodsFor = (structure: StructureIndex): Map<string, IndexedSymbol> => {
    let cached = methodIndex.get(structure.filePath);
    if (cached === undefined) {
      cached = methodsOf(structure);
      methodIndex.set(structure.filePath, cached);
    }
    return cached;
  };

  // Group by BASE, because every condition after (a) is a statement about the
  // family rather than about one edge. The key includes the base's file: two
  // unrelated `Policy` classes in one project are two families, and merging them
  // would let a subclass of one supply the differential evidence for the other.
  const byBase = new Map<string, InheritanceEdge[]>();
  for (const edge of edges) {
    const key = symbolKey(edge.base.filePath, edge.base.name);
    const list = byBase.get(key);
    if (list === undefined) byBase.set(key, [edge]);
    else list.push(edge);
  }

  const findings: CrossFileFinding[] = [];

  for (const key of [...byBase.keys()].sort()) {
    const family = byBase.get(key)!;
    // Fewer than two subclasses cannot produce differential evidence, so the
    // whole family is skipped before any body is read. Not an optimisation —
    // it is condition (d) stated at the point where it is cheapest to be sure
    // of, and it means a one-subclass hierarchy is never even classified.
    if (family.length < 2) continue;

    const { base, baseStructure } = family[0]!;
    const python = baseStructure.language === 'python';
    const baseMethods = methodsFor(baseStructure);

    for (const spec of SECURITY_ROLE_METHOD) {
      const methodName = python ? spec.snake : spec.camel;
      const baseMethod = baseMethods.get(symbolKey(base.name, methodName));
      if (baseMethod === undefined) continue;

      /**
       * ★ THE BASE MUST ACTUALLY DECIDE SOMETHING. Four of the seven shapes are
       * refused here, and each refusal is a different smell that is NOT this
       * one:
       *
       *  - `throws`  — Template Method. A base whose body is `raise
       *    NotImplementedError` / `throw new Error('implement me')` is an
       *    abstract declaration wearing a body, and its subclasses are
       *    IMPLEMENTING rather than refusing. The commissioning note singled
       *    this out and the corpus agrees it is the common shape: the only
       *    `return true` override in 1000 repositories has exactly this base
       *    (`@abstractmethod def can_execute(...): pass`).
       *  - `empty`   — the same thing spelled `pass` / `...`, plus a TypeScript
       *    `abstract authorize(): boolean;` which has no body at all and
       *    therefore is not indexed as a method, so it never reaches here.
       *  - `permissive` — the base default is already `return true`. A subclass
       *    restating the default has removed nothing; it is redundant code, not
       *    a bypass.
       *  - `falsy`   — the base default is deny. A subclass returning `true` is
       *    OPTING IN to permission rather than removing a check, which is the
       *    fail-open direction of a table of constants and is handled by
       *    `NULL_OBJECT_WORD` and by the differential test, not by an
       *    accusation that something was refused.
       *  - `delegates` — a base that calls `super` is itself a subclass; the
       *    decision it makes is somewhere further up, and this rule can only
       *    read one level.
       *
       * So only `other` — a body this rule cannot reduce to a constant or a
       * delegation, i.e. an actual implementation — is a bequest that can be
       * refused.
       */
      if (classifyOverride(baseStructure, baseMethod, methodName, base.name) !== 'other') continue;

      // Classify every subclass once. The map is keyed by the subclass symbol
      // itself rather than by name, because two files may each declare a
      // `ReportPolicy` and both may extend this base.
      const shapes = new Map<IndexedSymbol, OverrideShape>();
      for (const edge of family) {
        const override = methodsFor(edge.subclassStructure).get(
          symbolKey(edge.subclass.name, methodName),
        );
        shapes.set(
          edge.subclass,
          classifyOverride(edge.subclassStructure, override, methodName, base.name),
        );
      }

      const differential = family.filter((e) => DIFFERENTIAL_SHAPE.has(shapes.get(e.subclass)!));

      // Deterministic report order: by the subclass's file, then by where in it
      // the class is declared. `family` is already in population order (paths
      // sorted, symbols in index order), so this sort is a re-statement rather
      // than a correction — kept explicit because the grouping above went
      // through a `Map` and nothing should have to reason about its iteration.
      const accused = family
        .filter((e) => shapes.get(e.subclass) === 'permissive')
        .sort((a, b) =>
          a.subclass.filePath === b.subclass.filePath
            ? a.subclass.startLine - b.subclass.startLine
            : a.subclass.filePath < b.subclass.filePath
              ? -1
              : 1,
        );

      for (const edge of accused) {
        // Differential evidence must come from a DIFFERENT subclass. Computed
        // per accused subclass rather than once for the family, because with two
        // permissive subclasses and one real one, each of the two is still the
        // odd one out — but with two subclasses total, one permissive and one
        // real, only the permissive one is.
        const witnesses = differential.filter((e) => e.subclass !== edge.subclass);
        if (witnesses.length === 0) continue;

        if (isDeliberatelyPermissive(edge.subclass)) continue;
        if (!spec.selfEvident && !familyNamesAuthorization(edge)) continue;

        const override = methodsFor(edge.subclassStructure).get(
          symbolKey(edge.subclass.name, methodName),
        )!;

        const severity: Severity = isElevated(edge.subclass) ? 'high' : 'medium';
        /**
         * ★ CONFIDENCE IS FIXED AT `medium` AND IS NOT COMPUTED.
         *
         * There is a tempting boost available — the family is bigger, more
         * siblings decide, the path says `auth` — and every one of those is a
         * restatement of a condition the finding already had to satisfy to
         * exist. Confidence built out of the firing conditions is not a second
         * opinion, it is the first one with a number on it, and
         * `scattered-authorization.ts` records the same trap under
         * `ROUTING_LAYER_TOKEN`. The evidence here is structural and lexical:
         * the rule cannot see that the base's body is a real check, only that
         * it is not a constant. `medium` is the honest ceiling for that, and it
         * is the same value for every finding because the rule knows the same
         * amount about every finding.
         */
        const confidence: Confidence = 'medium';

        const witnessLocations: CodeLocation[] = witnesses.map((w) => {
          const theirs = methodsFor(w.subclassStructure).get(
            symbolKey(w.subclass.name, methodName),
          );
          return {
            filePath: w.subclass.filePath,
            startLine: theirs?.startLine ?? w.subclass.startLine,
            evidence: `sibling ${w.subclass.name}.${methodName}() ${
              shapes.get(w.subclass) === 'delegates'
                ? 'calls super'
                : shapes.get(w.subclass) === 'throws'
                  ? 'can fail closed'
                  : 'makes a decision'
            }`,
          };
        });

        findings.push({
          ruleId: 'VG-SMELL-030',
          title: 'Refused Security Inheritance',
          description:
            `\`${edge.subclass.name}\` extends \`${base.name}\` and overrides its ` +
            `\`${methodName}()\` with a body whose only statement is a permissive constant. ` +
            `The inherited check in \`${base.name}\` at ` +
            `${base.filePath}:${baseMethod.startLine} is gone for this subclass, while ` +
            `${witnesses.length} other subclass${witnesses.length === 1 ? '' : 'es'} of the same ` +
            `base still decide${witnesses.length === 1 ? 's' : ''}. Callers holding a ` +
            `\`${base.name}\` cannot see which they have, so the decision disappears at the ` +
            `point where the type says it is still being made.`,
          severity,
          confidence,
          category: DESIGN_SMELL_CATEGORY,
          sourceEngine: 'core-rule',
          scope: 'class',
          filePath: edge.subclass.filePath,
          startLine: override.startLine,
          evidence: [
            `${edge.subclass.filePath}:${override.startLine} ${edge.subclass.name}.${methodName}() returns a permissive constant`,
            `${base.filePath}:${baseMethod.startLine} ${base.name}.${methodName}() is the inherited decision`,
            // The witness line is the OVERRIDE's, not the class declaration's,
            // and matches the `relatedLocations` entry below. A reader who
            // opens the file wants the body that decides; two different lines
            // for the same witness in the same finding is the kind of small
            // inconsistency that makes a reader stop trusting the evidence
            // block, which `bareCallPattern` in `high-fanout-security-module.ts`
            // already records paying for once.
            ...witnesses.map((w) => {
              const theirs = methodsFor(w.subclassStructure).get(
                symbolKey(w.subclass.name, methodName),
              );
              return `${w.subclass.filePath}:${theirs?.startLine ?? w.subclass.startLine} ${w.subclass.name} overrides ${methodName}() without neutering it`;
            }),
          ],
          primaryLocation: {
            filePath: edge.subclass.filePath,
            startLine: override.startLine,
            evidence: `${edge.subclass.name}.${methodName}() always allows`,
          },
          relatedLocations: [
            {
              filePath: base.filePath,
              startLine: baseMethod.startLine,
              evidence: `${base.name}.${methodName}() — the decision being overridden`,
            },
            ...witnessLocations,
          ].filter(
            (location) =>
              !(
                location.filePath === edge.subclass.filePath &&
                location.startLine === override.startLine
              ),
          ),
          securityContext: {
            containsAuthorizationLogic: spec.family === 'authorization',
            containsAuthLogic: spec.family === 'authentication' || spec.family === 'token',
            containsTokenLogic: spec.family === 'token',
          },
          tags: ['design-smell', 'cross-file', 'inheritance'],
          remediation: {
            why:
              'A subtype that answers a security question with a constant still satisfies the ' +
              'supertype, so every call site keeps compiling and keeps reading as if a check ' +
              'were happening. The check is gone only for the objects that happen to be of this ' +
              'subtype, which is the hardest kind of gap to notice in review and the easiest to ' +
              'reach in production.',
            how:
              'Decide what the subtype actually means. If it genuinely has no restriction, say ' +
              'so in the name and the placement — a `PublicPolicy` / `AnonymousUser` that a call ' +
              'site has to select on purpose is a decision, not a hole. If it does have a ' +
              'restriction, implement it, or call the inherited one and add to it with ' +
              `\`super.${methodName}(…)\`. If the base should not have been decidable at all, ` +
              'make it abstract so a missing override is a compile error rather than a silent yes.',
            exampleFix:
              '// before: the check is silently replaced by a constant\n' +
              'class ExportController extends BaseController {\n' +
              `  ${methodName}(req) { return true; }\n` +
              '}\n\n' +
              '// after: the inherited decision still runs, and this class adds to it\n' +
              'class ExportController extends BaseController {\n' +
              `  ${methodName}(req) {\n` +
              `    if (!super.${methodName}(req)) return false;\n` +
              "    return req.user.permissions.includes('export');\n" +
              '  }\n' +
              '}',
          },
        });
      }
    }
  }

  return findings;
}

/**
 * ★ WHY PYTHON IS IN `languages` HERE WHEN IT IS NOT IN VG-SMELL-021's.
 *
 * That rule excluded Python because its membership test is a list of Node and
 * npm APIs, so it could not have recognised a Python security module and would
 * have failed silently rather than conservatively. Nothing in this rule is
 * language-specific in that way: the evidence is an inheritance edge, a method
 * name and a constant return, and Python has all three — with its own spellings,
 * which `SECURITY_ROLE_METHOD` carries and which the fixtures exercise
 * (`smell-030-python-policy`, `smell-030-neg-python-pass`). The negative
 * conditions are likewise implemented per language rather than assumed away:
 * `super().m()` and `Base.m(self)` are both recognised, and Python's `pass` is
 * the one shape that had to be reasoned about rather than transliterated.
 *
 * ★ WHY `pass` IS NOT A FINDING, WHICH READS BACKWARDS UNTIL IT DOESN'T.
 *
 * `def authorize(self): pass` looks like the most complete refusal available —
 * the body is literally nothing. It is the opposite. A Python function that
 * falls off the end returns `None`, `None` is falsy, and every caller that does
 * `if policy.authorize(user):` therefore DENIES. The subclass has made the
 * check fail closed, which is the safe direction and is not what this rule
 * accuses anyone of. (It is very possibly a different bug — a stub nobody
 * finished — but "the author forgot to implement this" and "the author replaced
 * a decision with yes" are different findings with different fixes, and merging
 * them would make the message wrong for whichever one the reader has.) The
 * TypeScript analogue is `authorize() {}`, which returns `undefined` and is
 * treated identically.
 *
 * ★ KNOWN MISSES, stated because a rule this quiet should be honest about what
 * it cannot see rather than leave a reader assuming coverage:
 *
 *  - A class-property override — `authorize = () => true;` — is not indexed as
 *    a method by `JS_HEAD` (its assignment arm requires `const`/`let`/`var`), so
 *    it is invisible. It is a real spelling of this smell and it is not caught.
 *  - A Python one-line body — `def authorize(self): return True` — puts the
 *    statement on the `def` line, and the indexer's body span starts at the
 *    NEXT line, so the body reads as empty and classifies as `empty`. Silent.
 *  - `implements` is not collected into `baseClasses` at all (see `types.ts`),
 *    so a TypeScript interface with a security method and several implementing
 *    classes is out of scope. An interface has no body to refuse, so there is
 *    nothing for condition (b) to read — which is also, exactly, why
 *    VG-SMELL-031 was dropped rather than implemented; see the mining record in
 *    this wave's report.
 */
export const refusedSecurityInheritance: CrossFileRule = {
  ruleId: 'VG-SMELL-030',
  name: 'Refused Security Inheritance',
  description:
    'A subclass overrides an inherited access-control method with a body that always allows, ' +
    'while sibling subclasses of the same base still decide.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  languages: ['typescript', 'javascript', 'python'],
  cwe: ['CWE-863', 'CWE-1041'],
  owasp: ['A01:2021 Broken Access Control'],
  references: ['https://cwe.mitre.org/data/definitions/863.html'],
  remediation: {
    why: 'The supertype promises a decision the subtype no longer makes, and no call site can tell.',
    how: 'Implement the subtype`s own rule, extend the inherited one with `super`, or name the class for the permissive answer it is giving.',
  },
  analyze,
};
