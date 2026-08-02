// VG-SMELL-021 — High Fan-out Security Module (implementation plan §5.4, the
// "依存グラフ" arm; appendix B lists it in the 0.3.0-β cross-file block).
//
// WHAT IT CLAIMS
//
// One module decides security — it hashes passwords, verifies tokens, or answers
// "may this subject do this" — and that module reaches out to a large share of
// the rest of the project to do it. Every one of those outgoing edges is a
// module whose behaviour the security decision now rests on: change the config
// loader, the cache, the user repository or the feature-flag service, and you
// have changed what the guard says without editing the guard. Two concrete
// consequences follow, and they are the two the plan names:
//
//  - ATTACK SURFACE. Reaching the security decision no longer requires reaching
//    the security module. Anything the security module imports is upstream of
//    it, so compromising, mocking, or merely misconfiguring any of them lands
//    inside the decision.
//  - INITIALISATION ORDER. A module with many dependencies has many things that
//    must already be ready when it runs. Security code is the code most likely
//    to run FIRST (a guard runs before the handler; a crypto init runs before
//    the subsystem), which is exactly when the fewest of its dependencies are
//    initialised. VG-AISC-003 in this same directory is the acute version of
//    that failure; this is the chronic one.
//
// WHY IT CANNOT BE A SINGLE-FILE RULE
//
// Fan-out is not a property of a file's text. `import { getUser } from
// '../repo/user'` looks identical whether it names a project module or a
// published package, and only the project's own file set decides which — the
// resolution that `dependency-graph-builder` performs. A single-file rule
// counting `import` lines would count `express`, `react` and `node:crypto` as
// fan-out and report a two-file project as a hub. The number this rule
// thresholds on exists only after the graph is built.
//
// ★ THE NUMBER COMES FROM `metrics-calculator`, NOT FROM HERE
//
// `fanMetrics` in `../metrics/index.js` is the one definition of fan-in and
// fan-out in this package, and it is called rather than reimplemented even
// though "count the resolved import edges" is three lines. VG-SMELL-010 already
// puts `fanIn` on its findings through the same function and its comment names
// this rule as the reason: two rules counting privately is how one report ends
// up carrying two different numbers both called `fanOut`. The threshold argument
// below is only meaningful if the quantity being thresholded is the quantity the
// finding reports.
//
// A consequence worth stating because it bounds what this rule can ever see:
// `fanMetrics` counts edges the graph RESOLVED, which means project-internal
// modules only. A security module that imports fifteen npm packages and no local
// file has fan-out 0 here. That is the right unit for this smell — the claim is
// about coupling to the project's own moving parts — but it is not the same
// quantity as "number of import statements", and nothing below should be read as
// if it were.
//
// ★★ WHAT "SECURITY MODULE" MEANS, AND THE MEASUREMENT THAT DECIDED IT
//
// The obvious definition is the cheap one: a file whose PATH carries a security
// word (`auth/`, `permissions/`, `crypto/`, `login/`). It was measured before it
// was written, over the first 169 repositories of `paper_data/corpus1k` that
// yielded TS/JS sources (16,641 files):
//
//   files with a security path word                  623   (3.74%)
//   of those, fan-out ≥ 8                             25
//
// The twelve highest of those 25 were listed and read (the remaining thirteen,
// at fan-out 8 and 9, were not — so this is a statement about the top of the
// distribution and is written as one):
//
//   28  Gitlawb__openclaude/src/components/permissions/PermissionRequest.tsx
//   21  …/src/components/permissions/rules/PermissionRuleList.tsx
//   18  …/src/components/permissions/BashPermissionRequest/…
//   16  …/src/components/permissions/ExitPlanModePermissionRequest/…
//   15  …/src/components/tasks/RemoteSessionDetailDialog.tsx
//   14  …/src/components/ConsoleOAuthFlow.tsx
//   13  …/src/components/permissions/FilePermissionDialog/FilePermissionDialog.tsx
//   13  …/src/components/permissions/rules/AddWorkspaceDirectory.tsx
//   12  …/src/components/permissions/AskUserQuestionPermissionRequest/…      (×2)
//   10  …/src/components/permissions/AskUserQuestionPermissionRequest/QuestionView.tsx
//   10  …/src/components/permissions/MonitorPermissionRequest/…test.tsx
//
// Every one of them is a REACT COMPONENT. They are dialogs and forms that talk
// ABOUT permissions; not one of them decides anything.
// Their fan-out is high because a React screen imports its child components, and
// a rule built on the path word would have reported the whole permissions/
// directory of a UI as a concentration of security responsibility. That is the
// same class of mistake the previous wave shipped and had to withdraw, and it is
// avoidable here for free, because the question "does this module decide
// security" has a behavioural answer.
//
// So the path word does not admit anything. Membership is decided by what the
// module DOES — a call into a cryptographic primitive, a token verification, a
// password comparison, or a privilege decision, from the closed vocabularies
// below — and the path word survives only as a CONFIDENCE signal, where a
// mistaken one costs a band rather than a finding.
//
// ★ WHY `project.symbols.guards` IS NOT THE MEMBERSHIP TEST EITHER
//
// It would be the natural thing to reach for and it is deliberately not used.
// `buildSymbolTable` admits a guard when a name is `usedAsMiddleware ||
// isGuardShapedName(name) || (exported && securityPath)`, and its own comment
// explains that the over-admission is intentional: `guards` is consumed as
// EXCULPATORY evidence elsewhere (VG-SMELL-010 fires when guards are missing), so
// admitting too many costs a missed finding there. Consumed as INCULPATORY
// evidence here the same looseness costs a false positive — every exported symbol
// in `src/middleware/logging.ts` is a "guard" by that third clause. Evidence that
// is safe to over-admit in one direction is not safe to reuse in the other, and
// this is the file where that would have gone wrong.

import type { Confidence, Severity } from '@vibeguard/findings-schema';
import { DESIGN_SMELL_CATEGORY } from '@vibeguard/findings-schema';
import { fanMetrics, fileMetrics, mergeMetrics } from '../metrics/index.js';
import type {
  CodeLocation,
  CrossFileFinding,
  CrossFileRule,
  CrossFileRuleContext,
  ProjectIndex,
  SourceFile,
  StructureIndex,
} from '../types.js';

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/**
 * Absolute floor on fan-out.
 *
 * ★ MEASURED, over the same 16,641 TS/JS files of `paper_data/corpus1k` used
 * above. The fan-out distribution of a real corpus is extremely skewed:
 *
 *   p50  0     p75  1     p90  3     p95  5     p99 11     p99.9 26     max 129
 *
 *   ≥ 5   5.85%      ≥ 8   2.54%      ≥ 12  1.00%      ≥ 20  0.27%
 *
 * Eight sits at roughly the 97.5th percentile: high enough that the word "high"
 * in the rule's name is a description of the population rather than a wish, low
 * enough that a genuinely central auth module in a mid-sized service is not
 * required to be pathological before anyone is told. Five would have put the
 * rule in the top 6% of every file in every project, which for a rule that has
 * to survive being run on well-factored code is far too much room.
 *
 * The number is a floor and not the whole test. On its own it would report the
 * top of the distribution in large projects and nothing in small ones — a
 * ranking, not a judgement. The two conditions below make it a judgement.
 */
const MIN_FAN_OUT = 8;

/**
 * The module may depend on at most this share of the project.
 *
 * ★ THE SMALL-PROJECT FLOOR, EXPRESSED AS A RATIO RATHER THAN AS A FILE COUNT.
 *
 * The failure this exists to prevent is stated in the task that commissioned the
 * rule and is worth writing out: a module with fan-out 8 in a nine-file project
 * is not a hub, it IS the project. Reporting "responsibility is concentrated
 * here" about a program with nowhere else to put it is a tautology dressed as a
 * finding.
 *
 * A flat `MIN_PROJECT_FILES = 24` would express the same intent for a fan-out of
 * exactly 8 and then stop working: a module with fan-out 20 in a 25-file project
 * would clear it, and that is the most extreme version of the very shape the
 * floor was written for. Tying the floor to the finding's own number keeps the
 * statement constant — a reported module always depends on at most a third of
 * the modules that exist — so the constant means one thing at every fan-out
 * instead of meaning "eight is special".
 *
 * A third rather than a half or a quarter: at a half the claim "the rest of the
 * project is somewhere else" is barely true, and at a quarter the floor becomes
 * the binding constraint for every mid-sized service (a fan-out of 8 would
 * demand 32 modules, which is above the corpus median project of 25 TS/JS
 * files). A third leaves the absolute floor doing the work in the range where it
 * was calibrated and takes over only where it must.
 */
const MAX_PROJECT_SHARE_DENOMINATOR = 3;

/**
 * The module must be in the upper tail of ITS OWN project's fan-out.
 *
 * ★ WHY A RELATIVE CONDITION IS PRESENT AT ALL, AND WHY IT IS NOT THE ONLY ONE.
 *
 * The commissioning note suggested a threshold normalised by project size might
 * be better than a magic number. A purely relative threshold — "the top 1% of
 * this project's files" — was rejected, and the corpus says why: it fires in
 * EVERY project, including a ten-file project whose busiest module imports
 * three others, because some file is always in the top 1%. A rule whose firing
 * condition is "be the maximum" reports one finding per repository by
 * construction and measures nothing.
 *
 * What a relative condition genuinely buys is protection against HOUSE STYLE. In
 * a heavily layered application where the ordinary module imports a dozen
 * others, a security module with fan-out 10 is unremarkable and reporting it
 * would be reporting the architecture rather than a smell. So the relative test
 * is used as an additional necessary condition rather than as a replacement:
 * the module's fan-out must be strictly greater than the project's own 90th
 * percentile. In the common project — where p90 is 3 — the condition costs
 * nothing and the absolute floor decides; in the layered project it is what
 * keeps the rule quiet.
 *
 * Strictly greater, not ≥: with a percentile taken from a small sample the value
 * is frequently a tie, and `≥` would admit a module that merely equals the
 * tenth-busiest file in its project. The point of the condition is to be an
 * outlier, and equalling the boundary is the opposite of that.
 */
const PROJECT_TAIL_PERCENTILE = 0.9;

/**
 * Minimum number of security operations before the module is a security module.
 *
 * Two, not one. A single `createHmac` in a webhook receiver, or one privilege
 * comparison in a service that mostly does something else, is a module that
 * touches security once — and this rule's claim is that security
 * RESPONSIBILITY is concentrated here, which one call does not establish. Two
 * occurrences is a low bar deliberately: it is meant to exclude the incidental
 * case, not to demand that the module be exclusively about security, and the
 * fan-out conditions above are what make the finding rare.
 *
 * Occurrences, not distinct families. Requiring two FAMILIES (crypto and
 * authorization, say) was the first draft and was dropped: a password-reset
 * module that only ever hashes, and an RBAC module that only ever compares
 * privileges, are both squarely the thing this rule is about, and a
 * two-family requirement would have excluded the purest examples while admitting
 * a module that did one of each by accident.
 */
const MIN_SECURITY_OPERATIONS = 2;

// ---------------------------------------------------------------------------
// What counts as a security operation
// ---------------------------------------------------------------------------

/**
 * The four kinds of evidence, named because the finding reports which one fired.
 *
 * A reader who disagrees with a finding needs to know whether the tool thinks
 * this is a security module because it verifies JWTs or because it compares a
 * `role` property; those are refuted by different arguments.
 */
type OperationFamily = 'crypto' | 'authentication' | 'token' | 'authorization';

interface SecurityOperation {
  family: OperationFamily;
  line: number;
  /** Source text of the operation, trimmed, for the finding's evidence. */
  evidence: string;
}

/**
 * Method names whose call IS a cryptographic operation, whatever the receiver.
 *
 * A closed list of names that have no non-cryptographic meaning. The three
 * obvious additions are refused, and each of them for a measured reason rather
 * than a stylistic one:
 *
 *  - `createHash` — the single most common non-security use of `node:crypto` in
 *    a web codebase. ETags, cache keys, content addresses, and deduplication all
 *    hash, and none of them are security. Admitting it would have made every
 *    build tool and static-site generator in the corpus a candidate.
 *  - `randomBytes` — identifiers, filenames, and test fixtures. The security use
 *    (a session id, a nonce) is indistinguishable from the rest at this layer.
 *  - bare `sign` / `verify` — `verify()` is what a mock, a form, and an assertion
 *    library are all called. They are reachable through the package-qualified
 *    arm below, where the import proves what is being signed.
 *
 * Losing them costs recall on modules whose ONLY security operation is a hash,
 * and this rule needs two operations anyway. Precision is the thing that cannot
 * be recovered later.
 */
const CRYPTO_METHOD: ReadonlySet<string> = new Set([
  'createCipheriv',
  'createDecipheriv',
  'createCipher',
  'createDecipher',
  'createHmac',
  'createSign',
  'createVerify',
  'publicEncrypt',
  'privateEncrypt',
  'publicDecrypt',
  'privateDecrypt',
  'timingSafeEqual',
  'pbkdf2',
  'pbkdf2Sync',
  'scrypt',
  'scryptSync',
  'hkdf',
  'hkdfSync',
  'generateKeyPair',
  'generateKeyPairSync',
  'diffieHellman',
  'encrypt',
  'decrypt',
  'deriveKey',
  'deriveBits',
  'unwrapKey',
  'wrapKey',
]);

/**
 * Packages whose bindings, when CALLED, are a security operation.
 *
 * The package import is what disambiguates a generic method name: `compare` is
 * meaningless on its own and unambiguous when the thing being called is the
 * default export of `bcrypt`. Both halves are required — an import with no call
 * is a re-export or a leftover, which is the shape a barrel file has and exactly
 * what must not be admitted here.
 *
 * Grouped by the family the finding will report, so a reader of the evidence
 * knows what kind of claim is being made.
 */
const SECURITY_PACKAGE: ReadonlyMap<string, OperationFamily> = new Map([
  // Password hashing and login frameworks — authentication.
  ['bcrypt', 'authentication'],
  ['bcryptjs', 'authentication'],
  ['@node-rs/bcrypt', 'authentication'],
  ['argon2', 'authentication'],
  ['@node-rs/argon2', 'authentication'],
  ['scrypt-kdf', 'authentication'],
  ['passport', 'authentication'],
  ['passport-local', 'authentication'],
  ['next-auth', 'authentication'],
  ['@auth/core', 'authentication'],
  ['lucia', 'authentication'],
  // Token issue / verification.
  ['jsonwebtoken', 'token'],
  ['jose', 'token'],
  ['jwt-decode', 'token'],
  ['express-jwt', 'token'],
  ['passport-jwt', 'token'],
  ['@nestjs/jwt', 'token'],
  ['fast-jwt', 'token'],
  // Cryptographic libraries.
  ['tweetnacl', 'crypto'],
  ['libsodium-wrappers', 'crypto'],
  ['sodium-native', 'crypto'],
  ['node-forge', 'crypto'],
  ['crypto-js', 'crypto'],
  ['@noble/hashes', 'crypto'],
  ['@noble/ciphers', 'crypto'],
]);

/**
 * A receiver whose NAME says the call is about tokens.
 *
 * The residual token case: `jwtService.verify(...)` in a Nest project, where the
 * package import lives in the module definition and not in the file doing the
 * verifying. Word-matched against the tokenised receiver rather than substring
 * matched, for the reason spelled out at length on `pathWords` in
 * `scattered-authorization.ts` — `tokenizer.decode(...)` is an LLM tokeniser and
 * is not a token operation, and only word matching separates the two.
 */
const TOKEN_RECEIVER_WORD: ReadonlySet<string> = new Set(['jwt', 'jwts', 'token', 'tokens', 'bearer']);

/** Methods that, on a token-named receiver, are the operation. */
const TOKEN_METHOD: ReadonlySet<string> = new Set(['sign', 'verify', 'decode', 'issue', 'refresh', 'validate']);

/**
 * Properties whose comparison IS an authorization decision.
 *
 * ★ DELIBERATELY THE SAME VOCABULARY AS `AUTHZ_PROPERTY` IN
 * `scattered-authorization.ts`, AND DELIBERATELY NOT IMPORTED FROM IT.
 *
 * That constant is module-private, and exporting it to share it here would make
 * one rule's private heuristic into a surface the other rule can break by
 * editing — the same argument the metrics module already records for why it
 * duplicates `BRANCH_WORD` from `design-smells-single.ts` rather than widening
 * `@vibeguard/rules`' public API. The two uses are also not the same question:
 * VG-SMELL-010 asks whether a check is scattered across HANDLERS and this asks
 * whether a module makes decisions at all, so the sets are free to diverge —
 * and they now do, see `SUBJECT_WORD`.
 */
const AUTHZ_PROPERTY =
  '(?:role|roles|userRole|user_role|isAdmin|is_admin|isOwner|is_owner|isSuperuser|is_superuser|isRoot|permissions|permission|privileges|privilege|scopes|accessLevel|access_level)';

/**
 * Properties whose name is ambiguous enough to need the receiver to agree.
 *
 * Only bare `role` / `roles`. `userRole`, `isAdmin`, `permissions`, `scopes` and
 * the rest name the privilege in the property itself and are read wherever they
 * appear.
 */
const AMBIGUOUS_PROPERTY: ReadonlySet<string> = new Set(['role', 'roles']);

/**
 * Words that make a receiver a SUBJECT — something that represents a principal.
 *
 * ★★ MEASURED CORRECTION. This allowlist did not exist in the first draft, and
 * the first draft's run over `paper_data/corpus1k` (169 repositories with TS/JS
 * sources) produced three findings of which TWO were the same mistake:
 *
 *   ChatGPTNextWeb__NextChat  app/components/exporter.tsx
 *       m.role === "user"                        ×2
 *   ChromeDevTools__chrome-devtools-mcp  src/tools/input.ts
 *       child.role === 'option'
 *       aXNode.role === 'combobox'
 *
 * Neither file decides anything. The first compares a CHAT MESSAGE role — the
 * collision `scattered-authorization.ts` already documents, and its denylist of
 * chat literals did not catch this one because the literal was `"user"`, which
 * that file deliberately leaves out (`role !== 'user'` is a real authorization
 * check). The second compares an ARIA ACCESSIBILITY role: `option`, `combobox`,
 * `textbox`, `menuitem` are a third meaning of the same property name, and one
 * that appears in every browser-automation and component library there is.
 *
 * A denylist cannot win this. Chat roles, ARIA's seventy-odd roles, database
 * enum values and form field names are four separate vocabularies that all
 * spell themselves `role`, and adding them one at a time is a losing game that
 * the ARIA list alone would make unreadable. What all of them have in common is
 * the RECEIVER: a privilege check reads the role off something that stands for a
 * person. `m`, `child` and `aXNode` do not, and no chat message or accessibility
 * node ever will.
 *
 * So the test is inverted into an allowlist, matched against the tokenised
 * receiver so `currentUser`, `req.user` and `sessionUser` all pass without being
 * listed. VG-SMELL-010 makes the opposite call — it uses a receiver DENYLIST and
 * only when no literal is available, having measured that an unconditional
 * receiver test discarded `entry.role !== 'admin'` inside a `for (const entry of
 * users)` loop. The two rules diverge here on purpose and the reason is the
 * population: that rule has already established it is looking inside a
 * registered route handler before it reads a receiver at all, and this one has
 * established nothing — the receiver is the only context it has. The cost is the
 * same recall that rule was protecting: a genuine `entry.role !== 'admin'` in a
 * loop is not counted here. A module that only ever decides authorization that
 * way, twice, and imports eight things, is a false negative this rule accepts.
 */
const SUBJECT_WORD: ReadonlySet<string> = new Set([
  'user',
  'users',
  'account',
  'accounts',
  'member',
  'members',
  'actor',
  'subject',
  'principal',
  'caller',
  'requester',
  'requestor',
  'viewer',
  'profile',
  'session',
  'claims',
  'identity',
  'employee',
  'staff',
  'person',
  'customer',
  'owner',
  'token',
  'me',
]);

/**
 * A privilege comparison. Horizontal whitespace is bounded (`[^\S\r\n]{0,4}`)
 * and no quantifier is unbounded or nested, so the pattern is linear on any
 * input — the D3 three-second contract is satisfied by construction, which is
 * the standard this repository adopted after the A1 ReDoS work.
 */
const AUTHZ_COMPARISON = new RegExp(
  String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>${AUTHZ_PROPERTY})\b[^\S\r\n]{0,4}(?:===|!==|==|!=)`,
  'g',
);

/** A membership test over a privilege collection: `user.permissions.includes('x')`. */
const AUTHZ_MEMBERSHIP = new RegExp(
  String.raw`(?<recv>[\w$][\w$.]{0,40})\.(?<prop>permissions|roles|scopes|privileges)\b[^\S\r\n]{0,4}\.[^\S\r\n]{0,4}(?:includes|indexOf|has|contains|some)[^\S\r\n]{0,4}\(`,
  'g',
);

/**
 * Receivers that are the BROWSER's permission API, not a subject's privileges.
 *
 * ★ MEASURED. `odysseus-dev__odysseus/static/js/notes.js`, fan-out 9, was
 * reported on the strength of three of these:
 *
 *   if (Notification.permission === 'granted') return true;
 *   if (Notification.permission === 'denied') return false;
 *   if ('Notification' in window && Notification.permission === 'granted') {
 *
 * A fourth meaning of the word — after the privilege, the chat message and the
 * ARIA node. `Notification.permission` is whether the USER let the page show a
 * toast, which is not an authorization decision the page makes and not
 * something a reviewer can act on.
 *
 * A closed list of Web platform globals rather than another receiver allowlist:
 * `permissions` is legitimately read off many things a subject allowlist would
 * not contain (`role.permissions`, `apiKey.permissions`, `group.permissions`),
 * so requiring a subject here would cost far more than it does for bare `role`.
 * The set that must be excluded is small, fixed by a specification, and will not
 * grow the way an application's vocabulary does.
 *
 * Case-sensitive and matched whole, because these are global CONSTRUCTORS: a
 * local variable called `notification` is an application's own object and its
 * `permissions` field means what it says.
 */
const BROWSER_PERMISSION_GLOBAL: ReadonlySet<string> = new Set([
  'Notification',
  'navigator',
  'Notifications',
  'Permissions',
  'PermissionStatus',
  'PushManager',
  'Geolocation',
  'MediaDevices',
]);

/** Any `.name(` call. The name is looked up in a set rather than baked in. */
const METHOD_CALL = /(?<recv>[\w$][\w$.]{0,40})?\.[^\S\r\n]{0,4}(?<method>[A-Za-z_$][\w$]{0,40})[^\S\r\n]{0,4}\(/g;

/**
 * A FREE call — `createHmac(...)` with no receiver.
 *
 * Necessary because the idiomatic way to reach `node:crypto` is a named import
 * (`import { createCipheriv } from 'node:crypto'`), after which the primitive is
 * called with nothing in front of it and `METHOD_CALL` never sees it. The
 * lookbehind is what keeps the two patterns from both matching `crypto.
 * createHmac(` — a name preceded by a dot is a method and belongs to the other
 * pattern.
 *
 * Only `CRYPTO_METHOD` is consulted here. The token arm needs a receiver to
 * decide, by construction, and the package arm searches for its binding by name.
 */
const BARE_CALL = /(?<![\w$.])(?<name>[A-Za-z_$][\w$]{0,40})[^\S\r\n]{0,4}\(/g;

/**
 * A CALL to an imported binding: `hash(password)`, `jwt.verify(token)`.
 *
 * ★ MEASURED CORRECTION. The first version ended `[^\S\r\n]{0,4}[.(]` — "the
 * binding, then a dot or an open paren" — which reads a PROPERTY ACCESS as an
 * operation. Over `paper_data/corpus1k` that produced this evidence for
 * `whyour__qinglong/back/services/user.ts`:
 *
 *   back/services/user.ts:101 token: let token = jwt.sign({ data }, config.jwt.secret, {
 *   back/services/user.ts:101 token: let token = jwt.sign({ data }, config.jwt.secret, {
 *   back/services/user.ts:102 token: expiresIn: config.jwt.expiresIn || expiration,
 *
 * One real operation reported three times: `config.jwt.secret` and
 * `config.jwt.expiresIn` are configuration reads that happen to contain the
 * binding's name. The finding on that file survives the fix — it does sign
 * tokens — but two thirds of what it showed a reviewer was noise, and noise in
 * the evidence is how a reviewer learns to stop reading it.
 *
 * So the pattern requires a call: the binding immediately applied, or one method
 * on it applied. The lookbehind refuses a binding that is itself a property of
 * something else, which is what `config.jwt` was — a different `jwt` from the
 * imported one, and nothing this rule knows about.
 */
function bareCallPattern(name: string): RegExp {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(
    String.raw`(?<![\w$.])${escaped}\b[^\S\r\n]{0,4}(?:\(|\.[^\S\r\n]{0,4}[A-Za-z_$][\w$]{0,40}[^\S\r\n]{0,4}\()`,
    'g',
  );
}

/**
 * `new Something(...)` — a construction, not an operation.
 *
 * ★ MEASURED. `express-jwt` exports both the middleware factory and the
 * `UnauthorizedError` class, so a module that imports the package and throws its
 * error type was credited with a token operation per `throw new
 * UnauthorizedError(...)` — three of the five operations reported for
 * `whyour__qinglong/back/loaders/express.ts`. Raising an error the package
 * defines is not verifying a token; it is what a module does AFTER something
 * else verified one.
 */
const PRECEDED_BY_NEW = /\bnew[^\S\r\n]{1,4}$/;

/** Path segments whose contents are fixtures, not the service under review. */
const TEST_PATH =
  /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|fixtures?|mocks?|examples?|e2e|testdata|stories)(?:\/|$)|\.(?:test|spec|stories)\.[\w]+$/i;

/** Any character that cannot appear inside an identifier word. */
const NON_WORD_CHAR = /[^A-Za-z0-9]/;

/** The camelCase seam: a lowercase or digit immediately followed by a capital. */
const CAMEL_SEAM = /([a-z0-9])([A-Z])/g;

/**
 * Split a path or identifier into lowercase words.
 *
 * A second small implementation of the tokenisation argued for at length on
 * `pathWords` in `scattered-authorization.ts` and on `tokenize` in
 * `../symbol-table/index.ts`: word matching, never substring matching, so
 * `src/authors/` is not an auth directory and `tokenizer` is not a token. Both
 * of the existing ones are private to their modules; this is four lines, and
 * widening either surface to share them would be the more expensive change.
 *
 * Neither regex has a quantifier, so neither can backtrack.
 */
function words(text: string): string[] {
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
 * Path words that CORROBORATE the behavioural evidence.
 *
 * Not a membership test — see the header. This set decides `confidence`, where
 * being wrong costs a band rather than a finding, which is the only place a
 * signal that classified React dialogs as security modules is safe to use.
 */
const SECURITY_PATH_WORD: ReadonlySet<string> = new Set([
  'auth',
  'authn',
  'authz',
  'authentication',
  'authorization',
  'authorisation',
  'security',
  'guard',
  'guards',
  'policy',
  'policies',
  'permission',
  'permissions',
  'acl',
  'rbac',
  'crypto',
  'cryptography',
  'token',
  'tokens',
  'jwt',
  'session',
  'sessions',
  'credential',
  'credentials',
  'password',
  'passwords',
]);

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/** 1-based line of an offset in `text`. */
function lineOf(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i += 1) {
    if (text[i] === '\n') line += 1;
  }
  return line;
}

/** Trim the source text at an offset to something printable next to a path. */
function evidenceAt(content: string, offset: number): string {
  const lineStart = content.lastIndexOf('\n', offset) + 1;
  const lineEnd = content.indexOf('\n', offset);
  const end = lineEnd === -1 ? content.length : lineEnd;
  return content.slice(lineStart, Math.min(end, lineStart + 160)).replace(/\r$/, '').trim();
}

/**
 * Every security operation in one module.
 *
 * ★ EXPORTED for the tests, and for the same reason `collectScatteredAuthSites`
 * is: the membership half of this rule is the half that can be wrong, and a
 * negative fixture that asserts only "no findings" cannot tell "the rule saw a
 * security module and the fan-out conditions declined it" from "the rule never
 * recognised the security module at all". Every negative below states which one
 * it is by calling this.
 *
 * Scans the BLANKED copy, so a `bcrypt.compare` written in a comment or quoted
 * in a string is not evidence that this module hashes anything. Evidence text is
 * read from the ORIGINAL content at the same offset, which blanking's
 * length-preserving property makes valid.
 *
 * ★ ON THE `found.has(offset)` GUARD, WHICH A MUTATION SURVIVES.
 *
 * The accumulator is keyed by OFFSET, so removing the guard cannot change how
 * many operations are found — a second write to the same key overwrites rather
 * than appends. What it changes is the family LABEL when two arms match at the
 * same offset, and the guard makes that "the first arm wins" rather than "the
 * last one does". The arms that actually overlap agree: `jwt.verify(...)` is
 * recognised by the package arm and by the token-receiver arm, both as `token`,
 * and `user.permissions.includes(x)` is seen by the membership arm and by
 * `METHOD_CALL`, which does not record `includes` at all. Constructing a case
 * where the label differs takes a package whose family is one thing and whose
 * method name is in `CRYPTO_METHOD` — reachable in principle, not present in any
 * real API this vocabulary names. So the mutation is reported as surviving
 * rather than answered with a fixture invented to kill it; the guard stays
 * because "first evidence wins" is the behaviour the evidence strings describe.
 */
export function securityOperations(
  structure: StructureIndex,
  content: string,
): SecurityOperation[] {
  const blanked = structure.blanked;
  const found = new Map<number, SecurityOperation>();

  const record = (family: OperationFamily, offset: number): void => {
    if (found.has(offset)) return;
    found.set(offset, { family, line: lineOf(blanked, offset), evidence: evidenceAt(content, offset) });
  };

  // ── Bindings imported from a known security package. ───────────────────────
  //
  // The binding name is what is searched for, not the package name: `import jwt
  // from 'jsonwebtoken'` binds `jwt`, and it is `jwt.verify(...)` that appears in
  // the code. A bare import with no binding (`import 'passport'`) names nothing
  // and therefore contributes nothing, which is correct — a side-effect import
  // is not an operation.
  for (const edge of structure.imports) {
    const family = SECURITY_PACKAGE.get(edge.specifier);
    if (family === undefined) continue;
    for (const binding of edge.names) {
      if (binding.length === 0) continue;
      // The import statement itself mentions the binding, and an earlier draft
      // skipped the edge's own line to keep that mention from counting as a
      // call. The skip is gone: the pattern requires a `.` or `(` within four
      // spaces of the name, and no import syntax the indexer recognises puts
      // either there — `import jwt from`, `const jwt = require(`, `import {
      // hash } from` all continue with something else. The branch could
      // therefore never change a verdict, and in the one shape where it could
      // have — `import jwt from 'jsonwebtoken'; jwt.verify(t)` written on a
      // single line — it would have discarded a real operation.
      const pattern = bareCallPattern(binding);
      for (let m = pattern.exec(blanked); m; m = pattern.exec(blanked)) {
        if (!PRECEDED_BY_NEW.test(blanked.slice(Math.max(0, m.index - 8), m.index))) {
          record(family, m.index);
        }
        if (pattern.lastIndex === m.index) pattern.lastIndex += 1;
      }
    }
  }

  // ── Cryptographic primitives, and token calls on a token-named receiver. ───
  METHOD_CALL.lastIndex = 0;
  for (let m = METHOD_CALL.exec(blanked); m; m = METHOD_CALL.exec(blanked)) {
    const method = m.groups?.method ?? '';
    const receiver = (m.groups?.recv ?? '').split('.').pop() ?? '';
    if (CRYPTO_METHOD.has(method)) {
      record('crypto', m.index);
    } else if (TOKEN_METHOD.has(method) && words(receiver).some((w) => TOKEN_RECEIVER_WORD.has(w))) {
      record('token', m.index);
    }
    if (METHOD_CALL.lastIndex === m.index) METHOD_CALL.lastIndex += 1;
  }

  BARE_CALL.lastIndex = 0;
  for (let m = BARE_CALL.exec(blanked); m; m = BARE_CALL.exec(blanked)) {
    if (CRYPTO_METHOD.has(m.groups?.name ?? '')) record('crypto', m.index);
    if (BARE_CALL.lastIndex === m.index) BARE_CALL.lastIndex += 1;
  }

  // ── Authorization decisions. ───────────────────────────────────────────────
  AUTHZ_COMPARISON.lastIndex = 0;
  for (let m = AUTHZ_COMPARISON.exec(blanked); m; m = AUTHZ_COMPARISON.exec(blanked)) {
    const prop = m.groups?.prop ?? '';
    const receiver = (m.groups?.recv ?? '').split('.').pop() ?? '';
    // A bare `role` needs the receiver to be a subject. See `SUBJECT_WORD` for
    // the two corpus false positives that put this test here, and for why it is
    // an allowlist rather than the growing denylist it replaced.
    const readable =
      !AMBIGUOUS_PROPERTY.has(prop) || words(receiver).some((w) => SUBJECT_WORD.has(w));
    if (readable && !BROWSER_PERMISSION_GLOBAL.has(receiver)) record('authorization', m.index);
    if (AUTHZ_COMPARISON.lastIndex === m.index) AUTHZ_COMPARISON.lastIndex += 1;
  }

  AUTHZ_MEMBERSHIP.lastIndex = 0;
  for (let m = AUTHZ_MEMBERSHIP.exec(blanked); m; m = AUTHZ_MEMBERSHIP.exec(blanked)) {
    const receiver = (m.groups?.recv ?? '').split('.').pop() ?? '';
    if (!BROWSER_PERMISSION_GLOBAL.has(receiver)) record('authorization', m.index);
    if (AUTHZ_MEMBERSHIP.lastIndex === m.index) AUTHZ_MEMBERSHIP.lastIndex += 1;
  }

  return [...found.values()].sort((a, b) => a.line - b.line);
}

/**
 * ★ THE ROUTER BARREL, AND THE EXPLICIT EXCLUSION THAT WAS WRITTEN AND REMOVED.
 *
 * `routes/index.ts` doing nothing but `export * from './users'` twenty times has
 * the highest fan-out in many projects and is not a module in the sense this
 * rule means: it holds no logic, makes no decision, and its dependencies are its
 * contents rather than things it relies on. It must never be reported, and it is
 * the negative the commissioning note singled out.
 *
 * A first draft carried an `isAggregator(structure)` test — `symbols.length ===
 * 0`, i.e. a file that declares no function, method or class — on the reasoning
 * that "it happens not to match" and "we decided it must not match" are
 * different guarantees. It is deleted, and the reason is the one this wave was
 * told to take seriously: NO INPUT SEPARATES IT FROM THE MEMBERSHIP TEST. A file
 * with no declarations has no body for a security operation to sit in, so
 * `securityOperations` is empty for every barrel, and the only inputs the
 * deleted branch could have changed the verdict for are ones where a file with
 * zero declarations nevertheless performs two security operations at module
 * scope — which is a security config module, not a barrel, and suppressing it
 * would have been the wrong answer anyway.
 *
 * A branch no test can cover is a claim nobody checks. In a rule whose entire
 * risk is false positives that is worse than the redundancy it was there to
 * prevent, so the guarantee is carried by the fixture
 * (`smell-021-neg-router-barrel`) and by this note instead of by a line that
 * would always be green.
 */

/** The `p`-th percentile of a sorted numeric array, by nearest-rank. */
function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.floor(p * sorted.length));
  return sorted[index]!;
}

/**
 * The files this rule is willing to consider, in deterministic order.
 *
 * The population is also the denominator for both relative conditions, which is
 * why it is computed once and shared rather than being re-derived per candidate:
 * a project's "size" and a project's "fan-out distribution" must be measured
 * over the same set of files the candidates are drawn from, or the ratio and the
 * percentile are answers about different projects.
 *
 * Test paths are excluded from the population as well as from the candidates. A
 * repository with a large test tree would otherwise have its p90 dragged down by
 * files the rule can never report, making the outlier condition easier to clear
 * exactly where there is most noise.
 */
function population(project: ProjectIndex): StructureIndex[] {
  return [...project.structures.keys()]
    .sort()
    .map((key) => project.structures.get(key)!)
    .filter((s) => highFanoutSecurityModule.languages.includes(s.language))
    .filter((s) => !TEST_PATH.test(s.filePath));
}

function analyze(ctx: CrossFileRuleContext): CrossFileFinding[] {
  const { project } = ctx;
  const modules = population(project);

  // Nothing to say about a project with no modules of the right language. The
  // early return is not an optimisation: `percentile` over an empty array would
  // return 0 and make the outlier condition vacuous.
  if (modules.length === 0) return [];

  const fanOutOf = new Map<string, number>();
  for (const structure of modules) {
    fanOutOf.set(structure.filePath, fanMetrics(structure.filePath, project.graph).fanOut ?? 0);
  }
  const sortedFanOut = [...fanOutOf.values()].sort((a, b) => a - b);
  const tail = percentile(sortedFanOut, PROJECT_TAIL_PERCENTILE);

  const findings: CrossFileFinding[] = [];

  for (const structure of modules) {
    const filePath = structure.filePath;
    const fanOut = fanOutOf.get(filePath) ?? 0;

    // ── The three fan-out conditions. ──────────────────────────────────────
    if (fanOut < MIN_FAN_OUT) continue;
    if (fanOut * MAX_PROJECT_SHARE_DENOMINATOR > modules.length) continue;
    if (fanOut <= tail) continue;

    /**
     * ── The module must be one others use. ──────────────────────────────────
     *
     * Fan-IN of at least one, and the case it excludes is specific: the
     * application entry point. `server.ts` / `main.ts` wires everything
     * together, so it has the highest fan-out in the project by construction,
     * and it is also where `passport.use(...)` and the session configuration
     * are written — which is enough security operations to qualify. It is not a
     * security MODULE; it is the place modules are assembled, and telling
     * someone their entry point depends on many things is not a finding.
     *
     * Nothing importing a file is what distinguishes the two, and it is a fact
     * the graph already holds rather than another name heuristic.
     */
    if ((fanMetrics(filePath, project.graph).fanIn ?? 0) < 1) continue;

    const source: SourceFile | undefined = project.files.find((f) => f.filePath === filePath);
    if (source === undefined) continue;

    const operations = securityOperations(structure, source.content);
    if (operations.length < MIN_SECURITY_OPERATIONS) continue;

    const families = new Set(operations.map((o) => o.family));

    /**
     * Severity.
     *
     * `high` when the module ENFORCES — when it decides authorization or
     * verifies a token — and `medium` when its security work is cryptographic
     * or authentication machinery only. The difference is what the fan-out
     * costs: a dependency of an enforcement point sits inside the decision that
     * says yes or no, so changing it changes who gets in, whereas a dependency
     * of a password hasher sits next to a computation whose result is checked by
     * someone else.
     *
     * ★ MEASURED so the band is known to partition rather than saturate — the
     * failure `ROUTING_LAYER_TOKEN` in `scattered-authorization.ts` documents,
     * where a condition true of 95% of sites was detected and deliberately not
     * scored. Over the corpus1k run recorded at the foot of this file the split
     * is 2 high / 1 medium across three findings. THREE IS NOT A RATE and is not
     * offered as one; what the sample establishes is only that both bands are
     * reachable on real code, which is the property a saturating condition
     * lacks. The figure to watch is the same one that rule watches: if a larger
     * labelled corpus ever shows the medium band empty, the fix is to stop
     * treating `token` as enforcement — a module that only ISSUES tokens is
     * closer to the crypto case than to the guard case, and it is the entry that
     * would be doing the saturating.
     */
    const enforces = families.has('authorization') || families.has('token');
    const severity: Severity = enforces ? 'high' : 'medium';

    /**
     * Confidence.
     *
     * `medium` is the floor and the cap is `high`, reached only when the
     * behavioural evidence is corroborated by an INDEPENDENT kind of signal: the
     * module's path or its own name says security too. Two kinds of evidence
     * agreeing is a different statement from one kind of evidence appearing
     * twice, and it is the only thing this rule has that deserves to move the
     * band — the path word cannot promote a React dialog on its own, because a
     * React dialog never gets this far.
     *
     * The fan-out number itself is not evidence about confidence in either
     * direction: it is a fact read off the graph, not an inference, so a bigger
     * one does not make the classification more likely to be right.
     */
    const identity =
      words(filePath).some((w) => SECURITY_PATH_WORD.has(w)) ||
      structure.exportedNames.some((n) => words(n).some((w) => SECURITY_PATH_WORD.has(w)));
    const confidence: Confidence = identity ? 'high' : 'medium';

    // Dependencies, sorted, so the evidence list is stable between runs. The
    // graph stores them in a `Set` whose iteration order is insertion order —
    // which is scan order — and a finding whose evidence reorders itself is one
    // no baseline can track.
    const dependencies = [...(project.graph.importsOf.get(filePath) ?? [])].sort();

    const importLineOf = new Map<string, number>();
    for (const edge of structure.imports) {
      if (edge.resolvedFile === undefined) continue;
      const existing = importLineOf.get(edge.resolvedFile);
      if (existing === undefined || edge.line < existing) importLineOf.set(edge.resolvedFile, edge.line);
    }

    /**
     * The finding is anchored at the FIRST SECURITY OPERATION, not at the first
     * import.
     *
     * The import line is where the fan-out is, and it is the wrong place to
     * point: a reader who opens the file at `import { db } from '../db'` has
     * been shown the thing the rule is least uncertain about. What they need to
     * see to accept or reject the finding is the line that made this module a
     * SECURITY module, because that is the inference — the fan-out is a fact
     * read off the graph. Every dependency is in `relatedLocations` and in
     * `evidence` regardless, so nothing is lost by pointing somewhere useful.
     */
    const firstOperation = operations[0]!;
    const anchorLine = firstOperation.line;

    const dependencyLocations: CodeLocation[] = dependencies.map((dependency) => ({
      filePath,
      startLine: importLineOf.get(dependency) ?? anchorLine,
      evidence: `depends on ${dependency}`,
    }));
    const operationLocations: CodeLocation[] = operations.map((operation) => ({
      filePath,
      startLine: operation.line,
      evidence: `${operation.family}: ${operation.evidence}`,
    }));

    // `relatedLocations` must not repeat `primaryLocation` — the schema field's
    // contract, because `allDesignSmellLocations` concatenates the two and a
    // repeat would be counted twice. The primary IS the first operation, so it
    // is dropped from the related list rather than filtered by coincidence; any
    // dependency that happens to share the anchor line goes with it, and both
    // are still present in the flat `evidence` array.
    const related = [...operationLocations, ...dependencyLocations].filter(
      (location) => location.startLine !== anchorLine,
    );

    const familyList = [...families].sort().join(', ');

    findings.push({
      ruleId: 'VG-SMELL-021',
      title: 'High Fan-out Security Module',
      description:
        `\`${filePath}\` decides security — ${operations.length} operations here are ` +
        `${familyList} — and depends on ${fanOut} other modules of this project, more than ` +
        `${Math.round(PROJECT_TAIL_PERCENTILE * 100)}% of its files and ${MIN_FAN_OUT} or more in ` +
        `absolute terms. Every one of those ${fanOut} modules is upstream of the security ` +
        `decision: it can change what the decision says without the decision being edited, and ` +
        `it must already be initialised when the decision runs — which for security code is ` +
        `earlier than for anything else. The concentration is the finding; no single import here ` +
        `is wrong.`,
      severity,
      confidence,
      category: DESIGN_SMELL_CATEGORY,
      sourceEngine: 'core-rule',
      scope: 'module',
      filePath,
      startLine: anchorLine,
      evidence: [
        `${filePath} fan-out ${fanOut} (project p${Math.round(PROJECT_TAIL_PERCENTILE * 100)} ${tail}, ${modules.length} modules)`,
        ...operations.map((o) => `${filePath}:${o.line} ${o.family}: ${o.evidence}`),
        ...dependencies.map((d) => `${filePath} → ${d}`),
      ],
      primaryLocation: {
        filePath,
        startLine: anchorLine,
        evidence: `security module with fan-out ${fanOut}: ${firstOperation.family}`,
      },
      relatedLocations: related,
      /**
       * The finding's own threshold quantities, from the shared producers.
       *
       * `fanMetrics` supplies the number the rule thresholded on, so a reader
       * checking the verdict reads the same `fanOut` the decision used.
       * `fileMetrics` adds `loc`, `methodCount` and `importCount`, and the last
       * of those is the one worth having next to `fanOut`: `importCount` counts
       * every import statement including packages, `fanOut` counts only edges
       * that resolved inside the project, and a reader who does not see both
       * will assume the rule counted `express`.
       */
      metrics: mergeMetrics(fileMetrics(structure, source), fanMetrics(filePath, project.graph)),
      securityContext: {
        containsAuthLogic: families.has('authentication'),
        containsAuthorizationLogic: families.has('authorization'),
        containsCryptoLogic: families.has('crypto'),
        containsTokenLogic: families.has('token'),
      },
      tags: ['design-smell', 'cross-file', 'coupling'],
      remediation: {
        why:
          'A security decision that reaches into a large share of the project has that share ' +
          'inside its trust boundary. Each dependency can alter the outcome without the ' +
          'security code changing, and each one must be ready before the security code runs — ' +
          'which is early, because guards and key material come first.',
        how:
          'Invert the direction of the coupling: have this module accept what it needs as ' +
          'arguments or an injected interface, and let the modules that own the data call it. ' +
          'Anything it imports only to read configuration or look something up is a candidate ' +
          'for being passed in instead, which shrinks the set of modules that can change the ' +
          'decision to the ones that were asked to.',
        exampleFix:
          '// before: the guard reaches out for everything it needs\n' +
          "import { db } from '../db';\nimport { cache } from '../cache';\nimport { flags } from '../flags';\n" +
          'export async function requireRole(req, res, next) { /* … uses all three … */ }\n\n' +
          '// after: the guard is given what it needs and depends on nothing\n' +
          'export function requireRole(lookupRole) {\n' +
          '  return async (req, res, next) => { /* … uses lookupRole … */ };\n' +
          '}',
      },
    });
  }

  return findings;
}

/**
 * ★ WHY TypeScript/JavaScript ONLY, WHEN FAN-OUT IS LANGUAGE-NEUTRAL.
 *
 * The graph resolves Python imports and C `#include`s too, so the fan-out half
 * of this rule would work unchanged in both. The membership half would not: the
 * security-operation vocabulary above is a list of Node and browser APIs and npm
 * packages, and in a Python project it would match nothing at all. A rule that
 * cannot recognise a security module in a language will never fire in it — which
 * is silent failure, not conservatism, and it puts a language in the `languages`
 * list that the rule has no fixtures for and no ability to be quiet on
 * deliberately. `scattered-authorization.ts` records the same decision, made
 * after the same discovery, and this follows it rather than re-learning it.
 *
 * ★★ MEASURED ON REAL REPOSITORIES — `paper_data/corpus1k`, all 1,000
 * directories walked, 630 of which yielded source the graph admitted.
 *
 *   findings                       3
 *   repositories with a finding    3
 *   read at the source, TP/FP      3 TP / 0 FP
 *   severity                       2 high / 1 medium
 *   confidence                     1 high / 2 medium
 *
 * The three:
 *
 *   Dokploy__dokploy  packages/server/src/lib/auth.ts        fan-out 8 of 800
 *     `bcrypt.hashSync` / `bcrypt.compareSync`, reaching into the db, the
 *     schema, access-control, the auth secret, an audit log and a HubSpot
 *     tracking module. medium/high.
 *   docmost__docmost  …/core/workspace/services/workspace.service.ts  15 of 1319
 *     Owner/admin enforcement — "there must be at least one workspace owner",
 *     "an admin may not act on an owner" — inside a service coupled to fifteen
 *     modules. high/medium.
 *   whyour__qinglong  back/loaders/express.ts                fan-out 9 of 165
 *     The whole app's JWT verification, API-token check and OAuth-style scope
 *     enforcement written into the Express loader. high/medium.
 *
 * ★ AND THE FALSE NEGATIVE THE SAME RUN PRODUCED, recorded because a precision
 * figure quoted without one is half a measurement. `whyour__qinglong`'s
 * `back/services/user.ts` signs JWTs, has fan-out 8, and is NOT reported: after
 * the property-access fix on `bareCallPattern` it has exactly one security
 * operation, and `MIN_SECURITY_OPERATIONS` is two. It is a real security module
 * and the floor is what silenced it — the trade that floor exists to make,
 * paid here in a case where it was not worth paying. Two operations stays,
 * because the alternative measured worse: the same fix that cost this finding is
 * what removed two thirds of the evidence lines from the one above it.
 *
 * The four shapes earlier drafts reported and no longer do — React permission
 * dialogs, chat-message roles, ARIA roles and the browser's `Notification.
 * permission` — are each pinned by a test rather than by this note.
 */
export const highFanoutSecurityModule: CrossFileRule = {
  ruleId: 'VG-SMELL-021',
  name: 'High Fan-out Security Module',
  description:
    'A module that decides security depends on a large share of the project, putting every one ' +
    'of those modules upstream of the security decision and inside its initialisation order.',
  category: DESIGN_SMELL_CATEGORY,
  severity: 'medium',
  defaultConfidence: 'medium',
  languages: ['typescript', 'javascript'],
  cwe: ['CWE-1047', 'CWE-1120'],
  owasp: ['A04:2021 Insecure Design'],
  references: ['https://cwe.mitre.org/data/definitions/1047.html'],
  remediation: {
    why: 'Every module a security decision depends on can change that decision without being reviewed as security code.',
    how: 'Pass dependencies in rather than importing them, so the set of modules able to change the decision is the set that was asked to.',
  },
  analyze,
};
