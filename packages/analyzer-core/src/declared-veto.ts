import type { RuleMatch } from '@vibeguard/rules';

/**
 * The declared-package veto — §17z-b, the second half of the sentence "a
 * hallucinated dependency is a name that is a near miss of a popular package
 * AND IS NOT IN THE LOCKFILE".
 *
 * VG-AISC-001 currently implements only the first half, because `match()` is a
 * pure function of one file's text and a lockfile is a different file. This
 * module is the other half, placed where cross-file evidence is allowed to
 * live: the analyzer, which receives the evidence as data (`ScanRequest.
 * declaredPackages`) and never reads it itself.
 *
 * ── WHY THE EVIDENCE IS A LOCKFILE AND ONLY A LOCKFILE ────────────────────
 *
 * REJECTED: package.json / requirements.txt / pyproject.toml / Pipfile, i.e.
 * the manifests. They are the obvious source — they are small, easy to parse,
 * and they are what a human would look at — and they are the wrong one, for a
 * reason specific to the threat this rule is about. The finding says "a
 * generator invented this dependency". A generator that invents an import
 * routinely invents the manifest entry to go with it, in the same completion:
 * that is what "write me an app that does X" produces. Vetoing on the manifest
 * therefore deletes the finding in exactly the case the rule exists for — the
 * model wrote both halves of the lie and the lie is self-consistent.
 *
 * A lockfile cannot be produced that way. An entry in a lockfile carries a
 * RESOLVED version (and usually an integrity hash and a `resolved` URL), which
 * only exists because a package manager asked a registry for that name and the
 * registry answered. A manifest is a wish; a lockfile is a receipt. A
 * hallucinated name has no receipt: `npm install` / `pip install` fails on it
 * and the lockfile never gets the entry. That asymmetry — not convenience — is
 * why the veto reads one and not the other, and it is why the CLI-side reader
 * (apps/cli/src/declared-packages.ts) refuses to fall back to a manifest when
 * no lockfile is present.
 *
 * ── WHAT THIS VETO DOES *NOT* CLAIM ───────────────────────────────────────
 *
 * It does not claim the package is safe. Slopsquatting works by REGISTERING the
 * hallucinated name, and once a developer has run `npm install` on it the name
 * is in the registry, in the lockfile, and vetoed here. The veto is therefore
 * weakest precisely in the state where the attack has already landed. That is
 * accepted deliberately, because it is the honest scope of the claim being
 * refuted: VG-AISC-001 asserts "this name looks fabricated", and a resolved
 * lockfile entry disproves THAT, not "this dependency is trustworthy".
 * Detecting a malicious-but-real package is a different rule with a different
 * evidence source (registry age, download counts, install scripts), and
 * pretending this one covers it would be the overclaim.
 *
 * REJECTED: downgrading confidence instead of removing the finding. It reads as
 * the safer option and is not: a `low`-confidence supply-chain finding on every
 * legitimately-installed near-miss package (`psycopg`, `merge2`, `preact`,
 * `enquirer` — all confirmed real-world false positives) is the noise that gets
 * the whole rule switched off, which loses the true positives too. The finding
 * being refuted is not "quieter now", it is WRONG: its premise is that the name
 * does not resolve, and the lockfile is proof that it does.
 *
 * ── WHY THE ANALYZER AND NOT THE RULE ─────────────────────────────────────
 *
 * `match()` stays a pure function of `RuleContext`. Three properties depend on
 * that and all three would break if a rule read a lockfile: the four delivery
 * channels agree only because they share one pure matcher (E1); the browser and
 * editor channels have no filesystem to read from; and "zero egress / no I/O
 * inside a rule" is the property the no-network CI job asserts. Passing the
 * declared set in as DATA keeps every one of them: a channel that has no
 * lockfile (Chrome, a snippet scan) simply passes nothing and gets today's
 * behaviour, byte for byte.
 */

/**
 * The `RuleMatch.variables` key by which a match declares "my subject is a
 * PACKAGE NAME, and this is the name".
 *
 * THIS IS THE WHOLE COUPLING between the veto and the rules. Deliberately NOT a
 * list of rule IDs: a `ruleId === 'VG-AISC-001'` test would mean every future
 * supply-chain rule silently opts out of the veto until someone remembers to
 * extend a list in a different package, and the failure mode of forgetting is a
 * false positive nobody can explain from reading either file. The contract is
 * instead a data contract, stated once here and honoured by construction:
 *
 *   A rule whose match names a package MUST put that name, as written in the
 *   source, in `variables.package`. Any such match is vetoed when the scan
 *   request declares that package. A rule that does not set the key is never
 *   touched by this code.
 *
 * `variables` is otherwise free-form (a remediation-template interpolation bag),
 * so `package` is reserved by this contract and must not be used for anything
 * that is not a package name. As of 0.2.1 the only producer is VG-AISC-001;
 * `matcher-utils.runRegex` also copies named capture groups into `variables`,
 * so a future rule with a `(?<package>…)` group opts in automatically — which
 * is the intended behaviour, not an accident, and is why the name is checked in
 * this file's tests rather than left implicit.
 *
 * WHY THE VETO CANNOT RUN LATER: `variables` exists on `RuleMatch` and NOT on
 * `Finding` — the analyzer consumes it (remediation interpolation) and drops
 * it. Once a finding is assembled the package name is gone and only a regex
 * over the snippet could recover it. So the veto must run before finding
 * assembly, which is also where it belongs for the merge reason below.
 */
export const DECLARED_PACKAGE_VARIABLE = 'package';

/** One match that the declared-package veto removed. Observability only. */
export interface DeclaredPackageVeto {
  /** The rule whose match was dropped. */
  ruleId: string;
  /** The package name as written in the source. */
  packageName: string;
  /** The file the match was in, when the scan had one. */
  filePath?: string;
  /** 1-based line of the dropped match. */
  startLine: number;
}

/**
 * The declared set, indexed for lookup. Opaque by intent — callers build one
 * with `buildDeclaredPackageIndex` and ask with `declaredPackageOfMatch`.
 */
export interface DeclaredPackageIndex {
  /** Lowercased AND separator-stripped forms of every declared name. */
  readonly keys: ReadonlySet<string>;
  /** How many distinct names were declared. For reporting, not for logic. */
  readonly declaredCount: number;
}

/**
 * Separator- and case-insensitive package key.
 *
 * MIRRORS `normKey` in packages/rules/src/rules/ai-supply-chain.ts, which is
 * not exported and which the analyzer must not reach into anyway (the analyzer
 * depending on a rule's internals is the coupling this whole design avoids).
 * The duplication is accepted because a drift between the two FAILS OPEN: a key
 * that stops matching means the veto does not fire and the finding is reported,
 * which is the direction a security tool is allowed to be wrong in. The
 * duplication is pinned by a test rather than by this comment.
 *
 * Why the normalized form is compared at all, on top of the literal lowercase
 * one: PyPI names ARE separator- and case-insensitive by specification (PEP 503
 * normalizes `-`, `_` and `.` to one form), so `Flask_Cors` in a lockfile and
 * `flask-cors` in an import are the SAME package and a literal comparison would
 * miss it. npm is stricter — `body-parser` and `bodyparser` are two different
 * names there — so applying the normalized comparison uniformly is wider than
 * npm's own equality, and can veto an npm import that would genuinely fail to
 * resolve (`require('bodyparser')` in a project whose lockfile has
 * `body-parser`). That cost is accepted rather than split per-ecosystem: the
 * analyzer does not know which registry a name came from and should not learn,
 * and the over-vetoed case is a typo that fails loudly at `require()` time in
 * a project that already has the real package installed — not the silent
 * install-time compromise this rule exists to catch. REJECTED for that reason:
 * (a) literal-lowercase only, which breaks the veto on Python, the ecosystem
 * where slopsquatting is most measured; (b) an ecosystem switch inside the
 * analyzer, which would put registry-naming policy in the layer furthest from
 * the registry.
 */
function normKey(s: string): string {
  return s.toLowerCase().replace(/[-_.]/g, '');
}

/**
 * Cache of built indexes, keyed by the caller's array IDENTITY.
 *
 * `scanPath` hands the same `declaredPackages` array to `Analyzer.scan` once
 * per file; a lockfile of a few thousand entries would otherwise be re-indexed
 * for every file in the tree. A WeakMap keyed on the array means the work
 * happens once per array and the entry disappears with it — no lifetime to
 * manage, and a caller that builds a fresh array per call is merely slower,
 * never wrong. Not a Map: that would pin every array a long-lived Analyzer has
 * ever been handed.
 */
const INDEX_CACHE = new WeakMap<readonly string[], DeclaredPackageIndex>();

/**
 * Build (or reuse) the lookup index for a declared set.
 *
 * Returns `undefined` for both "not provided" and "provided but empty", because
 * the veto has nothing to do in either case and a callers's `if (index)` should
 * read as "is there anything to veto with". The two are NOT equivalent to the
 * caller — `undefined` means nobody looked for a lockfile, `[]` means one was
 * looked for and had nothing usable — but that distinction belongs in the
 * caller's reporting, not in this decision.
 *
 * Empty and whitespace-only entries are dropped. A blank name would normalize
 * to the empty string and then match any match whose package name also
 * normalized to empty — a nonsense veto born of a sloppy parser, which is the
 * one direction this feature is not allowed to fail in.
 */
export function buildDeclaredPackageIndex(
  names: readonly string[] | undefined,
): DeclaredPackageIndex | undefined {
  if (!names || names.length === 0) return undefined;
  const cached = INDEX_CACHE.get(names);
  if (cached) return cached;

  const keys = new Set<string>();
  let declaredCount = 0;
  for (const raw of names) {
    if (typeof raw !== 'string') continue;
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const lower = trimmed.toLowerCase();
    const norm = normKey(trimmed);
    if (!norm) continue; // e.g. "---": normalizes to empty, see above.
    declaredCount += 1;
    keys.add(lower);
    keys.add(norm);
  }
  if (keys.size === 0) return undefined;

  const index: DeclaredPackageIndex = { keys, declaredCount };
  INDEX_CACHE.set(names, index);
  return index;
}

/** True when `name` is one of the declared packages, modulo case/separators. */
export function isDeclaredPackage(index: DeclaredPackageIndex, name: string): boolean {
  const trimmed = name.trim();
  if (!trimmed) return false;
  return index.keys.has(trimmed.toLowerCase()) || index.keys.has(normKey(trimmed));
}

/**
 * The package name this match is about, when the scan declares that package —
 * i.e. the reason to veto it. `undefined` means keep the match, for either of
 * two different reasons (the match is not about a package at all, or it is
 * about one nobody declared) which the caller has no reason to tell apart.
 */
export function declaredPackageOfMatch(
  match: RuleMatch,
  index: DeclaredPackageIndex,
): string | undefined {
  const name = match.variables?.[DECLARED_PACKAGE_VARIABLE];
  if (!name) return undefined;
  return isDeclaredPackage(index, name) ? name : undefined;
}
