// vibeguard:disable-file VG-INJ-004 reason="eval-exec family mapping strings (eval-detected/eval-injection/user-eval check-id patterns and prose describing CWE-95) — not an executable eval() of untrusted input; identical self-scan exemption to scripts/sec-transfer-semgrep.mjs, whose table this file copies"
// The common weakness vocabulary three tools are compared in.
//
// ★★ THIS TABLE IS COPIED, NOT INVENTED, AND THE COPY IS THE POINT
//
// `scripts/sec-transfer-semgrep.mjs` already carries a mapping from VibeGuard
// rule ids to weakness families to Semgrep `check_id` regexes, and its header
// records how it was built: every pattern in it "was confirmed to match a
// check_id that Semgrep actually emitted on a known-vulnerable ORIGINAL in this
// corpus". That is an empirical artifact, produced by a Semgrep run that
// happened, on files that exist. `scripts/sec-transfer-codeql.mjs` carries the
// CodeQL half, and its header is equally explicit that it is NOT empirical:
// the query ids are "correct-by-construction from CodeQL's PUBLISHED query ids
// (github/codeql), NOT yet confirmed on this corpus".
//
// Writing a third vocabulary here would give this project two different answers
// to "what did Semgrep say about SQL injection", and the two would drift the
// first time either was edited. So the family names, the weakness prose, the
// VibeGuard rule assignments and the tool patterns below are TAKEN FROM those two
// scripts. Where this file departs from them, the departure is marked ★ and
// argued in place. There are exactly four such departures and they are all in
// the same direction — TIGHTER, never looser, because a loosened mapping
// manufactures agreement and a tightened one only loses coverage:
//
//   1. `/insecure-.*request`  -> `/insecure-[A-Za-z0-9_-]{0,40}request`
//   2. `/insecure-.*protocol` -> `/insecure-[A-Za-z0-9_-]{0,40}protocol`
//   3. the `app-run-param-config` pattern of the debug-enabled family is DROPPED.
//      It over-matches a CWE-668 rule in this package's own recorded fixture; the
//      evidence and the cost are written out at that entry.
//   4. every pattern is asserted quantifier-bounded by a test in this package.
//
// Departures 1 and 2 are the ReDoS rule that governs product code here (an
// unbounded `.*` beside another quantifier is the shape that produced this
// project's A1 findings; a research script that runs once on a fixed corpus is
// not under that constraint, and a parser that runs on user-supplied reports is).
// They also stop the wildcard crossing a `/` or a `.`, i.e. they stop it spanning
// rule-id path segments. That is a semantic narrowing, and the blast radius is
// stated honestly: a CodeQL rule id of the shape `js/insecure-foo/bar-request`
// would classify under sec-transfer-codeql.mjs and not here. No such id is known;
// none could be checked, because CodeQL is not installed on this machine.
//
// ★ WHY NOT KEY AGREEMENT ON CWE, WHICH BOTH TOOLS ALREADY EMIT
//
// This was the first design and it was measured against the real Semgrep bytes in
// src/fixtures/semgrep-samples-vulnerable.json before being dropped. CWE would be
// a far cheaper key — no table, no per-tool patterns, and both tools attach CWE
// ids to their rules. It fails on this corpus, in the one family where it matters
// most:
//
//   VibeGuard  VG-AUTH-006          session cookie missing Secure / HttpOnly
//                                   -> CWE-614 / CWE-1004
//   Semgrep    express-cookie-session-no-httponly, ...-no-secure
//                                   -> CWE-522 (Insufficiently Protected Credentials)
//
// Those are the same weakness at the same line of the same file, and no CWE-based
// join finds it: 614 and 1004 are children of a different branch of the CWE tree
// than 522. Keying on CWE would have reported VibeGuard and Semgrep as
// disagreeing about `samples/vulnerable/express_session.js:14` when they agree
// exactly. The hand-built family table has this pair mapped because a human
// looked at both outputs — which is the whole reason it is worth its maintenance
// cost. CWE ids are still carried on every finding (`ExternalFinding.cweIds`), so
// a reader can see the divergence rather than take this paragraph on trust; they
// are simply not the join key.
//
// ★ THE MAPPING IS PARTIAL AND THE PARTIALNESS IS LOAD-BEARING
//
// Nine families. Nine VibeGuard rules out of the several dozen VibeGuard ships.
// MEASURED on the real Semgrep fixture in this package (20 recorded results from
// Semgrep 1.165.0 over samples/vulnerable): 11 classify, 9 do not.
//
//   classified   cookie-session-flags 2, injection-sql 2, weak-crypto 2,
//                debug-enabled 1, eval-exec 1, injection-shell 1,
//                insecure-transport 1, tls-verification-disabled 1
//   unmapped     no-csrf-exempt, express-check-csurf-middleware-usage,
//                express-cookie-session-default-name / -no-domain / -no-expires /
//                -no-path, express-session-hardcoded-secret,
//                avoid_app_run_with_bad_host, math-random-used
//
// 45% unmapped on a corpus the Semgrep half of this table was DERIVED from. The
// coverage on arbitrary code will be worse, not better, and nothing here should
// be read as if the mapping were near-complete.
//
// The consequence is stated here so no consumer has to infer it: an unmapped
// finding cannot be corroborated, cannot be contradicted, and must never be
// rendered as "only one tool found this". `EnsembleResult.mappingCoverage`
// reports the ratio on every run, and `Agreement.unclassified` is the label.

/**
 * The closed vocabulary. Names are verbatim from the `family` fields of
 * `RULE_FAMILIES` in scripts/sec-transfer-semgrep.mjs — a rename here would
 * silently unlink this table from the artifact it was derived from.
 */
export type WeaknessClass =
  | 'eval-exec'
  | 'weak-crypto'
  | 'injection-sql'
  | 'injection-shell'
  | 'unsafe-deserialization'
  | 'tls-verification-disabled'
  | 'debug-enabled'
  | 'cookie-session-flags'
  | 'insecure-transport';

/**
 * One weakness family: what it is, and which tool's rules detect it.
 *
 * `semgrepPatterns` / `codeqlPatterns` being EMPTY is meaningful and is not the
 * same as the family being absent. Empty means "this tool ships no detector we
 * have mapped for this weakness", which is what makes
 * `MergedFinding.silentTools` honest: a tool with no detector is never counted as
 * having stayed silent.
 */
export interface WeaknessFamily {
  readonly weaknessClass: WeaknessClass;
  /** CWE prose, verbatim from the source scripts, so the two read identically. */
  readonly weakness: string;
  readonly vibeguardRules: readonly string[];
  readonly semgrepPatterns: readonly RegExp[];
  readonly codeqlPatterns: readonly RegExp[];
  /**
   * Whether the Semgrep patterns were confirmed against check_ids a Semgrep run
   * actually emitted (sec-transfer-semgrep.mjs's derivation) — true for every
   * family it maps.
   */
  readonly semgrepEmpiricallyConfirmed: boolean;
  /**
   * Always false. sec-transfer-codeql.mjs marks every one of its entries
   * `empiricallyConfirmed:false`, and nothing in THIS repository has ever run
   * CodeQL, so the flag cannot become true here. It is a `false` literal rather
   * than a boolean so that a future edit claiming confirmation has to change the
   * type and justify itself.
   */
  readonly codeqlEmpiricallyConfirmed: false;
  readonly note: string;
}

/**
 * ★ THE TABLE.
 *
 * Reading order for each entry: family name and weakness prose from
 * sec-transfer-semgrep.mjs; `vibeguardRules` from the same (identical to
 * sec-transfer-bandit.mjs where they overlap, by that script's own design, so
 * all three external arms score the same VibeGuard side); `semgrepPatterns` from
 * sec-transfer-semgrep.mjs verbatim; `codeqlPatterns` from
 * sec-transfer-codeql.mjs, bounded per the header.
 *
 * The `languages` field of the source tables is NOT reproduced. It exists there
 * to keep an evasion-rate denominator honest ("Semgrep p/default fires no
 * weak-hash rule on C#, so scoring C# would measure the rule catalog, not the
 * transform"). Here the denominators are different — the merger never divides by
 * a per-language count — and carrying a field nobody reads is how a copied table
 * starts to drift from its original. Consumers who need the language scope must
 * read it from the source scripts, which remain the artifact of record.
 */
export const WEAKNESS_FAMILIES: readonly WeaknessFamily[] = [
  {
    weaknessClass: 'eval-exec',
    weakness: 'Dynamic evaluation of a string as code (CWE-95)',
    vibeguardRules: ['VG-INJ-004'],
    semgrepPatterns: [/(^|\.)eval-detected($|\.)/, /(^|\.)eval-injection($|\.)/, /(^|\.)user-eval($|\.)/],
    codeqlPatterns: [/\/code-injection/, /\/eval-/],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'Semgrep eval-detected (js/python) plus the flask/django eval-injection and user-eval variants. '
      + 'CodeQL js/py code-injection. CodeQL flags eval() only on a value dataflow reached from a source, '
      + 'so a constant-argument eval it stays quiet about is a coverage difference, not a miss.',
  },
  {
    weaknessClass: 'weak-crypto',
    weakness: 'Broken hash used in a security context (CWE-327)',
    vibeguardRules: ['VG-CRYPTO-001'],
    semgrepPatterns: [/insecure-hash-algorithm/, /weak-hashes-(md5|sha1)/],
    codeqlPatterns: [],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'python insecure-hash-algorithm-*, ruby weak-hashes-md5/sha1. NO CodeQL pattern: '
      + 'sec-transfer-codeql.mjs maps no family to weak hashing, and inventing one here — CodeQL does ship '
      + 'py/weak-sensitive-data-hashing — would be the first unsourced entry in a table whose whole value is '
      + 'that every entry has a source. The cost is that CodeQL is never counted as silent on weak crypto.',
  },
  {
    weaknessClass: 'injection-sql',
    weakness: 'SQL built by string concatenation / interpolation (CWE-89)',
    vibeguardRules: ['VG-INJ-001'],
    semgrepPatterns: [/sqlalchemy-execute-raw-query/, /(^|\.)tainted-sql/, /formatted-sql-query/],
    codeqlPatterns: [/\/sql-injection/],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'sqlalchemy-execute-raw-query is the pattern that fired on the corpus originals; the other two are '
      + 'carried forward from the source table for raw-string SQL forms it did not contain.',
  },
  {
    weaknessClass: 'injection-shell',
    weakness: "Command executed through a shell with interpolated input (CWE-78)",
    vibeguardRules: ['VG-INJ-002'],
    semgrepPatterns: [/subprocess-shell-true/, /dangerous-subprocess-use/],
    codeqlPatterns: [/\/command-line-injection/, /\/shell-command/],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'VG-INJ-002 = subprocess(shell=True). VG-INJ-003 (os.system / os.popen) is deliberately NOT in this '
      + 'family: sec-transfer-semgrep.mjs records that Semgrep p/default fired nothing on those originals, and '
      + 'adding it here would make VibeGuard look silent on a class Semgrep also does not cover.',
  },
  {
    weaknessClass: 'unsafe-deserialization',
    weakness: 'Deserializing untrusted data into arbitrary objects (CWE-502)',
    vibeguardRules: ['VG-INJ-005'],
    semgrepPatterns: [/insecure-deserialization/, /(^|\.)avoid-pickle($|\.)/, /deserialization\.pickle/],
    codeqlPatterns: [/\/unsafe-deserialization/, /\/deserialization/, /\/pickle/],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note: 'flask insecure-deserialization and lang.security.deserialization.pickle.avoid-pickle; CodeQL py/ruby deserialization queries.',
  },
  {
    weaknessClass: 'tls-verification-disabled',
    weakness: 'TLS certificate verification switched off (CWE-295)',
    vibeguardRules: ['VG-AUTH-004'],
    semgrepPatterns: [/disabled-cert-validation/],
    codeqlPatterns: [
      /\/request-without-cert-validation/,
      /\/disabled-certificate-validation/,
      // ★ bounded rewrite of sec-transfer-codeql.mjs's `/insecure-.*request`. See the header.
      /\/insecure-[A-Za-z0-9_-]{0,40}request/,
    ],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note: 'python.requests.security.disabled-cert-validation; CodeQL py/request-without-cert-validation.',
  },
  {
    weaknessClass: 'debug-enabled',
    weakness: 'Framework debug mode enabled in shipped code (CWE-489)',
    vibeguardRules: ['VG-FW-002'],
    // ★ THE THIRD DEPARTURE FROM sec-transfer-semgrep.mjs, AND THE ONLY ONE THE
    // RECORDED BYTES FORCED RATHER THAN THE ReDoS RULE.
    //
    // The source table maps this family with TWO patterns,
    // `(^|\.)debug-enabled($|\.)` and `app-run-param-config`. The second is
    // dropped here. `app-run-param-config` is the name of a Semgrep RULE FILE,
    // not of a rule, and the recorded fixture in this package shows what that
    // costs — both of these fired on samples/vulnerable/flask_app.py line 19:
    //
    //   python.flask.security.audit.debug-enabled.debug-enabled
    //       -> CWE-489: Active Debug Code                       (this family)
    //   python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host
    //       -> CWE-668: Exposure of Resource to Wrong Sphere    (NOT this family)
    //
    // Binding a host to 0.0.0.0 is not debug mode. In sec-transfer-semgrep.mjs
    // the over-match is harmless: that script asks only whether the family fired
    // in the same FILE before and after a transform, and both rules fire on the
    // same file either way. Here the mapping decides CROSS-TOOL AGREEMENT, so the
    // over-match manufactures corroboration — a project where only
    // `avoid_app_run_with_bad_host` fires and VibeGuard's VG-FW-002 fires within
    // two lines would be reported as two engines agreeing about debug mode when
    // neither said that.
    //
    // The cost of dropping it is stated rather than hidden: any Semgrep rule for
    // `app.run(debug=True)` that lives in that rule file and is NOT named
    // `debug-enabled` now classifies as unmapped. Such a rule may exist; its id
    // could not be checked, because Semgrep is not installed here, and guessing
    // an id would put the first unsourced pattern into a table whose whole value
    // is that every pattern has a source.
    semgrepPatterns: [/(^|\.)debug-enabled($|\.)/],
    codeqlPatterns: [],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'flask debug-enabled only — the source table\'s app-run-param-config pattern is dropped because it '
      + 'over-matches a CWE-668 host-binding rule in this package\'s recorded fixture (see the ★ note above). '
      + 'VG-FW-001 (Django DEBUG=True) and VG-FW-003 (CORS wildcard) stay unmapped for the reason the source '
      + 'table gives: a csurf hit NEAR a CORS finding is a different weakness, and mapping them would let '
      + 'co-location masquerade as corroboration — the exact error this package exists to avoid.',
  },
  {
    weaknessClass: 'cookie-session-flags',
    weakness: 'Session cookie missing Secure / HttpOnly flag (CWE-614 / CWE-1004)',
    vibeguardRules: ['VG-AUTH-006'],
    semgrepPatterns: [/express-cookie-session-no-(httponly|secure)/],
    codeqlPatterns: [],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'Mapped ONLY to the no-httponly / no-secure rules. The four sibling express-cookie-settings rules that '
      + 'fire on the SAME line of the real fixture (default-name, no-domain, no-expires, no-path) and the '
      + 'co-located express-session-hardcoded-secret are DIFFERENT weaknesses and stay unmapped on purpose: '
      + 'they are the concrete case where "same file, same line" is not "same finding".',
  },
  {
    weaknessClass: 'insecure-transport',
    weakness: 'Plaintext HTTP used for a non-localhost endpoint (CWE-319)',
    vibeguardRules: ['VG-CRYPTO-003'],
    semgrepPatterns: [/insecure-request/],
    codeqlPatterns: [
      /\/clear-text-transmission/,
      // ★ bounded rewrite of sec-transfer-codeql.mjs's `/insecure-.*protocol`. See the header.
      /\/insecure-[A-Za-z0-9_-]{0,40}protocol/,
      /\/clear-text/,
    ],
    semgrepEmpiricallyConfirmed: true,
    codeqlEmpiricallyConfirmed: false,
    note:
      'Semgrep react-insecure-request is react-specific but is the CWE-319 rule that fired on the corpus '
      + 'original; VG-CRYPTO-003 is the general http:// rule.',
  },
];

/**
 * VibeGuard rule id -> family. Exact string equality, never a pattern.
 *
 * ★ EXACT MATCH IS A DELIBERATE ASYMMETRY with the two pattern-matched tools, and
 * it is not laziness. Semgrep check_ids and CodeQL query ids are long dotted or
 * slashed paths whose prefix varies with how the tool was configured (a vendored
 * ruleset prepends the vendor path; a query pack prepends the pack name), so a
 * pattern over the tail is the only stable handle. VibeGuard rule ids are short,
 * stable, and OURS — `VG-INJ-001` will never arrive with a prefix. A pattern on
 * this side would buy nothing and would let `VG-INJ-00` match ten rules.
 */
const VIBEGUARD_RULE_TO_CLASS: ReadonlyMap<string, WeaknessClass> = new Map(
  WEAKNESS_FAMILIES.flatMap((f) => f.vibeguardRules.map((r) => [r, f.weaknessClass] as const)),
);

/** The family record for a class, or `undefined` for an unmapped one. */
export function weaknessFamily(weaknessClass: WeaknessClass): WeaknessFamily | undefined {
  return WEAKNESS_FAMILIES.find((f) => f.weaknessClass === weaknessClass);
}

/**
 * Classify a Semgrep `check_id`.
 *
 * Patterns are tested against the WHOLE id, unanchored, which is how
 * sec-transfer-semgrep.mjs tests them (`fam.regexes.some((re) => re.test(h.checkId))`).
 * That matters: a vendored config prepends its own path to the check_id, so an
 * anchored pattern would stop matching the moment someone scans with `--config
 * ./rules/`. The source script's header says exactly this — "Patterns match the
 * check_id tail, so they survive the vendor-path prefix a vendored config
 * prepends" — and reproducing the behaviour is more important than tightening it.
 *
 * First match wins, in table order. The table is checked for overlap by a test
 * (`no check_id may match two families`), so "first" is never load-bearing in
 * practice; it is defined here so the function is total and deterministic even if
 * a future edit introduces an overlap before the test catches it.
 */
export function classifySemgrepCheckId(checkId: string): WeaknessClass | null {
  for (const family of WEAKNESS_FAMILIES) {
    for (const pattern of family.semgrepPatterns) {
      if (pattern.test(checkId)) return family.weaknessClass;
    }
  }
  return null;
}

/** Classify a CodeQL query id (`py/sql-injection`). Same contract as the Semgrep side. */
export function classifyCodeqlRuleId(ruleId: string): WeaknessClass | null {
  for (const family of WEAKNESS_FAMILIES) {
    for (const pattern of family.codeqlPatterns) {
      if (pattern.test(ruleId)) return family.weaknessClass;
    }
  }
  return null;
}

/** Classify a VibeGuard rule id. Exact match — see `VIBEGUARD_RULE_TO_CLASS`. */
export function classifyVibeguardRuleId(ruleId: string): WeaknessClass | null {
  return VIBEGUARD_RULE_TO_CLASS.get(ruleId) ?? null;
}

/** Dispatch by tool, so callers do not re-derive which classifier goes with which id space. */
export function classifyRuleId(tool: 'vibeguard' | 'semgrep' | 'codeql', ruleId: string): WeaknessClass | null {
  if (tool === 'vibeguard') return classifyVibeguardRuleId(ruleId);
  if (tool === 'semgrep') return classifySemgrepCheckId(ruleId);
  return classifyCodeqlRuleId(ruleId);
}

/**
 * Whether a tool has ANY mapped detector for a weakness class.
 *
 * The predicate behind `MergedFinding.couldHaveBeenReportedBy`, and therefore
 * behind the distinction between `unique-to-tool` and `sole-detector`. Getting it
 * wrong in the permissive direction manufactures accusations: a tool credited
 * with a detector it does not have is reported as having stayed silent about a
 * weakness it was never looking for.
 *
 * Note what it answers and what it does not. It answers "is there a mapping entry
 * that would let us recognise this tool's finding of this class". It does NOT
 * answer "would this tool find this bug" — that depends on the ruleset the user
 * ran, the language, and the tool's own analysis, none of which is knowable from
 * a report. An empty pattern list is therefore a statement about THIS TABLE, and
 * `silentTools` inherits that limit; the README says so in the same words.
 */
export function toolHasDetectorFor(tool: 'vibeguard' | 'semgrep' | 'codeql', weaknessClass: WeaknessClass): boolean {
  const family = weaknessFamily(weaknessClass);
  if (!family) return false;
  if (tool === 'vibeguard') return family.vibeguardRules.length > 0;
  if (tool === 'semgrep') return family.semgrepPatterns.length > 0;
  return family.codeqlPatterns.length > 0;
}
