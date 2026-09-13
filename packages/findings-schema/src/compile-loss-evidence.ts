/**
 * `compileLossEvidence` — a ratio, counted over a corpus, about what a build
 * toolchain did to code of this shape. Adopted by the user's ruling of
 * 2026-09-12; specified in `compiler/eval/actuarial/README.md`, section
 * "Product side".
 *
 * ── WHAT IT IS ───────────────────────────────────────────────────────────────
 *
 * The build-side lanes in `compiler/` close a `find -> fix -> confirm` loop
 * entirely on the build side: a finder locates a wipe, a repair plugin pins it,
 * and differential compilation confirms the repair. The person who wrote the
 * `memset` never hears any of it. This field is the fourth step — what the
 * build side measured travels back to the source-side finding a human reads,
 * carrying its denominator with it. It is the difference between "this wipe may
 * be removed by the compiler", which is true of every wipe and therefore
 * ignorable, and "113 of 133 files that wrote this idiom lost it under the
 * toolchain you are building with".
 *
 * ── IT IS NOT `confidence`, AND NOT A MODIFIER OF `confidence` ───────────────
 *
 * This is the load-bearing constraint, quoted from the specification: "Field
 * name: `compileLossEvidence`. Not `confidence`, and not a modifier of it."
 *
 * The reason is in `packages/rules/src/confidence.ts`: the confidence axis is
 * DOWNGRADE-ONLY, because the context it reads is attacker-controlled, and
 * `explainContextConfidence` makes `result <= base` true by construction. A
 * ratio attached to that axis would be a raise — and a raise sourced from a
 * corpus, which is worse than one sourced from the file, because the file at
 * least belongs to the user being warned. So this rides under its own name and
 * does not touch that axis at all. Nothing in this module reads or returns a
 * `Confidence`, and nothing downstream may combine the two.
 *
 * It is also NOT `Finding.evidence`. That field is a `string[]` of the
 * offending text a rule matched in THIS file — an observation about the user's
 * own source. This one is a count over somebody else's corpus. Folding a
 * corpus statistic into the list of matched substrings would make the two
 * indistinguishable to every consumer that renders `evidence`, so the field is
 * separate and the two are never merged.
 *
 * ── IT IS SUPPLIED BY THE CONSUMER, NEVER DERIVED BY THE ANALYSER ────────────
 *
 * Quoted from the specification: "It is supplied by the consumer, never derived
 * by the analyser. The analyser cannot know the two axes that decide the cell."
 *
 * `packages/rules/src/rule-types.ts`: a `RuleContext` is
 * `{ filePath?, language?, content, lines }` — text and a path. Nothing in it
 * names a compiler or an optimisation level, and nothing should: the product
 * scans source that has not been built yet, often on a machine that will never
 * build it. A build system, a CI job or an IDE extension knows its own vendor
 * and level; the analyser knows a string. So the field arrives from outside
 * (`ScanRequest.compileLossEvidence`), the analyser only copies it onto the
 * findings it is supplied for, and A FINDING WITHOUT IT IS THE NORMAL CASE
 * RATHER THAN A DEGRADED ONE.
 */
export interface CompileLossEvidence {
  /** Integer. Files of this idiom, in this cell, that lost the wipe. */
  num: number;
  /** Integer, greater than zero. Files of this idiom with a live control. */
  den: number;
  /** Which corpus the ratio was counted over, e.g. `r2`. */
  corpusId: string;
  /** The toolchain the CONSUMER builds with, with its version, e.g. `clang-18`. */
  vendor: string;
  /** The level the CONSUMER builds at, e.g. `-O2`. */
  optLevel: string;
}

/**
 * Whether an unknown value satisfies the contract above.
 *
 * Total on `unknown` and free of side effects, so every channel can call it —
 * including the two that run in a browser. It is the gate the analyser applies
 * to consumer-supplied input; a value that fails it is recorded and dropped
 * rather than copied onto a finding, because a ratio whose denominator is zero
 * or whose numerator exceeds it would render a sentence that is arithmetically
 * false, and a false sentence carrying a corpus id is worse than no sentence.
 *
 * The string fields are checked against `trim()`: a whitespace-only `vendor`
 * is empty for every purpose this field has, and it would render as a gap in
 * the middle of the sentence rather than as an obvious defect.
 *
 * Unknown extra properties are NOT rejected. The shape is a floor, not a
 * ceiling, so a producer may carry its own keys through without this predicate
 * having to be revised in lockstep.
 */
export function isCompileLossEvidence(value: unknown): value is CompileLossEvidence {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  const { num, den } = v;
  if (!Number.isInteger(num) || !Number.isInteger(den)) return false;
  if ((den as number) <= 0) return false;
  if ((num as number) < 0 || (num as number) > (den as number)) return false;
  for (const key of ['corpusId', 'vendor', 'optLevel'] as const) {
    const s = v[key];
    if (typeof s !== 'string' || s.trim().length === 0) return false;
  }
  return true;
}

/* ─── THE WORDING RULE ───────────────────────────────────────────────────────
 *
 * The one sentence below is the ONLY rendering of this field that any channel
 * may produce. It is quoted from the specification, which inherits it from the
 * wording rule of the lane that produced the numbers
 * (`compiler/eval/actuarial/README.md`):
 *
 *   a consumer may print "113 of 133 files with this idiom lost the wipe under
 *   clang-18 -O2 in corpus r2" and may not print a percentage, a score, or
 *   anything that reads as a forecast about *this* file. The ratio is about a
 *   corpus; the finding is about a line.
 *
 * A percentage cannot be quoted without losing its denominator and a pair of
 * integers can, which is the whole reason the ratio is carried as two numbers
 * instead of one. The prohibition also covers the paraphrase that never says the
 * forbidden word — "N of every D builds of this idiom will lose the wipe" is a
 * probability statement wearing a ratio's clothes, and no test can tell it from
 * the sentence above. A reviewer can.
 *
 * This comment block is the only place in this module where those words are
 * spelled, and `compile-loss-evidence.test.ts` holds that boundary the way
 * `compiler/eval/actuarial/test/rate-table.test.mjs` holds the same boundary
 * for the lane's README: allowed inside the rule that states it, nowhere else.
 * ─────────────────────────────────────────────────────────────────────────── */

/**
 * The single permitted sentence. See the wording rule above for what it may not
 * be turned into.
 *
 * Takes an already-valid value: it does no arithmetic, computes no derived
 * quantity, and reads both integers out verbatim, so there is no place in here
 * for a ratio to become anything else. Callers gate on
 * `isCompileLossEvidence` first — the analyser does it once, at the boundary
 * where the value arrives.
 */
export function renderCompileLossEvidence(evidence: CompileLossEvidence): string {
  return (
    `${evidence.num} of ${evidence.den} files with this idiom lost the wipe under ` +
    `${evidence.vendor} ${evidence.optLevel} in corpus ${evidence.corpusId}`
  );
}

/**
 * One consumer-supplied entry that failed `isCompileLossEvidence` and was
 * therefore not copied onto any finding.
 *
 * Exists because the alternative is dropping it in silence, and this codebase
 * does not allow a channel that removes something to remove it quietly — the
 * same posture as `ScanDegradation`, `SuppressionRecord` and
 * `DeclaredPackageVetoRecord`. A consumer that hands the analyser a malformed
 * cell has a bug in the code that builds the request, and the only place it can
 * possibly learn about it is the response: nothing else in the pipeline ever
 * looks at what it supplied.
 *
 * Observability only. It does not contribute to `summary`, does not appear in
 * `findings`, and does not affect the CLI exit code.
 */
export interface CompileLossEvidenceRejection {
  /** The key of the rejected entry — the rule its evidence was meant for. */
  ruleId: string;
  /** Human-readable, and explicit that the entry was dropped. */
  detail: string;
}
