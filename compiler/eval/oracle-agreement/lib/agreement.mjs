/**
 * The 2x2 table, and every rule that decides what may enter it.
 *
 * This lane exists because of one sentence in the implementation order, section
 * 2.20(g): that A1/A2/A3/A5/A7 and -- through the rows -- A6 all reach their
 * verdict through `verdictOf` in `../../ai-generated/lib/ablation-cell.mjs`, so
 * "seven lanes agreed" is a re-sample of one instrument and not corroboration.
 * The sentence is right about the danger and wrong about the inventory (see the
 * README), and the correct response to both halves is the same: put a SECOND
 * instrument on the SAME cells and tabulate where the two part company.
 *
 * Everything here is a pure function of synthetic rows. Nothing compiles,
 * nothing reads a file, nothing can fail because a plugin is missing -- which is
 * the point, because the arithmetic of a 2x2 table is exactly the part that is
 * easy to get subtly wrong and impossible to notice afterwards from a number.
 *
 * THE ONE THING THIS MODULE REFUSES TO DO. It never maps a third answer onto one
 * of the four cells. `NOT_APPLICABLE`, `ABSENT`, `REINTRODUCED` and
 * `NO_WIPE_WRITTEN` are answers, not failures, and none of them is LOST or
 * PRESENT or ELIMINATED or SURVIVED. Deciding that `ABSENT` "really means"
 * eliminated would be the whole result of this lane, taken as a premise, inside
 * the module that is supposed to measure it. They are excluded, counted, and
 * listed by id. See NOT_COMPARABLE below.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

/**
 * O1 -- the shared oracle: `verdictOf`, differential assembly text.
 *
 * Two compiles of the same translation unit, one with the wipe and one with the
 * wipe's statements removed, and the target function's body compared as text.
 * Its two gradable words are these; everything else it can say is about the
 * instrument, not about the wipe.
 */
export const O1 = Object.freeze({ ELIMINATED: 'ELIMINATED', SURVIVED: 'SURVIVED' });

/**
 * O2 -- the PropertyObserver LLVM pass: an IR call-site count, read between
 * passes. Its `finalState` vocabulary is `../../schema/interfaces.md` section 3,
 * and only two of its six words are gradable against O1.
 */
export const O2 = Object.freeze({ LOST: 'LOST', PRESENT: 'PRESENT' });

/** The O1 verdicts that are a reading about the WIPE rather than about the instrument. */
export const O1_GRADABLE = Object.freeze({ WIPE_ELIMINATED: O1.ELIMINATED, WIPE_SURVIVED: O1.SURVIVED });

/** The O2 final states that are gradable against O1's two words. */
export const O2_GRADABLE = Object.freeze({ LOST: O2.LOST, PRESENT: O2.PRESENT });

/**
 * The four cells, in a fixed order, so a table printed twice prints the same.
 *
 * The name is `O1/O2`. The DIAGONAL is the pair this lane's conjecture calls
 * agreement -- and it IS a conjecture, argued in the README: "the differential
 * compile could not tell the two forms apart" and "the effect call site did not
 * survive the pass pipeline" are different sentences about different artefacts,
 * and the reason to tabulate them is precisely that nobody has shown they are
 * the same sentence.
 */
export const CELLS = Object.freeze([
  'ELIMINATED/LOST', 'ELIMINATED/PRESENT', 'SURVIVED/LOST', 'SURVIVED/PRESENT',
]);
export const DIAGONAL = Object.freeze(['ELIMINATED/LOST', 'SURVIVED/PRESENT']);
export const OFF_DIAGONAL = Object.freeze(['ELIMINATED/PRESENT', 'SURVIVED/LOST']);

/**
 * Why a cell did not enter the denominator.
 *
 * Three KINDS, and keeping them apart is most of the value of the list.
 *
 *   BROKEN_MEASUREMENT  a statement about the APPARATUS. The control fell, the
 *                       subject name never resolved, the compile failed, the
 *                       ablation would not build. Nothing about this cell's wipe
 *                       can be read out of it, and the honest denominator is the
 *                       one without it.
 *   NO_READING          the instrument RAN and there was no reading of this
 *                       property here. `../../schema/interfaces.md` section 3.1
 *                       is emphatic that this is a third situation and not a
 *                       broken instrument -- "the subject was not in the
 *                       translation unit, or the observation point was never
 *                       reached" -- and `../../lto-window/lib/cell.mjs` records
 *                       what happened in this tree when the two were merged.
 *   NOT_COMPARABLE      a statement about the two VOCABULARIES. Both instruments
 *                       worked, both answered, and their answers do not meet in
 *                       this table.
 *
 * Collapsing any of the three into another would blame the apparatus for a fact
 * about the program, or the reverse; putting any of them into the denominator
 * would manufacture agreement.
 */
export const KIND = Object.freeze({
  BROKEN_MEASUREMENT: 'BROKEN_MEASUREMENT',
  NO_READING: 'NO_READING',
  NOT_COMPARABLE: 'NOT_COMPARABLE',
});

export const REASON = Object.freeze({
  NO_O1_ROW: 'no-o1-row',
  NO_O2_READING: 'no-o2-reading',
  O2_COMPILE_FAILED: 'o2-compile-failed',
  O2_SUBJECT_UNRESOLVED: 'o2-subject-unresolved',
  O2_CONTROL_LOST: 'o2-control-lost',
  O2_CONTROL_NOT_MEASURED: 'o2-control-not-measured',
  O1_CONTROL_NOT_PRESENT: 'o1-control-not-present',
  O1_NOT_A_VERDICT: 'o1-not-a-verdict',
  O2_NOT_A_READING: 'o2-not-a-reading',
});

/**
 * Which kind each reason is, when the reason alone settles it.
 *
 * `O1_NOT_A_VERDICT` and `O2_NOT_A_READING` are not in this table: their kind
 * depends on WHICH word came back, and `kindOfWord` decides it. A default here
 * would be a default that is wrong half the time and silent about it.
 */
export const REASON_KIND = Object.freeze({
  [REASON.NO_O1_ROW]: KIND.NOT_COMPARABLE,
  [REASON.NO_O2_READING]: KIND.BROKEN_MEASUREMENT,
  [REASON.O2_COMPILE_FAILED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O2_SUBJECT_UNRESOLVED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O2_CONTROL_LOST]: KIND.BROKEN_MEASUREMENT,
  [REASON.O2_CONTROL_NOT_MEASURED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O1_CONTROL_NOT_PRESENT]: KIND.BROKEN_MEASUREMENT,
});

/**
 * The words that are an ANSWER this table has no column for, as against the
 * words that are a failure of the apparatus.
 *
 * `NO_WIPE_WRITTEN` is O1 saying the source contains no wipe to ablate;
 * `NOT_APPLICABLE` is the observer saying the property does not arise in this
 * unit; `ABSENT` is it saying the call site was never there to lose;
 * `REINTRODUCED` is it saying the site came back. All four are true statements
 * about the program. None of them is "the instrument failed", and none of them
 * is LOST or PRESENT.
 *
 * `ABSENT` is the judgement call in this list and is called out in the README: a
 * wipe lowered away before the pipeline's first observation point reads `ABSENT`
 * here and would very plausibly read `WIPE_ELIMINATED` over there. Mapping it
 * onto LOST is a defensible reading and this lane still refuses it, because that
 * mapping is the hypothesis under test.
 */
export const ANSWER_NOT_IN_TABLE = Object.freeze([
  'NO_WIPE_WRITTEN', 'NOT_APPLICABLE', 'ABSENT', 'REINTRODUCED',
]);

/**
 * The words that mean "there was no reading", on either side.
 *
 * `verdictOf` returns `NOT_OBSERVED` when it could not find the target function's
 * body in one of the two listings, and the observer returns it when the run
 * produced no SUMMARY row for the subject. Both are the section 3.1 situation,
 * and neither is a broken instrument.
 */
export const NO_READING_WORDS = Object.freeze(['NOT_OBSERVED']);

/** Which kind a word belongs to. Everything not named above is about the apparatus. */
export function kindOfWord(word) {
  if (ANSWER_NOT_IN_TABLE.includes(word)) return KIND.NOT_COMPARABLE;
  if (NO_READING_WORDS.includes(word)) return KIND.NO_READING;
  return KIND.BROKEN_MEASUREMENT;
}

/** `WIPE_ELIMINATED` -> `ELIMINATED`, `WIPE_SURVIVED` -> `SURVIVED`, anything else null. */
export function o1ClassOf(verdict) {
  return Object.prototype.hasOwnProperty.call(O1_GRADABLE, verdict) ? O1_GRADABLE[verdict] : null;
}

/** `LOST` / `PRESENT` pass through; every other final state is null. */
export function o2ClassOf(finalState) {
  return Object.prototype.hasOwnProperty.call(O2_GRADABLE, finalState) ? O2_GRADABLE[finalState] : null;
}

const excluded = (pair, reason, detail, kind) => ({
  status: 'EXCLUDED',
  reason,
  detail: detail === undefined ? null : detail,
  kind: kind || REASON_KIND[reason],
  id: pair.id,
  cc: pair.cc,
  opt: pair.opt,
  idiom: pair.idiom === undefined ? null : pair.idiom,
});

/**
 * One (id, vendor, level) cell: does it enter the table, and if not, why not.
 *
 * THE ORDER OF THESE CHECKS IS PART OF THE MEASUREMENT and is not arbitrary.
 * The controls are read BEFORE the subjects, on both sides, for the reason
 * `../../lto-window/README.md` gives at length: in a run whose positive control
 * fell, the subject's own "it is gone" cannot be told apart from the instrument
 * having stopped seeing anything, so a cell like that must leave the denominator
 * before its subject is ever looked at. A lane that read the subject first and
 * only then noticed the control would already have decided what it was about to
 * exclude.
 *
 * @param {object} pair
 * @param {string} pair.id       the corpus generation's id -- never a path
 * @param {string} pair.cc       vendor label (basename of the driver)
 * @param {string} pair.opt      optimisation level
 * @param {string} [pair.idiom]  the O1 rows' idiom column, carried for diagnosis
 * @param {object|null} pair.o1  {verdict, control, control_via} from the TRACKED rows
 * @param {object|null} pair.o2  {finalState, control, firstLossPass, subjectResolutionExit}
 * @returns {{status: 'GRADED', cell: string}|{status: 'EXCLUDED', reason: string}}
 */
export function classifyPair(pair) {
  const { o1, o2 } = pair;

  if (!o1) return excluded(pair, REASON.NO_O1_ROW, null, KIND.NOT_COMPARABLE);
  if (!o2) return excluded(pair, REASON.NO_O2_READING);

  // ---- the apparatus, before either subject --------------------------------
  //
  // A compile that did not happen first, and named as such. It reaches the next
  // check too -- a failed compile carries a null resolution exit, deliberately --
  // but "the subject did not resolve" is a statement about the plugin's
  // configuration and reporting it for a translation unit that never compiled
  // would send whoever reads the exclusion list to the wrong place.
  if (o2.compiled === false) {
    return excluded(pair, REASON.O2_COMPILE_FAILED);
  }
  // The observer's third silent failure next: a subject name that resolves to
  // nothing compiles cleanly, writes a non-empty log and reads a healthy
  // control. `check-subject-resolution.mjs` is the repository's own answer to it
  // and its exit code is carried here rather than re-derived.
  if (o2.subjectResolutionExit !== 0) {
    return excluded(pair, REASON.O2_SUBJECT_UNRESOLVED, `exit ${o2.subjectResolutionExit}`);
  }
  if (o2.control === null || o2.control === undefined) {
    return excluded(pair, REASON.O2_CONTROL_NOT_MEASURED);
  }
  if (o2.control !== 'PRESENT') {
    return excluded(pair, REASON.O2_CONTROL_LOST, o2.control);
  }
  // O1's control is the same appended `vgctl_control`, read out of the tracked
  // row rather than re-measured. A row without it is a row whose verdict was
  // about something other than a wipe.
  if (o1.control !== 'PRESENT') {
    return excluded(pair, REASON.O1_CONTROL_NOT_PRESENT, o1.control === undefined ? null : o1.control);
  }

  // ---- the two subjects ----------------------------------------------------
  const a = o1ClassOf(o1.verdict);
  if (a === null) {
    const word = o1.verdict === undefined ? null : o1.verdict;
    return excluded(pair, REASON.O1_NOT_A_VERDICT, word, kindOfWord(word));
  }
  const b = o2ClassOf(o2.finalState);
  if (b === null) {
    const word = o2.finalState === undefined ? null : o2.finalState;
    return excluded(pair, REASON.O2_NOT_A_READING, word, kindOfWord(word));
  }

  const cell = `${a}/${b}`;
  return {
    status: 'GRADED',
    cell,
    agrees: DIAGONAL.includes(cell),
    id: pair.id,
    cc: pair.cc,
    opt: pair.opt,
    idiom: pair.idiom === undefined ? null : pair.idiom,
    o1Verdict: o1.verdict,
    o2State: o2.finalState,
    firstLossPass: o2.firstLossPass === undefined ? null : o2.firstLossPass,
  };
}

const emptyTable = () => Object.fromEntries(CELLS.map((c) => [c, 0]));

/**
 * Does either instrument's marginal put all of its mass in one word?
 *
 * A stratum whose O1 column is entirely `SURVIVED` scores whatever O2 says about
 * `SURVIVED` and nothing else; an instrument physically unable to report the
 * other word would score identically. This is the `-O0` lesson of
 * `../../spike/README.md` ("Discriminating configurations -- the hole this gate
 * had") stated as arithmetic instead of as a level name, so that a NON-`-O0`
 * stratum which happens to come out uniform is caught by the same rule.
 *
 * A stratum with a denominator of 0 is degenerate on both sides: it has no mass
 * to put anywhere.
 */
export function degeneracyOf(table) {
  const o1 = {
    ELIMINATED: table['ELIMINATED/LOST'] + table['ELIMINATED/PRESENT'],
    SURVIVED: table['SURVIVED/LOST'] + table['SURVIVED/PRESENT'],
  };
  const o2 = {
    LOST: table['ELIMINATED/LOST'] + table['SURVIVED/LOST'],
    PRESENT: table['ELIMINATED/PRESENT'] + table['SURVIVED/PRESENT'],
  };
  const den = o1.ELIMINATED + o1.SURVIVED;
  const o1Degenerate = o1.ELIMINATED === 0 || o1.SURVIVED === 0;
  const o2Degenerate = o2.LOST === 0 || o2.PRESENT === 0;
  return {
    marginals: { o1, o2 },
    den,
    o1Degenerate,
    o2Degenerate,
    any: o1Degenerate || o2Degenerate,
  };
}

/**
 * The stratum name for a level. `-O0` is ALWAYS its own stratum.
 *
 * Not a stylistic choice and not a convenience: section 2.20(d) of the
 * implementation order records that at `-O0` BOTH spike subjects -- the one the
 * optimiser may delete and the one it may not -- come out `WIPE_SURVIVED`, so
 * the configuration has zero discriminating power on the O1 side by
 * construction. A pooled table would let those rows contribute agreement they
 * cannot possibly have earned: at `-O0` an instrument that can only ever say
 * "survived" and an instrument that is reading are the same instrument, and
 * "100% agreement" there would mean "neither one can report the phenomenon".
 *
 * The stratum is still MEASURED and still PRINTED, because "both instruments are
 * mute here" is itself a fact about the configuration, and dropping it would
 * leave a reader unable to see that it had been asked.
 */
export const O0 = '-O0';
export const STRATUM = Object.freeze({ AT_O0: 'at -O0', ABOVE_O0: 'above -O0' });
export const stratumOf = (opt) => (opt === O0 ? STRATUM.AT_O0 : STRATUM.ABOVE_O0);

const offDiagonalOrder = (x, y) => (
  x.cell < y.cell ? -1 : x.cell > y.cell ? 1
    : x.id < y.id ? -1 : x.id > y.id ? 1
      : x.cc < y.cc ? -1 : x.cc > y.cc ? 1
        : x.opt < y.opt ? -1 : x.opt > y.opt ? 1 : 0
);

const exclusionOrder = (x, y) => (
  x.reason < y.reason ? -1 : x.reason > y.reason ? 1
    : x.id < y.id ? -1 : x.id > y.id ? 1
      : x.cc < y.cc ? -1 : x.cc > y.cc ? 1
        : x.opt < y.opt ? -1 : x.opt > y.opt ? 1 : 0
);

/**
 * The exclusions, counted by reason and by kind, and LISTED.
 *
 * The list is not optional and is not truncated. "Excluded 37" with no ids is
 * the shape of a number nobody can check; the rule this lane was written under
 * says never silently drop, and a count without names is a quiet drop with a
 * receipt attached.
 */
export function summariseExclusions(rows) {
  const byReason = {};
  const byKind = { [KIND.BROKEN_MEASUREMENT]: 0, [KIND.NO_READING]: 0, [KIND.NOT_COMPARABLE]: 0 };
  for (const r of rows) {
    const key = r.detail ? `${r.reason}(${r.detail})` : r.reason;
    byReason[key] = (byReason[key] || 0) + 1;
    byKind[r.kind] = (byKind[r.kind] || 0) + 1;
  }
  return {
    total: rows.length,
    byKind,
    byReason,
    cells: rows.slice().sort(exclusionOrder),
  };
}

/**
 * Tabulate classified cells into the two strata.
 *
 * Every input lands in exactly one of two places -- a table cell or the
 * exclusion list -- and `accountedFor` re-adds them so a caller can assert it.
 * Four accounts summing to the declared total is the habit `compiler/evidence`'s
 * ledger is built on, and it costs one line here.
 */
export function tabulate(pairs, { classify = classifyPair } = {}) {
  const strata = new Map();
  const stratum = (name) => {
    if (!strata.has(name)) {
      strata.set(name, { name, levels: [], table: emptyTable(), graded: [], offDiagonal: [], excluded: [] });
    }
    return strata.get(name);
  };
  // Both strata always exist, in this order, even when empty: a report whose
  // `-O0` section is missing reads as "it was not measured" and a report whose
  // `-O0` section is empty reads as "no cell landed there". Different facts.
  stratum(STRATUM.AT_O0);
  stratum(STRATUM.ABOVE_O0);

  for (const pair of pairs) {
    const s = stratum(stratumOf(pair.opt));
    if (!s.levels.includes(pair.opt)) s.levels.push(pair.opt);
    const c = classify(pair);
    if (c.status === 'GRADED') {
      s.table[c.cell] += 1;
      s.graded.push(c);
      if (OFF_DIAGONAL.includes(c.cell)) s.offDiagonal.push(c);
    } else {
      s.excluded.push(c);
    }
  }

  const out = [...strata.values()].map((s) => {
    const d = degeneracyOf(s.table);
    const agree = DIAGONAL.reduce((n, k) => n + s.table[k], 0);
    const disagree = OFF_DIAGONAL.reduce((n, k) => n + s.table[k], 0);
    return {
      name: s.name,
      levels: s.levels.slice().sort(),
      table: s.table,
      den: d.den,
      agree,
      disagree,
      agreement: { num: agree, den: d.den },
      marginals: d.marginals,
      degenerate: { o1: d.o1Degenerate, o2: d.o2Degenerate, any: d.any },
      // A stratum can be READ as a comparison only when both instruments said
      // both of their words in it. `-O0` never can; any stratum may fail to.
      discriminating: d.den > 0 && !d.any,
      // Sorted so two runs over the same cells print the same list.
      offDiagonal: s.offDiagonal.slice().sort(offDiagonalOrder),
      excluded: summariseExclusions(s.excluded),
      accountedFor: d.den + s.excluded.length,
    };
  });

  return {
    strata: out,
    seen: pairs.length,
    accountedFor: out.reduce((n, s) => n + s.accountedFor, 0),
  };
}

/** `k/n` plus a percentage, or `0/0` and no percentage. Never `NaN%`, never `100%` of nothing. */
export function formatRate(rate) {
  if (!rate.den) return '0/0 (no cell entered the denominator)';
  return `${rate.num}/${rate.den} (${((rate.num / rate.den) * 100).toFixed(1)}%)`;
}

/**
 * What the exit code means -- and, as loudly as a comment can say it, what it
 * does NOT mean.
 *
 * THE EXIT CODE IS NOT "0 IFF THEY AGREE." Disagreement is the result this lane
 * was built to find: an off-diagonal cell is a place where a differential text
 * comparison and an IR call-site count give different answers about the same
 * build, and each one of those is a subject for diagnosis, not a failure. A lane
 * that went red on disagreement would be a lane with an incentive, and the first
 * thing anyone does with a red run is make it green.
 *
 * So the exit code answers a different question: WAS THE COMPARISON PERFORMED?
 *
 *   0  at least one stratum above `-O0` has a non-empty denominator AND both
 *      marginals non-degenerate in it. The two instruments each said both of
 *      their words on the same cells, so the table is a comparison. It may show
 *      perfect agreement or perfect disagreement; both exit 0.
 *   2  no such stratum. Every cell was excluded, or the only level run was
 *      `-O0`, or the selected cells were uniform on one side so the table cannot
 *      separate "the second instrument agrees" from "the second instrument can
 *      only say one word". THE RUN COULD NOT ASK ITS QUESTION. This is not a
 *      statement about whether the instruments agree.
 *
 * Exit 3 (a check that could not be completed -- absent plugin, absent compiler,
 * unreadable rows) and exit 4 (bad arguments, a lab inside the repository, a
 * report carrying an absolute path) belong to the runner, following
 * `../../spike/run-spike.mjs`, and are not decided here.
 */
export function laneVerdict(tab) {
  const above = tab.strata.filter((s) => s.name === STRATUM.ABOVE_O0);
  const readable = above.filter((s) => s.discriminating);
  const reasons = [];
  if (!readable.length) {
    for (const s of above) {
      if (s.den === 0) {
        reasons.push(`${s.name}: no cell entered the denominator (${s.excluded.total} excluded)`);
        continue;
      }
      if (s.degenerate.o1) {
        const word = s.marginals.o1.ELIMINATED === 0 ? 'SURVIVED' : 'ELIMINATED';
        reasons.push(`${s.name}: all ${s.den} graded cells read ${word} on O1, so this table cannot separate an agreeing second instrument from one stuck on a single word`);
      }
      if (s.degenerate.o2) {
        const word = s.marginals.o2.LOST === 0 ? 'PRESENT' : 'LOST';
        reasons.push(`${s.name}: all ${s.den} graded cells read ${word} on O2, the same objection in the other direction`);
      }
    }
    if (!above.length) {
      reasons.push('no level above -O0 was run; -O0 alone has no discriminating power on either side');
    }
  }
  return {
    readable: readable.length > 0,
    code: readable.length > 0 ? 0 : 2,
    // Said inside the verdict so that a reader of the JSON cannot reach the exit
    // code without reading what it is about.
    meaning: 'the exit code says whether the comparison was PERFORMED, not whether the two oracles agreed; disagreement exits 0',
    reasons,
  };
}
