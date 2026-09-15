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
 * passes. Its `finalState` vocabulary is `../../../schema/interfaces.md` section 3,
 * and only two of its six words are gradable against O1.
 */
export const O2 = Object.freeze({ LOST: 'LOST', PRESENT: 'PRESENT' });

/**
 * O3 -- the disassembly reader: `../../lto-window/tools/read-wipe.py`, through
 * `../../../gcc-repair/scripts/objdump_fill.py`. It reads the zero fill of ONE
 * function in a LINKED program and answers in its own four words: `PRESENT`
 * (the fill covers the buffer, or a memset call is still there), `ABSENT` (no
 * zero store and no such call), `PARTIAL` (some fill, but not the buffer's
 * worth) and `NOT_OBSERVED` (the function is not in the output).
 *
 * O3 EXISTS IN THIS LANE FOR ONE REASON: the corpus's gcc half had no second
 * instrument at all. The PropertyObserver is an LLVM pass plugin and gcc does
 * not load it, so every O2 reading in this lane is clang whatever `--cc` says.
 * `../../lto-window` hit the same wall from the other side and answered it with
 * this reader.
 */
export const O3 = Object.freeze({ ABSENT: 'ABSENT', PRESENT: 'PRESENT', PARTIAL: 'PARTIAL' });

/**
 * THE TWO SECOND ORACLES DO NOT SHARE A COLUMN HEADING, AND THIS IS THE PLACE
 * THAT DECISION IS TAKEN.
 *
 * O2's word for "the wipe is gone" is `LOST`: an effect call site that existed
 * at one observation point does not exist at a later one. O3's word for it is
 * `ABSENT`: the linked function contains no zero fill. Those are different
 * sentences about different artefacts, and `ABSENT` is ALSO one of O2's own
 * words, where it means something else again -- "the site was never there to
 * lose" -- which this lane refuses to fold into `LOST` because that fold is the
 * hypothesis under test.
 *
 * So the table is not given one fixed pair of column names with each instrument
 * squeezed into it. A vocabulary carries its own two gradable words and its own
 * cell names, and a gcc record says `ELIMINATED/ABSENT` -- never
 * `ELIMINATED/LOST`, which would be this module asserting that O3's `ABSENT` is
 * O2's `LOST` in the one place that is supposed to keep them apart.
 *
 * `gone` and `kept` are ROLES, not words: what the cell names are built from is
 * the vocabulary's own spelling of them.
 */
function vocabulary({ oracle, instrument, gone, kept, notInTable }) {
  const gradable = Object.freeze(Object.fromEntries([[gone, gone], [kept, kept]]));
  const cells = Object.freeze([
    `${O1.ELIMINATED}/${gone}`, `${O1.ELIMINATED}/${kept}`,
    `${O1.SURVIVED}/${gone}`, `${O1.SURVIVED}/${kept}`,
  ]);
  return Object.freeze({
    oracle,
    instrument,
    gone,
    kept,
    gradable,
    notInTable: Object.freeze([...notInTable]),
    cells,
    diagonal: Object.freeze([`${O1.ELIMINATED}/${gone}`, `${O1.SURVIVED}/${kept}`]),
    offDiagonal: Object.freeze([`${O1.ELIMINATED}/${kept}`, `${O1.SURVIVED}/${gone}`]),
  });
}

/**
 * The second oracle this lane has always had. Its four non-gradable words are
 * answers about the program, not failures of the instrument; `ABSENT` is the
 * judgement call among them and is argued in the README.
 */
export const O2_VOCAB = vocabulary({
  oracle: 'O2',
  instrument: 'PropertyObserver, IR call-site state, read between passes',
  gone: O2.LOST,
  kept: O2.PRESENT,
  notInTable: ['NO_WIPE_WRITTEN', 'NOT_APPLICABLE', 'ABSENT', 'REINTRODUCED'],
});

/**
 * The gcc-side second oracle.
 *
 * `PARTIAL` is O3's own "both instruments worked and the words do not meet":
 * the function holds some zero fill but not the buffer's worth, which is
 * neither "the wipe is there" nor "the wipe is gone". It is NOT_COMPARABLE for
 * the same reason `NOT_APPLICABLE` is on the O2 side, and folding it either way
 * would decide by fiat the thing the off-diagonal is supposed to expose.
 *
 * `PARTIAL` is not in `../../../schema/interfaces.md` section 3. It is
 * `objdump_fill.py`'s word, it predates this lane, and this lane does not get to
 * add a word to that file -- see the README's "Edits requested in files this
 * lane does not own".
 */
export const O3_VOCAB = vocabulary({
  oracle: 'O3',
  instrument: 'read-wipe.py over objdump, the zero fill of one function in the linked program',
  gone: O3.ABSENT,
  kept: O3.PRESENT,
  notInTable: [O3.PARTIAL],
});

/** The vocabularies by name, so a runner can take one from an argument. */
export const VOCABULARIES = Object.freeze({ O2: O2_VOCAB, O3: O3_VOCAB });

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
 *
 * THE DEFAULT IS O2's, and the four names below are the ones this lane has
 * printed and recorded since it was written. They are DERIVED from `O2_VOCAB`
 * rather than spelled again, so that a second vocabulary cannot quietly produce
 * a fifth spelling of the same four cells: `O3_VOCAB.cells` is built by the same
 * function from `ABSENT`/`PRESENT` and reads `ELIMINATED/ABSENT` and so on.
 */
export const CELLS = O2_VOCAB.cells;
export const DIAGONAL = O2_VOCAB.diagonal;
export const OFF_DIAGONAL = O2_VOCAB.offDiagonal;

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
 *                       property here. `../../../schema/interfaces.md` section 3.1
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
  // ---- the O3 channel. Its failures are its own words, not O2's -------------
  //
  // A gcc run that filed its link failure under `o2-compile-failed` would send
  // whoever reads the exclusion list to a plugin that was never loaded. The
  // reason a cell left has to name the instrument that could not read it.
  O3_BUILD_FAILED: 'o3-build-failed',
  O3_LINK_FAILED: 'o3-link-failed',
  O3_READER_FAILED: 'o3-reader-failed',
  O3_CONTROL_NOT_MEASURED: 'o3-control-not-measured',
  O3_CONTROL_LOST: 'o3-control-lost',
  O3_NOT_A_READING: 'o3-not-a-reading',
  /**
   * THE OUTCOME WORD FOR A CELL WHOSE BYTE COUNT COULD NOT BE ESTABLISHED.
   *
   * O3 asks "does this function hold `n` bytes of zero fill", and `n` is not in
   * the tracked rows' key -- there is no buffer size anywhere in a row. Where
   * `n` cannot be established for a cell, the cell is named here and leaves the
   * denominator. It is never defaulted and never guessed: a default `n` turns
   * every surviving wipe of another size into `PARTIAL` and every reading into
   * a statement about the default. `lib/bufferbytes.mjs` is where `n` comes from
   * and what it costs.
   */
  O3_BYTES_UNESTABLISHED: 'o3-buffer-bytes-unestablished',
  /**
   * The subject's wipe is spread over more than one span, or its span is not a
   * call, so no single (caller, helper, bytes) triple describes it. Separate
   * from the byte count itself: this cell has no ONE wipe for O3 to be pointed
   * at, which is a different fact from a wipe whose length nothing could
   * evaluate.
   */
  O3_NO_SINGLE_WIPE: 'o3-no-single-wipe',
  /**
   * THE READER CANNOT SEE THIS WIPE EVEN WHERE IT CERTAINLY EXISTS.
   *
   * O3's `ABSENT` means "no zero store and no memset call in this function", and
   * `objdump_fill.py` recognises exactly three things: a vector register zeroed
   * against itself and stored, an immediate zero stored, and a call to `memset`
   * or `__memset_chk`. A wipe written any other way -- `explicit_bzero`,
   * `OPENSSL_cleanse`, `memset_s`, or a `volatile` byte loop whose single
   * one-byte store does not cover the buffer -- reads `ABSENT` or `PARTIAL`
   * WHILE BEING PLAINLY THERE. Graded, that is an elimination manufactured out
   * of the reader's symbol list.
   *
   * So every cell carries a reading of ITSELF at `-O0`, where the wipe is
   * certainly present (the tracked rows have never recorded an elimination
   * there, over 319 gcc cells and 319 clang ones). A cell whose subject does not
   * read `PRESENT` at `-O0` is a cell this reader cannot be asked about, and it
   * leaves the denominator under this word rather than contributing an
   * `ELIMINATED` nobody measured.
   */
  O3_READER_BLIND: 'o3-reader-blind-to-this-wipe',
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
  [REASON.O3_BUILD_FAILED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_LINK_FAILED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_READER_FAILED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_CONTROL_NOT_MEASURED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_CONTROL_LOST]: KIND.BROKEN_MEASUREMENT,
  // Both of these are statements about the APPARATUS -- about what O3 could be
  // configured to ask here -- and not about the wipe. Nothing about this cell's
  // wipe can be read out of this run, which is the README's own definition of
  // the word.
  [REASON.O3_BYTES_UNESTABLISHED]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_NO_SINGLE_WIPE]: KIND.BROKEN_MEASUREMENT,
  [REASON.O3_READER_BLIND]: KIND.BROKEN_MEASUREMENT,
});

/** Every reason word, so a reading cannot smuggle one this module does not know. */
export const REASON_WORDS = Object.freeze(Object.values(REASON));

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
export const ANSWER_NOT_IN_TABLE = O2_VOCAB.notInTable;

/**
 * The words that mean "there was no reading", on either side.
 *
 * `verdictOf` returns `NOT_OBSERVED` when it could not find the target function's
 * body in one of the two listings, and the observer returns it when the run
 * produced no SUMMARY row for the subject. Both are the section 3.1 situation,
 * and neither is a broken instrument.
 */
export const NO_READING_WORDS = Object.freeze(['NOT_OBSERVED']);

/**
 * Which kind a word belongs to. Everything not named by the vocabulary is about
 * the apparatus.
 *
 * The vocabulary is a PARAMETER and defaults to O2's, so every existing caller
 * keeps its answer. It has to be a parameter: `ABSENT` is NOT_COMPARABLE on the
 * O2 side, where it means the call site was never there to lose, and it is a
 * GRADABLE word on the O3 side, where it means the linked function holds no zero
 * fill. One table mapping words to kinds without saying whose words they are is
 * how the two instruments would be merged by accident.
 */
export function kindOfWord(word, vocab = O2_VOCAB) {
  if (vocab.notInTable.includes(word)) return KIND.NOT_COMPARABLE;
  if (NO_READING_WORDS.includes(word)) return KIND.NO_READING;
  return KIND.BROKEN_MEASUREMENT;
}

/** `WIPE_ELIMINATED` -> `ELIMINATED`, `WIPE_SURVIVED` -> `SURVIVED`, anything else null. */
export function o1ClassOf(verdict) {
  return Object.prototype.hasOwnProperty.call(O1_GRADABLE, verdict) ? O1_GRADABLE[verdict] : null;
}

/**
 * The second oracle's two gradable words pass through; every other state is null.
 *
 * `LOST` / `PRESENT` for O2, `ABSENT` / `PRESENT` for O3. The name is kept from
 * when there was only one second oracle; `secondClassOf` is the same function
 * under the name the two-vocabulary version deserves.
 */
export function o2ClassOf(finalState, vocab = O2_VOCAB) {
  return Object.prototype.hasOwnProperty.call(vocab.gradable, finalState) ? vocab.gradable[finalState] : null;
}
export const secondClassOf = o2ClassOf;

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
export function classifyPair(pair, { vocab = O2_VOCAB } = {}) {
  const { o1, o2 } = pair;

  if (!o1) return excluded(pair, REASON.NO_O1_ROW, null, KIND.NOT_COMPARABLE);
  if (!o2) return excluded(pair, REASON.NO_O2_READING);

  // ---- a channel that named its own failure --------------------------------
  //
  // The O3 channel has failures O2 does not have -- a link that would not
  // complete, a disassembler that would not run, a byte count nothing could
  // establish -- and it reports them as a REASON rather than as a state, so that
  // the word in the exclusion list is the instrument's own. It is validated
  // against REASON_WORDS and not merely trusted: a channel that invented a
  // reason would otherwise put a word into the exclusion table that nothing in
  // this module can classify, and `summariseExclusions` would count it under a
  // kind of `undefined` without anybody noticing.
  //
  // READ BEFORE THE CONTROL ONLY when it is the reason there is no control to
  // read. A channel that built and linked and read the program reports its
  // control in `o2.control` and reaches the control rule below like any other.
  if (o2.brokenReason !== undefined && o2.brokenReason !== null) {
    if (!REASON_WORDS.includes(o2.brokenReason)) {
      throw new Error(`classifyPair: the channel reported a reason this module does not define: ${o2.brokenReason}`);
    }
    return excluded(pair, o2.brokenReason, o2.brokenDetail, KIND.BROKEN_MEASUREMENT);
  }

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
  //
  // `subjectResolutionExit` is the O2 channel's check and the O3 channel does
  // not have one: there is no subject NAME handed to a plugin to be misspelt, so
  // a reading that carries no such field is not a reading that skipped the
  // check. `undefined` therefore passes and `null` does not -- a failed O2
  // compile sets it to `null` deliberately, so that a run which was never shown
  // to resolve its subject cannot reach the table on the strength of a check
  // that did not run. The two are different answers and this is the one place in
  // the lane where that difference is load-bearing.
  const resolutionApplies = vocab.oracle !== 'O3';
  const resolutionMissing = o2.subjectResolutionExit === undefined;
  if (resolutionApplies ? o2.subjectResolutionExit !== 0 : (!resolutionMissing && o2.subjectResolutionExit !== 0)) {
    return excluded(pair, REASON.O2_SUBJECT_UNRESOLVED, `exit ${o2.subjectResolutionExit}`);
  }
  const controlNotMeasured = vocab.oracle === 'O3' ? REASON.O3_CONTROL_NOT_MEASURED : REASON.O2_CONTROL_NOT_MEASURED;
  const controlLost = vocab.oracle === 'O3' ? REASON.O3_CONTROL_LOST : REASON.O2_CONTROL_LOST;
  if (o2.control === null || o2.control === undefined) {
    return excluded(pair, controlNotMeasured);
  }
  if (o2.control !== 'PRESENT') {
    return excluded(pair, controlLost, o2.control);
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
  const b = o2ClassOf(o2.finalState, vocab);
  if (b === null) {
    const word = o2.finalState === undefined ? null : o2.finalState;
    const notAReading = vocab.oracle === 'O3' ? REASON.O3_NOT_A_READING : REASON.O2_NOT_A_READING;
    return excluded(pair, notAReading, word, kindOfWord(word, vocab));
  }

  const cell = `${a}/${b}`;
  return {
    status: 'GRADED',
    cell,
    // THE DIAGONAL OF THE VOCABULARY THIS CELL WAS GRADED UNDER, not the
    // module's default one. This line read `DIAGONAL.includes(cell)` -- the
    // hardcoded O2 diagonal -- which put every O3 cell sitting on O3's OWN
    // diagonal (`ELIMINATED/ABSENT`, `SURVIVED/PRESENT`) on the wrong side of
    // the comparison: `ELIMINATED/ABSENT` is not in O2's `['ELIMINATED/LOST',
    // 'SURVIVED/PRESENT']`, so an agreeing gcc cell was recorded as a
    // disagreement. Since the OFF-DIAGONAL is this lane's result, that
    // manufactured findings out of a vocabulary mismatch -- the one thing the
    // parameterisation was introduced to stop.
    agrees: vocab.diagonal.includes(cell),
    id: pair.id,
    cc: pair.cc,
    opt: pair.opt,
    idiom: pair.idiom === undefined ? null : pair.idiom,
    o1Verdict: o1.verdict,
    // The column heading this cell was filed under, carried with the cell: a row
    // saying `SURVIVED/ABSENT` is unreadable without knowing whose `ABSENT`.
    secondOracle: vocab.oracle,
    o2State: o2.finalState,
    firstLossPass: o2.firstLossPass === undefined ? null : o2.firstLossPass,
  };
}

const emptyTable = (vocab = O2_VOCAB) => Object.fromEntries(vocab.cells.map((c) => [c, 0]));

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
export function degeneracyOf(table, vocab = O2_VOCAB) {
  const at = (a, b) => {
    const k = `${a}/${b}`;
    const v = table[k];
    // A missing cell is not a zero. A table built under one vocabulary and read
    // under another would otherwise produce a denominator of 0 and be reported
    // as "no cell entered the denominator" -- a run that measured nothing and a
    // run whose columns were read under the wrong headings would print the same
    // line, and the second one is a defect.
    if (typeof v !== 'number') {
      throw new Error(`degeneracyOf: this table has no cell ${k}; it was not built with the ${vocab.oracle} vocabulary`);
    }
    return v;
  };
  const o1 = {
    ELIMINATED: at(O1.ELIMINATED, vocab.gone) + at(O1.ELIMINATED, vocab.kept),
    SURVIVED: at(O1.SURVIVED, vocab.gone) + at(O1.SURVIVED, vocab.kept),
  };
  // Keyed by the second oracle's OWN two words, so a gcc record's marginal reads
  // `{ ABSENT: n, PRESENT: m }` and cannot be quoted as a count of O2's `LOST`.
  const o2 = {
    [vocab.gone]: at(O1.ELIMINATED, vocab.gone) + at(O1.SURVIVED, vocab.gone),
    [vocab.kept]: at(O1.ELIMINATED, vocab.kept) + at(O1.SURVIVED, vocab.kept),
  };
  const den = o1.ELIMINATED + o1.SURVIVED;
  const o1Degenerate = o1.ELIMINATED === 0 || o1.SURVIVED === 0;
  const o2Degenerate = o2[vocab.gone] === 0 || o2[vocab.kept] === 0;
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
export function tabulate(pairs, { classify = classifyPair, vocab = O2_VOCAB } = {}) {
  const strata = new Map();
  const stratum = (name) => {
    if (!strata.has(name)) {
      strata.set(name, { name, levels: [], table: emptyTable(vocab), graded: [], offDiagonal: [], excluded: [] });
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
    const c = classify(pair, { vocab });
    if (c.status === 'GRADED') {
      if (!Object.prototype.hasOwnProperty.call(s.table, c.cell)) {
        throw new Error(`tabulate: the classifier produced the cell ${c.cell}, which the ${vocab.oracle} table has no column for`);
      }
      s.table[c.cell] += 1;
      s.graded.push(c);
      if (vocab.offDiagonal.includes(c.cell)) s.offDiagonal.push(c);
    } else {
      s.excluded.push(c);
    }
  }

  const out = [...strata.values()].map((s) => {
    const d = degeneracyOf(s.table, vocab);
    const agree = vocab.diagonal.reduce((n, k) => n + s.table[k], 0);
    const disagree = vocab.offDiagonal.reduce((n, k) => n + s.table[k], 0);
    return {
      name: s.name,
      levels: s.levels.slice().sort(),
      table: s.table,
      // The two column headings this stratum's table is under, recorded beside
      // it. `SURVIVED/ABSENT` read without them is a cell out of some other
      // instrument's table.
      columns: { oracle: vocab.oracle, gone: vocab.gone, kept: vocab.kept },
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
    secondOracle: vocab.oracle,
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
        // The words come from the stratum's own recorded columns, never from a
        // literal here: a gcc stratum whose cells all read `ABSENT` must say
        // `ABSENT`, and a message that said `LOST` would be naming the reading
        // of an instrument that did not run.
        const cols = s.columns || { oracle: 'O2', gone: O2.LOST, kept: O2.PRESENT };
        const word = s.marginals.o2[cols.gone] === 0 ? cols.kept : cols.gone;
        reasons.push(`${s.name}: all ${s.den} graded cells read ${word} on ${cols.oracle}, the same objection in the other direction`);
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
