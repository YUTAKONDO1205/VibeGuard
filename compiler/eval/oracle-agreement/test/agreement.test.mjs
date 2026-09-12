/**
 * The table arithmetic, over synthetic rows. No compiler, no plugin, no corpus.
 *
 * Every number this lane prints is produced by the functions under test here,
 * and a 2x2 table is the shape of result that is hardest to audit after the
 * fact: a denominator that quietly included an excluded cell, an off-diagonal
 * counted on the wrong diagonal, a stratum that pooled `-O0` back in -- none of
 * those change anything about the output except the number, and the number is
 * the only thing anyone reads. So they are tested as arithmetic, in both
 * directions, on rows written by hand.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyPair, tabulate, degeneracyOf, laneVerdict, summariseExclusions, formatRate,
  o1ClassOf, o2ClassOf, kindOfWord, stratumOf,
  CELLS, DIAGONAL, OFF_DIAGONAL, KIND, REASON, STRATUM, O1, O2, ANSWER_NOT_IN_TABLE,
} from '../lib/agreement.mjs';

// ---------------------------------------------------------------- helpers ----

/** One cell, healthy on both sides unless told otherwise. */
const pair = (over = {}) => ({
  id: 'model_E_scen_r1',
  cc: 'clang-18',
  opt: '-O2',
  idiom: 'removable',
  o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT', control_via: 'oracle' },
  o2: { finalState: 'LOST', control: 'PRESENT', firstLossPass: 'DSEPass', subjectResolutionExit: 0 },
  ...over,
});

const withO1 = (verdict, over = {}) => pair({ o1: { verdict, control: 'PRESENT', control_via: 'oracle' }, ...over });
const withO2 = (finalState, over = {}) => pair({
  o2: { finalState, control: 'PRESENT', firstLossPass: null, subjectResolutionExit: 0 }, ...over,
});

const above = (t) => t.strata.find((s) => s.name === STRATUM.ABOVE_O0);
const atO0 = (t) => t.strata.find((s) => s.name === STRATUM.AT_O0);

// ------------------------------------------------------- the two vocabularies --

test('o1ClassOf maps the two gradable verdicts and refuses every other word', () => {
  assert.equal(o1ClassOf('WIPE_ELIMINATED'), O1.ELIMINATED);
  assert.equal(o1ClassOf('WIPE_SURVIVED'), O1.SURVIVED);
  for (const w of ['COMPILE_ERROR', 'ABLATION_DID_NOT_COMPILE', 'NOT_OBSERVED',
    'VERIFICATION_INCOMPLETE', 'NO_WIPE_WRITTEN', 'NDEBUG_NO_EFFECT', 'DEFAULT_DIFFERS']) {
    assert.equal(o1ClassOf(w), null, `${w} must not be gradable`);
  }
});

test('o1ClassOf does not fall through the prototype chain', () => {
  // `hasOwnProperty` rather than a bare lookup: 'constructor' and 'toString'
  // resolve on any plain object, and a verdict that graded because of a
  // prototype would grade silently.
  assert.equal(o1ClassOf('constructor'), null);
  assert.equal(o1ClassOf('toString'), null);
  assert.equal(o2ClassOf('constructor'), null);
});

test('o2ClassOf grades LOST and PRESENT and nothing else', () => {
  assert.equal(o2ClassOf('LOST'), O2.LOST);
  assert.equal(o2ClassOf('PRESENT'), O2.PRESENT);
  for (const w of ['ABSENT', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED', 'BROKEN_MEASUREMENT']) {
    assert.equal(o2ClassOf(w), null, `${w} must not be gradable`);
  }
});

test('kindOfWord separates an answer from a broken instrument from no reading', () => {
  for (const w of ANSWER_NOT_IN_TABLE) assert.equal(kindOfWord(w), KIND.NOT_COMPARABLE, w);
  assert.equal(kindOfWord('NOT_OBSERVED'), KIND.NO_READING);
  for (const w of ['COMPILE_ERROR', 'ABLATION_DID_NOT_COMPILE', 'VERIFICATION_INCOMPLETE',
    'BROKEN_MEASUREMENT', 'UNSUPPORTED', null]) {
    assert.equal(kindOfWord(w), KIND.BROKEN_MEASUREMENT, String(w));
  }
});

test('the four cell names, the diagonal and the off-diagonal partition them', () => {
  assert.deepEqual([...DIAGONAL, ...OFF_DIAGONAL].sort(), [...CELLS].sort());
  assert.equal(DIAGONAL.length, 2);
  assert.equal(OFF_DIAGONAL.length, 2);
  assert.deepEqual(DIAGONAL, ['ELIMINATED/LOST', 'SURVIVED/PRESENT']);
  assert.deepEqual(OFF_DIAGONAL, ['ELIMINATED/PRESENT', 'SURVIVED/LOST']);
});

// ------------------------------------------------------------- classifyPair --

test('the substantive shape: eliminated on O1, lost on O2, both controls present', () => {
  const c = classifyPair(pair());
  assert.equal(c.status, 'GRADED');
  assert.equal(c.cell, 'ELIMINATED/LOST');
  assert.equal(c.agrees, true);
  assert.equal(c.firstLossPass, 'DSEPass');
});

test('the other diagonal cell: survived on O1, present on O2', () => {
  const c = classifyPair(withO1('WIPE_SURVIVED', { o2: { finalState: 'PRESENT', control: 'PRESENT', firstLossPass: null, subjectResolutionExit: 0 } }));
  assert.equal(c.cell, 'SURVIVED/PRESENT');
  assert.equal(c.agrees, true);
});

test('both off-diagonal cells are GRADED, not excluded -- disagreement is data', () => {
  const a = classifyPair(withO1('WIPE_ELIMINATED', { o2: { finalState: 'PRESENT', control: 'PRESENT', firstLossPass: null, subjectResolutionExit: 0 } }));
  assert.equal(a.status, 'GRADED');
  assert.equal(a.cell, 'ELIMINATED/PRESENT');
  assert.equal(a.agrees, false);

  const b = classifyPair(withO1('WIPE_SURVIVED', { o2: { finalState: 'LOST', control: 'PRESENT', firstLossPass: 'DSEPass', subjectResolutionExit: 0 } }));
  assert.equal(b.status, 'GRADED');
  assert.equal(b.cell, 'SURVIVED/LOST');
  assert.equal(b.agrees, false);
});

test('a missing O1 row is NOT_COMPARABLE, not a broken instrument', () => {
  const c = classifyPair(pair({ o1: null }));
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.NO_O1_ROW);
  assert.equal(c.kind, KIND.NOT_COMPARABLE);
});

test('a missing O2 reading is a broken measurement', () => {
  const c = classifyPair(pair({ o2: null }));
  assert.equal(c.reason, REASON.NO_O2_READING);
  assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
});

test('O2 control LOST excludes the cell and carries the word it read', () => {
  const c = classifyPair(pair({ o2: { finalState: 'LOST', control: 'LOST', firstLossPass: 'DSEPass', subjectResolutionExit: 0 } }));
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.O2_CONTROL_LOST);
  assert.equal(c.detail, 'LOST');
  assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
});

test('a control that was never measured is a different exclusion from one that fell', () => {
  const notMeasured = classifyPair(pair({ o2: { finalState: 'LOST', control: null, firstLossPass: null, subjectResolutionExit: 0 } }));
  assert.equal(notMeasured.reason, REASON.O2_CONTROL_NOT_MEASURED);
  const fell = classifyPair(pair({ o2: { finalState: 'LOST', control: 'ABSENT', firstLossPass: null, subjectResolutionExit: 0 } }));
  assert.equal(fell.reason, REASON.O2_CONTROL_LOST);
  assert.notEqual(notMeasured.reason, fell.reason);
});

test('an undefined O2 control is read as not measured rather than as not PRESENT', () => {
  const c = classifyPair(pair({ o2: { finalState: 'LOST', firstLossPass: null, subjectResolutionExit: 0 } }));
  assert.equal(c.reason, REASON.O2_CONTROL_NOT_MEASURED);
});

test('the control is read BEFORE the subject: a cell with a fallen control and a perfect subject still leaves', () => {
  // The ordering is the measurement. If the subject were read first this cell
  // would have been graded ELIMINATED/LOST and counted as agreement, on a run
  // where the instrument had already been shown not to see anything.
  const c = classifyPair(pair({
    o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' },
    o2: { finalState: 'LOST', control: 'LOST', firstLossPass: 'DSEPass', subjectResolutionExit: 0 },
  }));
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.O2_CONTROL_LOST);
});

test('a compile that failed is named a failed compile, not an unresolved subject', () => {
  // Both are BROKEN_MEASUREMENT, so the denominator is the same either way. The
  // difference is where the exclusion list sends whoever reads it: one says the
  // plugin was configured with a name that is not there, the other says the
  // translation unit never built.
  const c = classifyPair(pair({
    o2: { finalState: 'BROKEN_MEASUREMENT', control: null, firstLossPass: null, subjectResolutionExit: null, compiled: false },
  }));
  assert.equal(c.reason, REASON.O2_COMPILE_FAILED);
  assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
});

test('a reading with no `compiled` field at all is still graded -- the flag is not required', () => {
  // Synthetic rows in these tests, and any future producer, may omit it. Only an
  // explicit `false` means the compile failed.
  assert.equal(classifyPair(pair()).status, 'GRADED');
});

test('a non-zero subject-resolution exit excludes the cell before anything else is read', () => {
  for (const rc of [2, 3]) {
    const c = classifyPair(pair({ o2: { finalState: 'PRESENT', control: 'PRESENT', firstLossPass: null, subjectResolutionExit: rc } }));
    assert.equal(c.reason, REASON.O2_SUBJECT_UNRESOLVED);
    assert.equal(c.detail, `exit ${rc}`);
  }
});

test('a null subject-resolution exit is not treated as 0', () => {
  // observeCell returns null when the compile failed, precisely so that a run
  // whose checker never ran cannot pass the check by default.
  const c = classifyPair(pair({ o2: { finalState: 'BROKEN_MEASUREMENT', control: null, firstLossPass: null, subjectResolutionExit: null } }));
  assert.equal(c.reason, REASON.O2_SUBJECT_UNRESOLVED);
});

test('an O1 row whose control is not PRESENT leaves the denominator', () => {
  const c = classifyPair(withO1('WIPE_SURVIVED', { o1: { verdict: 'WIPE_SURVIVED', control: 'absent' } }));
  assert.equal(c.reason, REASON.O1_CONTROL_NOT_PRESENT);
  assert.equal(c.detail, 'absent');
  assert.equal(c.kind, KIND.BROKEN_MEASUREMENT);
});

test('every non-verdict O1 word is excluded with the word in the detail', () => {
  for (const w of ['COMPILE_ERROR', 'ABLATION_DID_NOT_COMPILE', 'NOT_OBSERVED', 'VERIFICATION_INCOMPLETE', 'NO_WIPE_WRITTEN']) {
    const c = classifyPair(withO1(w));
    assert.equal(c.reason, REASON.O1_NOT_A_VERDICT, w);
    assert.equal(c.detail, w);
  }
});

test('NO_WIPE_WRITTEN is NOT_COMPARABLE while COMPILE_ERROR is BROKEN_MEASUREMENT', () => {
  assert.equal(classifyPair(withO1('NO_WIPE_WRITTEN')).kind, KIND.NOT_COMPARABLE);
  assert.equal(classifyPair(withO1('COMPILE_ERROR')).kind, KIND.BROKEN_MEASUREMENT);
  assert.equal(classifyPair(withO1('NOT_OBSERVED')).kind, KIND.NO_READING);
});

test('NOT_APPLICABLE on O2 is an answer with no column, not a failure', () => {
  const c = classifyPair(withO2('NOT_APPLICABLE'));
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.reason, REASON.O2_NOT_A_READING);
  assert.equal(c.detail, 'NOT_APPLICABLE');
  assert.equal(c.kind, KIND.NOT_COMPARABLE);
});

test('ABSENT on O2 is never folded into LOST, however tempting the reading', () => {
  // A wipe lowered away before the pipeline's first observation point reads
  // ABSENT here and would very plausibly read WIPE_ELIMINATED over there.
  // Mapping it would assume the conclusion this lane is measuring.
  const c = classifyPair(withO2('ABSENT'));
  assert.equal(c.status, 'EXCLUDED');
  assert.equal(c.kind, KIND.NOT_COMPARABLE);
  assert.notEqual(c.cell, 'ELIMINATED/LOST');
});

test('REINTRODUCED on O2 is its own answer and leaves the table', () => {
  const c = classifyPair(withO2('REINTRODUCED'));
  assert.equal(c.reason, REASON.O2_NOT_A_READING);
  assert.equal(c.kind, KIND.NOT_COMPARABLE);
});

test('NOT_OBSERVED on O2 is NO_READING -- the instrument ran and found nothing to read', () => {
  const c = classifyPair(withO2('NOT_OBSERVED'));
  assert.equal(c.kind, KIND.NO_READING);
  assert.notEqual(c.kind, KIND.BROKEN_MEASUREMENT);
});

test('an excluded cell still carries id, vendor, level and idiom so it can be diagnosed', () => {
  const c = classifyPair(pair({ id: 'x_E_y_r2', cc: 'gcc-13', opt: '-Os', idiom: 'both', o2: null }));
  assert.equal(c.id, 'x_E_y_r2');
  assert.equal(c.cc, 'gcc-13');
  assert.equal(c.opt, '-Os');
  assert.equal(c.idiom, 'both');
});

// ------------------------------------------------------------- degeneracy ----

test('degeneracyOf computes both marginals and the denominator', () => {
  const d = degeneracyOf({ 'ELIMINATED/LOST': 3, 'ELIMINATED/PRESENT': 1, 'SURVIVED/LOST': 2, 'SURVIVED/PRESENT': 4 });
  assert.deepEqual(d.marginals.o1, { ELIMINATED: 4, SURVIVED: 6 });
  assert.deepEqual(d.marginals.o2, { LOST: 5, PRESENT: 5 });
  assert.equal(d.den, 10);
  assert.equal(d.o1Degenerate, false);
  assert.equal(d.o2Degenerate, false);
  assert.equal(d.any, false);
});

test('an all-SURVIVED column is degenerate on O1 even when O2 said both words', () => {
  const d = degeneracyOf({ 'ELIMINATED/LOST': 0, 'ELIMINATED/PRESENT': 0, 'SURVIVED/LOST': 3, 'SURVIVED/PRESENT': 7 });
  assert.equal(d.o1Degenerate, true);
  assert.equal(d.o2Degenerate, false);
  assert.equal(d.any, true);
});

test('an all-PRESENT column is degenerate on O2 even when O1 said both words', () => {
  const d = degeneracyOf({ 'ELIMINATED/LOST': 0, 'ELIMINATED/PRESENT': 5, 'SURVIVED/LOST': 0, 'SURVIVED/PRESENT': 5 });
  assert.equal(d.o1Degenerate, false);
  assert.equal(d.o2Degenerate, true);
});

test('an empty table is degenerate on both sides -- it has no mass to put anywhere', () => {
  const d = degeneracyOf({ 'ELIMINATED/LOST': 0, 'ELIMINATED/PRESENT': 0, 'SURVIVED/LOST': 0, 'SURVIVED/PRESENT': 0 });
  assert.equal(d.den, 0);
  assert.equal(d.o1Degenerate, true);
  assert.equal(d.o2Degenerate, true);
});

// ------------------------------------------------------------ stratification --

test('stratumOf puts -O0 on its own and every other level together', () => {
  assert.equal(stratumOf('-O0'), STRATUM.AT_O0);
  for (const o of ['-O1', '-O2', '-O3', '-Os', '-Ofast', '-Oz']) {
    assert.equal(stratumOf(o), STRATUM.ABOVE_O0, o);
  }
});

test('-O0 cells never enter the above--O0 table, however they read', () => {
  const t = tabulate([
    pair({ id: 'a', opt: '-O0', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    pair({ id: 'b', opt: '-O0', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    pair({ id: 'c', opt: '-O2' }),
  ]);
  assert.equal(atO0(t).den, 2);
  assert.equal(above(t).den, 1);
  assert.equal(atO0(t).table['SURVIVED/PRESENT'], 2);
  assert.equal(above(t).table['ELIMINATED/LOST'], 1);
});

test('an -O0 stratum of perfect agreement is reported as NOT discriminating', () => {
  // Section 2.20(d): at -O0 both spike subjects read WIPE_SURVIVED, so the
  // configuration has no discriminating power. 2/2 there is what an instrument
  // stuck on one word would also score.
  const t = tabulate([0, 1, 2, 3].map((i) => pair({
    id: `z${i}`, opt: '-O0',
    o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 },
  })));
  const s = atO0(t);
  assert.equal(s.agree, 4);
  assert.equal(s.den, 4);
  assert.equal(formatRate(s.agreement), '4/4 (100.0%)');
  assert.equal(s.discriminating, false);
  assert.equal(s.degenerate.o1, true);
});

test('both strata exist even when nothing landed in one of them', () => {
  const t = tabulate([pair()]);
  assert.equal(t.strata.length, 2);
  assert.equal(atO0(t).den, 0);
  assert.equal(atO0(t).levels.length, 0);
  assert.equal(above(t).levels.join(','), '-O2');
});

test('a stratum lists the levels that actually landed in it, sorted', () => {
  const t = tabulate([pair({ opt: '-Os' }), pair({ opt: '-O1' }), pair({ opt: '-O2' }), pair({ opt: '-O1' })]);
  assert.deepEqual(above(t).levels, ['-O1', '-O2', '-Os']);
});

// ----------------------------------------------------------- the arithmetic --

test('the four cells sum to the denominator and the two diagonals sum to it too', () => {
  const t = tabulate([
    pair({ id: 'a' }),
    pair({ id: 'b', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    withO1('WIPE_SURVIVED', { id: 'c', o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } }),
    withO1('WIPE_SURVIVED', { id: 'd', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  const s = above(t);
  assert.equal(CELLS.reduce((n, k) => n + s.table[k], 0), s.den);
  assert.equal(s.agree + s.disagree, s.den);
  assert.equal(s.den, 4);
  assert.equal(s.agree, 2);
  assert.equal(s.disagree, 2);
});

test('every cell seen is accounted for -- graded plus excluded, with nothing lost', () => {
  const pairs = [
    pair({ id: 'a' }),
    pair({ id: 'b', o2: null }),
    withO1('COMPILE_ERROR', { id: 'c' }),
    withO2('NOT_APPLICABLE', { id: 'd' }),
    pair({ id: 'e', opt: '-O0' }),
    pair({ id: 'f', opt: '-O0', o1: null }),
  ];
  const t = tabulate(pairs);
  assert.equal(t.seen, 6);
  assert.equal(t.accountedFor, 6);
  for (const s of t.strata) assert.equal(s.accountedFor, s.den + s.excluded.total);
});

test('an excluded cell is never in the denominator', () => {
  const t = tabulate([pair({ o2: { finalState: 'LOST', control: 'LOST', subjectResolutionExit: 0 } })]);
  assert.equal(above(t).den, 0);
  assert.equal(above(t).excluded.total, 1);
  assert.equal(above(t).agreement.den, 0);
});

test('formatRate never prints a percentage of nothing', () => {
  assert.equal(formatRate({ num: 0, den: 0 }), '0/0 (no cell entered the denominator)');
  assert.equal(formatRate({ num: 0, den: 4 }), '0/4 (0.0%)');
  assert.equal(formatRate({ num: 1, den: 3 }), '1/3 (33.3%)');
});

// ------------------------------------------------------- off-diagonal listing --

test('every off-diagonal cell is listed individually by id', () => {
  const t = tabulate([
    withO1('WIPE_ELIMINATED', { id: 'm2', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    withO1('WIPE_SURVIVED', { id: 'm1', o2: { finalState: 'LOST', control: 'PRESENT', firstLossPass: 'DSEPass', subjectResolutionExit: 0 } }),
    pair({ id: 'ok' }),
  ]);
  const s = above(t);
  assert.equal(s.disagree, 2);
  assert.equal(s.offDiagonal.length, 2);
  assert.deepEqual(s.offDiagonal.map((c) => c.id), ['m2', 'm1']);
  assert.deepEqual(s.offDiagonal.map((c) => c.cell), ['ELIMINATED/PRESENT', 'SURVIVED/LOST']);
});

test('the off-diagonal listing carries what a diagnosis needs, including the losing pass', () => {
  const t = tabulate([withO1('WIPE_SURVIVED', {
    id: 'q_E_r_r1', cc: 'gcc-13', opt: '-O3', idiom: 'nonremovable',
    o2: { finalState: 'LOST', control: 'PRESENT', firstLossPass: 'DSEPass', subjectResolutionExit: 0 },
  })]);
  const [c] = above(t).offDiagonal;
  assert.deepEqual(
    { id: c.id, cc: c.cc, opt: c.opt, idiom: c.idiom, o1: c.o1Verdict, o2: c.o2State, pass: c.firstLossPass },
    { id: 'q_E_r_r1', cc: 'gcc-13', opt: '-O3', idiom: 'nonremovable', o1: 'WIPE_SURVIVED', o2: 'LOST', pass: 'DSEPass' },
  );
});

test('the off-diagonal listing is deterministic -- the same cells in any input order print the same', () => {
  const mk = (id, cc) => withO1('WIPE_SURVIVED', { id, cc, o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } });
  const forward = above(tabulate([mk('b', 'clang-18'), mk('a', 'gcc-13'), mk('a', 'clang-18')])).offDiagonal;
  const backward = above(tabulate([mk('a', 'clang-18'), mk('a', 'gcc-13'), mk('b', 'clang-18')])).offDiagonal;
  assert.deepEqual(forward.map((c) => `${c.id}|${c.cc}`), backward.map((c) => `${c.id}|${c.cc}`));
  assert.deepEqual(forward.map((c) => `${c.id}|${c.cc}`), ['a|clang-18', 'a|gcc-13', 'b|clang-18']);
});

test('a diagonal cell never appears in the off-diagonal listing', () => {
  const t = tabulate([pair(), withO1('WIPE_SURVIVED', { o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } })]);
  assert.equal(above(t).offDiagonal.length, 0);
  assert.equal(above(t).agree, 2);
});

test('off-diagonal cells are counted in the denominator -- disagreement is graded, not excluded', () => {
  const t = tabulate([withO1('WIPE_SURVIVED', { o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } })]);
  assert.equal(above(t).den, 1);
  assert.equal(above(t).excluded.total, 0);
  assert.equal(above(t).agree, 0);
});

// ------------------------------------------------------------- exclusions ----

test('summariseExclusions counts by reason, by kind, and lists every cell', () => {
  const rows = [
    { id: 'b', cc: 'clang-18', opt: '-O2', reason: REASON.O2_CONTROL_LOST, detail: 'LOST', kind: KIND.BROKEN_MEASUREMENT },
    { id: 'a', cc: 'clang-18', opt: '-O2', reason: REASON.O2_CONTROL_LOST, detail: 'LOST', kind: KIND.BROKEN_MEASUREMENT },
    { id: 'c', cc: 'gcc-13', opt: '-O2', reason: REASON.O2_NOT_A_READING, detail: 'NOT_APPLICABLE', kind: KIND.NOT_COMPARABLE },
  ];
  const s = summariseExclusions(rows);
  assert.equal(s.total, 3);
  assert.equal(s.byKind[KIND.BROKEN_MEASUREMENT], 2);
  assert.equal(s.byKind[KIND.NOT_COMPARABLE], 1);
  assert.equal(s.byKind[KIND.NO_READING], 0);
  assert.equal(s.byReason['o2-control-lost(LOST)'], 2);
  assert.equal(s.byReason['o2-not-a-reading(NOT_APPLICABLE)'], 1);
  assert.equal(s.cells.length, 3);
});

test('the exclusion list is never truncated -- a count without names is a quiet drop', () => {
  const many = Array.from({ length: 37 }, (_, i) => pair({ id: `id${String(i).padStart(3, '0')}`, o2: null }));
  const s = above(tabulate(many)).excluded;
  assert.equal(s.total, 37);
  assert.equal(s.cells.length, 37);
  assert.equal(new Set(s.cells.map((c) => c.id)).size, 37);
});

test('the exclusion list is sorted deterministically', () => {
  const mk = (id) => pair({ id, o2: null });
  const one = above(tabulate([mk('c'), mk('a'), mk('b')])).excluded.cells.map((c) => c.id);
  const two = above(tabulate([mk('b'), mk('c'), mk('a')])).excluded.cells.map((c) => c.id);
  assert.deepEqual(one, ['a', 'b', 'c']);
  assert.deepEqual(one, two);
});

test('exclusions are stratified too -- an -O0 exclusion is not counted above -O0', () => {
  const t = tabulate([pair({ opt: '-O0', o2: null }), pair({ opt: '-O2', o2: null })]);
  assert.equal(atO0(t).excluded.total, 1);
  assert.equal(above(t).excluded.total, 1);
});

test('the three kinds are always present as keys, so a zero is visible rather than missing', () => {
  const s = summariseExclusions([]);
  assert.deepEqual(Object.keys(s.byKind).sort(), [KIND.BROKEN_MEASUREMENT, KIND.NO_READING, KIND.NOT_COMPARABLE].sort());
  for (const k of Object.keys(s.byKind)) assert.equal(s.byKind[k], 0);
});

// ------------------------------------------------------------ laneVerdict ----

test('perfect agreement above -O0 exits 0', () => {
  const t = tabulate([
    pair({ id: 'a' }),
    withO1('WIPE_SURVIVED', { id: 'b', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  const v = laneVerdict(t);
  assert.equal(v.code, 0);
  assert.equal(v.readable, true);
  assert.deepEqual(v.reasons, []);
});

test('PERFECT DISAGREEMENT ALSO EXITS 0 -- the exit code is not "0 iff they agree"', () => {
  // This is the test that stops the lane acquiring an incentive.
  const t = tabulate([
    withO1('WIPE_ELIMINATED', { id: 'a', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    withO1('WIPE_SURVIVED', { id: 'b', o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  const v = laneVerdict(t);
  assert.equal(above(t).agree, 0);
  assert.equal(above(t).disagree, 2);
  assert.equal(v.code, 0);
  assert.equal(v.readable, true);
});

test('an -O0-only run exits 2 however perfectly the two instruments agreed there', () => {
  const t = tabulate([0, 1, 2].map((i) => pair({
    id: `z${i}`, opt: '-O0',
    o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
    o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 },
  })));
  assert.equal(atO0(t).agree, 3);
  const v = laneVerdict(t);
  assert.equal(v.code, 2);
  assert.equal(v.readable, false);
  assert.match(v.reasons.join(' '), /no cell entered the denominator/);
});

test('a uniform O1 column above -O0 exits 2, and the reason says which word it was stuck on', () => {
  const t = tabulate([0, 1, 2, 3].map((i) => withO1('WIPE_SURVIVED', {
    id: `s${i}`, o2: { finalState: i < 2 ? 'PRESENT' : 'LOST', control: 'PRESENT', subjectResolutionExit: 0 },
  })));
  const v = laneVerdict(t);
  assert.equal(v.code, 2);
  assert.match(v.reasons.join(' '), /all 4 graded cells read SURVIVED on O1/);
});

test('a uniform O2 column above -O0 exits 2 with the objection in the other direction', () => {
  const t = tabulate([
    pair({ id: 'a' }),
    withO1('WIPE_SURVIVED', { id: 'b', o2: { finalState: 'LOST', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  const v = laneVerdict(t);
  assert.equal(above(t).degenerate.o2, true);
  assert.equal(v.code, 2);
  assert.match(v.reasons.join(' '), /read LOST on O2/);
});

test('a run in which everything was excluded exits 2 and says how many', () => {
  const t = tabulate([pair({ id: 'a', o2: null }), pair({ id: 'b', o2: null })]);
  const v = laneVerdict(t);
  assert.equal(v.code, 2);
  assert.match(v.reasons.join(' '), /no cell entered the denominator \(2 excluded\)/);
});

test('the verdict carries its own meaning, so the exit code cannot be read without it', () => {
  const v = laneVerdict(tabulate([pair()]));
  assert.match(v.meaning, /PERFORMED/);
  assert.match(v.meaning, /disagreement exits 0/);
});

test('laneVerdict looks only above -O0: a discriminating -O0 stratum does not rescue an empty one above it', () => {
  // Constructed rather than expected: the tracked rows have never put an
  // elimination at -O0. If one ever appeared, this lane must still refuse to
  // let it stand in for a level that can discriminate.
  const t = tabulate([
    pair({ id: 'a', opt: '-O0' }),
    withO1('WIPE_SURVIVED', { id: 'b', opt: '-O0', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  assert.equal(atO0(t).discriminating, true);
  assert.equal(laneVerdict(t).code, 2);
});

test('one discriminating stratum above -O0 is enough, and mixed levels pool within it', () => {
  const t = tabulate([
    pair({ id: 'a', opt: '-O1' }),
    withO1('WIPE_SURVIVED', { id: 'b', opt: '-Os', o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
    pair({ id: 'c', opt: '-O0', o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' }, o2: { finalState: 'PRESENT', control: 'PRESENT', subjectResolutionExit: 0 } }),
  ]);
  assert.equal(laneVerdict(t).code, 0);
  assert.deepEqual(above(t).levels, ['-O1', '-Os']);
});

test('tabulate takes an injected classifier, so the table can be tested apart from the rules', () => {
  const always = () => ({ status: 'GRADED', cell: 'SURVIVED/LOST', agrees: false, id: 'x', cc: 'c', opt: '-O2', idiom: null, o1Verdict: 'WIPE_SURVIVED', o2State: 'LOST', firstLossPass: null });
  const t = tabulate([pair(), pair()], { classify: always });
  assert.equal(above(t).table['SURVIVED/LOST'], 2);
  assert.equal(above(t).disagree, 2);
});
