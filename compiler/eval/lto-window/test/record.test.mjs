/**
 * What a run writes down about itself, and what it exits with.
 *
 * Every test here is a regression test for something that was true of this lane
 * on 2026-09-12 and read as fine:
 *
 *   - `--skip-negative-control` and `--skip-gcc` left NO record, while the
 *     README said the result records the skip;
 *   - a run with the lane's only demonstration that guard 1 can fire turned off
 *     exited 0 with a clean all-OK table;
 *   - the provenance backstop described as refusing "any absolute path" was a
 *     seven-root whitelist;
 *   - the linker's per-kind line counts were computed, quoted, and dropped
 *     before the record was written;
 *   - a by-hand disassembly count in the README was wrong by 13 and nothing in
 *     the artifact could contradict it.
 *
 * No compiler is required and nothing is measured here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  SKIP_FLAG, SKIP_WHY, skippedRecord, skipSummaryLines,
  linkGuardRecord, ABSOLUTE_PATH_RE, scrubbed, exitDecision,
  INTERVENTION, ABSORBED_FILL, interventionAbsentReading, absorbedFillReading, interventionPairVerdict,
  WHICH_WIPE, whichWipeSurvived,
} from '../lib/record.mjs';
import { MEASUREMENT, STATE, REASON } from '../lib/cell.mjs';

const cell = (over = {}) => ({ id: 'xtu.full.link', measurement: MEASUREMENT.OK, state: STATE.LOST, ...over });

/** A full-LTO clang link cell, the shape the per-cell checks below are about. */
const linkCell = (over = {}) => cell({
  window: 'link', vendor: 'clang', form: 'full', guards: { byteIdentical: true }, ...over,
});

/* ------------------------------------------------------------- skipping -- */

test('a skipped check leaves a record that names the flag and what was given up', () => {
  // It used to leave `{}` -- indistinguishable, in the JSON, from a run in which
  // there was nothing to say about the negative control.
  for (const what of Object.keys(SKIP_FLAG)) {
    const r = skippedRecord(what, SKIP_WHY[what]);
    assert.equal(r.skipped, true, what);
    assert.equal(r.attempted, false, what);
    assert.equal(r.ran, false, what);
    assert.equal(r.flag, SKIP_FLAG[what], what);
    assert.ok(r.note.includes(SKIP_FLAG[what]), what);
    assert.ok(r.note.includes(SKIP_WHY[what]), what);
  }
  assert.throws(() => skippedRecord('somethingElse', 'x'), /no skip flag known/);
});

test('the skip is stated in the report\'s own summary, not only in the JSON', () => {
  assert.deepEqual(skipSummaryLines({}), []);
  const lines = skipSummaryLines({ negativeControl: true, gcc: false, thinltoEvidence: false });
  assert.equal(lines.length, 1);
  assert.ok(lines[0].includes('--skip-negative-control'));
  assert.ok(/SKIPPED/.test(lines[0]));
  assert.ok(lines[0].includes('guard 1 was not shown to fire'));
});

/* ------------------------------------------------------------ exit code -- */

test('a run whose guard demonstration was skipped cannot exit 0', () => {
  // The defect: `--skip-negative-control --skip-gcc` produced a clean all-OK
  // table and exit 0. interfaces.md section 7 reserves 0 for "everything asked
  // for was checked and nothing was found" and 3 for "a check could not be
  // completed -- never conflated with 0". With the demonstration off, nothing in
  // the run establishes that a compile-time reading would have been refused.
  const clean = [cell(), cell({ id: 'xtu.full.compile', state: STATE.ABSENT })];
  assert.equal(exitDecision({ cells: clean }).code, 0);

  const skipped = exitDecision({ cells: clean, skipped: { negativeControl: true } });
  assert.equal(skipped.code, 3);
  assert.ok(skipped.messages.some((m) => m.includes('--skip-negative-control')),
    `the reason is printed, not just the code: ${JSON.stringify(skipped.messages)}`);

  for (const what of ['gcc', 'thinltoEvidence']) {
    const d = exitDecision({ cells: clean, skipped: { [what]: true } });
    assert.equal(d.code, 3, what);
    assert.ok(d.messages.some((m) => m.includes(SKIP_FLAG[what])), what);
  }
});

test('a cell that measured OK with nothing to read is 3, not 0', () => {
  // interfaces.md 3.1's third situation is a completed RUN, not a completed
  // CHECK: the instrument worked and there was no reading of that property, so
  // the cell is ungradeable either way and 0 would claim it was checked.
  const d = exitDecision({ cells: [cell(), cell({ id: 'xtu.full.compile', state: STATE.NOT_OBSERVED })] });
  assert.equal(d.code, 3);
  assert.ok(d.messages.some((m) => m.includes('nothing to read')));
});

test('the codes that outrank 3 still outrank it', () => {
  const clean = [cell()];
  assert.equal(exitDecision({ cells: clean, toolFailure: 'xtu/full: use.c did not compile' }).code, 1);
  assert.equal(exitDecision({ cells: clean, byteFinding: true, skipped: { gcc: true } }).code, 2);
  const nc = exitDecision({
    cells: clean,
    skipped: { gcc: true },
    negativeControls: { xtu: { ran: true, fired: false } },
  });
  assert.equal(nc.code, 2, 'a guard that did not fire is a finding, not an incomplete check');
  // A negative control that DID fire is the healthy shape and says nothing.
  assert.equal(exitDecision({ cells: clean, negativeControls: { xtu: { ran: true, fired: true } } }).code, 0);
  // A skipped one is not "ran and did not fire": it is a check that did not run.
  assert.equal(
    exitDecision({ cells: clean, skipped: { negativeControl: true }, negativeControls: { xtu: skippedRecord('negativeControl', SKIP_WHY.negativeControl) } }).code,
    3);
});

test('a family that reached the cells but not the negative control cannot pass', () => {
  // The shape section 2.20(d) caught in A2: a configuration keeps its clean word
  // while the thing that establishes the word has gone quiet. A fixture family
  // is added by editing one table, and every PER-FAMILY check has to be reached
  // from that table separately -- so the way this comes back is a new family
  // whose cells are all there and whose negative control never ran. It is
  // detected by ABSENCE, because a check that did not run writes no field.
  const cells = [linkCell({ id: 'xtu.full.link' }), linkCell({ id: 'xtu-inline.full.link' })];
  const fired = { ran: true, fired: true };

  assert.equal(exitDecision({
    cells, families: ['xtu', 'xtu-inline'], negativeControls: { xtu: fired, 'xtu-inline': fired },
  }).code, 0);

  const missing = exitDecision({
    cells, families: ['xtu', 'xtu-inline'], negativeControls: { xtu: fired },
  });
  assert.equal(missing.code, 2, 'a measured family with no negative-control record is a finding, not a skip');
  assert.ok(missing.messages.some((m) => m.includes('xtu-inline')), JSON.stringify(missing.messages));

  // A family skipped BY FLAG is a different thing: that record exists, says so,
  // and is already 3 rather than 2.
  const byFlag = exitDecision({
    cells,
    families: ['xtu', 'xtu-inline'],
    skipped: { negativeControl: true },
    negativeControls: {
      xtu: skippedRecord('negativeControl', SKIP_WHY.negativeControl),
      'xtu-inline': skippedRecord('negativeControl', SKIP_WHY.negativeControl),
    },
  });
  assert.equal(byFlag.code, 3);
});

test('a full-LTO link cell whose bytes were never compared cannot pass either', () => {
  // `byteFinding` covers byteIdentical === false. `null` is the check never
  // having run on that cell -- the same silent omission, and the one a new
  // family produces if it reaches the cell path by a route that skips the stock
  // link. Scoped to the cells the check is defined for: no plugin is loaded on a
  // ThinLTO link, a gcc link or a compile.
  const nc = { xtu: { ran: true, fired: true } };
  assert.equal(exitDecision({ cells: [linkCell()], negativeControls: nc }).code, 0);

  const never = exitDecision({ cells: [linkCell({ guards: { byteIdentical: null } })], negativeControls: nc });
  assert.equal(never.code, 2);
  assert.ok(never.messages.some((m) => m.includes('non-invasive')), JSON.stringify(never.messages));

  // The cells that are not about this check are left alone.
  for (const other of [
    cell({ id: 'xtu.thin.link', window: 'link', vendor: 'clang', form: 'thin', guards: { byteIdentical: null } }),
    cell({ id: 'xtu.gcc.link', window: 'link', vendor: 'gcc', form: 'full', guards: { byteIdentical: null } }),
    cell({ id: 'xtu.full.compile', window: 'compile', vendor: 'clang', form: 'full' }),
  ]) {
    assert.equal(exitDecision({ cells: [linkCell(), other], negativeControls: nc }).code, 0, other.id);
  }
});

/* ----------------------------------------------- the intervention pair -- */

test('a broken measurement without the intervention is a fault, not the family\'s result', () => {
  // THE point of the xtu-inline family, and the way it can lie. A link cell
  // carrying no attribution is what the expected outcome looks like AND what a
  // shredded observer log looks like; in a results table they are the same row.
  // Only one of them is a reading of the intervention.
  for (const m of [MEASUREMENT.BROKEN_MEASUREMENT, MEASUREMENT.UNSUPPORTED]) {
    const r = interventionAbsentReading({
      measurement: m, state: STATE.NOT_OBSERVED, reasons: [REASON.OBSERVER_LOG_NOT_INTACT],
    });
    assert.equal(r.reading, INTERVENTION.INSTRUMENT_FAULT, m);
    assert.equal(r.usable, false, m);
    assert.ok(/says nothing|NOT the family/i.test(r.why), r.why);
  }

  // The expected outcome: the instrument was established and there is no unit
  // under the subject's name to attribute anything to.
  const absorbed = interventionAbsentReading({
    measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, reasons: [REASON.NO_SUBJECT_READING],
  });
  assert.equal(absorbed.reading, INTERVENTION.ABSORBED);
  assert.equal(absorbed.usable, true);

  // And the outcome that contradicts the pair's expectation, which is a result
  // rather than a disappointment: the unit survived without the attribute.
  const survived = interventionAbsentReading({
    measurement: MEASUREMENT.OK, state: STATE.LOST, attribution: { pass: 'DSEPass', unit: 'handle' },
  });
  assert.equal(survived.reading, INTERVENTION.UNIT_SURVIVED);
  assert.equal(survived.usable, true);
  assert.ok(survived.why.includes('DSEPass'));
});

test('once both wipes are in one body it is the byte count that discriminates', () => {
  // With the subject and the control absorbed into `main`, the verdict WORD
  // stops separating them: `PRESENT in main` is what one surviving wipe and two
  // surviving wipes both produce. 32B where the source asks for two 32B wipes is
  // one wipe gone -- and byte counting still cannot say WHICH, which is why this
  // reading is stated as necessary and not sufficient.
  const one = absorbedFillReading({ bytes: 32, memsetCalls: 0, bufferBytes: 32 });
  assert.equal(one.reading, ABSORBED_FILL.ONE);
  assert.equal(one.discriminating, true);
  assert.ok(/not on its own proof/.test(one.why), one.why);

  assert.equal(absorbedFillReading({ bytes: 64, memsetCalls: 0, bufferBytes: 32 }).reading, ABSORBED_FILL.TWO);

  // A call covers a length this reading cannot see, so it is checked BEFORE the
  // byte comparison: a memset call plus one inline wipe would otherwise read as
  // "one wipe left".
  const call = absorbedFillReading({ bytes: 32, memsetCalls: 1, bufferBytes: 32 });
  assert.equal(call.reading, ABSORBED_FILL.MEMSET_CALL);
  assert.equal(call.discriminating, false);

  // No fill at all is a blind reading, not an elimination: the control did not
  // survive either, and "the store is gone" and "there is nothing to read here"
  // are then the same sentence.
  const none = absorbedFillReading({ bytes: 0, memsetCalls: 0, bufferBytes: 32 });
  assert.equal(none.reading, ABSORBED_FILL.NONE);
  assert.equal(none.discriminating, false);

  for (const bad of [{ bytes: 48, memsetCalls: 0, bufferBytes: 32 }, { bytes: null, bufferBytes: 32 }, {}]) {
    assert.equal(absorbedFillReading(bad).discriminating, false, JSON.stringify(bad));
  }
});

test('the pair is only supported when both halves were read, from two instruments', () => {
  const intervened = { attribution: { pass: 'DSEPass', unit: 'handle' } };
  const absorbed = interventionAbsentReading({
    measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, reasons: [REASON.NO_SUBJECT_READING],
  });
  const oneWipeLeft = absorbedFillReading({ bytes: 32, memsetCalls: 0, bufferBytes: 32 });

  const ok = interventionPairVerdict({ intervenedCell: intervened, plainReading: absorbed, plainFill: oneWipeLeft });
  assert.equal(ok.supported, true);

  // The fault must not be laundered into the pair's expected outcome. This is
  // the assertion the whole family exists to make possible.
  const faulted = interventionAbsentReading({
    measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, reasons: [REASON.CONTROL_DID_NOT_HOLD],
  });
  const fault = interventionPairVerdict({ intervenedCell: intervened, plainReading: faulted, plainFill: oneWipeLeft });
  assert.equal(fault.supported, null, 'an instrument fault is not evidence for the claim');
  assert.ok(fault.why.includes('must not be reported'), fault.why);

  // The observer half alone is not the pair: without the artifact half, all that
  // has been shown is that removing the attribute blinded the observer.
  const blind = interventionPairVerdict({
    intervenedCell: intervened, plainReading: absorbed,
    plainFill: absorbedFillReading({ bytes: 32, memsetCalls: 2, bufferBytes: 32 }),
  });
  assert.equal(blind.supported, null);
  assert.ok(blind.why.includes('Half a pair'), blind.why);

  // Two contradictions, and they contradict different halves of the claim.
  const survived = interventionAbsentReading({ measurement: MEASUREMENT.OK, state: STATE.LOST });
  assert.equal(interventionPairVerdict({ intervenedCell: intervened, plainReading: survived }).supported, false);
  assert.equal(interventionPairVerdict({
    intervenedCell: intervened, plainReading: absorbed,
    plainFill: absorbedFillReading({ bytes: 64, memsetCalls: 0, bufferBytes: 32 }),
  }).supported, false);

  // And a run that never put the question says so rather than answering it.
  assert.equal(interventionPairVerdict({}).supported, null);
  assert.equal(interventionPairVerdict({ intervenedCell: { attribution: null }, plainReading: absorbed }).supported, null);
});

test('the generator emits the pair from one template, and the harness knows both halves', () => {
  // The two families are a pair only while they differ by exactly the
  // intervention. That is a property of the GENERATOR -- one template, two seds
  // -- and this test is what keeps a later edit from adding a second difference
  // by touching one heredoc and not the other.
  const generator = fs.readFileSync(new URL('../tools/make-lto-fixtures.sh', import.meta.url), 'utf8');
  assert.ok(/xtu_use_c\(\)/.test(generator), 'use.c must be emitted from one shared function');
  assert.ok(/xtu_use_c \| sed 's\/\^@NOINLINE@\$\/__attribute__\(\(noinline\)\)\//.test(generator),
    'family xtu substitutes the attribute in');
  assert.ok(/xtu_use_c \| sed '\/\^@NOINLINE@\$\/d'/.test(generator), 'family xtu-inline deletes those lines');
  // The other three units are copied, not re-emitted, so they cannot drift.
  assert.ok(/for f in io\.c wipe\.c main\.c; do cp /.test(generator));
  assert.equal(generator.split('\n').filter((l) => l === '@NOINLINE@').length, 2,
    'exactly two markers in the template: the subject and the control, and nothing else');

  const harness = fs.readFileSync(new URL('../run-lto-window.mjs', import.meta.url), 'utf8');
  assert.ok(/fixtures: \['xtu', 'xtu-inline', 'erasure'\]/.test(harness),
    'a family measured only when someone remembers to name it is a family whose result nobody has');
  assert.ok(/'xtu-inline': \{/.test(harness), 'the harness must carry the un-intervened family in its table');
  assert.ok(/pairedWith: 'xtu'/.test(harness));
});

/* --------------------------------------------------------------- guards -- */

test('a link cell publishes the linker line kinds it was measured from', () => {
  // `lineKinds` was computed by parseLldPassLog on every run, carried as far as
  // the cell, and dropped when the cell was pushed into the results -- so
  // per-kind figures quoted anywhere could be reconciled against nothing.
  const lineKinds = { 'Clearing all analysis results for': 2, 'Invalidating analysis': 89, 'Running analysis': 214, 'Running pass': 176 };
  const g = linkGuardRecord({
    inputs: { ok: true, problems: [] },
    linkerPipeline: { runs: 176, lineKinds },
    agreement: { comparable: true, subset: true, sequenceEqual: true },
    byteIdentical: true,
    debugFlagChangedBytes: false,
  });
  assert.equal(g.lldRunningPassLines, 176);
  assert.deepEqual(g.lldLineKinds, lineKinds);
  assert.equal(g.inputsOk, true);
  assert.equal(g.byteIdentical, true);
  // The ThinLTO shape has no plugin reading at all, and must still record the
  // pipeline it did see rather than dropping the whole object.
  const thin = linkGuardRecord({ inputs: { ok: true, problems: [] }, linkerPipeline: { runs: 88, lineKinds: { 'Running pass': 88 } } });
  assert.deepEqual(thin.lldLineKinds, { 'Running pass': 88 });
  assert.equal(thin.byteIdentical, null);
  assert.equal(thin.passAgreement, null);
});

/* ----------------------------------------------------------- provenance -- */

test('the provenance scan refuses an absolute path anywhere, not under seven roots', () => {
  // It used to be /(home|root|mnt|Users|tmp|var|usr)/ -- a check for the roots
  // THIS machine happens to use. A lab under any other root walked through the
  // backstop the README describes as unconditional.
  //
  // The account names below are PLACEHOLDERS. That is not cosmetic: these
  // literals were first written with the real account name of the machine they
  // were developed on, in four spellings, and scripts/check-disclosure-shape.mjs
  // reported every one of them (exit 1, HOME-DIRECTORY). It was right to. A
  // negative test is still a committed file, and the shape of a leak does not
  // stop being one because the string is there to be refused. `builder` is on
  // that checker's allow list, so these keep testing what they were written to
  // test without publishing whose machine it was.
  for (const p of [
    '/root/vg-lab/lto-window/fixtures/xtu/use.c',
    '/home/builder/lab/x.o',
    '/Users/builder/proj/x',
    'C:/Users/builder/proj/x',
    'C:\\Users\\builder\\VibeGuard\\x',
    '/opt/vg-lab/lto-window/work/app.stock',
    '/srv/lab/observer.tsv',
    '/data/builder/lab/observer.tsv',
    '/workspace/secret-project/app.observed',
  ]) {
    assert.equal(scrubbed(`  "path": "${p}"`).length, 1, `${p} must be refused`);
  }
});

test('the scan does not fire on the shapes a healthy record really contains', () => {
  // Run against the lane's own 10-cell result before being adopted: 0 hits, the
  // same as the pattern it replaced. These are the lines that make it tempting
  // to write a looser regex than this one.
  const healthy = [
    '  "okShare": { "num": 5, "den": 10 },',
    '  "excludedPassIds": ["PassManager<LazyCallGraph::SCC, CGSCCAnalysisManager, LazyCallGraph &, CGSCCUpdateResult &>"],',
    '  "stderr": ["<ld>: unrecognized option \'--load-pass-plugin=<libPropertyObserver.so>\'"],',
    '  "generatedBy": "compiler/eval/lto-window/run-lto-window.mjs",',
    '  "moduleId": "ld-temp.o",',
    '  "note": "there is no gcc pass observer in this tree either (compiler/pass-instrumentation holds three LLVM plugins)",',
    '  "host": "Linux 5.15.167.4-microsoft-standard-WSL2 x86_64",',
  ];
  for (const line of healthy) {
    assert.deepEqual(scrubbed(line), [], `must not fire on: ${line}`);
  }
  assert.ok(ABSOLUTE_PATH_RE.source.includes('A-Za-z'), 'the Windows drive half is still there');
});

/* ------------------------------------------------- the by-hand readings -- */

test('the README\'s by-hand xorb count matches the fixture it was taken from', () => {
  // The README said `handle_request` is "nineteen" xorb. It is 32 -- one per
  // byte of the fixture's 32-byte buffer, measured twice on independent builds.
  // The harness records no disassembly, so nothing in the artifact could have
  // contradicted the sentence; pinning it to the generator that emits the buffer
  // is the cheapest thing that can.
  const readme = fs.readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const generator = fs.readFileSync(new URL('../tools/make-lto-fixtures.sh', import.meta.url), 'utf8');

  const claimed = readme.match(/`handle_request` is (\d+)\s*\n?`?xorb/);
  assert.ok(claimed, 'the README must state the xorb count as a number, not a word');
  const declared = generator.match(/void handle_request\(void\)\s*\{\s*unsigned char secret\[(\d+)\]/);
  assert.ok(declared, 'the generator must declare the subject buffer');
  assert.equal(Number(claimed[1]), Number(declared[1]),
    'one xorb per byte of the buffer: full LTO promotes the buffer out of memory and the wipe has nothing left to wipe');
});

/* --- which of the two absorbed wipes is gone --------------------------------
 *
 * absorbedFillReading() gets as far as "one of them is gone" and says in its own
 * `why` that byte counting cannot say which. These tests are for the step that
 * can: delete each wipe from the source in turn, rebuild, and see which deletion
 * the linked program notices.
 *
 * Measured on this machine 2026-09-12, clang-18 -O2 full LTO, fill bytes inside
 * the absorbed `main`: as written 32, subject's wipe deleted 32, control's wipe
 * deleted 0. That is the first case below, and it is what makes the pair's claim
 * a measurement rather than a consistency argument.
 */

test("deleting the subject's wipe and changing nothing is the subject already being gone", () => {
  const r = whichWipeSurvived({ asWritten: 32, subjectCut: 32, controlCut: 0 });
  assert.equal(r.reading, WHICH_WIPE.SUBJECT_GONE);
  assert.match(r.proves, /does not depend on the intervention/);
});

test("deleting the subject's wipe and losing fill is the subject still being there", () => {
  const r = whichWipeSurvived({ asWritten: 64, subjectCut: 32, controlCut: 32 });
  assert.equal(r.reading, WHICH_WIPE.SUBJECT_PRESENT);
  assert.match(r.proves, /DID depend on the intervention/);
});

test('a control deletion that does not move the fill makes the whole reading blind', () => {
  // The positive control of this reading. Without it, "deleting the subject
  // changed nothing" is equally consistent with a build whose output does not
  // respond to the source at all -- which is the failure mode that would make
  // every cell agree with whatever was hoped for.
  for (const controlCut of [32, 64]) {
    const r = whichWipeSurvived({ asWritten: 32, subjectCut: 32, controlCut });
    assert.equal(r.reading, WHICH_WIPE.BLIND, `controlCut=${controlCut}`);
    assert.equal(r.proves, null);
  }
});

test('the blind check runs BEFORE the subject comparison, so a dead instrument never proves anything', () => {
  // Same numbers that would otherwise read SUBJECT_GONE, with a control that did
  // not respond. The order matters: read the other way round this returns the
  // strongest word in the vocabulary from a build that measured nothing.
  const r = whichWipeSurvived({ asWritten: 32, subjectCut: 32, controlCut: 32 });
  assert.notEqual(r.reading, WHICH_WIPE.SUBJECT_GONE);
  assert.equal(r.reading, WHICH_WIPE.BLIND);
});

test('a missing or nonsensical byte count is inconclusive, never one of the two answers', () => {
  for (const bad of [{}, { asWritten: 32 }, { asWritten: 32, subjectCut: 32, controlCut: null },
    { asWritten: 32, subjectCut: -1, controlCut: 0 }, { asWritten: '32', subjectCut: 32, controlCut: 0 }]) {
    const r = whichWipeSurvived(bad);
    assert.equal(r.reading, WHICH_WIPE.INCONCLUSIVE, JSON.stringify(bad));
    assert.equal(r.proves, null);
  }
});

test('fill that GROWS when a wipe is deleted is reported, not rounded to a neighbouring word', () => {
  const r = whichWipeSurvived({ asWritten: 32, subjectCut: 64, controlCut: 0 });
  assert.equal(r.reading, WHICH_WIPE.INCONCLUSIVE);
  assert.match(r.why, /RAISED/);
});

test('every reading this function can return is one of the four declared words', () => {
  const words = new Set(Object.values(WHICH_WIPE));
  assert.equal(words.size, 4);
  const cases = [
    { asWritten: 32, subjectCut: 32, controlCut: 0 },
    { asWritten: 64, subjectCut: 32, controlCut: 32 },
    { asWritten: 32, subjectCut: 32, controlCut: 32 },
    { asWritten: 32, subjectCut: 64, controlCut: 0 },
    {},
  ];
  for (const c of cases) assert.ok(words.has(whichWipeSurvived(c).reading), JSON.stringify(c));
});
