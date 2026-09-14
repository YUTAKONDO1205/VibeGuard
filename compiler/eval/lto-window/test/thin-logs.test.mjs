/**
 * The ThinLTO cell, and the three ways it used to lie.
 *
 * Each test below has a mutation it is here to catch, and all three mutations
 * were restored and re-run on 2026-09-14 to check that the test goes red rather
 * than merely existing:
 *
 *   1  put the unconditional `refusal: { BROKEN_MEASUREMENT,
 *      plugin-multi-passbuilder }` back into run-lto-window.mjs's thin branch
 *      -> "an intact ThinLTO link is graded from its evidence" fails.
 *   2  make the reader treat a manifest line with no log as fine
 *      -> "a backend in the manifest with no log beside it is not a reading"
 *      fails.
 *   3  decide subject resolution from the first log only
 *      -> "the subject is resolved across every backend, not the first one"
 *      fails, with the subject in the LAST backend.
 *
 * The inputs are synthetic on purpose. A lost backend is a race losing to
 * another race and cannot be induced on demand on a working machine; the
 * reading the harness builds from a real link is a plain object, so the honest
 * way to test "what happens when one is missing" is to hand the grader that
 * object with one entry's `logPresent` false. What connects these fixtures to a
 * real link is `test/thin-logs-real-shape` at the bottom, which asserts the
 * fixture shape here is the shape readThinLtoBackends() builds.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  parseModuleManifest, gradeThinLtoCell, foldPassAgreements, resolutionAcrossBackends,
} from '../lib/thin-logs.mjs';
import { MEASUREMENT, STATE, REASON } from '../lib/cell.mjs';

/* ------------------------------------------------------------ fixtures -- */

const AGREE = Object.freeze({
  comparable: true, subset: true, sequenceEqual: false,
  counts: { observerBeforeCallbacks: 276, observerCompared: 227, lldRunningPassLines: 376 },
  observerOnly: [], excludedPassIds: ['PassManager<Function>'],
});

/** A SUMMARY row in the shape lib/pass-log.mjs's parseSummaryRow() returns. */
const row = (unit, role, over = {}) => ({
  unit, lineage: unit, role,
  firstLossSeq: null, firstLossPass: null,
  finalState: STATE.PRESENT, everPresent: true, everLost: false, everReintroduced: false,
  fate: 'LIVE',
  ...over,
});

const LOST_SUBJECT = row('handle', 'subject', {
  firstLossSeq: 248, firstLossPass: 'DSEPass', finalState: STATE.LOST, everLost: true,
});
const HELD_CONTROL = row('wipe_kept', 'control');

/** One backend's reading, healthy, with nothing of the subject in it. */
const bystander = (moduleId, over = {}) => ({
  moduleId,
  logPresent: true,
  logBytes: 14205,
  logIntact: true,
  handshakeRecords: 1,
  handshakeModuleIds: [moduleId],
  nulBytes: 0,
  tornLines: 0,
  tornLineSamples: [],
  passRecords: 124,
  evRecords: 0,
  summarySource: 'none',
  summaryIntact: null,
  summaryUnits: [],
  subjectResolution: 'not-in-module',
  controlResolution: 'not-in-module',
  subjectRow: null,
  controlRow: null,
  passAgreement: AGREE,
  ...over,
});

/** The backend that actually holds the subject and the control. */
const carrier = (moduleId, over = {}) => bystander(moduleId, {
  logBytes: 70286,
  evRecords: 496,
  passRecords: 276,
  summarySource: 'main',
  summaryIntact: true,
  summaryUnits: ['handle', 'wipe_kept'],
  subjectResolution: 'resolved',
  controlResolution: 'resolved',
  subjectRow: LOST_SUBJECT,
  controlRow: HELD_CONTROL,
  ...over,
});

/** A default-thread-pool link whose per-module logs all came back whole. */
const concurrentOk = (n) => ({
  linkRc: 0, manifest: { present: true, lines: n, malformedLines: 0 },
  logsRead: n, logsMissing: [], handshakeRecords: n, nulBytes: 0, tornLines: 0, intact: true,
});

const evidenceOf = (modules, over = {}) => ({
  attempted: true,
  linkRc: 0,
  byteIdentical: true,
  serialisedThinltoJobs: 1,
  concurrent: concurrentOk(modules.length),
  manifest: { present: true, lines: modules.length, malformedLines: 0 },
  modules,
  ...over,
});

const GUARDS = Object.freeze({
  inputs: { ok: true, problems: [] },
  linkerPipeline: { runs: 376, lineKinds: { 'Running pass': 376 } },
});

const grade = (evidence, over = {}) => gradeThinLtoCell({ evidence, ...GUARDS, ...over });

/* ------------------------------------------------- D1: graded, not told -- */

test('an intact ThinLTO link is graded from its evidence, not refused by construction', () => {
  // MUTATION 1. This is the test that goes red when the unconditional refusal
  // is put back. The numbers are the ones the xtu family really produced on
  // 2026-09-14 with the per-module observer: three backends, one HANDSHAKE
  // each, no NUL bytes, `handle` LOST at DSEPass in use.o.
  const cell = grade(evidenceOf([bystander('<main.o>'), carrier('<use.o>'), bystander('<wipe.o>')]));
  assert.equal(cell.measurement, MEASUREMENT.OK);
  assert.equal(cell.state, STATE.LOST);
  assert.deepEqual(cell.attribution, { pass: 'DSEPass', unit: 'handle', checkpoint: 'after-pass' });
  assert.equal(cell.controlHeld, true);
  assert.ok(!cell.reasons.includes(REASON.MULTI_PASSBUILDER),
    'a link whose logs all came back whole has not measured the multi-PassBuilder defect');
});

test('plugin-multi-passbuilder is now reachable ONLY from a shredded log', () => {
  // The word keeps its meaning and loses its other four jobs. This is what
  // makes the first test above a real check rather than a relabelling: if
  // MULTI_PASSBUILDER could still come from "we did not look" or "a log is
  // missing", "the cell was refused" would carry no information.
  const shredded = grade(evidenceOf([
    carrier('<use.o>'),
    bystander('<wipe.o>', { logIntact: false, handshakeRecords: 4, nulBytes: 9, tornLines: 25 }),
  ]));
  assert.equal(shredded.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(shredded.state, STATE.NOT_OBSERVED);
  assert.equal(shredded.reasons[0], REASON.MULTI_PASSBUILDER);
  assert.match(shredded.reasons[1], /<wipe\.o>: 4 HANDSHAKE record\(s\), 9 NUL byte\(s\), 25 torn line\(s\)/);

  for (const [evidence, reason] of [
    [null, REASON.THINLTO_EVIDENCE_NOT_TAKEN],
    [{ skipped: true, check: 'thinltoEvidence' }, REASON.THINLTO_EVIDENCE_NOT_TAKEN],
    [{ attempted: true, linkFailed: true, where: 'observed ThinLTO', linkRc: 1 }, REASON.THINLTO_LINK_FAILED],
    [evidenceOf([], { manifest: { present: false, lines: 0, malformedLines: 0 } }), REASON.THINLTO_NO_MANIFEST],
  ]) {
    const cell = grade(evidence);
    assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
    assert.equal(cell.reasons[0], reason);
    assert.ok(!cell.reasons.includes(REASON.MULTI_PASSBUILDER),
      `${reason} must not also assert the multi-PassBuilder defect`);
  }
});

test('a shredded DEFAULT-pool link refuses the cell even when the serialised logs are perfect', () => {
  // Serialising the backends is how the reading gets a usable linker log, and
  // it is also how a lane could accidentally buy itself a green reading of the
  // one defect it exists to detect: `--thinlto-jobs=1` cannot show a race. So
  // the concurrent link gates the cell. The `modules` below are the SERIALISED
  // link's, and they are flawless.
  const cell = grade(evidenceOf([carrier('<use.o>'), bystander('<wipe.o>')], {
    concurrent: {
      linkRc: 0, manifest: { present: false, lines: 0, malformedLines: 0 },
      logsRead: 1, handshakeRecords: 78, nulBytes: 9, tornLines: 25, intact: false,
    },
  }));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(cell.reasons[0], REASON.MULTI_PASSBUILDER);
  assert.match(cell.reasons[1], /DEFAULT thread pool/);
  assert.match(cell.reasons[1], /78 HANDSHAKE record\(s\), 9 NUL byte\(s\), 25 torn line\(s\)/);
});

test('a MISSING DEFAULT-pool reading refuses the cell too, and does not read as a good one', () => {
  // The gate above was written `if (cc && cc.intact !== true)`, which asks
  // whether the concurrent reading is BAD and never whether it is THERE. With
  // the reading absent the `cc &&` short-circuits, the gate is skipped, and the
  // cell is graded from the serialised link alone -- indistinguishable, in the
  // published record, from a run where concurrency was measured and was fine.
  // Found by probing the fix rather than the code it replaced, on 2026-09-14.
  //
  // Not reachable from run-lto-window.mjs today: thinLtoEvidence() either sets
  // `concurrent` or returns `linkFailed`, which an earlier guard catches. This
  // pins the branch against the next edit, and it is deliberately asserted
  // against the SAME flawless serialised modules the passing case uses, so what
  // it measures is the gate and not the reading.
  const modules = [carrier('<use.o>'), bystander('<wipe.o>')];
  const good = grade(evidenceOf(modules));
  assert.equal(good.measurement, MEASUREMENT.OK,
    'the same modules grade OK when the concurrent reading is present and intact');

  for (const absent of [undefined, null]) {
    const cell = grade(evidenceOf(modules, { concurrent: absent }));
    assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT, `concurrent: ${String(absent)}`);
    assert.equal(cell.reasons[0], REASON.MULTI_PASSBUILDER);
    assert.match(cell.reasons[1], /no DEFAULT-thread-pool reading was taken/);
    assert.equal(cell.attribution, null,
      'a cell with no concurrency evidence must not publish an attribution');
  }
});

test('a skipped ThinLTO run says the evidence was not taken, and never that the defect was seen', () => {
  const cell = grade({ skipped: true, check: 'thinltoEvidence', why: 'flag' });
  assert.equal(cell.reasons[0], REASON.THINLTO_EVIDENCE_NOT_TAKEN);
  assert.equal(cell.state, STATE.NOT_OBSERVED);
  assert.equal(cell.attribution, null);
});

/* ------------------------------------- D2: all the logs, not the first -- */

test('a backend in the manifest with no log beside it is not a reading', () => {
  // MUTATION 2. Restore "ignore a missing log" -- drop the `lost` check, or
  // filter `!logPresent` entries out of `readings` before grading -- and this
  // goes red: the remaining two backends are perfectly healthy and one of them
  // carries the subject, so the cell comes back OK / LOST with an attribution
  // taken from a link a third of whose history is gone.
  const cell = grade(evidenceOf([
    carrier('<use.o>'),
    bystander('<wipe.o>'),
    { moduleId: '<main.o>', logPresent: false, logBytes: 0, logIntact: null },
  ]));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(cell.state, STATE.NOT_OBSERVED);
  assert.equal(cell.attribution, null);
  assert.equal(cell.reasons[0], REASON.THINLTO_BACKEND_LOG_LOST);
  assert.ok(cell.reasons.some((r) => r.includes('<main.o>')),
    'the refusal has to name the backend whose history is missing, or a reader cannot act on it');
});

test('a torn manifest line is a lost backend too', () => {
  const cell = grade(evidenceOf([carrier('<use.o>'), bystander('<wipe.o>')],
    { manifest: { present: true, lines: 3, malformedLines: 1 } }));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(cell.reasons[0], REASON.THINLTO_BACKEND_LOG_LOST);
  assert.ok(cell.reasons.some((r) => r.includes('torn manifest line')));
});

test('no manifest under ThinLTO is refused, not read as a single-module link', () => {
  // The shape that matters: an observer WITHOUT the per-module change writes no
  // manifest and leaves one shredded <OBS_OUT> behind, which is the same shape
  // a one-backend link has. A reader that took the absence for "there was only
  // one backend" would rebuild the defect on the reading side.
  const cell = grade(evidenceOf([], { manifest: { present: false, lines: 0, malformedLines: 0 } }));
  assert.equal(cell.reasons[0], REASON.THINLTO_NO_MANIFEST);
  assert.match(cell.reasons[1], /single-module link/);

  const empty = grade(evidenceOf([], { manifest: { present: true, lines: 0, malformedLines: 0 } }));
  assert.equal(empty.reasons[0], REASON.THINLTO_NO_MANIFEST);
  assert.match(empty.reasons[1], /no tracker reached a module boundary/);
});

test('the subject is resolved across every backend, not the first one', () => {
  // MUTATION 3. Decide resolution from readings[0] and this goes red: the
  // subject is in the LAST backend here, the first two say `not-in-module`,
  // and a first-log reader calls that `subject-did-not-resolve` -- refusing a
  // link in which the subject resolved perfectly well. Which backend is first
  // is a race (measured twice on one fixture with two different winners), so
  // the order below is not a detail.
  const last = grade(evidenceOf([bystander('<main.o>'), bystander('<wipe.o>'), carrier('<use.o>')]));
  assert.equal(last.measurement, MEASUREMENT.OK);
  assert.equal(last.state, STATE.LOST);
  assert.ok(!last.reasons.includes(REASON.SUBJECT_DID_NOT_RESOLVE));

  // ... and the same evidence in every other order reads the same way, which
  // is the property a race makes necessary.
  const mods = [bystander('<main.o>'), bystander('<wipe.o>'), carrier('<use.o>')];
  for (let i = 0; i < mods.length; i++) {
    const rotated = [...mods.slice(i), ...mods.slice(0, i)];
    const cell = grade(evidenceOf(rotated));
    assert.equal(cell.measurement, MEASUREMENT.OK, `rotation ${i} changed the verdict`);
    assert.deepEqual(cell.attribution, { pass: 'DSEPass', unit: 'handle', checkpoint: 'after-pass' });
  }
});

test('`declaration-only` and `not-in-module` in the other backends are the normal case', () => {
  // The xtu family really produces all three words in one link: `use.o`
  // resolved, `main.o` declaration-only (it calls the subject), `wipe.o`
  // not-in-module. None of that is a fault.
  const cell = grade(evidenceOf([
    bystander('<main.o>', { subjectResolution: 'declaration-only', controlResolution: 'declaration-only' }),
    carrier('<use.o>'),
    bystander('<wipe.o>'),
  ]));
  assert.equal(cell.measurement, MEASUREMENT.OK);
  assert.equal(cell.reasons.length, 0);
});

test('a subject that resolved in NO backend is subject-did-not-resolve', () => {
  const cell = grade(evidenceOf([
    bystander('<main.o>', { evRecords: 3 }),
    bystander('<wipe.o>', { evRecords: 3 }),
  ]));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(cell.reasons.includes(REASON.SUBJECT_DID_NOT_RESOLVE));
});

test('one name with a SUMMARY row in two backends is refused rather than picked between', () => {
  const cell = grade(evidenceOf([carrier('<use.o>'), carrier('<use2.o>')]));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(cell.reasons[0], REASON.THINLTO_ROW_IN_SEVERAL_BACKENDS);
  assert.ok(cell.reasons[1].includes('<use.o>') && cell.reasons[1].includes('<use2.o>'));
});

test('a side file that is not intact refuses the cell, per backend', () => {
  const cell = grade(evidenceOf([carrier('<use.o>', { summaryIntact: false, summarySource: 'side' })]));
  assert.equal(cell.reasons[0], REASON.SUMMARY_LOG_NOT_INTACT);
  assert.match(cell.reasons[1], /<use\.o>'s side file/);
});

test('an observed ThinLTO link whose bytes were never compared cannot be read', () => {
  // The rule exitDecision() applies to full-LTO cells, applied to this form
  // inside the cell: a plugin that silently declined to install produces the
  // same log-less, byte-identical shape a clean run does, so "the bytes were
  // never compared" is not a smaller claim than "the bytes differed".
  const cell = grade(evidenceOf([carrier('<use.o>')], { byteIdentical: null }));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(cell.reasons[0], REASON.NON_INVASIVENESS_NOT_ESTABLISHED);
});

/* ---------------------------------------------------------- the reader -- */

test('the manifest reader takes column 2 verbatim and never re-derives a filename', () => {
  // `History.cpp:83-95` sanitises the module id into the suffix and falls back
  // to `module-<index>` past 128 characters, so the two columns do not always
  // agree and column 2 is the one that was opened.
  const { entries, malformed } = parseModuleManifest(
    '/lab/use.o\t/lab/observer.tsv\n'
    + '/very/deep/tree/x.o\t/lab/observer.tsv.module-2.tsv\n');
  assert.equal(malformed.length, 0);
  assert.deepEqual(entries[1], { moduleId: '/very/deep/tree/x.o', logPath: '/lab/observer.tsv.module-2.tsv' });
  assert.ok(!entries[1].logPath.includes('x.o'),
    'the fixture exists to make a re-derived filename visibly wrong');
});

test('a manifest line without a tab is malformed, not a module id on its own', () => {
  const { entries, malformed } = parseModuleManifest('/lab/a.o\t/lab/a.tsv\nmangled-line\n/lab/b.o\t\n');
  assert.equal(entries.length, 1);
  assert.deepEqual(malformed, ['mangled-line', '/lab/b.o\t']);
});

test('the ordered pass comparison is null under ThinLTO, not false', () => {
  // lld prints ONE stderr stream for N concurrent backends -- measured on xtu:
  // 751 lines, 107 spliced mid-word -- so comparing one backend's reading
  // against it in ORDER is not defined. `false` would put
  // PASS_READINGS_OUT_OF_ORDER on every healthy ThinLTO cell and claim two
  // readings drifted apart when they were never comparable in order.
  const folded = foldPassAgreements([carrier('<use.o>'), bystander('<wipe.o>')]);
  assert.equal(folded.comparable, true);
  assert.equal(folded.subset, true);
  assert.equal(folded.sequenceEqual, null);
  assert.deepEqual(folded.perBackend.map((p) => p.sequenceEqual), [false, false],
    'each backend\'s own ordered reading is kept, not dropped');

  const cell = grade(evidenceOf([carrier('<use.o>'), bystander('<wipe.o>')]));
  assert.deepEqual(cell.notes, [], 'a structural non-comparison must not be reported as a drift');
});

test('a pass the linker never ran still refuses the cell', () => {
  const cell = grade(evidenceOf([
    carrier('<use.o>', { passAgreement: { ...AGREE, subset: false, observerOnly: ['InventedPass'] } }),
  ]));
  assert.equal(cell.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(cell.reasons.includes(REASON.PASS_READINGS_DISAGREE));
});

test('resolutionAcrossBackends separates "no backend resolved it" from "nobody asked"', () => {
  assert.equal(resolutionAcrossBackends([{ r: 'not-in-module' }, { r: 'resolved' }], 'r'), true);
  assert.equal(resolutionAcrossBackends([{ r: 'not-in-module' }, { r: 'declaration-only' }], 'r'), false);
  assert.equal(resolutionAcrossBackends([{}, {}], 'r'), null);
});

test('the harness hands the thin cell to the grader and builds no verdict of its own', () => {
  // The unconditional refusal did not live in a graded function -- it was four
  // lines in run-lto-window.mjs's thin branch, `gradeCell({ refusal: {
  // BROKEN_MEASUREMENT, MULTI_PASSBUILDER } })`, sitting where a call to the
  // grader should be. A test of the grader alone cannot see that come back, so
  // this reads the branch. MUTATION 1 is restoring those lines, and it fails
  // here.
  const src = readFileSync(new URL('../run-lto-window.mjs', import.meta.url), 'utf8');
  const from = src.indexOf('} else {\n        // ThinLTO');
  assert.ok(from > 0, "the thin branch's shape changed; this pin no longer reads it");
  const branch = src.slice(from, src.indexOf("results.observationPoints.push({\n          id: `${name}-thin", from));
  assert.ok(branch.includes('gradeThinLtoCell({'),
    'the thin cell must be graded by lib/thin-logs.mjs, which is the tested code');
  assert.ok(!branch.includes('MULTI_PASSBUILDER') && !branch.includes('refusal:'),
    'the thin branch is constructing a verdict instead of grading one: that is the defect that put '
    + 'BROKEN_MEASUREMENT on a cell whose evidence said intact');
  assert.ok(!/reached:\s*false/.test(branch),
    'the observation point must report whether the cell was reached, not assert that it was not');
});

test('thin-logs-real-shape: the fixtures here carry every field the grader reads', () => {
  // The fixtures above are hand-built, so the risk they carry is that they stop
  // resembling what readThinLtoBackends() produces and the suite goes on
  // passing about nothing. This pins the contract between the two: every key
  // the grader consults has to exist on a fixture module.
  const consulted = ['moduleId', 'logPresent', 'logIntact', 'summaryIntact', 'evRecords',
    'handshakeRecords', 'nulBytes', 'tornLines', 'subjectResolution', 'controlResolution',
    'subjectRow', 'controlRow', 'passAgreement'];
  for (const key of consulted) {
    assert.ok(key in carrier('<use.o>'), `the grader reads \`${key}\` and the fixture has no such field`);
  }
  const src = readFileSync(new URL('../run-lto-window.mjs', import.meta.url), 'utf8');
  const reader = src.slice(src.indexOf('function readThinLtoBackends'), src.indexOf('function compileWindowCell'));
  assert.ok(reader.length > 0, 'readThinLtoBackends moved; this pin no longer reads it');
  for (const key of consulted) {
    assert.ok(reader.includes(`${key}:`) || key === 'moduleId',
      `readThinLtoBackends does not build \`${key}\`, so the fixtures describe a shape nothing produces`);
  }
});
