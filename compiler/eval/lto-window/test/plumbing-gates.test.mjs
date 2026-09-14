// The order the which-wipe plumbing is allowed to be believed in.
//
// WHY THIS FILE EXISTS
//
// whichWipeSurvived() grades three integers and its BLIND guard runs first --
// record.test.mjs pins that ordering, because "deleting the subject changed
// nothing" and "this build is not responding to its source" produce the same
// number. One layer out, the same problem has two more shapes that the integers
// cannot show:
//
//   there were never three builds  (a stale work directory, a write that did not
//                                   land, a cut that deleted nothing)
//   the fill was counted somewhere else  (objdump_fill counts the function it is
//                                   given; given the wrong one it returns a
//                                   number, and the number looks fine)
//
// Both of them end in `subject-store-already-gone`, which is this lane's
// published answer. So the gates are a function, they run in a fixed order, and
// the subject's word is a THUNK: a failed gate must mean the verdict was never
// computed, not that it was computed and then set aside. These tests are mostly
// about that thunk never being called.

import { strict as assert } from 'node:assert';
import test from 'node:test';

import { GATE, GATE_ORDER, controlIndependence, gatedSubjectReading } from '../lib/plumbing-gates.mjs';
import { WHICH_WIPE, whichWipeSurvived } from '../lib/record.mjs';

/** An observation set in which everything is as the lane's -O2 reading has it. */
const healthy = () => ({
  // The source texts differ before the objects do -- a cut that removed
  // nothing is a fact about the sources, and until 2026-09-14 the object
  // digests were asked to carry that and could not (the three variants were
  // compiled from three FILENAMES, so their objects differed whatever the
  // sources said; measured, and lib/build-variants.mjs's header has it).
  sourceDigests: { asWritten: 's-aaa', subjectCut: 's-bbb', controlCut: 's-ccc' },
  digests: { asWritten: 'aaa', subjectCut: 'bbb', controlCut: 'ccc' },
  caller: 'main',
  subjectReading: { verdict: 'PRESENT', where: 'main', bytes: 32, memsetCalls: 0 },
  controlReading: { verdict: 'PRESENT', where: 'main', bytes: 32, memsetCalls: 0 },
  fill: { asWritten: 32, subjectCut: 32, controlCut: 0 },
  // The control's own wipe is 32B, so deleting it has to take 32B away and
  // not merely `fewer than before`.
  controlWipeBytes: 32,
  subjectWipeBytes: 32,
});

/** A thunk that records whether the gates ever reached it. */
function counted(value = 'the-subject-word') {
  const calls = { n: 0 };
  return [() => { calls.n += 1; return value; }, calls];
}

test('every gate is reported, always, and in the documented order', () => {
  const [word] = counted();
  const r = gatedSubjectReading(healthy(), word);
  assert.deepEqual(r.gates.map((g) => g.gate), [...GATE_ORDER]);
  assert.equal(r.gates.filter((g) => g.ok).length, GATE_ORDER.length);
});

test('a healthy observation reaches the subject word, once', () => {
  const [word, calls] = counted();
  const r = gatedSubjectReading(healthy(), word);
  assert.equal(r.failed, null);
  assert.equal(r.subject, 'the-subject-word');
  assert.equal(calls.n, 1);
});

test('two variants that compiled to the same object never reach a verdict', () => {
  // The cut deleted nothing, or the build was reused. Both read as "deleting
  // the subject's wipe changed nothing" if the numbers are allowed to be graded.
  const [word, calls] = counted();
  const obs = healthy();
  obs.digests.subjectCut = obs.digests.asWritten;
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.DISTINCT_COMPILATIONS);
  assert.equal(r.subject, null);
  assert.equal(calls.n, 0, 'the verdict must not have been computed at all');
  assert.match(r.gates[1].why, /three different objects/);
});

test('a missing digest is not three distinct digests', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.digests.controlCut = '';
  assert.equal(gatedSubjectReading(obs, word).failed, GATE.DISTINCT_COMPILATIONS);
  assert.equal(calls.n, 0);
});

test('a fill counted in another function body never reaches a verdict', () => {
  // The second failure mode the ledger names. The numbers here would grade as
  // `subject-store-already-gone` -- which is the lane's published word -- and
  // they are numbers about the wrong function.
  const [word, calls] = counted();
  const obs = healthy();
  obs.subjectReading.where = 'wipe_kept';
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.READER_ON_NAMED_BODY);
  assert.equal(r.subject, null);
  assert.equal(calls.n, 0);
  // and what the numbers WOULD have said, so the test is about the gate rather
  // than about the arithmetic being unconvincing on its own
  assert.equal(whichWipeSurvived(obs.fill).reading, WHICH_WIPE.SUBJECT_GONE);
});

test('a body that is not in the disassembly at all is not a reading of zero fill', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.subjectReading = { verdict: 'NOT_OBSERVED', where: 'main', bytes: 0, memsetCalls: 0 };
  assert.equal(gatedSubjectReading(obs, word).failed, GATE.READER_ON_NAMED_BODY);
  assert.equal(calls.n, 0);
});

test('the control is read BEFORE the subject, and a blind control stops everything', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.controlReading.verdict = 'ABSENT';
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.CONTROL_PRESENT);
  assert.equal(r.subject, null);
  assert.equal(calls.n, 0);
  assert.match(r.gates[3].why, /blind before the subject is asked about/);
});

test('a control deletion that does not move the fill stops the subject word', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.fill.controlCut = 32; // the same as as-written: nothing responded
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.CONTROL_MOVES_FILL);
  assert.equal(calls.n, 0);
});

test('a missing byte count is a failed gate, not a zero', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.fill.subjectCut = null;
  assert.equal(gatedSubjectReading(obs, word).failed, GATE.CONTROL_MOVES_FILL);
  assert.equal(calls.n, 0);
});

test('when several gates fail, the EARLIEST one is the one named', () => {
  // The order is the claim: an instrument that was never three builds is not
  // asked whether its control moved. Naming the last failure instead of the
  // first would send a reader to the wrong end of the pipe.
  const obs = healthy();
  obs.sourceDigests.subjectCut = obs.sourceDigests.asWritten;
  obs.digests.subjectCut = obs.digests.asWritten;
  obs.subjectReading.where = 'handle';
  obs.controlReading.verdict = 'ABSENT';
  obs.fill.controlCut = 999;
  const [word, calls] = counted();
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.DISTINCT_SOURCES);
  assert.deepEqual(r.gates.filter((g) => !g.ok).map((g) => g.gate), [...GATE_ORDER]);
  assert.equal(calls.n, 0);
});

test('the control gate outranks the fill gate', () => {
  const obs = healthy();
  obs.controlReading.verdict = 'PARTIAL';
  obs.fill.controlCut = 32;
  const [word, calls] = counted();
  assert.equal(gatedSubjectReading(obs, word).failed, GATE.CONTROL_PRESENT);
  // Every failing-gate test in this file asserts this, and this one did not:
  // `failed` names a gate whether or not the thunk ran, so a file that checks
  // the name and not the call count is not checking the thing the thunk is for.
  assert.equal(calls.n, 0);
});

/* ---------------------------------------- the gate that could not fail -- */

test('three identical source texts -- a cut that removed nothing -- never reach a verdict', () => {
  // THE DEFECT THIS PAIR OF GATES EXISTS FOR. A cut whose pattern matched
  // nothing leaves the `subject cut` build byte-identical to the as-written
  // one, its fill unchanged, and that grades as `subject-store-already-gone`
  // -- the lane's published word. It has to stop at the first gate.
  const [word, calls] = counted();
  const obs = healthy();
  obs.sourceDigests.subjectCut = obs.sourceDigests.asWritten;
  // and the objects collide too, because every variant is now compiled from
  // one path: this is what the object gate could NOT see while the path
  // carried the tag.
  obs.digests.subjectCut = obs.digests.asWritten;
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.DISTINCT_SOURCES);
  assert.equal(r.subject, null);
  assert.equal(calls.n, 0, 'the verdict must not have been computed at all');
  assert.match(r.gates[0].why, /the cut removed nothing/);
  // and it would have graded as the headline answer
  assert.equal(whichWipeSurvived(obs.fill).reading, WHICH_WIPE.SUBJECT_GONE);
});

test('the source gate is asked before the object gate, and a missing source digest is not a source', () => {
  const [word, calls] = counted();
  const obs = healthy();
  obs.sourceDigests.controlCut = '';
  assert.equal(gatedSubjectReading(obs, word).failed, GATE.DISTINCT_SOURCES);
  assert.equal(calls.n, 0);
  assert.equal(GATE_ORDER[0], GATE.DISTINCT_SOURCES);
  assert.ok(GATE_ORDER.indexOf(GATE.DISTINCT_SOURCES) < GATE_ORDER.indexOf(GATE.DISTINCT_COMPILATIONS));
});

test('a control deletion that moves the fill by the WRONG amount is not a control that held', () => {
  // `controlCut < asWritten` was the old test, and any movement in the right
  // direction satisfied it. The control's wipe is 32B and the fixture says so,
  // so 16B out is a build that responded to something else.
  const [word, calls] = counted();
  const obs = healthy();
  obs.fill.controlCut = 16;
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.CONTROL_MOVES_FILL);
  assert.equal(calls.n, 0);
  const g = r.gates.at(-1);
  assert.equal(g.removedBytes, 16);
  assert.equal(g.expectedBytes, 32);
});

test('nobody saying how big the control wipe is is a failed gate, not a free pass', () => {
  const [word, calls] = counted();
  const obs = healthy();
  delete obs.controlWipeBytes;
  const r = gatedSubjectReading(obs, word);
  assert.equal(r.failed, GATE.CONTROL_MOVES_FILL);
  assert.equal(calls.n, 0);
  assert.match(r.gates.at(-1).why, /any movement at all would satisfy it/);
});

test('the record says the as-written control is NOT an independent reading here', () => {
  // The subject and the control are asked for the same body with the same byte
  // count in this family -- both wipes are absorbed into one -- so a passing
  // CONTROL_PRESENT cannot disagree with the subject reading it is a control
  // on. The gate stays (it still catches a blind instrument) and the result
  // carries what it is worth, so that nothing downstream can read it as more.
  const r = gatedSubjectReading(healthy(), counted()[0]);
  assert.equal(r.controlIndependence, 'same-body-same-question');
  assert.equal(r.gates.find((g) => g.gate === GATE.CONTROL_PRESENT).independence, 'same-body-same-question');
  assert.equal(controlIndependence({ subjectReading: { where: 'main' }, controlReading: { where: 'wipe_kept' } }), 'separate-body');
  assert.equal(controlIndependence({}), 'not-read');
});
