/**
 * lib/grade.mjs decides what an observation means, and these tests are mostly
 * about the cases where it must decide that it means NOTHING.
 *
 * Four of them exist because each corresponds to a way this lane could report a
 * fabricated green, and a grader that got any of them wrong would do so silently:
 *
 *   - control-retain reading nothing:  the reader or the window is broken, and
 *     every NONE elsewhere in the run is that, not a wipe working.
 *   - control-nosecret reading something: the observer is finding its own
 *     needle, and every FULL elsewhere is that.
 *   - control-o0-wiped reading residue: the stop point is BEFORE the wipe. Note
 *     that the other two controls still pass in that world -- this is the only
 *     one that turns red, which is why it is here and why it is not optional.
 *   - a stop that did not match being turned into a verdict: the single most
 *     expensive mistake available to this lane, because the resulting row looks
 *     exactly like a finding.
 *   - a window shallower than the subject's own frame being turned into a NONE.
 *     This one is new, and it is here because the co-resident control does NOT
 *     catch it: the control can sit near the top of the frame and be read at
 *     32/32 while the secret sits below the window and reads nothing. That is a
 *     silent false clean in the (WIPE_SURVIVED, NONE) square, which is the worst
 *     direction this lane can be wrong in.
 *
 * No compiler and no filesystem: every record below is a literal.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CONTROLS, MEASUREMENT, FRAME_MARGIN_BYTES, gradeCell, gradeControl, runValidity, assertPairing,
  crossTab, anomalies,
} from '../lib/grade.mjs';

const NL = 32;

/** A plausible stop rsp. Only the differences between it and the window matter. */
const RSP = 140737488347136;

/**
 * A well-formed observer record with a full-tracer stack reading, by default.
 *
 * `window.lo` and `stop.rsp` agree with each other -- lo = rsp - 4096, hi =
 * rsp + 64 -- because that is what the observer writes and because the grader now
 * derives the depth the window reached from exactly those two numbers. The old
 * fixture had rsp 100 with lo 0, which no run could produce.
 */
const obs = (over = {}) => ({
  schemaVersion: 'residue-observation-v0',
  ok: true,
  error: null,
  symbol: 'handle_request',
  map: { base: 4194304, expectedBase: 4194304, biasZero: true },
  stop: { expectedRip: 4199374, rip: 4199374, matched: true, expectedRsp: RSP, rsp: RSP, rspMatched: true },
  window: { lo: RSP - 4096, hi: RSP + 64, requested: 4160, bytesRead: 4160 },
  text: { compared: true, size: 917, restoredMatchesFile: true, firstMismatchOffset: -1 },
  fpregsRead: true,
  stack: { longestRunBytes: 32, windowOffset: 0, needleOffset: 0 },
  stackControl: { longestRunBytes: 32, windowOffset: 0, needleOffset: 0 },
  gpr: { longestRunBytes: 1, slot: 0 },
  xmm: { longestRunBytes: 1, slot: 0 },
  ...over,
});

/**
 * The frame of the subject function, as lib/frame.mjs reads it out of the binary.
 * 88 bytes is the real number for this lane's own target at clang-18 -O0
 * (`push %rbp` + `sub $0x50,%rsp`), so the default window covers it comfortably
 * and every test below that is not about the frame behaves as it did before.
 */
const FRAME = Object.freeze({ parsed: true, subjectBytes: 88, form: 'push+sub', why: null });

const grade = (o, frame = FRAME) => gradeCell(o, { needleLen: NL, controlNeedleLen: NL, frame });

test('the measurement vocabulary is interfaces.md section 3.1 and nothing else', () => {
  assert.deepEqual([...MEASUREMENT], ['OK', 'UNSUPPORTED', 'BROKEN_MEASUREMENT']);
});

test('a clean record with all 32 bytes readable grades FULL, with the control held', () => {
  const g = grade(obs());
  assert.equal(g.measurement, 'OK');
  assert.equal(g.residue.stack, 'FULL');
  assert.equal(g.controlHeld, true);
  assert.equal(g.longestRunBytes, 32);
});

test('the run length is graded against the floor, not against presence', () => {
  assert.equal(grade(obs({ stack: { longestRunBytes: 31 } })).residue.stack, 'PARTIAL');
  assert.equal(grade(obs({ stack: { longestRunBytes: 8 } })).residue.stack, 'PARTIAL');
  assert.equal(grade(obs({ stack: { longestRunBytes: 7 } })).residue.stack, 'NONE');
  assert.equal(grade(obs({ stack: { longestRunBytes: 0 } })).residue.stack, 'NONE');
});

// ---------------------------------------------------------------------------
// The four that must fail.
// ---------------------------------------------------------------------------

test('control-retain reading nothing FAILS the control, and the run is INVALID', () => {
  const g = grade(obs({ stack: { longestRunBytes: 0 } }));
  assert.equal(g.residue.stack, 'NONE');
  const c = gradeControl('control-retain', g);
  assert.equal(c.held, false, 'a retain control that reads nothing must not be reported as held');
  assert.match(c.why, /expected FULL, read NONE/);
  assert.equal(runValidity([c, { name: 'control-nosecret', held: true }, { name: 'control-o0-wiped', held: true }]).valid, false);
});

test('control-nosecret reading something FAILS the control', () => {
  const c = gradeControl('control-nosecret', grade(obs({ stack: { longestRunBytes: 32 } })));
  assert.equal(c.held, false, 'a needle that never entered the tracee must not be found in it');
  assert.match(c.why, /expected NONE, read FULL/);
  // A fragment is not a pass either: the whole point of the floor is that 8
  // bytes of a key is a leak.
  assert.equal(gradeControl('control-nosecret', grade(obs({ stack: { longestRunBytes: 8 } }))).held, false);
});

test('control-o0-wiped reading residue FAILS the control -- the stop is before the wipe', () => {
  const c = gradeControl('control-o0-wiped', grade(obs({ stack: { longestRunBytes: 32 } })));
  assert.equal(c.held, false);
  assert.match(c.why, /expected NONE, read FULL/);
  // And the point of having it: in a world where the stop is too early, the
  // other two controls still pass. If this test ever stops being the only one
  // that fails in that world, the controls have lost their independence.
  const tooEarly = grade(obs({ stack: { longestRunBytes: 32 } }));
  assert.equal(gradeControl('control-retain', tooEarly).held, true);
  assert.equal(gradeControl('control-nosecret', grade(obs({ stack: { longestRunBytes: 0 } }))).held, true);
});

test('a stop that did not match is NOT_OBSERVED, never a residue verdict', () => {
  for (const bad of [
    { stop: { expectedRip: 1, rip: 2, matched: false, expectedRsp: 100, rsp: 100, rspMatched: true } },
    { stop: { expectedRip: 1, rip: 1, matched: true, expectedRsp: 100, rsp: 200, rspMatched: false } },
  ]) {
    const g = grade(obs(bad));
    assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
    assert.equal(g.reason, 'stop-mismatch');
    assert.equal(g.residue.stack, 'NOT_OBSERVED');
    assert.equal(g.residue.gpr, 'NOT_OBSERVED');
    assert.equal(g.residue.xmm, 'NOT_OBSERVED');
    assert.equal(g.longestRunBytes, null, 'a failed stop must not carry a count that could be read as a reading');
    assert.equal(g.controlHeld, null, 'no control was measured, so null rather than false');
    // And a control on such a cell has not held either: it did not run.
    assert.equal(gradeControl('control-retain', g).held, false);
  }
});

// ---------------------------------------------------------------------------

test('the co-resident control failing is controlHeld false, not null, and carries its count', () => {
  const g = grade(obs({ stackControl: { longestRunBytes: 9 } }));
  assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
  assert.equal(g.reason, 'coresident-control-unreadable');
  assert.equal(g.controlHeld, false, 'measured and fell is false; null would claim nobody measured it');
  assert.equal(g.controlRunBytes, 9);
  assert.equal(g.residue.stack, 'NOT_OBSERVED');
});

// ---------------------------------------------------------------------------
// The fifth that must fail: the window that did not reach the subject.
// ---------------------------------------------------------------------------

test('a window shallower than the SUBJECT frame is NOT_OBSERVED even with the control fully readable', () => {
  // Every number here was measured, not invented. Build this lane's own target
  // with the buffers declared `keep[32]; pad[8192]; secret[32];` and clang-18
  // -O0 emits `push %rbp` + `sub $0x2060,%rsp`, a frame 8296 bytes deep. Run the
  // real observer over the real binary at --below 4096 and it reads
  // control = 32/32 and subject = 1 byte; at --below 16384 over the SAME binary
  // it reads subject = 32/32. The secret was there the whole time and the
  // control was held the whole time.
  //
  // Before this check the grader called that record measurement OK,
  // controlHeld true, residue NONE -- a clean wipe, in the worst direction a
  // wipe checker can be wrong.
  const deep = { parsed: true, subjectBytes: 8296, form: 'push+sub', why: null };
  const g = grade(obs({ stack: { longestRunBytes: 1 }, stackControl: { longestRunBytes: 32 } }), deep);
  assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
  assert.match(g.reason, /^window-shallower-than-subject-frame: /);
  assert.equal(g.residue.stack, 'NOT_OBSERVED', 'a window that did not reach the buffer reports no residue at all');
  assert.equal(g.longestRunBytes, null);
  assert.equal(g.controlHeld, null, 'the control was not what failed, so it is not what is reported');
  // And the operator is told what to pass rather than left to work it out:
  // 8296 + the 136-byte margin (8 for the popped return word, 128 for the red zone).
  assert.match(g.reason, /reached 4096 bytes below the stop rsp/);
  assert.match(g.reason, /needs 8432/);
  assert.match(g.reason, /--below 8432/);
  assert.equal(FRAME_MARGIN_BYTES, 136);
});

test('the same record with a window that DOES cover the frame is a reading again', () => {
  // The other half of the pair: the check refuses the shallow window, not the
  // measurement. Same frame, same control, a window that reaches past it.
  const deep = { parsed: true, subjectBytes: 8296, form: 'push+sub', why: null };
  const wide = obs({
    window: { lo: RSP - 16384, hi: RSP + 64, requested: 16448, bytesRead: 16448 },
    stack: { longestRunBytes: 32 },
  });
  const g = grade(wide, deep);
  assert.equal(g.measurement, 'OK');
  assert.equal(g.residue.stack, 'FULL');
  assert.equal(g.controlHeld, true);
});

test('a frame that could not be read is not a verdict either -- including when none was measured', () => {
  // "We could not establish that we looked where the secret was" is the same
  // case as "we did not look". A VLA compiles to `mov %rbx,%rsp`, and gcc's
  // stack-clash probe puts a `sub` inside a loop once the frame is large enough
  // (measured: unrolled at 8 KiB, a loop at 128 KiB); neither can be bounded by
  // counting instructions once, and both used to grade as an ordinary NONE.
  // Handed straight to gradeCell rather than through the helper: the point of the
  // last two rows is a caller that passes NO frame at all, which a default
  // argument would quietly fill in.
  for (const [opts, pattern] of [
    [{ frame: { parsed: false, subjectBytes: null, form: null, why: 'unbounded-rsp-write: mov %rbx,%rsp' } }, /^subject-frame-unparsed: unbounded-rsp-write/],
    [{ frame: { parsed: false, subjectBytes: null, form: null, why: 'stack-decrement-inside-a-loop' } }, /^subject-frame-unparsed: stack-decrement-inside-a-loop$/],
    [{}, /^subject-frame-not-measured$/],
    [{ frame: null }, /^subject-frame-not-measured$/],
    [{ frame: { parsed: true, subjectBytes: null, form: null, why: null } }, /^subject-frame-unparsed: unstated$/],
  ]) {
    const g = gradeCell(obs({ stack: { longestRunBytes: 0 } }), { needleLen: NL, controlNeedleLen: NL, ...opts });
    assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
    assert.match(g.reason, pattern);
    assert.equal(g.residue.stack, 'NOT_OBSERVED');
    assert.equal(gradeControl('control-retain', g).held, false, 'a control on such a cell has not held');
  }
});

test('a frame past the observer window ceiling says so instead of naming an impossible --below', () => {
  // The observer refuses below+above over 1 MiB with usage() and writes no
  // record at all, so "run it again with --below 2097288" would send the
  // operator to a run that produces nothing. A 2 MiB stack buffer is unusual and
  // entirely legal, and the honest answer is that this instrument cannot reach
  // it as built.
  const huge = { parsed: true, subjectBytes: 2 * 1024 * 1024, form: 'push+sub', why: null };
  const g = grade(obs({ stack: { longestRunBytes: 1 } }), huge);
  assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
  assert.match(g.reason, /^window-shallower-than-subject-frame/);
  assert.match(g.reason, /past the observer's 1048576-byte window ceiling/);
  assert.doesNotMatch(g.reason, /run it again with --below/);
  // And the ordinary case still tells the operator exactly what to pass.
  const deep = { parsed: true, subjectBytes: 8296, form: 'push+sub', why: null };
  assert.match(grade(obs({ stack: { longestRunBytes: 1 } }), deep).reason, /run it again with --below 8432/);
});

test('the frame check runs BEFORE the co-resident control, so the reason names the window', () => {
  // Order matters for the diagnosis, not just for the verdict: a shallow window
  // can leave the control readable, so a cell that failed both would otherwise
  // send the operator to look at a control that is working.
  const deep = { parsed: true, subjectBytes: 8296, form: 'push+sub', why: null };
  const g = grade(obs({ stack: { longestRunBytes: 1 }, stackControl: { longestRunBytes: 0 } }), deep);
  assert.match(g.reason, /^window-shallower-than-subject-frame/);
  assert.notEqual(g.reason, 'coresident-control-unreadable');
});

test('text not restored, a short window, a non-zero load bias and a failed observer are each NOT_OBSERVED', () => {
  const cases = [
    [obs({ text: { compared: true, restoredMatchesFile: false, firstMismatchOffset: 12 } }), 'text-not-restored'],
    [obs({ window: { lo: 0, hi: 4160, requested: 4160, bytesRead: 2048 } }), 'short-window'],
    [obs({ map: { base: 5, expectedBase: 4194304 } }), 'load-bias-not-zero'],
    [{ ok: false, error: 'child exited before handle_request was reached' }, 'observer-failed: child exited before handle_request was reached'],
    [null, 'no-observer-record'],
  ];
  for (const [rec, reason] of cases) {
    const g = grade(rec);
    assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
    assert.equal(g.reason, reason);
    assert.equal(g.residue.stack, 'NOT_OBSERVED');
  }
});

test('a cell that was never run -- plugin absent -- is NOT_OBSERVED with its reason, not UNSUPPORTED', () => {
  const g = gradeCell(null, { needleLen: NL, controlNeedleLen: NL, notRun: 'plugin-absent' });
  assert.equal(g.measurement, 'BROKEN_MEASUREMENT');
  assert.equal(g.reason, 'plugin-absent');
  assert.notEqual(g.measurement, 'UNSUPPORTED', 'UNSUPPORTED means the toolchain refused; it was never asked');
  assert.equal(g.residue.stack, 'NOT_OBSERVED');
});

test('a failed fpregs read makes xmm NOT_OBSERVED without touching the stack reading', () => {
  const g = grade(obs({ fpregsRead: false }));
  assert.equal(g.measurement, 'OK');
  assert.equal(g.residue.stack, 'FULL');
  assert.equal(g.residue.xmm, 'NOT_OBSERVED');
  assert.equal(g.residue.gpr, 'NONE');
});

test('runValidity refuses a run where a control was never executed at all', () => {
  const v = runValidity([{ name: 'control-retain', held: true }]);
  assert.equal(v.valid, false);
  assert.deepEqual(v.problems, ['control-nosecret: not run', 'control-o0-wiped: not run']);
  assert.equal(runValidity([]).valid, false);
  assert.equal(runValidity(null).valid, false);
});

test('every control this lane defines states what it catches', () => {
  assert.deepEqual(Object.keys(CONTROLS).sort(), ['control-nosecret', 'control-o0-wiped', 'control-retain']);
  for (const [, spec] of Object.entries(CONTROLS)) {
    assert.ok(spec.why.length > 60, 'a control with no stated purpose is decoration');
    assert.ok(['FULL', 'NONE'].includes(spec.expect));
  }
  assert.equal(CONTROLS['control-o0-wiped'].opt, '-O0', 'this control is only a control at -O0');
});

// ---------------------------------------------------------------------------

test('assertPairing catches a reading beside a failed measurement and the converse', () => {
  assert.equal(assertPairing([{ cell: 'a', measurement: 'OK', residue: { stack: 'FULL' }, controlHeld: true }]).ok, true);
  const bad = assertPairing([
    { cell: 'x', measurement: 'BROKEN_MEASUREMENT', residue: { stack: 'NONE' }, controlHeld: false },
    { cell: 'y', measurement: 'OK', residue: { stack: 'NOT_OBSERVED' }, controlHeld: true },
    { cell: 'z', measurement: 'BROKEN_MEASUREMENT', residue: { stack: 'NOT_OBSERVED' }, controlHeld: true },
  ]);
  assert.equal(bad.ok, false);
  assert.equal(bad.problems.length, 3);
  assert.match(bad.problems[0], /x: measurement BROKEN_MEASUREMENT with residue NONE/);
  assert.match(bad.problems[2], /z: measurement BROKEN_MEASUREMENT with controlHeld true/);
});

test('the cross-tab counts only gradeable cells and names every exclusion', () => {
  const rows = [
    { cell: 'a', measurement: 'OK', confirmVerdict: 'WIPE_SURVIVED', residue: { stack: 'NONE' } },
    { cell: 'b', measurement: 'OK', confirmVerdict: 'WIPE_ELIMINATED', residue: { stack: 'FULL' } },
    { cell: 'c', measurement: 'OK', confirmVerdict: 'WIPE_SURVIVED', residue: { stack: 'PARTIAL' } },
    { cell: 'd', measurement: 'BROKEN_MEASUREMENT', reason: 'plugin-absent', residue: { stack: 'NOT_OBSERVED' } },
    { cell: 'e', measurement: 'OK', confirmVerdict: 'NO_WIPE_WRITTEN', residue: { stack: 'FULL' } },
  ];
  const t = crossTab(rows);
  assert.equal(t.graded, 3);
  assert.equal(t.cells['WIPE_SURVIVED|NONE'], 1);
  assert.equal(t.cells['WIPE_SURVIVED|PARTIAL'], 1);
  assert.equal(t.cells['WIPE_ELIMINATED|FULL'], 1);
  assert.deepEqual(t.excluded, { 'plugin-absent': 1, 'confirm:NO_WIPE_WRITTEN': 1 });
});

test('a surviving wipe with readable bytes is a FINDING; an eliminated wipe with none is an ANOMALY', () => {
  const a = anomalies([
    { cell: 'f', measurement: 'OK', confirmVerdict: 'WIPE_SURVIVED', residue: { stack: 'PARTIAL' }, longestRunBytes: 8 },
    { cell: 'g', measurement: 'OK', confirmVerdict: 'WIPE_ELIMINATED', residue: { stack: 'NONE' }, longestRunBytes: 1 },
    { cell: 'h', measurement: 'OK', confirmVerdict: 'WIPE_ELIMINATED', residue: { stack: 'FULL' }, longestRunBytes: 32 },
    { cell: 'i', measurement: 'BROKEN_MEASUREMENT', confirmVerdict: 'WIPE_SURVIVED', residue: { stack: 'NOT_OBSERVED' } },
  ]);
  assert.equal(a.findings.length, 1);
  assert.match(a.findings[0], /^f: confirm said WIPE_SURVIVED, 8 tracer bytes readable/);
  assert.equal(a.anomalous.length, 1);
  assert.match(a.anomalous[0], /^g: .*not a pass/);
});
