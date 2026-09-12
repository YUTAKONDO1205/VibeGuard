/**
 * What an observation means, and when it means nothing.
 *
 * Pure. No compiler, no filesystem, no process. Everything here takes an
 * observer record (or a plain object shaped like one) and returns a grade, so
 * every rule below can be put under test without building anything -- including
 * the rules that are supposed to FAIL, which is the half that matters.
 *
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE. A reading is only a reading when the
 * instrument is known to have worked at the instant it read. Four things can
 * make that untrue, and each produces NOT_OBSERVED with a reason rather than a
 * residue verdict:
 *
 *   stop-mismatch                  the breakpoint that fired was not the return
 *                                  of the subject function, or the stack pointer
 *                                  at it was not the entry rsp plus eight.
 *   text-not-restored              the bytes this run patched did not come back
 *                                  identical to the file's.
 *   short-window                   the window read fewer bytes than it asked for.
 *   window-shallower-than-         the window did not reach the bottom of the
 *     subject-frame                SUBJECT's own frame, measured out of the
 *                                  binary. See below: this is the case the
 *                                  co-resident control cannot catch.
 *   subject-frame-unparsed /       the subject's frame depth could not be read
 *     subject-frame-not-measured   from the binary at all, so nothing says the
 *                                  window covered it.
 *   coresident-control-unreadable  the control tracer, which the subject holds in
 *                                  the SAME frame and never wipes, was not fully
 *                                  readable. Nothing was measured; this is the
 *                                  case that would otherwise be reported as a
 *                                  clean wipe.
 *
 * WHY THE CONTROL IS NOT ENOUGH ON ITS OWN, which is a correction to what this
 * file used to claim. A readable control says the window reached the CONTROL. It
 * does not say the window reached the subject buffer, and a stack layout that
 * puts the control shallow and the secret deeper than the window is ordinary:
 * `keep[32]; pad[8192]; secret[32];` at clang-18 -O0 reads control 32/32 HELD and
 * subject NONE with the default window, and reads subject 32/32 when the window
 * is widened over the same binary. That is a silent false clean in the
 * (WIPE_SURVIVED, NONE) square. So the window is also checked against the frame
 * depth `lib/frame.mjs` reads out of the linked executable, and a window that
 * does not cover it -- or a frame that could not be read -- is NOT a verdict.
 *
 * interfaces.md section 3.1 fixes the measurement vocabulary at OK, UNSUPPORTED
 * and BROKEN_MEASUREMENT, and its pairing rule says a cell whose measurement is
 * not OK carries no reading. That rule is implemented here rather than described:
 * gradeCell never returns a residue enum beside a non-OK measurement, and
 * assertPairing is exported so a caller can check the rule held on a whole run.
 *
 * UNSUPPORTED means the toolchain refused, and nothing else. A cell that was not
 * run because a plugin is not built is NOT unsupported -- the toolchain was never
 * asked. Such a cell is BROKEN_MEASUREMENT with reason `plugin-absent`, which is
 * the honest shape: we did not look.
 */
import { classify, PARTIAL_FLOOR } from './scan.mjs';
import { FRAME_MARGIN_BYTES, WINDOW_MAX_BYTES, requiredBelow } from './frame.mjs';

export { PARTIAL_FLOOR, FRAME_MARGIN_BYTES, WINDOW_MAX_BYTES };

/** interfaces.md section 3.1, verbatim and complete. */
export const MEASUREMENT = Object.freeze(['OK', 'UNSUPPORTED', 'BROKEN_MEASUREMENT']);

/** The two verdicts the find step's own code can hand back that this lane grades against. */
export const GRADEABLE_CONFIRM = Object.freeze(['WIPE_SURVIVED', 'WIPE_ELIMINATED']);

/**
 * The three run-level controls, with what each one is FOR.
 *
 * They are not interchangeable and two of them cannot catch the failure the
 * third catches. `expect` is what the subject needle must read; every control
 * additionally carries the per-frame co-resident control like any other cell.
 */
export const CONTROLS = Object.freeze({
  'control-retain': Object.freeze({
    expect: 'FULL',
    target: 'retain',
    why: 'No wipe at all, buffer escaped. If the reader and the window work, the whole tracer is there. '
      + 'This is the control that shows a NONE anywhere else is not simply an instrument that reads nothing.',
  }),
  'control-nosecret': Object.freeze({
    expect: 'NONE',
    target: 'retain',
    why: 'The tracee is given a different tracer and the observer searches for one that never entered its '
      + 'address space. This catches an observer that finds its own needle -- through its own memory, through a '
      + 'shared page, or through a search that returns a hit for the empty case.',
  }),
  'control-o0-wiped': Object.freeze({
    expect: 'NONE',
    target: 'memset',
    opt: '-O0',
    why: 'A memset at -O0 is a real call that no optimiser removes, so the buffer IS zero when the frame dies. '
      + 'THIS IS THE ONLY CONTROL THAT CATCHES A STOP POINT PLACED BEFORE THE WIPE. Stop one instruction too '
      + 'early and control-retain still reads FULL and control-nosecret still reads NONE -- both pass, and every '
      + 'subject cell reads residue that the wipe would have removed. Only this one turns red.',
  }),
});

/**
 * Grade one observation.
 *
 * @param {object|null} obs      the observer record, or null when it did not run
 * @param {object} opts
 * @param {number} opts.needleLen
 * @param {number} opts.controlNeedleLen
 * @param {object} [opts.frame]   the subject frame from lib/frame.mjs. Required
 *                                for any verdict: without it the cell is
 *                                BROKEN_MEASUREMENT, because nothing establishes
 *                                that the window reached the buffer.
 * @param {number} [opts.frameMargin]
 * @param {number} [opts.floor]
 * @param {string} [opts.notRun]  a reason the observer was never invoked
 * @returns {{measurement: string, reason: string|null, controlHeld: boolean|null,
 *            residue: {stack: string, gpr: string, xmm: string},
 *            longestRunBytes: number|null, controlRunBytes: number|null}}
 */
export function gradeCell(obs, opts) {
  const floor = Number.isInteger(opts && opts.floor) ? opts.floor : PARTIAL_FLOOR;
  const nl = opts && opts.needleLen;
  const cl = opts && opts.controlNeedleLen;
  const notObserved = (reason, controlHeld = null) => ({
    measurement: 'BROKEN_MEASUREMENT',
    reason,
    controlHeld,
    residue: { stack: 'NOT_OBSERVED', gpr: 'NOT_OBSERVED', xmm: 'NOT_OBSERVED' },
    longestRunBytes: null,
    controlRunBytes: null,
  });

  if (opts && opts.notRun) return notObserved(opts.notRun);
  if (!obs || typeof obs !== 'object') return notObserved('no-observer-record');
  if (obs.ok !== true) return notObserved(`observer-failed: ${String(obs.error || 'unstated')}`);
  if (!Number.isInteger(nl) || !Number.isInteger(cl) || nl <= 0 || cl <= 0) {
    return notObserved('needle-length-unknown');
  }

  const stop = obs.stop || {};
  if (stop.matched !== true || stop.rspMatched !== true) {
    // A stop that is not the one asked for is not a place to take a reading
    // from. Turning it into a verdict is the exact failure this lane is built to
    // make impossible, so it is the first thing checked after the record parses.
    return notObserved('stop-mismatch');
  }
  const map = obs.map || {};
  if (map.base !== map.expectedBase) return notObserved('load-bias-not-zero');
  const text = obs.text || {};
  if (text.compared !== true || text.restoredMatchesFile !== true) return notObserved('text-not-restored');
  const win = obs.window || {};
  if (!Number.isInteger(win.bytesRead) || !Number.isInteger(win.requested) || win.bytesRead < win.requested) {
    return notObserved('short-window');
  }

  // ---- did the window reach the SUBJECT's frame? -------------------------
  //
  // Checked before the co-resident control, and that order is the point. A
  // shallow window can leave the control readable and the subject outside, so
  // naming the control here would send the operator to look at the wrong thing.
  // The bound is external to the observation: it is read out of the binary that
  // was run, not inferred from what the observation happened to contain.
  const frame = opts && opts.frame;
  const margin = Number.isInteger(opts && opts.frameMargin) ? opts.frameMargin : FRAME_MARGIN_BYTES;
  if (!frame || typeof frame !== 'object') return notObserved('subject-frame-not-measured');
  if (frame.parsed !== true || !Number.isInteger(frame.subjectBytes) || frame.subjectBytes < 0) {
    return notObserved(`subject-frame-unparsed: ${String(frame.why || 'unstated')}`);
  }
  if (!Number.isInteger(win.lo) || !Number.isInteger(stop.rsp)) return notObserved('window-bounds-unknown');
  const need = requiredBelow(frame, margin);
  const reached = stop.rsp - win.lo;
  if (!Number.isInteger(reached) || reached < need) {
    // The required size is in the reason so the operator is told what to pass
    // rather than left to work it out from a frame number -- unless the number
    // is one the observer would refuse, in which case saying "pass it" would be
    // sending them somewhere that returns usage() and no record at all.
    const above = Number.isInteger(win.hi) ? win.hi - stop.rsp : 0;
    const fits = need + above <= WINDOW_MAX_BYTES;
    return notObserved(`window-shallower-than-subject-frame: reached ${reached} bytes below the stop rsp, `
      + `the subject frame needs ${need} (frame ${frame.subjectBytes} B via ${frame.form || 'unstated'}, `
      + `margin ${margin} B) -- ${fits ? `run it again with --below ${need}`
        : `which is past the observer's ${WINDOW_MAX_BYTES}-byte window ceiling, so this subject cannot be `
          + 'measured by the instrument as built'}`);
  }

  const ctlRun = obs.stackControl ? obs.stackControl.longestRunBytes : null;
  if (!Number.isInteger(ctlRun) || ctlRun < cl) {
    // Measured, and it fell. interfaces.md section 3.1 is explicit that this is
    // `false` and not `null`: null claims nobody ran a control.
    return { ...notObserved('coresident-control-unreadable', false), controlRunBytes: Number.isInteger(ctlRun) ? ctlRun : null };
  }

  const stackRun = obs.stack ? obs.stack.longestRunBytes : null;
  if (!Number.isInteger(stackRun)) return notObserved('no-stack-count', true);

  const gprRun = obs.gpr && Number.isInteger(obs.gpr.longestRunBytes) ? obs.gpr.longestRunBytes : 0;
  const xmmRun = obs.xmm && Number.isInteger(obs.xmm.longestRunBytes) ? obs.xmm.longestRunBytes : 0;

  return {
    measurement: 'OK',
    reason: null,
    controlHeld: true,
    residue: {
      stack: classify(stackRun, nl, floor),
      // Reported BESIDE the stack reading and excluded from the headline: a
      // register holding secret bytes is the ABI's doing, not the wipe's. The
      // GPRs come from PTRACE_GETREGS, which cannot fail separately here; xmm
      // comes from PTRACE_GETFPREGS, which can, and a failed fpregs read is
      // NOT_OBSERVED rather than a clean xmm. ymm/zmm upper halves are outside
      // what PTRACE_GETFPREGS returns and are unobserved in every cell.
      gpr: classify(gprRun, nl, floor),
      xmm: obs.fpregsRead === true ? classify(xmmRun, nl, floor) : 'NOT_OBSERVED',
    },
    longestRunBytes: stackRun,
    controlRunBytes: ctlRun,
  };
}

/**
 * Did one run-level control do what it exists to do?
 *
 * A control whose measurement is not OK has NOT held -- it has failed to run,
 * which is worse than reading the wrong thing, because a run that continues past
 * it is unqualified. Both cases return held: false, with the reason kept apart.
 */
export function gradeControl(name, graded) {
  const spec = CONTROLS[name];
  if (!spec) return { name, held: false, why: 'not a control this lane defines' };
  if (!graded || graded.measurement !== 'OK') {
    return { name, held: false, why: `did not measure (${graded ? graded.reason : 'no grade'})` };
  }
  const got = graded.residue.stack;
  if (got !== spec.expect) {
    return { name, held: false, why: `expected ${spec.expect}, read ${got} (longest run ${graded.longestRunBytes} bytes)` };
  }
  return { name, held: true, why: null };
}

/**
 * Is the whole run worth writing down?
 *
 * All three controls must have held. One that did not means the instrument is
 * not qualified for ANY cell in the run, including the ones that look like
 * findings -- especially those. The caller exits non-zero and writes no data.
 */
export function runValidity(controlGrades) {
  const names = Object.keys(CONTROLS);
  const problems = [];
  for (const n of names) {
    const g = Array.isArray(controlGrades) ? controlGrades.find((c) => c && c.name === n) : null;
    if (!g) { problems.push(`${n}: not run`); continue; }
    if (!g.held) problems.push(`${n}: ${g.why}`);
  }
  return { valid: problems.length === 0, problems };
}

/**
 * The pairing rule of interfaces.md section 3.1, as a check rather than a
 * sentence: a cell whose measurement is not OK carries no reading, and a cell
 * whose measurement IS OK carries one.
 */
export function assertPairing(rows) {
  const bad = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    const m = r.measurement;
    const s = r.residue && r.residue.stack;
    if (m !== 'OK' && s !== 'NOT_OBSERVED') bad.push(`${r.cell}: measurement ${m} with residue ${s}`);
    if (m === 'OK' && s === 'NOT_OBSERVED') bad.push(`${r.cell}: measurement OK with residue NOT_OBSERVED`);
    if (m !== 'OK' && r.controlHeld === true) bad.push(`${r.cell}: measurement ${m} with controlHeld true`);
  }
  return { ok: bad.length === 0, problems: bad };
}

/**
 * The headline: what the differential-compilation verdict said, against what the
 * process actually held.
 *
 * Only cells whose measurement is OK and whose confirm verdict is one of the two
 * WIPE_ verdicts enter the table. Everything else is counted in `excluded` by
 * reason, because a cross-tab with a silent denominator is not one a reader can
 * check.
 */
export function crossTab(rows) {
  const cells = {};
  for (const v of GRADEABLE_CONFIRM) for (const r of ['NONE', 'PARTIAL', 'FULL']) cells[`${v}|${r}`] = 0;
  const excluded = {};
  for (const row of Array.isArray(rows) ? rows : []) {
    const v = row.confirmVerdict;
    const r = row.residue && row.residue.stack;
    if (row.measurement !== 'OK' || !GRADEABLE_CONFIRM.includes(v) || !['NONE', 'PARTIAL', 'FULL'].includes(r)) {
      const key = row.measurement !== 'OK' ? (row.reason || 'not-observed') : `confirm:${v}`;
      excluded[key] = (excluded[key] || 0) + 1;
      continue;
    }
    cells[`${v}|${r}`] += 1;
  }
  const graded = Object.values(cells).reduce((a, b) => a + b, 0);
  return { cells, excluded, graded };
}

/**
 * The two cells of that table that are not ordinary.
 *
 * FINDING     the confirm step said the wipe survived and the secret was still
 *             readable. This is the claim the lane exists to be able to make, and
 *             it is a claim about the instrument pair, not about one of them.
 * ANOMALY     the confirm step said the wipe was ELIMINATED and no residue was
 *             read. That is not good news and is not reported as any. Either the
 *             buffer never reached the window, or something else overwrote it, or
 *             the confirm verdict is about a wipe that was not the one guarding
 *             this buffer. Each needs a look; none is a pass.
 */
export function anomalies(rows) {
  const findings = [];
  const anomalous = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (row.measurement !== 'OK') continue;
    const r = row.residue && row.residue.stack;
    if (row.confirmVerdict === 'WIPE_SURVIVED' && (r === 'FULL' || r === 'PARTIAL')) {
      findings.push(`${row.cell}: confirm said WIPE_SURVIVED, ${row.longestRunBytes} tracer bytes readable at the stop`);
    }
    if (row.confirmVerdict === 'WIPE_ELIMINATED' && r === 'NONE') {
      anomalous.push(`${row.cell}: confirm said WIPE_ELIMINATED yet no residue was read -- not a pass, look at it`);
    }
  }
  return { findings, anomalous };
}
