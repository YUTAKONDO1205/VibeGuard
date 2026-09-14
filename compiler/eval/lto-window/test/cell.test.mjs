/**
 * The two vocabularies, and the rule that keeps them apart.
 *
 * `../../schema/interfaces.md` section 3.1 says it in one line -- a cell whose
 * measurement is not OK has state NOT_OBSERVED -- and the subsection under it
 * records what happened twice when `controlHeld` was read as null-always: two
 * components described a control that demonstrably fell as one nobody measured,
 * and the list of removals was wrong for 16 of 20 entries in the first real
 * envelope. So `false` and `null` are tested here as different answers rather
 * than as two spellings of "not true".
 *
 * No compiler is required and nothing is measured here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { gradeCell, finish, gccChannelRefusal, MEASUREMENT, STATE, REASON, NOTE } from '../lib/cell.mjs';

const summary = (over = {}) => ({
  unit: 'handle', lineage: 'handle', role: 'subject',
  firstLossSeq: null, firstLossPass: null, finalState: STATE.PRESENT,
  everPresent: true, everLost: false, everReintroduced: false, fate: 'LIVE', ...over,
});

const healthyGuards = {
  inputs: { ok: true, problems: [] },
  linkerPipeline: { runs: 176 },
  passAgreement: { comparable: true, subset: true },
  logIntact: true,
  evidenceRecords: 388,
};

test('the substantive shape: subject LOST at a named pass, control PRESENT, measurement OK', () => {
  const c = gradeCell({
    guards: healthyGuards,
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass', firstLossSeq: 206 }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.OK);
  assert.equal(c.state, STATE.LOST);
  assert.equal(c.controlHeld, true);
  assert.deepEqual(c.attribution, { pass: 'DSEPass', unit: 'handle', checkpoint: 'after-pass' });
});

test('ABSENT throughout is a result, and it carries no attribution', () => {
  // The erasure family at link time when its control still holds: the loss was
  // complete before the link began. A link-time window that invented a pass for
  // it would be attributing to the wrong stage.
  const c = gradeCell({
    guards: healthyGuards,
    subject: summary({ finalState: STATE.ABSENT, everPresent: false }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.OK);
  assert.equal(c.state, STATE.ABSENT);
  assert.equal(c.attribution, null);
});

test('a control that fell gives controlHeld false -- measured and failed, not unmeasured', () => {
  const c = gradeCell({
    guards: healthyGuards,
    subject: summary({ finalState: STATE.ABSENT }),
    control: summary({ unit: 'wipe_kept', role: 'control', finalState: STATE.LOST, everLost: true, firstLossPass: 'SROAPass' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.controlHeld, false);
  assert.notEqual(c.controlHeld, null);
  assert.ok(c.reasons.includes(REASON.CONTROL_DID_NOT_HOLD));
  assert.ok(c.reasons.some((r) => /SROAPass/.test(r)));
});

test('a refused cell gives controlHeld null -- no control was run at all', () => {
  const c = gradeCell({ refusal: { measurement: MEASUREMENT.UNSUPPORTED, reason: REASON.LINKER_REFUSED_PLUGIN_OPTION } });
  assert.equal(c.measurement, MEASUREMENT.UNSUPPORTED);
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.controlHeld, null);
  assert.equal(c.attribution, null);
});

test('UNSUPPORTED and BROKEN_MEASUREMENT are different answers and stay different', () => {
  const gcc = gradeCell({ refusal: { measurement: MEASUREMENT.UNSUPPORTED, reason: REASON.LINKER_REFUSED_PLUGIN_OPTION } });
  const thin = gradeCell({ refusal: { measurement: MEASUREMENT.BROKEN_MEASUREMENT, reason: REASON.MULTI_PASSBUILDER } });
  assert.notEqual(gcc.measurement, thin.measurement);
  // Both are NOT_OBSERVED: neither is a claim about the property. That is the
  // composition section 3.1 is built for.
  assert.equal(gcc.state, STATE.NOT_OBSERVED);
  assert.equal(thin.state, STATE.NOT_OBSERVED);
});

test('guard 1: inputs that are not bitcode stop the cell before anything is read', () => {
  const c = gradeCell({
    guards: { ...healthyGuards, inputs: { ok: false, problems: ['use.o is elf, not LLVM bitcode: this link is not an LTO link'] } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(c.attribution, null);
  assert.ok(c.reasons.includes(REASON.NOT_AN_LTO_LINK));
});

test('guard 1: an empty linker pass log is refused even when the observer wrote plenty', () => {
  const c = gradeCell({
    guards: { ...healthyGuards, linkerPipeline: { runs: 0 } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(c.reasons.includes(REASON.NOT_AN_LTO_LINK));
});

test('guard 2: a disagreement is a broken measurement, not a result', () => {
  const c = gradeCell({
    guards: { ...healthyGuards, passAgreement: { comparable: true, subset: false } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(c.reasons.includes(REASON.PASS_READINGS_DISAGREE));
});

test('an observer that produced no evidence fails rather than passing quietly', () => {
  // Byte-identity is trivially true for a plugin that declined to install, so a
  // run with zero EV records is the one shape that must never read as clean.
  const c = gradeCell({
    guards: { ...healthyGuards, evidenceRecords: 0 },
    subject: null, control: null,
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(c.reasons.includes(REASON.NO_EVIDENCE_RECORDS));
});

test('a shredded log fails before any of its rows are believed', () => {
  const c = gradeCell({
    guards: { ...healthyGuards, logIntact: false },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(c.reasons.includes(REASON.OBSERVER_LOG_NOT_INTACT));
});

test('a subject name that did not resolve is a broken measurement, not an absence', () => {
  const c = gradeCell({
    guards: healthyGuards, subject: null,
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: false,
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.ok(c.reasons.includes(REASON.SUBJECT_DID_NOT_RESOLVE));
});

test('the pairing rule holds over every combination this lane can reach', () => {
  // finish() is the only exit from gradeCell and it throws on an illegal pair,
  // so an edit that produced one would fail here rather than write a record.
  // Swept rather than spot-checked, because the rule is about ALL cells and a
  // rule tested on the cases someone remembered is the rule that was broken.
  const guardSets = [
    healthyGuards,
    { ...healthyGuards, inputs: { ok: false, problems: ['not bitcode'] } },
    { ...healthyGuards, linkerPipeline: { runs: 0 } },
    { ...healthyGuards, passAgreement: { comparable: true, subset: false } },
    { ...healthyGuards, logIntact: false },
    { ...healthyGuards, evidenceRecords: 0 },
  ];
  const subjects = [
    null,
    summary({ finalState: STATE.ABSENT, everPresent: false }),
    summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass', firstLossSeq: 206 }),
    summary({ finalState: STATE.REINTRODUCED, everLost: true, everReintroduced: true, firstLossPass: 'DSEPass' }),
  ];
  const controls = [
    null,
    summary({ unit: 'wipe_kept', role: 'control' }),
    summary({ unit: 'wipe_kept', role: 'control', finalState: STATE.LOST, everLost: true, firstLossPass: 'SROAPass' }),
  ];
  let seenOk = 0;
  let seenOkNothingRead = 0;
  let seenBroken = 0;
  for (const guards of guardSets) {
    for (const subject of subjects) {
      for (const control of controls) {
        for (const subjectResolved of [true, false, null]) {
          const c = gradeCell({ guards, subject, control, subjectResolved });
          if (c.measurement === MEASUREMENT.OK) {
            seenOk++;
            // This line used to read `assert.notEqual(c.state, STATE.NOT_OBSERVED,
            // 'an OK cell must report a property state')`, and that rule was
            // WRONG -- wrong in the direction that reads as rigour.
            // interfaces.md 3.1 says in bold that `state = NOT_OBSERVED` with
            // `measurement = OK` is LEGAL, and why: "it is a third situation
            // that a symmetric rule would erase. The instrument ran, the record
            // hashes, the control was measured -- and at this point there was no
            // reading of *this* property". The lane threw on that pair and
            // graded the case BROKEN_MEASUREMENT, which blames its own
            // instrument for a fact about the program -- the conflation this
            // whole tree exists to prevent, running in the other direction.
            //
            // What replaces it: an OK cell either reports a property state, or
            // reports NOT_OBSERVED and says WHY it read nothing, with no
            // attribution and a control that was measured and held.
            if (c.state === STATE.NOT_OBSERVED) {
              seenOkNothingRead++;
              assert.ok(c.reasons.length > 0, 'an OK cell that read nothing must say why');
              assert.equal(c.attribution, null, 'an OK cell that read nothing cannot carry an attribution');
              assert.equal(c.controlHeld, true, 'the third situation needs a control that was measured and HELD');
            } else {
              assert.ok(Object.values(STATE).includes(c.state), `${c.state} is not a section-3 state`);
            }
            assert.notEqual(c.controlHeld, false, 'an OK cell cannot have a control that fell');
          } else {
            seenBroken++;
            assert.equal(c.state, STATE.NOT_OBSERVED);
            assert.equal(c.attribution, null);
            // Three legal answers, not two. interfaces.md 3.1's line about a
            // failed cell carrying `null` is written against the null-vs-false
            // confusion; a cell broken for some OTHER reason may still have
            // measured a control that held, and erasing that to null would be
            // the same lie in the other direction. The README asks for the
            // third case to be written down in interfaces.md.
            // "one of three values" is vacuous for anything boolean-or-null,
            // so the three answers are tied to the input instead: null only when
            // no control was measured, false only with the reason that says so.
            assert.ok(c.controlHeld === false || c.controlHeld === null || c.controlHeld === true,
              `controlHeld must be tri-state, got ${String(c.controlHeld)}`);
            if (control === null) assert.equal(c.controlHeld, null);
            if (c.controlHeld === false) assert.ok(c.reasons.includes(REASON.CONTROL_DID_NOT_HOLD));
            if (c.reasons.includes(REASON.CONTROL_DID_NOT_HOLD)) assert.equal(c.controlHeld, false);
          }
        }
      }
    }
  }
  // An empty sweep would pass every assertion above, which is the failure mode
  // this repository keeps finding in its own checks. The third count is here for
  // the same reason: the OK/NOT_OBSERVED branch has to be REACHED by this sweep,
  // or the rule it encodes is untested again.
  assert.ok(seenOk > 0 && seenBroken > 0, `sweep covered ${seenOk} OK and ${seenBroken} not-OK cells`);
  assert.ok(seenOkNothingRead > 0,
    `sweep reached the OK + NOT_OBSERVED case ${seenOkNothingRead} times`);
});

test('interfaces.md 3.1\'s third situation: an instrument that worked with nothing to read', () => {
  // The regression this file was written wrong for. Log intact, evidence
  // records present, the subject name resolved, the control measured and HELD,
  // and no SUMMARY row for the subject: the instrument worked and there was no
  // reading of THIS property here. That is `OK` + NOT_OBSERVED, quoted in bold
  // in interfaces.md 3.1 -- not BROKEN_MEASUREMENT, which would blame the
  // observer for a fact about the program.
  //
  // Reachable, not hypothetical: the observer resolves a subject by lineage
  // (History.cpp:119-129) and records units under their possibly-mangled names
  // (History.cpp:187), so a subject that survives a link only as
  // `handle.llvm.1041` resolves and has no row under `handle`.
  const c = gradeCell({
    guards: healthyGuards,
    subject: null,
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.OK);
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.controlHeld, true);
  assert.equal(c.attribution, null);
  assert.deepEqual(c.reasons, [REASON.NO_SUBJECT_READING]);
  // And the word is its own word: "the observer recorded no history" is the
  // instrument failing and must not be reused for the instrument working.
  assert.ok(!c.reasons.includes(REASON.NO_SUBJECT_HISTORY));
});

test('the same shape with the instrument NOT established stays BROKEN_MEASUREMENT', () => {
  // The other half of the distinction, and the half that must not be lost:
  // every one of these is an instrument whose working was never shown, so a
  // missing subject row is the instrument failing.
  const base = {
    guards: healthyGuards,
    subject: null,
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  };
  const cases = {
    'log integrity never established': { ...base, guards: { ...healthyGuards, logIntact: undefined } },
    'evidence records never counted': { ...base, guards: { ...healthyGuards, evidenceRecords: undefined } },
    'the subject name was never put to a module': { ...base, subjectResolved: null },
    'no control was measured at all': { ...base, control: null },
  };
  for (const [why, input] of Object.entries(cases)) {
    const c = gradeCell(input);
    assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT, why);
    assert.equal(c.state, STATE.NOT_OBSERVED, why);
    assert.ok(c.reasons.includes(REASON.NO_SUBJECT_HISTORY), why);
  }
});

test('the pairing-rule backstop actually throws -- this is the test that says so', () => {
  // finish() is the only exit from gradeCell, and every throw in it could be
  // deleted with all 31 of this lane's tests still passing: the sweep above
  // asserts properties of gradeCell's OUTPUT, which hold whether or not the
  // backstop checks anything. Proved by mutation at the time. So the backstop is
  // exported and exercised directly here.
  assert.throws(
    () => finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.LOST, controlHeld: null, attribution: null, reasons: ['x'] }),
    /requires state NOT_OBSERVED/);
  assert.throws(
    () => finish({ measurement: MEASUREMENT.BROKEN_MEASUREMENT, state: STATE.NOT_OBSERVED, controlHeld: null, attribution: { pass: 'DSEPass' }, reasons: ['x'] }),
    /cannot carry an attribution/);
  assert.throws(
    () => finish({ measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, controlHeld: true, attribution: null, reasons: [] }),
    /must say why nothing was read/);
  assert.throws(
    () => finish({ measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, controlHeld: true, attribution: { pass: 'DSEPass' }, reasons: ['r'] }),
    /cannot carry an attribution/);
  assert.throws(
    () => finish({ measurement: MEASUREMENT.OK, state: STATE.LOST, controlHeld: false, attribution: null, reasons: [] }),
    /control that fell/);
  // And the pair interfaces.md 3.1 declares legal passes through, because the
  // throw that used to stand here is the defect this test exists to keep out.
  const legal = finish({
    measurement: MEASUREMENT.OK, state: STATE.NOT_OBSERVED, controlHeld: true,
    attribution: null, reasons: [REASON.NO_SUBJECT_READING],
  });
  assert.equal(legal.state, STATE.NOT_OBSERVED);
  assert.deepEqual(legal.notes, []);
});

test('the file the verdict is read FROM gets its own integrity guard', () => {
  // Under full LTO the main log has no SUMMARY rows at all (lld exits without
  // unwinding), so every link-time verdict here is read out of
  // `<OBS_OUT>.summary.tsv` -- while `logIntact` was computed on the main log
  // only. The guarded file and the read file were two different files, and the
  // side file is the one this lane's own ThinLTO section calls the dangerous
  // one: "a lane that read only the side file would have published it".
  const c = gradeCell({
    guards: { ...healthyGuards, summaryLogIntact: false },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass', firstLossSeq: 206 }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.attribution, null, 'a torn side file cannot produce an attribution');
  assert.ok(c.reasons.includes(REASON.SUMMARY_LOG_NOT_INTACT));
  // A cell whose summaries came from the main log passes it `null`, which is
  // "this reading did not come from the side file", not "the side file is fine".
  const compileShape = gradeCell({
    guards: { ...healthyGuards, summaryLogIntact: null },
    subject: summary({ finalState: STATE.ABSENT, everPresent: false }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(compileShape.measurement, MEASUREMENT.OK);
});

test('an ordered-sequence disagreement is recorded, and does not refuse the cell', () => {
  // The README used to describe guard 2's refusal as an ordered-sequence
  // comparison. It is not: cell.mjs gates on the SUBSET reading, which is what
  // the task asked for. `sequenceEqual: false` used to be computed, reported in
  // the agreement record and consulted by nothing, so a cell whose two readings
  // had drifted apart in order came out OK with an empty `reasons` array and a
  // full link-time attribution. It still comes out OK -- the passes named are
  // passes the linker really ran -- but the divergence is now on the cell.
  const c = gradeCell({
    guards: { ...healthyGuards, passAgreement: { comparable: true, subset: true, sequenceEqual: false } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass', firstLossSeq: 206 }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(c.measurement, MEASUREMENT.OK);
  assert.deepEqual(c.attribution, { pass: 'DSEPass', unit: 'handle', checkpoint: 'after-pass' });
  assert.deepEqual(c.notes, [NOTE.PASS_READINGS_OUT_OF_ORDER]);
  assert.deepEqual(c.reasons, [], 'a note is not a refusal');
  // A subset violation is still the refusal, and it still wins.
  const refused = gradeCell({
    guards: { ...healthyGuards, passAgreement: { comparable: true, subset: false, sequenceEqual: false } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.equal(refused.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.ok(refused.reasons.includes(REASON.PASS_READINGS_DISAGREE));
  // And the healthy shape carries no note at all.
  const healthy = gradeCell({
    guards: { ...healthyGuards, passAgreement: { comparable: true, subset: true, sequenceEqual: true } },
    subject: summary({ finalState: STATE.LOST, everLost: true, firstLossPass: 'DSEPass' }),
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  });
  assert.deepEqual(healthy.notes, []);
});

test('a refusal with an unknown measurement word still cannot claim a property state', () => {
  const c = gradeCell({ refusal: { measurement: 'NOT_A_WORD', reason: 'x' } });
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.attribution, null);
});

/* ------------------------------------------- the backstop's own coverage -- */

test('finish() refuses a `state` that is not a member of STATE', () => {
  // THE SECOND LAYER. lib/pass-log.mjs now tears a short SUMMARY row before it
  // can become a summary, which closes the input this was measured through --
  // but finish() is the declared backstop ("every return above goes through
  // here, so a future edit that produces an illegal pair throws in this lane
  // instead of writing a record"), and until 2026-09-15 it checked three
  // COMBINATIONS and never checked that `state` was a state at all. The success
  // path copies `summary.finalState` out of the log text with no validation, so
  // whatever is in that field is what gets published.
  //
  // `undefined` is the measured one: a SUMMARY row torn before field 10 parsed
  // into a summary whose finalState was undefined, gradeCell returned
  // `{measurement: 'OK', state: undefined, ...}`, and JSON.stringify then
  // dropped the key -- the published cell had no `state` at all.
  assert.throws(() => finish({ measurement: MEASUREMENT.OK, state: undefined, controlHeld: true, reasons: [] }),
    /is not one of the states/);
  // And a typo, which is the shape a future edit to the observer's stateName()
  // would take. It is not caught by any pairing rule: it is not NOT_OBSERVED,
  // so every existing throw passes it.
  assert.throws(() => finish({ measurement: MEASUREMENT.OK, state: 'PRESNET', controlHeld: true, reasons: [] }),
    /PRESNET/);
  assert.throws(() => finish({ measurement: MEASUREMENT.OK, state: null, controlHeld: true, reasons: [] }),
    /is not one of the states/);
  // Every legal state still goes through, including the two the pairing rules
  // single out.
  for (const s of Object.values(STATE)) {
    const c = finish({ measurement: MEASUREMENT.OK, state: s, controlHeld: true, reasons: ['because'] });
    assert.equal(c.state, s);
  }
});

test('a torn SUMMARY row cannot reach a published cell: both layers, on the measured input', () => {
  // The end-to-end reproduction, as one assertion. Feed gradeCell the summary
  // that a 4-field `SUMMARY\thandle\thandle\tsubject` used to parse into --
  // every field past the cut `undefined` -- and the cell must not come back.
  const torn = {
    unit: 'handle', lineage: 'handle', role: 'subject',
    firstLossSeq: null, firstLossPass: null, finalState: undefined,
    everPresent: false, everLost: false, everReintroduced: false, fate: undefined,
  };
  assert.throws(() => gradeCell({
    guards: healthyGuards,
    subject: torn,
    control: summary({ unit: 'wipe_kept', role: 'control' }),
    subjectResolved: true,
  }), /is not one of the states/);
});

/* ------------------------------------------------------ the gcc cell's rc -- */

const gccProbesAllRefused = () => ({
  loadPassPluginOnGccLink: { rc: 1, stderr: ["/usr/bin/ld: unrecognized option '--load-pass-plugin=<so>'"] },
  llvmPluginIntoLto1: { rc: 1, stderr: ['lto1: error: cannot load plugin <so>: undefined symbol: _ZTVN4llvm18raw_string_ostreamE'] },
  gccObjectsThroughLld: { rc: 1, stderr: ['ld.lld: error: undefined symbol: main'] },
});

test('gccChannelRefusal earns UNSUPPORTED only when every channel was refused', () => {
  const r = gccChannelRefusal(gccProbesAllRefused());
  assert.equal(r.measurement, MEASUREMENT.UNSUPPORTED);
  assert.match(r.reason, /^linker-refused-plugin-option: \/usr\/bin\/ld: unrecognized option/);
  // The rc values that earned it are in the record, so "earned" is readable
  // from the artifact rather than from a comment in the source.
  assert.match(r.details[0], /all 3 gcc channels refused: loadPassPluginOnGccLink rc=1, llvmPluginIntoLto1 rc=1, gccObjectsThroughLld rc=1/);
});

test('a gcc probe that NEVER RAN does not publish UNSUPPORTED either', () => {
  // The second half of the same defect, and the half the first fix left open:
  // splitting rc into "0" and "not 0" files a probe that was never put to the
  // toolchain with the refusals. `run()` in the runner returns `rc: null` when
  // spawnSync fails -- no such binary, or the 180s timeout -- and the third
  // probe passes `-fuse-ld=lld`, so on a host without lld the lane would have
  // called it a refusal. UNSUPPORTED means the toolchain refused; silence is
  // not refusal. Found reviewing the fix, not the code it replaced.
  for (const missing of [null, undefined]) {
    const probes = gccProbesAllRefused();
    probes.gccObjectsThroughLld = { rc: missing, stderr: ['spawnSync ld.lld-18 ENOENT'] };
    const r = gccChannelRefusal(probes);
    assert.equal(r.measurement, MEASUREMENT.BROKEN_MEASUREMENT, `rc: ${String(missing)}`);
    assert.equal(r.reason, REASON.NO_OBSERVER_FOR_VENDOR);
    assert.match(r.details[0], /could not be put to the toolchain at all/);
    assert.match(r.details[0], /not-run: gccObjectsThroughLld/);
    // The rc values stay in the record: which channel was silent is the fact a
    // reader needs, and it is the one an UNSUPPORTED row would have hidden.
    assert.match(r.details[0], /loadPassPluginOnGccLink rc=1/);
  }
  // All three genuinely refused is still UNSUPPORTED -- this test must not be
  // satisfiable by a function that never returns it.
  assert.equal(gccChannelRefusal(gccProbesAllRefused()).measurement, MEASUREMENT.UNSUPPORTED);
});

test('a gcc probe that SUCCEEDED does not publish UNSUPPORTED', () => {
  // The defect, synthesised: until 2026-09-15 the cell was built with no rc
  // anywhere in the expression, so this input published `UNSUPPORTED /
  // linker-refused-plugin-option: no diagnostic` -- the `?? 'no diagnostic'`
  // fallback standing in for a diagnostic that was never printed because
  // nothing was refused.
  const accepted = { ...gccProbesAllRefused(), loadPassPluginOnGccLink: { rc: 0, stderr: [] } };
  const r = gccChannelRefusal(accepted);
  assert.notEqual(r.measurement, MEASUREMENT.UNSUPPORTED, 'the linker did not refuse, so the word is not earned');
  assert.equal(r.measurement, MEASUREMENT.BROKEN_MEASUREMENT);
  assert.equal(r.reason, REASON.NO_OBSERVER_FOR_VENDOR);
  assert.match(r.details[0], /accepted: loadPassPluginOnGccLink/);
  assert.ok(!JSON.stringify(r).includes('no diagnostic'),
    'the no-diagnostic fallback must not stand in for a probe that printed nothing because it succeeded');

  // The other two gate as well: three channels are probed because ONE refusal
  // is not the vendor, so any one of them opening is enough.
  for (const k of ['llvmPluginIntoLto1', 'gccObjectsThroughLld']) {
    const one = { ...gccProbesAllRefused(), [k]: { rc: 0, stderr: [] } };
    assert.equal(gccChannelRefusal(one).measurement, MEASUREMENT.BROKEN_MEASUREMENT, `${k} rc=0 must not read as UNSUPPORTED`);
  }

  // And the cell built from it is a legal cell, not a throw: the refusal is a
  // verdict this lane can publish, it is just not the UNSUPPORTED one.
  const c = gradeCell({ refusal: gccChannelRefusal(accepted) });
  assert.equal(c.state, STATE.NOT_OBSERVED);
  assert.equal(c.attribution, null);
  assert.ok(c.reasons.includes(REASON.NO_OBSERVER_FOR_VENDOR));
});

test('gccChannelRefusal will not grade a cell from no probes at all', () => {
  // An empty object has no accepted channel, so a plain "any accepted?" test
  // would call that a refusal by every channel there is -- of zero channels.
  assert.throws(() => gccChannelRefusal({}), /no probes at all/);
  assert.throws(() => gccChannelRefusal(null), /no probes at all/);
});
