// Controls for the harness itself.
//
// The table this harness produces is a list of things that were detected. A
// detector that always says yes produces the same table, and so does a harness
// that cannot tell a silent failure from a clean result. So each of the three
// components that can fail silently is deliberately broken here, in the same
// run, and the result is written into the same record as the measurement.
//
// A control that does not fail is a control that was not testing anything, so
// each one states what it must produce and the run reports `held: false` when it
// does not. Nothing here is allowed to be skipped quietly: a control that could
// not be run is UNSUPPORTED with a reason, never absent.

import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { parseObserverLog } from './gates.mjs';

export function runControls({ run, evaluate, observerSo, workRoot, fixtureDir, manifest, prop, cell, layers }) {
  const controls = [];
  const dir = path.join(workRoot, 'controls');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });

  /* --- negative control: the observer with no configuration at all -------- */
  //
  // The documented silent failure. rc stays 0, the object file is still
  // produced, and nothing is measured. If a gate read that as "nothing was
  // lost", every NOT_DETECTED in column D would be worthless.
  {
    const log = path.join(dir, 'noenv.tsv');
    const r = run(cell.compiler, [...cell.flags, '-c', manifest.sources.target, '-o', path.join(dir, 'noenv.o'), `-fpass-plugin=${observerSo}`], { cwd: fixtureDir });
    const refused = /refusing to install/.test(r.stderr);
    const wroteLog = existsSync(log);
    controls.push({
      id: 'observer-unconfigured',
      polarity: 'negative',
      what: 'the observer plugin is loaded with no OBS_* variables set',
      mustProduce: 'compiler exit 0, no log, and "refusing to install" on stderr',
      observed: { exitCode: r.status, stderrHead: r.stderr.trim().split('\n')[0] || '', logWritten: wroteLog },
      held: r.status === 0 && refused && !wroteLog,
      consequence:
        'a run in this state exits 0 and produces an object file. Column D reports ' +
        'VERIFICATION_INCOMPLETE for it, never NOT_DETECTED',
    });
  }

  /* --- red demonstration: the observer pointed at a subject that is not there */
  //
  // The failure the co-resident control cannot catch. The control resolves, the
  // control is PRESENT, STATS counts hundreds of passes, and only the subject's
  // rows are missing — which is also what a subject erased before the first
  // boundary looks like. SUBJECTRES is the only thing that separates them.
  {
    const log = path.join(dir, 'badsubject.tsv');
    const env = {
      OBS_TARGET_FN: `${prop.targetFn}_this_name_does_not_exist`,
      OBS_CONTROL_FN: prop.oracleControlFn,
      OBS_EFFECT_SYMBOLS: (prop.effectSymbols || []).join(','),
      OBS_OUT: log,
      OBS_MODE: 'standard',
    };
    const r = run(cell.compiler, [...cell.flags, '-c', manifest.sources.target, '-o', path.join(dir, 'badsubject.o'), `-fpass-plugin=${observerSo}`], { cwd: fixtureDir, env });
    const parsed = existsSync(log) ? parseObserverLog(readFileSync(log, 'utf8')) : null;
    const subj = parsed ? parsed.subjectRes.filter((s) => s.role === 'subject') : [];
    const ctrl = parsed ? parsed.subjectRes.filter((s) => s.role === 'control') : [];
    const subjectUnresolved = subj.length > 0 && subj.every((s) => s.resolution !== 'resolved');
    const controlStillFine = ctrl.some((s) => s.resolution === 'resolved');
    controls.push({
      id: 'observer-subject-not-in-module',
      polarity: 'red',
      what: 'the observer is pointed at a subject name that does not exist, with a valid control',
      mustProduce:
        'exit 0, a non-empty log, the control resolved, the subject NOT resolved — so that the gate ' +
        'reports VERIFICATION_INCOMPLETE and not NOT_DETECTED',
      observed: {
        exitCode: r.status,
        logWritten: Boolean(parsed),
        passesSeen: parsed && parsed.stats ? parsed.stats.passesSeen : null,
        subjectResolutions: subj.map((s) => s.resolution),
        controlResolutions: ctrl.map((s) => s.resolution),
      },
      held: r.status === 0 && Boolean(parsed) && subjectUnresolved && controlStillFine,
      consequence:
        'every invariant a co-resident control can check is satisfied in this run. Without SUBJECTRES the ' +
        'gate would have reported a clean NOT_DETECTED',
    });
  }

  /* --- red demonstration: the ground-truth oracle with no readable control -- */
  //
  // The refusal path, exercised in the way that does not depend on the family:
  // name a control function that is not in the text. If the oracle answered
  // anyway, every PRESERVED and every LOST row in the table would be a reading
  // taken without an oracle check.
  {
    const bogus = { ...prop, oracleControlFn: `${prop.oracleControlFn}_this_name_does_not_exist` };
    const reading = evaluate({ layer: 'asm', text: layers.asm, spec: bogus });
    controls.push({
      id: 'ground-truth-oracle-no-control',
      polarity: 'red',
      what: 'the assembly-layer oracle is given a control function name that is not in the text',
      mustProduce: 'INVALID_CONTROL — the oracle refuses rather than reporting the subject either way',
      observed: { verdict: reading.verdict, reason: reading.reason || null },
      held: reading.verdict === 'INVALID_CONTROL',
      consequence:
        'a LOST in the ground-truth column is a claim that the control was visible in the same text. ' +
        'This shows the column can say no',
    });
  }

  /* --- red demonstration: the oracle's symbol list replaced with a fiction --- */
  //
  // What this shows depends on the family, and the expectation is written per
  // family rather than assumed. For `callSite` and `guardedCheck` the symbol
  // list IS the oracle, so a fictional list must blind it. For `erasure` it is
  // not: the assembly extractor also counts inline zeroing stores, which no
  // symbol list can turn off, so a wrong symbol list does NOT blind this oracle
  // — and that is a limit of the co-resident control worth recording rather
  // than a control that failed.
  {
    const symbolIsTheWholeOracle = prop.family !== 'erasure';
    const bogus = { ...prop, effectSymbols: ['vgc_ablation_symbol_that_is_never_called'] };
    const reading = evaluate({ layer: 'asm', text: layers.asm, spec: bogus });
    controls.push({
      id: 'ground-truth-oracle-fictional-symbols',
      polarity: 'red',
      family: prop.family,
      what: 'the assembly-layer oracle is configured against an effect symbol that appears nowhere',
      mustProduce: symbolIsTheWholeOracle
        ? `INVALID_CONTROL: for family '${prop.family}' the symbol list is the whole oracle`
        : `a verdict other than INVALID_CONTROL: for family '${prop.family}' the assembly extractor also counts ` +
          'inline zeroing stores, so the control stays visible no matter what the symbol list says',
      observed: { verdict: reading.verdict, reason: reading.reason || null },
      held: symbolIsTheWholeOracle ? reading.verdict === 'INVALID_CONTROL' : reading.verdict !== 'INVALID_CONTROL',
      consequence: symbolIsTheWholeOracle
        ? 'a misconfigured symbol list is caught by the control for this family'
        : 'a misconfigured symbol list is NOT caught by the control for this family. The co-resident control ' +
          'defends against the compiler changing the form of the effect; it does not defend against the ' +
          'oracle being pointed at the wrong effect',
    });
  }

  /* --- positive control: the oracle correctly configured on the same text -- */
  {
    const reading = evaluate({ layer: 'asm', text: layers.asm, spec: prop });
    controls.push({
      id: 'ground-truth-oracle-configured',
      polarity: 'positive',
      what: 'the same oracle on the same assembly with the fixture\'s declared effect symbols',
      mustProduce: 'a verdict other than INVALID_CONTROL',
      observed: { verdict: reading.verdict, effect: reading.effect ? reading.effect.count : null, control: reading.control ? reading.control.count : null },
      held: reading.verdict !== 'INVALID_CONTROL' && reading.verdict !== 'UNOBSERVED',
      consequence: 'the refusal above is a property of the configuration, not of the fixture',
    });
  }

  /* --- positive control: the observer, correctly configured, on the same cell */
  {
    const log = path.join(dir, 'positive.tsv');
    const env = {
      OBS_TARGET_FN: prop.targetFn,
      OBS_CONTROL_FN: prop.oracleControlFn,
      OBS_EFFECT_SYMBOLS: (prop.effectSymbols || []).join(','),
      OBS_OUT: log,
      OBS_MODE: 'standard',
      OBS_REQUIRE_LIVE_BRANCH: prop.family === 'guardedCheck' ? '1' : '0',
    };
    const r = run(cell.compiler, [...cell.flags, '-c', manifest.sources.target, '-o', path.join(dir, 'positive.o'), `-fpass-plugin=${observerSo}`], { cwd: fixtureDir, env });
    const parsed = existsSync(log) ? parseObserverLog(readFileSync(log, 'utf8')) : null;
    const summary = parsed ? parsed.summary.find((s) => s.role === 'subject') : null;
    controls.push({
      id: 'observer-configured',
      polarity: 'positive',
      what: 'the observer on the same cell with the fixture\'s declared configuration',
      mustProduce: 'a HANDSHAKE, the subject resolved, and a SUMMARY row for the subject',
      observed: {
        exitCode: r.status,
        handshake: Boolean(parsed && parsed.handshake),
        subjectResolutions: parsed ? parsed.subjectRes.filter((s) => s.role === 'subject').map((s) => s.resolution) : [],
        firstLossPass: summary ? summary.firstLossPass : null,
        finalState: summary ? summary.finalState : null,
        passesSeen: parsed && parsed.stats ? parsed.stats.passesSeen : null,
      },
      held: Boolean(parsed && parsed.handshake && summary),
      consequence: 'the two refusals above are properties of the configuration, not of this plugin build',
    });
  }

  return {
    cell: cell.cellId,
    fixtureId: manifest.fixtureId,
    propertyId: prop.propertyId,
    allHeld: controls.every((c) => c.held),
    controls,
  };
}
