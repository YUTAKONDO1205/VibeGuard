/**
 * The gate another harness calls.
 *
 * Three modules meet here and nowhere else: `measure.mjs` produces readings and
 * cannot see the answers, `claims.mjs` holds the answers and measures nothing,
 * and `spike.mjs` compares them and is pure. This file is the wiring, and it is
 * deliberately the only place that imports all three.
 *
 *     import { runSpikeGate } from '<repo>/compiler/eval/spike/lib/gate.mjs';
 *     const gate = await runSpikeGate({ ccs: ['clang-18'], opts: ['-O0', '-O2'], lab });
 *     if (!gate.established) die(3, summarise(gate));   // refuse; write no data
 *
 * `established` is false whenever recovery is short of 2/2 in any configuration,
 * whenever a configuration was never registered, whenever NO configuration in
 * the run registers two different answers, and whenever the deliberately broken
 * run did NOT make the gate go red.
 *
 * The last two are each the difference between a gate and a decoration, and they
 * are not the same difference. The injection is the claim that the gate CAN
 * refuse, re-earned on the same instrument in the same process. The
 * discrimination requirement is the claim that this run asked the instrument to
 * tell the two spikes apart at all: at -O0 both are registered to read
 * WIPE_SURVIVED, so `opts: ['-O0']` recovers 2/2 for an instrument that has been
 * made incapable of ever reporting an elimination -- and such an instrument
 * passes the injection too, because the injection misspells the subject's name
 * rather than inverting a verdict. A caller that passes its own levels through
 * (every wiring patch in the README does) should pass at least one level above
 * -O0 for that reason, and gets a red gate naming the rule if it does not.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import { measureSpikes, probeCompilers, vendorLabel, SUBJECTS, MISSPELT_SUFFIX } from './measure.mjs';
import { measureObserver } from './observer.mjs';
import { loadExpected, expectedFor, observerExpectedFor, CLAIMS_PATH } from './claims.mjs';
import { gradeSpike, gradeInjected, gateVerdict } from './spike.mjs';

export const SCHEMA_VERSION = 'vibeguard.spike-gate/1';

/** Why a run stopped before it could be graded. Maps to an exit code by the caller. */
export const INCOMPLETE = Object.freeze({
  NO_COMPILER: 'NO_COMPILER',
  BAD_CLAIMS: 'BAD_CLAIMS',
});

/**
 * Run the gate.
 *
 * @param {object} args
 * @param {string[]} args.ccs        compiler drivers to gate on
 * @param {string[]} args.opts       levels to gate at
 * @param {string}   args.lab        scratch directory, outside the repository
 * @param {number}  [args.concurrency]
 * @param {string[]} [args.injectAt] levels to run the injection at; defaults to the
 *                                   last requested level, on every requested vendor
 * @param {string}  [args.claimsPath]
 * @returns {Promise<object>} the whole gate reading, ready to be written out
 */
export async function runSpikeGate(args) {
  const { ccs, opts, lab, concurrency = 4, claimsPath = CLAIMS_PATH } = args;
  const injectAt = args.injectAt && args.injectAt.length ? args.injectAt : [opts[opts.length - 1]];

  const probe = await probeCompilers(ccs);
  if (probe.unavailable.length) {
    // Reported as a check that could not be completed, not as UNSUPPORTED.
    // interfaces.md section 3.1 defines that word as "The toolchain refused the
    // invocation, so there was nothing to read. The configuration was asked for
    // and could not be built." -- a sentence about a toolchain that ran, beside
    // one that could be read either way. This lane does not settle another
    // file's vocabulary, and a reader who sees UNSUPPORTED cannot tell "it
    // refused" from "it is not here", so the absent compilers are named instead.
    return {
      schemaVersion: SCHEMA_VERSION,
      established: false,
      incomplete: INCOMPLETE.NO_COMPILER,
      unavailable: probe.unavailable,
      configurations: [],
      injected: null,
      verdict: { established: false, reasons: [`not installed on this host: ${probe.unavailable.join(', ')}`], configurations: { num: 0, den: 0 }, discriminating: { num: 0, den: 0 } },
    };
  }

  let doc;
  try {
    doc = loadExpected(claimsPath);
  } catch (err) {
    return {
      schemaVersion: SCHEMA_VERSION,
      established: false,
      incomplete: INCOMPLETE.BAD_CLAIMS,
      unavailable: [],
      configurations: [],
      injected: null,
      verdict: { established: false, reasons: [err.message], configurations: { num: 0, den: 0 }, discriminating: { num: 0, den: 0 } },
    };
  }

  // A reading is filed under the driver's basename, so that a --cc given as a
  // path grades against the version that was registered.
  const names = ccs.map(vendorLabel);

  const readings = await measureSpikes({ ccs, opts, lab, injected: false, concurrency });
  const configurations = [];
  for (const vendor of names) {
    for (const opt of opts) {
      const cell = readings.filter((r) => r.vendor === vendor && r.opt === opt);
      configurations.push({ channel: 'differential', vendor, opt, readings: cell, grade: gradeSpike(cell, expectedFor(doc, vendor, opt)) });
    }
  }

  const injReadings = await measureSpikes({ ccs, opts: injectAt, lab, injected: true, concurrency });
  const injPer = [];
  for (const vendor of names) {
    for (const opt of injectAt) {
      const cell = injReadings.filter((r) => r.vendor === vendor && r.opt === opt);
      injPer.push({ channel: 'differential', vendor, opt, readings: cell, grade: gradeInjected(cell, expectedFor(doc, vendor, opt)) });
    }
  }

  // ---- the second channel, when a plugin was named -------------------------
  //
  // Not run by default, and a run without it has NOT gated the observer: the
  // gate says so rather than omitting the row, because an absent channel that
  // leaves no trace is indistinguishable from one that passed.
  const obsReq = args.observer || null;
  const observer = {
    requested: !!obsReq,
    available: false,
    reason: obsReq ? null : 'no plugin was named, so the observer channel was not run in this run',
    vendor: obsReq ? vendorLabel(obsReq.cc || 'clang-18') : null,
    opt: obsReq ? obsReq.opt : null,
    readings: [],
    grade: null,
    injected: null,
  };
  if (obsReq) {
    const oOpt = obsReq.opt;
    const oCc = obsReq.cc || 'clang-18';
    const oName = vendorLabel(oCc);
    const wantObs = observerExpectedFor(doc, oOpt);
    const main = await measureObserver({ plugin: obsReq.plugin, cc: oCc, opt: oOpt, lab, injected: false });
    observer.available = main.available;
    observer.reason = main.reason || null;
    observer.readings = main.readings;
    if (main.available) {
      const inj = await measureObserver({ plugin: obsReq.plugin, cc: oCc, opt: oOpt, lab, injected: true });
      observer.grade = gradeSpike(main.readings, wantObs);
      observer.injected = { readings: inj.readings, grade: gradeInjected(inj.readings, wantObs) };
      configurations.push({ channel: 'observer', vendor: oName, opt: oOpt, readings: main.readings, grade: observer.grade });
      injPer.push({ channel: 'observer', vendor: oName, opt: oOpt, readings: inj.readings, grade: observer.injected.grade });
    } else {
      // Asked for and not obtainable. NOT_OBSERVED with the reason beside it --
      // never a silent pass, and never "the channel was clean".
      configurations.push({
        channel: 'observer',
        vendor: oName,
        opt: oOpt,
        readings: [],
        grade: {
          recovery: '0/2',
          recovered: { num: 0, den: 2 },
          held: false,
          // No reading came back, so this row cannot be the run's discriminating
          // configuration either -- the same shape gradeSpike returns, so that
          // gateVerdict does not have to know which rows it built itself.
          discriminating: false,
          sharedAnswer: null,
          violations: [{ code: 'MISSING_READING', spike: null, detail: observer.reason }],
        },
      });
    }
  }
  const injected = {
    misspeltSuffix: MISSPELT_SUFFIX,
    configurations: injPer,
    held: injPer.length > 0 && injPer.every((c) => c.grade.held),
    violations: injPer.flatMap((c) => c.grade.violations.map((v) => ({ ...v, vendor: c.vendor, opt: c.opt }))),
  };
  if (injPer.length === 0) {
    injected.violations.push({
      code: 'INJECTION_NOT_DETECTED',
      detail: 'no injected configuration was run, so the gate was never shown to go red',
    });
  }

  const verdict = gateVerdict(configurations, injected);
  return {
    schemaVersion: SCHEMA_VERSION,
    established: verdict.established,
    incomplete: null,
    unavailable: [],
    subjects: SUBJECTS.map((s) => ({ spike: s.spike, file: s.file, fn: s.fn })),
    configurations,
    injected,
    observer,
    verdict,
  };
}

/**
 * What the injected run showed, in three words rather than two.
 *
 * "stayed GREEN" would be a lie about an injection measured where nothing is
 * registered: there the gate is red before any reading is looked at, so it was
 * never asked the question. That case is named rather than folded into either
 * outcome.
 */
function injectionWord(injected) {
  if (!injected) return 'no injection';
  if (injected.held) return 'injection RED (as required)';
  const cfgs = injected.configurations || [];
  if (cfgs.some((c) => c.grade && c.grade.gradeable === false)) {
    return 'injection NOT GRADEABLE (unregistered configuration)';
  }
  return 'injection stayed GREEN';
}

/**
 * A one-line summary a harness can print before it decides what to do.
 *
 * The discriminating count is on the line because 2/2 everywhere does not by
 * itself say the instrument was reading: a reader needs to see that at least one
 * of those configurations registered two different answers.
 */
export function summarise(gate) {
  const parts = gate.configurations.map((c) => `${c.vendor}${c.opt}${c.channel === 'observer' ? '[obs]' : ''} ${c.grade.recovery}`);
  const inj = injectionWord(gate.injected);
  const d = gate.verdict && gate.verdict.discriminating;
  const disc = d ? ` -- ${d.num}/${d.den} discriminating` : '';
  return `spike gate: ${gate.established ? 'ESTABLISHED' : 'NOT ESTABLISHED'} -- ${parts.join(' | ')} -- ${inj}${disc}`;
}
