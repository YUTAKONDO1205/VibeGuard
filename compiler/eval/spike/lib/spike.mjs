/**
 * The grader. Pure: no fs, no child process, no clock, no environment.
 *
 * Analytical chemistry does not ask an assay whether it is working; it spikes
 * the sample with a known quantity of the analyte and reports the fraction
 * recovered beside the result. A recovery short of the spiked amount invalidates
 * the batch -- not the spike, the batch -- because the instrument has just been
 * shown, on this run, not to see what it is for.
 *
 * This is the same move. Every run mixes in one translation unit whose wipe the
 * optimiser is permitted to delete and one whose wipe it is not, and the run's
 * recovery is how many of the two read what they were registered to read.
 * Anything but 2/2 makes the run INVALID and no data is written.
 *
 * Three properties are worth more than the rest of this file:
 *
 *   1. A spike that did not COMPILE is failed, never "held". That is the vacuous
 *      pass this whole lane exists to refuse: a gate that treats an unreadable
 *      spike as an absent violation is green exactly when the instrument is most
 *      broken. COMPILE_ERROR, ABLATION_DID_NOT_COMPILE, NOT_OBSERVED,
 *      NO_WIPE_WRITTEN and VERIFICATION_INCOMPLETE are all readings about the
 *      instrument rather than about the code, and none of them can recover a
 *      spike -- not even the one whose registered answer it happens to match,
 *      which is why a claim spelling one of them is refused as malformed.
 *
 *   2. An unregistered configuration recovers nothing. A spike graded against no
 *      expectation is a spike that always passes, and "we did not look" is not
 *      "it was clean" (interfaces.md section 3, exit code 3).
 *
 *   3. A run needs at least one DISCRIMINATING configuration: one whose two
 *      registered answers are different words. Where both spikes are registered
 *      to read the same thing -- -O0 is exactly that, on both vendors, because
 *      the tracked rows have never put an elimination there -- recovery 2/2 is
 *      also what an instrument that can only ever report that one word would
 *      score, so the pair carries no information about whether it is reading.
 *      Such a rung is legitimate and stays in the matrix (an elimination at -O0
 *      would itself be a finding about the instrument); a run made only of such
 *      rungs is not ESTABLISHED. The injection does not substitute for this: it
 *      breaks name resolution, not verdict polarity, so an instrument stuck on
 *      one word passes the injection exactly as a working one does.
 *
 * The vocabulary of `verdict` is the ablation cell's
 * (../../ai-generated/lib/ablation-cell.mjs verdictOf) on the differential
 * channel and interfaces.md section 3's property states on the observer channel.
 * Nothing here knows which; both are compared as opaque strings against what was
 * registered, so the grader cannot be the place that quietly re-interprets a
 * word.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

/** The two members of the pair, in the order a report lists them. */
export const SPIKES = Object.freeze(['disappearing', 'surviving']);

/**
 * Readings that are claims about the INSTRUMENT, not about the subject.
 *
 * Each one means a compile, an ablation or a body read did not happen, so there
 * is no property state to compare. interfaces.md section 3.1: a cell that failed
 * to measure is NOT_OBSERVED with the reason beside it, and it is excluded --
 * never graded as though a reading had come back.
 */
export const NOT_A_READING = Object.freeze([
  'COMPILE_ERROR',
  'ABLATION_DID_NOT_COMPILE',
  'NOT_OBSERVED',
  'NO_WIPE_WRITTEN',
  'VERIFICATION_INCOMPLETE',
  'UNSUPPORTED',
  'BROKEN_MEASUREMENT',
]);
const NOT_A_READING_SET = new Set(NOT_A_READING);

/** Violation codes, so that a caller can branch without parsing prose. */
export const VIOLATION = Object.freeze({
  NO_EXPECTATION: 'NO_EXPECTATION',
  MALFORMED_EXPECTATION: 'MALFORMED_EXPECTATION',
  MISSING_READING: 'MISSING_READING',
  DUPLICATE_READING: 'DUPLICATE_READING',
  UNKNOWN_SPIKE: 'UNKNOWN_SPIKE',
  NO_VERDICT: 'NO_VERDICT',
  NOT_A_READING: 'NOT_A_READING',
  CONTROL_NOT_PRESENT: 'CONTROL_NOT_PRESENT',
  WRONG_VERDICT: 'WRONG_VERDICT',
  INJECTION_NOT_DETECTED: 'INJECTION_NOT_DETECTED',
  INJECTION_NOT_GRADEABLE: 'INJECTION_NOT_GRADEABLE',
  NO_DISCRIMINATING_CONFIGURATION: 'NO_DISCRIMINATING_CONFIGURATION',
});

const isString = (v) => typeof v === 'string' && v.length > 0;

/**
 * Grade ONE configuration's pair of readings against what was registered for it.
 *
 * @param {Array<{spike: string, verdict?: string, control?: string}>} readings
 *        the readings of one (vendor, level). Order is irrelevant; the pair is
 *        matched by `spike`.
 * @param {{disappearing?: string, surviving?: string}|null|undefined} expected
 *        the registered answers for that same (vendor, level), or nothing when
 *        the configuration was never registered.
 * @param {{requireControl?: boolean}} [opts]  `requireControl` defaults to true
 *        and NO caller in this lane passes false: both channels carry a co-
 *        resident control column (the observer's is filled from the plugin's own
 *        control SUMMARY row) and both are required to read PRESENT. The option
 *        exists for a channel whose control is a separate reading rather than a
 *        column, and until one exists only ../test/spike.test.mjs exercises it.
 * @returns {{recovery: string, recovered: {num: number, den: number},
 *            held: boolean, discriminating: boolean, sharedAnswer: string|null,
 *            violations: Array<object>}}
 *        `discriminating` is a fact about the EXPECTATION, not about the
 *        readings: it is true when the two registered answers are different
 *        words, so that recovering 2/2 here says something an instrument stuck on
 *        one word could not say. `sharedAnswer` is that one word when they are
 *        the same, and null otherwise. `gateVerdict` refuses a run in which no
 *        configuration is discriminating.
 */
export function gradeSpike(readings, expected, opts = {}) {
  const requireControl = opts.requireControl !== false;
  const violations = [];
  const list = Array.isArray(readings) ? readings : [];
  let recovered = 0;

  // What this configuration was registered to read, before any reading is
  // looked at. Two equal words mean the pair cannot separate an instrument that
  // reads from one that cannot -- see `gateVerdict`.
  const registered = SPIKES.map((s) => (expected && typeof expected === 'object' ? expected[s] : undefined));
  const gradeable = registered.every((w) => isString(w) && !NOT_A_READING_SET.has(w));
  const distinct = new Set(registered.filter(isString));
  const discriminating = gradeable && distinct.size > 1;
  const sharedAnswer = gradeable && distinct.size === 1 ? registered[0] : null;

  for (const r of list) {
    const name = r && r.spike;
    if (!SPIKES.includes(name)) {
      violations.push({
        code: VIOLATION.UNKNOWN_SPIKE, spike: typeof name === 'string' ? name : null,
        detail: 'a reading that is not one of the two spikes',
      });
    }
  }

  for (const spike of SPIKES) {
    const want = expected && typeof expected === 'object' ? expected[spike] : undefined;
    if (!isString(want)) {
      violations.push({
        code: VIOLATION.NO_EXPECTATION, spike,
        detail: 'nothing was registered for this spike in this configuration',
      });
      continue;
    }
    if (NOT_A_READING_SET.has(want)) {
      // Registering a failure word as the answer would make the failure the pass.
      violations.push({
        code: VIOLATION.MALFORMED_EXPECTATION, spike, expected: want,
        detail: 'the registered answer is a word that means no reading came back',
      });
      continue;
    }

    const got = list.filter((r) => r && r.spike === spike);
    if (got.length === 0) {
      violations.push({
        code: VIOLATION.MISSING_READING, spike, expected: want,
        detail: 'this spike produced no reading at all',
      });
      continue;
    }
    if (got.length > 1) {
      violations.push({
        code: VIOLATION.DUPLICATE_READING, spike,
        detail: `${got.length} readings for one spike; which one is the run's is not decidable here`,
      });
      continue;
    }

    const r = got[0];
    if (!isString(r.verdict)) {
      violations.push({
        code: VIOLATION.NO_VERDICT, spike, expected: want,
        detail: 'the reading carries no verdict',
      });
      continue;
    }
    if (NOT_A_READING_SET.has(r.verdict)) {
      violations.push({
        code: VIOLATION.NOT_A_READING, spike, expected: want, got: r.verdict,
        detail: 'the spike did not produce a reading, so it did not hold; this is the vacuous pass the gate refuses',
      });
      continue;
    }
    if (requireControl && r.control !== 'PRESENT') {
      violations.push({
        code: VIOLATION.CONTROL_NOT_PRESENT, spike, got: isString(r.control) ? r.control : null,
        detail: 'the co-resident positive control was not PRESENT, so this listing cannot separate '
          + '"the defence was removed" from "the detector stopped working"',
      });
      continue;
    }
    if (r.verdict !== want) {
      violations.push({
        code: VIOLATION.WRONG_VERDICT, spike, expected: want, got: r.verdict,
        detail: 'the reading is not what was registered for this configuration',
      });
      continue;
    }
    recovered += 1;
  }

  const den = SPIKES.length;
  return {
    recovery: `${recovered}/${den}`,
    recovered: { num: recovered, den },
    held: violations.length === 0 && recovered === den,
    discriminating,
    sharedAnswer,
    violations,
  };
}

/**
 * Grade the DELIBERATELY BROKEN readings of one configuration.
 *
 * A gate that has never been shown to go red has not been shown to be a gate.
 * Every run therefore also measures with the subject's name misspelt, which is
 * the observer's own third silent failure transplanted onto this channel: a
 * valid configuration of a subject that does not exist. The body reader finds
 * nothing, the reading becomes NOT_OBSERVED, and `gradeSpike` must refuse it.
 *
 * The check passes when the gate REFUSED. `wentRed` is that fact; `held` is the
 * same boolean under the name every other check in this lane uses, so a caller
 * can treat all of them alike.
 *
 * It must be possible for this check to FAIL, which is why the injected
 * configuration has to be one the claims file registers. An injection measured
 * at an unregistered (vendor, level) is refused with NO_EXPECTATION before any
 * reading is compared, so it is red whatever came back -- including when nothing
 * was injected at all. A check that cannot fail is not evidence, so that case is
 * INJECTION_NOT_GRADEABLE and the run is NOT ESTABLISHED rather than green on a
 * statement about the claims file. `redBecause` carries the codes the refusal
 * actually rested on, so a reader can see it was the misspelling (NOT_A_READING)
 * and not something else.
 *
 * @returns {{recovery: string, recovered: {num: number, den: number},
 *            wentRed: boolean, held: boolean, gradeable: boolean,
 *            redBecause: string[], violations: Array<object>, inner: object}}
 */
export function gradeInjected(readings, expected, opts = {}) {
  const inner = gradeSpike(readings, expected, opts);
  const ungradeable = inner.violations.filter((v) => v.code === VIOLATION.NO_EXPECTATION
    || v.code === VIOLATION.MALFORMED_EXPECTATION);
  const gradeable = ungradeable.length === 0;
  const wentRed = gradeable && !inner.held;
  const violations = [];
  if (!gradeable) {
    violations.push({
      code: VIOLATION.INJECTION_NOT_GRADEABLE,
      detail: 'the injection was measured at a configuration nothing is registered for, where the gate is red '
        + 'whatever the readings say -- so it shows nothing about the gate\'s sensitivity. Inject at a level the '
        + 'claims file registers; this run is NOT ESTABLISHED',
    });
  } else if (!wentRed) {
    violations.push({
      code: VIOLATION.INJECTION_NOT_DETECTED,
      detail: 'the gate stayed green on readings taken with the subject name deliberately misspelt; '
        + 'it therefore passes runs in which nothing observed the subject, and this run is NOT ESTABLISHED',
    });
  }
  const redBecause = [...new Set(inner.violations.map((v) => v.code))];
  return {
    recovery: inner.recovery,
    recovered: inner.recovered,
    wentRed,
    held: wentRed,
    gradeable,
    redBecause,
    violations,
    inner,
  };
}

/** How a reason names one configuration: vendor, level, and the channel when it is not the usual one. */
function configurationLabel(c) {
  const vendor = c && c.vendor ? c.vendor : '?';
  const opt = c && c.opt ? c.opt : '?';
  const channel = c && c.channel && c.channel !== 'differential' ? ` [${c.channel}]` : '';
  return `${vendor} ${opt}${channel}`;
}

/**
 * The run-level verdict, from every configuration's grade and the injection.
 *
 * Kept here, pure, so that "was this run valid" is decided by the same code in
 * every harness that asks -- the point of the lane being importable at all.
 *
 * A run is established when every configuration held, at least one of them was
 * DISCRIMINATING, and the injected run went red. The middle condition is the one
 * that is easy to leave out and expensive to leave out: at -O0 both spikes are
 * registered to read WIPE_SURVIVED, so a -O0-only run recovers 2/2 for an
 * instrument that reports WIPE_SURVIVED for everything -- for a `verdictOf` that
 * has been made structurally incapable of ever saying WIPE_ELIMINATED. That was
 * measured, not imagined: with the elimination branch of verdictOf removed in a
 * copy, `--opt -O0` on both vendors printed ESTABLISHED 2/2 and exited 0. The
 * injection does not cover it, because the injection misspells the subject's
 * NAME: it proves the gate can refuse a run that observed nothing, and an
 * instrument stuck on one verdict observes the subject perfectly well.
 *
 * -O0 is not thereby dropped. It is a real rung and an elimination there would
 * be a finding about the instrument; what is refused is a run consisting only of
 * rungs that cannot tell the two spikes apart.
 *
 * @param {Array<{vendor: string, opt: string, grade: object}>} configurations
 * @param {{held: boolean, violations: Array<object>}|null} injected
 * @returns {{established: boolean, reasons: string[],
 *            configurations: {num: number, den: number},
 *            discriminating: {num: number, den: number}}}
 */
export function gateVerdict(configurations, injected) {
  const list = Array.isArray(configurations) ? configurations : [];
  const reasons = [];
  if (list.length === 0) reasons.push('no configuration was measured, so nothing validated this run');
  for (const c of list) {
    const g = c && c.grade;
    if (!g || !g.held) {
      const why = (g && g.violations ? g.violations : [])
        .map((v) => (v.spike ? `${v.code}(${v.spike})` : v.code)).join(', ');
      const recovery = g && g.recovery ? g.recovery : '0/2';
      reasons.push(`${configurationLabel(c)}: recovery ${recovery}${why ? ` -- ${why}` : ''}`);
    }
  }

  const discriminating = list.filter((c) => c && c.grade && c.grade.discriminating === true);
  if (list.length > 0 && discriminating.length === 0) {
    const which = list.map((c) => {
      const shared = c && c.grade ? c.grade.sharedAnswer : null;
      return `${configurationLabel(c)} (${shared
        ? `both spikes registered ${shared}`
        : 'no pair of registered answers to compare'})`;
    }).join('; ');
    reasons.push(`${VIOLATION.NO_DISCRIMINATING_CONFIGURATION}: no configuration in this run registers two `
      + 'different answers, so recovering 2/2 in every one of them is also what an instrument that can only ever '
      + `report one word would score. Non-discriminating: ${which}. Add a configuration whose two registered `
      + 'answers differ -- any level above -O0 on either registered vendor is one');
  }

  if (!injected) reasons.push('the injected run was not performed, so the gate was never shown to go red');
  else if (!injected.held) for (const v of injected.violations) reasons.push(v.detail);
  const held = list.filter((c) => c && c.grade && c.grade.held).length;
  return {
    established: reasons.length === 0,
    reasons,
    configurations: { num: held, den: list.length },
    discriminating: { num: discriminating.length, den: list.length },
  };
}
