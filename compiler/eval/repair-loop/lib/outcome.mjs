/**
 * The outcome of one repair cell, as a pure function.
 *
 * Inputs are two verdicts produced by the SAME verdict code the find step uses
 * (baseline: plugin off; repaired: plugin on), the two plugin records read by
 * pin-record.mjs, and whether the positive control was PRESENT in the plugin-on
 * compiles. Nothing here compiles, reads a file, or looks at assembly.
 *
 * The plugin's record never decides survival. It is consulted for two things
 * only: whether the repair demonstrably ran (a missing or refused record, or a
 * target it could not find, is BROKEN_REPAIR), and whether it changed anything
 * (pinnedCount), which separates RETAINED from a survival the plugin did not
 * cause.
 *
 * PRECEDENCE -- first match wins, and the order is the argument:
 *
 *   1. NOT_SCORED  (baseline side)  the plugin-off cell is not one of the two
 *      WIPE_ verdicts. Nothing the plugin did can be judged against a baseline
 *      that has no answer, and a file that does not compile without the plugin is
 *      not a broken repair.
 *   2. BROKEN_REPAIR  a record is missing or refused, a requested function was
 *      not resolved (one exact exception: see absentAfterAblation), the two
 *      records disagree about being a dry run, or the
 *      positive control is not PRESENT in a plugin-on compile. Ahead of the
 *      repaired verdict on purpose: a plugin that made the build fail, or made the
 *      oracle blind, must not be reported as "not scored".
 *   3. NOT_SCORED  (repaired side)  the plugin-on cell is not a WIPE_ verdict
 *      although the repair itself is intact (for example, the body could not be
 *      delimited). Both verdicts are carried.
 *   4. the two-by-two table on (baseline, repaired):
 *        SURVIVED   -> SURVIVED    ALREADY_SURVIVED
 *        SURVIVED   -> ELIMINATED  REGRESSED
 *        ELIMINATED -> SURVIVED    RETAINED if the w record pinned something,
 *                                  else SURVIVED_WITHOUT_PIN (investigate; never
 *                                  counted as RETAINED)
 *        ELIMINATED -> ELIMINATED  PIN_INEFFECTIVE if something was pinned (or, in
 *                                  a dry run, would have been), else
 *                                  PIN_NOT_APPLIED
 */

export const OUTCOMES = Object.freeze([
  'RETAINED',
  'ALREADY_SURVIVED',
  'PIN_INEFFECTIVE',
  'PIN_NOT_APPLIED',
  'BROKEN_REPAIR',
  'REGRESSED',
  'SURVIVED_WITHOUT_PIN',
  'NOT_SCORED',
]);

export const ELIMINATED = 'WIPE_ELIMINATED';
export const SURVIVED = 'WIPE_SURVIVED';
const SCORABLE = new Set([ELIMINATED, SURVIVED]);

/** Accept a bare verdict string or the {verdict, ...} object verdictOf returns. */
export function verdictWord(v) {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object' && typeof v.verdict === 'string') return v.verdict;
  return 'MISSING';
}

function recordProblems(tag, rr) {
  if (!rr || typeof rr !== 'object') return [`record-${tag}: record-missing`];
  if (!rr.ok || !rr.record) {
    const p = Array.isArray(rr.problems) && rr.problems.length ? rr.problems.join(', ') : 'invalid';
    return [`record-${tag}: ${p}`];
  }
  return [];
}

function unresolved(tag, rec, tolerated = new Set()) {
  if (rec.scope !== 'functions') return [];
  return rec.resolution.filter((r) => r.resolution !== 'resolved' && !tolerated.has(r.name))
    .map((r) => `unresolved-${tag}: ${r.name} (${r.resolution})`);
}

/**
 * Helpers that exist in the wipe-kept unit and are gone from the ablated one.
 *
 * Ablation deletes the wipe statement. When that statement was the only call to
 * a `static` wipe helper, the compiler does not emit the helper at all in the
 * ablated unit, so the plugin reports it `not-in-module` there. That is what
 * ablation is supposed to do, not a repair that failed to find its target; it was
 * first seen on a nonremovable file with a static `secure_wipe`. It is tolerated
 * ONLY in that exact shape -- resolved in the w record, `not-in-module` in the wo
 * record -- and the names are returned so the runner can put them in the row
 * rather than let the tolerance be silent. Every other unresolved name, on either
 * side, is still BROKEN_REPAIR.
 */
export function absentAfterAblation(recordW, recordWo) {
  const w = recordW && recordW.ok ? recordW.record : null;
  const wo = recordWo && recordWo.ok ? recordWo.record : null;
  if (!w || !wo || w.scope !== 'functions' || wo.scope !== 'functions') return [];
  const resolvedInW = new Set(w.resolution.filter((r) => r.resolution === 'resolved').map((r) => r.name));
  return wo.resolution.filter((r) => r.resolution === 'not-in-module' && resolvedInW.has(r.name)).map((r) => r.name);
}

/**
 * Everything that makes the repair itself unusable, in a fixed order.
 * Exported so the runner and the tests read the same list.
 */
export function brokenReasons(recordW, recordWo, controlOnOk) {
  const reasons = [...recordProblems('w', recordW), ...recordProblems('wo', recordWo)];
  const w = recordW && recordW.ok ? recordW.record : null;
  const wo = recordWo && recordWo.ok ? recordWo.record : null;
  if (w) reasons.push(...unresolved('w', w));
  if (wo) reasons.push(...unresolved('wo', wo, new Set(absentAfterAblation(recordW, recordWo))));
  if (w && wo && w.dryRun !== wo.dryRun) reasons.push('dry-run-mismatch: the two plugin-on compiles disagree about being a dry run');
  if (controlOnOk !== true) reasons.push('control-not-present-in-on-compile');
  return reasons;
}

/**
 * @returns {{outcome: string, reason: string, baseline: string, repaired: string}}
 */
export function outcomeOf(baseline, repaired, recordW, recordWo, controlOnOk) {
  const b = verdictWord(baseline);
  const r = verdictWord(repaired);
  const out = (outcome, reason) => ({ outcome, reason, baseline: b, repaired: r });

  // 1.
  if (!SCORABLE.has(b)) return out('NOT_SCORED', `baseline-not-scorable: ${b}`);

  // 2.
  const broken = brokenReasons(recordW, recordWo, controlOnOk);
  if (broken.length) return out('BROKEN_REPAIR', broken.join('; '));

  // 3.
  if (!SCORABLE.has(r)) return out('NOT_SCORED', `repaired-not-scorable: ${r}`);

  // 4.
  const w = recordW.record;
  if (b === SURVIVED) {
    return r === SURVIVED
      ? out('ALREADY_SURVIVED', 'survived without the plugin and with it')
      : out('REGRESSED', 'survived without the plugin, eliminated with it');
  }
  if (r === SURVIVED) {
    return w.pinnedCount > 0
      ? out('RETAINED', `eliminated without the plugin, survived with it; ${w.pinnedCount} site(s) pinned`)
      : out('SURVIVED_WITHOUT_PIN', 'survived with the plugin loaded although it pinned nothing -- investigate');
  }
  if (w.pinnedCount > 0) {
    return out('PIN_INEFFECTIVE', `${w.pinnedCount} site(s) pinned and the wipe was still eliminated`);
  }
  if (w.dryRun && w.wouldPinCount > 0) {
    return out('PIN_INEFFECTIVE', `dry run: ${w.wouldPinCount} site(s) would have been pinned; nothing was`);
  }
  if (w.wouldPinCount === 0) {
    return out('PIN_NOT_APPLIED', 'no zero-fill memset intrinsic in the selected functions to pin');
  }
  // Only reachable with a record pin-record.mjs would have refused (outside a dry
  // run, something "would" be pinned and nothing was). Kept so this function is
  // total rather than trusting its caller.
  return out('BROKEN_REPAIR', `record-inconsistent: wouldPinCount ${w.wouldPinCount} with pinnedCount 0 outside a dry run`);
}

const SCORABLE_BASELINE = (r) => r.baseline === ELIMINATED || r.baseline === SURVIVED;

/**
 * Grade a red-control run against the answer it was designed to give. Graded,
 * not narrated: a red control that stops failing the way it should is a finding
 * about the plugin or about this lane, and a sentence in a README would not
 * notice it.
 *
 *   --dry-run        nothing may change: no RETAINED, no SURVIVED_WITHOUT_PIN, no
 *                    REGRESSED, and no noPinNoChange violated anywhere.
 *   --target-suffix  nothing resolves: every cell with a scorable baseline is
 *                    BROKEN_REPAIR, and no noPinNoChange is violated.
 *
 * @param rows  erasure and no-wipe rows as the runner writes them
 * @returns null when the run is not a red control, else {control, expected, held, violations[]}
 */
export function gradeRedControl(rows, { dryRun = false, targetSuffix = null } = {}) {
  if (!dryRun && targetSuffix === null) return null;
  const er = rows.filter((r) => r.kind === 'erasure');
  const none = rows.filter((r) => r.kind === 'none');
  const violations = [];
  const cellTag = (r) => `${r.id} ${r.opt}`;
  for (const r of [...er, ...none]) {
    for (const k of ['noPinNoChangeW', 'noPinNoChangeWo', 'noPinNoChange']) {
      if (r[k] === false) violations.push(`${cellTag(r)}: ${k} violated`);
    }
  }
  let control, expected;
  if (dryRun) {
    control = '--dry-run';
    expected = 'no RETAINED, SURVIVED_WITHOUT_PIN or REGRESSED; every listing unchanged';
    for (const r of er) {
      if (['RETAINED', 'SURVIVED_WITHOUT_PIN', 'REGRESSED'].includes(r.outcome)) violations.push(`${cellTag(r)}: ${r.outcome}`);
    }
  }
  if (targetSuffix !== null) {
    control = dryRun ? `${control} with --target-suffix` : '--target-suffix';
    expected = (dryRun ? `${expected}; ` : '') + 'BROKEN_REPAIR on every cell with a scorable baseline';
    for (const r of er) {
      if (SCORABLE_BASELINE(r) && r.outcome !== 'BROKEN_REPAIR') violations.push(`${cellTag(r)}: ${r.outcome}`);
    }
  }
  const scored = er.filter(SCORABLE_BASELINE).length;
  if (scored === 0) violations.push('vacuous: no cell had a scorable baseline, so the control was never exercised');
  return { control, expected, held: violations.length === 0, violations };
}
