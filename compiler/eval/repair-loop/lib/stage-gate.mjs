/**
 * Where the repair cannot reach, stated per family rather than left out.
 *
 * Each repair plugin runs inside its compiler's middle end: WipePin at the start
 * of the LLVM optimisation pipeline, WipePinGcc on GIMPLE directly after `cfg`.
 * That fixes what they can and cannot see:
 *
 *   - They see the compiler's IR. Anything the preprocessor already removed
 *     never reaches it: an `assert` under -DNDEBUG, a check behind an `#ifdef`
 *     that the default build leaves undefined. No IR pass brings back tokens
 *     that were never parsed.
 *   - Each loads into one vendor only. A run drives one compiler; the tracked
 *     rows of any other compiler get one line (otherVendorLine).
 *   - They pin zero-fill memsets. A loss that is a folded comparison rather
 *     than a deleted store is a different repair.
 *
 * Silence about those families would read as "not examined" or, worse, as
 * "covered". So each gets a line, and the one that can be MEASURED is measured:
 * for configguard, loading the plugin must leave the default build's target body
 * as it was. That is the observable half of "cannot bring back a defence the
 * preprocessor removed".
 *
 * Everything here is pure: it reads rows and bodies it is handed.
 */
import { vendorOf, VENDORS } from './vendor.mjs';

/** authz: summarise the tracked NDEBUG differential. */
export function authzSummary(rows) {
  const byCell = {};
  let changed = 0, noEffect = 0, other = 0;
  for (const r of rows) {
    if (r.kind !== 'authz') continue;
    const key = `${r.cc} ${r.opt}`;
    byCell[key] ??= { CHANGED_BY_NDEBUG: 0, NDEBUG_NO_EFFECT: 0, other: 0 };
    if (r.verdict === 'CHANGED_BY_NDEBUG') { byCell[key].CHANGED_BY_NDEBUG++; changed++; }
    else if (r.verdict === 'NDEBUG_NO_EFFECT') { byCell[key].NDEBUG_NO_EFFECT++; noEffect++; }
    else { byCell[key].other++; other++; }
  }
  const total = changed + noEffect + other;
  let status, line;
  if (total === 0) {
    status = 'NO_TRACKED_ROWS';
    line = 'authz: NO_TRACKED_ROWS -- the tracked rows carry no authz family, so nothing is said about it';
  } else if (changed === 0) {
    status = 'NO_LOSS_OBSERVED';
    line = `authz: NO_LOSS_OBSERVED -- -DNDEBUG changed the target body in 0 of ${changed + noEffect} compiling `
      + `configurations (${other} not compiling or not observed); no loss observed, nothing to repair`;
  } else {
    status = 'OUT_OF_REACH_PREPROCESS';
    line = `authz: OUT_OF_REACH_PREPROCESS -- -DNDEBUG changed the target body in ${changed} of ${changed + noEffect} `
      + 'compiling configurations; an assert removed by the preprocessor never reaches IR, so no IR pass can restore it';
  }
  return { status, changed, noEffect, other, byCell, line };
}

/** configguard: the tracked DEFAULT_DIFFERS files for one (cc, opt), sorted by id. */
export function configguardTargets(rows, { cc = 'clang-18', opt = '-O2' } = {}) {
  return rows
    .filter((r) => r.kind === 'configguard' && r.cc === cc && r.opt === opt && r.verdict === 'DEFAULT_DIFFERS')
    .map((r) => ({
      id: r.id, model: r.model, framing: r.framing, scen: r.scen, fam: r.fam, fn: r.fn,
      macros: Array.isArray(r.macros) ? [...r.macros] : [],
    }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

const eq = (a, b) => (a === null || a === undefined || b === null || b === undefined ? null : a === b);

/**
 * One OUT_OF_REACH_PREPROCESS row. The outcome is fixed by the family; what the
 * row carries is the measurement that the plugin left the default build alone.
 *
 * @param target   an element of configguardTargets()
 * @param measured {bodyDefaultOff, bodyDefaultOn, bodyEnabledOff, recordOk, pinnedCount, controlOn}
 *                 bodies are strings or null (did not compile / not delimited)
 */
export function configguardRow(target, measured, { cc = 'clang-18', opt = '-O2', scope = 'module', dryRun = false } = {}) {
  const { bodyDefaultOff, bodyDefaultOn, bodyEnabledOff } = measured;
  return {
    id: target.id, model: target.model, framing: target.framing, scen: target.scen,
    fam: 'configguard', fn: target.fn, kind: 'configguard', cc, opt, scope, dryRun,
    outcome: 'OUT_OF_REACH_PREPROCESS',
    trackedVerdict: 'DEFAULT_DIFFERS',
    // Re-observed here, plugin off: the default build still differs from the
    // all-macros-defined one. null if either did not compile or read.
    defaultDiffersReproduced: eq(bodyDefaultOff, bodyEnabledOff) === null ? null : bodyDefaultOff !== bodyEnabledOff,
    // The measured boolean: loading the plugin left the default target body as it was.
    pluginLeftDefaultBodyUnchanged: eq(bodyDefaultOff, bodyDefaultOn),
    // The direct form of the claim: with the plugin, the default build became the enabled one.
    pluginDefaultEqualsEnabled: eq(bodyDefaultOn, bodyEnabledOff),
    recordOk: measured.recordOk === true,
    pinnedCount: Number.isInteger(measured.pinnedCount) ? measured.pinnedCount : null,
    controlOn: measured.controlOn === true,
  };
}

/**
 * A compiler the tracked rows know and this run did not drive: one line, no rows.
 *
 *   SEPARATE_RUN        a repair plugin exists for its vendor (vendor.VENDORS);
 *                       its cells are measured by a run with --cc <that compiler>,
 *                       and the cross-vendor coverage line reads that run's tracked
 *                       rows, if there are any
 *   UNSUPPORTED_VENDOR  no repair plugin loads into it, so there is no plugin-on
 *                       compile to make for its cells at all
 */
export function otherVendorLine(rows, cc) {
  const n = rows.filter((r) => r.kind === 'erasure' && r.cc === cc).length;
  const vendor = vendorOf(cc);
  if (vendor === null) {
    return `${cc}: UNSUPPORTED_VENDOR -- ${n} tracked erasure cell(s); no repair plugin loads into ${cc}, `
      + 'so this lane has no plugin-on compile to make for them';
  }
  const v = VENDORS[vendor];
  return `${cc}: SEPARATE_RUN -- ${n} tracked erasure cell(s); its repair plugin is ${v.component} `
    + `(${v.pluginFlag}<so>), and its cells are measured by a run with --cc ${cc}, not by this one`;
}

/** One otherVendorLine per compiler in the tracked erasure rows other than `runCc`, in name order. */
export function otherVendorLines(rows, runCc) {
  const ccs = [...new Set(rows.filter((r) => r.kind === 'erasure' && r.cc !== runCc).map((r) => r.cc))].sort();
  return ccs.map((cc) => otherVendorLine(rows, cc));
}

/** Families outside the corpus and outside the repair's mechanism. */
export function notAttemptedLine(families = ['nullcheck', 'signedovf']) {
  return `${families.join(', ')}: NOT_ATTEMPTED -- not in the r2 corpus (scenarios.json has erasure, authz and `
    + 'configguard only), and the loss there is a folded comparison, not a removed store; pinning a memset does not touch it';
}
