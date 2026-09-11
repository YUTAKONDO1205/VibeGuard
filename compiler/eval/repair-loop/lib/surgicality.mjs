/**
 * Surgicality checks: did the plugin change ONLY what it said it changed?
 *
 * These are reported beside the outcome and never folded into it. An outcome
 * says what happened to the wipe; these say whether the instrument that caused
 * it stayed inside its lane. A RETAINED cell whose surgicality check failed is
 * still RETAINED -- and is listed, so nobody has to find it.
 *
 * Each check returns true (held), false (violated) or null (not applicable, or
 * not decidable because an input is missing). null is never counted as a pass.
 *
 * `bodyOf` is injected so that these stay pure and testable without a compiler;
 * the runner passes the find step's own bodyOf.
 */

const pinned = (rr) => (rr && rr.ok && rr.record ? rr.record.pinnedCount : null);

/**
 * The plugin cannot fabricate a wipe: where the ablated (wipe-deleted) compile
 * pinned nothing, the target body with the plugin must equal the body without.
 */
export function ablatedUnchanged({ asmWoOff, asmWoOn, fn, recordWo, bodyOf }) {
  if (pinned(recordWo) !== 0) return null;
  if (!asmWoOff || !asmWoOn) return null;
  const a = bodyOf(asmWoOff, fn), b = bodyOf(asmWoOn, fn);
  if (a === null || b === null) return null;
  return a === b;
}

/**
 * In functions scope the positive control is not a selected function, so its
 * body must not move. Checked in both the wipe-kept and the wipe-deleted
 * translation unit. Not applicable in module scope, where the control's own
 * memset is a legitimate target.
 */
export function controlUntouched({ scope, pairs, bodyOf, controlFn = 'vgctl_control' }) {
  if (scope !== 'functions') return null;
  let decided = 0;
  for (const [off, on] of pairs) {
    if (!off || !on) return null;
    const a = bodyOf(off, controlFn), b = bodyOf(on, controlFn);
    if (a === null || b === null) return null;
    if (a !== b) return false;
    decided++;
  }
  return decided > 0 ? true : null;
}

/**
 * Loading the plugin and pinning nothing must change nothing -- the FULL listing,
 * not only the target body, so that an analysis invalidation or a pass-order
 * side effect anywhere in the unit would show.
 */
export function noPinNoChange({ asmOff, asmOn, record }) {
  if (pinned(record) !== 0) return null;
  if (!asmOff || !asmOn) return null;
  return asmOff === asmOn;
}

/**
 * How many more sites the wipe-kept compile pinned than the wipe-deleted one.
 * Positive means at least one pinned site exists only because the wipe
 * statement does -- the pin is attributable to the wipe, not to an initialiser
 * both versions share. In a dry run the would-pin counts are compared instead.
 * null when either record is unusable.
 */
export function pinDelta(recordW, recordWo) {
  const w = recordW && recordW.ok ? recordW.record : null;
  const wo = recordWo && recordWo.ok ? recordWo.record : null;
  if (!w || !wo) return null;
  return w.dryRun ? w.wouldPinCount - wo.wouldPinCount : w.pinnedCount - wo.pinnedCount;
}
