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
 * GCC's local code labels, `.L<n>`, are numbered by one counter for the whole
 * translation unit, in emission order. A pin that gives the target function one
 * label more or fewer renumbers every `.L<n>` in the functions emitted after it,
 * with not one instruction changed there. Measured on gcc-13 (fable_N_token_r3,
 * -O1/-O2): the control's body, which follows the target, differed only in
 * `jne .L12` / `.L12:` against `jne .L13` / `.L13:`. clang names its labels per
 * function (`.LBB<f>_<n>`, `.Ltmp<n>`, `.LCPI...`), none of which this pattern
 * matches, so on clang this is the identity.
 *
 * Renames each `.L<digits>` in order of first appearance to `.L#0`, `.L#1`, ...
 * Only names change: a branch that now goes somewhere else, or a label that moved,
 * still shows, because the mapping is by position in this text.
 */
export function canonicalLocalLabels(text) {
  if (typeof text !== 'string') return text;
  const m = new Map();
  return text.replace(/\.L\d+\b/g, (s) => {
    if (!m.has(s)) m.set(s, `.L#${m.size}`);
    return m.get(s);
  });
}

/**
 * true when two bodies differ as text and are the same once canonicalLocalLabels
 * has renamed their `.L<n>` labels; false when they are equal as text or still
 * differ after it; null when either is missing. Reported, never used to change a
 * verdict: the find step's verdictOf compares the text as it is.
 */
export function differsOnlyInLabels(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return null;
  return a !== b && canonicalLocalLabels(a) === canonicalLocalLabels(b);
}

function controlPairs({ scope, pairs, bodyOf, controlFn }) {
  if (scope !== 'functions') return null;
  const out = [];
  for (const [off, on] of pairs) {
    if (!off || !on) return null;
    const a = bodyOf(off, controlFn), b = bodyOf(on, controlFn);
    if (a === null || b === null) return null;
    out.push([a, b]);
  }
  return out.length ? out : null;
}

/**
 * In functions scope the positive control is not a selected function, so its
 * body must not move. Checked in both the wipe-kept and the wipe-deleted
 * translation unit. Not applicable in module scope, where the control's own
 * memset is a legitimate target.
 *
 * Compared after canonicalLocalLabels: on gcc a pin in the target renumbers the
 * unit-wide `.L<n>` labels of the control, which follows it, and that is not the
 * plugin touching the control. Where that renaming was needed for the check to
 * hold, controlRenumberedOnly says so, and the runner counts it.
 */
export function controlUntouched({ scope, pairs, bodyOf, controlFn = 'vgctl_control' }) {
  const ps = controlPairs({ scope, pairs, bodyOf, controlFn });
  if (!ps) return null;
  return ps.every(([a, b]) => canonicalLocalLabels(a) === canonicalLocalLabels(b));
}

/**
 * true when controlUntouched held only because `.L<n>` labels were renamed (some
 * pair differs as text); false when it held on the text as it is; null when it
 * is not applicable or did not hold.
 */
export function controlRenumberedOnly({ scope, pairs, bodyOf, controlFn = 'vgctl_control' }) {
  const ps = controlPairs({ scope, pairs, bodyOf, controlFn });
  if (!ps) return null;
  if (!ps.every(([a, b]) => canonicalLocalLabels(a) === canonicalLocalLabels(b))) return null;
  return ps.some(([a, b]) => a !== b);
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
 * In a dry run the would-pin counts are compared instead. null when either
 * record is unusable.
 *
 * Carried in the rows, and NOT attribution. Where the wipe-deleted compile pins
 * nothing -- the usual case, since ablation removed the wipe -- this is simply
 * the wipe-kept pin count, which RETAINED already requires to be positive, so
 * "pinDelta > 0 in every RETAINED cell" says nothing new. Nor can it tell an
 * initialising memset from a wipe when the find step labelled both as wipe spans
 * and the ablation deleted both. The per-span view in spans.mjs looks at each
 * span on its own; an initialiser that is a cell's only span remains
 * indistinguishable from a wipe there too (README, "Limits of the find step's
 * labelling").
 */
export function pinDelta(recordW, recordWo) {
  const w = recordW && recordW.ok ? recordW.record : null;
  const wo = recordWo && recordWo.ok ? recordWo.record : null;
  if (!w || !wo) return null;
  return w.dryRun ? w.wouldPinCount - wo.wouldPinCount : w.pinnedCount - wo.pinnedCount;
}
