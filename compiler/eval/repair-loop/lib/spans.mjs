/**
 * The per-span view: the find step's verdict, one wipe span at a time.
 *
 * The find step ablates every wipe span of the target function at once and
 * compares the two bodies. That is its criterion, and the cell outcome here keeps
 * it unchanged. But a cell-level verdict can hide a removed wipe. When a function
 * holds two zero-fills -- an initialiser and a trailing wipe, or a wipe on an
 * error path and one at the end -- deleting both changes the code (the initialiser
 * mattered, or the loop is laid out differently), so the cell reads WIPE_SURVIVED
 * although the trailing wipe, deleted on its own, changes nothing: it was already
 * gone.
 *
 * So for every cell with two or more spans, each removable span is ablated on its
 * own and judged by the SAME verdictOf, plugin off and plugin on. A cell with one
 * span needs no second compile: ablating its only span is the cell's own ablation,
 * so the span verdict is the cell verdict, and the row says so (source 'cell').
 *
 * A nonremovable span in a multi-span cell is not ablated on its own. It is a
 * volatile store, a volatile-pointer declaration or a call the compiler may not
 * delete; the wipe it performs is not what the plugin repairs, and deleting a
 * volatile-pointer declaration without its loop does not compile. It is listed
 * with source 'not-measured' so the indices stay aligned with the find step's
 * spans.
 *
 * Pure: verdicts are handed in. Nothing here compiles or reads a file.
 *
 * spanPlan itself -- which spans get a compile of their own -- is the find
 * step's, imported from ../../ai-generated/lib/ablation-cell.mjs and re-exported
 * here, because the stock per-span supplement in that lane plans its compiles
 * with the same function. The dependency runs one way, repair-loop ->
 * ai-generated, as it does for verdictOf.
 *
 * The import is dynamic and its failure is swallowed on purpose. The runner
 * checks that ablation-cell.mjs exists and exits 5 when it does not (README,
 * "The four-compile cell"); a static import here would crash the runner at load
 * time with a module-not-found trace before that check could run. So when the
 * module is missing, spanPlan is a stub that throws, and the runner's own check
 * is what the user sees. When it is present, spanPlan IS the find step's
 * function (the same object; test/spans.test.mjs pins that).
 */
import { ELIMINATED, SURVIVED, verdictWord } from './outcome.mjs';

let findStepSpanPlan = null;
try {
  ({ spanPlan: findStepSpanPlan } = await import('../../ai-generated/lib/ablation-cell.mjs'));
} catch { /* reported by the runner as exit 5; see above */ }

export const spanPlan = typeof findStepSpanPlan === 'function' ? findStepSpanPlan : () => {
  throw new Error('spanPlan: ../../ai-generated/lib/ablation-cell.mjs could not be imported; there is no private copy');
};

export const SPAN_SOURCES = Object.freeze(['cell', 'span', 'not-measured']);

/** 'cell' when the only span is the cell's own ablation, 'span' otherwise, null without spans. */
export function spanSourceOf(plan) {
  if (!plan.length) return null;
  return plan.length === 1 ? 'cell' : 'span';
}

/**
 * The spans of one row, as verdict strings only (no source text).
 *
 * @param plan      spanPlan(...)
 * @param baseline  the cell's plugin-off verdict (string or verdictOf object)
 * @param repaired  the cell's plugin-on verdict
 * @param measured  index -> {off, on, recordOk} for every span whose source is
 *                  'span'; off/on are verdictOf results or strings. A span the
 *                  plan asked for and nobody measured reads 'MISSING', never a
 *                  WIPE_ verdict.
 */
export function spanRows(plan, { baseline, repaired, measured = {} }) {
  return plan.map((p) => {
    const base = { index: p.index, kind: p.kind };
    if (p.source === 'cell') {
      return { ...base, off: verdictWord(baseline), on: verdictWord(repaired), source: 'cell', recordOk: null };
    }
    if (p.source === 'not-measured') return { ...base, off: null, on: null, source: 'not-measured', recordOk: null };
    const m = measured[p.index];
    return {
      ...base,
      off: m ? verdictWord(m.off) : 'MISSING',
      on: m ? verdictWord(m.on) : 'MISSING',
      source: 'span',
      recordOk: m && typeof m.recordOk === 'boolean' ? m.recordOk : null,
    };
  });
}

/**
 * hiddenElimination: the find step scored the cell WIPE_SURVIVED, and some
 * removable span, ablated on its own, is WIPE_ELIMINATED without the plugin.
 * hiddenRetained: hiddenElimination, and every such span is WIPE_SURVIVED with
 * the plugin.
 *
 * Neither changes the cell outcome. They are the same verdictOf at a finer grain,
 * reported beside it.
 */
export function hiddenFlags(baseline, spans) {
  const b = verdictWord(baseline);
  const elim = (spans || []).filter((s) => s.kind === 'removable' && s.off === ELIMINATED);
  const hiddenElimination = b === SURVIVED && elim.length > 0;
  const hiddenRetained = hiddenElimination && elim.every((s) => s.on === SURVIVED);
  return { hiddenElimination, hiddenRetained };
}
