/**
 * Run-level counts the results file prints beside the outcome table.
 *
 * None of these changes an outcome. Each is a different view of the rows the
 * runner already wrote -- a finer grain (spans), a second reading of the same
 * listing (the effect oracle), a provenance check (listing digests), or a bridge
 * back to the find step (the pin plan, the cross-vendor coverage line). All pure:
 * rows in, numbers out. Nothing here compiles or reads a file.
 */
import { ELIMINATED, SURVIVED } from './outcome.mjs';
import { vendorOf } from './vendor.mjs';

const erasureRows = (rows) => rows.filter((r) => r.kind === 'erasure');
const byOpt = (rows, opt) => rows.filter((r) => r.opt === opt);

/**
 * The per-span layer, per optimisation level.
 *
 *   retainedSpans   in RETAINED cells, removable spans that survive individually
 *                   with the plugin (survived) out of all removable spans (total).
 *                   A one-span cell contributes its cell verdict (source 'cell').
 *   hidden          cells the find step scored WIPE_SURVIVED in which a removable
 *                   span, ablated alone, is WIPE_ELIMINATED without the plugin;
 *                   hiddenRetained of those have every such span surviving with it.
 */
export function spanSummary(rows, opts) {
  const er = erasureRows(rows);
  return opts.map((opt) => {
    const sub = byOpt(er, opt);
    const retained = sub.filter((r) => r.outcome === 'RETAINED');
    let survived = 0, total = 0;
    const misses = [];
    for (const r of retained) {
      for (const s of r.spans || []) {
        if (s.kind !== 'removable') continue;
        total++;
        if (s.on === SURVIVED) survived++;
        else misses.push({ id: r.id, index: s.index, on: s.on });
      }
    }
    const hidden = sub.filter((r) => r.hiddenElimination === true);
    return {
      opt,
      multiSpanCells: sub.filter((r) => r.spanSource === 'span').length,
      retainedCells: retained.length,
      retainedSpans: { survived, total },
      retainedSpanMisses: misses,
      hidden: hidden.length,
      hiddenRetained: hidden.filter((r) => r.hiddenRetained === true).length,
      hiddenIds: hidden.map((r) => ({ id: r.id, retained: r.hiddenRetained === true })),
    };
  });
}

/**
 * The effect oracle's reading of the target body, for one listing. null when the
 * listing does not exist. `observe` is asm-oracle.mjs's observeEffect, injected.
 */
export function effectVerdict(observe, listing, fn, effect) {
  if (typeof listing !== 'string') return null;
  return observe(listing, fn, effect).verdict;
}

/**
 * Corroboration of RETAINED cells by a second reading of the w listings: how many
 * have the effect PRESENT in w/on, and how many in w/off. The w/off number is not
 * evidence of anything: the oracle counts any memset call or zero store to memory
 * in the body, so an array initialiser (`= {0}`) or an initialising memset can
 * read PRESENT although the wipe is gone. It is printed so that blind spot stays
 * visible. Never changes an outcome.
 *
 * The oracle does not know `rep stos`, the form gcc-13 gives a zero fill at -Os
 * (compiler/gcc-repair/README.md). Rows carry a second, separately labelled
 * reading, `effectWRepStos: {off, on}` (a zeroed %eax, then `rep stos`, in the
 * target body: repStosZeroFill from compiler/gcc-repair/scripts/lib/asm-presence.mjs,
 * imported by the runner, which is the fallback the find step's controlPresent
 * applies to the control, generalised to any function). It is never folded into
 * the oracle's count: `onRepStosOnly` counts
 * the RETAINED cells the oracle reads as not PRESENT in w/on and the fallback
 * reads as a zero fill, and `onNotPresent` still lists every oracle miss.
 */
export function corroborationSummary(rows, opts) {
  const er = erasureRows(rows);
  return opts.map((opt) => {
    const ret = byOpt(er, opt).filter((r) => r.outcome === 'RETAINED');
    const onMiss = ret.filter((r) => !r.effectW || r.effectW.on !== 'PRESENT');
    const repStosOnly = onMiss.filter((r) => r.effectWRepStos && r.effectWRepStos.on === true);
    return {
      opt,
      retained: ret.length,
      onPresent: ret.length - onMiss.length,
      offPresent: ret.filter((r) => r.effectW && r.effectW.off === 'PRESENT').length,
      onNotPresent: onMiss.map((r) => r.id),
      onRepStosOnly: repStosOnly.length,
      onRepStosOnlyIds: repStosOnly.map((r) => r.id),
    };
  });
}

/**
 * ALREADY_SURVIVED cells in which the plugin pinned something in the wipe-kept
 * compile and the w listing changed (digests differ): the plugin moved code where
 * the find step reported no loss. Split by whether the per-span layer found a
 * hidden elimination there -- where it did, the change is the repair of a wipe
 * the cell verdict could not see; where it did not, it is a change nobody asked
 * the plugin for.
 */
export function listingChangedWithoutLoss(rows, opts) {
  const er = erasureRows(rows);
  return opts.map((opt) => {
    const hit = byOpt(er, opt).filter((r) => r.outcome === 'ALREADY_SURVIVED'
      && r.listings && typeof r.listings.wOff === 'string' && typeof r.listings.wOn === 'string'
      && r.listings.wOff !== r.listings.wOn
      && r.recordW && r.recordW.ok === true && r.recordW.pinnedCount > 0);
    const hidden = hit.filter((r) => r.hiddenElimination === true);
    const notHidden = hit.filter((r) => r.hiddenElimination !== true);
    return { opt, total: hit.length, hidden: hidden.length, notHidden: notHidden.length, notHiddenIds: notHidden.map((r) => r.id) };
  });
}

/**
 * Where a verdict or a surgicality check rests on label NAMES alone.
 *
 * gcc numbers its `.L<n>` code labels once per translation unit, so a change in
 * one function renumbers the labels of every function emitted after it
 * (surgicality.canonicalLocalLabels). The find step's verdictOf compares target
 * bodies as text, labels included, and this lane does not change that. What it
 * does is say, per level, where the text differs and the code does not:
 *
 *   baselineLabelsOnly   cells whose w/off and wo/off target bodies differ only in
 *                        `.L<n>` names: the find step's WIPE_SURVIVED there is a
 *                        renumbering, not a surviving wipe
 *   retainedLabelsOnly   RETAINED cells whose w/on and wo/on target bodies differ
 *                        only in `.L<n>` names: a RETAINED that is a renumbering.
 *                        Listed by id; a nonzero count must be read before any
 *                        RETAINED number is quoted
 *   controlRenumbered    cells whose controlUntouched held only after the renaming
 *
 * Rows carry `labelsOnly: {baseline, repaired}` and `controlUntouchedRenumberedOnly`.
 * On clang every one of these is 0 by construction (no `.L<digits>` labels).
 */
export function labelRenumbering(rows, opts) {
  const er = erasureRows(rows);
  return opts.map((opt) => {
    const sub = byOpt(er, opt);
    const base = sub.filter((r) => r.labelsOnly && r.labelsOnly.baseline === true);
    const ret = sub.filter((r) => r.outcome === 'RETAINED' && r.labelsOnly && r.labelsOnly.repaired === true);
    return {
      opt,
      baselineLabelsOnly: base.length,
      baselineLabelsOnlyIds: base.map((r) => `${r.id} (${r.baseline})`),
      retainedLabelsOnly: ret.length,
      retainedLabelsOnlyIds: ret.map((r) => r.id),
      controlRenumbered: sub.filter((r) => r.controlUntouchedRenumberedOnly === true).length,
    };
  });
}

/**
 * Eliminations the find step found, per compiler, against the ones a repair run
 * reversed. Computed, never written down.
 *
 * "Found" is read from the tracked find-step rows (erasure, WIPE_ELIMINATED),
 * over the files and levels this run selected. "Reversed" is a found cell whose
 * repair row is RETAINED. Each run measures one compiler, so the repair rows come
 * from two places:
 *
 *   - the compiler this run drove: this run's own rows ("this run");
 *   - any other compiler: that compiler's TRACKED repair rows file, when the
 *     caller found one and handed it in as `others[cc]` = {label, sha256, rows,
 *     full: {full, why}, error?}. Its sha256 is printed, and so is whether it is
 *     a full --write-data run (vendor.fullRunCheck). A file that is not is still
 *     counted where it has rows, and says so. A file that could not be read as
 *     repair rows for that compiler (`error`) counts nothing and says why.
 *   - no file: "not measured", and nothing counted. That is not the same as 0
 *     reversed, so the total says how many found cells nobody measured.
 *
 * A found cell with no repair row at all (a plan-driven run compiles only the
 * cells it was asked about; a partial file lacks some) is "not measured" too.
 *
 * @param tracked  the find step's rows
 * @param rows     this run's rows
 * @param runCc    the compiler this run drove
 * @param ids      Set of selected ids, or null for all
 * @param opts     selected levels, or null for all
 * @param others   {[cc]: {label, sha256, rows, full, error}} for other compilers
 */
export function crossVendorCoverage({ tracked, rows, runCc, ids = null, opts = null, others = {} }) {
  const sel = (r) => r.kind === 'erasure' && (!ids || ids.has(r.id)) && (!opts || opts.includes(r.opt));
  // every compiler the tracked erasure rows know, even one with nothing selected:
  // one that vanishes from the line would read as "not in the data"
  const vendors = [...new Set([runCc, ...tracked.filter((r) => r.kind === 'erasure').map((r) => r.cc)])].sort();
  const perVendor = vendors.map((cc) => {
    const foundCells = tracked.filter((r) => sel(r) && r.cc === cc && r.verdict === ELIMINATED);
    const found = foundCells.length;
    const here = cc === runCc;
    const o = here ? null : others[cc] || null;
    let source, repairRows = null;
    if (here) { source = { kind: 'this-run' }; repairRows = rows; }
    else if (!o) source = { kind: 'not-measured' };
    else if (o.error) source = { kind: 'unreadable', label: o.label, sha256: o.sha256 ?? null, error: o.error };
    else { source = { kind: 'tracked', label: o.label, sha256: o.sha256, full: !!(o.full && o.full.full), why: (o.full && o.full.why) || [] }; repairRows = o.rows; }
    const outcomeAt = new Map();
    if (repairRows) {
      for (const r of erasureRows(repairRows)) if (r.cc === cc) outcomeAt.set(`${r.id}|${r.opt}`, r.outcome);
    }
    let reversed = 0, measured = 0;
    for (const f of foundCells) {
      const oc = outcomeAt.get(`${f.id}|${f.opt}`);
      if (oc === undefined) continue;
      measured++;
      if (oc === 'RETAINED') reversed++;
    }
    return { cc, found, measured, reversed, notMeasured: found - measured, source };
  });
  const total = {
    reversed: perVendor.reduce((n, v) => n + v.reversed, 0),
    found: perVendor.reduce((n, v) => n + v.found, 0),
    notMeasured: perVendor.reduce((n, v) => n + v.notMeasured, 0),
  };
  // the run's own compiler first, then the others in name order
  const ordered = [...perVendor.filter((v) => v.cc === runCc), ...perVendor.filter((v) => v.cc !== runCc)];
  const part = (v) => {
    const s = v.source;
    if (s.kind === 'this-run') return `${v.cc} ${v.reversed}/${v.found} (this run${v.notMeasured ? `; ${v.notMeasured} of ${v.found} not compiled in it` : ''})`;
    if (s.kind === 'not-measured') {
      return `${v.cc} -/${v.found} (not measured: ${vendorOf(v.cc) === null ? `no repair plugin loads into ${v.cc}` : `no tracked repair rows for ${v.cc}`})`;
    }
    if (s.kind === 'unreadable') return `${v.cc} -/${v.found} (not measured: ${s.label} could not be read as repair rows for ${v.cc}: ${s.error})`;
    const kind = s.full ? 'a full --write-data run' : `NOT a full --write-data run: ${s.why.join('; ')}`;
    return `${v.cc} ${v.reversed}/${v.found} (tracked repair rows ${s.label}, sha256 ${s.sha256}, ${kind}`
      + `${v.notMeasured ? `; ${v.notMeasured} of ${v.found} not in it` : ''})`;
  };
  const line = `eliminations reversed / found: ${ordered.map(part).join(', ')}, total ${total.reversed}/${total.found}`
    + (total.notMeasured ? `, ${total.notMeasured} found cell(s) not measured` : '');
  return { perVendor: ordered, total, line };
}

/**
 * The find -> fix artifact: for every file, the levels at which the find step's
 * observation says a wipe is gone -- the cell verdict is WIPE_ELIMINATED
 * (reason 'cell') or a removable span, ablated alone, is (reason 'span') -- and
 * the names to pin there: WPIN_TARGET_FNS = [fn, ...helpers]. Files with no such
 * level are left out.
 *
 * @param rows  this run's rows (erasure rows carry fn, helpers, baseline, hiddenElimination)
 * @param opts  the level order to list levels in
 */
export function buildPinPlan(rows, opts) {
  const order = new Map(opts.map((o, i) => [o, i]));
  const byId = new Map();
  for (const r of erasureRows(rows)) {
    let reason = null;
    if (r.baseline === ELIMINATED) reason = 'cell';
    else if (r.hiddenElimination === true) reason = 'span';
    if (!reason) continue;
    let e = byId.get(r.id);
    if (!e) {
      e = { id: r.id, fn: r.fn, helpers: Array.isArray(r.helpers) ? [...r.helpers] : [], opts: [], reason: {} };
      byId.set(r.id, e);
    }
    if (!(r.opt in e.reason)) e.opts.push(r.opt);
    e.reason[r.opt] = reason;
  }
  const entries = [...byId.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  for (const e of entries) {
    e.opts.sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99) || (a < b ? -1 : a > b ? 1 : 0));
    const reason = {};
    for (const o of e.opts) reason[o] = e.reason[o];
    e.reason = reason;
  }
  return entries;
}
