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
 */
export function corroborationSummary(rows, opts) {
  const er = erasureRows(rows);
  return opts.map((opt) => {
    const ret = byOpt(er, opt).filter((r) => r.outcome === 'RETAINED');
    return {
      opt,
      retained: ret.length,
      onPresent: ret.filter((r) => r.effectW && r.effectW.on === 'PRESENT').length,
      offPresent: ret.filter((r) => r.effectW && r.effectW.off === 'PRESENT').length,
      onNotPresent: ret.filter((r) => !r.effectW || r.effectW.on !== 'PRESENT').map((r) => r.id),
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

const isGcc = (cc) => /^(gcc|g\+\+)(-[\d.]+)?$/.test(cc) || /-(gcc|g\+\+)(-[\d.]+)?$/.test(cc);

/**
 * Eliminations the find step found, per vendor, against the ones this run
 * reversed. "Found" is read from the tracked find-step rows (erasure,
 * WIPE_ELIMINATED), over the files and levels this run selected; "reversed" is a
 * measured RETAINED cell whose tracked verdict is WIPE_ELIMINATED, for the vendor
 * this run compiled with. A gcc vendor reverses 0 because no LLVM plugin can load
 * into it. Computed, never written down.
 *
 * @param tracked  the find step's rows
 * @param rows     this run's rows
 * @param runCc    the vendor this run compiled with
 * @param ids      Set of selected ids, or null for all
 * @param opts     selected levels, or null for all
 */
export function crossVendorCoverage({ tracked, rows, runCc, ids = null, opts = null }) {
  const sel = (r) => r.kind === 'erasure' && (!ids || ids.has(r.id)) && (!opts || opts.includes(r.opt));
  // every vendor the tracked erasure rows know, even one with nothing selected:
  // a vendor that vanishes from the line would read as "not in the data"
  const vendors = [...new Set([runCc, ...tracked.filter((r) => r.kind === 'erasure').map((r) => r.cc)])].sort();
  const reversedHere = erasureRows(rows).filter((r) => r.cc === runCc && r.outcome === 'RETAINED' && r.trackedVerdict === ELIMINATED).length;
  const perVendor = vendors.map((cc) => {
    const found = tracked.filter((r) => sel(r) && r.cc === cc && r.verdict === ELIMINATED).length;
    const loadable = cc === runCc;
    return { cc, found, reversed: loadable ? reversedHere : 0, loadable, note: loadable ? null : isGcc(cc) ? 'no plugin can load' : 'not run' };
  });
  const total = { reversed: perVendor.reduce((n, v) => n + v.reversed, 0), found: perVendor.reduce((n, v) => n + v.found, 0) };
  // the run's own vendor first, then the others in name order
  const ordered = [...perVendor.filter((v) => v.loadable), ...perVendor.filter((v) => !v.loadable)];
  const parts = ordered.map((v) => `${v.cc} ${v.reversed}/${v.found}${v.note ? ` (${v.note})` : ''}`);
  const line = `eliminations reversed / found: ${parts.join(', ')}, total ${total.reversed}/${total.found}`;
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
