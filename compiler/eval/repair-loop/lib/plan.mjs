/**
 * find -> fix, driven by the find step's own output.
 *
 * A full run of this lane loads the plugin in every cell, because that is how
 * REGRESSED and the side effects of a pin are measured. A user does not do that:
 * they take what the find step reported and pin only there. `pin-plan.json`
 * (written by every run, see summaries.buildPinPlan) is that hand-off: per file,
 * the levels at which the observation says a wipe is gone and the names to pin.
 * `--plan` replays it: only the planned (file, level) cells are compiled, each
 * with exactly the names the plan lists, and each is judged by the same verdict.
 *
 * Pure: the runner reads the file and passes the parsed object in.
 */

/**
 * Validate a parsed pin plan. Returns {ok, entries: Map(id -> {fn, helpers, opts:Set, reason}), problems}.
 * Strict for the same reason the record reader is: a plan from another tree or
 * another version of the find step would pin names that no longer mean the same
 * thing, and that has to be a refusal rather than a quiet partial repair.
 */
export function readPlan(obj, { allOpts }) {
  const problems = [];
  const entries = new Map();
  if (!obj || typeof obj !== 'object' || !Array.isArray(obj.entries)) {
    return { ok: false, entries, problems: ['not-a-plan: no entries array'] };
  }
  obj.entries.forEach((e, i) => {
    const where = `entries[${i}]`;
    if (!e || typeof e !== 'object') { problems.push(`${where}: not an object`); return; }
    if (typeof e.id !== 'string' || !/^[A-Za-z0-9_.-]+$/.test(e.id)) { problems.push(`${where}.id: not a file id`); return; }
    if (entries.has(e.id)) { problems.push(`${where}.id: ${e.id} appears twice`); return; }
    if (typeof e.fn !== 'string' || !e.fn) problems.push(`${where}.fn: missing`);
    if (!Array.isArray(e.helpers) || e.helpers.some((h) => typeof h !== 'string' || !h)) problems.push(`${where}.helpers: not a list of names`);
    if (!Array.isArray(e.opts) || !e.opts.length) problems.push(`${where}.opts: empty`);
    else for (const o of e.opts) if (!allOpts.includes(o)) problems.push(`${where}.opts: ${o} is not a known level`);
    entries.set(e.id, { fn: e.fn, helpers: Array.isArray(e.helpers) ? [...e.helpers] : [], opts: new Set(Array.isArray(e.opts) ? e.opts : []), reason: e.reason || {} });
  });
  if (!entries.size && !problems.length) problems.push('empty-plan: nothing to pin');
  return { ok: problems.length === 0, entries, problems };
}

/**
 * Does the plan's entry still describe this tree's find step for this file?
 * The names the plan would pin must be the names wipeSpans finds now.
 */
export function planMismatch(entry, { fn, helpers }) {
  if (entry.fn !== fn) return `fn ${entry.fn} in the plan, ${fn} in this tree`;
  const a = [...new Set(entry.helpers)].sort().join(',');
  const b = [...new Set(helpers)].sort().join(',');
  if (a !== b) return `helpers [${a}] in the plan, [${b}] in this tree`;
  return null;
}

/**
 * Was the plan written for the compiler this run drives? A pin plan lists the
 * levels at which ONE compiler's observation says a wipe is gone (the runner
 * writes `cc` into it); gcc-13 and clang-18 lose different wipes at different
 * levels, so a plan replayed on the other one would pin cells whose loss is not
 * there. A plan with no `cc` (written by hand) is not checked. Returns a
 * problem string, or null.
 */
export function planCompilerMismatch(obj, ccName) {
  if (!obj || typeof obj !== 'object' || obj.cc === undefined) return null;
  if (obj.cc !== ccName) return `the plan was written for ${JSON.stringify(obj.cc)}; this run drives ${JSON.stringify(ccName)}`;
  return null;
}

/**
 * What a plan-driven run established, from its rows (erasure rows only; every
 * row of such a run is a planned cell).
 *  - cellPlanned / cellRetained: cells planned because the cell verdict is eliminated
 *  - spanPlanned / spanRetained: cells planned because a span is eliminated on its own
 *  - notReproduced: planned cells in which the plugin-off observation no longer
 *    shows the loss the plan was written from (neither the cell nor any span is
 *    eliminated) -- the plan is stale for them
 *  - notRepaired: ids x opt of planned cells whose loss did not come back
 */
export function planSummary(rows) {
  const s = { cells: 0, cellPlanned: 0, cellRetained: 0, spanPlanned: 0, spanRetained: 0, notReproduced: [], notRepaired: [] };
  for (const r of rows) {
    if (r.kind !== 'erasure') continue;
    s.cells++;
    const tag = `${r.id} ${r.opt}`;
    if (r.baseline === 'WIPE_ELIMINATED') {
      s.cellPlanned++;
      if (r.outcome === 'RETAINED') s.cellRetained++; else s.notRepaired.push(`${tag} (${r.outcome})`);
    } else if (r.hiddenElimination === true) {
      s.spanPlanned++;
      if (r.hiddenRetained === true) s.spanRetained++; else s.notRepaired.push(`${tag} (span not retained)`);
    } else {
      s.notReproduced.push(`${tag} (baseline ${r.baseline})`);
    }
  }
  return s;
}

export function renderPlanSummary(s, { planSha256, entries }) {
  const L = [];
  L.push('', 'plan-driven run (--plan): only the cells the pin plan names were compiled with the plugin');
  L.push(`  plan sha256 ${planSha256}, ${entries} file(s), ${s.cells} planned cell(s)`);
  L.push(`  planned because the cell is eliminated     ${s.cellPlanned}; RETAINED ${s.cellRetained}`);
  L.push(`  planned because a span is eliminated alone ${s.spanPlanned}; every such span retained ${s.spanRetained}`);
  L.push(`  planned cells whose loss did not reproduce plugin-off: ${s.notReproduced.length}`);
  for (const t of s.notReproduced) L.push(`    STALE ${t}`);
  L.push(`  planned cells whose loss did not come back with the plugin: ${s.notRepaired.length}`);
  for (const t of s.notRepaired) L.push(`    NOT REPAIRED ${t}`);
  return L.join('\n') + '\n';
}
