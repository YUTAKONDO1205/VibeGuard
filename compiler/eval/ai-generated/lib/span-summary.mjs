/**
 * The per-span supplement, as pure functions: which files it covers, what one
 * row holds, the cross-check against the repair loop's per-span rows, and the
 * counts the results print.
 *
 * The supplement exists because the find step's tracked numbers are cell-level.
 * Ablation deletes every wipe span of the target function at once, so a file
 * whose trailing wipe is gone can still read WIPE_SURVIVED: the other span (an
 * initialiser, or a wipe on an error path) makes the two bodies differ. The
 * supplement ablates each removable span on its own and judges it with the SAME
 * verdictOf and the SAME flags. It never changes a tracked verdict; it is a
 * second measurement, in a second data file, printed beside the first.
 *
 * Rows carry verdict words, ids and booleans only -- no source text and no path.
 * Nothing here compiles or reads a file.
 */

export const ELIMINATED = 'WIPE_ELIMINATED';
export const SURVIVED = 'WIPE_SURVIVED';
export const ALL_OPTS = Object.freeze(['-O0', '-O1', '-O2', '-O3', '-Os']);
export const VENDORS = Object.freeze(['clang-18', 'gcc-13']);
/**
 * Where the repair loop keeps its tracked rows for each vendor, relative to this
 * directory (lib/). Every vendor whose file exists is cross-checked; a vendor
 * whose file does not is reported as not cross-checked.
 *
 * Named here rather than imported: this lane imports no code from the repair
 * loop. The names follow ../../repair-loop/lib/vendor.mjs dataFileNames
 * (clang-18 keeps r2-repair-rows.json, any other compiler gets
 * r2-repair-rows-<cc>.json); a change to that naming has to be made here too.
 */
export const REPAIR_ROWS_FILES = Object.freeze({
  'clang-18': '../../repair-loop/data/r2-repair-rows.json',
  'gcc-13': '../../repair-loop/data/r2-repair-rows-gcc-13.json',
});

const verdictWord = (v) => (v && typeof v === 'object' ? v.verdict ?? null : v ?? null);

/**
 * Files the tracked find-step rows show with two or more wipe spans.
 *
 * @param trackedRows  data/r2-build-rows.json
 * @returns {{files: Map<string, {nSpans: number, idiom: string}>, problems: string[]}}
 *          problems: ids whose erasure rows disagree with each other about n_spans
 *          or idiom -- the tracked data would then not say what "multi-span" is.
 */
export function multiSpanFiles(trackedRows) {
  const seen = new Map();
  const problems = [];
  for (const r of trackedRows) {
    if (r.kind !== 'erasure') continue;
    const prev = seen.get(r.id);
    if (!prev) { seen.set(r.id, { nSpans: r.n_spans, idiom: r.idiom }); continue; }
    if (prev.nSpans !== r.n_spans || prev.idiom !== r.idiom) problems.push(r.id);
  }
  const files = new Map([...seen].filter(([, v]) => Number.isInteger(v.nSpans) && v.nSpans >= 2)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  return { files, problems: [...new Set(problems)].sort() };
}

/** The tracked cell verdict per `${id}|${cc}|${opt}`. */
export function trackedVerdicts(trackedRows) {
  const m = new Map();
  for (const r of trackedRows) if (r.kind === 'erasure') m.set(`${r.id}|${r.cc}|${r.opt}`, r.verdict);
  return m;
}

/**
 * A hidden elimination: the cell verdict is WIPE_SURVIVED, and some removable
 * span, ablated on its own, is WIPE_ELIMINATED. The same predicate as the repair
 * loop's hiddenElimination (../../repair-loop/lib/spans.mjs), read here against
 * the tracked cell verdict; the cross-check below compares the two on every
 * cell they share, per vendor, so the two cannot drift apart unnoticed.
 */
export function hiddenOf(cellVerdict, spans) {
  return verdictWord(cellVerdict) === SURVIVED
    && (spans || []).some((s) => s.kind === 'removable' && s.off === ELIMINATED);
}

/**
 * One row.
 *
 * @param meta     {id, model, framing, scen, fn}
 * @param plan     spanPlan(kinds) for a multi-span file: entries 'span' or 'not-measured'
 * @param labels   initialiserLike per span, in span order (true/false/null)
 * @param cell     verdictOf(w, wo) with every span ablated, or null when nothing was compiled
 * @param measured index -> verdictOf(w, wo_i) for every 'span' entry that was compiled
 * @param trackedVerdict  the find step's tracked verdict for this (id, cc, opt), or undefined
 */
export function spanRow({ meta, cc, opt, idiom, nSpans, plan, labels, cell = null, measured = {}, trackedVerdict }) {
  const spans = plan.map((p) => {
    const base = { index: p.index, kind: p.kind, source: p.source };
    let off = null;
    if (p.source === 'span') off = cell === null ? null : (p.index in measured ? verdictWord(measured[p.index]) : 'MISSING');
    return { ...base, off, initialiserLike: labels[p.index] ?? null };
  });
  const cellVerdict = verdictWord(cell);
  const tv = trackedVerdict ?? null;
  return {
    id: meta.id, model: meta.model, framing: meta.framing, scen: meta.scen, fn: meta.fn,
    kind: 'erasure-span', cc, opt, idiom, n_spans: nSpans,
    measured: cell !== null,
    trackedVerdict: tv,
    cellVerdict,
    cellMatchesTracked: cellVerdict === null || tv === null ? null : cellVerdict === tv,
    control: cell && typeof cell === 'object' ? cell.control ?? null : null,
    spans,
    hiddenElimination: hiddenOf(tv, spans),
  };
}

/**
 * Integrity of one run's rows against the tracked data: every re-derived cell
 * verdict must equal the tracked one, and every measured span must have a WIPE_
 * or other verdict word (never MISSING).
 */
export function integrityProblems(rows) {
  const out = [];
  for (const r of rows) {
    if (r.cellMatchesTracked === false) out.push(`CELL DISAGREES ${r.id} ${r.cc} ${r.opt}: tracked ${r.trackedVerdict}, re-derived ${r.cellVerdict}`);
    if (r.measured && r.trackedVerdict === null) out.push(`NO TRACKED ROW ${r.id} ${r.cc} ${r.opt}`);
    for (const s of r.spans) if (s.off === 'MISSING') out.push(`SPAN MISSING ${r.id} ${r.cc} ${r.opt} span ${s.index}`);
  }
  return out;
}

/**
 * The cross-check against the repair loop's per-span rows, for one vendor.
 *
 * For every `cc` row here and every span measured on its own here, the repair
 * rows' entry for the same (cc, id, opt, span index) is compared where the repair
 * loop also measured that span on its own (its `source` is 'span') -- the plugin-
 * off verdict, `off`, must be the same word. Where both rows exist, the
 * hiddenElimination flags must agree too. A span that the repair rows do not
 * measure alone is counted as not compared, never as agreeing. Rows of any other
 * vendor, on either side, never enter.
 *
 * @returns {{cc: string, compared: number, agreed: number, notCompared: number, mismatches: object[],
 *            hiddenCompared: number, hiddenMismatches: object[], ids: string[]}}
 */
export function crossCheckRepairRows(rows, repairRows, cc) {
  if (!VENDORS.includes(cc)) throw new Error(`crossCheckRepairRows: ${JSON.stringify(cc)} is not one of ${VENDORS.join(' ')}`);
  const theirs = new Map();
  for (const r of repairRows) {
    if (r.kind === 'erasure' && r.cc === cc) theirs.set(`${r.id}|${r.opt}`, r);
  }
  let compared = 0, agreed = 0, notCompared = 0, hiddenCompared = 0;
  const mismatches = [];
  const hiddenMismatches = [];
  for (const r of rows) {
    if (r.cc !== cc || !r.measured) continue;
    const t = theirs.get(`${r.id}|${r.opt}`);
    for (const s of r.spans) {
      if (s.source !== 'span') continue;
      const ts = t && Array.isArray(t.spans) ? t.spans.find((x) => x.index === s.index) : null;
      if (!ts || ts.source !== 'span') { notCompared++; continue; }
      compared++;
      if (ts.off === s.off && ts.kind === s.kind) agreed++;
      else mismatches.push({ id: r.id, opt: r.opt, index: s.index, ours: s.off, theirs: ts.off, kinds: ts.kind === s.kind ? null : [s.kind, ts.kind] });
    }
    if (t && typeof t.hiddenElimination === 'boolean') {
      hiddenCompared++;
      if (t.hiddenElimination !== r.hiddenElimination) hiddenMismatches.push({ id: r.id, opt: r.opt, ours: r.hiddenElimination, theirs: t.hiddenElimination });
    }
  }
  const ids = [...new Set([...mismatches, ...hiddenMismatches].map((m) => m.id))].sort();
  return { cc, compared, agreed, notCompared, mismatches, hiddenCompared, hiddenMismatches, ids };
}

/**
 * `--repair-rows <cc>=<path>[,<cc>=<path>]`: the repair rows to read for a
 * vendor instead of its default file. A bare path is refused -- with two
 * vendors it would not say whose rows it is.
 *
 * @returns {{given: Object<string, string>, problems: string[]}}
 */
export function parseRepairRowsArg(text) {
  const given = {};
  const problems = [];
  for (const part of String(text).split(',').map((s) => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    const cc = eq > 0 ? part.slice(0, eq) : null;
    const path = eq > 0 ? part.slice(eq + 1) : '';
    if (cc === null || !path) { problems.push(`${part}: expected <cc>=<path>`); continue; }
    if (!VENDORS.includes(cc)) { problems.push(`${cc} is not one of ${VENDORS.join(' ')}`); continue; }
    if (cc in given) { problems.push(`${cc} given twice`); continue; }
    given[cc] = path;
  }
  if (!Object.keys(given).length && !problems.length) problems.push('no <cc>=<path> given');
  return { given, problems };
}

/** Spans measured on their own for `cc` in these rows (what a cross-check of `cc` could compare). */
export function spansMeasuredAlone(rows, cc) {
  return rows.filter((r) => r.cc === cc && r.measured).reduce((n, r) => n + r.spans.filter((s) => s.source === 'span').length, 0);
}

/**
 * The cross-check over every vendor of a run.
 *
 * @param perVendor  cc -> crossCheckRepairRows(rows, repairRows, cc) for a vendor
 *                   whose repair rows were read, or null when that vendor has no
 *                   repair rows file
 * @param measured   cc -> spansMeasuredAlone(rows, cc)
 * @returns {{vendors: {cc: string, status: 'held'|'failed'|'not-cross-checked', vacuous: boolean, cross: object|null}[],
 *            held: string[], failed: string[], notChecked: string[]}}
 *   A vendor is `held` only when its repair rows were read, nothing disagreed,
 *   and -- where it measured any span alone -- at least one span was compared
 *   (none compared is `vacuous`, and fails). A vendor without repair rows is
 *   `not-cross-checked`: never held, never failed.
 */
export function crossCheckSummary(perVendor, measured) {
  const vendors = [];
  for (const cc of VENDORS) {
    if (!(cc in perVendor)) continue;
    const cross = perVendor[cc];
    if (cross === null) { vendors.push({ cc, status: 'not-cross-checked', vacuous: false, cross: null }); continue; }
    const vacuous = (measured[cc] || 0) > 0 && cross.compared === 0;
    const failed = vacuous || cross.mismatches.length > 0 || cross.hiddenMismatches.length > 0;
    vendors.push({ cc, status: failed ? 'failed' : 'held', vacuous, cross });
  }
  const of = (s) => vendors.filter((v) => v.status === s).map((v) => v.cc);
  return { vendors, held: of('held'), failed: of('failed'), notChecked: of('not-cross-checked') };
}

/**
 * Hidden eliminations per vendor and level, with ids, and the size of the
 * undercount beside the tracked cell-level count.
 *
 *   trackedEliminated   tracked erasure cells WIPE_ELIMINATED at (cc, opt), over
 *                       the whole erasure family (every file, not only the
 *                       multi-span ones): the number the find step reports
 *   hidden              cells here whose tracked verdict is WIPE_SURVIVED and in
 *                       which a removable span, ablated alone, is WIPE_ELIMINATED
 *
 * A hidden cell is not added to the eliminated count as a claim that the cell is
 * "really" eliminated -- the other span still survives. It is the number of cells
 * in which at least one wipe the model wrote is gone although the cell says it
 * survived.
 */
export function hiddenSummary(trackedRows, rows, { vendors = VENDORS, opts = ALL_OPTS } = {}) {
  const out = [];
  for (const cc of vendors) {
    for (const opt of opts) {
      const sub = rows.filter((r) => r.cc === cc && r.opt === opt);
      if (!sub.length) continue;
      const trackedEliminated = trackedRows.filter((r) => r.kind === 'erasure' && r.cc === cc && r.opt === opt && r.verdict === ELIMINATED).length;
      const hidden = sub.filter((r) => r.hiddenElimination === true);
      const byIdiom = {};
      for (const r of hidden) byIdiom[r.idiom] = (byIdiom[r.idiom] || 0) + 1;
      out.push({
        cc, opt,
        cells: sub.length,
        measuredCells: sub.filter((r) => r.measured).length,
        survivedCells: sub.filter((r) => r.measured && r.trackedVerdict === SURVIVED).length,
        trackedEliminated,
        hidden: hidden.length,
        hiddenByIdiom: byIdiom,
        withHidden: trackedEliminated + hidden.length,
        // A hidden elimination whose eliminated span is itself initialiser-like
        // is a removed initialiser, not a removed wipe; counted apart so it
        // cannot pass for one.
        hiddenOnlyInitialiserLike: hidden.filter((r) => r.spans
          .filter((s) => s.kind === 'removable' && s.off === ELIMINATED).every((s) => s.initialiserLike === true)).length,
        hiddenIds: hidden.map((r) => ({
          id: r.id, idiom: r.idiom,
          spans: r.spans.filter((s) => s.kind === 'removable' && s.off === ELIMINATED).map((s) => s.index),
          eliminatedInitialiserLike: r.spans.filter((s) => s.kind === 'removable' && s.off === ELIMINATED && s.initialiserLike === true).map((s) => s.index),
          initialiserLikeElsewhere: r.spans.some((s) => s.initialiserLike === true && s.off !== ELIMINATED),
        })),
      });
    }
  }
  return out;
}

/** One line per (cc, opt): the tracked cell-level count, and it plus the hidden cells. */
export function undercountLine(h) {
  return `${h.cc} ${h.opt}  cell-level eliminated ${h.trackedEliminated}   cell-level eliminated + hidden ${h.withHidden}  (+${h.hidden}`
    + ` over ${h.measuredCells} measured multi-span cells)`;
}

/**
 * The lexical label over every erasure file (no compile needed).
 *
 * @param files  [{id, kinds: string[], labels: (boolean|null)[]}]
 */
export function labelSummary(files) {
  const counts = {};
  const oneSpanInit = [];
  for (const f of files) {
    f.labels.forEach((l, i) => {
      const k = `${f.kinds[i]}:${l === null ? 'null' : l}`;
      counts[k] = (counts[k] || 0) + 1;
    });
    if (f.labels.length === 1 && f.labels[0] === true) oneSpanInit.push(f.id);
  }
  return { files: files.length, spans: files.reduce((n, f) => n + f.labels.length, 0), counts, oneSpanInit: oneSpanInit.sort() };
}

/**
 * Why a run may not be written to data/: the tracked per-span file is the full
 * run -- every multi-span file, both vendors, all five levels, the default
 * tracked rows and repair rows -- and a run whose integrity held and whose
 * cross-check held for every vendor. `crossCheck` is crossCheckSummary's result,
 * or null before the run.
 */
export function writeDataProblems({ files, vendors, opts, rowsIsDefault, repairRowsIsDefault, integrity, crossCheck }) {
  const why = [];
  if (files) why.push('--files');
  if (vendors.length !== VENDORS.length || VENDORS.some((v) => !vendors.includes(v))) why.push('a partial --cc');
  if (opts.length !== ALL_OPTS.length) why.push('a partial --opts');
  if (!rowsIsDefault) why.push('--rows');
  if (!repairRowsIsDefault) why.push('--repair-rows');
  if (integrity.length) why.push(`${integrity.length} integrity problem(s)`);
  if (crossCheck && crossCheck.failed.length) why.push(`a failed cross-check (${crossCheck.failed.join(', ')})`);
  if (crossCheck && crossCheck.notChecked.length) why.push(`no repair rows to cross-check ${crossCheck.notChecked.join(', ')}`);
  return why;
}

/** Absolute-path shapes that must never reach a written file. */
export function pathHits(text) {
  const hits = [];
  for (const re of [/\/home\//, /\/root\//, /\/mnt\//, /\/Users\//, /\b[A-Za-z]:[\\/]/]) if (re.test(text)) hits.push(String(re));
  return hits;
}
