/**
 * Routing: for each disappearance shape this run actually SAW, does the fix go
 * to the compiler or back to the source?
 *
 * `../pin-families.json` already holds that judgement, one row per (property,
 * shape, repair candidate), with `routesTo` naming the source-side rule where
 * the compiler cannot hold the shape. Until this module existed, nothing read
 * it during a run: `../run-repair-loop.mjs` printed cells and outcomes, and a
 * human carried the sentence "this one is not repairable in the compiler, send
 * it to the source" across from the table by eye. That is the step this file
 * mechanises -- and the reason it is worth mechanising is not typing effort but
 * the failure mode of the manual version, which is to route a shape the run
 * never observed and to quietly drop one it did.
 *
 * THE MAPPING IS DERIVED FROM THE TABLE, NEVER WRITTEN HERE.
 *
 * A second copy of "libcallMemset means the libcall-memset shape" in this file
 * would be exactly the hand-transcription the table exists to remove: it would
 * go stale the first time a row is renamed and nothing would fail. So the
 * mapping is read out of the rows' own `evidence.cite`:
 *
 *   claim `unhandled-shape-occurrences`      -> cite.counter is the name of a
 *                                               counter in a plugin record's
 *                                               `unhandled` block
 *   claim `configguard-default-equals-enabled` -> cite.scen is the scenario id a
 *                                               configguard row carries
 *
 * Those two claims are the only ones whose citation names something a run row
 * can be matched against; every other claim counts outcomes, not occurrences of
 * a shape. A cell reached by neither is a cell with NO SHAPE SIGNAL, and that
 * is a state this module prints rather than hides (see below).
 *
 * TWO REFUSALS, BOTH DELIBERATE.
 *
 *  1. A counter name in a record that the table names no row for is an
 *     EXCEPTION, not a skipped key. Silently ignoring it is how "we did not
 *     look at that shape" becomes "that shape did not occur": the plugin would
 *     be reporting a shape it does not pin, the run would see the number, and
 *     the routing would say nothing at all. The same for a configguard `scen`.
 *  2. A cell whose signal fired zero times in this run is NOT routed, and the
 *     count of such cells is printed. `../test/pin-families.test.mjs` pins that
 *     all five `unhandled` counters are 0 in both tracked runs, so over the r2
 *     corpus this is the normal state of every erasure-side signal and the
 *     honest report is "no shape signal", never "routed".
 *
 * Pure: no file is read, no compiler is driven, nothing is written. The runner
 * passes the parsed table and its own rows in.
 */
import { byShape, shapeVerdicts } from './pin-families.mjs';

/**
 * The claims whose citation names a signal a RUN ROW can carry, and the field
 * of the citation that holds the name. Everything else in CLAIMS counts
 * outcomes of a repair rather than occurrences of a shape, and cannot key a
 * routing decision.
 */
export const SIGNAL_CLAIMS = Object.freeze({
  'unhandled-shape-occurrences': Object.freeze({ kind: 'counter', field: 'counter' }),
  'configguard-default-equals-enabled': Object.freeze({ kind: 'scen', field: 'scen' }),
});

/**
 * What this run decided to do with a shape. The three that matter most are at
 * the top, because they are the ones a reader has to act on.
 *
 *   repair-in-compiler        a candidate is measured to retain the shape; the
 *                             fix stays where it is
 *   route-to-source           no candidate retains it and a source-side rule is
 *                             named whose scope was checked and does cover it
 *   route-to-source-unverified  a rule is named but nobody ran it over this
 *                             shape; it says where to look, not that it catches
 *   no-source-rule-covers-it  a rule is named and its scope explicitly does NOT
 *                             cover the shape. Neither side holds it
 *   unrouted                  no candidate retains it and the table says there
 *                             is no rule to route it to
 *   open                      no candidate retains it and the table says nothing
 *   not-routed-no-signal      this run saw no instance of the shape, so nothing
 *                             is routed either way
 */
export const DECISIONS = Object.freeze([
  'repair-in-compiler',
  'route-to-source',
  'route-to-source-unverified',
  'no-source-rule-covers-it',
  'unrouted',
  'open',
  'not-routed-no-signal',
]);

/** The decisions worth printing loudest: a shape nothing in this project holds. */
export const LOUD = Object.freeze(['unrouted', 'open', 'no-source-rule-covers-it']);

/** Why a cell was not routed. A count of "not routed" without this is unreadable. */
export const NO_SIGNAL_REASONS = Object.freeze([
  'no-signal-defined',   // the table defines no run-observable signal for this cell
  'not-measured',        // a signal exists but this run did not measure it (e.g. --plan)
  'zero-occurrences',    // the signal is defined and measured, and read 0
]);

const cellKey = (r) => `${r.property} / ${r.shape}`;
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The table's signal vocabulary, derived from the rows' citations.
 *
 * @returns {{byCounter: Map<string, object[]>, byScen: Map<string, object[]>,
 *            counters: string[], scens: string[]}}
 */
export function signalIndex(table) {
  const byCounter = new Map();
  const byScen = new Map();
  for (const r of table?.rows ?? []) {
    const cite = r.evidence?.cite;
    if (!cite) continue;
    const spec = SIGNAL_CLAIMS[cite.claim];
    if (!spec) continue;
    const name = cite[spec.field];
    if (typeof name !== 'string' || name === '') {
      throw new Error(`pin-families.json: ${cellKey(r)} / ${r.candidate} cites ${cite.claim} without a `
        + `${spec.field}, so the signal it stands for cannot be derived from the table`);
    }
    const into = spec.kind === 'counter' ? byCounter : byScen;
    if (!into.has(name)) into.set(name, []);
    into.get(name).push({
      cell: cellKey(r), property: r.property, shape: r.shape, candidate: r.candidate,
      status: r.status, cc: cite.cc ?? null,
    });
  }
  return {
    byCounter, byScen,
    counters: [...byCounter.keys()].sort(cmp),
    scens: [...byScen.keys()].sort(cmp),
  };
}

/**
 * Sum each `unhandled` counter over every plugin record this run's rows carry.
 * `unknown` holds counter names the table knows nothing about; the caller turns
 * those into an exception rather than dropping them.
 */
export function counterOccurrences(rows, counters) {
  const totals = new Map(counters.map((c) => [c, 0]));
  const unknown = new Set();
  let records = 0;
  for (const r of rows ?? []) {
    // erasure rows carry recordW/recordWo, no-wipe rows carry record.
    for (const rec of [r.recordW, r.recordWo, r.record]) {
      if (!rec || rec.ok !== true || !rec.unhandled || typeof rec.unhandled !== 'object') continue;
      records++;
      for (const [k, n] of Object.entries(rec.unhandled)) {
        if (!totals.has(k)) { unknown.add(k); continue; }
        totals.set(k, totals.get(k) + (Number.isFinite(Number(n)) ? Number(n) : 0));
      }
    }
  }
  return { totals, records, unknown: [...unknown].sort(cmp) };
}

/**
 * The configguard rows this run produced, per scenario. `rows` is the count of
 * cells of that scenario -- the occurrence of the shape; `notRepaired` is how
 * many of them the plugin did NOT turn into the enabled build, which is the
 * measurement that the compiler cannot hold this shape.
 */
export function scenOccurrences(rows, scens) {
  const seen = new Map(scens.map((s) => [s, { rows: 0, repaired: 0, notRepaired: 0, undecided: 0 }]));
  const unknown = new Set();
  for (const r of rows ?? []) {
    if (r?.kind !== 'configguard') continue;
    const s = r.scen;
    if (typeof s !== 'string' || !seen.has(s)) { unknown.add(String(s)); continue; }
    const e = seen.get(s);
    e.rows++;
    if (r.pluginDefaultEqualsEnabled === true) e.repaired++;
    else if (r.pluginDefaultEqualsEnabled === false) e.notRepaired++;
    else e.undecided++;
  }
  return { seen, unknown: [...unknown].sort(cmp) };
}

/**
 * The decision for one cell, given the table's own shape verdict and the rows
 * of that cell. `shapeVerdicts()` already separates repairable from routed; the
 * refinement here is that "routed to source" is split by whether the rule's
 * scope was checked to cover the shape. The table carries four rows whose
 * `appliesToThisShape` is `"no"` -- a rule is named and it explicitly does not
 * cover the shape -- and calling those "routed to source" would be the quiet
 * overclaim `checkRowRouting` in ../lib/pin-families.mjs refuses in the table.
 */
export function decisionFor(verdict, group) {
  if (verdict?.verdict === 'repairable-in-compiler') return 'repair-in-compiler';
  const named = (group ?? []).filter((r) => r.routesTo && r.routesTo.rule !== 'none');
  if (!named.length) return verdict?.verdict === 'unrouted' ? 'unrouted' : 'open';
  if (named.some((r) => r.routesTo.appliesToThisShape === 'yes')) return 'route-to-source';
  if (named.some((r) => r.routesTo.appliesToThisShape === 'unverified')) return 'route-to-source-unverified';
  return 'no-source-rule-covers-it';
}

/**
 * Route one run.
 *
 * @param {object}   o
 * @param {object}   o.table    the parsed ../pin-families.json
 * @param {object[]} o.rows     this run's rows (erasure, none and configguard)
 * @param {string}  [o.cc]      the compiler this run drove
 * @param {string}  [o.cfgNote] the runner's own note when configguard was not
 *   measured (a plan-driven run, or a run without -O2). Passed in rather than
 *   re-worded here, so the routing section and the results text say the same
 *   thing in the same words.
 * @throws when a record carries an `unhandled` counter, or a configguard row a
 *   `scen`, that the table names no row for.
 */
export function routeRun({ table, rows = [], cc = null, cfgNote = null }) {
  const index = signalIndex(table);
  const co = counterOccurrences(rows, index.counters);
  if (co.unknown.length) {
    throw new Error(`routing: this run's plugin records carry unhandled counter(s) ${co.unknown.join(', ')}, `
      + `which pin-families.json holds no row for. A counter with no row cannot be routed, and skipping it would `
      + `turn "nobody looked at this shape" into "this shape did not occur" -- the one substitution this table exists `
      + `to prevent. Add a row citing unhandled-shape-occurrences with that counter, or stop emitting it. `
      + `The counters the table knows: ${index.counters.join(', ') || '(none)'}.`);
  }
  const so = scenOccurrences(rows, index.scens);
  if (so.unknown.length) {
    throw new Error(`routing: this run produced configguard row(s) with scen ${so.unknown.join(', ')}, `
      + `which pin-families.json holds no row for. The same refusal as for an unknown counter: a shape the run `
      + `observed and the table cannot name is reported, never dropped. `
      + `The scenarios the table knows: ${index.scens.join(', ') || '(none)'}.`);
  }

  const verdicts = shapeVerdicts(table);
  const groups = byShape(table?.rows ?? []);

  // cell -> signals, de-duplicated: the two configguard rows of one cell (clang
  // and gcc) cite the same scen and must contribute one signal, not two.
  const signalsByCell = new Map();
  const add = (cell, sig) => {
    if (!signalsByCell.has(cell)) signalsByCell.set(cell, new Map());
    signalsByCell.get(cell).set(`${sig.kind}|${sig.name}`, sig);
  };
  for (const [name, hits] of index.byCounter) {
    const n = co.totals.get(name) ?? 0;
    for (const h of hits) {
      add(h.cell, { kind: 'counter', name, occurrences: n, records: co.records, measured: true, observed: n > 0 });
    }
  }
  for (const [name, hits] of index.byScen) {
    const e = so.seen.get(name) ?? { rows: 0, repaired: 0, notRepaired: 0, undecided: 0 };
    // When the runner says configguard was not measured, 0 rows is an absence of
    // measurement and not an absence of the shape. The two are different states
    // and the report keeps them apart.
    const measured = !cfgNote;
    for (const h of hits) {
      add(h.cell, {
        kind: 'scen', name, occurrences: e.rows, repaired: e.repaired,
        notRepaired: e.notRepaired, undecided: e.undecided,
        measured, observed: measured && e.rows > 0, note: measured ? null : cfgNote,
      });
    }
  }

  const cells = Object.keys(verdicts).sort(cmp).map((key) => {
    const group = groups[key] ?? [];
    const signals = [...(signalsByCell.get(key)?.values() ?? [])]
      .sort((a, b) => cmp(a.kind, b.kind) || cmp(a.name, b.name));
    const observed = signals.filter((s) => s.observed);
    const noSignalReason = signals.length === 0 ? 'no-signal-defined'
      : signals.every((s) => !s.measured) ? 'not-measured'
        : observed.length === 0 ? 'zero-occurrences' : null;
    const decision = noSignalReason ? 'not-routed-no-signal' : decisionFor(verdicts[key], group);
    return {
      cell: key,
      property: group[0]?.property ?? null,
      shape: group[0]?.shape ?? null,
      tableVerdict: verdicts[key].verdict,
      retainedBy: verdicts[key].retainedBy,
      candidates: verdicts[key].candidates,
      signals,
      signalObserved: observed.length > 0,
      noSignalReason,
      why: whyLine(noSignalReason, signals),
      decision,
      routes: group.filter((r) => r.routesTo).map((r) => ({
        candidate: r.candidate,
        status: r.status,
        rule: r.routesTo.rule,
        appliesToThisShape: r.routesTo.appliesToThisShape ?? null,
        appliesWhy: r.routesTo.appliesWhy ?? null,
        whyNone: r.routesTo.whyNone ?? null,
        recallVerified: r.routesTo.recallVerified === true,
        recall: r.routesTo.recall ?? null,
        cc: r.evidence?.cite?.cc ?? null,
      })),
    };
  });

  const counts = Object.fromEntries(DECISIONS.map((d) => [d, 0]));
  for (const c of cells) counts[c.decision]++;
  const noSignal = Object.fromEntries(NO_SIGNAL_REASONS.map((k) => [k, 0]));
  for (const c of cells) if (c.noSignalReason) noSignal[c.noSignalReason]++;
  // Of the cells this run did not route: how many the table nevertheless calls
  // repairable in the compiler. Without this the "not routed" count reads as a
  // pile of shapes nothing handles, when several of them are the shapes the pin
  // was written for and whose evidence is an outcome ratio rather than a counter.
  const notRoutedButRepairable = cells
    .filter((c) => c.decision === 'not-routed-no-signal' && c.tableVerdict === 'repairable-in-compiler')
    .map((c) => c.cell);

  return {
    what: 'A5, the clonal selection step: per (property, disappearance shape), what this run saw and '
      + 'where the repair goes. The mapping from a run signal to a table cell is derived from '
      + 'pin-families.json, not written in lib/routing.mjs.',
    cc,
    configguardNote: cfgNote ?? null,
    signalVocabulary: { counters: index.counters, scens: index.scens },
    recordsRead: co.records,
    counterTotals: Object.fromEntries([...co.totals].sort((a, b) => cmp(a[0], b[0]))),
    scenTotals: Object.fromEntries([...so.seen].sort((a, b) => cmp(a[0], b[0]))),
    cells,
    counts,
    noSignal,
    notRoutedButRepairable,
    // The two states worth acting on, lifted out so they cannot be missed in a
    // table of twelve rows.
    loud: cells.filter((c) => LOUD.includes(c.decision)).map((c) => c.cell),
    routedToSource: cells.filter((c) => c.decision === 'route-to-source' || c.decision === 'route-to-source-unverified')
      .map((c) => ({ cell: c.cell, decision: c.decision, rules: [...new Set(c.routes.filter((r) => r.rule !== 'none').map((r) => r.rule))] })),
  };
}

function whyLine(reason, signals) {
  if (!reason) return null;
  const names = signals.map((s) => `${s.kind} ${s.name}`).join(', ');
  if (reason === 'no-signal-defined') {
    return 'no shape signal -- pin-families.json defines no run-observable signal for this cell, '
      + 'so this run says nothing about where it routes';
  }
  if (reason === 'not-measured') {
    const note = signals.map((s) => s.note).find(Boolean);
    return `no shape signal -- ${names} was not measured in this run${note ? ` (${note})` : ''}`;
  }
  return `no shape signal -- ${names} is defined for this cell and this run read 0 occurrence(s)`;
}

/** The routing section of the results, as text. Nothing here reads a file. */
export function renderRouting(report) {
  const L = [];
  const pad = (s, n) => (String(s).length >= n ? String(s) : String(s) + ' '.repeat(n - String(s).length));
  L.push('routing (A5: repair in the compiler, or back to the source?)');
  L.push('  the signal -> cell mapping is derived from pin-families.json; nothing here is transcribed by hand');
  L.push(`  signals the table defines: ${report.signalVocabulary.counters.length} unhandled counter(s) `
    + `[${report.signalVocabulary.counters.join(' ') || '-'}], ${report.signalVocabulary.scens.length} configguard scen(s) `
    + `[${report.signalVocabulary.scens.join(' ') || '-'}]`);
  L.push(`  plugin records read: ${report.recordsRead}`);
  if (report.configguardNote) L.push(`  ${report.configguardNote}`);
  L.push('');

  // The loudest thing first: what nothing in this project currently holds.
  const loud = report.cells.filter((c) => LOUD.includes(c.decision));
  L.push(`  >>> NOT HELD BY EITHER SIDE: ${loud.length} cell(s) this run observed whose shape no measured repair `
    + 'retains and no source-side rule is verified to cover');
  if (!loud.length) L.push('  >>> (none in this run)');
  for (const c of loud) {
    L.push(`  >>> ${pad(c.decision, 24)} ${c.cell}`);
    for (const r of c.routes) {
      if (r.rule === 'none') L.push(`        no rule: ${r.whyNone}`);
      else L.push(`        ${r.rule} appliesToThisShape=${r.appliesToThisShape}: ${r.appliesWhy}`);
    }
  }
  L.push('');

  L.push('  per cell');
  for (const c of report.cells) {
    const sig = c.signals.length
      ? c.signals.map((s) => `${s.kind} ${s.name}=${s.measured ? s.occurrences : 'not measured'}`).join(', ')
      : '(none defined)';
    L.push(`    ${pad(c.decision, 26)} ${pad(c.cell, 62)} table=${pad(c.tableVerdict, 24)} signal: ${sig}`);
    if (c.why) L.push(`      ${c.why}`);
    if (!c.why) {
      for (const r of c.routes) {
        if (r.rule === 'none') L.push(`      -> no source-side rule: ${r.whyNone}`);
        else L.push(`      -> ${r.rule} (${r.appliesToThisShape}) via ${r.candidate}`);
      }
      if (c.decision === 'repair-in-compiler') L.push(`      -> stays in the compiler: retained by ${c.retainedBy.join(', ')}`);
    }
  }
  L.push('');

  L.push('  counts');
  for (const d of DECISIONS) L.push(`    ${pad(d, 26)} ${report.counts[d]}`);
  L.push(`  of the ${report.counts['not-routed-no-signal']} not routed: `
    + NO_SIGNAL_REASONS.map((k) => `${k} ${report.noSignal[k]}`).join(', '));
  L.push(`  ${report.notRoutedButRepairable.length} of them the table calls repairable-in-compiler anyway `
    + '(their evidence is an outcome ratio, not a shape counter, so this run routes nothing for them): '
    + (report.notRoutedButRepairable.join('; ') || '(none)'));
  L.push('');
  return L.join('\n');
}
