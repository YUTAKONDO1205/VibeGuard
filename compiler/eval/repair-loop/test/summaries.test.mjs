/**
 * The run-level views printed beside the outcome table, and the pin plan. Rows are
 * built here in the runner's shape. None of these may change an outcome, so every
 * test also checks the rows it was handed are left as they were.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  spanSummary, effectVerdict, corroborationSummary, listingChangedWithoutLoss, labelRenumbering, crossVendorCoverage, buildPinPlan,
} from '../lib/summaries.mjs';

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];

function er(id, opt, extra = {}) {
  return {
    id, opt, kind: 'erasure', cc: 'clang-18', fn: 'f', helpers: [], baseline: S, repaired: S, outcome: 'ALREADY_SURVIVED',
    trackedVerdict: S, spanSource: 'cell', spans: [{ index: 0, kind: 'removable', off: S, on: S, source: 'cell', recordOk: null }],
    hiddenElimination: false, hiddenRetained: false,
    effectW: { off: 'PRESENT', on: 'PRESENT' },
    listings: { wOff: 'a', woOff: 'b', wOn: 'a', woOn: 'b' },
    recordW: { ok: true, pinnedCount: 0, wouldPinCount: 0 },
    ...extra,
  };
}
const retained = (id, opt, extra = {}) => er(id, opt, {
  baseline: E, repaired: S, outcome: 'RETAINED', trackedVerdict: E,
  spans: [{ index: 0, kind: 'removable', off: E, on: S, source: 'cell', recordOk: null }],
  effectW: { off: 'ABSENT', on: 'PRESENT' }, listings: { wOff: 'a', woOff: 'a', wOn: 'c', woOn: 'a' },
  recordW: { ok: true, pinnedCount: 1, wouldPinCount: 1 }, ...extra,
});
const frozen = (rows) => JSON.stringify(rows);

// ---- spans ------------------------------------------------------------------------

test('spanSummary: removable spans of RETAINED cells, one-span cells contributing their cell verdict', () => {
  const rows = [
    retained('one', '-O2'),
    retained('two', '-O2', {
      spanSource: 'span',
      spans: [
        { index: 0, kind: 'removable', off: E, on: S, source: 'span', recordOk: true },
        { index: 1, kind: 'removable', off: E, on: E, source: 'span', recordOk: true },
        { index: 2, kind: 'nonremovable', off: null, on: null, source: 'not-measured', recordOk: null },
      ],
    }),
    er('surv', '-O2'),
  ];
  const before = frozen(rows);
  const s = spanSummary(rows, ['-O2']);
  assert.equal(s.length, 1);
  assert.equal(s[0].retainedCells, 2);
  assert.deepEqual(s[0].retainedSpans, { survived: 2, total: 3 });
  assert.deepEqual(s[0].retainedSpanMisses, [{ id: 'two', index: 1, on: E }]);
  assert.equal(s[0].multiSpanCells, 1);
  assert.equal(frozen(rows), before);
});

test('spanSummary: hidden eliminations per level, retained or not, with ids', () => {
  const rows = [
    er('h1', '-O2', { hiddenElimination: true, hiddenRetained: true, spanSource: 'span' }),
    er('h2', '-O2', { hiddenElimination: true, hiddenRetained: false, spanSource: 'span' }),
    er('h3', '-O3', { hiddenElimination: true, hiddenRetained: true, spanSource: 'span' }),
    er('plain', '-O2'),
    { id: 'none', opt: '-O2', kind: 'none', hiddenElimination: true },
  ];
  const [o2, o3] = spanSummary(rows, ['-O2', '-O3']);
  assert.equal(o2.hidden, 2);
  assert.equal(o2.hiddenRetained, 1);
  assert.deepEqual(o2.hiddenIds, [{ id: 'h1', retained: true }, { id: 'h2', retained: false }]);
  assert.equal(o3.hidden, 1);
  assert.equal(o3.hiddenRetained, 1);
});

// ---- corroboration ------------------------------------------------------------------

test('effectVerdict reads through the injected oracle, and a missing listing is null', () => {
  const calls = [];
  const observe = (listing, fn, effect) => { calls.push([listing, fn, effect]); return { verdict: listing.includes('z') ? 'PRESENT' : 'ABSENT' }; };
  const eff = { symbols: ['memset'], allowInlineZeroStore: true };
  assert.equal(effectVerdict(observe, 'xz', 'f', eff), 'PRESENT');
  assert.equal(effectVerdict(observe, 'x', 'f', eff), 'ABSENT');
  assert.equal(effectVerdict(observe, null, 'f', eff), null);
  assert.deepEqual(calls, [['xz', 'f', eff], ['x', 'f', eff]]);
});

test('corroborationSummary counts RETAINED cells only, both sides, and lists on-side misses', () => {
  const rows = [
    retained('a', '-O2'),
    retained('b', '-O2', { effectW: { off: 'PRESENT', on: 'PRESENT' } }),
    retained('c', '-O2', { effectW: { off: 'ABSENT', on: 'ABSENT' } }),
    er('d', '-O2', { effectW: { off: 'PRESENT', on: 'PRESENT' } }),
  ];
  const before = frozen(rows);
  const [c] = corroborationSummary(rows, ['-O2']);
  assert.deepEqual({ retained: c.retained, onPresent: c.onPresent, offPresent: c.offPresent }, { retained: 3, onPresent: 2, offPresent: 1 });
  assert.deepEqual(c.onNotPresent, ['c']);
  assert.equal(c.onRepStosOnly, 0);
  assert.equal(frozen(rows), before);
});

test('corroborationSummary: the rep-stos reading is counted beside the oracle\'s misses, never added to its count', () => {
  const rows = [
    retained('oracle', '-Os', { effectWRepStos: { off: false, on: false } }),
    retained('stos', '-Os', { effectW: { off: 'ABSENT', on: 'ABSENT' }, effectWRepStos: { off: false, on: true } }),
    retained('neither', '-Os', { effectW: { off: 'ABSENT', on: 'ABSENT' }, effectWRepStos: { off: false, on: false } }),
    // both readings PRESENT: an oracle hit, not a rep-stos-only one
    retained('both', '-Os', { effectWRepStos: { off: false, on: true } }),
    // a row written before the reading existed carries no field: not rep stos
    retained('old', '-Os', { effectW: { off: 'ABSENT', on: 'ABSENT' } }),
  ];
  const [c] = corroborationSummary(rows, ['-Os']);
  assert.equal(c.retained, 5);
  assert.equal(c.onPresent, 2);
  assert.deepEqual(c.onNotPresent, ['stos', 'neither', 'old']);
  assert.equal(c.onRepStosOnly, 1);
  assert.deepEqual(c.onRepStosOnlyIds, ['stos']);
});

// ---- listing changed where the find step saw no loss -----------------------------------

test('listingChangedWithoutLoss: ALREADY_SURVIVED, pinned in w, w digests differ; split by hidden elimination', () => {
  const pinned = { ok: true, pinnedCount: 1, wouldPinCount: 1 };
  const moved = { wOff: 'a', woOff: 'b', wOn: 'c', woOn: 'b' };
  const rows = [
    er('hidden', '-O2', { recordW: pinned, listings: moved, hiddenElimination: true, hiddenRetained: true }),
    er('plain', '-O2', { recordW: pinned, listings: moved }),
    er('same', '-O2', { recordW: pinned }), // digests equal
    er('nopin', '-O2', { listings: moved }), // pinned nothing
    er('refused', '-O2', { recordW: { ok: false, problems: ['record-missing'] }, listings: moved }),
    er('nolisting', '-O2', { recordW: pinned, listings: { wOff: 'a', woOff: 'b', wOn: null, woOn: null } }),
    retained('ret', '-O2', { listings: moved }), // not ALREADY_SURVIVED
  ];
  const [c] = listingChangedWithoutLoss(rows, ['-O2']);
  assert.deepEqual({ total: c.total, hidden: c.hidden, notHidden: c.notHidden }, { total: 2, hidden: 1, notHidden: 1 });
  assert.deepEqual(c.notHiddenIds, ['plain']);
});

// ---- label names ---------------------------------------------------------------------------

test('labelRenumbering: per level, baseline and RETAINED cells whose bodies differ only in .L names, and renumbered controls', () => {
  const rows = [
    er('base', '-O2', { labelsOnly: { baseline: true, repaired: false } }),
    retained('ret', '-O2', { labelsOnly: { baseline: false, repaired: true } }),
    // labels-only on the repaired side, but not RETAINED: not in that count
    er('surv', '-O2', { labelsOnly: { baseline: false, repaired: true } }),
    retained('ctl', '-O2', { labelsOnly: { baseline: false, repaired: false }, controlUntouchedRenumberedOnly: true }),
    er('old', '-O2'), // a row from before the field existed
    er('o3', '-O3', { labelsOnly: { baseline: true, repaired: null } }),
  ];
  const before = frozen(rows);
  const [o2, o3] = labelRenumbering(rows, ['-O2', '-O3']);
  assert.deepEqual(o2, {
    opt: '-O2', baselineLabelsOnly: 1, baselineLabelsOnlyIds: [`base (${S})`], retainedLabelsOnly: 1, retainedLabelsOnlyIds: ['ret'], controlRenumbered: 1,
  });
  assert.equal(o3.baselineLabelsOnly, 1);
  assert.equal(o3.retainedLabelsOnly, 0);
  assert.equal(frozen(rows), before);
});

// ---- cross-vendor coverage ----------------------------------------------------------------

const tr = (id, cc, opt, verdict) => ({ id, cc, opt, kind: 'erasure', verdict });

const gccRow = (id, opt, outcome) => ({ id, opt, kind: 'erasure', cc: 'gcc-13', outcome });
const SHA = 'ab'.repeat(32);
const FULL = { full: true, why: [] };

test('crossVendorCoverage: found from the tracked rows, reversed from this run; no gcc rows is "not measured", never 0', () => {
  const tracked = [
    tr('a', 'clang-18', '-O2', E), tr('b', 'clang-18', '-O2', E), tr('c', 'clang-18', '-O2', S),
    tr('a', 'gcc-13', '-O2', E), tr('b', 'gcc-13', '-O2', E), tr('c', 'gcc-13', '-O2', E),
    { id: 'x', cc: 'clang-18', opt: '-O2', kind: 'authz', verdict: E },
  ];
  const rows = [retained('a', '-O2'), er('b', '-O2', { baseline: E, outcome: 'PIN_INEFFECTIVE', trackedVerdict: E }), er('c', '-O2')];
  const before = frozen(rows);
  const c = crossVendorCoverage({ tracked, rows, runCc: 'clang-18' });
  assert.deepEqual(c.total, { reversed: 1, found: 5, notMeasured: 3 });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 1/2 (this run), gcc-13 -/3 (not measured: no tracked repair rows for gcc-13), '
    + 'total 1/5, 3 found cell(s) not measured');
  assert.deepEqual(c.perVendor.map((v) => [v.cc, v.reversed, v.found, v.measured, v.source.kind]),
    [['clang-18', 1, 2, 2, 'this-run'], ['gcc-13', 0, 3, 0, 'not-measured']]);
  assert.equal(frozen(rows), before);
});

test('crossVendorCoverage: the other vendor\'s tracked repair rows are read, with their sha256 and whether the run was full', () => {
  const tracked = [
    tr('a', 'clang-18', '-O2', E), tr('b', 'clang-18', '-O2', E),
    tr('a', 'gcc-13', '-O2', E), tr('b', 'gcc-13', '-O2', E), tr('c', 'gcc-13', '-O2', E), tr('d', 'gcc-13', '-O2', S),
  ];
  const rows = [retained('a', '-O2'), retained('b', '-O2')];
  const gccRows = [gccRow('a', '-O2', 'RETAINED'), gccRow('b', '-O2', 'PIN_NOT_APPLIED'), gccRow('c', '-O2', 'RETAINED'),
    gccRow('d', '-O2', 'RETAINED'), // RETAINED but the find step never found a loss there: not a reversed finding
    { id: 'z', opt: '-O2', kind: 'configguard', cc: 'gcc-13', outcome: 'OUT_OF_REACH_PREPROCESS' }];
  const label = 'compiler/eval/repair-loop/data/r2-repair-rows-gcc-13.json';
  const c = crossVendorCoverage({ tracked, rows, runCc: 'clang-18', others: { 'gcc-13': { label, sha256: SHA, rows: gccRows, full: FULL } } });
  assert.deepEqual(c.total, { reversed: 4, found: 5, notMeasured: 0 });
  assert.equal(c.line, `eliminations reversed / found: clang-18 2/2 (this run), gcc-13 2/3 (tracked repair rows ${label}, sha256 ${SHA}, `
    + 'a full --write-data run), total 4/5');
});

test('crossVendorCoverage: a gcc run reads clang\'s tracked rows the same way, and lists itself first', () => {
  const tracked = [tr('a', 'clang-18', '-O2', E), tr('a', 'gcc-13', '-O2', E), tr('b', 'gcc-13', '-O2', E)];
  const rows = [gccRow('a', '-O2', 'RETAINED'), gccRow('b', '-O2', 'RETAINED')];
  const clangRows = [retained('a', '-O2')];
  const c = crossVendorCoverage({ tracked, rows, runCc: 'gcc-13',
    others: { 'clang-18': { label: 'compiler/eval/repair-loop/data/r2-repair-rows.json', sha256: SHA, rows: clangRows, full: FULL } } });
  assert.match(c.line, /^eliminations reversed \/ found: gcc-13 2\/2 \(this run\), clang-18 1\/1 \(tracked repair rows compiler\/eval\/repair-loop\/data\/r2-repair-rows\.json, sha256 abab/);
  assert.match(c.line, /total 3\/3$/);
});

test('crossVendorCoverage: a tracked file that is not a full run says so, and counts only the cells it has', () => {
  const tracked = [tr('a', 'gcc-13', '-O2', E), tr('b', 'gcc-13', '-O2', E), tr('c', 'gcc-13', '-O3', E)];
  const partial = { full: false, why: ['a dry-run row', '4 (file, level) cell(s) of the corpus have no row'] };
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18',
    others: { 'gcc-13': { label: 'L', sha256: SHA, rows: [gccRow('a', '-O2', 'RETAINED')], full: partial } } });
  assert.equal(c.line, `eliminations reversed / found: clang-18 0/0 (this run), gcc-13 1/3 (tracked repair rows L, sha256 ${SHA}, `
    + 'NOT a full --write-data run: a dry-run row; 4 (file, level) cell(s) of the corpus have no row; 2 of 3 not in it), '
    + 'total 1/3, 2 found cell(s) not measured');
});

test('crossVendorCoverage: an unreadable tracked file counts nothing and says why', () => {
  const tracked = [tr('a', 'gcc-13', '-O2', E)];
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18', others: { 'gcc-13': { label: 'L', sha256: SHA, error: 'not JSON' } } });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 0/0 (this run), gcc-13 -/1 (not measured: L could not be read as repair rows for gcc-13: not JSON), '
    + 'total 0/1, 1 found cell(s) not measured');
});

test('crossVendorCoverage: rows another compiler wrote are not counted for this one', () => {
  const tracked = [tr('a', 'gcc-13', '-O2', E)];
  const mislabelled = [{ id: 'a', opt: '-O2', kind: 'erasure', cc: 'gcc-14', outcome: 'RETAINED' }];
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18', others: { 'gcc-13': { label: 'L', sha256: SHA, rows: mislabelled, full: { full: false, why: ['rows for gcc-14, not only gcc-13'] } } } });
  assert.deepEqual(c.total, { reversed: 0, found: 1, notMeasured: 1 });
});

test('crossVendorCoverage: a RETAINED cell whose tracked verdict is not ELIMINATED is not a reversed finding', () => {
  const tracked = [tr('a', 'clang-18', '-O2', S)];
  const rows = [retained('a', '-O2', { trackedVerdict: S })];
  assert.deepEqual(crossVendorCoverage({ tracked, rows, runCc: 'clang-18' }).total, { reversed: 0, found: 0, notMeasured: 0 });
});

test('crossVendorCoverage: restricted to the selected files and levels, in this run and in the other vendor\'s file', () => {
  const tracked = [tr('a', 'clang-18', '-O2', E), tr('a', 'clang-18', '-O3', E), tr('b', 'clang-18', '-O2', E), tr('a', 'gcc-13', '-O3', E), tr('a', 'gcc-13', '-O2', E)];
  const rows = [retained('a', '-O2')];
  const gccRows = [gccRow('a', '-O2', 'RETAINED'), gccRow('a', '-O3', 'RETAINED')];
  const c = crossVendorCoverage({ tracked, rows, runCc: 'clang-18', ids: new Set(['a']), opts: ['-O2'],
    others: { 'gcc-13': { label: 'L', sha256: SHA, rows: gccRows, full: FULL } } });
  assert.deepEqual(c.total, { reversed: 2, found: 2, notMeasured: 0 });
  assert.match(c.line, /clang-18 1\/1 \(this run\), gcc-13 1\/1 \(/);
});

test('crossVendorCoverage: a found cell this run did not compile (a plan-driven run) is not measured, and says so', () => {
  const tracked = [tr('a', 'clang-18', '-O2', E), tr('a', 'clang-18', '-O3', E)];
  const c = crossVendorCoverage({ tracked, rows: [retained('a', '-O2')], runCc: 'clang-18' });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 1/2 (this run; 1 of 2 not compiled in it), total 1/2, 1 found cell(s) not measured');
});

test('crossVendorCoverage: the run vendor is listed even without tracked rows; a compiler no plugin loads into says that', () => {
  const tracked = [tr('a', 'clang-17', '-O2', E), tr('b', 'icx-2024', '-O2', E)];
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18' });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 0/0 (this run), clang-17 -/1 (not measured: no tracked repair rows for clang-17), '
    + 'icx-2024 -/1 (not measured: no repair plugin loads into icx-2024), total 0/2, 2 found cell(s) not measured');
});

// ---- the pin plan ------------------------------------------------------------------------

test('buildPinPlan: a level enters for a cell elimination or a hidden one, with its reason; other files are left out', () => {
  const rows = [
    retained('b_file', '-O2', { fn: 'g', helpers: ['wipe'] }),
    retained('b_file', '-Os', { fn: 'g', helpers: ['wipe'] }),
    er('b_file', '-O1', { fn: 'g', helpers: ['wipe'], hiddenElimination: true }),
    er('b_file', '-O0', { fn: 'g', helpers: ['wipe'] }),
    er('a_file', '-O3', { hiddenElimination: true, hiddenRetained: false }),
    er('c_clean', '-O2'),
    { id: 'n_none', opt: '-O2', kind: 'none', fn: 'f' },
  ];
  const before = frozen(rows);
  const plan = buildPinPlan(rows, OPTS);
  assert.deepEqual(plan, [
    { id: 'a_file', fn: 'f', helpers: [], opts: ['-O3'], reason: { '-O3': 'span' } },
    { id: 'b_file', fn: 'g', helpers: ['wipe'], opts: ['-O1', '-O2', '-Os'], reason: { '-O1': 'span', '-O2': 'cell', '-Os': 'cell' } },
  ]);
  assert.equal(frozen(rows), before);
  // the helpers are a copy, not the row's own array
  plan[1].helpers.push('x');
  assert.deepEqual(rows[0].helpers, ['wipe']);
});

test('buildPinPlan: the level order is the one given, not the order rows arrive in', () => {
  const rows = [retained('a', '-Os'), retained('a', '-O1'), retained('a', '-O3')];
  assert.deepEqual(buildPinPlan(rows, OPTS)[0].opts, ['-O1', '-O3', '-Os']);
  assert.deepEqual(Object.keys(buildPinPlan(rows, OPTS)[0].reason), ['-O1', '-O3', '-Os']);
});

test('buildPinPlan: a baseline that is not scorable never enters the plan', () => {
  assert.deepEqual(buildPinPlan([er('a', '-O2', { baseline: 'ABLATION_DID_NOT_COMPILE', outcome: 'NOT_SCORED' })], OPTS), []);
});
