/**
 * The run-level views printed beside the outcome table, and the pin plan. Rows are
 * built here in the runner's shape. None of these may change an outcome, so every
 * test also checks the rows it was handed are left as they were.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  spanSummary, effectVerdict, corroborationSummary, listingChangedWithoutLoss, crossVendorCoverage, buildPinPlan,
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
  assert.equal(frozen(rows), before);
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

// ---- cross-vendor coverage ----------------------------------------------------------------

const tr = (id, cc, opt, verdict) => ({ id, cc, opt, kind: 'erasure', verdict });

test('crossVendorCoverage: found from the tracked rows, reversed from this run, gcc reverses nothing', () => {
  const tracked = [
    tr('a', 'clang-18', '-O2', E), tr('b', 'clang-18', '-O2', E), tr('c', 'clang-18', '-O2', S),
    tr('a', 'gcc-13', '-O2', E), tr('b', 'gcc-13', '-O2', E), tr('c', 'gcc-13', '-O2', E),
    { id: 'x', cc: 'clang-18', opt: '-O2', kind: 'authz', verdict: E },
  ];
  const rows = [retained('a', '-O2'), er('b', '-O2', { baseline: E, outcome: 'PIN_INEFFECTIVE', trackedVerdict: E }), er('c', '-O2')];
  const c = crossVendorCoverage({ tracked, rows, runCc: 'clang-18' });
  assert.deepEqual(c.total, { reversed: 1, found: 5 });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 1/2, gcc-13 0/3 (no plugin can load), total 1/5');
  assert.deepEqual(c.perVendor.map((v) => [v.cc, v.reversed, v.found, v.loadable]), [['clang-18', 1, 2, true], ['gcc-13', 0, 3, false]]);
});

test('crossVendorCoverage: a RETAINED cell whose tracked verdict is not ELIMINATED is not a reversed finding', () => {
  const tracked = [tr('a', 'clang-18', '-O2', S)];
  const rows = [retained('a', '-O2', { trackedVerdict: S })];
  assert.deepEqual(crossVendorCoverage({ tracked, rows, runCc: 'clang-18' }).total, { reversed: 0, found: 0 });
});

test('crossVendorCoverage: restricted to the selected files and levels', () => {
  const tracked = [tr('a', 'clang-18', '-O2', E), tr('a', 'clang-18', '-O3', E), tr('b', 'clang-18', '-O2', E), tr('a', 'gcc-13', '-O3', E)];
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18', ids: new Set(['a']), opts: ['-O2'] });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 0/1, gcc-13 0/0 (no plugin can load), total 0/1');
});

test('crossVendorCoverage: the run vendor is listed even without tracked rows, and another clang is "not run"', () => {
  const tracked = [tr('a', 'clang-17', '-O2', E)];
  const c = crossVendorCoverage({ tracked, rows: [], runCc: 'clang-18' });
  assert.equal(c.line, 'eliminations reversed / found: clang-18 0/0, clang-17 0/1 (not run), total 0/1');
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
