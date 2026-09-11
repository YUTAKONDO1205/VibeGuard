/**
 * Tests for lib/span-summary.mjs. Rows are built in code; nothing compiles.
 *
 * The shapes are the two the per-span supplement exists for: an error-path wipe
 * plus a trailing wipe, and an initialiser plus a trailing wipe. In both the cell
 * reads WIPE_SURVIVED and the trailing wipe, ablated alone, reads
 * WIPE_ELIMINATED.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { spanPlan } from '../lib/ablation-cell.mjs';
import {
  ELIMINATED, SURVIVED, multiSpanFiles, trackedVerdicts, hiddenOf, spanRow, integrityProblems,
  crossCheckRepairRows, hiddenSummary, undercountLine, labelSummary, writeDataProblems, pathHits, VENDORS, ALL_OPTS,
} from '../lib/span-summary.mjs';

const E = ELIMINATED;
const S = SURVIVED;
const v = (verdict) => ({ control: 'PRESENT', control_via: 'oracle', verdict });
const meta = (id) => ({ id, model: id.split('_')[0], framing: id.split('_')[1], scen: id.split('_')[2], fn: 'f' });
const tracked = (id, cc, opt, verdict, nSpans = 2, idiom = 'removable') => ({ id, kind: 'erasure', cc, opt, verdict, n_spans: nSpans, idiom });

test('multiSpanFiles: two or more spans, from the tracked rows, and inconsistent rows are named', () => {
  const rows = [
    tracked('a_N_x_r1', 'clang-18', '-O2', S, 2),
    tracked('a_N_x_r1', 'gcc-13', '-O2', S, 2),
    tracked('b_N_x_r1', 'clang-18', '-O2', E, 1),
    tracked('c_N_x_r1', 'clang-18', '-O2', S, 3, 'both'),
    tracked('d_N_x_r1', 'clang-18', '-O2', S, 2),
    tracked('d_N_x_r1', 'gcc-13', '-O2', S, 3),
    { id: 'e_N_x_r1', kind: 'none', verdict: 'NO_WIPE_WRITTEN' },
    { id: 'f_N_x_r1', kind: 'authz', cc: 'clang-18', opt: '-O2', verdict: 'NDEBUG_NO_EFFECT' },
  ];
  const { files, problems } = multiSpanFiles(rows);
  assert.deepEqual([...files.keys()], ['a_N_x_r1', 'c_N_x_r1', 'd_N_x_r1']);
  assert.deepEqual(files.get('c_N_x_r1'), { nSpans: 3, idiom: 'both' });
  assert.deepEqual(problems, ['d_N_x_r1']);
  assert.equal(trackedVerdicts(rows).get('b_N_x_r1|clang-18|-O2'), E);
});

const errorPathRow = (cc, opt, trailing, trackedVerdict = S, labels = [false, false]) => spanRow({
  meta: meta('fable_N_token_r3'), cc, opt, idiom: 'removable', nSpans: 2, plan: spanPlan(['removable', 'removable']), labels,
  cell: v(S), measured: { 0: v(S), 1: v(trailing) }, trackedVerdict,
});

test('spanRow: verdict words, ids and booleans only, and the label beside the verdict', () => {
  const r = errorPathRow('gcc-13', '-O2', E, S, [true, false]);
  assert.deepEqual(r.spans, [
    { index: 0, kind: 'removable', source: 'span', off: S, initialiserLike: true },
    { index: 1, kind: 'removable', source: 'span', off: E, initialiserLike: false },
  ]);
  assert.equal(r.cellVerdict, S);
  assert.equal(r.cellMatchesTracked, true);
  assert.equal(r.hiddenElimination, true);
  assert.equal(r.measured, true);
  assert.equal(r.control, 'PRESENT');
  const allowed = new Set(['id', 'model', 'framing', 'scen', 'fn', 'kind', 'cc', 'opt', 'idiom', 'n_spans', 'measured',
    'trackedVerdict', 'cellVerdict', 'cellMatchesTracked', 'control', 'spans', 'hiddenElimination']);
  for (const k of Object.keys(r)) assert.ok(allowed.has(k), k);
  assert.deepEqual(pathHits(JSON.stringify(r)), []);
});

test('spanRow: a file with only nonremovable spans is listed, not measured, and never hidden', () => {
  const r = spanRow({ meta: meta('x_S_y_r1'), cc: 'clang-18', opt: '-O2', idiom: 'nonremovable', nSpans: 2,
    plan: spanPlan(['nonremovable', 'nonremovable']), labels: [false, false], trackedVerdict: S });
  assert.equal(r.measured, false);
  assert.equal(r.cellVerdict, null);
  assert.equal(r.cellMatchesTracked, null);
  assert.deepEqual(r.spans.map((s) => [s.source, s.off]), [['not-measured', null], ['not-measured', null]]);
  assert.equal(r.hiddenElimination, false);
  assert.deepEqual(integrityProblems([r]), []);
});

test('hiddenOf: only a SURVIVED cell, only a removable span, only WIPE_ELIMINATED', () => {
  const sp = (kind, off) => ({ index: 0, kind, source: 'span', off });
  assert.equal(hiddenOf(S, [sp('removable', S), sp('removable', E)]), true);
  assert.equal(hiddenOf(v(S), [sp('removable', E)]), true);
  assert.equal(hiddenOf(E, [sp('removable', E)]), false);
  assert.equal(hiddenOf('ABLATION_DID_NOT_COMPILE', [sp('removable', E)]), false);
  assert.equal(hiddenOf(S, [sp('nonremovable', E)]), false);
  assert.equal(hiddenOf(S, [sp('removable', 'MISSING'), sp('removable', 'NOT_OBSERVED')]), false);
  assert.equal(hiddenOf(S, undefined), false);
});

test('integrityProblems: a re-derived cell that disagrees, and a planned span nobody measured', () => {
  const bad = errorPathRow('clang-18', '-O2', E, E);
  assert.deepEqual(integrityProblems([bad]), ['CELL DISAGREES fable_N_token_r3 clang-18 -O2: tracked WIPE_ELIMINATED, re-derived WIPE_SURVIVED']);
  const missing = spanRow({ meta: meta('a_N_x_r1'), cc: 'clang-18', opt: '-O2', idiom: 'removable', nSpans: 2,
    plan: spanPlan(['removable', 'removable']), labels: [null, null], cell: v(S), measured: { 0: v(S) }, trackedVerdict: S });
  assert.deepEqual(integrityProblems([missing]), ['SPAN MISSING a_N_x_r1 clang-18 -O2 span 1']);
  assert.equal(missing.hiddenElimination, false);
});

// ---- the cross-check -----------------------------------------------------------

const repairRow = (id, opt, spans, hiddenElimination) => ({ id, kind: 'erasure', cc: 'clang-18', opt, spans, hiddenElimination });
const rs = (index, off, source = 'span', kind = 'removable') => ({ index, kind, off, on: S, source, recordOk: true });

test('crossCheckRepairRows: agreement where the repair loop measured the span alone', () => {
  const ours = [errorPathRow('clang-18', '-O2', E), errorPathRow('gcc-13', '-O2', E)];
  const theirs = [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true)];
  const c = crossCheckRepairRows(ours, theirs);
  assert.equal(c.compared, 2);
  assert.equal(c.agreed, 2);
  assert.equal(c.notCompared, 0);
  assert.deepEqual(c.mismatches, []);
  assert.equal(c.hiddenCompared, 1);
  assert.deepEqual(c.hiddenMismatches, []);
  assert.deepEqual(c.ids, []);
});

test('crossCheckRepairRows: a shifted index is a mismatch, and the ids are listed', () => {
  const ours = [errorPathRow('clang-18', '-O2', E)];
  // the repair rows' span indices shifted by one: span 1's verdict sits at index 0
  const shifted = [repairRow('fable_N_token_r3', '-O2', [rs(0, E), rs(1, S)], true)];
  const c = crossCheckRepairRows(ours, shifted);
  assert.equal(c.compared, 2);
  assert.equal(c.agreed, 0);
  assert.deepEqual(c.mismatches.map((m) => [m.id, m.opt, m.index, m.ours, m.theirs]),
    [['fable_N_token_r3', '-O2', 0, S, E], ['fable_N_token_r3', '-O2', 1, E, S]]);
  assert.deepEqual(c.ids, ['fable_N_token_r3']);
});

test('crossCheckRepairRows: spans the repair loop did not measure alone are not compared, never agreed', () => {
  const ours = [errorPathRow('clang-18', '-O2', E)];
  const c1 = crossCheckRepairRows(ours, [repairRow('fable_N_token_r3', '-O2', [rs(0, S, 'cell'), rs(1, null, 'not-measured')], false)]);
  assert.equal(c1.compared, 0);
  assert.equal(c1.notCompared, 2);
  assert.deepEqual(c1.hiddenMismatches.map((m) => m.id), ['fable_N_token_r3']);
  const c2 = crossCheckRepairRows(ours, []);
  assert.equal(c2.compared, 0);
  assert.equal(c2.notCompared, 2);
  assert.equal(c2.hiddenCompared, 0);
  // gcc rows and repair rows of another vendor never enter
  const c3 = crossCheckRepairRows([errorPathRow('gcc-13', '-O2', E)], [{ ...repairRow('fable_N_token_r3', '-O2', [rs(0, E)], true), cc: 'gcc-13' }]);
  assert.equal(c3.compared + c3.notCompared, 0);
});

// ---- the summary ----------------------------------------------------------------

test('hiddenSummary and undercountLine: hidden cells with ids, beside the tracked cell-level count', () => {
  const trackedRows = [
    tracked('a_N_x_r1', 'gcc-13', '-O2', E, 1), tracked('b_N_x_r1', 'gcc-13', '-O2', E, 1),
    tracked('fable_N_token_r3', 'gcc-13', '-O2', S), tracked('c_N_x_r1', 'gcc-13', '-O2', S),
    tracked('a_N_x_r1', 'clang-18', '-O2', E, 1),
  ];
  const rows = [
    errorPathRow('gcc-13', '-O2', E, S, [true, false]),
    spanRow({ meta: meta('c_N_x_r1'), cc: 'gcc-13', opt: '-O2', idiom: 'removable', nSpans: 2,
      plan: spanPlan(['removable', 'removable']), labels: [false, false], cell: v(S), measured: { 0: v(S), 1: v(S) }, trackedVerdict: S }),
  ];
  const [h] = hiddenSummary(trackedRows, rows, { vendors: ['gcc-13'], opts: ['-O2'] });
  assert.equal(h.trackedEliminated, 2);
  assert.equal(h.hidden, 1);
  assert.equal(h.withHidden, 3);
  assert.equal(h.survivedCells, 2);
  assert.deepEqual(h.hiddenByIdiom, { removable: 1 });
  assert.deepEqual(h.hiddenIds, [{ id: 'fable_N_token_r3', idiom: 'removable', spans: [1], eliminatedInitialiserLike: [], initialiserLikeElsewhere: true }]);
  assert.equal(h.hiddenOnlyInitialiserLike, 0);
  // the eliminated span itself initialiser-like: a removed initialiser, counted apart
  const initOnly = hiddenSummary(trackedRows, [errorPathRow('gcc-13', '-O2', E, S, [false, true])], { vendors: ['gcc-13'], opts: ['-O2'] })[0];
  assert.equal(initOnly.hiddenOnlyInitialiserLike, 1);
  assert.deepEqual(initOnly.hiddenIds[0].eliminatedInitialiserLike, [1]);
  assert.equal(undercountLine(h), 'gcc-13 -O2  cell-level eliminated 2   cell-level eliminated + hidden 3  (+1 over 2 measured multi-span cells)');
  // a (cc, opt) with no rows is not printed as a zero
  assert.deepEqual(hiddenSummary(trackedRows, rows, { vendors: ['clang-18'], opts: ['-O2'] }), []);
});

test('labelSummary: counts per kind and label, and one-span files whose only span is initialiser-like', () => {
  const s = labelSummary([
    { id: 'opus_N_pinpad_r2', kinds: ['removable'], labels: [true] },
    { id: 'x_N_y_r1', kinds: ['removable'], labels: [false] },
    { id: 'z_N_y_r1', kinds: ['removable', 'nonremovable'], labels: [true, null] },
  ]);
  assert.deepEqual(s.oneSpanInit, ['opus_N_pinpad_r2']);
  assert.deepEqual(s.counts, { 'removable:true': 2, 'removable:false': 1, 'nonremovable:null': 1 });
  assert.equal(s.spans, 4);
});

test('writeDataProblems: only the full, checked run may be written', () => {
  const full = { files: null, vendors: [...VENDORS], opts: [...ALL_OPTS], rowsIsDefault: true, repairRowsIsDefault: true,
    integrity: [], crossCheck: { mismatches: [], hiddenMismatches: [] } };
  assert.deepEqual(writeDataProblems(full), []);
  assert.deepEqual(writeDataProblems({ ...full, files: ['a*'] }), ['--files']);
  assert.deepEqual(writeDataProblems({ ...full, vendors: ['gcc-13'] }), ['a partial --cc']);
  assert.deepEqual(writeDataProblems({ ...full, opts: ['-O2'] }), ['a partial --opts']);
  assert.deepEqual(writeDataProblems({ ...full, repairRowsIsDefault: false }), ['--repair-rows']);
  assert.deepEqual(writeDataProblems({ ...full, integrity: ['x'] }), ['1 integrity problem(s)']);
  assert.deepEqual(writeDataProblems({ ...full, crossCheck: { mismatches: [{}], hiddenMismatches: [] } }), ['a failed cross-check']);
});

test('pathHits: the shapes of a home directory, a mount and a drive letter', () => {
  assert.deepEqual(pathHits('{"id":"a","verdict":"WIPE_SURVIVED"}'), []);
  for (const t of ['/home/u/x', '/root/vg-lab', '/mnt/c/x', '/Users/x', 'C:\\Users\\x', 'C:/x']) assert.ok(pathHits(t).length, t);
});
