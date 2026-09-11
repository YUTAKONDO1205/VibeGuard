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
  crossCheckRepairRows, crossCheckSummary, spansMeasuredAlone, parseRepairRowsArg, REPAIR_ROWS_FILES,
  hiddenSummary, undercountLine, labelSummary, writeDataProblems, pathHits, VENDORS, ALL_OPTS,
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

const repairRow = (id, opt, spans, hiddenElimination, cc = 'clang-18') => ({ id, kind: 'erasure', cc, opt, spans, hiddenElimination });
const rs = (index, off, source = 'span', kind = 'removable') => ({ index, kind, off, on: S, source, recordOk: true });

test('REPAIR_ROWS_FILES: one file per vendor, named as the repair loop names them', () => {
  assert.deepEqual(Object.keys(REPAIR_ROWS_FILES).sort(), [...VENDORS].sort());
  // repair-loop/lib/vendor.mjs dataFileNames: clang-18 keeps the first name, any other compiler gets its own
  assert.equal(REPAIR_ROWS_FILES['clang-18'], '../../repair-loop/data/r2-repair-rows.json');
  assert.equal(REPAIR_ROWS_FILES['gcc-13'], '../../repair-loop/data/r2-repair-rows-gcc-13.json');
  for (const p of Object.values(REPAIR_ROWS_FILES)) assert.deepEqual(pathHits(p), []);
});

test('crossCheckRepairRows: agreement where the repair loop measured the span alone, per vendor', () => {
  const ours = [errorPathRow('clang-18', '-O2', E), errorPathRow('gcc-13', '-O2', E)];
  const theirs = [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true)];
  const c = crossCheckRepairRows(ours, theirs, 'clang-18');
  assert.equal(c.cc, 'clang-18');
  assert.equal(c.compared, 2);
  assert.equal(c.agreed, 2);
  assert.equal(c.notCompared, 0);
  assert.deepEqual(c.mismatches, []);
  assert.equal(c.hiddenCompared, 1);
  assert.deepEqual(c.hiddenMismatches, []);
  assert.deepEqual(c.ids, []);
  // gcc-13 is checked the same way, against gcc-13 repair rows
  const g = crossCheckRepairRows(ours, [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true, 'gcc-13')], 'gcc-13');
  assert.deepEqual([g.cc, g.compared, g.agreed, g.hiddenCompared, g.mismatches.length], ['gcc-13', 2, 2, 1, 0]);
  assert.throws(() => crossCheckRepairRows(ours, theirs, 'gcc'), /not one of/);
});

test('crossCheckRepairRows: a shifted index is a mismatch, and the ids are listed', () => {
  const ours = [errorPathRow('clang-18', '-O2', E)];
  // the repair rows' span indices shifted by one: span 1's verdict sits at index 0
  const shifted = [repairRow('fable_N_token_r3', '-O2', [rs(0, E), rs(1, S)], true)];
  const c = crossCheckRepairRows(ours, shifted, 'clang-18');
  assert.equal(c.compared, 2);
  assert.equal(c.agreed, 0);
  assert.deepEqual(c.mismatches.map((m) => [m.id, m.opt, m.index, m.ours, m.theirs]),
    [['fable_N_token_r3', '-O2', 0, S, E], ['fable_N_token_r3', '-O2', 1, E, S]]);
  assert.deepEqual(c.ids, ['fable_N_token_r3']);
  // the same shift in gcc-13's repair rows fails gcc-13's check
  const g = crossCheckRepairRows([errorPathRow('gcc-13', '-O2', E)],
    [repairRow('fable_N_token_r3', '-O2', [rs(0, E), rs(1, S)], true, 'gcc-13')], 'gcc-13');
  assert.equal(g.mismatches.length, 2);
});

test('crossCheckRepairRows: spans the repair loop did not measure alone are not compared, never agreed', () => {
  const ours = [errorPathRow('clang-18', '-O2', E)];
  const c1 = crossCheckRepairRows(ours, [repairRow('fable_N_token_r3', '-O2', [rs(0, S, 'cell'), rs(1, null, 'not-measured')], false)], 'clang-18');
  assert.equal(c1.compared, 0);
  assert.equal(c1.notCompared, 2);
  assert.deepEqual(c1.hiddenMismatches.map((m) => m.id), ['fable_N_token_r3']);
  const c2 = crossCheckRepairRows(ours, [], 'clang-18');
  assert.equal(c2.compared, 0);
  assert.equal(c2.notCompared, 2);
  assert.equal(c2.hiddenCompared, 0);
  // one vendor's repair rows never judge the other vendor's rows, either way round
  const c3 = crossCheckRepairRows([errorPathRow('gcc-13', '-O2', E)], [repairRow('fable_N_token_r3', '-O2', [rs(0, E), rs(1, S)], true)], 'gcc-13');
  assert.deepEqual([c3.compared, c3.notCompared, c3.hiddenCompared], [0, 2, 0]);
  const c4 = crossCheckRepairRows([errorPathRow('gcc-13', '-O2', E)], [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true, 'gcc-13')], 'clang-18');
  assert.equal(c4.compared + c4.notCompared + c4.hiddenCompared, 0);
});

test('crossCheckSummary: a vendor without repair rows is not cross-checked, and never held', () => {
  const ours = [errorPathRow('clang-18', '-O2', E), errorPathRow('gcc-13', '-O2', E)];
  const measured = { 'clang-18': spansMeasuredAlone(ours, 'clang-18'), 'gcc-13': spansMeasuredAlone(ours, 'gcc-13') };
  assert.deepEqual(measured, { 'clang-18': 2, 'gcc-13': 2 });
  const clang = crossCheckRepairRows(ours, [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true)], 'clang-18');
  const s = crossCheckSummary({ 'clang-18': clang, 'gcc-13': null }, measured);
  assert.deepEqual(s.held, ['clang-18']);
  assert.deepEqual(s.failed, []);
  assert.deepEqual(s.notChecked, ['gcc-13']);
  assert.deepEqual(s.vendors.map((v) => [v.cc, v.status]), [['clang-18', 'held'], ['gcc-13', 'not-cross-checked']]);
  // both files: both held
  const gcc = crossCheckRepairRows(ours, [repairRow('fable_N_token_r3', '-O2', [rs(0, S), rs(1, E)], true, 'gcc-13')], 'gcc-13');
  assert.deepEqual(crossCheckSummary({ 'clang-18': clang, 'gcc-13': gcc }, measured).held, ['clang-18', 'gcc-13']);
  // a file that compares nothing while that vendor measured spans alone is vacuous, and fails
  const empty = crossCheckRepairRows(ours, [], 'gcc-13');
  const v = crossCheckSummary({ 'clang-18': clang, 'gcc-13': empty }, measured);
  assert.deepEqual(v.failed, ['gcc-13']);
  assert.equal(v.vendors[1].vacuous, true);
  // a vendor not in the run does not appear at all
  assert.deepEqual(crossCheckSummary({ 'clang-18': clang }, measured).vendors.map((x) => x.cc), ['clang-18']);
});

test('parseRepairRowsArg: <cc>=<path> per vendor; a bare path or an unknown vendor is refused', () => {
  assert.deepEqual(parseRepairRowsArg('gcc-13=lab/g.json,clang-18=lab/c.json'),
    { given: { 'gcc-13': 'lab/g.json', 'clang-18': 'lab/c.json' }, problems: [] });
  assert.deepEqual(parseRepairRowsArg('lab/c.json').problems, ['lab/c.json: expected <cc>=<path>']);
  assert.deepEqual(parseRepairRowsArg('gcc=lab/g.json').problems, ['gcc is not one of clang-18 gcc-13']);
  assert.deepEqual(parseRepairRowsArg('gcc-13=a,gcc-13=b').problems, ['gcc-13 given twice']);
  assert.deepEqual(parseRepairRowsArg('gcc-13=').problems, ['gcc-13=: expected <cc>=<path>']);
  assert.deepEqual(parseRepairRowsArg('').problems, ['no <cc>=<path> given']);
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

test('writeDataProblems: only the full run, checked for every vendor, may be written', () => {
  const full = { files: null, vendors: [...VENDORS], opts: [...ALL_OPTS], rowsIsDefault: true, repairRowsIsDefault: true,
    integrity: [], crossCheck: { held: [...VENDORS], failed: [], notChecked: [] } };
  assert.deepEqual(writeDataProblems(full), []);
  assert.deepEqual(writeDataProblems({ ...full, crossCheck: null }), []);
  assert.deepEqual(writeDataProblems({ ...full, files: ['a*'] }), ['--files']);
  assert.deepEqual(writeDataProblems({ ...full, vendors: ['gcc-13'] }), ['a partial --cc']);
  assert.deepEqual(writeDataProblems({ ...full, opts: ['-O2'] }), ['a partial --opts']);
  assert.deepEqual(writeDataProblems({ ...full, repairRowsIsDefault: false }), ['--repair-rows']);
  assert.deepEqual(writeDataProblems({ ...full, integrity: ['x'] }), ['1 integrity problem(s)']);
  assert.deepEqual(writeDataProblems({ ...full, crossCheck: { held: ['clang-18'], failed: ['gcc-13'], notChecked: [] } }),
    ['a failed cross-check (gcc-13)']);
  assert.deepEqual(writeDataProblems({ ...full, crossCheck: { held: ['clang-18'], failed: [], notChecked: ['gcc-13'] } }),
    ['no repair rows to cross-check gcc-13']);
});

test('pathHits: the shapes of a home directory, a mount and a drive letter', () => {
  assert.deepEqual(pathHits('{"id":"a","verdict":"WIPE_SURVIVED"}'), []);
  for (const t of ['/home/u/x', '/root/vg-lab', '/mnt/c/x', '/Users/x', 'C:\\Users\\x', 'C:/x']) assert.ok(pathHits(t).length, t);
});
