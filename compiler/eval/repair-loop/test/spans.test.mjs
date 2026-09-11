/**
 * The per-span view. Verdicts are injected: nothing here compiles. The shapes are
 * the two measured ones the cell verdict hides -- a wipe on an error path plus a
 * trailing wipe, and an initialising memset plus a trailing wipe -- and the
 * one-span case, which must not be recompiled.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { spanPlan, spanSourceOf, spanRows, hiddenFlags, SPAN_SOURCES } from '../lib/spans.mjs';
import { gradeRedControl } from '../lib/outcome.mjs';

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';
const v = (verdict) => ({ verdict, control: 'PRESENT', control_via: 'oracle' });

test('spanPlan: one span is the cell itself, and is never recompiled', () => {
  assert.deepEqual(spanPlan(['removable']), [{ index: 0, kind: 'removable', source: 'cell' }]);
  assert.deepEqual(spanPlan(['nonremovable']), [{ index: 0, kind: 'nonremovable', source: 'cell' }]);
  assert.equal(spanSourceOf(spanPlan(['removable'])), 'cell');
});

test('spanPlan: with two or more spans, removable spans are measured and nonremovable ones are listed, not measured', () => {
  const p = spanPlan(['removable', 'nonremovable', 'removable']);
  assert.deepEqual(p.map((x) => x.source), ['span', 'not-measured', 'span']);
  assert.deepEqual(p.map((x) => x.index), [0, 1, 2]);
  assert.equal(spanSourceOf(p), 'span');
  // a volatile-pointer declaration and its loop: both nonremovable, neither ablated alone
  assert.deepEqual(spanPlan(['nonremovable', 'nonremovable']).map((x) => x.source), ['not-measured', 'not-measured']);
  for (const x of p) assert.ok(SPAN_SOURCES.includes(x.source));
});

test('spanPlan: no spans, no plan', () => {
  assert.deepEqual(spanPlan([]), []);
  assert.deepEqual(spanPlan(undefined), []);
  assert.equal(spanSourceOf([]), null);
});

test('spanRows: a one-span cell carries the cell verdicts, marked as such', () => {
  const rows = spanRows(spanPlan(['removable']), { baseline: v(E), repaired: v(S) });
  assert.deepEqual(rows, [{ index: 0, kind: 'removable', off: E, on: S, source: 'cell', recordOk: null }]);
});

test('spanRows: verdict strings only, and a span nobody measured is MISSING, never a WIPE_ verdict', () => {
  const plan = spanPlan(['removable', 'removable', 'nonremovable']);
  const rows = spanRows(plan, { baseline: v(S), repaired: v(S), measured: { 0: { off: v(S), on: v(S), recordOk: true } } });
  assert.deepEqual(rows[0], { index: 0, kind: 'removable', off: S, on: S, source: 'span', recordOk: true });
  assert.deepEqual(rows[1], { index: 1, kind: 'removable', off: 'MISSING', on: 'MISSING', source: 'span', recordOk: null });
  assert.deepEqual(rows[2], { index: 2, kind: 'nonremovable', off: null, on: null, source: 'not-measured', recordOk: null });
  for (const r of rows) for (const k of ['off', 'on']) assert.ok(r[k] === null || typeof r[k] === 'string');
});

// The error-path shape: two memsets of the same buffer, one in the error branch,
// one at the end. Deleting both changes the loop layout, so the cell reads
// SURVIVED; deleting only the trailing one changes nothing: it was already gone.
const errorPath = (on1) => spanRows(spanPlan(['removable', 'removable']), {
  baseline: v(S), repaired: v(S),
  measured: { 0: { off: v(S), on: v(S), recordOk: true }, 1: { off: v(E), on: v(on1), recordOk: true } },
});

test('hiddenFlags: a SURVIVED cell with an individually eliminated removable span is a hidden elimination', () => {
  assert.deepEqual(hiddenFlags(v(S), errorPath(S)), { hiddenElimination: true, hiddenRetained: true });
  assert.deepEqual(hiddenFlags(v(S), errorPath(E)), { hiddenElimination: true, hiddenRetained: false });
  assert.deepEqual(hiddenFlags(S, errorPath(S)), { hiddenElimination: true, hiddenRetained: true });
});

test('hiddenFlags: retained means EVERY individually eliminated span survives with the plugin', () => {
  const spans = spanRows(spanPlan(['removable', 'removable', 'removable']), {
    baseline: v(S), repaired: v(S),
    measured: { 0: { off: v(E), on: v(S) }, 1: { off: v(S), on: v(S) }, 2: { off: v(E), on: v('NOT_OBSERVED') } },
  });
  assert.deepEqual(hiddenFlags(v(S), spans), { hiddenElimination: true, hiddenRetained: false });
});

test('hiddenFlags: never on an ELIMINATED or unscorable cell, never from a nonremovable span, never from a one-span cell', () => {
  // the cell already says ELIMINATED: nothing is hidden
  assert.deepEqual(hiddenFlags(v(E), errorPath(S)), { hiddenElimination: false, hiddenRetained: false });
  assert.deepEqual(hiddenFlags(v('ABLATION_DID_NOT_COMPILE'), errorPath(S)), { hiddenElimination: false, hiddenRetained: false });
  // an eliminated nonremovable span does not count
  const nonrem = [{ index: 0, kind: 'nonremovable', off: E, on: E, source: 'span', recordOk: true }];
  assert.deepEqual(hiddenFlags(v(S), nonrem), { hiddenElimination: false, hiddenRetained: false });
  // one span: its verdict IS the cell's, so a SURVIVED cell cannot hide an elimination
  const one = spanRows(spanPlan(['removable']), { baseline: v(S), repaired: v(S) });
  assert.deepEqual(hiddenFlags(v(S), one), { hiddenElimination: false, hiddenRetained: false });
  // MISSING is not ELIMINATED
  const missing = spanRows(spanPlan(['removable', 'removable']), { baseline: v(S), repaired: v(S), measured: {} });
  assert.deepEqual(hiddenFlags(v(S), missing), { hiddenElimination: false, hiddenRetained: false });
  assert.deepEqual(hiddenFlags(v(S), undefined), { hiddenElimination: false, hiddenRetained: false });
});

test('the initialiser-plus-wipe shape: the initialiser survives alone, the wipe does not', () => {
  // span 0: a memset before the buffer is filled (needed; deleting it changes code)
  // span 1: the trailing wipe (dead; deleting it changes nothing)
  const spans = spanRows(spanPlan(['removable', 'removable']), {
    baseline: v(S), repaired: v(S),
    measured: { 0: { off: v(S), on: v(S) }, 1: { off: v(E), on: v(S) } },
  });
  const h = hiddenFlags(v(S), spans);
  assert.equal(h.hiddenElimination, true);
  assert.equal(h.hiddenRetained, true);
});

// ---- the dry-run red control grades hiddenRetained --------------------------------

const row = (id, extra) => ({ id, opt: '-O2', kind: 'erasure', baseline: S, outcome: 'ALREADY_SURVIVED', ...extra });

test('gradeRedControl --dry-run: a hiddenRetained anywhere is a violation', () => {
  const ok = [row('a', { hiddenElimination: true, hiddenRetained: false }), row('b', { hiddenElimination: false, hiddenRetained: false })];
  const g = gradeRedControl(ok, { dryRun: true });
  assert.equal(g.held, true, JSON.stringify(g.violations));
  assert.match(g.expected, /no hiddenRetained/);
  const bad = gradeRedControl([...ok, row('c', { hiddenElimination: true, hiddenRetained: true })], { dryRun: true });
  assert.equal(bad.held, false);
  assert.deepEqual(bad.violations, ['c -O2: hiddenRetained']);
});

test('gradeRedControl: hiddenRetained is not graded outside a dry run', () => {
  const rows = [{ id: 'c', opt: '-O2', kind: 'erasure', baseline: S, outcome: 'BROKEN_REPAIR', hiddenElimination: true, hiddenRetained: true }];
  assert.equal(gradeRedControl(rows, { targetSuffix: '__absent' }).held, true);
  assert.equal(gradeRedControl(rows, {}), null);
});
