/**
 * What --write-data refuses, as a unit.
 *
 * This test exists because the lane's prose was ahead of its code. Until
 * 2026-09-12, `--write-data` refused `--controls-only` and nothing else, while
 * test/data.test.mjs asserted "--write-data is refused for a partial matrix, so
 * an excluded cell here is a bug". A `--opt -O0 --write-data` run wrote twelve
 * cells over the sixty-cell record and exited 0, and a run with no repair
 * plugin wrote a record in which the whole repair arm was plugin-absent.
 *
 * The refusal is a pure function so the refusals can be tested without a
 * compiler, a plugin or a ptrace stop, the way ../../spike/lib/data-record.mjs
 * and ../../oracle-agreement/lib/record.mjs are.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { writeDataRefusals } from '../lib/grade.mjs';
import { VENDORS, OPTS, IDIOMS, ARMS } from '../lib/manifest.mjs';

/** A full matrix of graded subject rows: the only shape that may be written. */
function fullRows({ measurement = 'OK', reason = null } = {}) {
  const rows = [];
  for (const arm of ARMS) {
    for (const cc of VENDORS) {
      for (const opt of OPTS) {
        for (const idiom of IDIOMS) {
          rows.push({ kind: 'subject', cell: `${arm}/${cc}/${opt}/${idiom}`, arm, cc, opt, subject: idiom, measurement, reason });
        }
      }
    }
  }
  return rows;
}

const full = { ccs: [...VENDORS], opts: [...OPTS], idioms: [...IDIOMS], controlsOnly: false, rows: fullRows() };

test('a full matrix with every cell measured may be written', () => {
  assert.deepEqual(writeDataRefusals(full), []);
});

test('a subset of any axis is refused, and the refusal names what is missing', () => {
  const oneLevel = writeDataRefusals({ ...full, opts: ['-O0'], rows: fullRows().filter((r) => r.opt === '-O0') });
  assert.ok(oneLevel.length >= 2, oneLevel.join(' | '));
  assert.ok(oneLevel.some((w) => w.includes('--opt') && w.includes('-O2')), oneLevel.join(' | '));
  assert.ok(oneLevel.some((w) => /subject cell\(s\) were graded/.test(w)), oneLevel.join(' | '));

  assert.ok(writeDataRefusals({ ...full, ccs: ['clang-18'] }).some((w) => w.includes('--cc') && w.includes('gcc-13')));
  assert.ok(writeDataRefusals({ ...full, idioms: ['memset'] }).some((w) => w.includes('--idiom')));
});

test('a controls-only run is refused, with the reason it always had', () => {
  const why = writeDataRefusals({ ...full, controlsOnly: true });
  assert.ok(why.some((w) => w.includes('--controls-only')), why.join(' | '));
});

test('a cell that carries no reading is refused, and plugin-absent is the case that matters', () => {
  const rows = fullRows();
  for (const r of rows) if (r.arm === 'wipepin') { r.measurement = 'BROKEN_MEASUREMENT'; r.reason = 'plugin-absent'; }
  const why = writeDataRefusals({ ...full, rows });
  assert.ok(why.some((w) => w.includes('plugin-absent')), why.join(' | '));
  assert.ok(why.some((w) => /30 subject cell\(s\) carry no reading/.test(w)), why.join(' | '));
});

test('every reason is collected, not just the first one reached', () => {
  const why = writeDataRefusals({ ccs: ['clang-18'], opts: ['-O0'], idioms: ['memset'], controlsOnly: true, rows: [] });
  assert.ok(why.length >= 5, `expected every axis plus the cell count and the controls-only reason: ${why.join(' | ')}`);
});

test('controls are not counted as subject cells', () => {
  // A run whose controls make up the shortfall is still a partial matrix, and
  // counting them would let one through.
  const rows = fullRows().filter((r) => r.opt !== '-Os');
  for (let i = 0; i < 12; i++) rows.push({ kind: 'control', cell: `control-${i}`, measurement: 'OK' });
  const why = writeDataRefusals({ ...full, rows });
  assert.ok(why.some((w) => /48 subject cell\(s\) were graded/.test(w)), why.join(' | '));
});
