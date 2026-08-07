// The counting contract, both directions.
//
// Positive: a run with nothing in it is refused. Negative: a run with something
// in it is not. A test suite that only had the first would be satisfied by a
// module that returned exit 3 for everything.

import { strict as assert } from 'node:assert';
import test from 'node:test';

import { countingLine, settleCounts, EXIT_INCOMPLETE } from '../counting.mjs';

test('the line has the shape every entry point prints', () => {
  assert.equal(countingLine({ inputs: 3, checked: 2, skipped: 1 }), 'inputs=3 checked=2 skipped=1');
});

test('nought inputs is not success', () => {
  const r = settleCounts({ inputs: 0, checked: 0, skipped: 0, what: 'record' });
  assert.equal(r.empty, true);
  assert.equal(r.code, EXIT_INCOMPLETE);
  assert.match(r.problems.join(' '), /no record was examined/);
});

test('nought inputs is success when --allow-empty said so', () => {
  const r = settleCounts({ inputs: 0, checked: 0, skipped: 0, allowEmpty: true, what: 'record' });
  assert.equal(r.empty, false);
  assert.equal(r.code, null);
});

test('a run that skipped everything is not success either', () => {
  const r = settleCounts({ inputs: 10, checked: 0, skipped: 10, what: 'file' });
  assert.equal(r.empty, true);
  assert.equal(r.code, EXIT_INCOMPLETE);
  assert.match(r.problems.join(' '), /every one of the 10 file\(s\)/);
});

test('a run that checked something is success as far as the contract goes', () => {
  const r = settleCounts({ inputs: 10, checked: 9, skipped: 1, what: 'file' });
  assert.equal(r.empty, false);
  assert.equal(r.code, null);
  assert.deepEqual(r.problems, []);
});

test('counts that do not add up are refused even when work was done', () => {
  const r = settleCounts({ inputs: 10, checked: 3, skipped: 0, what: 'file' });
  assert.equal(r.code, EXIT_INCOMPLETE);
  assert.match(r.problems.join(' '), /7 file\(s\) are unaccounted for/);
});

test('a negative or fractional count is refused rather than reasoned about', () => {
  assert.equal(settleCounts({ inputs: -1, checked: 0, skipped: 0 }).code, EXIT_INCOMPLETE);
  assert.equal(settleCounts({ inputs: 1.5, checked: 1.5, skipped: 0 }).code, EXIT_INCOMPLETE);
});

test('--allow-empty does not excuse counts that do not add up', () => {
  const r = settleCounts({ inputs: 10, checked: 3, skipped: 0, allowEmpty: true });
  assert.equal(r.code, EXIT_INCOMPLETE);
});
