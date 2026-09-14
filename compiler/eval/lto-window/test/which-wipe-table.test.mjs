// The which-wipe table: the prose and the tracked numbers, held together.
//
// WHY THIS FILE EXISTS
//
// README.md prints a four-column table of fill bytes and calls one of its rows
// the answer to "you only saw it because of the intervention". Until
// data/which-wipe-survived.json existed, those integers lived ONLY in that
// table: nothing read them, nothing re-measured them, and a later edit to the
// prose -- or a later run that disagreed -- would have left no trace. This lane
// has been here before: record.test.mjs exists partly because a by-hand
// disassembly count in this same README was wrong by 13 and nothing in the tree
// noticed.
//
// So the numbers are tracked, and this file is the joint:
//
//   the README's table  ==  data/which-wipe-survived.json   (here)
//   the tracked row     ==  a rebuild of that row           (tools/check-which-wipe-plumbing.mjs, needs a compiler)
//
// The second half is what makes the first half worth having. This file cannot
// tell whether the numbers are TRUE -- both sides would move together if
// somebody edited both -- it can only make the prose and the record inseparable,
// so that a disagreement with the measurement has exactly one place to show up.
// The data file says as much in its own `provenance`.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { WHICH_WIPE, whichWipeSurvived } from '../lib/record.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const README = readFileSync(join(HERE, '..', 'README.md'), 'utf8');
const TABLE_PATH = join(HERE, '..', 'data', 'which-wipe-survived.json');
const TABLE = JSON.parse(readFileSync(TABLE_PATH, 'utf8'));

const plain = (cell) => cell.replaceAll('*', '').replaceAll('`', '').trim();

/** The README's fill table, as {label: [cell, cell, ...]} plus its header levels. */
function readmeTable() {
  const lines = README.split('\n');
  const head = lines.findIndex((l) => l.startsWith('| fill in `main` (bytes) |'));
  assert.ok(head >= 0, 'the README no longer prints the which-wipe fill table; the tracked numbers now describe nothing');
  const cells = (l) => l.split('|').slice(1, -1).map(plain);
  const levels = cells(lines[head]).slice(1);
  const rows = new Map();
  for (let i = head + 2; i < lines.length && lines[i].startsWith('|'); i++) {
    const c = cells(lines[i]);
    // `same` repeats the cell to its left, which is how the README writes the
    // three levels that read alike. Expand it rather than special-casing it in
    // every comparison below.
    for (let k = 1; k < c.length; k++) if (c[k] === 'same') c[k] = c[k - 1];
    rows.set(c[0], c.slice(1));
  }
  return { levels, rows };
}

const KEYS = { 'as written': 'asWritten', "subject's wipe deleted from the source": 'subjectWipeDeleted', "control's wipe deleted from the source": 'controlWipeDeleted' };

test('the tracked file is a record, not a machine transcript', () => {
  const text = readFileSync(TABLE_PATH, 'utf8');
  assert.deepEqual(absolutePathHits(text), [], 'the record carries an absolute path');
  assert.ok(TABLE.provenance.kind, 'a record with no provenance is a number with no origin');
  assert.match(TABLE.provenance.note, /NOT re-measured/, 'the record must say what this test can and cannot establish');
  for (const row of TABLE.rows) {
    for (const [k, v] of Object.entries(row.fillBytes)) {
      assert.equal(Number.isInteger(v) && v >= 0, true, `${row.fixture}${row.optLevel}.${k} is not a non-negative integer`);
    }
    assert.ok(Object.hasOwn(WHICH_WIPE, row.reading), `${row.reading} is not one of WHICH_WIPE`);
  }
});

test("each tracked row's word is the word the grader gives for that row's numbers", () => {
  // A transcription error on either side shows up here: the three integers are
  // re-graded through the same function the tool uses, and the recorded word
  // has to be what comes back. This is the one thing this file can check about
  // the numbers themselves without a compiler.
  for (const row of TABLE.rows) {
    const graded = whichWipeSurvived({
      asWritten: row.fillBytes.asWritten,
      subjectCut: row.fillBytes.subjectWipeDeleted,
      controlCut: row.fillBytes.controlWipeDeleted,
    });
    assert.equal(graded.reading, WHICH_WIPE[row.reading], `${row.fixture} at ${row.optLevel}`);
    // `instrumentReads` is what tools/check-which-wipe-plumbing.mjs refuses on,
    // so it may not disagree with the word.
    assert.equal(row.instrumentReads, graded.reading !== WHICH_WIPE.BLIND, `${row.fixture} at ${row.optLevel}: instrumentReads`);
  }
});

test('the README table and the tracked rows are the same numbers', () => {
  const { levels, rows } = readmeTable();
  const tracked = TABLE.rows.filter((r) => r.fixture === 'xtu-inline');
  assert.deepEqual(levels, tracked.map((r) => r.optLevel), 'the table and the record cover different levels');
  for (const [label, field] of Object.entries(KEYS)) {
    const printed = rows.get(label);
    assert.ok(printed, `the README table has no "${label}" row`);
    assert.deepEqual(
      printed.map(Number), tracked.map((r) => r.fillBytes[field]),
      `the README's "${label}" row and data/which-wipe-survived.json disagree`,
    );
  }
});

test("the README's reading row names the same words as the tracked rows", () => {
  const { rows } = readmeTable();
  const printed = rows.get('reading');
  assert.ok(printed, 'the README table has no "reading" row');
  const tracked = TABLE.rows.filter((r) => r.fixture === 'xtu-inline');
  assert.equal(printed.length, tracked.length);
  printed.forEach((cell, i) => {
    const word = WHICH_WIPE[tracked[i].reading];
    // the README abbreviates the long words to their first clause; a prefix is
    // what it may do, a different word is not.
    assert.ok(cell === tracked[i].reading || word.startsWith(cell),
      `the README reads "${cell}" at ${tracked[i].optLevel}, the record reads ${tracked[i].reading}`);
  });
});

test("the README's sentence about the intervened family is the tracked xtu row", () => {
  // "asked at `wipe_kept` at -O2, the numbers are 32 / 32 / 0" -- prose, and the
  // only other place this lane states a which-wipe measurement.
  const flat = README.replaceAll('\n', ' ');
  const m = flat.match(/asked at `(\w+)` at (-O\w+), the numbers are (\d+) \/ (\d+) \/ (\d+)/);
  assert.ok(m, 'the README no longer states the xtu family\'s three numbers in the form the record pins');
  const row = TABLE.rows.find((r) => r.fixture === 'xtu' && r.optLevel === m[2]);
  assert.ok(row, `nothing tracked for the xtu family at ${m[2]}`);
  assert.equal(m[1], row.caller);
  assert.deepEqual(
    [Number(m[3]), Number(m[4]), Number(m[5])],
    [row.fillBytes.asWritten, row.fillBytes.subjectWipeDeleted, row.fillBytes.controlWipeDeleted],
  );
});

test('the README does not hard-code how many tests this lane has', () => {
  // A rotting fact (rule 9). It said `107 tests, 0 failures` beside the
  // command and `107 tests, no compiler required` in the file list, and both
  // were true on the morning of 2026-09-14 and false by the afternoon: the
  // wave that wrote this test added two test files. A number nobody recounts
  // is a number that is wrong between commits, and it is wrong in the
  // direction that makes a reader trust a suite they have not run.
  const counts = README.split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /\b\d+\s+(tests|test files|test cases|assertions|failures)\b/.test(l));
  assert.deepEqual(
    counts, [],
    'the README states a test count; `node --test` prints the real one and this file cannot keep a copy of it true',
  );
});

test('the check that re-measures these rows is named where a reader of them will look', () => {
  // A tracked number whose re-measurement is undiscoverable is prose in JSON.
  assert.match(TABLE.provenance.note, /check-which-wipe-plumbing/);
  assert.match(README, /check-which-wipe-plumbing\.mjs/);
});
