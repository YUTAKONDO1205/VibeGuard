/**
 * The re-measurement under the spike/recovery gate, pinned.
 *
 * WHY THIS FILE EXISTS
 *
 *   The gate was wired into lib/build-analyze.mjs on 2026-09-12. The tracked
 *   rows were measured before it existed. For one day the honest sentence was
 *   "the harness is gated and its rows are not", and nothing in the tree said
 *   so -- the wiring is a line of code, and a line of code says nothing about
 *   when the data beside it was taken. data/r2-regate.json is the run that
 *   closed that gap and this file is what stops it from re-opening silently.
 *
 * WHAT IS RECOMPUTED HERE, AND WHAT IS NOT
 *
 *   Recomputed: the tracked rows' sha256 and row count. If someone re-records
 *   data/r2-build-rows.json without re-running the comparison, the record now
 *   describes a file that no longer exists and this test says so.
 *
 *   Not recomputed, and said so in the record's own `provenance` block: the lab
 *   file's digest (the lab is not tracked) and the two negative controls (typed
 *   from their run logs). They are held to the README instead, which is the
 *   difference between "a number nothing checks" and "a number that has to
 *   appear in two places that were written for different readers".
 *
 * Nothing here compiles and nothing is written.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const bytes = (rel) => readFileSync(path.join(ROOT, rel));
const text = (rel) => bytes(rel).toString('utf8').replace(/\r\n/g, '\n');

const README = text('README.md');
const record = JSON.parse(text('data/r2-regate.json'));
const trackedBytes = bytes('data/r2-build-rows.json');
const trackedRows = JSON.parse(trackedBytes.toString('utf8'));

test('the record describes the tracked rows that are here now', () => {
  const digest = createHash('sha256').update(trackedBytes).digest('hex');
  assert.equal(record.rows.tracked.sha256, digest,
    'data/r2-build-rows.json was re-recorded without re-running the comparison in data/r2-regate.json');
  assert.equal(record.rows.tracked.rows, trackedRows.length);
  assert.equal(record.run.rows, trackedRows.length);
});

test('the comparison is a multiset equality over every row, not a sample', () => {
  const c = record.comparison;
  assert.equal(c.equal, true);
  assert.equal(c.only_in_a, 0);
  assert.equal(c.only_in_b, 0);
  assert.equal(c.identical, trackedRows.length,
    'identical must cover every row: a comparison that matched fewer rows than exist is not an equality');
  assert.equal(c.exit, 0);
});

test('the two digests differ, and that is the completion-order point rather than a discrepancy', () => {
  assert.notEqual(record.rows.regate.sha256, record.rows.tracked.sha256);
  assert.match(record.readMeFirst, /MULTISET/);
});

test('the gate held, and the run says which configurations could not discriminate', () => {
  const g = record.gate;
  assert.equal(g.established, true);
  assert.equal(g.injectionHeld, true);
  assert.equal(g.configurations.num, g.configurations.den);
  assert.ok(g.configurations.den >= 10);
  // A gate whose every configuration discriminates would be a stronger claim
  // than this run can make: -O0 registers the same answer for both spikes.
  assert.ok(g.discriminating.num < g.discriminating.den,
    'if every configuration now discriminates, the -O0 sentence in the record and the README is stale');
  assert.match(g.nonDiscriminating, /-O0/);
});

test('both negative controls went red, exited 3, and wrote no rows', () => {
  const controls = record.negativeControls;
  assert.equal(controls.length, 2);
  for (const c of controls) {
    assert.equal(c.gateEstablished, false, `${c.name}: a negative control that establishes the gate is not a control`);
    assert.equal(c.exit, 3);
    assert.equal(c.rowsWritten, 0);
    assert.ok(typeof c.how === 'string' && c.how.length > 0);
  }
  const wrong = controls.find((c) => c.name === 'never-optimises');
  assert.ok(wrong, 'the control that compiles and answers wrongly is the one this lane cannot do without');
  assert.equal(wrong.redConfigurations.length, 4);
  assert.match(wrong.reason, /WRONG_VERDICT/);
});

test('the README section quotes the record, and the record says what nothing recomputes', () => {
  const section = README.split('## Measured again under the gate')[1];
  assert.ok(section, 'the README section this record was written for is gone');
  assert.ok(section.includes(String(record.run.rows).replace(/^(\d)(\d{3})$/, '$1,$2')) || section.includes(String(record.run.rows)),
    'the README does not quote the row count the record holds');
  assert.ok(section.includes(`${record.gate.configurations.num}/${record.gate.configurations.den}`));
  assert.ok(section.includes(`${record.gate.discriminating.num}/${record.gate.discriminating.den}`));
  assert.ok(section.includes(record.rows.tracked.sha256.slice(0, 8)));
  assert.ok(section.includes(record.rows.regate.sha256.slice(0, 8)));
  for (const c of record.negativeControls) assert.ok(section.includes(c.name), `the README does not name the ${c.name} control`);
  assert.match(record.provenance.negativeControls, /lab-run/);
  assert.match(record.provenance.regateSha256, /lab-run/);
});

test('the record carries integers and no path that names a machine', () => {
  const raw = text('data/r2-regate.json');
  for (const re of [/\/home\//, /\/root\//, /\/mnt\//, /\/Users\//, /\b[A-Za-z]:[\\/]/]) {
    assert.equal(re.test(raw), false, `data/r2-regate.json carries ${re}`);
  }
  const walk = (v, at) => {
    if (typeof v === 'number') assert.equal(Number.isInteger(v), true, `${at} is not an integer`);
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
  };
  walk(record, 'record');
});
