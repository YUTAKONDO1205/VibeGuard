/**
 * The re-measurement under the spike/recovery gate, pinned.
 *
 * The gate has been in run-repair-loop.mjs since 2026-09-12 and the rows beside
 * it were older than the gate. data/r2-regate.json is the run that closed that,
 * once per vendor, and this file holds the record to the files it describes:
 * if either tracked rows file is re-recorded without re-running the comparison,
 * the digests here stop matching and this test says so.
 *
 * This lane is byte-deterministic where compiler/eval/ai-generated is not -- it
 * writes its rows in a fixed order rather than in pool completion order -- so
 * the record claims byte identity and this test checks exactly that, rather
 * than the weaker multiset equality that lane has to settle for.
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

const record = JSON.parse(text('data/r2-regate.json'));

test('both vendors were re-run, and each names a tracked rows file', () => {
  assert.equal(record.runs.length, 2);
  assert.deepEqual(record.runs.map((r) => r.cc).sort(), ['clang-18', 'gcc-13']);
  for (const run of record.runs) {
    assert.match(run.trackedFile, /^data\/r2-repair-rows/);
    assert.equal(run.wroteTrackedRows, false, 'a re-measurement that overwrote the thing it was comparing against has compared nothing');
  }
});

test('each run describes the tracked rows that are here now, byte for byte', () => {
  for (const run of record.runs) {
    const raw = bytes(run.trackedFile);
    const digest = createHash('sha256').update(raw).digest('hex');
    assert.equal(run.trackedSha256, digest,
      `${run.trackedFile} was re-recorded without re-running the comparison in data/r2-regate.json`);
    assert.equal(JSON.parse(raw.toString('utf8')).length, run.rows);
    assert.equal(run.labSha256, run.trackedSha256, 'the record claims byte identity; these two digests are what that claim is');
    assert.equal(run.byteIdentical, true);
  }
});

test('the comparison covered every row rather than a sample', () => {
  for (const run of record.runs) {
    assert.equal(run.comparison.equal, true);
    assert.equal(run.comparison.only_in_a, 0);
    assert.equal(run.comparison.only_in_b, 0);
    assert.equal(run.comparison.identical, run.rows);
    assert.equal(run.comparison.exit, 0);
    assert.equal(run.exit, 0);
  }
});

test('the gate held on both vendors, and neither claims every configuration discriminates', () => {
  for (const run of record.runs) {
    assert.equal(run.gate.established, true);
    assert.equal(run.gate.injectionHeld, true);
    assert.equal(run.gate.configurations.num, run.gate.configurations.den);
    assert.ok(run.gate.discriminating.num < run.gate.discriminating.den,
      'at -O0 both spikes are registered to read the same word, so a run claiming every configuration discriminates has changed shape');
  }
});

test('what was not measured is named, and the LTO probes are named among it', () => {
  assert.ok(Array.isArray(record.notMeasuredHere) && record.notMeasuredHere.length >= 2);
  assert.ok(record.notMeasuredHere.some((s) => /lto-probe/.test(s)),
    'the LTO probes write no tracked rows and that has to be said here, not left to be inferred');
  assert.match(record.provenance.gate, /lab-run/);
  assert.match(record.provenance.comparison, /recomputed/);
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
