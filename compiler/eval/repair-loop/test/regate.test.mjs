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
 * On 2026-11-09 the rows were re-recorded with the wipe-pin-v3 plugins
 * (data/r2-v3-rerecord.json), so the rows data/r2-regate.json describes are no
 * longer the files here. That record is kept as what it was, the comparison of
 * the rows the re-record replaced, and the chain is checked instead: the
 * re-record must have replaced exactly the rows r2-regate.json pins, and must
 * describe the rows here now. What the re-record says about the rows here now
 * is recomputed from them.
 *
 * Nothing here compiles and nothing is written.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { UNHANDLED_KEYS, UNHANDLED_KEYS_V2 } from '../lib/pin-record.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const bytes = (rel) => readFileSync(path.join(ROOT, rel));
const text = (rel) => bytes(rel).toString('utf8').replace(/\r\n/g, '\n');
const sha256 = (rel) => createHash('sha256').update(bytes(rel)).digest('hex');

const record = JSON.parse(text('data/r2-regate.json'));
const rerecord = JSON.parse(text('data/r2-v3-rerecord.json'));
const rerecordOf = (cc) => {
  const runs = rerecord.runs.filter((r) => r.cc === cc);
  assert.equal(runs.length, 1, `data/r2-v3-rerecord.json has ${runs.length} runs for ${cc}`);
  return runs[0];
};
const V3_ONLY = UNHANDLED_KEYS.filter((k) => !UNHANDLED_KEYS_V2.includes(k));
const SUMMARY_SLOTS = ['recordW', 'recordWo', 'record'];

test('both vendors were re-run, and each names a tracked rows file', () => {
  assert.equal(record.runs.length, 2);
  assert.deepEqual(record.runs.map((r) => r.cc).sort(), ['clang-18', 'gcc-13']);
  for (const run of record.runs) {
    assert.match(run.trackedFile, /^data\/r2-repair-rows/);
    assert.equal(run.wroteTrackedRows, false, 'a re-measurement that overwrote the thing it was comparing against has compared nothing');
  }
});

test('each run describes the tracked rows here now, or the rows the v3 re-record replaced, byte for byte', () => {
  for (const run of record.runs) {
    const raw = bytes(run.trackedFile);
    const digest = createHash('sha256').update(raw).digest('hex');
    const rows = JSON.parse(raw.toString('utf8')).length;
    if (run.trackedSha256 !== digest) {
      // Re-recorded since: the re-record must start from exactly these rows and
      // end at the file here, or the file was rewritten with no comparison at all.
      const rr = rerecordOf(run.cc);
      assert.equal(rr.trackedFile, run.trackedFile);
      assert.equal(rr.before.sha256, run.trackedSha256,
        `${run.trackedFile} was re-recorded from rows other than the ones data/r2-regate.json compared`);
      assert.equal(rr.after.sha256, digest,
        `${run.trackedFile} was re-recorded without re-running the comparison in data/r2-v3-rerecord.json`);
      assert.equal(rr.before.rows, run.rows);
    }
    assert.equal(rows, run.rows);
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

// ---------------------------------------------------------------------------
// The v3 re-record (data/r2-v3-rerecord.json): the rows rewritten with the
// wipe-pin-v3 plugins, every switch off, after a row-by-row comparison with the
// rows they replaced. The comparison ran in the lab against rows that are no
// longer in the working tree, so it is read here as a record; everything it
// says about the rows that ARE here is recomputed from them.

const pluginLineOf = (rel) => {
  const m = /^plugin sha256[ \t]+([0-9a-f]{64})[ \t]*$/m.exec(text(rel));
  assert.ok(m, `${rel} prints no plugin sha256`);
  return m[1];
};

test('the v3 re-record names both vendors, wrote the tracked rows, and describes the files here now', () => {
  assert.equal(rerecord.schemaVersion, 'repair-rerecord/1');
  assert.deepEqual(rerecord.runs.map((r) => r.cc).sort(), ['clang-18', 'gcc-13']);
  for (const run of rerecord.runs) {
    assert.equal(run.wroteTrackedRows, true);
    assert.match(run.trackedFile, /^data\/r2-repair-rows/);
    assert.match(run.resultsFile, /^data\/r2-repair-results/);
    assert.equal(run.after.sha256, sha256(run.trackedFile), `${run.trackedFile} is not the file the re-record wrote`);
    assert.equal(run.after.resultsSha256, sha256(run.resultsFile), `${run.resultsFile} is not the text the re-record wrote`);
    assert.equal(run.after.rows, JSON.parse(text(run.trackedFile)).length);
    assert.equal(run.before.rows, run.after.rows, 'a re-record that lost or gained rows is not a re-record');
    // and it replaced exactly what the 2026-09-12 comparison describes
    const v2 = record.runs.find((r) => r.cc === run.cc);
    assert.ok(v2, `data/r2-regate.json has no ${run.cc} run`);
    assert.equal(run.before.sha256, v2.trackedSha256);
    assert.equal(run.before.rows, v2.rows);
    assert.notEqual(run.before.sha256, run.after.sha256, 'v3 summaries carry more keys, so the bytes must differ');
  }
});

test('the re-record compared every row, and found nothing but the four counters v3 adds', () => {
  const slotPath = new RegExp(`^(${SUMMARY_SLOTS.join('|')})\\.unhandled\\.(${V3_ONLY.join('|')})$`);
  for (const run of rerecord.runs) {
    const c = run.comparison;
    assert.equal(c.rowsCompared, run.after.rows, `${run.cc}: compared ${c.rowsCompared} of ${run.after.rows} rows`);
    assert.equal(c.sameRowCount, true);
    assert.equal(c.sameCellSequence, true);
    assert.equal(c.equalAfterRemovingTheFourV3Counters, run.after.rows,
      `${run.cc}: ${run.after.rows - c.equalAfterRemovingTheFourV3Counters} rows differ in something besides the four v3 counters`);
    assert.equal(c.otherDifferences, 0);
    assert.equal(c.everyValidSummaryCarriesTheNineCounters, true);
    assert.ok(Object.keys(c.addedPaths).length > 0, 'the comparison found no added key at all, so it compared nothing');
    for (const p of Object.keys(c.addedPaths)) assert.match(p, slotPath, `${run.cc}: an added path outside the v3 counters: ${p}`);
    for (const f of ['outcome', 'baseline', 'repaired', 'listings', 'spans', 'hiddenElimination']) {
      assert.ok(c.fieldsEqual[f], `${run.cc}: ${f} was not compared`);
    }
    for (const [f, v] of Object.entries(c.fieldsEqual)) {
      assert.ok(v.den > 0, `${run.cc}: ${f} compared over no rows`);
      assert.equal(v.num, v.den, `${run.cc}: ${f} equal in ${v.num} of ${v.den} rows`);
    }
    // compare-rows.mjs's multiset view of the same two files
    const m = c.compareRows;
    assert.equal(m.identical + m.paired_by_cell, run.after.rows);
    assert.equal(m.unpaired_only_in_a, 0);
    assert.equal(m.unpaired_only_in_b, 0);
    assert.deepEqual(m.verdict_transitions, {});
    for (const f of Object.keys(m.differing_fields)) assert.ok(SUMMARY_SLOTS.includes(f), `${run.cc}: compare-rows saw ${f} differ`);
  }
});

test('what the re-record says about the rows here now is what they hold, recomputed', () => {
  const nine = [...UNHANDLED_KEYS].sort();
  for (const run of rerecord.runs) {
    const rows = JSON.parse(text(run.trackedFile));
    const valid = Object.fromEntries(SUMMARY_SLOTS.map((s) => [s, 0]));
    const totals = Object.fromEntries(V3_ONLY.map((k) => [k, 0]));
    let invalid = 0;
    for (const r of rows) {
      for (const s of SUMMARY_SLOTS) {
        const sum = r[s];
        if (!sum) continue;
        if (sum.ok !== true) { invalid++; continue; }
        valid[s]++;
        assert.deepEqual(Object.keys(sum.unhandled).sort(), nine, `${run.cc} ${r.id} ${r.opt} ${s}: not the nine v3 counters`);
        for (const k of V3_ONLY) totals[k] += sum.unhandled[k];
      }
    }
    const nValid = SUMMARY_SLOTS.reduce((n, s) => n + valid[s], 0);
    assert.equal(run.comparison.validSummaries, nValid);
    assert.equal(run.comparison.invalidSummaries, invalid);
    for (const k of V3_ONLY) {
      assert.deepEqual(run.v3Counters[k], { total: totals[k], records: nValid }, `${run.cc} ${k}`);
      // every valid summary gained the key, and nothing else did
      for (const s of SUMMARY_SLOTS) {
        assert.equal(run.comparison.addedPaths[`${s}.unhandled.${k}`] ?? 0, valid[s], `${run.cc} ${s}.unhandled.${k}`);
      }
    }
  }
});

test('each results text was printed by the plugin the re-record names, with the nine counters', () => {
  for (const run of rerecord.runs) {
    const p = rerecord.plugins[run.cc];
    assert.equal(p.schema, 'wipe-pin-v3');
    assert.equal(pluginLineOf(run.resultsFile), p.sha256, `${run.resultsFile} was printed by another build`);
    assert.match(p.replaces, /^[0-9a-f]{64}$/);
    assert.notEqual(p.replaces, p.sha256);
    const lines = text(run.resultsFile).split('\n').map((l) => /^ {2}unhandled\.(\w+) +(\S+)$/.exec(l)).filter(Boolean);
    assert.deepEqual(lines.map((m) => m[1]).sort(), [...UNHANDLED_KEYS].sort(), `${run.resultsFile}: not one line per v3 counter`);
    for (const m of lines) assert.match(m[2], /^\d+$/, `${run.resultsFile}: unhandled.${m[1]} is "${m[2]}", not a measured count`);
    for (const k of V3_ONLY) {
      assert.equal(Number(lines.find((m) => m[1] === k)[2]), run.v3Counters[k].total, `${run.resultsFile} ${k}`);
    }
    // the text differs from the replaced one only where the plugin and the schema say it should
    const t = run.resultsText;
    for (const k of Object.keys(t.removed)) assert.ok(['plugin sha256', 'cross-vendor coverage line'].includes(k), `removed: ${k}`);
    for (const k of Object.keys(t.added)) {
      assert.ok(['plugin sha256', 'unhandled counter line', 'cross-vendor coverage line'].includes(k), `added: ${k}`);
    }
    assert.equal(t.added['unhandled counter line'], V3_ONLY.length);
    assert.equal(t.linesAfter - t.linesBefore, V3_ONLY.length);
    assert.equal(t.linesAfter, text(run.resultsFile).split('\n').length - 1);
  }
  for (const s of Object.values(rerecord.switches)) assert.equal(s, 'unset', 'these rows are the switches-off rows');
});

test('the re-record was deterministic, and the gate held in every invocation', () => {
  for (const run of rerecord.runs) {
    assert.equal(run.determinism.byteIdentical, true);
    assert.ok(run.invocations.length >= 2, `${run.cc}: one invocation cannot show determinism`);
    for (const inv of run.invocations) {
      assert.equal(inv.exit, 0);
      assert.equal(inv.rowsSha256, run.after.sha256, `${run.cc} invocation ${inv.order} wrote other rows`);
      assert.equal(inv.gate.established, true);
      assert.equal(inv.gate.injectionHeld, true);
      assert.equal(inv.gate.configurations.num, inv.gate.configurations.den);
      assert.ok(inv.gate.discriminating.num < inv.gate.discriminating.den);
    }
    assert.ok(run.invocations.some((i) => i.writeData && i.resultsSha256 === run.after.resultsSha256),
      `${run.cc}: no --write-data invocation wrote the results text here`);
  }
});

test('the re-record names what it did not measure, and carries integers and no machine path', () => {
  assert.ok(rerecord.notMeasuredHere.some((s) => /WPIN_BUFFER_BARRIER/.test(s) && /switch/.test(s)),
    'a switches-off re-record must say that no switch was measured');
  assert.ok(rerecord.notMeasuredHere.some((s) => /LTO/.test(s)));
  assert.match(rerecord.provenance.comparison, /lab-run/);
  assert.match(rerecord.provenance.afterDigests, /recomputed/);
  const raw = text('data/r2-v3-rerecord.json');
  for (const re of [/\/home\//, /\/root\//, /\/mnt\//, /\/Users\//, /\b[A-Za-z]:[\\/]/]) {
    assert.equal(re.test(raw), false, `data/r2-v3-rerecord.json carries ${re}`);
  }
  const walk = (v, at) => {
    if (typeof v === 'number') assert.equal(Number.isInteger(v), true, `${at} is not an integer`);
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
  };
  walk(rerecord, 'rerecord');
});
