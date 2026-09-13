/**
 * data/lto-regate.json against tools/LTO.md.
 *
 * WHY THIS FILE
 *
 * `data/r2-regate.json` records the repair loop re-measured with the spike gate in
 * front of it and names the two LTO probes as what it does not cover: they write no
 * tracked rows, so there was nothing in `data/` of theirs to compare. That left the
 * probes in the state the rows had been in -- gated code, ungated figures -- and the
 * figures are quoted in `tools/LTO.md`.
 *
 * `data/lto-regate.json` closes it by a different route, and the route is why this
 * file exists. The probes refuse `--write-data` (exit 4), so nothing wrote that
 * record: a person read the logs and typed the numbers in. A hand-transcribed record
 * is exactly the kind that is right on the day and wrong six months later, in either
 * direction -- a typo now, or an edit to LTO.md later that moves a number the record
 * still claims to match. So every run's numbers are read back OUT of LTO.md here.
 *
 * HOW, AND WHY IT IS THIS AND NOT SOMETHING EASIER
 *
 * Each run in the record names the LTO.md row it reproduced and the EXACT TEXT of
 * every cell it claims, and this file compares the text. Both earlier shapes were
 * measured vacuous by mutation, on copies, and both failures are the reason for the
 * shape here:
 *
 *   - comparing only `runs[0]` per vendor left the second run per vendor -- the
 *     whole point of the two-builds design -- held to nothing but self-consistency.
 *     14 of 17 mutations of those runs stayed green. EVERY run is compared now.
 *   - reading a cell's FIRST INTEGER left every denominator and every verdict word
 *     unguarded: `HELD 113/113` -> `FAILED 113/113` and `452/452` -> `452/1` both
 *     stayed green. The whole cell text is compared now, so a denominator and a
 *     word are as checked as a numerator.
 *
 * No compiler, no linker, no lab. Two tracked files.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.join(HERE, '..');
const RECORD_PATH = path.join(LANE, 'data', 'lto-regate.json');
const RECORD = JSON.parse(readFileSync(RECORD_PATH, 'utf8'));
const LTO_MD = readFileSync(path.join(LANE, 'tools', 'LTO.md'), 'utf8');

const cellsOf = (line) => line.trim().replace(/^\|/, '').replace(/\|$/, '')
  .split('|').map((c) => c.trim().replace(/\*\*/g, ''));

/**
 * Every markdown table in LTO.md whose first column is `run` or `form`, as
 * `{ header, rows }`. A table is recognised by its separator line, so a table that
 * loses its header or gains a column is a parse failure here rather than a silent
 * shift of every comparison onto the next cell.
 */
function outcomeTables() {
  const lines = LTO_MD.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*\|/.test(lines[i])) continue;
    if (!/^\s*\|[-\s|:]+\|\s*$/.test(lines[i + 1] ?? '')) continue;
    const header = cellsOf(lines[i]);
    if (header[0] !== 'run' && header[0] !== 'form') continue;
    const rows = [];
    for (let j = i + 2; j < lines.length && /^\s*\|/.test(lines[j]); j++) rows.push(cellsOf(lines[j]));
    out.push({ header, rows, line: i + 1 });
  }
  return out;
}

const TABLES = outcomeTables();

/**
 * The one row of the one table whose leading key columns equal `rowKey`.
 *
 * Ambiguity is a failure, not a first-match: two tables in this file share the
 * `run | form | level` header (runs A-D and run G), so a rowKey that matched both
 * would silently compare against whichever came first.
 */
function findRow(rowKey) {
  const hits = [];
  for (const t of TABLES) {
    for (const r of t.rows) {
      if (rowKey.every((v, k) => r[k] === v)) hits.push({ t, r });
    }
  }
  assert.equal(hits.length, 1,
    `rowKey ${JSON.stringify(rowKey)} matches ${hits.length} row(s) in LTO.md's outcome tables `
    + `(expected exactly 1; the tables are at lines ${TABLES.map((t) => t.line).join(', ')}). `
    + 'Either the row was renamed or removed, or two tables now share these key columns.');
  return hits[0];
}

test('LTO.md still has the outcome tables this record is about', () => {
  assert.ok(TABLES.length >= 5,
    `found ${TABLES.length} outcome table(s) in LTO.md; five were there when this was written `
    + '(clang A-D, clang G, clang E, clang F, gcc A/B). The PARSE broke, or the file was '
    + 'restructured and this record no longer points at anything.');
});

test('the record names both probes, and every run in it exited 0 with the gate established', () => {
  assert.equal(RECORD.schemaVersion, 'repair-regate/1');
  assert.deepEqual([...new Set(RECORD.runs.map((r) => r.probe))].sort(),
    ['tools/lto-probe-gcc.mjs', 'tools/lto-probe.mjs'],
    'both probes must appear: naming one and not the other is half the hole');
  assert.ok(RECORD.runs.length >= 8,
    `${RECORD.runs.length} run(s) recorded; the closure covers four levels per vendor plus the `
    + 'all-removable idiom, so a record this short has lost runs');

  for (const r of RECORD.runs) {
    const who = `${r.probe} ${r.level} ${r.pluginSha256.slice(0, 12)}`;
    assert.equal(r.exit, 0, `${who}: exit ${r.exit}`);
    assert.equal(r.wroteTrackedRows, false,
      `${who}: neither probe may write tracked data; both refuse --write-data with exit 4`);
    // The gate, as the gate's own object reports it -- NOT as the summary line reads.
    // The first version of this record copied "2/2" off that line, which is the
    // per-configuration RECOVERY count printed beside the configuration count; the
    // probes pass one vendor and one level, so `verdict.configurations` is 1/1.
    // Measured by running the gate and printing the object.
    assert.equal(r.gate.established, true, `${who}: gate not established`);
    assert.equal(r.gate.injectionHeld, true, `${who}: injection control did not go red`);
    for (const k of ['configurations', 'discriminating']) {
      assert.equal(r.gate[k].den, 1,
        `${who}: gate.${k}.den is ${r.gate[k].den}. Each probe calls the gate with one vendor and `
        + 'one level, so both dens are 1; spike.mjs derives them from the same list length, which '
        + 'makes any other pair impossible rather than merely unexpected.');
      assert.equal(r.gate[k].num, 1,
        `${who}: gate.${k}.num is ${r.gate[k].num}, so the gate did not hold -- at -O0 the real `
        + 'reading is discriminating 0/1 with established false, and a num === den check alone '
        + 'would not have caught a record claiming 2/2.');
    }
  }
});

test('every run is compared against the LTO.md row it names, cell text for cell text', () => {
  // THE test. One assertion per claimed cell, per run -- no run held only to
  // self-consistency, no cell reduced to its first integer.
  let compared = 0;
  for (const r of RECORD.runs) {
    const { t, r: row } = findRow(r.ltoMd.rowKey);
    for (const [column, expected] of Object.entries(r.ltoMd.columns)) {
      const k = t.header.indexOf(column);
      assert.notEqual(k, -1,
        `${r.ltoMd.rowKey.join('/')}: LTO.md's table at line ${t.line} has no column `
        + `${JSON.stringify(column)}; its columns are: ${t.header.join(' | ')}`);
      assert.equal(row[k], expected,
        `${r.probe} ${r.level} (${r.pluginSha256.slice(0, 12)}): LTO.md row `
        + `${r.ltoMd.rowKey.join(' | ')}, column ${JSON.stringify(column)} reads `
        + `${JSON.stringify(row[k])}; data/lto-regate.json claims ${JSON.stringify(expected)}. `
        + 'One of the two files is wrong.');
      compared += 1;
    }
    assert.ok(Object.keys(r.ltoMd.columns).length >= 5,
      `${r.probe} ${r.level}: only ${Object.keys(r.ltoMd.columns).length} column(s) claimed. A run `
      + 'that claims two cells is a run that reproduced almost nothing.');
  }
  assert.ok(compared >= 60,
    `${compared} cell comparison(s) made; the record claimed far more than that when this was `
    + 'written, so either runs or columns have been dropped');
});

test('each vendor was run with the exact plugin binary LTO.md quotes, not only a second build', () => {
  for (const cc of ['clang-18', 'gcc-13']) {
    const runs = RECORD.runs.filter((r) => r.cc === cc);
    assert.ok(runs.length >= 4, `${cc}: only ${runs.length} run(s) recorded`);
    const quoted = runs.filter((r) => r.pluginIsTheOneTheProseQuotes);
    assert.ok(quoted.length >= 1,
      `${cc}: no run was made with the binary LTO.md quotes, so every figure that reproduced did `
      + 'so under a different build and the two variables were never separated');
    for (const q of quoted) {
      assert.ok(LTO_MD.includes(q.pluginSha256),
        `${cc}: LTO.md does not contain the digest ${q.pluginSha256.slice(0, 12)}… that this record `
        + 'claims it quotes. Either the record names the wrong binary, or LTO.md was rewritten and '
        + 'the run no longer corresponds to anything in it.');
    }
    for (const r of runs) assert.match(r.pluginSha256, /^[0-9a-f]{64}$/);
  }
  // The second build is not a "rebuild": measured, the two differ in
  // CMAKE_BUILD_TYPE (empty vs Release) and in size by a factor of several. The
  // record has to say which, because "same source, two build recipes, same numbers"
  // is a stronger claim than "ran it twice" and a different one.
  const builds = new Set(RECORD.runs.map((r) => r.pluginBuildType));
  assert.ok(builds.size >= 2,
    `every run records pluginBuildType ${[...builds]}; the point of the second binary per vendor `
    + 'is that it was configured differently, and a record that does not say so is claiming a '
    + 'weaker result than it has');
});

test('LTO.md says its own figures predate the gate, and points at this record', () => {
  assert.match(LTO_MD, /gate/,
    'tools/LTO.md contains no mention of the gate. Every figure in it was measured before '
    + "compiler/eval/spike's gate was wired into the probes on 2026-09-12, and a reader cannot "
    + 'know that from the file.');
  assert.match(LTO_MD, /lto-regate\.json/,
    'tools/LTO.md must point at data/lto-regate.json, which is where the gated re-measurement is');
});

test('what was NOT re-measured is named, including the parts that cannot be', () => {
  assert.ok(Array.isArray(RECORD.notMeasuredHere) && RECORD.notMeasuredHere.length >= 4);
  const text = RECORD.notMeasuredHere.join(' ');
  for (const [what, re] of [
    ['the wipe-pin-v1 binary runs A-D used', /aa7329c3/],
    ["run A's (ii) figures being unreproducible by design", /unreproducible/i],
    ['the fallback path', /fallback/i],
    ['that one host is not replication', /independent replication/],
  ]) {
    assert.match(text, re, `notMeasuredHere does not name ${what}`);
  }
});

test('the record carries integers and no path that names a machine', () => {
  const raw = readFileSync(RECORD_PATH, 'utf8');
  for (const re of [/\/home\//, /\/root\//, /\/mnt\//, /\/Users\//, /\b[A-Za-z]:[\\/]/]) {
    assert.equal(re.test(raw), false, `data/lto-regate.json carries ${re}`);
  }
  const walk = (v, at) => {
    if (typeof v === 'number') assert.equal(Number.isInteger(v), true, `${at} is not an integer`);
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${at}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`);
  };
  walk(RECORD, 'lto-regate');
});
