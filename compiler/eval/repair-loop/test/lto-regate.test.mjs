/**
 * data/lto-regate.json against tools/LTO.md.
 *
 * WHY THIS FILE
 *
 * `data/r2-regate.json` records the repair loop re-measured with the spike gate in
 * front of it and names the two LTO probes as what it does not cover: they write no
 * tracked rows, so there was nothing in `data/` of theirs to compare. That left the
 * probes in the state the rows had been in -- gated code, ungated figures -- and the
 * figures are quoted in `tools/LTO.md`, which does not contain the word "gate".
 *
 * `data/lto-regate.json` closes it by a different route, and the route is why this
 * file exists. The probes refuse `--write-data` (exit 4), so nothing wrote that
 * record: a person read four logs and typed the numbers in. A hand-transcribed
 * record is exactly the kind that is right on the day and wrong six months later,
 * in either direction -- a typo now, or an edit to LTO.md later that moves a number
 * the record still claims to match. So the numbers are read back OUT of LTO.md here
 * and compared, which makes the two files fail together rather than drift apart.
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
const RECORD = JSON.parse(readFileSync(path.join(LANE, 'data', 'lto-regate.json'), 'utf8'));
const LTO_MD = readFileSync(path.join(LANE, 'tools', 'LTO.md'), 'utf8');

/**
 * Every integer appearing anywhere in a row, in order.
 *
 * Substrings, not whole cells: these tables write `HELD 113/113`, `226/226` and
 * `**113**` as single cells, and a whole-cell `^\d+$` filter silently drops every
 * one of them -- which is how the first version of this file failed to find rows
 * it was looking at. Used only to LOCATE a row; the comparisons below are per
 * column, because a row-wide `includes` is blind to one number changing while the
 * same number stays elsewhere in the row. Mutation-tested: changing Run E's
 * `cells` cell from 113 to 112 left the row-wide version green.
 */
const ints = (row) => row.join(' ').replace(/\*\*/g, '')
  .match(/\d+/g)?.map(Number) ?? [];

/**
 * A table located by a header cell, as `{ index: name -> column, rows }`.
 *
 * The header is matched on its first two cells, so the two tables this file reads
 * are told apart without counting lines, and a column inserted anywhere shifts the
 * indices rather than silently moving a comparison onto the wrong cell.
 */
function table(firstCell, secondCell) {
  const all = LTO_MD.split(/\r?\n/);
  const cells = (l) => l.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
  for (let i = 0; i < all.length; i++) {
    if (!/^\s*\|/.test(all[i])) continue;
    const head = cells(all[i]);
    if (head[0] !== firstCell || head[1] !== secondCell) continue;
    if (!/^\s*\|[-\s|:]+\|\s*$/.test(all[i + 1] ?? '')) continue;
    const body = [];
    for (let j = i + 2; j < all.length && /^\s*\|/.test(all[j]); j++) body.push(cells(all[j]));
    const index = new Map(head.map((h, k) => [h, k]));
    return { index, rows: body, header: head };
  }
  assert.fail(`LTO.md has no table whose header starts \`${firstCell} | ${secondCell}\`; the `
    + 'PARSE broke, or the table was renamed');
}

/** One cell's first integer, by column name, asserting the column exists. */
function cell(t, row, column) {
  const k = t.index.get(column);
  assert.notEqual(k, undefined,
    `LTO.md's table has no column "${column}"; its columns are: ${t.header.join(' | ')}`);
  const m = String(row[k]).replace(/\*\*/g, '').match(/\d+/);
  assert.ok(m, `LTO.md column "${column}" holds ${JSON.stringify(row[k])}, which carries no integer`);
  return Number(m[0]);
}

test('the record names both probes, and every run in it exited 0 with the gate established', () => {
  assert.equal(RECORD.schemaVersion, 'repair-regate/1');
  const probes = new Set(RECORD.runs.map((r) => r.probe));
  assert.deepEqual([...probes].sort(),
    ['tools/lto-probe-gcc.mjs', 'tools/lto-probe.mjs'],
    'both probes must appear: naming one and not the other is half the hole');
  for (const r of RECORD.runs) {
    assert.equal(r.exit, 0, `${r.probe} ${r.pluginSha256.slice(0, 12)}: exit ${r.exit}`);
    assert.equal(r.gate.established, true);
    assert.equal(r.gate.injectionHeld, true);
    assert.equal(r.gate.configurations.num, r.gate.configurations.den);
    assert.equal(r.gate.discriminating.num, r.gate.discriminating.den,
      'at -O2 each vendor has exactly one registered discriminating pair, so num and den are both 1; '
      + 'a run claiming otherwise was made at a different selection of levels than this record says');
    assert.equal(r.wroteTrackedRows, false,
      'neither probe may write tracked data; both refuse --write-data with exit 4');
  }
});

test('each vendor was run with the exact plugin binary LTO.md quotes, not only a rebuild', () => {
  // The whole point of the second run per vendor. Reproducing a figure with the
  // gate added AND the plugin binary changed does not separate the two, and the
  // first run of each vendor did change both.
  for (const cc of ['clang-18', 'gcc-13']) {
    const runs = RECORD.runs.filter((r) => r.cc === cc);
    assert.ok(runs.length >= 2, `${cc}: only ${runs.length} run(s) recorded`);
    const quoted = runs.filter((r) => r.pluginIsTheOneTheProseQuotes);
    assert.equal(quoted.length, 1,
      `${cc}: exactly one run must be the one made with the binary LTO.md quotes`);
    assert.ok(LTO_MD.includes(quoted[0].pluginSha256),
      `${cc}: LTO.md does not contain the digest ${quoted[0].pluginSha256.slice(0, 12)}… that this `
      + 'record claims it quotes. Either the record names the wrong binary, or LTO.md was '
      + 'rewritten and the run no longer corresponds to anything in it.');
    for (const r of runs) {
      assert.match(r.pluginSha256, /^[0-9a-f]{64}$/);
      assert.equal(r.everyQuotedNumberReproduced, true);
    }
  }
});

test("the clang figures are the ones LTO.md's Run E row carries, read back out of it", () => {
  // Run E: the -O2 full/thin rows, located by form and level, then compared cell by
  // cell through the table's own HEADER NAMES. A renamed or removed column fails
  // here by name rather than moving a comparison onto a neighbouring number.
  const t = table('form', 'level');
  const runE = t.rows.filter((r) => r[1] === '`-O2`' && ints(r).includes(452));
  assert.equal(runE.length, 2,
    `found ${runE.length} Run E row(s) in LTO.md (expected the full and thin -O2 rows, each ending `
    + 'in 452/452 relinks); the PARSE broke, or the table changed shape');
  assert.deepEqual(runE.map((r) => r[0]), ['full', 'thin']);

  const clang = RECORD.runs.filter((r) => r.cc === 'clang-18');
  for (const row of runE) {
    for (const [column, v] of [
      ['cells', clang[0].cells],
      ['eliminated without the plugin (LTO)', clang[0].eliminatedWithoutPlugin],
      ['differs from the tracked non-LTO row', clang[0].differsFromTrackedNonLtoRow],
      ['`RETAINED`', clang[0].retained],
      ['dry run (iii)', clang[0].dryRunHeld.num],
      ['(ii) links', clang[0].linkLineLinks],
      ['relinks identical', clang[0].relinksIdentical.num],
    ]) {
      assert.equal(cell(t, row, column), v,
        `LTO.md Run E ${row[0]} row, column "${column}", reads ${cell(t, row, column)} while `
        + `data/lto-regate.json records ${v}. One of the two files is wrong.`);
    }
    assert.match(String(row[t.index.get('(ii) graded')]), /HELD/,
      'the Run E row must still grade (ii) as HELD');
  }
  for (const r of clang) {
    assert.equal(r.cells, 113);
    assert.equal(r.retained, r.eliminatedWithoutPlugin);
    assert.equal(r.differsFromTrackedNonLtoRow, 0);
    assert.equal(r.dryRunHeld.num, r.dryRunHeld.den);
    assert.equal(r.linkLineGradedHeld, true);
    assert.equal(r.relinksIdentical.num, r.relinksIdentical.den);
    assert.equal(r.linkLineLinks, r.cells * r.forms,
      'the (ii) link count is one per cell per side, so it is cells x forms');
  }
});

test("the gcc figures are the ones LTO.md's gcc Run A -O2 row carries, read back out of it", () => {
  const t = table('run', 'level');
  const runA = t.rows.filter((r) => r[0] === 'A' && r[1] === '`-O2`' && ints(r).includes(1296));
  assert.equal(runA.length, 1,
    `found ${runA.length} gcc Run A -O2 row(s) in LTO.md (expected one, ending in 1296/1296 `
    + 'relinks); the PARSE broke, or the table changed shape');
  const gcc = RECORD.runs.filter((r) => r.cc === 'gcc-13');
  for (const [column, v] of [
    ['cells', gcc[0].cells],
    ['eliminated without the plugin (LTO)', gcc[0].eliminatedWithoutPlugin],
    ['differs from the tracked non-LTO row', gcc[0].differsFromTrackedNonLtoRow],
    ['`RETAINED`', gcc[0].retained],
    ['`ALREADY_SURVIVED`', gcc[0].alreadySurvived],
    ['dry run (iii)', gcc[0].dryRunHeld.num],
    ['(ii) links', gcc[0].linkLineLinks],
    ['(ii) refusals, each link', gcc[0].linkLineRefusalsPerLink],
    ['relink comparisons identical', gcc[0].relinksIdentical.num],
  ]) {
    assert.equal(cell(t, runA[0], column), v,
      `LTO.md's gcc Run A -O2 row, column "${column}", reads ${cell(t, runA[0], column)} while `
      + `data/lto-regate.json records ${v}`);
  }
  for (const r of gcc) {
    assert.equal(r.cells, 108);
    assert.equal(r.forms, 1, 'gcc has one LTO form; a 2 here means the record was copied from clang');
    assert.equal(r.retained, r.eliminatedWithoutPlugin);
    assert.equal(r.differsFromTrackedNonLtoRow, 0);
    assert.equal(r.linkLineRefusalsPerLink, 2,
      'WipePinGcc is refused by lto1 twice per link because lto1 runs twice (wpa + 1 ltrans)');
    assert.equal(r.relinksIdentical.num, r.cells * r.forms * 12,
      'gcc relink comparisons are 1296 over 108 cells; a change here means the probe changed what '
      + 'it compares and the record was not re-taken');
  }
});

test('LTO.md says its own figures predate the gate, and points at this record', () => {
  // The other half of closing this. Re-running is evidence; a reader of LTO.md who
  // never opens data/ has to be told that the tables there were taken before the
  // gate existed and where the gated run is written down.
  assert.match(LTO_MD, /gate/,
    'tools/LTO.md contains no mention of the gate. Every figure in it was measured before '
    + 'compiler/eval/spike\'s gate was wired into the probes on 2026-09-12, and a reader cannot '
    + 'know that from the file.');
  assert.match(LTO_MD, /lto-regate\.json/,
    'tools/LTO.md must point at data/lto-regate.json, which is where the gated re-measurement is');
});

test('what was NOT re-measured is named, and the single-machine limit with it', () => {
  assert.ok(Array.isArray(RECORD.notMeasuredHere) && RECORD.notMeasuredHere.length >= 3);
  const text = RECORD.notMeasuredHere.join(' ');
  for (const [what, re] of [
    ['the levels other than -O2', /-O1/],
    ['the --all-removable runs', /all-removable/],
    ['that one host is not replication', /independent replication/],
  ]) {
    assert.match(text, re, `notMeasuredHere does not name ${what}`);
  }
  assert.equal(RECORD.scope.level, '-O2 only');
});

test('the record carries integers and no path that names a machine', () => {
  const raw = readFileSync(path.join(LANE, 'data', 'lto-regate.json'), 'utf8');
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
