/**
 * The tracked record's rules, over synthetic runs.
 *
 * Nothing here reads `../data/`. These tests are about the three fences the
 * record is written behind -- full runs only, integers only, no machine path --
 * and each one is tested by trying to get past it. `test/data.test.mjs` is the
 * other half: it reads the real record and checks it against the README.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  buildRecord, writeRecord, writeDataRefusals, nonIntegerNumbers, versionTriple,
  dataFileName, dataPathFor, REQUIRED_LEVELS, SCHEMA, DATA_DIR,
} from '../lib/record.mjs';
import { tabulate, laneVerdict, STRATUM, O2_VOCAB, O3_VOCAB } from '../lib/agreement.mjs';

/** A full run's arguments -- the only shape `--write-data` accepts. */
const FULL = Object.freeze({
  dryRun: false, ids: null, write: true, observer: '/x/libPropertyObserver.so',
  ccs: ['clang-18'], opts: ['-O0', '-O2'], perBucket: 24, diagnoseCallSites: true,
});

const o2 = (finalState, control = 'PRESENT') => ({
  finalState, control, firstLossPass: finalState === 'LOST' ? 'DSEPass' : null,
  subjectResolutionExit: 0, compiled: true, compileError: null,
});
const pair = (id, opt, verdict, state) => ({
  id, cc: 'clang-18', opt, fn: `wipe_${id}`, idiom: 'both', nSpans: 1,
  o1: { verdict, control: 'PRESENT', control_via: 'asm' },
  o2: state === null ? null : o2(state),
});

function synthetic() {
  const pairs = [
    pair('a', '-O2', 'WIPE_ELIMINATED', 'LOST'),
    pair('b', '-O2', 'WIPE_SURVIVED', 'PRESENT'),
    pair('c', '-O2', 'WIPE_SURVIVED', 'LOST'),
    pair('d', '-O2', 'WIPE_SURVIVED', 'ABSENT'),
    pair('e', '-O0', 'WIPE_SURVIVED', 'ABSENT'),
  ];
  const tab = tabulate(pairs);
  return {
    pairs,
    tab,
    verdict: laneVerdict(tab),
    chosen: pairs.map((p) => ({ id: p.id, cc: p.cc, opt: p.opt, fn: p.fn, idiom: p.idiom, nSpans: p.nSpans, o1: p.o1 })),
  };
}

function record(extra = {}) {
  const s = synthetic();
  return buildRecord({
    tab: s.tab,
    verdict: s.verdict,
    chosen: s.chosen,
    pairs: s.pairs,
    args: FULL,
    toolchain: { version: '18.1.3', vendor: 'clang' },
    plugin: { basename: 'libPropertyObserver.so', sha256: 'a'.repeat(64) },
    // Added when the lane grew a second second-oracle. The vocabulary is
    // REQUIRED rather than defaulted: a record that did not say which
    // instrument it is of would describe a gcc run as a run of the pass
    // observer gcc does not load, and the four table keys would be the wrong
    // four. `buildRecord refuses a record that cannot name its second oracle`
    // below is the test for the refusal.
    vocab: O2_VOCAB,
    rows: { file: '(tracked default)', sha256: 'b'.repeat(64) },
    generatedAt: '2026-09-12T00:00:00.000Z',
    node: process.version,
    ...extra,
  });
}

// ------------------------------------------------------- full runs only ------

test('a full run is accepted and every partial one is refused, with the reason named', () => {
  assert.deepEqual(writeDataRefusals(FULL), []);
  const cases = [
    [{ dryRun: true }, /dry-run/],
    [{ ids: ['fable_E_dbpass_r3'] }, /--ids/],
    [{ write: false }, /--no-write/],
    [{ observer: null }, /--observer/],
    [{ ccs: ['clang-18', 'gcc-13'] }, /more than one --cc/],
    [{ opts: ['-O2'] }, /-O0/],
    [{ opts: ['-O0'] }, /-O2/],
    [{ diagnoseCallSites: false }, /--diagnose-callsites/],
  ];
  for (const [patch, re] of cases) {
    const why = writeDataRefusals({ ...FULL, ...patch });
    assert.ok(why.length, `${JSON.stringify(patch)} was accepted`);
    assert.ok(why.some((w) => re.test(w)), `${JSON.stringify(patch)}: ${why.join('; ')}`);
  }
});

test('both strata are required, because -O0 is the one that must be tabulated apart', () => {
  assert.deepEqual([...REQUIRED_LEVELS], ['-O0', '-O2']);
  // A run that adds a level is still full; a run that drops one is not.
  assert.deepEqual(writeDataRefusals({ ...FULL, opts: ['-O0', '-O1', '-O2', '-O3'] }), []);
});

// ---------------------------------------------------- integers only ----------

test('nonIntegerNumbers finds a percentage wherever it is buried', () => {
  assert.deepEqual(nonIntegerNumbers({ a: 1, b: [2, 3], c: { d: 4 } }), []);
  assert.deepEqual(nonIntegerNumbers({ agreement: 0.96 }), ['agreement']);
  assert.deepEqual(nonIntegerNumbers({ strata: [{ rate: 96.0001 }] }), ['strata[0].rate']);
  // 96.0 is an integer in JSON and that is fine: the rule is about a number
  // that cannot be a count, not about a number somebody typed with a point.
  assert.deepEqual(nonIntegerNumbers({ n: 96.0 }), []);
});

test('the built record carries no float anywhere, and rates are integer pairs', () => {
  const r = record();
  assert.deepEqual(nonIntegerNumbers(r), []);
  const above = r.strata.find((s) => s.name === STRATUM.ABOVE_O0);
  assert.deepEqual(above.diagonal, { num: 2, den: 3 });
  assert.equal(above.den, 3);
  assert.equal(r.aboveO0.den, 3);
  // and nowhere a percentage sign or a `%` field, which is the other way a rate
  // gets into a file people quote
  assert.ok(!JSON.stringify(r).includes('%'));
});

test('a float reaching the record is refused and NOTHING is written', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oa-rec-'));
  const r = record();
  r.strata[1].agreementRate = 0.96;
  const res = writeRecord(r, { cc: 'clang-18', dir });
  assert.equal(res.written, false);
  assert.deepEqual(res.floats, ['strata[1].agreementRate']);
  assert.equal(existsSync(dataPathFor('clang-18', dir)), false);
  assert.deepEqual(readdirSync(dir), []);
});

// ------------------------------------------------ no machine in the file -----

test('an absolute path reaching the record is refused and NOTHING is written', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oa-rec-'));
  const r = record();
  // Assembled rather than written, following test/lane.test.mjs: this file is
  // itself scanned for absolute paths by that test's hygiene sweep.
  r.plugin = { basename: ['', 'home', 'someone', 'libPropertyObserver.so'].join('/'), sha256: 'a'.repeat(64) };
  const res = writeRecord(r, { cc: 'clang-18', dir });
  assert.equal(res.written, false);
  assert.ok(res.hits.length, 'the path scan did not fire');
  assert.equal(existsSync(dataPathFor('clang-18', dir)), false);
});

test('the compiler version is reduced to a triple, so its install directory is not recorded', () => {
  assert.equal(versionTriple('Ubuntu clang version 18.1.3 (1ubuntu1)'), '18.1.3');
  assert.equal(versionTriple('gcc (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0'), null);
  assert.equal(versionTriple(''), null);
  assert.equal(versionTriple(null), null);
});

// ------------------------------------------------------------ the file -------

test('one file per compiler, named after it, in this lane’s own data directory', () => {
  assert.equal(dataFileName('clang-18'), 'oracle-agreement-clang-18.json');
  assert.equal(dataFileName('/usr/bin/gcc-13'), 'oracle-agreement-gcc-13.json');
  assert.ok(DATA_DIR.endsWith(join('oracle-agreement', 'data')));
});

test('a written record round-trips, and the file is the text that was scanned', () => {
  const dir = mkdtempSync(join(tmpdir(), 'oa-rec-'));
  const res = writeRecord(record(), { cc: 'clang-18', dir });
  assert.equal(res.written, true);
  const back = JSON.parse(readFileSync(res.path, 'utf8'));
  assert.equal(back.schemaVersion, SCHEMA);
  assert.equal(readFileSync(res.path, 'utf8'), res.text);
});

test('the record enumerates the cells the run observed rather than leaving them derivable', () => {
  const r = record();
  assert.equal(r.selected, 5);
  assert.deepEqual(r.selectedCells.map((c) => c.id), ['a', 'b', 'c', 'd', 'e']);
  for (const c of r.selectedCells) assert.ok(c.o1 && c.cc && c.opt && c.fn);
});

test('the record keeps the two accountings apart: what was selected, and what the stratum is over', () => {
  // The README's exclusion table and its call-site table are both over the
  // above-`-O0` stratum, and its row is labelled "cells selected". The record
  // carries both numbers so the two can never be read as one.
  const r = record();
  assert.equal(r.selected, 5);
  assert.equal(r.aboveO0.accountedFor, 4);
  const at0 = r.strata.find((s) => s.name === STRATUM.AT_O0);
  assert.equal(at0.den, 0);
  assert.equal(at0.accountedFor, 1);
  assert.equal(r.accountedFor, 5);
});

test('the off-diagonal is recorded by id, with both verdicts and the pass', () => {
  const above = record().strata.find((s) => s.name === STRATUM.ABOVE_O0);
  assert.equal(above.offDiagonal.length, 1);
  assert.deepEqual(above.offDiagonal[0], {
    id: 'c', cc: 'clang-18', opt: '-O2', cell: 'SURVIVED/LOST',
    o1: 'WIPE_SURVIVED', o2: 'LOST', firstLossPass: 'DSEPass', idiom: 'both',
  });
});

test('every excluded cell is listed by id and kind -- a count with no names is a quiet drop', () => {
  const above = record().strata.find((s) => s.name === STRATUM.ABOVE_O0);
  assert.equal(above.excludedTotal, 1);
  assert.equal(above.excludedByKind.NOT_COMPARABLE, 1);
  assert.deepEqual(above.excludedIds.map((c) => c.id), ['d']);
  assert.equal(above.excludedIds[0].reason, 'o2-not-a-reading');
  assert.equal(above.excludedIds[0].detail, 'ABSENT');
});

test('the record carries the exit code and what it means, not just the table', () => {
  const r = record();
  assert.equal(r.exit, r.verdict.exit);
  assert.equal(typeof r.verdict.readable, 'boolean');
  assert.ok(r.oracles.O1.includes('verdictOf'));
  assert.ok(r.oracles.O2.includes('PropertyObserver'));
});

test('the call-site diagnosis is carried with its provenance, or the field is null', () => {
  assert.equal(record().irCallSites, null);
  const withSplit = record({
    callSites: {
      provenance: 'tool', cells: 48, generations: 48,
      split: { excludedZero: 23, excludedNonZero: 0, gradedZero: 0, gradedNonZero: 25 },
      perfect: true,
    },
  });
  assert.equal(withSplit.irCallSites.provenance, 'tool');
  assert.deepEqual(nonIntegerNumbers(withSplit), []);
});

// ------------------------------- the second oracle the record is OF ----------
//
// Added when the lane grew a gcc-side second oracle. Until then there was one
// second instrument and the record could name it in a literal; with two, a
// literal is a record that describes the run that did not happen.

test('buildRecord refuses a record that cannot name its second oracle', () => {
  assert.throws(() => record({ vocab: undefined }), /which second oracle/);
});

test('the record names the second oracle and its two column headings', () => {
  const r = record();
  assert.equal(r.secondOracle.name, 'O2');
  assert.equal(r.secondOracle.gone, 'LOST');
  assert.equal(r.secondOracle.kept, 'PRESENT');
  assert.ok(r.oracles.O2, 'the record does not describe O2');
  assert.equal(r.oracles.O3, undefined, 'an O2 record describes an oracle that did not run');
});

test('an O3 record carries O3’s own four table keys, not O2’s', () => {
  // The table is copied from the stratum rather than from four spelled keys.
  // Four literals would have dropped every graded cell of a gcc run and left a
  // denominator that disagreed with its own table.
  const pairs = [
    { id: 'g1', cc: 'gcc-13', opt: '-O2', fn: 'wipe_g1', idiom: 'removable', nSpans: 1,
      o1: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT', control_via: 'asm' },
      o2: { finalState: 'ABSENT', control: 'PRESENT' } },
    { id: 'g2', cc: 'gcc-13', opt: '-O2', fn: 'wipe_g2', idiom: 'nonremovable', nSpans: 1,
      o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT', control_via: 'asm' },
      o2: { finalState: 'PRESENT', control: 'PRESENT' } },
    { id: 'g3', cc: 'gcc-13', opt: '-O0', fn: 'wipe_g3', idiom: 'nonremovable', nSpans: 1,
      o1: { verdict: 'WIPE_SURVIVED', control: 'PRESENT', control_via: 'asm' },
      o2: { finalState: 'PARTIAL', control: 'PRESENT' } },
  ];
  const tab = tabulate(pairs, { vocab: O3_VOCAB });
  const r = buildRecord({
    tab,
    verdict: laneVerdict(tab),
    chosen: pairs.map((p) => ({ id: p.id, cc: p.cc, opt: p.opt, fn: p.fn, idiom: p.idiom, nSpans: p.nSpans, o1: p.o1 })),
    pairs,
    args: { ...FULL, ccs: ['gcc-13'], observer: null, diagnoseCallSites: false, secondOracle: 'O3' },
    toolchain: { version: '13.3.0', vendor: 'gcc' },
    plugin: null,
    vocab: O3_VOCAB,
    instrument: { reader: 'read-wipe.py', objdump: 'GNU objdump 2.42' },
    rows: { file: '(tracked default)', sha256: 'b'.repeat(64) },
    generatedAt: '2026-09-14T00:00:00.000Z',
    node: process.version,
  });
  const above = r.strata.find((s) => s.name === STRATUM.ABOVE_O0);
  assert.deepEqual(Object.keys(above.table).sort(),
    ['ELIMINATED/ABSENT', 'ELIMINATED/PRESENT', 'SURVIVED/ABSENT', 'SURVIVED/PRESENT']);
  assert.equal(above.table['ELIMINATED/ABSENT'], 1);
  assert.equal(above.table['SURVIVED/PRESENT'], 1);
  assert.equal(above.den, 2);
  assert.equal(above.columns.oracle, 'O3');
  assert.equal(r.secondOracle.name, 'O3');
  assert.equal(r.plugin, null);
  // PARTIAL is at -O0 here and is NOT_COMPARABLE, never folded into ABSENT.
  const atO0 = r.strata.find((s) => s.name === STRATUM.AT_O0);
  assert.equal(atO0.excludedTotal, 1);
  assert.equal(atO0.excludedByKind.NOT_COMPARABLE, 1);
});

test('an O3 run may not be recorded while naming a plugin it never loaded', () => {
  const why = writeDataRefusals({
    ...FULL, ccs: ['gcc-13'], secondOracle: 'O3', diagnoseCallSites: false, observer: null,
  });
  assert.deepEqual(why, [], why.join('; '));
  const withPlugin = writeDataRefusals({
    ...FULL, ccs: ['gcc-13'], secondOracle: 'O3', diagnoseCallSites: false, observer: '/x/libPropertyObserver.so',
  });
  assert.ok(withPlugin.some((w) => /O3 run/.test(w)), withPlugin.join('; '));
});
