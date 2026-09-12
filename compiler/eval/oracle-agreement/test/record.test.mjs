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
import { tabulate, laneVerdict, STRATUM } from '../lib/agreement.mjs';

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
