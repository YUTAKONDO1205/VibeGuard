/**
 * The tracked record against the README, number by number.
 *
 * WHAT THIS TEST IS FOR
 *
 * The README's "Measured, 2026-09-12" section is the lane's result: 48 cells,
 * a denominator of 25, 24 on the diagonal, 23 `NOT_COMPARABLE`, one off-diagonal
 * id, exit 2, and a 48-of-48 call-site split underneath. Until `--write-data`
 * existed, every one of those was prose. Prose does not disagree with anything;
 * it just becomes wrong quietly, and the first person to notice is whoever tries
 * to reproduce the run months later.
 *
 * So this file reads BOTH sides -- the record in `../data/` and the numbers
 * parsed straight out of `../README.md` -- and fails when they part company. The
 * direction of the check matters: it does not verify that the run was right, it
 * verifies that the document and the artefact are about the SAME run.
 *
 * IT FAILS UNTIL THE RECORD EXISTS, AND THAT IS THE POINT. The record is written
 * by a lab run with a compiler and the observer plugin; it cannot be produced
 * here, and it must not be faked. A skip would let the lane look green while its
 * central claim rests on a paragraph -- the exact failure mode this lane's own
 * exit-code contract was written against (a check that could not be completed
 * must never be readable as a check that passed). The failure message names the
 * command that ends it.
 *
 * WHAT IT DOES NOT CLAIM. It does not re-run the comparison and it does not
 * recompute a verdict. The one thing it does re-derive is the SELECTION, which
 * it can: `../lib/rows.mjs` `selectCells` sorts its buckets and its ids and
 * takes a prefix, so the same arguments over the same tracked rows choose the
 * same cells on any machine. See the determinism test at the end.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { nonIntegerNumbers, dataFileName, SCHEMA } from '../lib/record.mjs';
import { STRATUM } from '../lib/agreement.mjs';
import { loadRows, selectCells, ROWS_PATH } from '../lib/rows.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const DATA = join(LANE, 'data');
const CC = 'clang-18';
const RECORD_PATH = join(DATA, dataFileName(CC));
const README = readFileSync(join(LANE, 'README.md'), 'utf8');

/** The command that ends the failure below. Printed, not guessed at. */
const HOW = 'node compiler/eval/oracle-agreement/run-oracle-agreement.mjs'
  + ' --observer ~/vg-build/pass-observer/libPropertyObserver.so'
  + ' --cc clang-18 --opt -O0,-O2 --per-bucket 24 --diagnose-callsites --write-data'
  + ' --out ~/vg-lab/oracle-agreement';

let recordText = null;
function load() {
  if (recordText === null) {
    if (!existsSync(RECORD_PATH)) {
      throw new Error(
        `compiler/eval/oracle-agreement/data/${dataFileName(CC)} does not exist, so the README's measured `
        + 'numbers are not backed by anything this suite can read. This is NOT a skip: run the lane with '
        + `--write-data and the record appears.\n    ${HOW}`,
      );
    }
    recordText = readFileSync(RECORD_PATH, 'utf8');
  }
  return JSON.parse(recordText);
}

/** One number out of the README, or a failure naming the line that went missing. */
function readme(re, what, group = 1) {
  const m = re.exec(README);
  assert.ok(m, `the README no longer states ${what} in the shape this test reads (${re})`);
  return m[group];
}
const num = (re, what, group = 1) => Number.parseInt(readme(re, what, group), 10);

const aboveOf = (r) => {
  const s = r.strata.find((x) => x.name === STRATUM.ABOVE_O0);
  assert.ok(s, 'the record has no above--O0 stratum');
  return s;
};

// ---------------------------------------------------------- the file ---------

test('the tracked record exists, and it is the only thing in data/', () => {
  load();
  assert.deepEqual(readdirSync(DATA).filter((f) => !f.startsWith('.')).sort(), [dataFileName(CC)]);
});

test('the record declares its schema, its lane and the compiler it is of', () => {
  const r = load();
  assert.equal(r.schemaVersion, SCHEMA);
  assert.equal(r.lane, 'oracle-agreement');
  assert.equal(r.toolchain.cc, CC);
  assert.ok(r.plugin.basename && /^[0-9a-f]{64}$/.test(r.plugin.sha256), 'the observer build is not identified');
  assert.ok(/^[0-9a-f]{64}$/.test(r.rows.sha256), 'the O1 rows are not identified by digest');
  // Both halves were measured on different days; a record that names only one
  // build cannot be re-read after a toolchain change.
  assert.ok(r.toolchain.version, 'the record does not name the compiler version');
});

test('the record carries no float and no percentage -- a rate is an integer pair', () => {
  const r = load();
  assert.deepEqual(nonIntegerNumbers(r), [], 'the record carries a number that is not a count');
  assert.ok(!recordText.includes('%'), 'the record carries a percentage sign');
  const above = aboveOf(r);
  assert.equal(typeof above.diagonal.num, 'number');
  assert.equal(typeof above.diagonal.den, 'number');
});

test('the record carries no absolute path, no host and no account name', () => {
  load();
  assert.deepEqual(absolutePathHits(recordText), []);
});

test('the record is of a FULL run: both strata, no hand-named ids', () => {
  const r = load();
  assert.equal(r.request.full, true);
  assert.equal(r.request.ids, null);
  for (const lvl of ['-O0', '-O2']) assert.ok(r.request.levels.includes(lvl), `the run did not cover ${lvl}`);
  assert.equal(r.strata.length, 2);
});

// ------------------------------------------------- record against README -----

test('README: the denominator above -O0 is the record’s', () => {
  const above = aboveOf(load());
  assert.equal(above.den, num(/\|\s*denominator above `-O0` after exclusions\s*\|\s*\*\*(\d+)\*\*\s*\|/, 'the denominator'));
});

test('README: the diagonal is the record’s, as both of its integers', () => {
  const above = aboveOf(load());
  const re = /\|\s*on the diagonal\s*\|\s*\*\*(\d+)\s*\/\s*(\d+)/;
  assert.equal(above.diagonal.num, num(re, 'the diagonal', 1));
  assert.equal(above.diagonal.den, num(re, 'the diagonal denominator', 2));
  assert.equal(above.diagonal.den, above.den, 'the diagonal is over a different denominator than the stratum');
  assert.equal(above.agree + above.disagree, above.den, 'the table does not account for its own denominator');
});

test('README: the 48 is the above--O0 stratum, and the record keeps it apart from what was SELECTED', () => {
  // The README's row is labelled "cells selected" and its number is the size of
  // the stratum the exclusion table and the call-site table are both over:
  // 23 excluded + 25 graded. The selector draws more than that for the same
  // command, because the `-O0` cells are selected too and then all excluded.
  // Both numbers are in the record, and conflating them is how a denominator
  // silently changes.
  const r = load();
  const stated = num(/\|\s*cells selected[^|]*\|\s*\**\s*(\d+)\s*\**\s*\|/, 'the cells selected');
  const above = aboveOf(r);
  assert.equal(above.accountedFor, stated);
  assert.equal(above.den + above.excludedTotal, stated);
  assert.ok(r.selected >= stated, `the run selected ${r.selected} cells, fewer than the ${stated} the README accounts for`);
});

test('README: the exclusions, by kind, are the record’s', () => {
  const above = aboveOf(load());
  assert.equal(above.excludedByKind.NOT_COMPARABLE, num(/\*\*`NOT_COMPARABLE`\s*(\d+)\*\*/, 'the NOT_COMPARABLE count'));
  assert.equal(above.excludedByKind.BROKEN_MEASUREMENT, num(/`BROKEN_MEASUREMENT`\s*(\d+)/, 'the BROKEN_MEASUREMENT count'));
  assert.equal(above.excludedByKind.NO_READING, num(/`NO_READING`\s*(\d+)/, 'the NO_READING count'));
  assert.equal(above.excludedIds.length, above.excludedTotal, 'an excluded cell was counted and not named');
  // "all `o2-not-a-reading(ABSENT)`" -- the README's claim about WHY, which is
  // the claim the call-site diagnosis below is a diagnosis OF.
  if (/all `o2-not-a-reading\(ABSENT\)`/.test(README)) {
    for (const c of above.excludedIds) {
      assert.equal(c.reason, 'o2-not-a-reading', `${c.id} was excluded for another reason`);
      assert.equal(c.detail, 'ABSENT', `${c.id} was excluded with detail ${c.detail}`);
    }
  }
});

test('README: the off-diagonal cell is the record’s, by id and by both verdicts', () => {
  const above = aboveOf(load());
  const m = /off-diagonal entries, by id\s*\|\s*`([A-Za-z0-9_]+)`\s*`([^`]+)`[^|]*O1 `([A-Z_]+)` \/ O2 `([A-Z]+)`/.exec(README);
  assert.ok(m, 'the README no longer names its off-diagonal cell in the shape this test reads');
  assert.equal(above.offDiagonal.length, 1, `the record has ${above.offDiagonal.length} off-diagonal cells and the README names one`);
  const [, id, where, o1, o2] = m;
  assert.equal(above.offDiagonal[0].id, id);
  assert.equal(`${above.offDiagonal[0].cc} ${above.offDiagonal[0].opt}`, where);
  assert.equal(above.offDiagonal[0].o1, o1);
  assert.equal(above.offDiagonal[0].o2, o2);
  assert.equal(above.disagree, 1);
});

test('README: the -O0 stratum is stated with the denominator the record holds', () => {
  // This test was written asserting `denominator 0`, because that is what the
  // README said. The first run that produced a record failed it: 23 of the 24
  // -O0 cells are NOT_COMPARABLE and one -- fable_E_dbpass_r3, the only
  // idiom=both file in the selection, so the only one with an IR call site at
  // -O0 -- is comparable and agrees. The README now says so, and this test
  // reads the number out of the record rather than carrying a copy of it.
  const r = load();
  const at0 = r.strata.find((s) => s.name === STRATUM.AT_O0);
  const stated = /\|\s*`-O0` stratum\s*\|([^|]*)\|/.exec(README);
  assert.ok(stated, 'the README no longer has a -O0 stratum row');
  const den = /denominator\*{0,2}\s*\*{0,2}(\d+)/.exec(stated[1]);
  assert.ok(den, `the -O0 row no longer states a denominator: ${stated[1].trim()}`);
  assert.equal(Number(den[1]), at0.den, 'the README and the record disagree about the -O0 denominator');
  const excluded = /(\d+)\s+of\s+(\d+)\s+cells?\s+`NOT_COMPARABLE`/.exec(stated[1]);
  assert.ok(excluded, `the -O0 row no longer states how many cells were excluded: ${stated[1].trim()}`);
  assert.equal(Number(excluded[1]), at0.excludedTotal);
  assert.equal(Number(excluded[2]), at0.accountedFor);
  assert.equal(at0.excludedByKind.NOT_COMPARABLE, at0.excludedTotal);
  assert.equal(at0.den + at0.excludedTotal, at0.accountedFor,
    'graded plus excluded must account for every -O0 cell selected: a cell in neither column is one nobody looked for');
  // A denominator this small cannot discriminate, and the record must not
  // claim otherwise -- the stratum is reported separately for that reason.
  assert.equal(at0.discriminating, false);
});

test('README: the exit code is the record’s, and the comparison was refused', () => {
  const r = load();
  assert.equal(r.exit, num(/\|\s*\*\*exit\*\*\s*\|\s*\*\*(\d+)/, 'the exit code'));
  assert.equal(r.verdict.readable, r.exit === 0);
  if (r.exit === 2) {
    assert.ok(r.verdict.reasons.length, 'exit 2 with no reason recorded');
    assert.ok(aboveOf(r).degenerateO1 || aboveOf(r).degenerateO2 || aboveOf(r).den === 0,
      'the run exited 2 but the record shows a discriminating stratum');
  }
});

// -------------------------------------------- the 48-of-48 call-site split ---

test('the call-site split was counted by a tool, not transcribed from a hand count', () => {
  const cs = load().irCallSites;
  assert.ok(cs, 'the record carries no call-site diagnosis; run with --diagnose-callsites');
  assert.equal(cs.provenance, 'tool');
  assert.ok(Array.isArray(cs.symbols) && cs.symbols.length, 'the diagnosis does not say which symbols it counted');
  // The README names three; the registry list is the one actually counted, and
  // the three have to be in it or the table is about a different question.
  for (const s of ['memset', 'llvm.memset', 'explicit_bzero']) {
    assert.ok(cs.symbols.includes(s), `the diagnosis did not count ${s}, which the README says it counted`);
  }
});

test('README: the 2x2 of exclusions against IR call sites is the record’s', () => {
  const cs = load().irCallSites;
  const ex = /\|\s*excluded, O2 `ABSENT` \((\d+)\)\s*\|\s*\*\*(\d+)\*\*\s*\|\s*(\d+)\s*\|/.exec(README);
  const gr = /\|\s*graded by both \((\d+)\)\s*\|\s*(\d+)\s*\|\s*\*\*(\d+)\*\*\s*\|/.exec(README);
  assert.ok(ex && gr, 'the README no longer prints the call-site table in the shape this test reads');
  assert.equal(cs.split.excludedZero, Number.parseInt(ex[2], 10));
  assert.equal(cs.split.excludedNonZero, Number.parseInt(ex[3], 10));
  assert.equal(cs.split.gradedZero, Number.parseInt(gr[2], 10));
  assert.equal(cs.split.gradedNonZero, Number.parseInt(gr[3], 10));
  // the row labels are counts too, and they are the stratum's own
  const above = aboveOf(load());
  assert.equal(Number.parseInt(ex[1], 10), above.excludedTotal);
  assert.equal(Number.parseInt(gr[1], 10), above.den);
});

test('README: "a perfect split, 48 of 48" is a statement the record makes', () => {
  const cs = load().irCallSites;
  const m = /\*\*A perfect split, (\d+) of (\d+)\.\*\*/.exec(README);
  assert.ok(m, 'the README no longer claims a perfect split');
  assert.equal(Number.parseInt(m[1], 10), Number.parseInt(m[2], 10), 'the README claims a perfect split of unequal numbers');
  assert.equal(cs.cells, Number.parseInt(m[2], 10));
  assert.equal(cs.perfect, true, 'the README claims a perfect split and the record does not show one');
  const s = cs.split;
  assert.equal(s.excludedZero + s.excludedNonZero + s.gradedZero + s.gradedNonZero, cs.cells);
});

test('README: the intersection of the two oracles’ domains is the record’s', () => {
  const cs = load().irCallSites;
  const m = /intersection on this corpus is (\d+) of (\d+) cells/.exec(README);
  assert.ok(m, 'the README no longer states the intersection');
  assert.equal(aboveOf(load()).den, Number.parseInt(m[1], 10));
  assert.equal(cs.cells, Number.parseInt(m[2], 10));
});

// ------------------------------------------------- the selection, re-derived --

test('the selection in the record is the one selectCells makes -- it is deterministic', () => {
  // `../lib/rows.mjs` sorts the bucket keys and the ids inside each bucket and
  // takes a prefix (selectCells, the two lines after `const chosen = []`). There
  // is no randomness and no reliance on an object's key order, so the same
  // arguments over the same rows choose the same cells anywhere. That is what
  // makes this a re-derivation rather than a second sample.
  const r = load();
  if (r.rows.file !== '(tracked default)') return; // a run over other rows cannot be re-derived from these
  const again = selectCells(loadRows(ROWS_PATH), {
    ccs: [CC], opts: r.request.levels, perBucket: r.request.perBucket,
  });
  assert.deepEqual(
    again.map((c) => `${c.id}|${c.cc}|${c.opt}`),
    r.selectedCells.map((c) => `${c.id}|${c.cc}|${c.opt}`),
    'the tracked rows no longer select the cells this record was measured over',
  );
});

test('every off-diagonal and excluded id was one of the cells the record says it selected', () => {
  const r = load();
  const selected = new Set(r.selectedCells.map((c) => `${c.id}|${c.cc}|${c.opt}`));
  for (const s of r.strata) {
    for (const c of [...s.offDiagonal, ...s.excludedIds]) {
      assert.ok(selected.has(`${c.id}|${c.cc}|${c.opt}`), `${c.id} ${c.cc} ${c.opt} is reported but was never selected`);
    }
  }
  assert.equal(r.observed, r.selected, 'the run observed a different number of cells than it selected');
  assert.equal(r.accountedFor, r.strata.reduce((n, s) => n + s.accountedFor, 0));
});
