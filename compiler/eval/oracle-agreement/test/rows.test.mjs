/**
 * The O1 side: indexing the tracked rows, and choosing which cells to observe.
 *
 * Two kinds of test live here and they are worth telling apart.
 *
 * The first kind is arithmetic over rows written in this file, and it holds
 * whatever the corpus says.
 *
 * The second kind RE-DERIVES a fact from `../../ai-generated/data/
 * r2-build-rows.json` -- the tracked, frozen record -- and fails if the ground
 * under a design decision has moved. `../../spike/test/lane.test.mjs` does the
 * same thing to its pre-registered `-O0` expectation, for the same reason: this
 * lane separates `-O0` because that configuration has never recorded an
 * elimination, and if a future re-measurement ever puts one there, the argument
 * for the separation has changed and somebody should have to read it again
 * rather than inherit it.
 *
 * Nothing here compiles anything. The rows file is opened for READING only.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

import {
  loadRows, loadScenarios, indexRows, keyOf, o1Of, selectCells, bucketSizes, sourcePathOf,
  ROWS_PATH, CORPUS_DIR, SCENARIOS_PATH, COMPARABLE_FAMILY,
} from '../lib/rows.mjs';
import { o1ClassOf, stratumOf, STRATUM } from '../lib/agreement.mjs';

const TRACKED = loadRows();
const ERASURE = TRACKED.filter((r) => r.fam === COMPARABLE_FAMILY && r.cc !== undefined);

// ------------------------------------------------------------- synthetic ----

const row = (over = {}) => ({
  id: 'fable_E_aeskey_r1', model: 'fable', framing: 'E', scen: 'aeskey', rep: 'r1',
  fam: 'erasure', fn: 'encrypt_blob', kind: 'erasure', idiom: 'nonremovable',
  cc: 'clang-18', opt: '-O2', n_spans: 1, control: 'PRESENT', control_via: 'oracle',
  verdict: 'WIPE_SURVIVED', ...over,
});

test('keyOf addresses a cell by all three of id, vendor and level', () => {
  assert.equal(keyOf('a', 'clang-18', '-O2'), 'a|clang-18|-O2');
  assert.notEqual(keyOf('a', 'clang-18', '-O2'), keyOf('a', 'clang-18', '-O3'));
  assert.notEqual(keyOf('a', 'clang-18', '-O2'), keyOf('a', 'gcc-13', '-O2'));
});

test('indexRows skips the rows that carry no (vendor, level) pair', () => {
  const ix = indexRows([row(), { id: 'x', fam: 'erasure', verdict: 'NO_WIPE_WRITTEN' }]);
  assert.equal(ix.size, 1);
});

test('indexRows throws on a duplicate key rather than letting one row win silently', () => {
  assert.throws(() => indexRows([row(), row()]), /two rows for fable_E_aeskey_r1\|clang-18\|-O2/);
});

test('o1Of carries the verdict and the control, and null for a missing row', () => {
  assert.deepEqual(o1Of(row()), { verdict: 'WIPE_SURVIVED', control: 'PRESENT', control_via: 'oracle' });
  assert.equal(o1Of(null), null);
});

test('o1Of turns an absent control into null rather than into undefined', () => {
  // `classifyPair` compares against 'PRESENT' either way, but a report that
  // serialises `undefined` loses the key entirely and a reader cannot tell a
  // control that was absent from one nobody wrote down.
  const o1 = o1Of(row({ control: undefined, control_via: undefined }));
  assert.equal(o1.control, null);
  assert.equal(o1.control_via, null);
  assert.equal('control' in JSON.parse(JSON.stringify(o1)), true);
});

// ------------------------------------------------------------- selection ----

test('selectCells takes perBucket cells from each (vendor, level, O1 verdict) bucket', () => {
  const rows = [];
  for (let i = 0; i < 10; i++) rows.push(row({ id: `e${i}`, verdict: 'WIPE_ELIMINATED' }));
  for (let i = 0; i < 10; i++) rows.push(row({ id: `s${i}`, verdict: 'WIPE_SURVIVED' }));
  const chosen = selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 3 });
  assert.equal(chosen.length, 6);
  assert.equal(chosen.filter((c) => c.o1.verdict === 'WIPE_ELIMINATED').length, 3);
  assert.equal(chosen.filter((c) => c.o1.verdict === 'WIPE_SURVIVED').length, 3);
});

test('the selection is balanced on purpose, so its marginals are not the corpus rate', () => {
  // 1 eliminated among 20 survived. A proportional sample of 4 would draw zero
  // eliminations and the lane would spend four compiles to learn that it could
  // not ask its question.
  const rows = [row({ id: 'e0', verdict: 'WIPE_ELIMINATED' })];
  for (let i = 0; i < 20; i++) rows.push(row({ id: `s${i}`, verdict: 'WIPE_SURVIVED' }));
  const chosen = selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 4 });
  assert.equal(chosen.filter((c) => c.o1.verdict === 'WIPE_ELIMINATED').length, 1);
  assert.equal(chosen.filter((c) => c.o1.verdict === 'WIPE_SURVIVED').length, 4);
});

test('a bucket smaller than perBucket contributes what it has, without complaint', () => {
  const rows = [row({ id: 'e0', verdict: 'WIPE_ELIMINATED' }), row({ id: 's0', verdict: 'WIPE_SURVIVED' })];
  assert.equal(selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 9 }).length, 2);
});

test('selectCells is deterministic: input order does not change what is chosen', () => {
  const mk = (i) => row({ id: `s${String(i).padStart(2, '0')}`, verdict: 'WIPE_SURVIVED' });
  const forward = [0, 1, 2, 3, 4].map(mk);
  const backward = [4, 3, 2, 1, 0].map(mk);
  const a = selectCells(forward, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 2 }).map((c) => c.id);
  const b = selectCells(backward, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 2 }).map((c) => c.id);
  assert.deepEqual(a, ['s00', 's01']);
  assert.deepEqual(a, b);
});

test('selectCells keeps the vendors and levels apart: each is its own set of buckets', () => {
  const rows = [
    row({ id: 'a', cc: 'clang-18', opt: '-O2', verdict: 'WIPE_ELIMINATED' }),
    row({ id: 'a', cc: 'gcc-13', opt: '-O2', verdict: 'WIPE_ELIMINATED' }),
    row({ id: 'a', cc: 'clang-18', opt: '-O3', verdict: 'WIPE_ELIMINATED' }),
  ];
  const chosen = selectCells(rows, { ccs: ['clang-18', 'gcc-13'], opts: ['-O2', '-O3'], perBucket: 5 });
  assert.equal(chosen.length, 3);
  assert.equal(new Set(chosen.map((c) => `${c.cc}|${c.opt}`)).size, 3);
});

test('only the erasure family is comparable; authz and configguard rows never reach the table', () => {
  const rows = [
    row({ id: 'e', verdict: 'WIPE_ELIMINATED' }),
    row({ id: 'a', fam: 'authz', verdict: 'NDEBUG_NO_EFFECT' }),
    row({ id: 'c', fam: 'configguard', verdict: 'DEFAULT_DIFFERS' }),
  ];
  const chosen = selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 9 });
  assert.deepEqual(chosen.map((c) => c.id), ['e']);
});

test('a row whose O1 verdict is not gradable is not selected -- a compile spent to learn nothing', () => {
  const rows = [row({ id: 'bad', verdict: 'ABLATION_DID_NOT_COMPILE' }), row({ id: 'good', verdict: 'WIPE_SURVIVED' })];
  assert.deepEqual(selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 9 }).map((c) => c.id), ['good']);
});

test('--ids overrides that: a cell named by hand is observed whatever its O1 verdict says', () => {
  const rows = [row({ id: 'bad', verdict: 'ABLATION_DID_NOT_COMPILE' }), row({ id: 'good', verdict: 'WIPE_SURVIVED' })];
  const chosen = selectCells(rows, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 9, ids: ['bad'] });
  assert.deepEqual(chosen.map((c) => c.id), ['bad']);
});

test('a selected cell carries the function name the observer has to be told', () => {
  const [c] = selectCells([row({ verdict: 'WIPE_SURVIVED' })], { ccs: ['clang-18'], opts: ['-O2'], perBucket: 1 });
  assert.equal(c.fn, 'encrypt_blob');
  assert.equal(c.idiom, 'nonremovable');
  assert.equal(c.nSpans, 1);
});

test('selectCells returns nothing for a vendor or level nobody measured', () => {
  assert.equal(selectCells([row()], { ccs: ['clang-19'], opts: ['-O2'], perBucket: 4 }).length, 0);
  assert.equal(selectCells([row()], { ccs: ['clang-18'], opts: ['-Ofast'], perBucket: 4 }).length, 0);
});

test('bucketSizes reports what the selection is drawing from, including the ungradable words', () => {
  const rows = [
    row({ id: 'a', verdict: 'WIPE_ELIMINATED' }),
    row({ id: 'b', verdict: 'WIPE_SURVIVED' }),
    row({ id: 'c', verdict: 'ABLATION_DID_NOT_COMPILE' }),
  ];
  const sizes = bucketSizes(rows, { ccs: ['clang-18'], opts: ['-O2'] });
  assert.equal(sizes['clang-18|-O2|ELIMINATED'], 1);
  assert.equal(sizes['clang-18|-O2|SURVIVED'], 1);
  assert.equal(sizes['clang-18|-O2|other(ABLATION_DID_NOT_COMPILE)'], 1);
});

// ---------------------------------------------- grounded in the tracked rows --

test('the tracked rows are where this lane says they are, and hold an array', () => {
  assert.ok(existsSync(ROWS_PATH), 'r2-build-rows.json is missing');
  assert.ok(Array.isArray(TRACKED));
  assert.ok(TRACKED.length > 4000, `only ${TRACKED.length} rows`);
});

test('4,650 of the tracked rows carry a (vendor, level) pair, and the index holds exactly those', () => {
  // The corrected denominator recorded in section 2.20(c): the README next door
  // said 4,660 for a while and the lane's own output always said 4,650.
  const withCell = TRACKED.filter((r) => r.cc !== undefined && r.opt !== undefined);
  assert.equal(withCell.length, 4650);
  assert.equal(indexRows(TRACKED).size, 4650);
});

test('GROUNDING: the tracked rows record ZERO eliminations at -O0, on either vendor', () => {
  // This is the ground under tabulating -O0 separately. If a re-measurement ever
  // puts an elimination there, this test fails and the separation has to be
  // argued again rather than inherited.
  for (const cc of ['clang-18', 'gcc-13']) {
    const at0 = ERASURE.filter((r) => r.cc === cc && r.opt === '-O0');
    assert.equal(at0.filter((r) => r.verdict === 'WIPE_ELIMINATED').length, 0, cc);
    assert.equal(at0.filter((r) => r.verdict === 'WIPE_SURVIVED').length, 319, cc);
    assert.equal(at0.filter((r) => r.verdict === 'ABLATION_DID_NOT_COMPILE').length, 2, cc);
  }
});

test('GROUNDING: a real -O0 selection is therefore degenerate on O1 by construction', () => {
  const chosen = selectCells(TRACKED, { ccs: ['clang-18'], opts: ['-O0'], perBucket: 8 });
  assert.ok(chosen.length > 0);
  assert.equal(new Set(chosen.map((c) => o1ClassOf(c.o1.verdict))).size, 1, 'more than one O1 class appeared at -O0');
  assert.equal(o1ClassOf(chosen[0].o1.verdict), 'SURVIVED');
  assert.equal(stratumOf(chosen[0].opt), STRATUM.AT_O0);
});

test('GROUNDING: -O2 and above have both O1 words, so a balanced selection there is possible', () => {
  const counts = bucketSizes(TRACKED, { ccs: ['clang-18', 'gcc-13'], opts: ['-O2'] });
  assert.equal(counts['clang-18|-O2|ELIMINATED'], 113);
  assert.equal(counts['clang-18|-O2|SURVIVED'], 206);
  assert.equal(counts['gcc-13|-O2|ELIMINATED'], 108);
  assert.equal(counts['gcc-13|-O2|SURVIVED'], 211);
});

test('a real -O2 selection draws both O1 words, which is what makes the stratum readable', () => {
  const chosen = selectCells(TRACKED, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 6 });
  assert.equal(chosen.length, 12);
  assert.equal(chosen.filter((c) => o1ClassOf(c.o1.verdict) === 'ELIMINATED').length, 6);
  assert.equal(chosen.filter((c) => o1ClassOf(c.o1.verdict) === 'SURVIVED').length, 6);
});

test('every cell a real selection names has a source file in the corpus directory', () => {
  // The rows carry no path, by design -- an absolute path on the measuring
  // machine is a disclosure. This is where the id is turned back into a file,
  // and it is the step that silently produces an empty run when it is wrong.
  assert.ok(existsSync(CORPUS_DIR), 'generated-corpus/r2 is missing');
  const chosen = selectCells(TRACKED, { ccs: ['clang-18', 'gcc-13'], opts: ['-O1', '-O2', '-O3', '-Os'], perBucket: 4 });
  assert.ok(chosen.length >= 32, `only ${chosen.length} cells selected`);
  for (const c of chosen) {
    assert.ok(existsSync(sourcePathOf(c.id)), `no source for ${c.id}`);
  }
});

test('every selected cell names a function the scenario table declares', () => {
  const scen = loadScenarios(SCENARIOS_PATH);
  const chosen = selectCells(TRACKED, { ccs: ['clang-18'], opts: ['-O2'], perBucket: 8 });
  for (const c of chosen) {
    const meta = scen[c.id.split('_')[2]];
    assert.ok(meta, `no scenario for ${c.id}`);
    assert.equal(c.fn, meta.fn, c.id);
    assert.equal(meta.fam, COMPARABLE_FAMILY);
  }
});

test('every erasure row that carries a verdict also carries a PRESENT control', () => {
  // If this stopped being true the O1 control guard in classifyPair would start
  // excluding cells for a reason nobody expected, and the count would move.
  const graded = ERASURE.filter((r) => o1ClassOf(r.verdict) !== null);
  assert.equal(graded.filter((r) => r.control !== 'PRESENT').length, 0);
  assert.equal(graded.length, 3190);
});
