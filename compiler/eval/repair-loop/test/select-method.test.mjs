/**
 * tools/lib/select-method.mjs and tools/select-method.mjs: the r6b auto-loop's
 * choice of repair method, replayed without a compiler.
 *
 * What these tests can and cannot show. The loop files the tool replays live
 * outside this repository (README.md, *Choosing the next method*: 318/318 rows
 * of r6b's E1 with the learned table, and every row of its cold, E3 and E5 runs,
 * agreed when replayed in the lab). Nothing here reads them. The rows below are
 * synthetic, written in the shape vgloop.mjs wrote, and what they pin is the
 * selection order (table -> declarations -> partial declarations -> route), the
 * record-driven second choice, the outcome rules, and that a replay notices a
 * row whose choice was changed. The method set itself is the tracked copy,
 * ../tools/select-method.r6b.json: a method is a repair a person wrote, and the
 * only thing that grows from measurement is the table, by learnRows.
 *
 * No compiler is run. The CLI is spawned with node on files under os.tmpdir().
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  SET_SCHEMA, CONDS, MAX_ATTEMPTS, validateSet, methodsFor, covers, byClaims, byPartialClaims, route, fromTable,
  shapesFromRecord, stageOf, firstSelection, nextSelection, selectMethod, replayLoop, compareLoopRow, learnRows,
} from '../tools/lib/select-method.mjs';
import { loopFileProblems, checkLoopDoc, tableSelectionSha16 } from '../tools/select-method.mjs';
import { UNHANDLED_KEYS } from '../lib/pin-record.mjs';
import { absolutePathHits } from '../lib/provenance.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');
const SET_PATH = path.join(LANE, 'tools', 'select-method.r6b.json');
const SET_TEXT = readFileSync(SET_PATH, 'utf8');
const SET = JSON.parse(SET_TEXT);
const CLI = path.join(LANE, 'tools', 'select-method.mjs');
const COLD = SET.tables.cold;
const LEARNED = SET.tables.learned;
const sha16Of = (name) => SET.copiedFrom.files.find((f) => f.file === `table-${name}.json`).loopSha16;
const PLUGINS = Object.fromEntries(Object.entries(SET.methods).map(([n, m]) => [n, m.pluginSha16]));

const U = (over = {}) => ({ libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0, bzeroCall: 0, inlineWrapperBzero: 0, ...over });
const IR = { cls: 'ir', pass: 'DSEPass', index: 40 };
const GIMPLE = { cls: 'gimple', pass: 'dse1' };

/** One iteration as vgloop.mjs wrote it (apply()'s fields, the record itself dropped). */
const iter = (k, why, method, verdict, { fromTable = false, pinned = 1, unhandled = U(), component = 'WipePin', rediagnosis } = {}) => ({
  k, why, fromTable, method, verdict, pinned, unhandled, component, ...(rediagnosis ? { rediagnosis } : {}),
});

// ---------------------------------------------------------------- the set ----

test('the copied method set validates, and is the r6b set: four methods a person wrote, two tables', () => {
  assert.deepEqual(validateSet(SET), []);
  assert.equal(SET.schemaVersion, SET_SCHEMA);
  assert.deepEqual(Object.keys(SET.methods).sort(), ['wipepin-barrier', 'wipepin-volatile', 'wipepingcc', 'wipepingcc-barrier']);
  for (const [n, m] of Object.entries(SET.methods)) {
    assert.ok(m.source.length > 20, `${n}: says where its claims were copied from`);
    assert.match(m.pluginSha16, /^[0-9a-f]{16}$/, `${n}: the plugin build the loop used`);
  }
  assert.deepEqual(SET.default, { 'clang-18': 'wipepin-volatile', 'gcc-13': 'wipepingcc' });
  assert.equal(COLD.rows.length, 2);
  // learned = cold + the four rows learn.py adopted from E1, and every row cites its run
  assert.equal(LEARNED.rows.length, 6);
  assert.deepEqual(LEARNED.rows.slice(0, 2), COLD.rows);
  for (const r of LEARNED.rows) assert.match(r.evidence, /\((poster\/v36\/exp_r4\/cut|data\/e1\/loop-cold\.json)\)$/, r.evidence);
  // copied from three files, each by sha256; the two tables also by the digest the loop rows name them by
  assert.deepEqual(SET.copiedFrom.files.map((f) => f.file), ['methods.json', 'table-cold.json', 'table-learned.json']);
  for (const f of SET.copiedFrom.files) assert.match(f.sha256, /^[0-9a-f]{64}$/);
  assert.equal(sha16Of('cold'), 'e9bd64ba35ee7c95');
  assert.equal(sha16Of('learned'), '61f3d53127a35fa6');
});

test('the copy carries no machine path (the plugin paths of the lab were left out)', () => {
  assert.deepEqual(absolutePathHits(SET_TEXT), []);
  for (const m of Object.values(SET.methods)) assert.ok(!('so' in m), 'no plugin path');
});

test('validateSet refuses a table row that names a method the set does not hold, or another compiler\'s', () => {
  const s = structuredClone(SET);
  s.tables.learned.rows.push({ cc: 'gcc-13', stage: 'gimple', shape: 'memset-chk', method: 'wipepin-barrier', evidence: 'x' });
  s.tables.learned.rows.push({ cc: 'gcc-13', stage: 'gimple', shape: 'bzero-call', method: 'no-such', evidence: 'x' });
  s.tables.cold.rows.push({ ...s.tables.cold.rows[0] });
  delete s.methods['wipepingcc-barrier'].source;
  const p = validateSet(s);
  assert.ok(p.some((x) => /gives gcc-13 the clang-18 method wipepin-barrier/.test(x)), p.join('\n'));
  assert.ok(p.some((x) => /names method no-such/.test(x)));
  assert.ok(p.some((x) => /repeats the cell clang-18\|ir\|dead-store-memset-intrinsic/.test(x)));
  assert.ok(p.some((x) => /wipepingcc-barrier\.source must say where the claims were copied from/.test(x)));
});

// ----------------------------------------------------------- the four steps ----

test('methodsFor and covers: per compiler, by order; a method covers shapes it declares, all of them', () => {
  assert.deepEqual(methodsFor(SET, 'clang-18').map(([n]) => n), ['wipepin-volatile', 'wipepin-barrier']);
  assert.deepEqual(methodsFor(SET, 'gcc-13').map(([n]) => n), ['wipepingcc', 'wipepingcc-barrier']);
  assert.equal(covers(SET, 'wipepin-barrier', ['inline-wrapper-memset', 'bzero-call']), true);
  assert.equal(covers(SET, 'wipepingcc-barrier', ['inline-wrapper-bzero']), false, 'gcc has no bzero.<suffix>');
});

test('fromTable: every shape needs a row for this compiler and stage; the method must be untried and cover them all', () => {
  assert.deepEqual(fromTable(SET, LEARNED, 'clang-18', IR, ['inline-wrapper-memset'], []),
    { method: 'wipepin-barrier', why: 'table(clang-18,ir,inline-wrapper-memset)', fromTable: true });
  assert.equal(fromTable(SET, COLD, 'clang-18', IR, ['inline-wrapper-memset'], []), null, 'the cold table has no such row');
  assert.equal(fromTable(SET, LEARNED, 'clang-18', { cls: 'after-ir' }, ['dead-store-memset-intrinsic'], []), null, 'no row at that stage');
  assert.equal(fromTable(SET, LEARNED, 'clang-18', IR, ['dead-store-memset-intrinsic'], ['wipepin-volatile']), null, 'already tried');
  // two shapes whose rows name two methods: only one that covers both is taken
  assert.deepEqual(fromTable(SET, LEARNED, 'clang-18', IR, ['dead-store-memset-intrinsic', 'inline-wrapper-memset'], []).method, 'wipepin-barrier');
  assert.equal(fromTable(SET, LEARNED, 'clang-18', IR, [], []), null);
  assert.equal(fromTable(SET, null, 'clang-18', IR, ['dead-store-memset-intrinsic'], []), null);
});

test('byClaims and byPartialClaims: the first full cover by order; else the most shapes covered, ties to the lower order', () => {
  assert.deepEqual(byClaims(SET, 'clang-18', ['memset-chk'], []), { method: 'wipepin-barrier', why: 'claims(memset-chk)' });
  assert.deepEqual(byClaims(SET, 'clang-18', ['dead-store-memset-intrinsic'], []).method, 'wipepin-volatile');
  assert.equal(byClaims(SET, 'clang-18', ['dead-store-memset-intrinsic', 'wipe-written-as-stores'], []), null);
  assert.equal(byClaims(SET, 'clang-18', [], []), null);
  assert.deepEqual(byPartialClaims(SET, 'clang-18', ['dead-store-memset-intrinsic', 'wipe-written-as-stores'], []),
    { method: 'wipepin-volatile', why: 'partial-claims(1/2 of dead-store-memset-intrinsic+wipe-written-as-stores)' });
  assert.deepEqual(byPartialClaims(SET, 'clang-18', ['inline-wrapper-memset', 'wipe-written-as-stores'], []).method, 'wipepin-barrier');
  assert.equal(byPartialClaims(SET, 'clang-18', ['wipe-written-as-stores'], []), null);
});

test('route: a shape the compiler cannot hold goes to the source; anything else to a person, never to a guess', () => {
  assert.deepEqual(route(SET, ['wipe-written-as-stores'], 'L2 stage=ir'),
    { method: null, route: 'SOURCE', why: 'L2 stage=ir; source-side shape wipe-written-as-stores' });
  assert.deepEqual(route(SET, [], 'L2 stage=gimple'), { method: null, route: 'HUMAN', why: 'L2 stage=gimple; no method claims (no shape)' });
  assert.equal(route(SET, ['counter:zeroGlobalCopy'], 'x').route, 'HUMAN');
});

test('shapesFromRecord: counters above 0 through counterToShape; a counter the set has no shape for is kept, not dropped', () => {
  assert.deepEqual(shapesFromRecord(SET, null), { shapes: [], why: 'no-record' });
  const d = shapesFromRecord(SET, { pinnedCount: 0, unhandled: U({ inlineWrapperMemset: 1, bzeroCall: 2 }) });
  assert.deepEqual(d.shapes, ['bzero-call', 'inline-wrapper-memset']);
  assert.equal(d.pinned, 0);
  assert.equal(d.why, `record pinned=0 unhandled=${JSON.stringify(U({ inlineWrapperMemset: 1, bzeroCall: 2 }))}`);
  // the v3 copy counters: the r6b set has no method that claims a copy, so they route to a person
  const v3 = Object.fromEntries(UNHANDLED_KEYS.map((k) => [k, 0]));
  const z = shapesFromRecord(SET, { pinnedCount: 0, unhandled: { ...v3, zeroGlobalCopy: 1, zeroGlobalCopyCall: 1 } });
  assert.deepEqual(z.shapes, ['counter:zeroGlobalCopy', 'counter:zeroGlobalCopyCall']);
  assert.equal(nextSelection({ set: SET, cc: 'clang-18', k: 1, record: { pinnedCount: 0, unhandled: { ...v3, zeroGlobalCopy: 1 } }, tried: ['wipepin-volatile'] })
    .next.route, 'HUMAN');
  assert.equal(shapesFromRecord(SET, { pinnedCount: null, unhandled: U() }).why, `record pinned=- unhandled=${JSON.stringify(U())}`);
});

test('stageOf: clang ir when an IR pass is found and no zero store is left at the end of the IR; gcc gimple when a dump is named', () => {
  assert.deepEqual(stageOf(null, 'clang-18'), { cls: 'unknown', why: 'no-stage-row' });
  assert.deepEqual(stageOf({ status: 'NO_DUMP' }, 'gcc-13'), { cls: 'unknown', why: 'NO_DUMP' });
  assert.deepEqual(stageOf({ status: 'OK', read2: { first: 40, zeroAtEnd: 0, pass: 'DSEPass' } }, 'clang-18'), { cls: 'ir', pass: 'DSEPass', index: 40 });
  assert.equal(stageOf({ status: 'OK', read2: { first: 40, zeroAtEnd: 2 } }, 'clang-18').cls, 'after-ir');
  assert.deepEqual(stageOf({ status: 'OK', read2: { first: { key: 'dse1' } } }, 'gcc-13'), { cls: 'gimple', pass: 'dse1' });
  assert.equal(stageOf({ status: 'OK', read2: { first: null, zeroAtEnd: 1 } }, 'gcc-13').cls, 'after-gimple');
});

test('firstSelection: L0 and L1 take the compiler\'s default; L2 reads the table, then the declarations, then routes', () => {
  assert.deepEqual(firstSelection({ set: SET, table: LEARNED, cc: 'clang-18', cond: 'L0' }), { method: 'wipepin-volatile', why: 'default' });
  assert.deepEqual(firstSelection({ set: SET, table: LEARNED, cc: 'gcc-13', cond: 'L1' }), { method: 'wipepingcc', why: 'default' });
  assert.equal(firstSelection({ set: SET, table: LEARNED, cc: 'clang-18', cond: 'L2', stage: IR, shapes: ['inline-wrapper-memset'] }).fromTable, true);
  assert.equal(firstSelection({ set: SET, table: COLD, cc: 'clang-18', cond: 'L2', stage: IR, shapes: ['inline-wrapper-memset'] }).why,
    'claims(inline-wrapper-memset)');
  assert.equal(firstSelection({ set: SET, table: LEARNED, cc: 'gcc-13', cond: 'L2', stage: GIMPLE, shapes: ['wipe-written-as-stores'] }).route, 'SOURCE');
  assert.equal(firstSelection({ set: SET, table: LEARNED, cc: 'gcc-13', cond: 'L2', stage: null, shapes: [] }).why,
    'L2 stage=unknown; no method claims (no shape)');
  assert.throws(() => firstSelection({ set: SET, cc: 'clang-18', cond: 'L3' }), /is not one of L0, L1, L2/);
  assert.throws(() => firstSelection({ set: SET, cc: 'clang-20', cond: 'L0' }), /no default method for clang-20/);
  assert.deepEqual(CONDS, ['L0', 'L1', 'L2']);
});

test('selectMethod: the first choice with nothing tried; after a failed attempt, the record\'s shapes among the untried', () => {
  assert.equal(selectMethod({ set: SET, table: LEARNED, cc: 'clang-18', cond: 'L2', stage: IR, shapes: ['dead-store-memset-intrinsic'] }).method,
    'wipepin-volatile');
  const after = selectMethod({ set: SET, cc: 'clang-18', record: { pinnedCount: 0, unhandled: U({ inlineWrapperMemset: 1 }) }, tried: ['wipepin-volatile'] });
  assert.deepEqual(after, { method: 'wipepin-barrier', why: 'claims(inline-wrapper-memset)' });
  // with both clang methods tried there is nothing left: a person
  assert.equal(selectMethod({ set: SET, cc: 'clang-18', record: { pinnedCount: 0, unhandled: U({ inlineWrapperMemset: 1 }) },
    tried: ['wipepin-volatile', 'wipepin-barrier'] }).route, 'HUMAN');
});

// ------------------------------------------------------------ the loop rules ----

test('replayLoop: L0 does not go back; L1 goes back through the record; three failures stop', () => {
  const failFortify = { verdict: 'WIPE_ELIMINATED', record: { pinnedCount: 0, unhandled: U({ inlineWrapperMemset: 1 }) } };
  const l0 = replayLoop({ set: SET, cc: 'clang-18', cond: 'L0', attempts: [failFortify] });
  assert.equal(l0.outcome, 'FAILED');
  assert.equal(l0.steps.length, 1);
  assert.equal(l0.steps[0].rediagnosis, undefined, 'L0 reads no record');
  const l1 = replayLoop({ set: SET, cc: 'clang-18', cond: 'L1', attempts: [failFortify, { verdict: 'WIPE_SURVIVED', record: null }] });
  assert.equal(l1.outcome, 'REPAIRED');
  assert.equal(l1.method, 'wipepin-barrier');
  assert.equal(l1.k, 2);
  assert.deepEqual(l1.steps[0].rediagnosis.shapes, ['inline-wrapper-memset']);
  // a repaired build that is neither verdict goes to a person
  assert.equal(replayLoop({ set: SET, cc: 'gcc-13', cond: 'L1', attempts: [{ verdict: 'NOT_SCORED', record: null }] }).outcome, 'HUMAN');
  // three eliminations: needs three methods, so build a set with a third clang method
  const s3 = structuredClone(SET);
  s3.methods['wipepin-third'] = { cc: 'clang-18', order: 3, arg: '-fpass-plugin', env: {}, pluginSha16: '0'.repeat(16),
    claims: ['inline-wrapper-memset', 'memset-chk'], source: 'a synthetic third method for this test' };
  const elim = (c) => ({ verdict: 'WIPE_ELIMINATED', record: { pinnedCount: 0, unhandled: U({ [c]: 1 }) } });
  const r3 = replayLoop({ set: s3, cc: 'clang-18', cond: 'L1', attempts: [elim('inlineWrapperMemset'), elim('memsetChk'), elim('memsetChk')] });
  assert.equal(r3.outcome, 'FAILED');
  assert.equal(r3.steps.length, MAX_ATTEMPTS);
  assert.deepEqual(r3.steps.map((s) => s.method), ['wipepin-volatile', 'wipepin-barrier', 'wipepin-third']);
  // and a replay that runs out of observed attempts says what it would try next
  const pend = replayLoop({ set: SET, cc: 'clang-18', cond: 'L1', attempts: [failFortify] });
  assert.equal(pend.outcome, null);
  assert.equal(pend.pending.method, 'wipepin-barrier');
});

test('compareLoopRow: a row as the loop wrote it agrees with its replay', () => {
  const fortifyL1 = {
    id: 'f1', cc: 'clang-18', cfg: 'f2', cond: 'L1', outcome: 'REPAIRED', method: 'wipepin-barrier', k: 2,
    iters: [
      iter(1, 'default', 'wipepin-volatile', 'WIPE_ELIMINATED', { pinned: 0, unhandled: U({ inlineWrapperMemset: 1 }),
        rediagnosis: { shapes: ['inline-wrapper-memset'], pinned: 0, why: `record pinned=0 unhandled=${JSON.stringify(U({ inlineWrapperMemset: 1 }))}` } }),
      iter(2, 'claims(inline-wrapper-memset)', 'wipepin-barrier', 'WIPE_SURVIVED', { pinned: 0 }),
    ],
  };
  assert.deepEqual(compareLoopRow(fortifyL1, { set: SET, table: LEARNED }), []);
  const tableL2 = { id: 't', cc: 'clang-18', cfg: 'none', cond: 'L2', stage: IR, shapes: ['dead-store-memset-intrinsic'], outcome: 'REPAIRED',
    method: 'wipepin-volatile', k: 1, iters: [iter(1, 'table(clang-18,ir,dead-store-memset-intrinsic)', 'wipepin-volatile', 'WIPE_SURVIVED', { fromTable: true })] };
  assert.deepEqual(compareLoopRow(tableL2, { set: SET, table: LEARNED }), []);
  const loopL2 = { id: 's', cc: 'gcc-13', cfg: 'off', cond: 'L2', stage: GIMPLE, shapes: ['wipe-written-as-stores'], outcome: 'SOURCE',
    why: 'L2 stage=gimple; source-side shape wipe-written-as-stores', iters: [] };
  assert.deepEqual(compareLoopRow(loopL2, { set: SET, table: LEARNED }), []);
  // a record that was never written (component null) reads as no record
  const noRec = { id: 'n', cc: 'gcc-13', cfg: 'none', cond: 'L1', outcome: 'HUMAN', why: 'after k=1: no-record; no method claims (no shape)',
    iters: [iter(1, 'default', 'wipepingcc', 'WIPE_ELIMINATED', { pinned: null, unhandled: null, component: null,
      rediagnosis: { shapes: [], why: 'no-record' } })] };
  assert.deepEqual(compareLoopRow(noRec, { set: SET, table: LEARNED }), []);
});

test('compareLoopRow names every kind of difference: method, why, fromTable, record shapes, outcome, route sentence', () => {
  const base = { id: 't', cc: 'clang-18', cfg: 'none', cond: 'L2', stage: IR, shapes: ['dead-store-memset-intrinsic'], outcome: 'REPAIRED',
    method: 'wipepin-volatile', k: 1, iters: [iter(1, 'table(clang-18,ir,dead-store-memset-intrinsic)', 'wipepin-volatile', 'WIPE_SURVIVED', { fromTable: true })] };
  const ctx = { set: SET, table: LEARNED };
  const m = (f) => { const r = structuredClone(base); f(r); return compareLoopRow(r, ctx).join(' | '); };
  assert.match(m((r) => { r.iters[0].method = 'wipepin-barrier'; }), /k=1 method: replay wipepin-volatile, row wipepin-barrier/);
  assert.match(m((r) => { r.iters[0].why = 'claims(dead-store-memset-intrinsic)'; }), /k=1 why/);
  assert.match(m((r) => { r.iters[0].fromTable = false; }), /k=1 fromTable: replay true, row false/);
  assert.match(m((r) => { r.outcome = 'FAILED'; }), /outcome: replay REPAIRED, row FAILED/);
  assert.match(m((r) => { r.k = 2; }), /repaired by: replay wipepin-volatile k=1, row wipepin-volatile k=2/);
  // replayed with the cold table, which has no row for the fortify wrapper, the choice comes from the declarations
  const fort = { id: 'w', cc: 'clang-18', cfg: 'f2', cond: 'L2', stage: IR, shapes: ['inline-wrapper-memset'], outcome: 'REPAIRED', method: 'wipepin-barrier', k: 1,
    iters: [iter(1, 'table(clang-18,ir,inline-wrapper-memset)', 'wipepin-barrier', 'WIPE_SURVIVED', { fromTable: true })] };
  assert.deepEqual(compareLoopRow(fort, ctx), []);
  assert.match(compareLoopRow(fort, { set: SET, table: COLD }).join(' | '),
    /k=1 why: replay "claims\(inline-wrapper-memset\)", row "table\(clang-18,ir,inline-wrapper-memset\)" \| k=1 fromTable: replay false, row true/);
  const routed = { id: 's', cc: 'gcc-13', cfg: 'off', cond: 'L2', stage: GIMPLE, shapes: ['wipe-written-as-stores'], outcome: 'SOURCE', why: 'something else', iters: [] };
  assert.match(compareLoopRow(routed, ctx).join(' | '), /why: replay "L2 stage=gimple; source-side shape wipe-written-as-stores"/);
  const rd = {
    id: 'f1', cc: 'clang-18', cfg: 'f2', cond: 'L1', outcome: 'REPAIRED', method: 'wipepin-barrier', k: 2,
    iters: [
      iter(1, 'default', 'wipepin-volatile', 'WIPE_ELIMINATED', { pinned: 0, unhandled: U({ inlineWrapperMemset: 1 }), rediagnosis: { shapes: ['memset-chk'], why: 'x' } }),
      iter(2, 'claims(inline-wrapper-memset)', 'wipepin-barrier', 'WIPE_SURVIVED'),
    ],
  };
  assert.match(compareLoopRow(rd, ctx).join(' | '), /k=1 rediagnosis\.shapes: replay \["inline-wrapper-memset"\], row \["memset-chk"\]/);
  // a row with a step the replay would not take
  const extra = structuredClone(base);
  extra.iters.push(iter(2, 'claims(x)', 'wipepin-barrier', 'WIPE_SURVIVED'));
  assert.match(compareLoopRow(extra, ctx).join(' | '), /steps: replay 1, row 2/);
});

// ---------------------------------------------------- the table, and only it, grows ----

test('learnRows: a one-shape group repaired at k=1 by one method is adopted and cites its run; anything else is recorded, not adopted', () => {
  const l2 = (id, stage, shapes, outcome, method, k) => ({ id, cc: 'clang-18', cond: 'L2', stage, shapes, outcome, method, k });
  const rows = [
    l2('a', IR, ['inline-wrapper-memset'], 'REPAIRED', 'wipepin-barrier', 1),
    l2('b', IR, ['inline-wrapper-memset'], 'REPAIRED', 'wipepin-barrier', 1),
    l2('c', { cls: 'unknown' }, ['dead-store-memset-intrinsic', 'wipe-written-as-stores'], 'REPAIRED', 'wipepin-volatile', 1),
    l2('d', IR, ['memset-chk'], 'REPAIRED', 'wipepin-barrier', 1),
    l2('e', IR, ['memset-chk'], 'REPAIRED', 'wipepin-barrier', 2),
    l2('f', IR, ['dead-store-memset-intrinsic'], 'REPAIRED', 'wipepin-volatile', 1), // already in the table
    { ...l2('g', IR, ['bzero-call'], 'REPAIRED', 'wipepin-barrier', 1), cond: 'L1' }, // not L2
  ];
  const got = learnRows(rows, COLD, (g) => `synthetic: ${g.rows.length} cell(s)`);
  assert.deepEqual(got.adopted, [{ cc: 'clang-18', stage: 'ir', shape: 'inline-wrapper-memset', method: 'wipepin-barrier', evidence: 'synthetic: 2 cell(s)' }]);
  assert.equal(got.rows.length, COLD.rows.length + 1);
  assert.deepEqual(got.considered.map((c) => [c.stage, c.shapes.join('+'), c.adopted]), [
    ['ir', 'inline-wrapper-memset', 'wipepin-barrier'],
    ['ir', 'memset-chk', null], // one cell needed a second attempt
    ['unknown', 'dead-store-memset-intrinsic+wipe-written-as-stores', null], // two shapes: recorded only
  ]);
  // the table it was given is not changed
  assert.equal(COLD.rows.length, 2);
});

test('learnRows over E1-shaped rows re-derives the learned table: cold + four rows, in learn.py\'s order', () => {
  // The group sizes are E1's (102, 1, 2, 3 cells and the three two-shape groups); the rows are synthetic.
  const rows = [];
  const add = (n, cc, stage, shapes, method) => {
    for (let i = 0; i < n; i++) rows.push({ id: `${method}${i}`, cc, cond: 'L2', stage: { cls: stage }, shapes, outcome: 'REPAIRED', method, k: 1 });
  };
  add(3, 'gcc-13', 'unknown', ['dead-store-builtin-memset-gimple'], 'wipepingcc');
  add(102, 'clang-18', 'ir', ['inline-wrapper-memset'], 'wipepin-barrier');
  add(2, 'clang-18', 'unknown', ['inline-wrapper-memset'], 'wipepin-barrier');
  add(1, 'clang-18', 'unknown', ['dead-store-memset-intrinsic'], 'wipepin-volatile');
  add(1, 'clang-18', 'unknown', ['dead-store-memset-intrinsic', 'wipe-written-as-stores'], 'wipepin-volatile');
  add(2, 'clang-18', 'unknown', ['inline-wrapper-memset', 'wipe-written-as-stores'], 'wipepin-barrier');
  add(3, 'gcc-13', 'unknown', ['dead-store-builtin-memset-gimple', 'wipe-written-as-stores'], 'wipepingcc');
  add(200, 'clang-18', 'ir', ['dead-store-memset-intrinsic'], 'wipepin-volatile'); // known cells: skipped
  const got = learnRows(rows, COLD, () => 'e');
  const key = (r) => [r.cc, r.stage, r.shape, r.method].join('|');
  assert.deepEqual(got.rows.map(key), LEARNED.rows.map(key));
  assert.equal(got.considered.filter((c) => c.adopted === null).length, 3);
});

// ------------------------------------------------------------------- the CLI ----

const LOOP = (rows, table = 'learned') => ({ schema: 'r6-loop-v1', table: { name: table, sha16: sha16Of(table) }, methods: PLUGINS, conds: CONDS, rows });
const ROWS = [
  { id: 'a', cc: 'clang-18', cfg: 'none', cond: 'L2', stage: IR, shapes: ['dead-store-memset-intrinsic'], outcome: 'REPAIRED', method: 'wipepin-volatile', k: 1,
    iters: [iter(1, 'table(clang-18,ir,dead-store-memset-intrinsic)', 'wipepin-volatile', 'WIPE_SURVIVED', { fromTable: true })] },
  { id: 'b', cc: 'clang-18', cfg: 'f2', cond: 'L0', outcome: 'FAILED', why: 'L0 は戻らない',
    iters: [iter(1, 'default', 'wipepin-volatile', 'WIPE_ELIMINATED', { pinned: 0, unhandled: U({ inlineWrapperMemset: 1 }) })] },
  { id: 'c', cc: 'gcc-13', cfg: 'none', cond: 'L2', stage: GIMPLE, shapes: ['wipe-written-as-stores'], outcome: 'SOURCE',
    why: 'L2 stage=gimple; source-side shape wipe-written-as-stores', iters: [] },
  { id: 'x', cc: 'gcc-13', cfg: 'off', cond: 'L1', outcome: 'EXCEPTION', message: 'compile timed out' },
];

test('loopFileProblems: the table and every plugin build must be the ones the set was copied with', () => {
  assert.deepEqual(loopFileProblems(LOOP(ROWS), SET), []);
  assert.match(loopFileProblems({ ...LOOP(ROWS), table: { name: 'learned', sha16: '0'.repeat(16) } }, SET).join(), /digest 0000000000000000; the set's copy is 61f3d53127a35fa6/);
  assert.match(loopFileProblems({ ...LOOP(ROWS), table: { name: 'warm', sha16: 'x' } }, SET).join(), /table "warm", which the set does not hold/);
  assert.match(loopFileProblems({ ...LOOP(ROWS), methods: { ...PLUGINS, 'wipepin-barrier': 'f'.repeat(16) } }, SET).join(), /plugin build ffff/);
  assert.match(loopFileProblems({ table: {} }, SET).join(), /no rows/);
});

test('the copied tables still choose what the files they were copied from chose: selectionSha16 is recomputed', () => {
  // The copy records, per table, the digest of [cc, stage, shape, method] taken from the
  // original file; it must equal the digest of the copied rows.
  for (const name of ['cold', 'learned']) {
    const e = SET.copiedFrom.files.find((f) => f.file === `table-${name}.json`);
    assert.match(e.selectionSha16, /^[0-9a-f]{16}$/);
    assert.equal(tableSelectionSha16(SET.tables[name]), e.selectionSha16, `table ${name}: the copy no longer chooses what the original did`);
  }
  // An edited copy is refused before any row is replayed, whatever the loop file says.
  const dropped = structuredClone(SET);
  dropped.tables.learned.rows.pop();
  assert.match(loopFileProblems(LOOP(ROWS), dropped).join(), /copy of table learned chooses by rows with selection digest [0-9a-f]{16}; the file it was copied from had a96bc4c48d12d0bb/);
  const changed = structuredClone(SET);
  changed.tables.learned.rows[0].method = 'wipepin-barrier';
  assert.match(loopFileProblems(LOOP(ROWS), changed).join(), /selection digest/);
  const reordered = structuredClone(SET);
  reordered.tables.learned.rows.reverse();
  assert.match(loopFileProblems(LOOP(ROWS), reordered).join(), /selection digest/);
  // A translated note or evidence string is not what the table decides, so it is not a refusal.
  const reworded = structuredClone(SET);
  reworded.tables.learned.rows[0].evidence = 'reworded';
  assert.deepEqual(loopFileProblems(LOOP(ROWS), reworded), []);
  const unrecorded = structuredClone(SET);
  delete unrecorded.copiedFrom.files.find((f) => f.file === 'table-learned.json').selectionSha16;
  assert.match(loopFileProblems(LOOP(ROWS), unrecorded).join(), /had \(none recorded\)/);

  // and through the CLI: an edited copy passed with --set is an input refusal (exit 5), not a replay difference (exit 2)
  const dir = mkdtempSync(path.join(tmpdir(), 'select-method-'));
  try {
    const loop = path.join(dir, 'loop.json');
    writeFileSync(loop, JSON.stringify(LOOP(ROWS)));
    const setPath = path.join(dir, 'set.json');
    writeFileSync(setPath, JSON.stringify(dropped));
    const r = cli(['--check', loop, '--set', setPath]);
    assert.equal(r.status, 5, r.stderr);
    assert.match(r.stderr, /selection digest/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the copied set says its source-side shapes are r6b\'s, not the current pin-family table\'s', () => {
  assert.match(SET.sourceSideShapesFrom, /2026-10-04/);
  assert.match(SET.sourceSideShapesFrom, /does not describe the current table/);
});

test('checkLoopDoc: rows agree or differ, and a row the loop could not run is counted apart, never compared', () => {
  const r = checkLoopDoc(LOOP(ROWS), SET);
  assert.equal(r.rows, 4);
  assert.equal(r.compared, 3);
  assert.equal(r.agree, 3);
  assert.equal(r.differ, 0);
  assert.equal(r.notCompared, 1);
  assert.deepEqual(r.notComparedRows[0], { id: 'x', cc: 'gcc-13', cfg: 'off', cond: 'L1', outcome: 'EXCEPTION', message: 'compile timed out' });
  assert.deepEqual(r.byCondOutcome, { 'L2.REPAIRED': 1, 'L0.FAILED': 1, 'L2.SOURCE': 1 });
});

function cli(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('the CLI: --check exits 0 when every row agrees, 2 with the differing row named, 5 for a table the set does not hold', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'select-method-'));
  try {
    const good = path.join(dir, 'good.json');
    writeFileSync(good, JSON.stringify(LOOP(ROWS)));
    const out = path.join(dir, 'summary.json');
    const r0 = cli(['--check', good, '--out', out]);
    assert.equal(r0.status, 0, r0.stderr);
    assert.match(r0.stdout, /rows 4 {2}compared 3 {2}agree 3 {2}differ 0 {2}not compared 1/);
    assert.match(r0.stdout, /NOT COMPARED x gcc-13 off L1: EXCEPTION/);
    const sum = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(sum.schema, 'select-method-check-v1');
    assert.equal(sum.total.agree, 3);

    const bad = path.join(dir, 'bad.json');
    const rows = structuredClone(ROWS);
    rows[0].iters[0].method = 'wipepin-barrier';
    writeFileSync(bad, JSON.stringify(LOOP(rows)));
    const r1 = cli(['--check', bad]);
    assert.equal(r1.status, 2);
    assert.match(r1.stdout, /DIFFERS a clang-18 none L2: k=1 method: replay wipepin-volatile, row wipepin-barrier/);

    const other = path.join(dir, 'other.json');
    writeFileSync(other, JSON.stringify({ ...LOOP(ROWS), table: { name: 'learned', sha16: '1'.repeat(16) } }));
    assert.equal(cli(['--check', other]).status, 5);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the CLI: --learn, --select, and the refusals (--out in the tree, --write-data, two modes)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'select-method-'));
  try {
    const rows = [];
    for (let i = 0; i < 3; i++) rows.push({ id: `g${i}`, cc: 'gcc-13', cfg: 'none', cond: 'L2', stage: { cls: 'unknown' }, shapes: ['dead-store-builtin-memset-gimple'],
      outcome: 'REPAIRED', method: 'wipepingcc', k: 1, iters: [iter(1, 'claims(dead-store-builtin-memset-gimple)', 'wipepingcc', 'WIPE_SURVIVED', { component: 'WipePinGcc' })] });
    const cold = path.join(dir, 'cold.json');
    writeFileSync(cold, JSON.stringify(LOOP(rows, 'cold')));
    const rl = cli(['--learn', cold]);
    assert.equal(rl.status, 2, 'one of the four learned rows re-derived: three are missing');
    assert.match(rl.stdout, /adopted 1 {2}expected 4 {2}missing 3 {2}extra 0/);
    assert.match(rl.stdout, /ADOPTED {5}gcc-13 unknown dead-store-builtin-memset-gimple {2}cells 3/);

    const sel = cli(['--select', '--cc', 'clang-18', '--tried', 'wipepin-volatile', '--unhandled', JSON.stringify(U({ inlineWrapperBzero: 1 }))]);
    assert.equal(sel.status, 0, sel.stderr);
    assert.deepEqual(JSON.parse(sel.stdout), { method: 'wipepin-barrier', why: 'claims(inline-wrapper-bzero)' });
    const first = cli(['--select', '--cc', 'gcc-13', '--stage', 'gimple', '--shapes', 'memset-chk', '--table', 'learned']);
    assert.deepEqual(JSON.parse(first.stdout), { method: 'wipepingcc-barrier', why: 'claims(memset-chk)' });

    assert.equal(cli(['--check', cold, '--out', path.join(LANE, 'x.json')]).status, 4);
    assert.equal(cli(['--check', cold, '--write-data']).status, 4);
    assert.equal(cli(['--check', cold, '--select', '--cc', 'clang-18']).status, 4);
    assert.equal(cli(['--select']).status, 4);
    assert.equal(cli(['--check', path.join(dir, 'missing.json')]).status, 5);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the CLI and its library never compile: neither imports child_process', () => {
  const src = readFileSync(CLI, 'utf8') + readFileSync(path.join(LANE, 'tools', 'lib', 'select-method.mjs'), 'utf8');
  assert.ok(!/child_process/.test(src));
  assert.ok(!/\bexecFile\b|\bspawn\b/.test(src));
});
