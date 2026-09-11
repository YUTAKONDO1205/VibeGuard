/**
 * lib/plan.mjs replays the find step's pin plan. These tests show it refuses a
 * plan that no longer describes the tree, and that the summary cannot call a
 * planned cell repaired unless its loss was observed and came back.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readPlan, planMismatch, planCompilerMismatch, planSummary, renderPlanSummary } from '../lib/plan.mjs';

const ALL = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const entry = (over = {}) => ({ id: 'fable_N_token_r3', fn: 'send_session_token', helpers: [], opts: ['-O2', '-Os'], reason: { '-O2': 'span', '-Os': 'span' }, ...over });

test('a well-formed plan is read into a map keyed by file id', () => {
  const p = readPlan({ entries: [entry(), entry({ id: 'fable_N_aeskey_r3', fn: 'encrypt_blob', opts: ['-O2'] })] }, { allOpts: ALL });
  assert.equal(p.ok, true, JSON.stringify(p.problems));
  assert.equal(p.entries.size, 2);
  assert.deepEqual([...p.entries.get('fable_N_token_r3').opts], ['-O2', '-Os']);
});

test('a plan is refused when it is not one, is empty, repeats a file, or names an unknown level', () => {
  assert.equal(readPlan(null, { allOpts: ALL }).ok, false);
  assert.equal(readPlan({ entries: 'x' }, { allOpts: ALL }).ok, false);
  assert.match(readPlan({ entries: [] }, { allOpts: ALL }).problems.join(), /empty-plan/);
  assert.match(readPlan({ entries: [entry(), entry()] }, { allOpts: ALL }).problems.join(), /appears twice/);
  assert.match(readPlan({ entries: [entry({ opts: ['-O9'] })] }, { allOpts: ALL }).problems.join(), /not a known level/);
  assert.match(readPlan({ entries: [entry({ opts: [] })] }, { allOpts: ALL }).problems.join(), /opts: empty/);
  assert.match(readPlan({ entries: [entry({ id: '../x' })] }, { allOpts: ALL }).problems.join(), /not a file id/);
  assert.match(readPlan({ entries: [entry({ helpers: [1] })] }, { allOpts: ALL }).problems.join(), /helpers/);
});

test('planMismatch accepts the same names in any order and refuses different ones', () => {
  const e = { fn: 'f', helpers: ['a', 'b'] };
  assert.equal(planMismatch(e, { fn: 'f', helpers: ['b', 'a'] }), null);
  assert.match(planMismatch(e, { fn: 'g', helpers: ['a', 'b'] }), /fn f in the plan, g/);
  assert.match(planMismatch(e, { fn: 'f', helpers: ['a'] }), /helpers/);
});

test('planCompilerMismatch: a plan written for one compiler is refused on the other; a plan without cc is not checked', () => {
  assert.equal(planCompilerMismatch({ cc: 'gcc-13', entries: [] }, 'gcc-13'), null);
  assert.equal(planCompilerMismatch({ cc: 'gcc-13', entries: [] }, 'clang-18'), 'the plan was written for "gcc-13"; this run drives "clang-18"');
  assert.match(planCompilerMismatch({ cc: 'clang-18' }, 'gcc-13'), /written for "clang-18"/);
  assert.equal(planCompilerMismatch({ entries: [] }, 'clang-18'), null);
  assert.equal(planCompilerMismatch(null, 'clang-18'), null);
});

const row = (over) => ({ kind: 'erasure', id: 'x', opt: '-O2', baseline: 'WIPE_ELIMINATED', outcome: 'RETAINED', hiddenElimination: false, hiddenRetained: false, ...over });

test('planSummary counts a cell repaired only when its observed loss came back', () => {
  const s = planSummary([
    row({ id: 'a' }),
    row({ id: 'b', outcome: 'PIN_INEFFECTIVE' }),
    row({ id: 'c', baseline: 'WIPE_SURVIVED', outcome: 'ALREADY_SURVIVED', hiddenElimination: true, hiddenRetained: true }),
    row({ id: 'd', baseline: 'WIPE_SURVIVED', outcome: 'ALREADY_SURVIVED', hiddenElimination: true, hiddenRetained: false }),
    row({ id: 'e', baseline: 'WIPE_SURVIVED', outcome: 'ALREADY_SURVIVED' }),
    { kind: 'configguard', id: 'z' },
  ]);
  assert.equal(s.cells, 5);
  assert.equal(s.cellPlanned, 2); assert.equal(s.cellRetained, 1);
  assert.equal(s.spanPlanned, 2); assert.equal(s.spanRetained, 1);
  assert.deepEqual(s.notReproduced, ['e -O2 (baseline WIPE_SURVIVED)']);
  assert.deepEqual(s.notRepaired, ['b -O2 (PIN_INEFFECTIVE)', 'd -O2 (span not retained)']);
  const text = renderPlanSummary(s, { planSha256: 'f'.repeat(64), entries: 5 });
  assert.match(text, /STALE e -O2/);
  assert.match(text, /NOT REPAIRED b -O2/);
});
