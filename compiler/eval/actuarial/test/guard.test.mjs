/**
 * The guards in `lib/rate-table.mjs`, exercised on rows that do not exist in the
 * corpus yet.
 *
 * This is the one file in the lane that imports the builder's library, and it is
 * separate from `rate-table.test.mjs` on purpose: that file recomputes the table
 * with its own arithmetic and must not touch the code it is checking. This one
 * asks the opposite question -- what happens to a row shape the r2 corpus happens
 * not to contain -- which can only be asked of the code itself.
 *
 * The cases below are real row shapes the ai-generated lane can produce
 * (`verdictOf` in its `lib/ablation-cell.mjs` emits `NOT_OBSERVED` and
 * `VERIFICATION_INCOMPLETE`, and `wipeSpans` can classify an idiom this lane's
 * display order has never seen). r2 contains none of them, so nothing in the
 * tracked table exercises the branches that decide what to do with them. An
 * untested branch that decides whether a row lands in a denominator is exactly the
 * kind of thing that is discovered by a number being wrong months later.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { buildTable, renderText, scopeRows } from '../lib/rate-table.mjs';

const PROV = { file: 'x', sha256: 'y', bytes: 1, corpusId: 'r2', protocol: 'PROTOCOL-r2.md' };

const row = (over = {}) => ({
  id: 'model_N_scen_r1',
  kind: 'erasure',
  idiom: 'removable',
  cc: 'clang-18',
  opt: '-O2',
  control: 'PRESENT',
  verdict: 'WIPE_SURVIVED',
  ...over,
});

test('a live control with no wipe verdict stops the table instead of being absorbed', () => {
  // NOT_OBSERVED means the target function's body was not found in the listing:
  // the run looked and saw nothing, with its control intact. Such a row is in
  // neither the eliminated nor the survived column, so `den` would stop meaning
  // "eliminated + survived" and the printed ratio would change its subject without
  // saying so. Refusing to print is the only honest option left at that point.
  assert.throws(
    () => buildTable([row(), row({ id: 'model_N_scen_r2', verdict: 'NOT_OBSERVED' })], PROV),
    /den would no longer mean/,
  );
});

test('a withheld row is on neither side of the ratio and is counted by name', () => {
  // VERIFICATION_INCOMPLETE: the positive control itself was not visible, so the
  // row is evidence about the instrument, not about the compiler. `control` here
  // carries the detection path rather than 'PRESENT', which is what keeps it out
  // of the denominator.
  const t = buildTable(
    [
      row({ verdict: 'WIPE_ELIMINATED' }),
      row({ id: 'model_N_scen_r2', control: 'oracle', verdict: 'VERIFICATION_INCOMPLETE' }),
    ],
    PROV,
  );
  assert.equal(t.cells.length, 1);
  assert.deepEqual(t.cells[0].eliminated, { num: 1, den: 1 });
  assert.equal(t.cells[0].verificationIncomplete, 1);
  assert.equal(t.cells[0].notScored, 0);
  assert.equal(t.cells[0].rows, 2);
});

test('a row that reached no verdict at all is notScored, and byVerdict says which', () => {
  const t = buildTable(
    [
      row(),
      row({ id: 'model_N_scen_r2', control: undefined, verdict: 'ABLATION_DID_NOT_COMPILE' }),
      row({ id: 'model_N_scen_r3', control: undefined, verdict: 'COMPILE_ERROR' }),
    ],
    PROV,
  );
  const c = t.cells[0];
  assert.deepEqual(c.eliminated, { num: 0, den: 1 });
  assert.equal(c.notScored, 2);
  assert.deepEqual(c.byVerdict, {
    ABLATION_DID_NOT_COMPILE: 1,
    COMPILE_ERROR: 1,
    WIPE_SURVIVED: 1,
  });
  // The roll-up never stands alone: the two reasons are separable in the record.
  assert.equal(Object.values(c.byVerdict).reduce((a, b) => a + b, 0), c.rows);
});

test('an idiom the display order has never seen is appended, not dropped', () => {
  const t = buildTable([row(), row({ id: 'model_N_scen_r2', idiom: 'volatile-array' })], PROV);
  assert.deepEqual(t.axes.idiom, ['removable', 'volatile-array']);
  assert.equal(t.cells.length, 2);
  assert.equal(t.scope.rowsInScope, 2);
});

test('an optimisation level the display order has never seen is appended too', () => {
  const t = buildTable([row(), row({ id: 'model_N_scen_r2', opt: '-Ofast' })], PROV);
  assert.deepEqual(t.axes.optLevel, ['-O2', '-Ofast']);
});

test('scopeRows separates "other question" from "no wipe was written"', () => {
  const { inScope, otherFamily, noWipeWritten } = scopeRows([
    row(),
    { id: 'a', kind: 'authz', cc: 'gcc-13', opt: '-O0', verdict: 'NDEBUG_NO_EFFECT' },
    { id: 'b', kind: 'none', verdict: 'NO_WIPE_WRITTEN' },
  ]);
  assert.equal(inScope.length, 1);
  assert.equal(otherFamily.length, 1);
  assert.equal(noWipeWritten.length, 1);
});

test('denominatorExclusions separates the two ways a row leaves the denominator', () => {
  // r2 exercises only one of the two: every excluded row there reached no verdict,
  // so the record's rule has to be able to count both or it is describing a column
  // that cannot appear. The withheld row carries its detection path in `control`;
  // the not-scored row carries no `control` key at all, because verdictOf returns
  // before it reads one.
  const t = buildTable(
    [
      row(),
      row({ id: 'model_N_scen_r2', control: 'oracle', verdict: 'VERIFICATION_INCOMPLETE' }),
      row({ id: 'model_N_scen_r3', control: undefined, verdict: 'ABLATION_DID_NOT_COMPILE' }),
    ],
    PROV,
  );
  assert.deepEqual(t.denominatorExclusions, {
    rows: 2,
    withheldControlUnseen: 1,
    noVerdictReached: 1,
    byVerdict: { ABLATION_DID_NOT_COMPILE: 1, VERIFICATION_INCOMPLETE: 1 },
  });
  assert.deepEqual(t.cells[0].eliminated, { num: 0, den: 1 });
  // The rule that travels with the record has to name both paths, since either can
  // be the reason for the gap between `rows` and `den` in a future corpus.
  assert.match(t.denominatorRule, /verificationIncomplete/);
  assert.match(t.denominatorRule, /notScored/);
});

test('the printed table carries the exclusion accounting, not just the record', () => {
  // The text file is the copy that gets quoted, and "den is smaller than rows" with
  // no reason printed invites the reader to supply one.
  const t = buildTable(
    [row(), row({ id: 'model_N_scen_r2', control: undefined, verdict: 'COMPILE_ERROR' })],
    PROV,
  );
  assert.match(renderText(t), /out of every den\s+1 \(control unseen 0, no verdict 1: COMPILE_ERROR 1\)/);
});
