/**
 * Tests for the Optimisation Fragility Score.
 *
 * Every expected value below is hand-computed from the rule the module is
 * documented to follow, not transcribed from a run. The point of most of these
 * is not that the arithmetic works; it is that cells which must not be counted
 * are not counted, and that the counting stops rather than guessing when there
 * is nothing left to count.
 *
 * Test data is inline rather than in a directory beside this file. A path
 * segment named `fixtures` under compiler/ is a committable measurement input
 * and scripts/check-packaging-invariants.mjs fails the build on one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  computeFragility,
  toEvidenceJson,
  formatReport,
  scoreAsFloat,
  classifyCell,
  configKey,
  parseThreshold,
  ratioExceeds,
  FragilityInputError,
  FragilityIncompleteError,
  EXCLUSION_REASONS,
  KNOWN_STATES,
} from '../fragility.mjs';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'fragility.mjs');

/** A well-formed cell; each test overrides only what it is about. */
function cell(over = {}) {
  return {
    cellId: over.cellId ?? `c${Math.random().toString(36).slice(2)}`,
    propertyId: 'erasure.wipe',
    config: { opt: 'O2' },
    state: 'PRESENT',
    controlHeld: true,
    completesTheCheck: true,
    ...over,
  };
}

/** n cells at n distinct optimisation levels, all in the same state. */
function uniform(state, opts = ['O0', 'O1', 'O2', 'O3']) {
  return opts.map((o) => cell({ cellId: `erasure-${o}`, config: { opt: o }, state }));
}

// --- 1. every cell PRESENT -> 0.0 -------------------------------------------

test('a property present in every measured config scores 0', () => {
  const r = computeFragility(uniform('PRESENT'));
  assert.deepEqual(r.score, { num: 0, den: 4 });
  assert.equal(scoreAsFloat(r.score), 0.0);
  assert.equal(r.scoreText, '0.000');
  assert.equal(r.counts.eligible, 4);
  assert.equal(r.counts.excluded, 0);
  assert.equal(r.measuredConfigs.length, 4);
});

// --- 2. every cell LOST -> 1.0 ----------------------------------------------

test('a property lost in every measured config scores 1', () => {
  const r = computeFragility(uniform('LOST'));
  assert.deepEqual(r.score, { num: 4, den: 4 });
  assert.equal(scoreAsFloat(r.score), 1.0);
  assert.equal(r.scoreText, '1.000');
});

// --- 3. mixed -> a hand-computed intermediate value --------------------------

test('a mixed envelope scores the hand-computed ratio', () => {
  // PRESENT at O0 and O1, LOST at O2 and O3. Eligible 4, lost 2 => 2/4.
  const cells = [
    cell({ cellId: 'erasure-O0', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'erasure-O1', config: { opt: 'O1' }, state: 'PRESENT' }),
    cell({ cellId: 'erasure-O2', config: { opt: 'O2' }, state: 'LOST' }),
    cell({ cellId: 'erasure-O3', config: { opt: 'O3' }, state: 'LOST' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 2, den: 4 });
  assert.equal(scoreAsFloat(r.score), 0.5);
  assert.equal(r.scoreText, '0.500');
});

test('a three-cell envelope with one loss scores 1/3, not a rounded float', () => {
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'PRESENT' }),
    cell({ cellId: 'c', config: { opt: 'O3' }, state: 'LOST' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 1, den: 3 });
  assert.equal(r.scoreText, '0.333');
  // interfaces.md section 5 rule 4: the record carries integers, never 0.3333…
  const json = toEvidenceJson(r);
  assert.equal(Number.isInteger(json.score.num), true);
  assert.equal(Number.isInteger(json.score.den), true);
});

// --- 4. a broken control leaves the denominator, visibly ---------------------

test('a cell whose control did not hold is excluded and the exclusion is reported', () => {
  // Three real cells (2 PRESENT, 1 LOST) plus one broken measurement whose
  // state claims PRESENT. If the broken cell were counted the score would be
  // 1/4 = 0.250; the honest answer over what was actually measured is 1/3.
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O1' }, state: 'PRESENT' }),
    cell({ cellId: 'c', config: { opt: 'O2' }, state: 'LOST' }),
    cell({ cellId: 'pc2-broken-control', config: { opt: 'O3' }, state: 'PRESENT', controlHeld: false }),
  ];
  const r = computeFragility(cells);

  assert.deepEqual(r.score, { num: 1, den: 3 }, 'the broken measurement must not be a survivor');
  assert.equal(r.counts.total, 4);
  assert.equal(r.counts.eligible, 3);
  assert.equal(r.counts.excluded, 1);

  // The exclusion count appears in the output, both aggregated and itemised.
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD], 1);
  assert.deepEqual(
    r.excluded.map((e) => [e.cellId, e.reason]),
    [['pc2-broken-control', EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD]],
  );
  assert.equal(toEvidenceJson(r).excludedByReason[EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD], 1);
  assert.match(formatReport(r), /excluded 1 for control-did-not-hold/);

  // And the config it was attempted at is named, so an envelope that lost a
  // whole column to a broken control cannot read as one that was never run.
  assert.deepEqual(
    r.configsAttemptedWithoutEligibleCells.map((c) => c.key),
    ['opt=O3'],
  );
  assert.match(formatReport(r), /configs attempted that contributed no eligible cell: opt=O3/);
});

test('a broken control is excluded even when its state is LOST', () => {
  // The complement of the test above: exclusion is not a quiet way of dropping
  // inconvenient losses either. It must not raise the score.
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'LOST', controlHeld: false }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 0, den: 1 });
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD], 1);
});

// --- 5. incomplete and inapplicable verdicts leave the denominator ------------

test('completesTheCheck=false, NOT_OBSERVED and NOT_APPLICABLE are each excluded', () => {
  const cells = [
    cell({ cellId: 'live', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'gone', config: { opt: 'O2' }, state: 'LOST' }),
    // The three shapes that must never be read as survival.
    cell({ cellId: 'incomplete', config: { opt: 'O1' }, state: 'PRESENT', completesTheCheck: false }),
    cell({ cellId: 'unseen', config: { opt: 'O1' }, state: 'NOT_OBSERVED', completesTheCheck: false }),
    cell({ cellId: 'moot', config: { opt: 'O3' }, state: 'NOT_APPLICABLE' }),
  ];
  const r = computeFragility(cells);

  // Eligible are only `live` and `gone`: 1/2. Counting the other three as
  // survivors would give 1/5 = 0.200.
  assert.deepEqual(r.score, { num: 1, den: 2 });
  assert.equal(r.counts.excluded, 3);
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.CHECK_DID_NOT_COMPLETE], 2);
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.NOT_APPLICABLE], 1);
});

test('a NOT_OBSERVED cell that claims to have completed is still excluded', () => {
  const r = computeFragility([
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'NOT_OBSERVED', completesTheCheck: true }),
  ]);
  assert.deepEqual(r.score, { num: 0, den: 1 });
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.NOT_OBSERVED], 1);
});

test('ABSENT is excluded as never established rather than counted either way', () => {
  const r = computeFragility([
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'LOST' }),
    cell({ cellId: 'c', config: { opt: 'O3' }, state: 'ABSENT' }),
  ]);
  assert.deepEqual(r.score, { num: 1, den: 2 });
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.NEVER_ESTABLISHED], 1);
});

test('REINTRODUCED counts as surviving and stays visible in stateCounts', () => {
  const r = computeFragility([
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'REINTRODUCED' }),
    cell({ cellId: 'c', config: { opt: 'O3' }, state: 'LOST' }),
  ]);
  assert.deepEqual(r.score, { num: 1, den: 3 });
  assert.equal(r.stateCounts.REINTRODUCED, 1);
});

test('classifyCell reports the broken control ahead of whatever the state says', () => {
  const v = classifyCell(cell({ state: 'NOT_OBSERVED', controlHeld: false, completesTheCheck: false }));
  assert.deepEqual(v, { eligible: false, reason: EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD });
});

// The pair to the test above. `false` is a control that ran and failed; `null` is
// a control that never ran, which is what a producer writes on a cell it could
// not read at all. Filing the second under control-did-not-hold is a report that
// a control failed when none was measured, and in the first real envelope this
// module scored it was 16 of the 20 removals. The score does not move -- both are
// excluded -- so only the breakdown catches this, which is why the breakdown is
// asserted rather than the number.
test('a control that was never measured is not reported as a control that failed', () => {
  const v = classifyCell(cell({ state: 'NOT_OBSERVED', controlHeld: null, completesTheCheck: null }));
  assert.deepEqual(v, { eligible: false, reason: EXCLUSION_REASONS.NOT_OBSERVED });
});

test('the two removals are counted apart in the report', () => {
  const r = computeFragility([
    cell({ cellId: 'ok', state: 'PRESENT' }),
    cell({ cellId: 'never-ran', state: 'NOT_OBSERVED', controlHeld: null, completesTheCheck: null }),
    cell({ cellId: 'ran-and-failed', state: 'LOST', controlHeld: false }),
  ]);
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.NOT_OBSERVED], 1);
  assert.equal(r.excludedByReason[EXCLUSION_REASONS.CONTROL_DID_NOT_HOLD], 1);
  assert.match(formatReport(r), /excluded 1 for state-not-observed/);
  assert.match(formatReport(r), /excluded 1 for control-did-not-hold/);
});

// --- 6. nothing to measure is refused, never scored 0 ------------------------

test('an empty matrix is refused rather than scored 0.000', () => {
  assert.throws(() => computeFragility([]), (err) => {
    assert.ok(err instanceof FragilityIncompleteError);
    assert.equal(err.exitCode, 3);
    assert.match(err.message, /empty/);
    return true;
  });
});

test('a matrix whose every cell is ineligible is refused, with the removals named', () => {
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT', controlHeld: false }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'NOT_OBSERVED', completesTheCheck: false }),
    cell({ cellId: 'c', config: { opt: 'O3' }, state: 'NOT_APPLICABLE' }),
  ];
  assert.throws(() => computeFragility(cells), (err) => {
    assert.ok(err instanceof FragilityIncompleteError, 'must not be scored 0/0');
    assert.equal(err.exitCode, 3);
    assert.equal(err.detail.counts.eligible, 0);
    assert.equal(err.detail.counts.excluded, 3);
    assert.match(err.message, /control-did-not-hold=1/);
    assert.match(err.message, /check-did-not-complete=1/);
    assert.match(err.message, /state-not-applicable=1/);
    return true;
  });
});

test('scoreAsFloat refuses a zero denominator instead of returning NaN', () => {
  assert.throws(() => scoreAsFloat({ num: 0, den: 0 }), FragilityIncompleteError);
});

// --- 7. the score is not quotable without its envelope -----------------------

test('both serialisers refuse a report whose measuredConfigs is missing', () => {
  const r = computeFragility(uniform('LOST', ['O0', 'O2']));
  for (const missing of [{ ...r, measuredConfigs: undefined }, { ...r, measuredConfigs: [] }]) {
    assert.throws(() => toEvidenceJson(missing), FragilityInputError);
    assert.throws(() => formatReport(missing), FragilityInputError);
  }
});

test('every rendered form names the configs the score was measured over', () => {
  const r = computeFragility(uniform('LOST', ['O0', 'O2']));
  const text = formatReport(r);
  assert.match(text, /opt=O0/);
  assert.match(text, /opt=O2/);
  assert.match(text, /2 measured config/);
  const json = toEvidenceJson(r);
  assert.deepEqual(json.measuredConfigs.map((c) => c.key), ['opt=O0', 'opt=O2']);
  // There is no key that carries the score without the envelope beside it.
  assert.ok('measuredConfigs' in json && 'score' in json);
  // The denominator is enumerable: exactly `den` cells are listed as counted.
  assert.equal(json.counted.length, json.score.den);
});

test('a score is refused as unquotable when the report is frozen without an envelope', () => {
  assert.throws(() => formatReport({ score: { num: 1, den: 2 }, scoreText: '0.500' }), FragilityInputError);
});

// --- envelope honesty: axes that were never varied --------------------------

test('axes that no cell varied are named as unmeasured', () => {
  const r = computeFragility(uniform('PRESENT', ['O0', 'O2']));
  assert.deepEqual(r.unmeasuredAxes, ['ndebug', 'lto', 'target']);
  assert.deepEqual(r.axes.opt, { values: ['O0', 'O2'], varied: true });
  assert.match(formatReport(r), /axes never varied in this envelope: ndebug, lto, target/);
});

test('an axis present but constant is reported as constant, not as varied', () => {
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0', ndebug: true }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2', ndebug: true }, state: 'LOST' }),
  ];
  const r = computeFragility(cells);
  assert.equal(r.axes.ndebug.varied, false);
  assert.match(formatReport(r), /axes present but held constant: ndebug=true/);
});

// --- polarity: a must-not-appear property reads the other way round ---------

test('for a must-not-appear property PRESENT is the failure and LOST is the success', () => {
  // The real `notappear.deny-path-call` shape: the forbidden call is there at
  // -O0 and gone at -O2. On the must-survive table this would score 1/2 with
  // the wrong cell blamed; here the failing cell is the -O0 one.
  const cells = [
    cell({ cellId: 'notappear-O0', polarity: 'must-not-appear', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'notappear-O2', polarity: 'must-not-appear', config: { opt: 'O2' }, state: 'LOST' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 1, den: 2 });
  const byCell = Object.fromEntries(r.counted.map((c) => [c.cellId, c.heldHere]));
  assert.equal(byCell['notappear-O0'], false, 'the forbidden call being present is the failure');
  assert.equal(byCell['notappear-O2'], true, 'the forbidden call going away is the property working');
});

test('a must-not-appear property that never appears scores 0, not 1', () => {
  const cells = [
    cell({ cellId: 'a', polarity: 'must-not-appear', config: { opt: 'O0' }, state: 'LOST' }),
    cell({ cellId: 'b', polarity: 'must-not-appear', config: { opt: 'O2' }, state: 'LOST' }),
  ];
  assert.deepEqual(computeFragility(cells).score, { num: 0, den: 2 });
});

test('ABSENT counts as holding for must-not-appear but is excluded for must-survive', () => {
  const na = computeFragility([
    cell({ cellId: 'a', polarity: 'must-not-appear', config: { opt: 'O0' }, state: 'ABSENT' }),
  ]);
  assert.deepEqual(na.score, { num: 0, den: 1 }, 'the forbidden thing was never there');

  assert.throws(
    () => computeFragility([cell({ cellId: 'a', config: { opt: 'O0' }, state: 'ABSENT' })]),
    FragilityIncompleteError,
    'for must-survive, ABSENT establishes nothing and leaves no denominator',
  );
});

test('blended polarities are counted and named in the rendered report', () => {
  const cells = [
    cell({ cellId: 's-O2', propertyId: 'erasure.wipe', config: { opt: 'O2' }, state: 'LOST' }),
    cell({ cellId: 'n-O2', propertyId: 'notappear.x', polarity: 'must-not-appear', config: { opt: 'O2' }, state: 'LOST' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 1, den: 2 });
  assert.deepEqual(r.polarityCounts, { 'must-survive': 1, 'must-not-appear': 1 });
  assert.match(formatReport(r), /two property families are blended here/);
});

test('an unrecognised polarity is rejected rather than defaulted', () => {
  assert.throws(() => computeFragility([cell({ polarity: 'whatever' })]), FragilityInputError);
});

// --- grouping ---------------------------------------------------------------

test('each property gets its own score over its own envelope', () => {
  const cells = [
    cell({ cellId: 'e-O0', propertyId: 'erasure.wipe', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'e-O2', propertyId: 'erasure.wipe', config: { opt: 'O2' }, state: 'LOST' }),
    cell({ cellId: 'a-O0', propertyId: 'authz.failclosed', config: { opt: 'O0' }, state: 'PRESENT' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 1, den: 3 });
  assert.deepEqual(r.byProperty['erasure.wipe'].score, { num: 1, den: 2 });
  assert.deepEqual(r.byProperty['authz.failclosed'].score, { num: 0, den: 1 });
  // authz was only measured at O0 and must not borrow erasure's O2 column.
  assert.deepEqual(r.byProperty['authz.failclosed'].measuredConfigs.map((c) => c.key), ['opt=O0']);
});

test('a property with no eligible cell gets no score and is named as such', () => {
  const cells = [
    cell({ cellId: 'e-O0', propertyId: 'erasure.wipe', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'x-O2', propertyId: 'notappear.x', config: { opt: 'O2' }, state: 'NOT_APPLICABLE' }),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.propertiesWithoutScore, ['notappear.x']);
  assert.equal(r.byProperty['notappear.x'].score, null);
  assert.match(formatReport(r), /properties with no score at all: notappear\.x/);
});

// --- input validation: a malformed cell stops the run -----------------------

test('a missing or non-boolean controlHeld is rejected, not read as true', () => {
  const bad = cell({ cellId: 'a' });
  delete bad.controlHeld;
  assert.throws(() => computeFragility([bad]), FragilityInputError);
  assert.throws(
    () => computeFragility([cell({ cellId: 'a', controlHeld: 'yes' })]),
    FragilityInputError,
  );
});

test('an unrecognised state is rejected rather than bucketed', () => {
  assert.throws(() => computeFragility([cell({ state: 'SURVIVED' })]), FragilityInputError);
  // The two labels the neighbouring envelope assembler writes are refused too,
  // and the refusal names the conflict instead of just failing to parse.
  for (const label of ['BROKEN_MEASUREMENT', 'UNSUPPORTED']) {
    assert.throws(() => computeFragility([cell({ state: label })]), (err) => {
      assert.ok(err instanceof FragilityInputError);
      assert.match(err.message, /interfaces\.md section 3/);
      assert.match(err.message, /envelope assembler/);
      return true;
    });
  }
  // Guards the vocabulary against silent drift away from interfaces.md s3.
  assert.deepEqual(KNOWN_STATES, [
    'PRESENT',
    'ABSENT',
    'LOST',
    'REINTRODUCED',
    'NOT_APPLICABLE',
    'NOT_OBSERVED',
  ]);
});

test('a cell with no config is rejected, because it cannot sit in an envelope', () => {
  assert.throws(() => computeFragility([cell({ config: {} })]), FragilityInputError);
  assert.throws(() => computeFragility([cell({ config: { opt: null } })]), FragilityInputError);
});

test('a duplicated cellId is rejected rather than double-weighted', () => {
  const cells = [
    cell({ cellId: 'dup', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'dup', config: { opt: 'O2' }, state: 'LOST' }),
  ];
  assert.throws(() => computeFragility(cells), FragilityInputError);
});

test('configKey is order-independent so one column is not counted as two', () => {
  assert.equal(configKey({ opt: 'O2', ndebug: true }), configKey({ ndebug: true, opt: 'O2' }));
});

// --- interfaces.md section 5: no absolute path may reach the record ---------

test('the evidence form refuses to carry an absolute path out of its input', () => {
  const r = computeFragility([
    cell({ cellId: '/mnt/c/build/erasure-O0', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'erasure-O2', config: { opt: 'O2' }, state: 'LOST' }),
  ]);
  // The path reaches the record through `counted`, which is only there because
  // this test found that an eligible cell's id was previously emitted nowhere.
  assert.deepEqual(r.counted.map((c) => c.cellId), ['/mnt/c/build/erasure-O0', 'erasure-O2']);
  assert.throws(() => toEvidenceJson(r), (err) => {
    assert.ok(err instanceof FragilityInputError);
    assert.match(err.message, /absolute path/);
    return true;
  });
});

// --- thresholds -------------------------------------------------------------

test('a threshold is an integer ratio and is compared without floating point', () => {
  assert.deepEqual(parseThreshold('1/2'), { num: 1, den: 2 });
  assert.throws(() => parseThreshold('0.5'), FragilityInputError);
  assert.throws(() => parseThreshold('1/0'), FragilityInputError);
  assert.equal(ratioExceeds({ num: 2, den: 3 }, { num: 1, den: 2 }), true);
  assert.equal(ratioExceeds({ num: 1, den: 2 }, { num: 1, den: 2 }), false);
});

// --- CLI: exit codes follow interfaces.md section 7 --------------------------

function runCli(cells, extra = []) {
  const dir = mkdtempSync(join(tmpdir(), 'envelope-'));
  const file = join(dir, 'matrix.json');
  writeFileSync(file, JSON.stringify(cells));
  try {
    const stdout = execFileSync(process.execPath, [CLI, file, ...extra], { encoding: 'utf8' });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    return { code: err.status, stdout: String(err.stdout ?? ''), stderr: String(err.stderr ?? '') };
  }
}

test('the CLI exits 0 and prints the envelope alongside the score', () => {
  const res = runCli(uniform('LOST', ['O0', 'O2']));
  assert.equal(res.code, 0);
  assert.match(res.stdout, /fragility 1\.000/);
  assert.match(res.stdout, /opt=O0 \| opt=O2/);
});

test('the CLI exits 3 rather than 0 when there is nothing eligible to score', () => {
  const res = runCli([cell({ cellId: 'a', config: { opt: 'O2' }, state: 'NOT_OBSERVED', completesTheCheck: false })]);
  assert.equal(res.code, 3, 'a run that measured nothing must not exit 0');
  assert.match(res.stderr, /no fragility score/);
});

test('the CLI exits 3 on an empty matrix', () => {
  assert.equal(runCli([]).code, 3);
});

test('the CLI exits 2 when a given threshold is exceeded', () => {
  const res = runCli(uniform('LOST', ['O0', 'O2']), ['--max-score', '1/2']);
  assert.equal(res.code, 2);
  assert.match(res.stderr, /exceeds the threshold/);
});

test('the CLI exits 0 when the score is at the threshold', () => {
  const cells = [
    cell({ cellId: 'a', config: { opt: 'O0' }, state: 'PRESENT' }),
    cell({ cellId: 'b', config: { opt: 'O2' }, state: 'LOST' }),
  ];
  assert.equal(runCli(cells, ['--max-score', '1/2']).code, 0);
});

test('the CLI --json form is integer-only and carries measuredConfigs', () => {
  const res = runCli(uniform('LOST', ['O0', 'O2']), ['--json']);
  assert.equal(res.code, 0);
  const json = JSON.parse(res.stdout);
  assert.deepEqual(json.score, { num: 2, den: 2 });
  assert.equal(json.measuredConfigs.length, 2);
  const floats = [];
  (function walk(v) {
    if (typeof v === 'number' && !Number.isInteger(v)) floats.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  })(json);
  assert.deepEqual(floats, [], 'interfaces.md section 5 rule 4: every number is an integer');
});
