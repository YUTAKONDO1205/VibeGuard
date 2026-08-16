/**
 * Tests for the IrCheckpoints -> fragility-matrix adapter.
 *
 * The record fragment below is the real top-level shape, copied from the field
 * set of an actual record in the lab (the parts this adapter reads, not the
 * whole thing). It is inline for the same reason the other test file's data is:
 * a `fixtures` path segment under compiler/ is a committable measurement input
 * and scripts/check-packaging-invariants.mjs fails the build on one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { adaptRecord, AdapterError, AXES_NOT_RECORDED } from '../adapt-ir-checkpoints.mjs';
import { computeFragility } from '../fragility.mjs';

/** The shape a real record has, reduced to the fields the adapter reads. */
function record(over = {}) {
  return {
    component: 'IrCheckpoints',
    schemaVersion: 'ir-checkpoints-v0',
    propertyId: 'erasure.wipe',
    control: { held: true, minEffectObserved: 1 },
    verdict: { state: 'LOST', completesTheCheck: true, reason: 'effect removed' },
    oracle: { findingWhenPresent: false, unitOfCount: 'one IR function' },
    ...over,
  };
}

test('a record maps onto the fields the matrix needs', () => {
  assert.deepEqual(adaptRecord('erasure-O2', record()), {
    cellId: 'erasure-O2',
    propertyId: 'erasure.wipe',
    polarity: 'must-survive',
    config: { opt: 'O2' },
    state: 'LOST',
    controlHeld: true,
    completesTheCheck: true,
  });
});

test('polarity comes from oracle.findingWhenPresent, not from the property name', () => {
  // The real notappear record carries findingWhenPresent: true.
  const cell = adaptRecord(
    'notappear-O2',
    record({ propertyId: 'notappear.deny-path-call', oracle: { findingWhenPresent: true } }),
  );
  assert.equal(cell.polarity, 'must-not-appear');

  // A property whose name suggests nothing still gets the measured polarity.
  const odd = adaptRecord('weird-O2', record({ propertyId: 'zzz', oracle: { findingWhenPresent: true } }));
  assert.equal(odd.polarity, 'must-not-appear');
});

test('a record with no recorded polarity is refused rather than assumed', () => {
  // Absent entirely: caught as a missing field.
  assert.throws(() => adaptRecord('a-O2', record({ oracle: {} })), (err) => {
    assert.ok(err instanceof AdapterError);
    assert.match(err.message, /no oracle\.findingWhenPresent/);
    return true;
  });
  // Present but not a boolean: caught as an unknown polarity.
  assert.throws(
    () => adaptRecord('a-O2', record({ oracle: { findingWhenPresent: 'yes' } })),
    (err) => {
      assert.ok(err instanceof AdapterError);
      assert.match(err.message, /polarity is unknown/);
      return true;
    },
  );
});

test('the deliberately broken cells convert without being smoothed over', () => {
  // pc2: the control was named on a function the compiler may delete.
  const pc2 = adaptRecord(
    'pc2-broken-control-O2',
    record({ control: { held: false }, verdict: { state: 'LOST', completesTheCheck: false } }),
  );
  assert.equal(pc2.controlHeld, false);
  assert.equal(pc2.config.opt, 'O2');

  // pc3: the subject was not in the translation unit at all.
  const pc3 = adaptRecord(
    'pc3-missing-subject-O2',
    record({ verdict: { state: 'NOT_OBSERVED', completesTheCheck: false } }),
  );
  assert.equal(pc3.state, 'NOT_OBSERVED');
});

test('the optimisation level comes from the cell id and is refused when absent', () => {
  assert.equal(adaptRecord('erasure-O0', record()).config.opt, 'O0');
  assert.equal(adaptRecord('erasure-O3', record()).config.opt, 'O3');
  assert.throws(() => adaptRecord('erasure', record()), (err) => {
    assert.ok(err instanceof AdapterError);
    assert.equal(err.exitCode, 3);
    assert.match(err.message, /refused rather than defaulted/);
    return true;
  });
});

test('the axes the record never states are left absent, not defaulted', () => {
  const cell = adaptRecord('erasure-O2', record());
  assert.deepEqual(Object.keys(cell.config), ['opt']);
  for (const axis of AXES_NOT_RECORDED) {
    assert.equal(axis in cell.config, false, `${axis} must not be invented`);
  }
});

test('a missing field is reported rather than filled in permissively', () => {
  assert.throws(() => adaptRecord('a-O2', record({ control: {} })), AdapterError);
  assert.throws(
    () => adaptRecord('a-O2', record({ verdict: { state: 'LOST' } })),
    AdapterError,
  );
  const noProp = record();
  delete noProp.propertyId;
  assert.throws(() => adaptRecord('a-O2', noProp), AdapterError);
});

test('the adapted cells feed the scorer, and the missing axes surface there', () => {
  const cells = [
    adaptRecord('erasure-O0', record({ verdict: { state: 'PRESENT', completesTheCheck: true } })),
    adaptRecord('erasure-O2', record()),
  ];
  const r = computeFragility(cells);
  assert.deepEqual(r.score, { num: 1, den: 2 });
  // The whole point of the adapter's honesty: a one-axis sweep is reported as
  // one, so the score cannot be read as covering a configuration envelope.
  assert.deepEqual(r.unmeasuredAxes, ['ndebug', 'lto', 'target']);
});
