import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  PROPERTY_STATES,
  StateHistoryError,
  assertStatesAreSane,
  checkOracle,
  effectiveState,
  stateHistory,
} from '../src/states.mjs';

const at = (checkpoint, state, effect, control) => ({
  checkpoint,
  state,
  verdict: state === 'PRESENT' || state === 'REINTRODUCED' ? 'PRESENT' : state === 'NOT_OBSERVED' ? 'UNOBSERVED' : 'ABSENT',
  effect,
  control,
});

// ── The whole sequence ──────────────────────────────────────────────────────

test('the vocabulary is the six states of the contract', () => {
  assert.deepEqual(
    [...PROPERTY_STATES],
    ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED'],
  );
});

test('a history with two losses reports TWO losses, not one', () => {
  // This is the rule the obvious implementation breaks. `findIndex` stops at
  // the first ABSENT, reports the loss a later pass undid, and drops the loss
  // that actually reached the artefact.
  const history = stateHistory([
    at('ir-pre', 'PRESENT', 2, 2),
    at('ir-post', 'LOST', 0, 2),
    at('asm', 'REINTRODUCED', 1, 2),
    at('artifact', 'LOST', 0, 2),
  ]);
  assert.equal(history.losses.length, 2, 'both losses are kept');
  assert.equal(history.reintroductions.length, 1);
  assert.equal(history.sequence.length, 4, 'the whole sequence survives');
  assert.deepEqual(
    history.sequence.map((s) => s.state),
    ['PRESENT', 'LOST', 'REINTRODUCED', 'LOST'],
  );
  assert.deepEqual(
    history.losses.map((l) => l.to),
    ['ir-post', 'artifact'],
  );
});

test('a history with one loss reports one', () => {
  const history = stateHistory([at('ir-pre', 'PRESENT', 1, 1), at('ir-post', 'LOST', 0, 1)]);
  assert.equal(history.losses.length, 1);
  assert.equal(history.reintroductions.length, 0);
});

test('a history that never loses the property reports no loss', () => {
  const history = stateHistory([at('ir-pre', 'PRESENT', 2, 2), at('ir-post', 'PRESENT', 2, 2)]);
  assert.deepEqual(history.losses, []);
});

test('NOT_APPLICABLE is neither a loss nor an observation of presence', () => {
  const history = stateHistory([
    at('ir-pre', 'PRESENT', 1, 1),
    at('ir-post', 'NOT_APPLICABLE', 0, 1),
  ]);
  assert.deepEqual(history.losses, [], 'the referent changed; that is not a loss');
});

test('NOT_OBSERVED is counted apart from what was observed', () => {
  const history = stateHistory([
    at('ir-pre', 'PRESENT', 1, 1),
    at('asm', 'NOT_OBSERVED', 0, 1),
  ]);
  assert.equal(history.observed, 1);
  assert.equal(history.unobserved, 1);
});

test('UNOBSERVED in the record maps onto NOT_OBSERVED in the vocabulary', () => {
  assert.equal(effectiveState({ verdict: 'UNOBSERVED' }), 'NOT_OBSERVED');
  assert.equal(effectiveState({ verdict: 'PRESENT' }), 'PRESENT');
  assert.equal(effectiveState({ verdict: 'PRESENT', state: 'REINTRODUCED' }), 'REINTRODUCED');
});

// ── The oracle rule ─────────────────────────────────────────────────────────

test('a control that fell to zero is a broken measurement, not a finding', () => {
  const bad = checkOracle({ verdict: 'ABSENT', effect: 0, control: 0 });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'control-zero');
});

test('the measured shape is accepted: control stays nonzero while the subject goes to zero', () => {
  // Measured on a fresh fixture: -O0 gives 2 call sites, -O2 gives 1 because
  // the CONTROL function keeps its store. Both readings are legitimate.
  assert.deepEqual(checkOracle({ verdict: 'PRESENT', effect: 1, control: 1 }), { ok: true });
  assert.deepEqual(checkOracle({ verdict: 'ABSENT', effect: 0, control: 1 }), { ok: true });
});

test('a verdict that disagrees with its count on zero-versus-nonzero is refused', () => {
  assert.equal(checkOracle({ verdict: 'PRESENT', effect: 0, control: 1 }).ok, false);
  assert.equal(checkOracle({ verdict: 'ABSENT', effect: 2, control: 2 }).ok, false);
});

test('an entry carrying no counts is "not checked", never "checked and clean"', () => {
  assert.equal(checkOracle({ verdict: 'PRESENT' }), null);
  assert.equal(checkOracle({ verdict: 'PRESENT', effect: 1 }), null);
});

// ── The seal-time gate ──────────────────────────────────────────────────────

test('a sane record is sealed without complaint', () => {
  assert.doesNotThrow(() =>
    assertStatesAreSane({
      properties: [
        {
          propertyId: 'demo.erasure',
          states: [at('ir-pre', 'PRESENT', 1, 1), at('ir-post', 'LOST', 0, 1)],
        },
      ],
    }),
  );
});

test('a state name outside the vocabulary is refused at seal time', () => {
  assert.throws(
    () =>
      assertStatesAreSane({
        properties: [{ propertyId: 'p', states: [{ checkpoint: 'ir-pre', state: 'MAYBE' }] }],
      }),
    StateHistoryError,
  );
});

test('REINTRODUCED with no preceding loss is refused at seal time', () => {
  assert.throws(
    () =>
      assertStatesAreSane({
        properties: [
          {
            propertyId: 'p',
            states: [at('ir-pre', 'PRESENT', 1, 1), at('ir-post', 'REINTRODUCED', 1, 1)],
          },
        ],
      }),
    /no preceding loss/,
  );
});

test('a broken measurement is refused at seal time', () => {
  assert.throws(
    () =>
      assertStatesAreSane({
        properties: [{ propertyId: 'p', states: [at('ir-post', 'LOST', 0, 0)] }],
      }),
    /control count is 0/,
  );
});
