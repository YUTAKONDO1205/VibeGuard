// The alias table, both directions and both refusals.
//
// The first test is the one that matters most and is the reason this file reads
// a schema rather than a constant: the observation vocabulary is pinned against
// `../../schema/observation.schema.json` itself. A table that drifted from the
// schema it claims to alias would otherwise agree with its own copy of the list
// forever, which is the failure mode the whole module was written to stop —
// `README.md` describes a producer copying `observeAt` straight into
// `plannedCheckpoints` and getting a true report whose cause is a spelling.

import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import {
  CHECKPOINT_MAP,
  CheckpointVocabularyError,
  FIDELITY,
  LANE_CHECKPOINT_MAPS,
  OBSERVATION_CHECKPOINTS,
  RECORD_CHECKPOINTS,
  laneCheckpoint,
  mappingRecord,
  recordCheckpointOrder,
  recordCheckpointSources,
  toRecordCheckpoint,
} from '../checkpoint-map.mjs';
import { EVIDENCE_DIR, REPO_ROOT } from './helpers.mjs';

test('the observation vocabulary is the schema\'s, read from the schema', () => {
  const schema = JSON.parse(
    readFileSync(join(REPO_ROOT, 'compiler', 'schema', 'observation.schema.json'), 'utf8'),
  );
  assert.deepEqual(OBSERVATION_CHECKPOINTS, schema.definitions.checkpoint.enum);
});

test('the record vocabulary is the one verify.mjs names intervals between', () => {
  // Read out of the verifier's source rather than imported: STAGE_TABLE is not
  // exported, and a test that imported a constant would pass against a table
  // that had been edited around it.
  const src = readFileSync(join(EVIDENCE_DIR, 'verify.mjs'), 'utf8');
  const table = /const STAGE_TABLE = Object\.freeze\(\[([\s\S]*?)\]\);/.exec(src);
  assert.ok(table, 'verify.mjs still carries a STAGE_TABLE');
  const named = new Set();
  for (const m of table[1].matchAll(/(?:last|first): '([a-z-]+)'/g)) named.add(m[1]);
  for (const c of named) {
    assert.ok(RECORD_CHECKPOINTS.includes(c), `${c} is named by STAGE_TABLE and missing from RECORD_CHECKPOINTS`);
  }
});

test('every observation checkpoint has a row, including the two with no answer', () => {
  assert.equal(CHECKPOINT_MAP.length, OBSERVATION_CHECKPOINTS.length);
  assert.deepEqual(CHECKPOINT_MAP.map((r) => r.observation), [...OBSERVATION_CHECKPOINTS]);
  for (const row of CHECKPOINT_MAP) {
    assert.ok(row.why.length > 0, `${row.observation} has no reason`);
    if (row.record === null) assert.equal(row.fidelity, FIDELITY.REFUSED);
    else assert.ok(RECORD_CHECKPOINTS.includes(row.record));
  }
});

test('after-pass is ir-post and pre-opt-ir is ir-pre', () => {
  assert.equal(toRecordCheckpoint('after-pass').checkpoint, 'ir-post');
  assert.equal(toRecordCheckpoint('after-pass').fidelity, FIDELITY.EXACT);
  assert.equal(toRecordCheckpoint('pre-opt-ir').checkpoint, 'ir-pre');
});

test('object and linked convert, and say that something was lost doing it', () => {
  assert.equal(toRecordCheckpoint('object').checkpoint, 'asm');
  assert.equal(toRecordCheckpoint('object').fidelity, FIDELITY.NEAR);
  assert.equal(toRecordCheckpoint('linked').checkpoint, 'artifact');
  assert.equal(toRecordCheckpoint('linked').fidelity, FIDELITY.NEAR);
});

test('invocation and process are refused rather than approximated', () => {
  for (const word of ['invocation', 'process']) {
    assert.throws(
      () => toRecordCheckpoint(word),
      (e) => e instanceof CheckpointVocabularyError && /no counterpart/.test(e.message),
      `${word} must be refused`,
    );
  }
});

test('a record checkpoint offered as an observation checkpoint is refused, and told why', () => {
  assert.throws(
    () => toRecordCheckpoint('ir-post'),
    (e) => e instanceof CheckpointVocabularyError && /already a RECORD checkpoint/.test(e.message),
  );
  assert.throws(() => toRecordCheckpoint('nonesuch'), CheckpointVocabularyError);
});

test('the reverse is a relation, not a function', () => {
  assert.deepEqual(recordCheckpointSources('artifact'), ['linked', 'artifact']);
  assert.deepEqual(recordCheckpointSources('preprocess'), []);
  assert.deepEqual(recordCheckpointSources('ast'), ['ast']);
});

test('checkpoint order is pipeline order', () => {
  assert.ok(recordCheckpointOrder('ir-pre') < recordCheckpointOrder('ir-post'));
  assert.ok(recordCheckpointOrder('ir-post') < recordCheckpointOrder('artifact'));
  assert.throws(() => recordCheckpointOrder('after-pass'), CheckpointVocabularyError);
});

test('the lane table separates two readings that carry one checkpoint word', () => {
  const compile = laneCheckpoint('lto-window', { checkpoint: 'after-pass', stage: 'compile' });
  const link = laneCheckpoint('lto-window', { checkpoint: 'after-pass', stage: 'lto-backend' });
  assert.equal(compile.checkpoint, 'ir-pre');
  assert.equal(link.checkpoint, 'ir-post');
  // The point of the separation: this pair, and only this pair, is the interval
  // STAGE_TABLE calls `ir-pass`, which is the one a record may name a pass at.
  assert.notEqual(compile.checkpoint, link.checkpoint);
});

test('a lane with no table, and a pair with no row, are both refused', () => {
  assert.throws(
    () => laneCheckpoint('spike', { checkpoint: 'after-pass', stage: 'compile' }),
    (e) => e instanceof CheckpointVocabularyError && /no checkpoint table for the lane/.test(e.message),
  );
  assert.throws(
    () => laneCheckpoint('lto-window', { checkpoint: 'after-pass', stage: 'backend' }),
    (e) => e instanceof CheckpointVocabularyError && /no row for checkpoint/.test(e.message),
  );
  // Not silently forwarded to the general table: a pair nobody decided about
  // has no answer here either.
  assert.throws(() => laneCheckpoint('lto-window', { checkpoint: 'ast', stage: 'compile' }), CheckpointVocabularyError);
});

test('every lane row lands on a record checkpoint and says why', () => {
  for (const [lane, rows] of Object.entries(LANE_CHECKPOINT_MAPS)) {
    assert.ok(rows.length > 0, `${lane} has no rows`);
    for (const r of rows) {
      assert.ok(OBSERVATION_CHECKPOINTS.includes(r.checkpoint), `${lane}: ${r.checkpoint}`);
      assert.ok(RECORD_CHECKPOINTS.includes(r.record), `${lane}: ${r.record}`);
      assert.ok(r.why.length > 0, `${lane}: ${r.checkpoint}@${r.stage} has no reason`);
    }
  }
});

test('the mapping a record carries is the rows that were used, deduplicated', () => {
  const m = mappingRecord('lto-window', [
    { from: 'after-pass', stage: 'compile', to: 'ir-pre', fidelity: FIDELITY.NEAR },
    { from: 'after-pass', stage: 'compile', to: 'ir-pre', fidelity: FIDELITY.NEAR },
    { from: 'after-pass', stage: 'lto-backend', to: 'ir-post', fidelity: FIDELITY.EXACT },
  ]);
  assert.equal(m.rows.length, 2);
  assert.equal(m.lane, 'lto-window');
  assert.equal(m.contract, 'compiler/schema/interfaces.md section 5');
});
