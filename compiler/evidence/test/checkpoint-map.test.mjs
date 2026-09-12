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
  // Was pinned to the literal 'compiler/schema/interfaces.md section 5' until
  // 2026-09-12. That was the misattribution in its most durable form: a citation
  // to an unratified proposal written into every record the producer emits,
  // where it would outlive the source comment that made the same claim. The pin
  // is now on the two things that have to be true of it -- it names the table
  // that is actually in force, and it does not hand the authority to §5.
  assert.match(m.contract, /compiler\/evidence\/checkpoint-map\.mjs/);
  assert.doesNotMatch(m.contract, /^compiler\/schema\/interfaces\.md/);
  assert.match(m.contract, /not part of it|proposed/i,
    'the contract field names interfaces.md without saying the mapping is only proposed for it');
});

// --- what this component says the governing document requires ----------------
//
// Added 2026-09-12. Three places in this directory attributed requirements to
// ../schema/interfaces.md that interfaces.md does not make: a "canonical mapping
// table belongs in this section" quotation (real, but from THIS directory's
// README under the heading "Suggested text, to be appended to §5"), a claim that
// §5 asks a producer to record which mapping it used (same source), and a claim
// that §5 requires `command.argv` (that is verify.mjs's VG-ART-052).
//
// None of them changed what the code does. All three would have turned a lane's
// own preference into a constraint whose origin no later reader could find --
// which is the failure this whole directory is organised against, applied to
// prose instead of to numbers.
//
// So the citations are checked the way a count is: against the source.

import { readdirSync } from 'node:fs';

const IFACE = readFileSync(join(REPO_ROOT, 'compiler/schema/interfaces.md'), 'utf8');

test('interfaces.md really does not contain the words this component used to cite it for', () => {
  // If any of these ever appears, §5 has been opened and this directory's
  // requests may have landed in it -- at which point the comments should be
  // rewritten to cite it, and this test updated to say so.
  for (const word of ['mapping', 'evidence-v1', 'argv']) {
    assert.equal(IFACE.includes(word), false,
      `interfaces.md now contains "${word}"; the citations in this directory can be revisited`);
  }
  // and the thing it DOES require, which one of the three citations was right about
  assert.match(IFACE, /"toolchain"/);
});

test('no file in this directory claims interfaces.md requires argv or a mapping', () => {
  const dir = EVIDENCE_DIR;
  const files = readdirSync(dir).filter((f) => f.endsWith('.mjs'));
  assert.ok(files.length >= 5, 'the file list is empty, so this test checks nothing');
  for (const f of files) {
    const text = readFileSync(join(dir, f), 'utf8');
    // The needle is an attribution, not a mention: interfaces.md may be named
    // beside `argv` (the corrected comments do exactly that, to say it is NOT
    // the source). What may not appear is interfaces.md being given as the
    // authority for one.
    for (const re of [
      // `[^\n]` and not `[^.\n]`: the thing being cited is `command.argv`, which
      // has a dot in it, so a needle that stopped at the first dot could not
      // reach the word it was looking for. The first version of this test did
      // exactly that and passed a mutation that put the false claim back --
      // caught by mutating the message and watching this NOT fire.
      /interfaces\.md[^\n]{0,40}(?:requires|asks for|asks a producer to record)[^\n]{0,60}argv/i,
      /interfaces\.md[^\n]{0,40}(?:asks for|requires)[^\n]{0,60}mapping/i,
    ]) {
      const m = text.match(re);
      assert.equal(m, null, `${f} cites interfaces.md for something it does not say: ${m && m[0]}`);
    }
  }
});

test('the sentence the header quotes is where the header says it is', () => {
  const readme = readFileSync(join(EVIDENCE_DIR, 'README.md'), 'utf8');
  const sentence = 'A canonical mapping table belongs in this section';
  assert.ok(readme.includes(sentence), 'README.md no longer contains the sentence the header attributes to it');
  assert.equal(IFACE.includes(sentence), false);
  // and it must still be under a heading that says it is a proposal
  const at = readme.indexOf(sentence);
  assert.match(readme.slice(Math.max(0, at - 2500), at), /Suggested text|to be appended/i,
    'the sentence is no longer marked as suggested text, so it now reads as settled');
});

// --- why the lto-window lane needs a row of its own --------------------------
//
// An adversarial review asked whether `(after-pass, compile) -> ir-pre` was
// chosen because `ir-pass` is the only interval VG-ART-055 lets a record name a
// pass at -- i.e. whether the producer is shaping its output to satisfy the
// verifier, which is the one thing this directory's README says the two must
// never do. It is not, and this test is why that is checkable rather than
// argued: under the general table the two readings collapse onto ONE record
// checkpoint, and this lane's finding is a state CHANGE between them. A record
// placing ABSENT and LOST at a single point is incoherent before any check is
// consulted.

test('the general table cannot hold this lane\'s two readings apart', () => {
  // One word for "after a pass", and this lane observes two pass pipelines.
  assert.equal(toRecordCheckpoint('after-pass').checkpoint, 'ir-post');

  const lane = LANE_CHECKPOINT_MAPS['lto-window'];
  const compileRow = lane.find((r) => r.checkpoint === 'after-pass' && r.stage === 'compile');
  const linkRow = lane.find((r) => r.checkpoint === 'after-pass' && r.stage === 'lto-backend');
  assert.ok(compileRow && linkRow);

  // The lane row exists precisely to make them different. If it ever stopped
  // doing that, the record would say a state changed at a point.
  assert.notEqual(compileRow.record, linkRow.record);
  assert.equal(compileRow.record, 'ir-pre');
  assert.equal(linkRow.record, 'ir-post');
  assert.equal(compileRow.fidelity, FIDELITY.NEAR, 'the re-based reading must stay marked as near');
  assert.equal(linkRow.fidelity, FIDELITY.EXACT);

  // And the collapse is real, not hypothetical: without the lane row both sides
  // map to the same word.
  assert.equal(toRecordCheckpoint(linkRow.checkpoint).checkpoint, linkRow.record,
    'the link reading is the one the general table already gets right');
  assert.equal(toRecordCheckpoint(compileRow.checkpoint).checkpoint, 'ir-post',
    'the general table gives the compile reading the SAME word as the link reading');
});

test('laneCheckpoint separates the two, and no other lane is quietly given this row', () => {
  const compile = laneCheckpoint('lto-window', { checkpoint: 'after-pass', stage: 'compile' });
  const link = laneCheckpoint('lto-window', { checkpoint: 'after-pass', stage: 'lto-backend' });
  assert.equal(compile.checkpoint, 'ir-pre');
  assert.equal(link.checkpoint, 'ir-post');
  // A lane with no table of its own is REFUSED rather than forwarded to the
  // general one. That is the stronger rule and the right one: re-basing a
  // reading is a decision somebody made about a particular pipeline, and a lane
  // that inherited it by default would be re-based by nobody's decision.
  for (const lane of ['spike', 'version-ladder', '', null, undefined]) {
    assert.throws(
      () => laneCheckpoint(lane, { checkpoint: 'after-pass', stage: 'compile' }),
      CheckpointVocabularyError,
      `lane ${JSON.stringify(lane)} was given lto-window's row instead of being refused`,
    );
  }
});
