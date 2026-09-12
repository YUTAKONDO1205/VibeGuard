// The producer, held to the verifier.
//
// WHAT THE INPUT IS, AND WHAT IT IS NOT  —  [SPEC-INPUT]
//
//   The lane result below is CONSTRUCTED. `compiler/eval/lto-window` writes its
//   result to the lab directory named by `--out` (interfaces.md §1: measurement
//   output lives outside the checkout), so there is no recorded run of it on
//   disk here to point this at, and this suite may not compile anything to make
//   one. What is built below is the shape that lane writes — the fields are
//   taken from `run-lto-window.mjs` (`results.cells.push({...})`) and from
//   `lib/cell.mjs`'s `finish()`, not invented — with plausible verdicts in it.
//
//   So these tests establish that the producer converts THAT SHAPE correctly and
//   that the verifier agrees with what comes out. They do not establish that a
//   real run of the lane produces a record that verifies; that is one command,
//   and `README.md`'s "Running it" section carries it. Until it has been run,
//   the producer's end-to-end status is [SPEC-INPUT] and this comment is where
//   it says so.
//
// WHAT EACH CASE IS FOR
//
//   1. produce -> verify exits 0, against the declaration as an EXTERNAL
//      document (`--declared`). Run without it the source would be the record's
//      own copy, which `README.md` calls the weakest of the three.
//   2. take one cell out of the lane result and the SAME producer, over the SAME
//      declaration, emits a record the verifier refuses. This is the case that
//      matters: a producer that could only ever emit records that pass would
//      make the ledger unfalsifiable, and the declaration is what stops it —
//      the missing cell is still declared, so it is still counted.
//   3. no declaration, nothing written. Not a warning, not a fallback.

import { strict as assert } from 'node:assert';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { DECLARATION_ABSENT, ProducerError, declarationFromPolicy, produceRecord, subjectKeyOf } from '../produce.mjs';
import { EVIDENCE_DIR, VERIFY, cleanup, countingOf, makeScratch, run } from './helpers.mjs';

const PRODUCE = join(EVIDENCE_DIR, 'produce.mjs');

/** Pinned so that two runs of these tests digest identically. */
const PINNED_CONTEXT = Object.freeze({
  generatedAt: '1970-01-01T00:00:00.000Z',
  timeSource: 'SOURCE_DATE_EPOCH',
  sourceDateEpoch: 0,
});

const SUBJECTS = Object.freeze({
  xtuFull: 'lto-window.xtu.full.clang',
  erasureFull: 'lto-window.erasure.full.clang',
  xtuThin: 'lto-window.xtu.thin.clang',
});

/**
 * The policy: three properties, each observed at the two points the lane reads.
 *
 * `pre-opt-ir` and `after-pass` are the OBSERVATION vocabulary — this is what a
 * `.vgpolicy.json` holds. Nothing in this file spells a record checkpoint; the
 * conversion is the producer's job and is the thing under test.
 */
function policy() {
  return {
    properties: Object.values(SUBJECTS).map((id) => ({
      id,
      kind: 'must-survive',
      observeAt: ['pre-opt-ir', 'after-pass'],
    })),
  };
}

/** interfaces.md §5's two blocks, which a lane result does not carry. */
function envelope() {
  return {
    toolchain: {
      digest: '0'.repeat(64),
      clang: '18.1.3',
      packages: [{ name: 'llvm-18-dev', version: '18.1.3' }],
    },
    command: { argv: ['clang-18', '-O2', '-flto', '-c', 'fixtures/xtu/use.c', '-o', 'work/use.o'] },
  };
}

/**
 * A result in the shape `compiler/eval/lto-window/run-lto-window.mjs` writes.
 *
 * Six cells: for each of three subjects a compile-window reading and a
 * link-window reading. Both carry `checkpoint: 'after-pass'` and are told apart
 * by `stage` — which is exactly the collision `checkpoint-map.mjs`'s lane table
 * exists for, and the reason this fixture is worth running the producer over.
 *
 * @param {{drop?: string[]}} [opts] cell ids to leave out, for case 2
 */
function laneResult({ drop = [] } = {}) {
  const compile = (fixture, form) => ({
    id: `${fixture}.${form}.compile`,
    fixture,
    form,
    vendor: 'clang',
    window: 'compile',
    stage: 'compile',
    checkpoint: 'after-pass',
    measurement: 'OK',
    state: 'PRESENT',
    controlHeld: true,
    attribution: null,
    reasons: [],
    notes: [],
  });
  const cells = [
    compile('xtu', 'full'),
    {
      id: 'xtu.full.link',
      fixture: 'xtu',
      form: 'full',
      vendor: 'clang',
      window: 'link',
      stage: 'lto-backend',
      checkpoint: 'after-pass',
      measurement: 'OK',
      state: 'LOST',
      controlHeld: true,
      attribution: { pass: 'GlobalDCEPass', unit: 'handle', checkpoint: 'after-pass' },
      subjectHistory: {
        state: 'LOST',
        firstLoss: { pass: 'GlobalDCEPass', seq: 41 },
        everPresent: true,
        everLost: true,
        everReintroduced: false,
        fate: 'removed',
      },
      reasons: [],
      notes: [],
    },
    compile('erasure', 'full'),
    {
      id: 'erasure.full.link',
      fixture: 'erasure',
      form: 'full',
      vendor: 'clang',
      window: 'link',
      stage: 'lto-backend',
      checkpoint: 'after-pass',
      measurement: 'OK',
      state: 'PRESENT',
      controlHeld: true,
      attribution: null,
      subjectHistory: { state: 'PRESENT', firstLoss: null, everPresent: true, everLost: false },
      reasons: [],
      notes: [],
    },
    compile('xtu', 'thin'),
    {
      // The refusal the lane always reaches for ThinLTO: lld builds one
      // PassBuilder per backend module and the observer keeps one tracker.
      id: 'xtu.thin.link',
      fixture: 'xtu',
      form: 'thin',
      vendor: 'clang',
      window: 'link',
      stage: 'lto-backend',
      checkpoint: 'after-pass',
      measurement: 'BROKEN_MEASUREMENT',
      state: 'NOT_OBSERVED',
      controlHeld: null,
      attribution: null,
      reasons: ['plugin-multi-passbuilder'],
      notes: [],
    },
  ];
  return {
    schema: 'lto-window-v1',
    lane: 'lto-window',
    generatedBy: 'compiler/eval/lto-window/run-lto-window.mjs',
    optLevel: '-O2',
    cells: cells.filter((c) => !drop.includes(c.id)),
    unobserved: ['xtu.thin.link-time-attribution'],
    skipped: { negativeControl: false, gcc: true, thinltoEvidence: false },
  };
}

/** Produce into a scratch directory and hand back the two file paths. */
function produceInto(dir, opts = {}) {
  const declaration = declarationFromPolicy(policy(), { lane: 'lto-window' });
  const { record, counts, imbalances } = produceRecord({
    lane: laneResult(opts),
    declaration,
    envelope: envelope(),
    context: PINNED_CONTEXT,
  });
  const declFile = join(dir, 'declaration.json');
  const recFile = join(dir, 'evidence.json');
  writeFileSync(declFile, `${JSON.stringify(declaration, null, 2)}\n`, 'utf8');
  writeFileSync(recFile, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
  return { declFile, recFile, record, declaration, counts, imbalances };
}

/* ------------------------------------------------------ the declaration -- */

test('the declaration converts observeAt into the record vocabulary', () => {
  const d = declarationFromPolicy(policy(), { lane: 'lto-window' });
  assert.equal(d.schemaVersion, 'evidence-declaration-v1');
  assert.deepEqual(d.plannedCheckpoints, ['ir-pre', 'ir-post']);
  assert.equal(d.properties.length, 3);
  for (const p of d.properties) assert.deepEqual(p.plannedCheckpoints, ['ir-pre', 'ir-post']);
  // It says which rows it used, which is what interfaces.md §5 asks of a
  // producer that maps between the vocabularies.
  assert.equal(d.source.kind, 'policy');
  assert.deepEqual(d.source.checkpointMapping.rows.map((r) => `${r.from}->${r.to}`).sort(), [
    'after-pass->ir-post',
    'pre-opt-ir->ir-pre',
  ]);
});

test('a policy that plans two observations landing on one record cell is refused', () => {
  // `linked` and `artifact` both convert to `artifact`. De-duplicating them
  // would halve that property's denominator without telling anybody.
  assert.throws(
    () => declarationFromPolicy({ properties: [{ id: 'p', kind: 'must-survive', observeAt: ['linked', 'artifact'] }] }),
    (e) => e instanceof ProducerError && /both convert to the record checkpoint/.test(e.message),
  );
});

test('a policy property planned nowhere, and one at a refused checkpoint, are both refused', () => {
  assert.throws(
    () => declarationFromPolicy({ properties: [{ id: 'p', kind: 'must-survive' }] }),
    (e) => e instanceof ProducerError && /names no observeAt/.test(e.message),
  );
  assert.throws(
    () => declarationFromPolicy({ properties: [{ id: 'p', kind: 'must-survive', observeAt: ['process'] }] }),
    (e) => e instanceof ProducerError && /no counterpart in the record/.test(e.message),
  );
});

/* ------------------------------------------------------------ the shape -- */

test('the subject key keeps the gcc row apart from the clang row it shares a form with', () => {
  const clang = subjectKeyOf('lto-window', { id: 'xtu.full.link', fixture: 'xtu', form: 'full', vendor: 'clang' });
  const gcc = subjectKeyOf('lto-window', { id: 'xtu.gcc.link', fixture: 'xtu', form: 'full', vendor: 'gcc' });
  assert.notEqual(clang, gcc);
  assert.equal(clang, SUBJECTS.xtuFull);
});

test('the produced record takes its declared counts from the declaration, not from itself', () => {
  const dir = makeScratch('produce-counts');
  try {
    // One subject is measured at one checkpoint only; the declaration still
    // opens two accounts for it, so `planned` stays 6 while `observed` falls.
    const full = produceInto(dir).record;
    assert.deepEqual(full.coverage, { observed: 5, planned: 6 });
    assert.equal(full.declaredProperties.length, 3);
    assert.deepEqual(full.ledger.entries.map((e) => e.declared), [3, 3]);

    const short = produceRecord({
      lane: laneResult({ drop: ['erasure.full.compile'] }),
      declaration: declarationFromPolicy(policy(), { lane: 'lto-window' }),
      envelope: envelope(),
      context: PINNED_CONTEXT,
    }).record;
    assert.deepEqual(short.coverage, { observed: 4, planned: 6 });
    // The denominator did not move with the numerator. That is the whole point.
    assert.deepEqual(short.ledger.entries.map((e) => e.declared), [3, 3]);
    assert.equal(short.declaredProperties.length, 3);
  } finally {
    cleanup(dir);
  }
});

test('the link-time pass attribution survives into firstLoss, because the interval is ir-pass', () => {
  const dir = makeScratch('produce-attr');
  try {
    const { record } = produceInto(dir);
    const lost = record.properties.find((p) => p.propertyId === SUBJECTS.xtuFull);
    assert.deepEqual(lost.states.map((s) => `${s.checkpoint}:${s.verdict}`), ['ir-pre:PRESENT', 'ir-post:ABSENT']);
    assert.equal(lost.firstLoss.stage, 'ir-pass');
    assert.equal(lost.firstLoss.pass, 'GlobalDCEPass');
    assert.equal(lost.firstLoss.occurrence, 41);
    assert.equal(lost.confidence, 'provisional');
    // And the reading is carried verbatim as well, so nothing measured depends
    // on a field the verifier happens to allow.
    assert.equal(lost.laneAttribution.pass, 'GlobalDCEPass');
  } finally {
    cleanup(dir);
  }
});

test('a cell that read nothing posts to unobserved and its reason reaches unresolved[]', () => {
  const dir = makeScratch('produce-unobserved');
  try {
    const { record } = produceInto(dir);
    const thin = record.properties.find((p) => p.propertyId === SUBJECTS.xtuThin);
    assert.equal(thin.states[1].verdict, 'UNOBSERVED');
    assert.equal(thin.states[1].state, 'NOT_OBSERVED');
    const entry = record.unresolved.find((u) => u.propertyId === SUBJECTS.xtuThin);
    assert.equal(entry.checkpoint, 'ir-post');
    assert.match(entry.reason, /multi-passbuilder/);
    // Booked to `unobserved`, never to `unresolved`: the suspense account is for
    // cells with no state at all.
    const irPost = record.ledger.entries.find((e) => e.checkpoint === 'ir-post');
    assert.equal(irPost.unobserved, 1);
    assert.equal(irPost.unresolved, 0);
  } finally {
    cleanup(dir);
  }
});

test('a cell that read nothing and gives no reason is refused rather than written', () => {
  const lane = laneResult();
  lane.cells.find((c) => c.id === 'xtu.thin.link').reasons = [];
  assert.throws(
    () => produceRecord({
      lane,
      declaration: declarationFromPolicy(policy(), { lane: 'lto-window' }),
      envelope: envelope(),
      context: PINNED_CONTEXT,
    }),
    (e) => e instanceof ProducerError && /gives no reason/.test(e.message),
  );
});

/* ------------------------------------------------------- the round trip -- */

test('produce -> verify --record --declared exits 0 with nothing unchecked', () => {
  const dir = makeScratch('produce-roundtrip');
  try {
    const { declFile, recFile, imbalances } = produceInto(dir);
    assert.deepEqual(imbalances, []);
    const r = run(VERIFY, ['--record', recFile, '--declared', declFile]);
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.doesNotMatch(r.stdout, /^unchecked:/m);
    assert.match(r.stdout, /ledger: external declaration, 3 declared properties, 6 planned cell\(s\)/);
    assert.match(r.stdout, /ir-pre present=3 absent=0 unobserved=0 unresolved=0 of 3/);
    assert.match(r.stdout, /ir-post present=1 absent=1 unobserved=1 unresolved=0 of 3/);
    assert.deepEqual(countingOf(r), { inputs: 1, checked: 1, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('the same record verifies through the CLI, out of tree, from files on disk', () => {
  const dir = makeScratch('produce-cli');
  try {
    const policyFile = join(dir, 'policy.json');
    const laneFile = join(dir, 'lto-window.json');
    const envFile = join(dir, 'envelope.json');
    const declFile = join(dir, 'declaration.json');
    const recFile = join(dir, 'evidence.json');
    writeFileSync(policyFile, `${JSON.stringify(policy(), null, 2)}\n`, 'utf8');
    writeFileSync(laneFile, `${JSON.stringify(laneResult(), null, 2)}\n`, 'utf8');
    writeFileSync(envFile, `${JSON.stringify(envelope(), null, 2)}\n`, 'utf8');

    const declared = run(PRODUCE, ['--declare', '--policy', policyFile, '--lane', 'lto-window', '--out', declFile]);
    assert.equal(declared.status, 0, `${declared.stdout}\n${declared.stderr}`);

    const produced = run(PRODUCE, [
      '--lane', laneFile, '--declaration', declFile, '--envelope', envFile, '--out', recFile,
    ], { env: { SOURCE_DATE_EPOCH: '0' } });
    assert.equal(produced.status, 0, `${produced.stdout}\n${produced.stderr}`);
    assert.deepEqual(countingOf(produced), { inputs: 6, checked: 6, skipped: 0 });

    const verified = run(VERIFY, ['--record', recFile, '--declared', declFile]);
    assert.equal(verified.status, 0, `${verified.stdout}\n${verified.stderr}`);
  } finally {
    cleanup(dir);
  }
});

/* ------------------------------------------- the case that has to fail -- */

test('drop one cell and the producer emits a record the verifier refuses', () => {
  const dir = makeScratch('produce-dropped');
  try {
    const { declFile, recFile, record, imbalances } = produceInto(dir, { drop: ['erasure.full.compile'] });
    // The producer noticed, and wrote the record anyway. Both halves matter: a
    // producer that could not emit a failing record would never be caught by
    // anything, and one that emitted it silently would be no better than the
    // hand-written fixtures this replaces.
    assert.deepEqual(imbalances, [{ checkpoint: 'ir-pre', declared: 3, posted: 2 }]);
    const irPre = record.ledger.entries.find((e) => e.checkpoint === 'ir-pre');
    assert.equal(irPre.declared, 3);
    assert.equal(irPre.present + irPre.absent + irPre.unobserved + irPre.unresolved, 2);

    const r = run(VERIFY, ['--record', recFile, '--declared', declFile]);
    assert.equal(r.status, 2, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /VG-ART-064/);
    assert.match(r.stdout, new RegExp(SUBJECTS.erasureFull.replace(/\./g, '\\.')));
    // And the record's own tally is NOT the thing that caught it: the tally
    // agrees with the recomputation, and the imbalance is still reported.
    assert.doesNotMatch(r.stdout, /VG-ART-065/);
  } finally {
    cleanup(dir);
  }
});

test('the same drop with the declaration read out of the record still fails', () => {
  // `--declared` is the strongest source; this is the weakest. The cell is still
  // declared in `declaredProperties`, which the producer copied from the
  // declaration rather than from what it measured, so the gap is still visible.
  const dir = makeScratch('produce-dropped-weak');
  try {
    const { recFile } = produceInto(dir, { drop: ['erasure.full.compile'] });
    const r = run(VERIFY, ['--record', recFile]);
    assert.equal(r.status, 2, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, /VG-ART-064/);
    assert.match(r.stdout, /ledger: record declaration/);
  } finally {
    cleanup(dir);
  }
});

/* ------------------------------------------------ the missing declaration -- */

test('produceRecord refuses when the declaration is absent', () => {
  for (const declaration of [undefined, null]) {
    assert.throws(
      () => produceRecord({ lane: laneResult(), declaration, envelope: envelope(), context: PINNED_CONTEXT }),
      (e) => e instanceof ProducerError && e.message === DECLARATION_ABSENT,
    );
  }
});

test('the CLI refuses without --declaration and writes nothing', () => {
  const dir = makeScratch('produce-nodecl');
  try {
    const laneFile = join(dir, 'lto-window.json');
    const envFile = join(dir, 'envelope.json');
    const recFile = join(dir, 'evidence.json');
    writeFileSync(laneFile, `${JSON.stringify(laneResult(), null, 2)}\n`, 'utf8');
    writeFileSync(envFile, `${JSON.stringify(envelope(), null, 2)}\n`, 'utf8');
    const r = run(PRODUCE, ['--lane', laneFile, '--envelope', envFile, '--out', recFile]);
    assert.equal(r.status, 4, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /no declaration was given/);
    assert.equal(existsSync(recFile), false, 'no record may be written without a declaration');
  } finally {
    cleanup(dir);
  }
});

test('the envelope is required too, and named rather than filled in', () => {
  assert.throws(
    () => produceRecord({
      lane: laneResult(),
      declaration: declarationFromPolicy(policy(), { lane: 'lto-window' }),
      envelope: null,
      context: PINNED_CONTEXT,
    }),
    (e) => e instanceof ProducerError && /no envelope was given/.test(e.message),
  );
});

test('a record is refused inside the checkout, because it is measurement output', () => {
  const dir = makeScratch('produce-intree');
  try {
    const laneFile = join(dir, 'lto-window.json');
    const envFile = join(dir, 'envelope.json');
    const declFile = join(dir, 'declaration.json');
    writeFileSync(laneFile, `${JSON.stringify(laneResult(), null, 2)}\n`, 'utf8');
    writeFileSync(envFile, `${JSON.stringify(envelope(), null, 2)}\n`, 'utf8');
    writeFileSync(
      declFile,
      `${JSON.stringify(declarationFromPolicy(policy(), { lane: 'lto-window' }), null, 2)}\n`,
      'utf8',
    );
    const inTree = join(EVIDENCE_DIR, 'must-not-appear.json');
    const r = run(PRODUCE, ['--lane', laneFile, '--declaration', declFile, '--envelope', envFile, '--out', inTree]);
    assert.equal(r.status, 4, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stderr, /inside the checkout/);
    assert.equal(existsSync(inTree), false);
  } finally {
    cleanup(dir);
  }
});

test('a lane result with no cells produces nothing, and says so with exit 3', () => {
  // The counting contract, one component upstream of where it usually bites: a
  // producer that wrote a record out of nought readings would hand the verifier
  // a document that passes every check it is able to run.
  const dir = makeScratch('produce-empty');
  try {
    const laneFile = join(dir, 'lto-window.json');
    const envFile = join(dir, 'envelope.json');
    const declFile = join(dir, 'declaration.json');
    const recFile = join(dir, 'evidence.json');
    writeFileSync(laneFile, `${JSON.stringify({ ...laneResult(), cells: [] }, null, 2)}\n`, 'utf8');
    writeFileSync(envFile, `${JSON.stringify(envelope(), null, 2)}\n`, 'utf8');
    writeFileSync(
      declFile,
      `${JSON.stringify(declarationFromPolicy(policy(), { lane: 'lto-window' }), null, 2)}\n`,
      'utf8',
    );
    const r = run(PRODUCE, ['--lane', laneFile, '--declaration', declFile, '--envelope', envFile, '--out', recFile]);
    assert.equal(r.status, 3, `${r.stdout}\n${r.stderr}`);
    assert.equal(existsSync(recFile), false);
  } finally {
    cleanup(dir);
  }
});

test('the record seals through canon.mjs and its digest re-derives', () => {
  const dir = makeScratch('produce-digest');
  try {
    const { recFile, record } = produceInto(dir);
    assert.match(record.evidenceDigest, /^[0-9a-f]{64}$/);
    const r = run(VERIFY, ['--digest', recFile]);
    assert.equal(r.status, 0, `${r.stdout}\n${r.stderr}`);
    assert.match(r.stdout, new RegExp(record.evidenceDigest));
    // Two productions of the same inputs are the same bytes, `context` aside.
    const again = produceInto(makeScratch('produce-digest-2'));
    assert.equal(again.record.evidenceDigest, record.evidenceDigest);
    cleanup(again.recFile.replace(/[/\\]evidence\.json$/, ''));
    // And nothing machine-specific reached the file.
    assert.doesNotMatch(readFileSync(recFile, 'utf8'), /"[A-Za-z]:[\\/]/);
  } finally {
    cleanup(dir);
  }
});
