/**
 * lib/observation.mjs -- the consumer for compiler/schema/emit-observation.mjs.
 *
 * WHAT THESE TESTS ARE FOR
 *
 * Three separate claims, and the third is the one that is easy to fake:
 *
 *   1. The lane can produce a record at all, THROUGH the reference writer, and
 *      the reference writer's own validator accepts it. Nothing here re-checks
 *      the schema by hand -- the record goes back into validateDocument from
 *      compiler/schema/validate-observation.mjs, which is the same file
 *      emit-observation.mjs calls, and the record carries checkpoint `process`,
 *      which nothing in this repository had ever emitted.
 *
 *   2. The cells the schema has no honest shape for are REFUSED with a code,
 *      and every one of those refusals is a real hole rather than a convenience.
 *      The gcc one is the expensive one: this lane runs on two vendors and only
 *      one of them can be named in a toolchain block.
 *
 *   3. THE GATE. emit-observation refuses a clean verdict when something was not
 *      observed. A consumer that only ever succeeds has not tested that -- and
 *      one that only ever fails has not either, because an emitter that refused
 *      everything would look identical. So the gate is asked in BOTH directions
 *      over the same draft, with a run-level control cell as the only variable:
 *      with it, a record; without it, no record.
 *
 * All of this runs over the lane's own tracked rows, so a change to either side
 * of the mapping fails here rather than at the next lab run.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, relative, isAbsolute, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  loadSchema, validateDocument,
} from '../../../schema/validate-observation.mjs';
import {
  emitObservation, findMachinePaths, CHECKPOINTS, STAGES,
} from '../../../schema/emit-observation.mjs';
import {
  draftForCell, emitForRows, gateSelfCheck, pointsFor, propertyStateFor, findControlRow,
  controlLevelFor, unobservedFor, wouldWriteInsideRepo, recordSlug, observationOutcome,
  isExpectedRefusal, EXPECTED_REFUSAL_CODES, PROPERTY_ID, PROPERTY_KIND, POINT_IDS,
  STRINGS_HALF_UNOBSERVED,
} from '../lib/observation.mjs';
import { DIGEST_SOURCE, DIGEST_DERIVATION } from '../lib/toolchain-digest.mjs';
import { CONTROLS } from '../lib/grade.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROWS = JSON.parse(readFileSync(join(HERE, '..', 'data', 'residue-rows-clang-18-gcc-13.json'), 'utf8'));
const SCHEMA = loadSchema();

/**
 * Frozen and clock-free, for the same reason emit-observation's own
 * SELF_CHECK_DRAFT is: a test that reads a clock fails on a different day for a
 * reason that is not a finding.
 */
const RUN = Object.freeze({
  generatedAt: '1970-01-01T00:00:00Z',
  timeSource: 'SOURCE_DATE_EPOCH',
  sourceDateEpoch: 0,
  toolchainDigest: 'a'.repeat(64),
  // Where that digest came from. A record may carry only the digest this tree
  // already computes for a toolchain; see lib/toolchain-digest.mjs and the
  // refusal test below. The 64 a's stand in for a real pinned set the way the
  // frozen timestamp stands in for a clock.
  toolchainDigestSource: DIGEST_SOURCE,
  ccVersion: 'Ubuntu clang version 18.1.3 (1ubuntu1)',
  observerSha256: 'b'.repeat(64),
});

const clangRows = ROWS.filter((r) => r.cc === 'clang-18');
const gccRows = ROWS.filter((r) => r.cc === 'gcc-13');

// ── 1. a record exists, it validates, and it says `process` ──────────────────

test('the lane emits records through emit-observation.mjs and the validator accepts every one', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  assert.ok(records.length > 0, 'no record was produced at all; the consumer consumed nothing');
  for (const { cell, record, text } of records) {
    const v = validateDocument(SCHEMA, JSON.parse(text), text);
    assert.equal(v.ok, true, `${cell} does not validate: ${(v.errors || []).join(' | ')}`);
    assert.equal(record.observationVersion, 'observation-v0');
  }
});

test('every emitted record carries checkpoint `process` at stage `run` -- the thing nothing here had emitted', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  assert.ok(CHECKPOINTS.includes('process'), 'the checkpoint word is gone from the emitter');
  assert.ok(STAGES.includes('run'), 'the stage word is gone from the emitter');
  for (const { cell, record } of records) {
    assert.ok(record.observationPoints.length > 0, `${cell} declares no observation point`);
    for (const p of record.observationPoints) {
      assert.equal(p.checkpoint, 'process', `${cell} point ${p.id} is at ${p.checkpoint}`);
      assert.equal(p.stage, 'run', `${cell} point ${p.id} is at stage ${p.stage}`);
    }
  }
});

test('a record names the catalogue property and one point per run-level control', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  const ids = new Set(Object.values(POINT_IDS));
  for (const { cell, record } of records) {
    assert.equal(record.properties.length, 1, `${cell} carries ${record.properties.length} properties`);
    assert.equal(record.properties[0].id, PROPERTY_ID);
    assert.equal(record.properties[0].kind, PROPERTY_KIND);
    assert.deepEqual(new Set(record.observationPoints.map((p) => p.id)), ids, `${cell} point ids`);
    assert.equal(record.observationPoints.length, 1 + Object.keys(CONTROLS).length);
  }
});

test('the RECORD verdict is never VERIFIED_CLEAN; the PROPERTY verdict always is, and both are asserted here', () => {
  // WHICH OF THE TWO IS WRONG. The test above this one used to be named "no
  // record from this lane is VERIFIED_CLEAN" and checked only `record.verdict`,
  // while every record it produced carried `properties[0].verdict:
  // VERIFIED_CLEAN`. One of the two had to change, and the schema says which.
  //
  // `verdict.unobserved` -- "a non-empty list here forbids VERIFIED_CLEAN" --
  // exists at the RECORD level and nowhere else: `propertyObservation` has no
  // such field, and emit-observation derives the property verdict from the
  // property's own evidence (its history, its control, findings naming it) and
  // never from the supplied list. A property verdict is not this lane's claim to
  // make at all: `q.verdict = verdict` overwrites anything a draft puts there,
  // so the only way for this lane to move it would be to misstate its history.
  // The schema then gates the record verdict ON the property verdicts -- a
  // property that is not clean is itself a cleanBlocker -- which makes
  // property-clean a NECESSARY-AND-NOT-SUFFICIENT condition for record-clean.
  // Clean property under an incomplete record is that design, not a leak.
  //
  // So the test's name changes, not the emitted verdict, and the gap is pinned
  // in BOTH directions here: if the emitter ever starts deriving something else
  // at the property level, this goes red rather than quietly agreeing.
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  assert.ok(records.length > 0);
  for (const { cell, record } of records) {
    assert.equal(record.verdict.state, 'VERIFICATION_INCOMPLETE',
      `${cell} record verdict is ${record.verdict.state}; verdict.unobserved should have forbidden anything cleaner`);
    assert.equal(record.properties[0].verdict, 'VERIFIED_CLEAN',
      `${cell} property verdict is ${record.properties[0].verdict}; the emitter derives it from the property's own `
      + 'evidence, and a change here means that derivation moved');
    // The disclosure a reader of properties[0] alone gets, in the property
    // itself rather than in the lane's prose.
    assert.match(record.properties[0].note,
      /answers the residency half of the catalogue oracle "strings, then residency" and no part of the strings half/,
      `${cell} property note does not say which half of the oracle was answered`);
    assert.ok(record.verdict.unobserved.includes(STRINGS_HALF_UNOBSERVED),
      `${cell} does not name the half of the oracle this lane never measures`);
    for (const w of ['heap', 'other-threads', 'ymm-upper']) {
      assert.ok(record.verdict.unobserved.includes(w), `${cell} does not name \`${w}\` as unobserved`);
    }
  }
});

test('the verdict reason states facts rather than reporting a checkpoint failure that did not happen', () => {
  // emit-observation's defaultReason builds the VERIFICATION_INCOMPLETE
  // sentence from unobservedBlockers alone and never reads a SUPPLIED
  // verdict.unobserved, so a record of this lane's normal shape -- every point
  // reached -- used to read "the run did not finish looking: a checkpoint was
  // not reached". The consumer supplies its own reason for that reason.
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  const full = records.find(({ record }) => record.counts.pointCoverage.num === record.counts.pointCoverage.den);
  assert.ok(full, 'no record had every point reached');
  assert.ok(!/a checkpoint was not reached/.test(full.record.verdict.reason), full.record.verdict.reason);
  assert.match(full.record.verdict.reason, /observation points were reached/);
});

test('no record names one machine', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  for (const { cell, record } of records) {
    assert.deepEqual(findMachinePaths(record), [], `${cell} carries a machine path`);
  }
});

// ── 2. the refusals, each one a hole rather than a convenience ───────────────

test('MEASURED: emit-observation can name only one vendor, so every gcc cell is refused', () => {
  // The measurement this refusal rests on, re-run here rather than quoted.
  const base = {
    context: { generatedAt: '1970-01-01T00:00:00Z', timeSource: 'SOURCE_DATE_EPOCH' },
    toolchain: { digest: '0'.repeat(64), clang: '18.1.3', packages: [] },
    counts: { inputs: 0, checked: 0, skipped: 0 },
    observationPoints: [],
    properties: [],
    layers: {
      compile: { observed: true },
      link: { observed: true, ltoMode: 'none', backendObserved: false },
      artifact: { observed: true },
    },
    findings: [],
  };

  // (a) naming gcc honestly is refused outright.
  const named = structuredClone(base);
  delete named.toolchain.clang;
  named.toolchain.gcc = '13.3.0';
  const a = emitObservation(SCHEMA, named);
  assert.equal(a.ok, false, 'toolchain.gcc was accepted; this test is stale and the refusal can be lifted');
  assert.ok(a.errors.some((e) => /toolchain\.clang must be a string/.test(e)), a.errors.join(' | '));

  // (b) naming it BESIDE clang is worse: accepted, and the vendor is dropped
  //     without a word. buildToolchainBlock returns a three-key literal.
  const beside = structuredClone(base);
  beside.toolchain.vendor = 'gcc';
  beside.toolchain.cc = 'gcc-13';
  const b = emitObservation(SCHEMA, beside);
  assert.equal(b.ok, true);
  assert.deepEqual(Object.keys(b.record.toolchain).sort(), ['clang', 'digest', 'packages']);
  assert.equal(b.record.toolchain.vendor, undefined, 'the vendor key survived; the drop is no longer silent');

  // (c) therefore: no gcc cell becomes a record here.
  const { records, refusals } = emitForRows(SCHEMA, gccRows, RUN);
  assert.equal(records.length, 0, 'a gcc cell was emitted; the version string went into a field named clang');
  const subjects = gccRows.filter((r) => r.kind === 'subject');
  assert.ok(subjects.length > 0, 'the tracked rows carry no gcc subject cell');
  assert.equal(refusals.length, subjects.length);
  for (const r of refusals) assert.equal(r.code, 'toolchain-vendor-not-expressible', `${r.cell}: ${r.code}`);
});

test('a cell whose secret was still readable is refused, because a finding has nowhere to say where', () => {
  const readable = clangRows.filter((r) => r.kind === 'subject' && r.measurement === 'OK'
    && ['FULL', 'PARTIAL'].includes(r.residue.stack));
  assert.ok(readable.length > 0, 'the tracked rows carry no cell where the secret survived; this test measures nothing');
  for (const row of readable) {
    assert.equal(propertyStateFor(row), 'PRESENT');
    const d = draftForCell(row, clangRows, RUN);
    assert.equal(d.ok, false, `${row.cell} was emitted with a measured failure and no finding`);
    assert.equal(d.refusal.code, 'residue-present-has-no-finding-location');
    assert.match(d.refusal.message, /where\.kind/);
  }
});

test('a control that survived as an inline zero store has no call-site count, and is refused', () => {
  // Every rep-stos-fallback row in the tracked set is a gcc row, where the
  // vendor refusal fires first, so the case is constructed from a clang row
  // rather than left unexercised. It is a real shape: CONTROL_EFFECT in
  // ai-generated/lib/ablation-cell.mjs sets allowInlineZeroStore.
  const base = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  assert.ok(base, 'no clean clang subject row to build the case from');
  const row = { ...base, confirmControlVia: 'rep-stos-fallback' };
  const d = draftForCell(row, clangRows, RUN);
  assert.equal(d.ok, false);
  assert.equal(d.refusal.code, 'control-effect-not-a-call-site');
});

test('a control cell is not a record of its own', () => {
  const c = clangRows.find((r) => r.kind === 'control');
  const d = draftForCell(c, clangRows, RUN);
  assert.equal(d.ok, false);
  assert.equal(d.refusal.code, 'cell-not-a-subject');
});

test('run facts that cannot identify the toolchain are refused before a record exists', () => {
  const row = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  for (const bad of [
    { ...RUN, toolchainDigest: 'not-a-digest' },
    { ...RUN, ccVersion: '' },
    { ...RUN, timeSource: 'whenever' },
    { ...RUN, generatedAt: '' },
    { ...RUN, observerSha256: 'zz' },
  ]) {
    const d = draftForCell(row, clangRows, bad);
    assert.equal(d.ok, false, `accepted run facts ${JSON.stringify(bad).slice(0, 90)}`);
    assert.equal(d.refusal.code, 'run-facts-missing');
  }
});

// ── 3. the gate, in both directions ─────────────────────────────────────────

test('THE GATE: with every run-level control present a clean claim is accepted', () => {
  const g = gateSelfCheck(SCHEMA, clangRows, RUN);
  assert.equal(g.positive.emitted, true,
    `the gate refused even with every control present, so the negative case proves nothing: ${(g.positive.errors || []).join(' | ')}`);
  assert.equal(g.positive.record.verdict.state, 'VERIFIED_CLEAN');
});

test('THE GATE: delete one run-level control cell and NO record is produced', () => {
  for (const name of Object.keys(CONTROLS)) {
    const g = gateSelfCheck(SCHEMA, clangRows, RUN, name);
    assert.equal(g.ok, true, `${name}: ${g.why}`);
    assert.equal(g.negative.emitted, false, `${name}: a record was produced with the control cell missing`);
    assert.equal(g.negative.record, undefined);
    assert.ok(g.negative.errors.some((e) => /clean-over-unobserved/.test(e) && new RegExp(POINT_IDS[name].replace('.', '\\.')).test(e)),
      `${name}: the refusal does not name the missing control: ${g.negative.errors.join(' | ')}`);
  }
});

test('THE GATE: a control that RAN but read the wrong thing is also not reached', () => {
  // Not the same failure as an absent cell, and it must not be reported as one:
  // control-nosecret reading the tracer means the observer is finding its own
  // needle, and every FULL elsewhere in the run is that.
  const subject = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  const broken = clangRows.map((r) => (r.kind === 'control' && r.control === 'control-nosecret'
    ? { ...r, residue: { ...r.residue, stack: 'FULL' }, longestRunBytes: r.needleLen }
    : r));
  const p = pointsFor(subject, broken).find((x) => x.id === POINT_IDS['control-nosecret']);
  assert.equal(p.reached, false);
  assert.match(p.unreachedReason, /did not hold/);
  assert.ok(unobservedFor(subject, pointsFor(subject, broken)).some((u) => u.includes(POINT_IDS['control-nosecret'])),
    'the unreached control did not reach verdict.unobserved');
});

test('a control taken at ANOTHER optimisation level does not qualify this cell', () => {
  // The silent pass this wave removed. findControlRow used to end
  //     return list.find((r) => r.opt === wanted) ?? list[0] ?? null;
  // and the `?? list[0]` handed back whatever control of that name had been run
  // on this vendor, at any level. A -O2 cell was then qualified by a -O0
  // instrument check and pointsFor reported `reached: true` -- the run-level
  // control that is supposed to establish that the window and the reader work on
  // THIS layout established it for a different one.
  const subject = clangRows.find((r) => r.kind === 'subject' && r.opt === '-O2' && r.measurement === 'OK');
  assert.ok(subject, 'the tracked rows carry no -O2 clang subject cell');
  assert.equal(controlLevelFor('control-retain', '-O2'), '-O2', 'control-retain is not pinned, so it follows the cell');
  assert.equal(controlLevelFor('control-o0-wiped', '-O2'), '-O0', 'control-o0-wiped is the -O0 control at every level');

  // Every control-retain row except the -O0 one removed: the name is still in
  // the run, at the wrong level.
  const wrongLevel = clangRows.filter(
    (r) => !(r.kind === 'control' && r.control === 'control-retain') || r.opt === '-O0',
  );
  assert.ok(wrongLevel.some((r) => r.kind === 'control' && r.control === 'control-retain' && r.opt === '-O0'),
    'the -O0 control-retain row is gone too, so this measures nothing');
  assert.equal(findControlRow(wrongLevel, 'control-retain', subject.cc, '-O2'), null,
    'a control-retain measured at -O0 was returned for a -O2 cell');

  const p = pointsFor(subject, wrongLevel).find((x) => x.id === POINT_IDS['control-retain']);
  assert.equal(p.reached, false, 'a -O2 cell was qualified by a control taken at -O0');
  assert.match(p.unreachedReason, /was not run on clang-18 at -O2, only at -O0/);
  assert.match(p.unreachedReason, /does not qualify the instrument for this cell/);
  assert.equal(p.optLevel, '-O2', 'the point names the level it wanted, not the level it found');

  // and the unqualified point reaches the record, rather than being absorbed.
  assert.ok(unobservedFor(subject, pointsFor(subject, wrongLevel))
    .some((u) => u.includes(POINT_IDS['control-retain'])));

  // The positive half: with the -O2 control back, the same point is reached.
  const q = pointsFor(subject, clangRows).find((x) => x.id === POINT_IDS['control-retain']);
  assert.equal(q.reached, true, `${subject.cell}: ${q.unreachedReason}`);
});

test('an absent control cell says so in words that are not the same as "it read the wrong thing"', () => {
  const subject = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK');
  const without = clangRows.filter((r) => !(r.kind === 'control' && r.control === 'control-retain'));
  assert.equal(findControlRow(without, 'control-retain', subject.cc, subject.opt), null);
  const p = pointsFor(subject, without).find((x) => x.id === POINT_IDS['control-retain']);
  assert.equal(p.reached, false);
  assert.match(p.unreachedReason, /was not run on/);
});

// ── where records may go ────────────────────────────────────────────────────

test('a record directory inside the repository is refused', () => {
  const api = { relative, isAbsolute, sep };
  const repo = join(HERE, '..', '..', '..', '..');
  assert.equal(wouldWriteInsideRepo(join(repo, 'compiler', 'eval', 'residue-tracer', 'observations'), repo, api), true);
  assert.equal(wouldWriteInsideRepo(repo, repo, api), true);
  assert.equal(wouldWriteInsideRepo(join(repo, '..', 'vg-lab', 'residue-tracer', 'observations'), repo, api), false);
});

test('a record file name carries the cell it is about and no separator', () => {
  assert.equal(recordSlug('stock/clang-18/-O2/memset'), 'stock_clang_18_O2_memset');
  assert.ok(!recordSlug('stock/clang-18/-O2/memset').includes('/'));
});

// -- 4. the digest, the buckets and the layers -------------------------------
//
// Three silent passes that a test named after the thing it was supposed to
// catch would not have caught: a digest nobody else computes, an apparatus
// failure filed as a deliberate refusal, and three layers claimed observed
// whatever the cell did.

test('a digest this lane invented is refused; only the one the tree already computes may be written', () => {
  // The lane used to compute sha256(JSON.stringify({cc, version, observer}))
  // and put it in toolchain.digest. It is well formed, it is stable, and it is
  // a digest of nothing: no other value in this tree equals it for the same
  // toolchain, and a reader holding the compiler cannot recompute it. The file
  // this lane feeds refuses to invent one in its own driver adapter --
  // "this adapter will not invent a digest for it" -- so the provenance of the
  // number is now a run fact, and a record is refused without it.
  const row = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  for (const bad of [
    { ...RUN, toolchainDigestSource: undefined },
    { ...RUN, toolchainDigestSource: null },
    { ...RUN, toolchainDigestSource: 'sha256-of-cc-version-and-observer' },
    { ...RUN, toolchainDigestSource: 'pinned-set' },
  ]) {
    const d = draftForCell(row, clangRows, bad);
    assert.equal(d.ok, false, `accepted a digest whose source is ${JSON.stringify(bad.toolchainDigestSource ?? null)}`);
    assert.equal(d.refusal.code, 'toolchain-digest-not-derivable');
    assert.match(d.refusal.message, /evidenceDigest\(pinnedSet/);
  }
  // and it is not the same failure as missing run facts, so it does not hide in
  // that bucket either.
  assert.notEqual('toolchain-digest-not-derivable', 'run-facts-missing');
  assert.equal(draftForCell(row, clangRows, { ...RUN, ccVersion: '' }).refusal.code, 'run-facts-missing');
});

test('every record says where its toolchain digest came from', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  assert.ok(records.length > 0);
  for (const { cell, record } of records) {
    assert.ok(record.properties[0].note.includes(DIGEST_DERIVATION),
      `${cell} does not say in the record itself what toolchain.digest is a digest of`);
    assert.match(record.toolchain.digest, /^[0-9a-f]{64}$/);
  }
});

test('an emitter failure is not a refusal: different bucket, different exit', () => {
  // A refusal is one of three named holes in the schema's vocabulary, decided
  // before the run. Anything else that stops a cell becoming a record is the
  // apparatus not working, and until this wave both went into `refusals` and
  // the runner exited 0 as long as one cell emitted -- so an emitter that
  // rejected fifty-nine of sixty drafts printed a tidy count and passed.
  //
  // The failure is constructed by making the emitter's own validator reject
  // every record: a schema with one more required key at the root. Nothing
  // about the drafts changes.
  const broken = structuredClone(SCHEMA);
  broken.required = [...broken.required, 'aKeyNoRecordHas'];

  const good = emitForRows(SCHEMA, clangRows, RUN);
  assert.equal(good.failures.length, 0, `the production path failed on a cell: ${JSON.stringify(good.failures[0])}`);
  assert.ok(good.records.length > 0);

  const bad = emitForRows(broken, clangRows, RUN);
  assert.equal(bad.records.length, 0, 'a record validated against a schema that requires a key no record has');
  assert.ok(bad.failures.length > 0, 'the emitter rejected every draft and nothing was filed as a failure');
  for (const f of bad.failures) {
    assert.match(f.code, /^emitter-/, `${f.cell} was filed as ${f.code}`);
    assert.equal(isExpectedRefusal(f.code), false);
  }
  // The deliberate refusals are still exactly the deliberate refusals: the
  // vocabulary holes do not become failures, and the failures do not become
  // refusals.
  for (const r of bad.refusals) {
    assert.ok(EXPECTED_REFUSAL_CODES.includes(r.code), `${r.cell} was filed as a refusal with code ${r.code}`);
  }
  assert.equal(bad.refusals.length, good.refusals.length,
    'the count of deliberately refused cells moved when the emitter broke');
});

test('a cell that never compiled is a failure too: there is no reading to express', () => {
  // nSpans is null exactly when the find step never judged the cell -- it did
  // not compile, or the repair plugin was absent -- so there is no call-site
  // count for the history entry. That is the apparatus not having produced a
  // measurement, not the schema lacking a word, and a run carrying one is
  // already a partial matrix that --write-data refuses. It exits 5 rather than
  // printing a refusal count and passing.
  const base = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK');
  const row = { ...base, cell: 'wipepin/clang-18/-O2/constructed-plugin-absent', nSpans: null,
    measurement: 'BROKEN_MEASUREMENT', reason: 'plugin-absent' };
  const d = draftForCell(row, clangRows, RUN);
  assert.equal(d.ok, false);
  assert.equal(d.refusal.code, 'no-span-count');
  assert.equal(isExpectedRefusal('no-span-count'), false,
    'a cell with no reading is being counted as one of the three schema holes');

  const { records, refusals, failures } = emitForRows(SCHEMA, [...clangRows, row], RUN);
  assert.ok(records.length > 0, 'the rest of the run still emitted');
  assert.equal(refusals.some((r) => r.code === 'no-span-count'), false);
  assert.equal(failures.filter((f) => f.code === 'no-span-count').length, 1);
  assert.equal(observationOutcome({ records, refusals, failures }).exitCode, 5);
});

test('the exit: a failure is 5 however many records were written, a refusal changes nothing', () => {
  const rec = [{ cell: 'stock/clang-18/-O0/memset' }];
  const vocab = [{ cell: 'stock/gcc-13/-O0/memset', code: 'toolchain-vendor-not-expressible' }];
  const fail = [{ cell: 'stock/clang-18/-O2/memset', code: 'emitter-validate' }];

  assert.deepEqual(observationOutcome({ records: rec, refusals: vocab, failures: [] }),
    { ok: true, exitCode: 0, why: null });

  const withFailure = observationOutcome({ records: rec, refusals: vocab, failures: fail });
  assert.equal(withFailure.ok, false);
  assert.equal(withFailure.exitCode, 5, 'a cell the apparatus failed on was absorbed because another cell emitted');
  assert.match(withFailure.why, /could not be expressed at all/);

  // the older rule, kept: emitting nothing at all is still exit 5.
  const nothing = observationOutcome({ records: [], refusals: vocab, failures: [] });
  assert.equal(nothing.exitCode, 5);
  assert.match(nothing.why, /has not consumed anything/);

  // and the three vocabulary holes on their own never change the exit.
  for (const code of EXPECTED_REFUSAL_CODES) {
    assert.equal(isExpectedRefusal(code), true);
    assert.equal(observationOutcome({ records: rec, refusals: [{ cell: 'x', code }], failures: [] }).exitCode, 0);
  }
  assert.equal(isExpectedRefusal('emitter-draft'), false);
  assert.equal(isExpectedRefusal('run-facts-missing'), false);
});

// ── the layers, which used to be three unconditional `true`s ─────────────────

/** A subject row that stopped before it compiled. Every digest it never took is null. */
function compileFailedRow(base) {
  return {
    ...base,
    cell: 'stock/clang-18/-O2/constructed-compile-failed',
    measurement: 'BROKEN_MEASUREMENT',
    reason: 'compile-failed',
    controlHeld: null,
    residue: { stack: 'NOT_OBSERVED', gpr: 'NOT_OBSERVED', xmm: 'NOT_OBSERVED' },
    longestRunBytes: null,
    controlRunBytes: null,
    scanAgrees: null,
    stop: { expectedRip: null, rip: null, matched: null, expectedRsp: null, rsp: null, rspMatched: null },
    window: { lo: null, hi: null, bytesRead: null, belowReached: null, sha256: null },
    frame: { parsed: null, subjectBytes: null, form: null, requiredBelow: null, why: null },
    textRestoredMatchesFile: null,
    exe: { sha256Before: null, sha256After: null, unmodified: null },
    asmSha256: null,
    objSha256: null,
  };
}

test('a cell that never compiled does not claim three observed layers', () => {
  // The tracked matrix is 82/82 measurement OK, so no tracked row can exercise
  // this and layersFor returned `observed: true` three times for anything it
  // was handed -- including a cell whose compile failed, whose binary never
  // existed and whose artefact was never read. The schema's own words:
  // "a layer that was never looked at must not read as a layer that was clean".
  const base = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  const row = compileFailedRow(base);
  assert.equal(propertyStateFor(row), 'NOT_OBSERVED');

  const d = draftForCell(row, clangRows, RUN);
  assert.equal(d.ok, true, d.ok ? '' : `${d.refusal.code}: ${d.refusal.message}`);
  const e = emitObservation(SCHEMA, d.draft);
  assert.equal(e.ok, true, (e.errors || []).join(' | '));
  const v = validateDocument(SCHEMA, JSON.parse(e.text), e.text);
  assert.equal(v.ok, true, (v.errors || []).join(' | '));

  const L = e.record.layers;
  assert.equal(L.compile.observed, false, 'a cell with no assembly digest claimed its compile was observed');
  assert.match(L.compile.unobservedReason, /no assembly or object digest/);
  assert.match(L.compile.unobservedReason, /compile-failed/);
  assert.equal(L.link.observed, false, 'a cell that was never linked claimed its link was observed');
  assert.match(L.link.unobservedReason, /no linked executable digest/);
  assert.equal(L.artifact.observed, false, 'a cell whose binary never existed claimed its artefact was observed');
  assert.match(L.artifact.unobservedReason, /frame\.parsed is null/);

  // and the record still says the property was not observed rather than absent.
  assert.equal(e.record.properties[0].finalState, 'NOT_OBSERVED');
  assert.notEqual(e.record.properties[0].verdict, 'VERIFIED_CLEAN');
});

test('the layers follow the digests, not the measurement: a built cell whose observer failed observed all three', () => {
  // The other side of the same conditional. This cell compiled, linked and was
  // disassembled -- three layers really were observed -- and then the ptrace
  // stop did not happen. Reporting the layers as unobserved here would be the
  // opposite lie, so the test holds both directions.
  const base = clangRows.find((r) => r.kind === 'subject' && r.measurement === 'OK' && r.residue.stack === 'NONE');
  const row = {
    ...base,
    cell: 'stock/clang-18/-O2/constructed-observer-failed',
    measurement: 'BROKEN_MEASUREMENT',
    reason: 'observer-did-not-stop',
    residue: { stack: 'NOT_OBSERVED', gpr: 'NOT_OBSERVED', xmm: 'NOT_OBSERVED' },
  };
  const d = draftForCell(row, clangRows, RUN);
  assert.equal(d.ok, true);
  const e = emitObservation(SCHEMA, d.draft);
  assert.equal(e.ok, true, (e.errors || []).join(' | '));
  assert.equal(e.record.layers.compile.observed, true);
  assert.equal(e.record.layers.link.observed, true);
  assert.equal(e.record.layers.artifact.observed, true);
  // The reading is what is missing, and it is missing at the point, not the layer.
  const subject = e.record.observationPoints.find((x) => x.id === POINT_IDS.subject);
  assert.equal(subject.reached, false);
  assert.match(subject.unreachedReason, /observer-did-not-stop/);
});

test('every tracked row still observes all three layers, which is why this needed constructing', () => {
  const { records } = emitForRows(SCHEMA, clangRows, RUN);
  for (const { cell, record } of records) {
    for (const name of ['compile', 'link', 'artifact']) {
      assert.equal(record.layers[name].observed, true, `${cell} layers.${name} is not observed`);
    }
  }
  assert.equal(clangRows.filter((r) => r.measurement !== 'OK').length, 0,
    'a tracked row now carries a failed measurement; the constructed cases above may be replaceable by it');
});
