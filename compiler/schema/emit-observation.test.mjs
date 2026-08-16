// Tests for compiler/schema/emit-observation.mjs — the reference writer for
// observation.schema.json.
//
//   node --test "compiler/schema/*.test.mjs"
//
// Passing the DIRECTORY to `node --test` throws MODULE_NOT_FOUND on this
// runtime. Always glob. (Same note as observation-schema.test.mjs.)
//
// WHAT THIS SUITE IS FOR
//
// observation-schema.test.mjs checks the FORM and its validator. Until this
// file existed, `validate-observation.mjs` had exactly one caller — that test —
// so the honest description of the deliverable was "a form, a validator, and no
// implementation that can write it". Four things are checked here, and the
// third and fourth are the ones that would catch a validator that is not really
// checking anything:
//
//   1. POSITIVE CONTROL. The emitter produces records, and the validator
//      accepts them. `--self-check` is that control as a runnable command.
//   2. AGREEMENT WITH SIX RECORDS NOBODY GENERATED. Every valid sample in the
//      corpus was written by hand before this emitter existed. Strip the fields
//      the emitter is supposed to derive, hand the rest back, and the emitter
//      has to reproduce each record byte-identically. Six independent targets
//      is a much harder test than "the writer agrees with itself".
//   3. NEGATIVE CONTROL, BY REASON. Breaking one field of an emitted record
//      must make the validator fail FOR THAT REASON — the rule id or the
//      pointer is asserted, not merely `ok === false`. A suite that only checks
//      "it was rejected" passes just as happily when one bug rejects
//      everything.
//   4. THE MUTATION BATTERY. Every required field of every valid sample, at
//      every depth, is deleted and then type-violated, and each of those
//      mutations must be rejected at the exact pointer. This is the test for a
//      tautological validator: if `validate` returned `[]` for everything, all
//      of the several hundred cases below would fail at once.
//
// PROVENANCE OF emitter-inputs/driver-record-compile-only.json
//
// It is not hand-written. It is a `compiler-evidence-v0` record the driver
// itself wrote, captured by running compiler/driver/cli/vgcc.mjs over the
// `hello.c` fixture in compiler/driver/test/helpers.mjs with clang-18 on
// linux, with a policy declaring `survive.secure-wipe` at `pre-opt-ir` and
// `after-pass`. It is checked here for machine paths on every run, because a
// captured record is exactly the kind of file a machine path arrives in.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validate as validateSchema } from '../driver/lib/jsonschema.mjs';
import { loadSchema, validateDocument, semanticErrors } from './validate-observation.mjs';
import {
  buildObservation,
  emitObservation,
  sealObservation,
  draftFromDriverRecord,
  findMachinePaths,
  findNonIntegers,
  run,
  SELF_CHECK_DRAFT,
  OBSERVATION_VERSION,
  DRIVER_RECORD_VERSION,
  PROPERTY_STATES,
  VERDICT_STATES,
  VERDICT_EXIT,
  STAGES,
  CHECKPOINTS,
  PROPERTY_KINDS,
  EXIT_OK,
  EXIT_INCOMPLETE,
  EXIT_INTEGRITY,
} from './emit-observation.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const VALID_DIR = join(HERE, 'observation-samples', 'valid');
const DRIVER_RECORD = join(HERE, 'emitter-inputs', 'driver-record-compile-only.json');

const schema = loadSchema();
const readDoc = (path) => JSON.parse(readFileSync(path, 'utf8'));
const validNames = () => readdirSync(VALID_DIR).filter((n) => n.endsWith('.json')).sort();

/** Collects stdout/stderr from `run` so the exit code AND the output can be asserted. */
async function capture(argv) {
  const out = [];
  const err = [];
  const code = await run(argv, (m) => out.push(String(m)), (m) => err.push(String(m)));
  return { code, out: out.join('\n'), err: err.join('\n') };
}

const reasonsOf = (built) => (built.ok ? [] : built.errors.map((e) => e.reason));
const messagesOf = (built) => (built.ok ? '' : built.errors.map((e) => `${e.reason}: ${e.message}`).join('\n'));

// ── 0. the vocabularies do not drift from the schema ────────────────────────
//
// The emitter carries its own copies so that it does not have to read the
// schema to be a pure function. A copy that drifts is a copy that quietly stops
// applying, so each one is asserted against the schema rather than against a
// comment.

test('the emitter and the schema use one vocabulary', () => {
  assert.deepStrictEqual([...PROPERTY_STATES], schema.definitions.propertyState.enum);
  assert.deepStrictEqual([...VERDICT_STATES], schema.definitions.verdictState.enum);
  assert.deepStrictEqual([...CHECKPOINTS], schema.definitions.checkpoint.enum);
  assert.deepStrictEqual([...STAGES], schema.definitions.stage.enum);
  assert.deepStrictEqual([...PROPERTY_KINDS], schema.definitions.propertyObservation.properties.kind.enum);
  assert.deepStrictEqual(Object.keys(VERDICT_EXIT).sort(), [...schema.definitions.verdictState.enum].sort());
  const allowedExits = schema.definitions.verdict.properties.exitCode.enum;
  for (const [state, code] of Object.entries(VERDICT_EXIT)) {
    assert.ok(allowedExits.includes(code), `${state} maps to exit ${code}, which the schema does not allow`);
  }
  assert.equal(OBSERVATION_VERSION, schema.properties.observationVersion.const);
});

// ── 1. the positive control ─────────────────────────────────────────────────

test('the emitter writes a record and the validator accepts it', () => {
  const emitted = emitObservation(schema, structuredClone(SELF_CHECK_DRAFT));
  assert.equal(emitted.ok, true, `the emitter refused its own self-check draft:\n${(emitted.errors ?? []).join('\n')}`);

  // Re-checked here rather than trusting emitObservation's own gate.
  const again = validateDocument(schema, JSON.parse(emitted.text), emitted.text);
  assert.equal(again.ok, true, `the emitted record does not validate:\n${again.errors.join('\n')}`);

  assert.equal(emitted.record.observationVersion, 'observation-v0');
  assert.equal(emitted.record.verdict.state, 'VERIFIED_CLEAN');
  assert.equal(emitted.record.verdict.exitCode, 0);
  assert.deepStrictEqual(emitted.record.verdict.unobserved, []);
  assert.deepStrictEqual(emitted.record.counts.pointCoverage, { num: 2, den: 2 });
  assert.deepStrictEqual(emitted.record.properties.map((p) => p.verdict), ['VERIFIED_CLEAN']);
  assert.deepStrictEqual(emitted.record.properties[0].history.map((h) => h.index), [0, 1]);
  assert.equal(emitted.record.properties[0].finalState, 'PRESENT');
  assert.equal(emitted.record.properties[0].firstLoss, null);
  assert.equal(emitted.record.properties[0].lossEpisodes, 0);
});

test('--self-check is the positive control as one command', async () => {
  const { code, out } = await capture(['--self-check']);
  assert.equal(code, EXIT_OK);
  assert.match(out, /^inputs=1 checked=1 skipped=0$/m);
  assert.match(out, /record verdict=VERIFIED_CLEAN recordExitCode=0; emission ok/);
});

// ── 2. six records this emitter did not write, reproduced exactly ───────────

/**
 * Remove exactly the fields the emitter is specified to derive. Everything
 * else — what was observed, where, by which pass — is an observation and is
 * handed back untouched.
 */
function draftFromRecord(rec) {
  const d = structuredClone(rec);
  delete d.observationVersion;
  delete d.counts.pointCoverage;
  delete d.verdict.exitCode;
  for (const p of d.properties) {
    delete p.finalState;
    delete p.firstLoss;
    delete p.lossEpisodes;
    delete p.verdict;
    for (const h of p.history) delete h.index;
  }
  // Which part of the configuration is outside the measured envelope is not in
  // the record as a field, so an UNSUPPORTED claim has to carry it separately.
  if (rec.verdict.state === 'UNSUPPORTED') d.unsupportedReason = rec.verdict.reason;
  return d;
}

test('the six valid samples are exactly these six, and each still validates', () => {
  assert.deepStrictEqual(validNames(), [
    'valid-clean.json',
    'valid-evidence-mismatch.json',
    'valid-findings.json',
    'valid-incomplete.json',
    'valid-state-vocabulary.json',
    'valid-unsupported.json',
  ]);
  for (const name of validNames()) {
    const raw = readFileSync(join(VALID_DIR, name), 'utf8');
    const result = validateDocument(schema, JSON.parse(raw), raw);
    assert.equal(result.ok, true, `${name} no longer validates:\n${result.errors.join('\n')}`);
  }
});

test('the emitter reproduces every hand-written valid record, field for field', () => {
  const names = validNames();
  assert.equal(names.length, 6);
  for (const name of names) {
    const rec = readDoc(join(VALID_DIR, name));
    const draft = draftFromRecord(rec);

    // The stripping has to have removed something, or this test compares a
    // record with itself and proves nothing.
    assert.equal('pointCoverage' in draft.counts, false, `${name}: nothing was stripped`);
    assert.equal('exitCode' in draft.verdict, false, `${name}: nothing was stripped`);
    for (const p of draft.properties) {
      assert.equal('finalState' in p, false, `${name}: finalState was not stripped`);
      assert.equal('verdict' in p, false, `${name}: the property verdict was not stripped`);
      for (const h of p.history) assert.equal('index' in h, false, `${name}: a history index was not stripped`);
    }

    const built = buildObservation(draft);
    assert.equal(built.ok, true, `${name} was refused:\n${messagesOf(built)}`);
    assert.deepStrictEqual(built.record, rec, `${name} was not reproduced`);
  }
});

test('the derived numbers are the ones the corpus records, not zeroes', () => {
  // A spot check with the numbers written out, so that a derivation that
  // silently returned 0/null everywhere could not pass the deepStrictEqual
  // above by accident of both sides being empty.
  const findings = buildObservation(draftFromRecord(readDoc(join(VALID_DIR, 'valid-findings.json'))));
  assert.equal(findings.ok, true);
  assert.deepStrictEqual(findings.record.properties[0].firstLoss, {
    pass: 'DSEPass', unit: 'handle_request', seq: 200, historyIndex: 1,
  });
  assert.equal(findings.record.properties[0].lossEpisodes, 1);
  assert.equal(findings.record.properties[0].finalState, 'LOST');
  assert.equal(findings.record.verdict.exitCode, 2);

  const vocab = buildObservation(draftFromRecord(readDoc(join(VALID_DIR, 'valid-state-vocabulary.json'))));
  assert.equal(vocab.ok, true);
  assert.deepStrictEqual(vocab.record.properties[0].history.map((h) => h.index), [0, 1, 2, 3, 4]);
  assert.deepStrictEqual(vocab.record.counts.pointCoverage, { num: 4, den: 5 });
  assert.equal(vocab.record.properties[0].lossEpisodes, 1, 'LOST -> REINTRODUCED is one episode, not two');
});

// ── 3. the negative control: broken by hand, refused for the stated reason ───

test('one broken field in an emitted record fails the validator for that reason', () => {
  const emitted = emitObservation(schema, structuredClone(SELF_CHECK_DRAFT));
  assert.equal(emitted.ok, true);
  const good = emitted.record;

  /** @type {[string, (d: any) => void, 'schema'|'semantic', string][]} */
  const cases = [
    ['the exit code stops agreeing with the verdict',
      (d) => { d.verdict.exitCode = 1; }, 'semantic', 'OBS-S08'],
    ['finalState stops agreeing with the history',
      (d) => { d.properties[0].finalState = 'ABSENT'; }, 'semantic', 'OBS-S04'],
    ['a history index stops agreeing with array order',
      (d) => { d.properties[0].history[1].index = 0; }, 'semantic', 'OBS-S03'],
    ['a history entry names a point nobody declared',
      (d) => { d.properties[0].history[0].point = 'no-such-point'; }, 'semantic', 'OBS-S01'],
    ['two observation points carry one id',
      (d) => { d.observationPoints[1].id = 'pre-opt'; }, 'semantic', 'OBS-S02'],
    ['a point stops being reached while the record still claims clean',
      (d) => { d.observationPoints[1].reached = false; d.observationPoints[1].unreachedReason = 'the compiler crashed'; }, 'semantic', 'OBS-S07'],
    ['a control stops surviving',
      (d) => { d.properties[0].control.count.callSites = 0; }, 'semantic', 'OBS-S09'],
    ['a point that was not reached stops saying why',
      (d) => { d.observationPoints[1].reached = false; d.observationPoints[1].unreachedReason = null; }, 'semantic', 'OBS-S12'],
    ['an absolute path arrives in a string',
      (d) => { d.properties[0].note = 'measured in /opt/build/secret.c'; }, 'semantic', 'OBS-S11'],
    ['a count is taken by searching for a symbol name',
      (d) => { d.properties[0].history[0].count.oracle = 'symbol-name'; }, 'schema', 'must be "call-site"'],
    ['the verdict leaves the five states',
      (d) => { d.verdict.state = 'PROBABLY_FINE'; }, 'schema', '/verdict/state'],
    ['the artefact path names one machine',
      (d) => { d.layers.artifact.path = '/opt/build/app'; }, 'schema', '/layers/artifact/path'],
    ['a required field is dropped',
      (d) => { delete d.properties[0].control; }, 'schema', 'missing required property `control`'],
  ];

  for (const [why, mutate, kind, needle] of cases) {
    const broken = structuredClone(good);
    mutate(broken);
    const text = `${JSON.stringify(broken, null, 2)}\n`;
    const result = validateDocument(schema, JSON.parse(text), text);
    assert.equal(result.ok, false, `${why}: the record still validated`);
    assert.equal(result.kind, kind, `${why}: failed as ${result.kind}, expected ${kind}:\n${result.errors.join('\n')}`);
    const haystack = kind === 'semantic' ? (result.rules ?? []).join(' ') : result.errors.join('\n');
    assert.ok(haystack.includes(needle), `${why}: failed, but not on ${needle}:\n${result.errors.join('\n')}`);
  }

  // The counterweight. Without it the table above would also pass against a
  // validator that rejects every document it is shown.
  const untouched = `${JSON.stringify(good, null, 2)}\n`;
  assert.equal(validateDocument(schema, JSON.parse(untouched), untouched).ok, true);
  const harmless = structuredClone(good);
  harmless.properties[0].note = 'the same effect was counted again from the post-backend bitcode and agreed';
  const harmlessText = `${JSON.stringify(harmless, null, 2)}\n`;
  assert.equal(validateDocument(schema, JSON.parse(harmlessText), harmlessText).ok, true,
    'a harmless edit was rejected, so the rejections above are not about what they claim');
});

// ── 4. the mutation battery over the whole valid corpus ─────────────────────

function derefSchema(node, root, depth = 0) {
  if (depth > 16) throw new Error('$ref nesting too deep');
  if (!node || typeof node !== 'object' || typeof node.$ref !== 'string') return node;
  let cur = root;
  for (const seg of node.$ref.slice(2).split('/')) cur = cur?.[seg];
  if (cur === undefined) throw new Error(`unresolvable $ref ${node.$ref}`);
  return derefSchema(cur, root, depth + 1);
}

/**
 * Every (path, pointer) at which the schema says a key is required AND the
 * document actually carries it. Walking the document rather than the schema is
 * deliberate: a required key inside an array item is required once per item,
 * and mutating only the first would leave the deeper ones unmeasured.
 */
function requiredSites(sub, doc, root, pointer, path, out) {
  const s = derefSchema(sub, root);
  if (!s || typeof s !== 'object') return out;
  const isObj = doc !== null && typeof doc === 'object' && !Array.isArray(doc);
  if (isObj && Array.isArray(s.required)) {
    for (const key of s.required) {
      if (Object.prototype.hasOwnProperty.call(doc, key)) {
        out.push({
          parentPointer: pointer,
          pointer: `${pointer}/${key}`,
          key,
          path: [...path, key],
          sub: derefSchema(s.properties?.[key], root),
        });
      }
    }
  }
  if (isObj && s.properties) {
    for (const [k, child] of Object.entries(s.properties)) {
      if (Object.prototype.hasOwnProperty.call(doc, k)) {
        requiredSites(child, doc[k], root, `${pointer}/${k}`, [...path, k], out);
      }
    }
  }
  if (Array.isArray(doc) && s.items && !Array.isArray(s.items)) {
    doc.forEach((item, i) => requiredSites(s.items, item, root, `${pointer}/${i}`, [...path, i], out));
  }
  return out;
}

const atParent = (doc, path) => path.slice(0, -1).reduce((c, k) => c[k], doc);

/**
 * A value whose JSON type no branch of `sub` accepts. Chosen from the subschema
 * rather than fixed, because "wrong type" for `{type: ["integer","null"]}` and
 * for `{type: "boolean"}` are different values, and a single fixed mutant would
 * silently be a legal value at some of the several hundred sites below.
 */
function wrongValueFor(sub) {
  const allowed = new Set(Array.isArray(sub?.type) ? sub.type : (sub?.type ? [sub.type] : []));
  if (allowed.has('number')) allowed.add('integer');
  if (allowed.has('integer')) allowed.add('number');
  for (const [type, value] of [
    ['string', '__mutant__'],
    ['integer', 987654321],
    ['boolean', true],
    ['object', { mutant: true }],
    ['array', ['mutant']],
  ]) {
    if (!allowed.has(type)) return { type, value };
  }
  return null;
}

test('every required field of every valid sample, deleted, is refused at its own pointer', () => {
  let mutations = 0;
  for (const name of validNames()) {
    const doc = readDoc(join(VALID_DIR, name));
    const sites = requiredSites(schema, doc, schema, '', [], []);
    assert.ok(sites.length >= 20, `${name}: the walk found only ${sites.length} required fields`);
    for (const site of sites) {
      const broken = structuredClone(doc);
      delete atParent(broken, site.path)[site.key];
      const errors = validateSchema(schema, broken);
      assert.ok(
        errors.some((e) => e.pointer === site.parentPointer && e.message === `missing required property \`${site.key}\``),
        `${name}: dropping ${site.pointer} was not reported at ${site.parentPointer || '(root)'}; got ${JSON.stringify(errors.slice(0, 3))}`,
      );
      assert.equal(validateDocument(schema, broken).kind, 'schema', `${name}: dropping ${site.pointer} failed as something other than a shape error`);
      mutations += 1;
    }
  }
  assert.ok(mutations >= 200, `only ${mutations} deletions were tried; the walk is not reaching the corpus`);
});

test('every required field of every valid sample, type-violated, is refused at its own pointer', () => {
  let mutations = 0;
  for (const name of validNames()) {
    const doc = readDoc(join(VALID_DIR, name));
    for (const site of requiredSites(schema, doc, schema, '', [], [])) {
      const wrong = wrongValueFor(site.sub);
      assert.notEqual(wrong, null, `${name}: no wrong-typed value could be chosen for ${site.pointer}`);
      const broken = structuredClone(doc);
      atParent(broken, site.path)[site.key] = wrong.value;
      const errors = validateSchema(schema, broken);
      assert.ok(
        errors.some((e) => e.pointer === site.pointer),
        `${name}: putting a ${wrong.type} at ${site.pointer} raised nothing there; got ${JSON.stringify(errors.slice(0, 3))}`,
      );
      mutations += 1;
    }
  }
  assert.ok(mutations >= 200, `only ${mutations} type violations were tried`);
});

test('the battery is not rejecting everything: the unmutated corpus is accepted', () => {
  // The control for the two tests above. If `validate` had been broken into
  // always returning an error, every case above would still pass and only this
  // one would fail.
  for (const name of validNames()) {
    assert.deepStrictEqual(validateSchema(schema, readDoc(join(VALID_DIR, name))), [],
      `${name} is reported as malformed by the same validator the battery uses`);
  }
});

// ── 5. the emitter refuses rather than writing a claim it cannot support ────

function cleanDraft() {
  return structuredClone(SELF_CHECK_DRAFT);
}

test('a claim stronger than the evidence produces no record, and says which rule stopped it', () => {
  /** @type {[string, (d: any) => void, string][]} */
  const cases = [
    ['VERIFIED_CLEAN over a point that was not reached', (d) => {
      d.verdict = { state: 'VERIFIED_CLEAN' };
      d.observationPoints[1].reached = false;
      d.observationPoints[1].unreachedReason = 'the compiler crashed before the pass pipeline ended';
    }, 'clean-over-unobserved'],
    ['VERIFIED_CLEAN with a finding recorded', (d) => {
      d.verdict = { state: 'VERIFIED_CLEAN' };
      d.findings = [{
        id: 'VG-PROP-001', severity: 'high', title: 'A required zeroing effect did not survive',
        detail: 'the call site went to zero', where: { kind: 'ir', path: 'fixtures/secret.c', unit: 'wipe_kept', pass: 'DSEPass' },
        property: 'prop.erasure.stack-buffer', point: 'compile-end',
      }];
    }, 'clean-over-unobserved'],
    ['VERIFIED_CLEAN while a layer was never looked at', (d) => {
      d.verdict = { state: 'VERIFIED_CLEAN' };
      d.layers.link.observed = false;
      d.layers.link.unobservedReason = 'a compile-only invocation produces no link';
    }, 'clean-over-unobserved'],
    ['VERIFIED_CLEAN while an LTO backend ran unwatched', (d) => {
      d.verdict = { state: 'VERIFIED_CLEAN' };
      d.layers.link.ltoMode = 'thin';
      d.layers.link.backendObserved = false;
      d.layers.link.backendUnobservedReason = 'the plugin path did not resolve and the linker ignored the request';
    }, 'clean-over-unobserved'],
    ['a finding taken from a run whose control did not survive', (d) => {
      d.verdict = { state: 'FINDINGS_PRESENT' };
      d.properties[0].control.count.callSites = 0;
      d.findings = [{
        id: 'VG-PROP-001', severity: 'high', title: 'A required zeroing effect did not survive',
        detail: 'the call site went to zero', where: { kind: 'ir', path: 'fixtures/secret.c', unit: 'wipe_kept', pass: 'DSEPass' },
        property: 'prop.erasure.stack-buffer', point: 'compile-end',
      }];
    }, 'control-did-not-survive'],
    ['FINDINGS_PRESENT with nothing in findings', (d) => {
      d.verdict = { state: 'FINDINGS_PRESENT' };
    }, 'findings-present-without-findings'],
    ['UNSUPPORTED carrying findings', (d) => {
      d.verdict = { state: 'UNSUPPORTED' };
      d.unsupportedReason = 'the target reaches an object file but not a linked artefact';
      d.findings = [{
        id: 'VG-PROP-001', severity: 'high', title: 'A required zeroing effect did not survive',
        detail: 'the call site went to zero', where: { kind: 'ir', path: 'fixtures/secret.c', unit: 'wipe_kept', pass: 'DSEPass' },
        property: 'prop.erasure.stack-buffer', point: 'compile-end',
      }];
    }, 'findings-under-unsupported'],
    ['a point that was not reached and gives no reason', (d) => {
      d.observationPoints[1].reached = false;
      d.observationPoints[1].unreachedReason = null;
    }, 'unreached-without-reason'],
    ['a must-survive property that ends LOST with nobody saying so', (d) => {
      d.properties[0].history[1].state = 'LOST';
      d.properties[0].history[1].count.callSites = 0;
    }, 'unaccounted-violation'],
    ['LOST used for something that was never PRESENT', (d) => {
      d.properties[0].history[0].state = 'LOST';
    }, 'impossible-transition'],
    ['REINTRODUCED used for something that was never LOST', (d) => {
      d.properties[0].history[1].state = 'REINTRODUCED';
    }, 'impossible-transition'],
    ['a history entry naming a point nobody declared', (d) => {
      d.properties[0].history[1].point = 'lto-end';
    }, 'dangling-point'],
    ['a count taken by searching for a symbol name', (d) => {
      d.properties[0].history[0].count.oracle = 'symbol-name';
    }, 'bad-oracle'],
    ['a property with no control', (d) => {
      delete d.properties[0].control;
    }, 'no-control'],
    ['an absolute path in a finding detail', (d) => {
      d.findings = [{
        id: 'VG-PROP-001', severity: 'high', title: 'A required zeroing effect did not survive',
        detail: 'read from /opt/build/secret.c', where: { kind: 'ir', path: 'fixtures/secret.c', unit: 'wipe_kept', pass: 'DSEPass' },
        property: 'prop.erasure.stack-buffer', point: 'compile-end',
      }];
    }, 'absolute-path'],
    ['a ratio written as a float', (d) => {
      d.layers.compile.passesSeen = 578.5;
    }, 'non-integer-number'],
    ['a toolchain that cannot be identified', (d) => {
      d.toolchain.digest = null;
    }, 'no-toolchain-digest'],
    ['two observation points with one id', (d) => {
      d.observationPoints[1].id = 'pre-opt';
    }, 'duplicate-point-id'],
    ['a verdict outside the five states', (d) => {
      d.verdict = { state: 'PROBABLY_FINE' };
    }, 'unknown-verdict'],
    ['a record with no counting line', (d) => {
      delete d.counts;
    }, 'no-counts'],
  ];

  for (const [why, mutate, reason] of cases) {
    const draft = cleanDraft();
    mutate(draft);
    const built = buildObservation(draft);
    assert.equal(built.ok, false, `${why}: the emitter wrote a record anyway`);
    assert.ok(reasonsOf(built).includes(reason),
      `${why}: refused, but not on ${reason}:\n${messagesOf(built)}`);
  }
});

test('the same evidence without the claim is accepted, so the gate is about the claim', () => {
  // The negative fixture for the gate. An unreached point is not an error by
  // itself; it is only an error next to a claim of cleanliness. Without this,
  // "clean-over-unobserved" could be a rule that refuses every incomplete run.
  const draft = cleanDraft();
  draft.observationPoints[1].reached = false;
  draft.observationPoints[1].unreachedReason = 'the compiler crashed before the pass pipeline ended';
  draft.properties[0].history[1].state = 'NOT_OBSERVED';

  const built = buildObservation(draft);
  assert.equal(built.ok, true, `expected acceptance, got:\n${messagesOf(built)}`);
  assert.equal(built.record.verdict.state, 'VERIFICATION_INCOMPLETE', 'the derived verdict is the weakest honest one');
  assert.equal(built.record.verdict.exitCode, 3);
  assert.equal(built.record.properties[0].verdict, 'VERIFICATION_INCOMPLETE');
  assert.equal(built.record.properties[0].finalState, 'NOT_OBSERVED');
  assert.deepStrictEqual(built.record.counts.pointCoverage, { num: 1, den: 2 });
  const text = `${JSON.stringify(built.record, null, 2)}\n`;
  assert.equal(validateDocument(schema, JSON.parse(text), text).ok, true);
});

test('with no claim the verdict is derived, and the derivation is not always the same answer', () => {
  const clean = buildObservation(cleanDraft());
  assert.equal(clean.ok, true, messagesOf(clean));
  assert.equal(clean.record.verdict.state, 'VERIFIED_CLEAN');

  const withFinding = cleanDraft();
  withFinding.properties[0].history[1].state = 'LOST';
  withFinding.properties[0].history[1].count.callSites = 0;
  withFinding.findings = [{
    id: 'VG-PROP-001', severity: 'high', title: 'A required zeroing effect did not survive optimisation',
    detail: 'wipe_kept went from one zeroing call site to none at AnnotationRemarksPass',
    where: { kind: 'ir', path: 'fixtures/secret.c', unit: 'wipe_kept', pass: 'AnnotationRemarksPass' },
    property: 'prop.erasure.stack-buffer', point: 'compile-end',
  }];
  const found = buildObservation(withFinding);
  assert.equal(found.ok, true, messagesOf(found));
  assert.equal(found.record.verdict.state, 'FINDINGS_PRESENT');
  assert.equal(found.record.verdict.exitCode, 2);
  assert.equal(found.record.properties[0].verdict, 'FINDINGS_PRESENT');
  assert.equal(found.record.properties[0].lossEpisodes, 1);
  assert.deepStrictEqual(found.record.properties[0].firstLoss, {
    pass: 'AnnotationRemarksPass', unit: 'wipe_kept', seq: 578, historyIndex: 1,
  });

  const brokenControl = cleanDraft();
  brokenControl.properties[0].control.count.callSites = 0;
  const mismatch = buildObservation(brokenControl);
  assert.equal(mismatch.ok, true, messagesOf(mismatch));
  assert.equal(mismatch.record.verdict.state, 'EVIDENCE_MISMATCH');
  assert.equal(mismatch.record.verdict.exitCode, 4);
  assert.equal(mismatch.record.properties[0].verdict, 'EVIDENCE_MISMATCH');

  const outside = cleanDraft();
  outside.unsupportedReason = 'the target reaches an object file but not a linked artefact with this toolchain';
  const unsupported = buildObservation(outside);
  assert.equal(unsupported.ok, true, messagesOf(unsupported));
  assert.equal(unsupported.record.verdict.state, 'UNSUPPORTED');
  assert.equal(unsupported.record.verdict.exitCode, 3);

  assert.deepStrictEqual(
    [clean, found, mismatch, unsupported].map((b) => b.record.verdict.state),
    ['VERIFIED_CLEAN', 'FINDINGS_PRESENT', 'EVIDENCE_MISMATCH', 'UNSUPPORTED'],
  );
});

test('the schema gate on the emitter\'s own output is live, not decorative', () => {
  // `emitObservation` validates what `buildObservation` produced before handing
  // it back. That gate is only worth having if it can actually fire, so here are
  // two fields the builder carries through without an opinion of its own: an
  // artefact format outside the enum, and a skipped-name that is not a string.
  // Both pass the builder and are stopped by the schema.
  const badFormat = cleanDraft();
  badFormat.layers.artifact.format = 'coff';
  assert.equal(buildObservation(badFormat).ok, true, 'the builder was expected to carry this through');
  const stopped = emitObservation(schema, badFormat);
  assert.equal(stopped.ok, false);
  assert.equal(stopped.stage, 'validate');
  assert.match(stopped.errors.join('\n'), /\/layers\/artifact\/format/);

  const badSkipped = cleanDraft();
  badSkipped.counts.skippedNames = [17];
  assert.equal(buildObservation(badSkipped).ok, true);
  const stopped2 = emitObservation(schema, badSkipped);
  assert.equal(stopped2.ok, false);
  assert.equal(stopped2.stage, 'validate');
  assert.match(stopped2.errors.join('\n'), /\/counts\/skippedNames\/0/);
});

test('an absent field stays absent and a null stays null', () => {
  // `null` is "not applicable" and an absent key is "not written down"; the
  // canonicaliser in compiler/evidence treats them as different records, so the
  // writer must not turn one into the other.
  const draft = cleanDraft();
  delete draft.properties[0].note;
  delete draft.properties[0].scope;
  draft.observationPoints[0].tool = null;
  const built = buildObservation(draft);
  assert.equal(built.ok, true, messagesOf(built));
  assert.equal('note' in built.record.properties[0], false);
  assert.equal('scope' in built.record.properties[0], false);
  assert.equal('tool' in built.record.observationPoints[0], true);
  assert.equal(built.record.observationPoints[0].tool, null);
});

// ── 6. the adapter for the record form this tree already writes ─────────────

test('the fixture really is a record the driver writes', () => {
  const rec = readDoc(DRIVER_RECORD);
  assert.equal(rec.recordVersion, DRIVER_RECORD_VERSION);
  assert.equal(rec.component, 'driver');
  assert.equal(rec.checks.properties.entries.length, 1);
  assert.equal(rec.checks.properties.entries[0].id, 'survive.secure-wipe');
  assert.deepStrictEqual(rec.checks.properties.entries[0].requestedCheckpoints, ['pre-opt-ir', 'after-pass']);
});

test('a driver record becomes an observation record the validator accepts', () => {
  const adapted = draftFromDriverRecord(readDoc(DRIVER_RECORD));
  assert.equal(adapted.ok, true, JSON.stringify(adapted.errors ?? []));
  const emitted = emitObservation(schema, adapted.draft);
  assert.equal(emitted.ok, true, (emitted.errors ?? []).join('\n'));

  const r = emitted.record;
  assert.equal(r.verdict.state, 'VERIFICATION_INCOMPLETE');
  assert.equal(r.verdict.exitCode, 3);
  assert.deepStrictEqual(
    r.observationPoints.map((p) => `${p.id}:${p.checkpoint}:${p.stage}:${p.reached}`),
    ['survive.secure-wipe.pre-opt-ir:pre-opt-ir:compile:false', 'survive.secure-wipe.after-pass:after-pass:compile:false'],
  );
  assert.deepStrictEqual(r.counts.pointCoverage, { num: 0, den: 2 });

  // The honest hole, asserted rather than left to be noticed: a driver record
  // carries a reachability cross-check and no measurement, and an observation
  // property needs a control, so there is nothing here to put in properties[].
  assert.deepStrictEqual(r.properties, []);
  assert.deepStrictEqual([r.layers.compile.observed, r.layers.link.observed, r.layers.artifact.observed], [false, false, false]);

  // A package whose version was never observed is skipped BY NAME, and the
  // counting line says so rather than the array quietly reading as complete.
  assert.deepStrictEqual(r.toolchain.packages, []);
  assert.equal(r.counts.skipped, 2);
  assert.equal(r.counts.skippedNames.length, 2);
  assert.match(r.counts.skippedNames[0], /^toolchain package `clang-18`: its version was not observed \(null\)/);
  assert.equal(r.toolchain.digest, readDoc(DRIVER_RECORD).toolchain.digest);
});

test('the adapter refuses rather than inventing what a driver record does not carry', () => {
  const base = readDoc(DRIVER_RECORD);

  const noDigest = structuredClone(base);
  noDigest.toolchain.digest = null; // what the driver writes when no pin was configured
  const a = draftFromDriverRecord(noDigest);
  assert.equal(a.ok, false);
  assert.deepStrictEqual(a.errors.map((e) => e.reason), ['no-toolchain-digest']);

  const wrongVersion = structuredClone(base);
  wrongVersion.recordVersion = 'compiler-evidence-v1';
  const b = draftFromDriverRecord(wrongVersion);
  assert.equal(b.ok, false);
  assert.ok(b.errors.map((e) => e.reason).includes('wrong-record-version'));

  // A finding this form cannot express must stop the emission. Dropping it
  // would turn a reported problem into a record with nothing in it.
  const alienFinding = structuredClone(base);
  alienFinding.findings = [{
    id: 'VG-BEYOND-001', severity: 'high', title: 'something a peer reported',
    detail: 'from a namespace this schema does not reserve', where: { kind: 'invocation', path: null, unit: null, pass: null },
  }];
  const c = draftFromDriverRecord(alienFinding);
  assert.equal(c.ok, false);
  assert.ok(c.errors.map((e) => e.reason).includes('unrepresentable-finding'));
  assert.match(c.errors.map((e) => e.message).join('\n'), /VG-BEYOND-001/);

  // And the counterweight: a finding inside the reserved namespaces is carried.
  const ownFinding = structuredClone(base);
  ownFinding.findings = [{
    id: 'VG-CFG-002', severity: 'high', title: 'A forbidden flag was on the command line',
    detail: '-fno-stack-protector was present', where: { kind: 'invocation', path: null, unit: null, pass: null },
  }];
  const d = draftFromDriverRecord(ownFinding);
  assert.equal(d.ok, true, JSON.stringify(d.errors ?? []));
  const emitted = emitObservation(schema, d.draft);
  assert.equal(emitted.ok, true, (emitted.errors ?? []).join('\n'));
  assert.deepStrictEqual(emitted.record.findings.map((f) => f.id), ['VG-CFG-002']);
});

// ── 7. path hygiene of everything this directory ships and writes ───────────

test('no record this directory ships or writes names one machine', () => {
  const targets = [
    ['the driver-record fixture', readDoc(DRIVER_RECORD)],
    ...validNames().map((n) => [n, readDoc(join(VALID_DIR, n))]),
  ];
  const emitted = emitObservation(schema, structuredClone(SELF_CHECK_DRAFT));
  assert.equal(emitted.ok, true);
  targets.push(['the emitted self-check record', emitted.record]);
  const adapted = draftFromDriverRecord(readDoc(DRIVER_RECORD));
  assert.equal(adapted.ok, true);
  const fromDriver = emitObservation(schema, adapted.draft);
  assert.equal(fromDriver.ok, true);
  targets.push(['the record emitted from the driver record', fromDriver.record]);

  for (const [label, doc] of targets) {
    assert.deepStrictEqual(findMachinePaths(doc), [], `${label} names one machine`);
    assert.deepStrictEqual(findNonIntegers(doc), [], `${label} carries a non-integer number`);
  }

  // The emitter's own scan and the validator's are two independent lists of
  // shapes; they are checked against each other on a string that must trip both.
  const bad = structuredClone(emitted.record);
  bad.properties[0].note = 'read from /opt/build/secret.c';
  assert.equal(findMachinePaths(bad).length, 1, 'the emitter-side scan missed an absolute path');
  assert.ok(semanticErrors(bad).map((e) => e.rule).includes('OBS-S11'), 'the validator-side scan missed the same string');
});

// ── 8. sealing ──────────────────────────────────────────────────────────────

test('the seal is over the record without context, and moves only when the evidence moves', async () => {
  const emitted = emitObservation(schema, structuredClone(SELF_CHECK_DRAFT));
  assert.equal(emitted.ok, true);
  const sealed = await sealObservation(emitted.record);
  assert.match(sealed.evidenceDigest, /^[0-9a-f]{64}$/);

  const text = `${JSON.stringify(sealed, null, 2)}\n`;
  assert.equal(validateDocument(schema, JSON.parse(text), text).ok, true, 'a sealed record must still validate');

  // Rule 1 of interfaces.md section 5, measured in both directions rather than
  // asserted: `context` is excluded as a whole subtree, so a different clock
  // must not move the digest — and a different measurement must.
  const laterClock = structuredClone(emitted.record);
  laterClock.context.generatedAt = '2031-01-01T00:00:00Z';
  const sealedLater = await sealObservation(laterClock);
  assert.equal(sealedLater.evidenceDigest, sealed.evidenceDigest, 'the clock moved the digest, so `context` is not being excluded');

  const differentEvidence = structuredClone(emitted.record);
  differentEvidence.properties[0].history[1].count.callSites = 2;
  const sealedOther = await sealObservation(differentEvidence);
  assert.notEqual(sealedOther.evidenceDigest, sealed.evidenceDigest, 'a changed call-site count did not move the digest');
});

// ── 9. the runner ───────────────────────────────────────────────────────────

test('the runner prints inputs/checked/skipped on every path', async () => {
  for (const argv of [['--self-check'], ['--from-driver-record', DRIVER_RECORD], []]) {
    const { out } = await capture(argv);
    assert.match(out, /inputs=\d+ checked=\d+ skipped=\d+/, `no count line for ${argv.join(' ') || '(no arguments)'}`);
  }
});

test('naming no input is incomplete, never a silent success', async () => {
  const { code, out, err } = await capture([]);
  assert.equal(code, EXIT_INCOMPLETE);
  assert.match(out, /inputs=0 checked=0 skipped=0/);
  assert.match(err, /no input was named/);
});

test('an input that cannot be read is incomplete, and a draft that is refused is an integrity failure', async () => {
  const missing = await capture(['--from-draft', join(HERE, 'no-such-draft.json')]);
  assert.equal(missing.code, EXIT_INCOMPLETE);
  assert.match(missing.out, /inputs=0 checked=0 skipped=0/);

  const dir = mkdtempSync(join(tmpdir(), 'emit-obs-'));
  try {
    const badDraft = structuredClone(SELF_CHECK_DRAFT);
    badDraft.verdict = { state: 'VERIFIED_CLEAN' };
    badDraft.observationPoints[1].reached = false;
    badDraft.observationPoints[1].unreachedReason = 'the compiler crashed';
    const p = join(dir, 'draft.json');
    writeFileSync(p, `${JSON.stringify(badDraft, null, 2)}\n`, 'utf8');
    const refused = await capture(['--from-draft', p]);
    assert.equal(refused.code, EXIT_INTEGRITY);
    assert.match(refused.err, /REFUSED \(draft\)/);
    assert.match(refused.err, /clean-over-unobserved/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--out writes a file, and the file it wrote validates', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'emit-obs-out-'));
  try {
    const out = join(dir, 'nested', 'observation.json');
    const { code } = await capture(['--from-driver-record', DRIVER_RECORD, '--out', out, '--seal']);
    assert.equal(code, EXIT_OK);
    const raw = readFileSync(out, 'utf8');
    const result = validateDocument(schema, JSON.parse(raw), raw);
    assert.equal(result.ok, true, `the file the runner wrote does not validate:\n${result.errors.join('\n')}`);
    assert.match(JSON.parse(raw).evidenceDigest, /^[0-9a-f]{64}$/);
    assert.equal(JSON.parse(raw).verdict.state, 'VERIFICATION_INCOMPLETE');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the runner exit code is about the emission, not about the build it describes', async () => {
  // The record below carries exitCode 3. The command still exits 0, because it
  // succeeded at writing an honest record. Conflating the two would make "the
  // build was incomplete" indistinguishable from "the record could not be
  // written", which is the distinction this whole directory is about.
  const { code, out } = await capture(['--from-driver-record', DRIVER_RECORD]);
  assert.equal(code, EXIT_OK);
  assert.match(out, /record verdict=VERIFICATION_INCOMPLETE recordExitCode=3; emission ok/);
});

test('two inputs at once are refused rather than one being silently ignored', async () => {
  const { code, err } = await capture(['--self-check', '--from-driver-record', DRIVER_RECORD]);
  assert.equal(code, EXIT_INCOMPLETE);
  assert.match(err, /mutually exclusive/);
});
