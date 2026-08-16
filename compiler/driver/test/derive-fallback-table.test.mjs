// Tests for compiler/driver/tools/derive-fallback-table.mjs and
// compiler/schema/fallback-table.schema.json.
//
//   node --test compiler/driver/test/derive-fallback-table.test.mjs
//
// Nothing here compiles anything. The generator is a pure function of an
// envelope, so every case is a hand-written envelope in
// ./fallback-table-envelopes.mjs and every assertion is about a decision, not a
// measurement. The fixture names are `p.alpha` and `s-a` on purpose: a number
// that escapes from that module into a result should be obviously fake.
//
// WHAT IS BEING DEFENDED
//
// Three ways this generator could be wrong while still producing a plausible
// table, each with a test that fails if the defence is removed:
//
//   * two-subjects — a property carried by two programs, the second of
//     which was never measured at the candidate configuration. Aggregating by
//     property instead of by subject makes this row say `fallback`, citing the
//     wrong program. The test asserts it says `not-observed`, and also asserts
//     that the trap is really in the fixture (the first subject does hold).
//   * control-cells — positive controls parked at the same (subject,
//     config) coordinates as real cells, contradicting them. Indexing without
//     removing them makes a control silently overwrite a measurement.
//   * measured-absent / not-observed — a candidate that was measured
//     ABSENT, and a candidate that was never measured. Collapsing either into
//     "lost" turns "we did not look" into "there is nothing there".
//
// And two exits that must not be quiet: exit 3 when nothing in the envelope is
// usable, exit 2 when a LOST cell exists that no row accounts for. Both are
// asserted to leave no output file behind, because a partial table on disk is
// what a later step would read.
//
// ABOUT THE VALIDATOR IN THIS FILE
//
// compiler/driver/lib/jsonschema.mjs implements fifteen draft-07 keywords and
// refuses the rest by name rather than guessing — the right call, and the
// reason it cannot check this schema: the whole point of fallback-table.schema
// .json is the `if`/`then`/`else` that stops a row saying `fallback` while
// pointing at a null. So the subset validator below implements exactly the
// keywords this schema uses, refuses anything else, and the first test asserts
// both halves of that claim rather than trusting it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validate as inRepoValidate } from '../lib/jsonschema.mjs';
import { ENVELOPES } from './fallback-table-envelopes.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const TOOL = join(HERE, '..', 'tools', 'derive-fallback-table.mjs');
const SCHEMA_PATH = join(HERE, '..', '..', 'schema', 'fallback-table.schema.json');
const REAL_ENVELOPE = join(HERE, '..', '..', 'llvm-pass', '_results', 'envelope', 'envelope.json');

const SCHEMA = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8'));

// Derived from the module rather than restated, so a new envelope cannot be
// added without the coverage tests below picking it up.
const FIXTURE_NAMES = Object.keys(ENVELOPES).sort();

const WORK = mkdtempSync(join(tmpdir(), 'fallback-table-test-'));
test.after(() => rmSync(WORK, { recursive: true, force: true }));

let runCounter = 0;

/** Run the CLI on a fixture. Returns { status, stderr, stdout, outPath, table }. */
function derive(fixture, { out } = {}) {
  runCounter += 1;
  // Synthetic envelopes live in a module, not in a data directory — see the
  // note at the top of fallback-table-envelopes.mjs. They are written into the
  // scratch directory here because the generator's interface is a path.
  let envelope;
  if (fixture.endsWith('.json')) {
    envelope = fixture;
  } else {
    const doc = ENVELOPES[fixture];
    assert.ok(doc, `no synthetic envelope named ${fixture}`);
    envelope = join(WORK, `${runCounter}-in-${fixture}.json`);
    writeFileSync(envelope, JSON.stringify(doc, null, 2));
  }
  const outPath = out ?? join(WORK, `${runCounter}-${fixture.replace(/[\\/:]/g, '_')}.json`);
  const r = spawnSync(process.execPath, [TOOL, '--envelope', envelope, '--out', outPath], { encoding: 'utf8' });
  const table = r.status === 0 && existsSync(outPath) ? JSON.parse(readFileSync(outPath, 'utf8')) : null;
  return { status: r.status, stderr: r.stderr, stdout: r.stdout, outPath, table };
}

/** Write one synthetic envelope into the scratch dir and return its path. */
function writeEnvelope(name) {
  runCounter += 1;
  const p2 = join(WORK, `${runCounter}-in-${name}.json`);
  writeFileSync(p2, JSON.stringify(ENVELOPES[name], null, 2));
  return p2;
}

/** `derive`, plus the envelope it was given, for tests that reconcile the two. */
function deriveWithEnvelope(fixture) {
  const envelope = fixture.endsWith('.json') ? JSON.parse(readFileSync(fixture, 'utf8')) : ENVELOPES[fixture];
  return { ...derive(fixture), envelope };
}

const rowFor = (table, propertyId, pred = () => true) => table.rows.find((r) => r.propertyId === propertyId && pred(r));

// ── a draft-07 subset validator that implements `if` ────────────────────────

const IMPLEMENTED_KEYWORDS = Object.freeze([
  '$id', '$ref', '$schema', 'additionalProperties', 'const', 'definitions', 'description',
  'else', 'enum', 'if', 'items', 'minItems', 'minimum', 'properties', 'required', 'then',
  'title', 'type',
]);

function typeOf(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

function matchesType(v, name) {
  switch (name) {
    case 'null': return v === null;
    case 'array': return Array.isArray(v);
    case 'object': return v !== null && typeof v === 'object' && !Array.isArray(v);
    case 'integer': return typeof v === 'number' && Number.isInteger(v);
    case 'number': return typeof v === 'number' && Number.isFinite(v);
    case 'string': return typeof v === 'string';
    case 'boolean': return typeof v === 'boolean';
    default: return false;
  }
}

function deref(schema, root, depth = 0) {
  if (depth > 16) throw new Error('$ref nesting too deep');
  if (!schema || typeof schema !== 'object' || typeof schema.$ref !== 'string') return schema;
  let node = root;
  for (const seg of schema.$ref.slice(2).split('/')) {
    node = node?.[seg];
    if (node === undefined) throw new Error(`unresolvable $ref ${schema.$ref}`);
  }
  return deref(node, root, depth + 1);
}

function check(schema, value, pointer, root, errors) {
  const s = deref(schema, root);
  if (s === true) return;
  if (s === false) { errors.push(`${pointer}: schema forbids any value`); return; }
  if (!s || typeof s !== 'object') return;

  for (const key of Object.keys(s)) {
    if (!IMPLEMENTED_KEYWORDS.includes(key)) {
      errors.push(`${pointer}: unsupported keyword \`${key}\` — this validator refuses to guess`);
      return;
    }
  }

  if (s.type !== undefined) {
    const names = Array.isArray(s.type) ? s.type : [s.type];
    if (!names.some((n) => matchesType(value, n))) {
      errors.push(`${pointer}: expected ${names.join('|')}, got ${typeOf(value)}`);
      return;
    }
  }
  if (s.const !== undefined && value !== s.const) {
    errors.push(`${pointer}: must be ${JSON.stringify(s.const)}, got ${JSON.stringify(value)}`);
  }
  if (Array.isArray(s.enum) && !s.enum.includes(value)) {
    errors.push(`${pointer}: must be one of ${JSON.stringify(s.enum)}, got ${JSON.stringify(value)}`);
  }
  if (typeof s.minimum === 'number' && typeof value === 'number' && value < s.minimum) {
    errors.push(`${pointer}: must be >= ${s.minimum}`);
  }
  if (Array.isArray(value)) {
    if (typeof s.minItems === 'number' && value.length < s.minItems) {
      errors.push(`${pointer}: needs at least ${s.minItems} item(s), has ${value.length}`);
    }
    if (s.items !== undefined) value.forEach((v, i) => check(s.items, v, `${pointer}/${i}`, root, errors));
  }
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const name of s.required ?? []) {
      if (!Object.prototype.hasOwnProperty.call(value, name)) errors.push(`${pointer}: missing required \`${name}\``);
    }
    for (const [name, sub] of Object.entries(s.properties ?? {})) {
      if (Object.prototype.hasOwnProperty.call(value, name)) check(sub, value[name], `${pointer}/${name}`, root, errors);
    }
    if (s.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!Object.prototype.hasOwnProperty.call(s.properties ?? {}, name)) {
          errors.push(`${pointer}: unexpected property \`${name}\``);
        }
      }
    }
  }
  if (s.if !== undefined) {
    const probe = [];
    check(s.if, value, pointer, root, probe);
    const branch = probe.length === 0 ? s.then : s.else;
    if (branch !== undefined) check(branch, value, pointer, root, errors);
  }
}

function validateTable(doc) {
  const errors = [];
  check(SCHEMA, doc, '', SCHEMA, errors);
  return errors;
}

/** Every keyword the schema uses, ignoring `properties`/`definitions` key names. */
function keywordsUsedBy(schema) {
  const seen = new Set();
  const walk = (node, insideNames) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach((n) => walk(n, false)); return; }
    for (const [key, value] of Object.entries(node)) {
      if (!insideNames) seen.add(key);
      walk(value, key === 'properties' || key === 'definitions');
    }
  };
  walk(schema, false);
  return [...seen].sort();
}

// ── the schema, and why it is not checked by the in-repo validator ──────────

test('the schema uses only keywords this file implements', () => {
  const unimplemented = keywordsUsedBy(SCHEMA).filter((k) => !IMPLEMENTED_KEYWORDS.includes(k));
  assert.deepEqual(unimplemented, [], `schema grew keywords the test validator does not implement: ${unimplemented}`);
});

test('the in-repo validator refuses this schema, by name, rather than half-checking it', () => {
  // Not a defect in either component. jsonschema.mjs is documented to refuse
  // what it does not implement, and `if` is what this schema is for. Asserted
  // so that a future widening of jsonschema.mjs is noticed here.
  // A real table, so the walk actually reaches `definitions/row` where the
  // conditional lives — a stub would fail on missing properties first and the
  // assertion would pass for the wrong reason.
  const { table } = derive('fallback-simple');
  const errs = inRepoValidate(SCHEMA, table);
  assert.ok(errs.length > 0, 'expected the in-repo validator to object');
  assert.ok(
    errs.some((e) => /unsupported keyword/.test(e.message)),
    `expected an "unsupported keyword" refusal, got ${JSON.stringify(errs)}`,
  );
});

test('the schema forbids a `fallback` row that names no target', () => {
  const { table } = derive('fallback-simple');
  assert.deepEqual(validateTable(table), []);

  const broken = structuredClone(table);
  broken.rows[0].to = null;
  broken.rows[0].profile = null;
  broken.rows[0].evidence = [];
  const errs = validateTable(broken);
  assert.ok(errs.length > 0, 'a fallback row with to=null must not validate');
  assert.ok(errs.some((e) => /\/to: expected object/.test(e)), errs.join('\n'));
});

test('the schema forbids a refusal row that names a target anyway', () => {
  const { table } = derive('not-observed');
  assert.deepEqual(validateTable(table), []);

  const broken = structuredClone(table);
  broken.rows[0].to = { cc: 'cc-fixture', freestanding: false, lto: 'none', ndebug: false, opt: '-O0', target: 'host' };
  broken.rows[0].profile = '-O0';
  const errs = validateTable(broken);
  assert.ok(errs.some((e) => /\/to: expected null/.test(e)), errs.join('\n'));
  assert.ok(errs.some((e) => /\/profile: expected null/.test(e)), errs.join('\n'));
});

test('the schema pins the three resolution words', () => {
  const { table } = derive('fallback-simple');
  const broken = structuredClone(table);
  broken.rows[0].resolution = 'probably-fine';
  const errs = validateTable(broken);
  assert.ok(errs.some((e) => /resolution: must be one of/.test(e)), errs.join('\n'));
});

// ── the branches ────────────────────────────────────────────────────────────

test('fallback: the highest surviving optimisation level is chosen, and cited', () => {
  const { status, table, stderr } = derive('fallback-simple');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);
  assert.equal(table.counts.rows, 1);

  const row = table.rows[0];
  assert.equal(row.resolution, 'fallback');
  assert.equal(row.to.opt, '-O1', 'must not over-weaken to -O0 when -O1 was measured to hold');
  assert.equal(row.profile, '-O1');
  assert.deepEqual(row.lostSubjects, ['s-a']);
  assert.equal(row.evidence.length, 1);
  assert.equal(row.evidence[0].state, 'PRESENT');
  assert.equal(row.evidence[0].controlHeld, true);
  assert.match(stderr, /^rows=1 lost=1 control=0 byResolution=\{.*\}\n$/);
});

test('no-safe-target: every candidate was measured and every candidate lost', () => {
  const { status, table } = derive('no-safe-target');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);
  assert.equal(table.counts.byResolution['no-safe-target'], 3);
  assert.equal(table.counts.byResolution['not-observed'], 0);

  const o2 = rowFor(table, 'p.beta', (r) => r.from.opt === '-O2');
  assert.equal(o2.resolution, 'no-safe-target');
  assert.deepEqual([...new Set(o2.rejected.map((x) => x.why))], ['measured-lost']);
  assert.deepEqual(o2.rejected.map((x) => x.config.opt), ['-O1', '-O0'], 'candidates must be tried strongest first');

  // The already-weakest row: "no-safe-target" with nothing rejected means
  // "there was nothing to try", which is a different sentence, so it is named.
  const o0 = rowFor(table, 'p.beta', (r) => r.from.opt === '-O0');
  assert.equal(o0.resolution, 'no-safe-target');
  assert.deepEqual(o0.rejected, []);
  assert.ok(table.anomalies.some((a) => a.startsWith('already-weakest:')), table.anomalies.join('\n'));
});

test('not-observed: a broken instrument and a missing cell are not a measured loss', () => {
  const { status, table } = derive('not-observed');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  const row = table.rows[0];
  assert.equal(row.resolution, 'not-observed', 'a broken candidate must not be read as "everything was tried"');
  assert.equal(row.to, null);
  assert.equal(row.profile, null);
  assert.deepEqual(row.evidence, []);
  assert.deepEqual(row.rejected.map((x) => x.why), ['broken-measurement', 'absent-from-envelope']);
});

test('measured-absent: ABSENT is an observation, and it is not LOST', () => {
  const { status, table } = derive('measured-absent');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  const row = table.rows[0];
  assert.deepEqual(row.rejected.map((x) => x.why), ['measured-absent']);
  assert.ok(!row.rejected.some((x) => x.why === 'measured-lost'), 'ABSENT must never be recorded as a loss');
  assert.equal(row.resolution, 'not-observed', 'no candidate held, and not every candidate was lost');
  assert.ok(table.anomalies.some((a) => a.startsWith('measured-absent-candidate:')), table.anomalies.join('\n'));
});

test('control cells are excluded, counted, and named — and cannot overwrite a measurement', () => {
  const { status, table } = derive('control-cells');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  assert.equal(table.counts.cells, 6);
  assert.equal(table.counts.controlCells, 3);
  assert.equal(
    table.anomalies.filter((a) => a.startsWith('control-excluded:')).length,
    3,
    'every excluded control must be listed, not just counted',
  );

  // pce2 sits on the -O1 coordinates and reports BROKEN_MEASUREMENT. If it were
  // allowed into the index this row would read `not-observed`.
  const row = table.rows[0];
  assert.equal(row.resolution, 'fallback');
  assert.equal(row.to.opt, '-O1');
  for (const e of row.evidence) assert.ok(!e.cellId.includes('ctl='), `a control was cited as evidence: ${e.cellId}`);

  // A positive control that reports a healthy PRESENT did not control anything.
  assert.ok(table.anomalies.some((a) => a.startsWith('control-did-not-fail:')), table.anomalies.join('\n'));
});

test('two subjects: one holding subject is not enough, and the trap is really in the fixture', () => {
  const { status, table } = derive('two-subjects');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  const delta = rowFor(table, 'p.delta');
  assert.equal(delta.resolution, 'not-observed');
  assert.equal(delta.to, null);
  assert.deepEqual(delta.lostSubjects, ['d-folded']);

  // The fixture must actually contain the trap: d-folded DOES hold at -O1, so a
  // generator that aggregated by property alone would have said `fallback` here.
  const envelope = ENVELOPES['two-subjects'];
  const folded = envelope.cells.find((c) => c.subject === 'd-folded' && c.config.opt === '-O1');
  assert.equal(folded.state, 'PRESENT');
  assert.equal(folded.measurement, 'OK');
  assert.deepEqual(
    delta.rejected.map((x) => `${x.config.opt}:${x.subject}:${x.why}`),
    ['-O1:d-live:absent-from-envelope', '-O0:d-live:absent-from-envelope'],
    'the row must be refused because of the unmeasured subject, and say which one',
  );

  // ...and the aggregation is not simply always refusing: with both subjects
  // measured, the same property shape resolves.
  const epsilon = rowFor(table, 'p.epsilon');
  assert.equal(epsilon.resolution, 'fallback');
  assert.equal(epsilon.to.opt, '-O1');
  assert.deepEqual(epsilon.evidence.map((e) => e.subject), ['e-one', 'e-two']);
});

test('dropping LTO is not a fallback, and a row that has only that is not resolved', () => {
  // The fixture offers a target that holds the property, reachable only by
  // dropping LTO. It is not taken, for two reasons that both live outside the
  // driver. observe-config.sh gives `full-prelink` and `full-backend` the same
  // compiler invocation and separates them by where the observer looks, so the
  // envelope's lto label is a build flag fused with an observation stage rather
  // than a build axis; and link-time optimisation is a whole-programme link
  // decision, while this fallback recompiles one translation unit. A row that
  // said "drop LTO" would name something the driver cannot do, on the strength
  // of evidence measured somewhere the recompile does not go.
  const { status, table } = derive('lto-weakening');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  const row = table.rows[0];
  assert.equal(row.from.lto, 'thin-prelink');
  assert.equal(row.to, null);
  assert.equal(row.profile, null);
  assert.notEqual(row.resolution, 'fallback');
  assert.equal(
    table.anomalies.filter((a) => a.startsWith('lto-widened:')).length,
    0,
    'no row should need an lto-widened warning any more; lto is a fixed axis',
  );
});

test('an opt level off the ladder is not-observed, never no-safe-target', () => {
  // -Os is a real level this ladder does not rank, so no candidate can be
  // formed. Zero candidates is "we do not know what is weaker", and calling
  // that no-safe-target would report "everything weaker was measured and lost"
  // on the strength of never having looked. Extending OPT_ORDER would fill this
  // row in; no amount of measuring fills in a genuine no-safe-target.
  const { status, table } = derive('opt-off-ladder');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);

  assert.equal(table.rows.length, 1);
  const row = table.rows[0];
  assert.equal(row.from.opt, '-Os');
  assert.equal(row.resolution, 'not-observed');
  assert.equal(row.to, null);
  assert.equal(row.profile, null);
  assert.ok(table.anomalies.some((a) => a.startsWith('opt-off-ladder:')), table.anomalies.join('\n'));
  assert.equal(
    table.counts.byResolution['no-safe-target'],
    0,
    'zero candidates must not be reported as "every candidate lost"',
  );
});

test('a LOST reported by a broken instrument gets no row, and does not trip the invariant', () => {
  // verdictFor() already refuses such a cell on the candidate side. If the row
  // side accepted it, the table would recommend a recompile on the strength of
  // a measurement it would not itself accept as evidence — and the exit-2
  // invariant, which wants every LOST cell accounted for, has to learn about
  // the exclusion or it turns a data condition into a crash.
  const { status, table } = derive('lost-under-broken-instrument');
  assert.equal(status, 0, 'an excused LOST cell must not read as an uncovered one');
  assert.deepEqual(validateTable(table), []);

  assert.equal(table.counts.lostCells, 2, 'the envelope still contains two LOST cells');
  assert.equal(table.counts.lostCellsUnderBrokenInstrument, 1);
  assert.equal(table.rows.length, 1, 'only the OK-measured LOST cell earns a row');
  assert.equal(table.rows[0].from.opt, '-O3');
  assert.ok(
    table.anomalies.some((a) => a.startsWith('lost-under-broken-instrument:') && a.includes('s-b+opt=O2+broken')),
    'the excluded cell must be named, not just counted: ' + table.anomalies.join('\n'),
  );
});

test('the table counts reconcile with the envelope it came from', () => {
  // byState and byMeasurement exist so a reader can check the table against the
  // envelope without opening the envelope. If they were derived from the rows
  // rather than from the cells they would agree with the table by construction
  // and check nothing.
  const { table, envelope } = deriveWithEnvelope('two-subjects');
  const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
  assert.equal(sum(table.counts.byState), envelope.cells.length);
  assert.equal(sum(table.counts.byMeasurement), envelope.cells.length);
  assert.equal(table.counts.byState.LOST ?? 0, envelope.cells.filter((c) => c.state === 'LOST').length);
  assert.equal(table.counts.lostCells, table.counts.byState.LOST ?? 0);
});

test('non-monotonic survival is recorded rather than smoothed', () => {
  const { status, table } = derive('non-monotonic');
  assert.equal(status, 0);
  assert.deepEqual(validateTable(table), []);
  const flagged = table.anomalies.filter((a) => a.startsWith('non-monotonic:'));
  assert.equal(flagged.length, 1, table.anomalies.join('\n'));
  assert.match(flagged[0], /LOST at -O1 .* but PRESENT at -O2/);
});

test('a fixed axis is never varied', () => {
  const { table } = derive('fallback-simple');
  for (const row of table.rows) {
    if (!row.to) continue;
    for (const axis of ['cc', 'target', 'ndebug', 'freestanding', 'lto']) {
      assert.equal(row.to[axis], row.from[axis], `fallback moved the fixed axis ${axis}`);
    }
  }
  assert.deepEqual(table.policy.fixedAxes, ['cc', 'target', 'ndebug', 'freestanding', 'lto']);
  assert.deepEqual(table.policy.variableAxes, ['opt']);
  assert.equal(table.policy.subjectAggregation, 'all-subjects-of-the-property-must-hold');
});

// ── the two loud exits ──────────────────────────────────────────────────────

test('exit 3 when not one cell is usable, and nothing is written', () => {
  const { status, stderr, outPath } = derive('all-broken');
  assert.equal(status, 3);
  assert.equal(existsSync(outPath), false, 'exit 3 must not leave a table behind');
  assert.match(stderr, /measurement="OK"/);
  assert.match(stderr, /measurementOK=0/);
});

test('exit 2 when a LOST cell exists that no row accounts for, and nothing is written', () => {
  const { status, stderr, outPath } = derive('lost-control-cell');
  assert.equal(status, 2);
  assert.equal(existsSync(outPath), false, 'exit 2 must not leave a partial table behind');
  assert.match(stderr, /produced no row/);
  assert.match(stderr, /ctl=pce1-plugin-absent/, 'the uncovered cell must be named, not counted');
  assert.match(stderr, /uncovered=1/);
});

test('a missing envelope is exit 3, not a cheerful empty table', () => {
  const outPath = join(WORK, 'never-written.json');
  const r = spawnSync(process.execPath, [TOOL, '--envelope', join(WORK, 'no-such-envelope.json'), '--out', outPath], { encoding: 'utf8' });
  assert.equal(r.status, 3);
  assert.equal(existsSync(outPath), false);
  assert.match(r.stderr, /cannot read envelope/);
});

test('a wrong command line is exit 1', () => {
  for (const argv of [[], ['--envelope', writeEnvelope('fallback-simple')], ['--wat']]) {
    const r = spawnSync(process.execPath, [TOOL, ...argv], { encoding: 'utf8' });
    assert.equal(r.status, 1, `expected usage failure for ${JSON.stringify(argv)}`);
    assert.match(r.stderr, /usage: derive-fallback-table\.mjs/);
  }
});

test('paths are arguments, not constants', () => {
  const src = readFileSync(TOOL, 'utf8');
  assert.ok(!/_results[\\/]envelope/.test(src), 'the generator must not hard-code the envelope location');
});

// ── determinism and total coverage of the fixtures ──────────────────────────

test('two runs of the same envelope produce identical bytes', () => {
  for (const name of ['fallback-simple', 'two-subjects', 'control-cells', 'no-safe-target']) {
    // The *same* envelope file for both runs, not two copies of the same
    // content. `source.path` names the envelope relative to the table, so two
    // copies at two paths are two different inputs and would fail this for a
    // reason that has nothing to do with determinism.
    const input = writeEnvelope(name);
    const a = join(WORK, `det-a-${name}.json`);
    const b = join(WORK, `det-b-${name}.json`);
    const ra = derive(input, { out: a });
    const rb = derive(input, { out: b });
    assert.equal(ra.status, 0);
    assert.equal(rb.status, 0);
    assert.equal(readFileSync(a, 'utf8'), readFileSync(b, 'utf8'), `${name} is not byte-stable`);
    assert.equal(ra.stderr, rb.stderr, `${name} summary line is not stable`);
  }
});

test('every fixture is exercised, and every table produced validates', () => {
  const exercised = [];
  for (const name of FIXTURE_NAMES) {
    const { status, table } = derive(name);
    exercised.push(name);
    if (status === 0) {
      assert.ok(table, `${name} exited 0 but wrote no table`);
      assert.deepEqual(validateTable(table), [], `${name} does not validate`);
      const sum = table.counts.byResolution.fallback
        + table.counts.byResolution['no-safe-target']
        + table.counts.byResolution['not-observed'];
      assert.equal(sum, table.counts.rows, `${name}: byResolution does not add up to rows`);
    } else {
      assert.ok([2, 3].includes(status), `${name} exited ${status}, which is not a defined outcome`);
    }
  }
  // The counting contract this repository keeps re-learning: a loop that
  // silently iterated over nothing must not be able to pass.
  assert.equal(exercised.length, FIXTURE_NAMES.length);
  assert.ok(exercised.length >= 10);
});

test('all three resolution words are reached by the fixture set', () => {
  const seen = new Set();
  for (const name of FIXTURE_NAMES) {
    const { table } = derive(name);
    for (const r of table?.rows ?? []) seen.add(r.resolution);
  }
  assert.deepEqual([...seen].sort(), ['fallback', 'no-safe-target', 'not-observed']);
});

// ── the real envelope, when this machine happens to have one ────────────────

test('the measured envelope, if it is on this machine', (t) => {
  if (!existsSync(REAL_ENVELOPE)) {
    // _results/ is gitignored, so most checkouts do not have it. Skipping is
    // stated, never implied, and the assertions below are never weakened to
    // make an absent file look like a pass.
    t.skip('compiler/llvm-pass/_results/envelope/envelope.json is untracked and absent here');
    return;
  }
  const { status, table, stderr } = derive(REAL_ENVELOPE);
  assert.equal(status, 0, stderr);
  assert.deepEqual(validateTable(table), []);

  assert.equal(table.counts.cells, table.source.cells);
  assert.equal(table.counts.rows, table.rows.length);
  assert.ok(table.counts.controlCells >= 2, 'the two observer silent-failure controls must be excluded and counted');

  // The conservative aggregation must actually bite on real data: authz
  // .failclosed is carried by two programs and the second is measured on one
  // target only, so some rows cannot be resolved. If this ever reads zero, the
  // aggregation has quietly become "any subject will do".
  assert.ok(
    table.counts.byResolution['not-observed'] > 0,
    'no row is `not-observed` — check that aggregation still requires every subject',
  );
  for (const row of table.rows) {
    if (row.resolution !== 'fallback') continue;
    assert.ok(row.evidence.length >= 1);
    for (const e of row.evidence) {
      assert.equal(e.state, 'PRESENT');
      assert.equal(e.measurement, 'OK');
      assert.equal(e.controlHeld, true);
    }
  }
});
