// The property catalogue, and the gate that connects it to a build.
//
// Two shapes of test, on purpose:
//
//   * against the REAL catalogue (compiler/schema/properties.json), because a
//     gate tested only against a fixture catalogue is a gate that has never met
//     the file it exists to read. These assert on ids the catalogue actually
//     carries, so if the catalogue changes status on one of them, this suite
//     says so instead of quietly passing;
//   * against synthetic catalogues, for the cases the real one cannot produce
//     on demand (an unreadable file, a kind whose coverage line is "none").
//
// Every detector has both directions. `survive.secure-wipe` / `must-survive`
// is the negative fixture throughout: it is the entry the catalogue marks
// implemented at two checkpoints, and it must never be flagged.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  CATALOGUE_PATH, CATALOGUE_RECORD_PATH, DECLARED_STATUSES, checkProperties, countingLine,
  kindHasAnyImplementation, loadCatalogue,
} from '../lib/properties.mjs';
import {
  DRIVER_DIR, evidenceRecords, makeScratch, makeSyntheticPin, runDriver, writeFakeCompiler,
} from './helpers.mjs';

const loaded = loadCatalogue();
assert.equal(loaded.ok, true, `the real catalogue must load: ${JSON.stringify(loaded)}`);
const CATALOGUE = loaded.catalogue;

// The three entries the catalogue marks `implemented`. Asserted rather than
// assumed: if the catalogue's own statuses move, the assertion below fails
// loudly instead of these fixtures quietly changing meaning.
const IMPLEMENTED = ['survive.secure-wipe', 'survive.fail-closed-branch', 'survive.authorization-check'];

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

test('the driver loads the real catalogue that ships in this repository', () => {
  assert.equal(CATALOGUE.schemaVersion, 'properties-v0');
  assert.ok(CATALOGUE.entryCount >= 20, `only ${CATALOGUE.entryCount} entries`);
  assert.match(CATALOGUE.sha256, /^[0-9a-f]{64}$/);
  assert.equal(CATALOGUE_PATH.endsWith('properties.json'), true);
  assert.equal(CATALOGUE_RECORD_PATH.includes(':'), false, 'the recorded path must never be absolute');
});

test('the entries this suite calls implemented really are implemented in the catalogue', () => {
  for (const id of IMPLEMENTED) {
    const entry = CATALOGUE.byId.get(id);
    assert.ok(entry, `${id} is missing from the catalogue`);
    assert.equal(entry.status, 'implemented', `${id} is ${entry.status}`);
    assert.ok(
      entry.checkpoints.some((c) => c.status === 'implemented' && c.extractor !== null),
      `${id} has no implemented checkpoint`,
    );
  }
});

test('a catalogue that is not there is reported, not treated as an empty one', () => {
  const r = loadCatalogue(join(makeScratch('cat-missing'), 'absent.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unreadable');
});

test('a catalogue with the wrong schemaVersion does not load', () => {
  const dir = makeScratch('cat-version');
  const p = join(dir, 'properties.json');
  writeFileSync(p, JSON.stringify({ schemaVersion: 'properties-v1', properties: [] }), 'utf8');
  const r = loadCatalogue(p);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-version');
});

test('a catalogue that lists no properties cannot answer anything', () => {
  const dir = makeScratch('cat-empty');
  const p = join(dir, 'properties.json');
  writeFileSync(p, JSON.stringify({ schemaVersion: 'properties-v0', properties: [] }), 'utf8');
  const r = loadCatalogue(p);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-properties');
});

// ---------------------------------------------------------------------------
// Cross-checking, both directions
// ---------------------------------------------------------------------------

test('a property the catalogue implements at a checkpoint the policy asks for is usable', () => {
  const r = checkProperties(
    [{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['pre-opt-ir', 'after-pass'] }],
    CATALOGUE,
  );
  assert.equal(r.complete, true, JSON.stringify(r.findings));
  assert.equal(r.usable, 1);
  assert.equal(r.verdict, 'all-requested-reachable');
  assert.deepEqual(r.entries[0].reachableCheckpoints, ['pre-opt-ir', 'after-pass']);
});

test('an unknown property id is a finding, not a pass', () => {
  const r = checkProperties([{ id: 'survive.no-such-thing', kind: 'must-survive' }], CATALOGUE);
  assert.equal(r.complete, false);
  assert.equal(r.usable, 0);
  assert.equal(r.entries[0].verdict, 'unknown-id');
  assert.equal(r.findings[0].id, 'VG-CFG-016');
});

test('a kind that disagrees with the catalogue is a finding, not a pass', () => {
  const r = checkProperties([{ id: 'survive.secure-wipe', kind: 'must-not-appear' }], CATALOGUE);
  assert.equal(r.complete, false);
  assert.equal(r.entries[0].verdict, 'kind-mismatch');
  assert.equal(r.entries[0].catalogueKind, 'must-survive');
  assert.equal(r.findings[0].id, 'VG-CFG-017');
});

test('a property the catalogue marks unimplemented has no reachable checkpoint', () => {
  const r = checkProperties([{ id: 'survive.input-validation', kind: 'must-survive' }], CATALOGUE);
  assert.equal(r.complete, false);
  assert.equal(r.entries[0].verdict, 'property-unimplemented');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
});

test('a candidate property is not usable — the catalogue says it must not be quoted as evidence', () => {
  const r = checkProperties([{ id: 'survive.bounds-check', kind: 'must-survive' }], CATALOGUE);
  assert.equal(r.complete, false);
  assert.equal(r.entries[0].verdict, 'property-candidate');
  assert.match(r.findings[0].detail, /candidate/);
});

test('a status outside the declared vocabulary is refused rather than guessed at', () => {
  // The catalogue's preamble declares three statuses. `notappear.forbidden-external-call`
  // carries a fourth. Guessing what it is worth is how a partial check becomes
  // a whole one, so the driver refuses it by name.
  const entry = CATALOGUE.byId.get('notappear.forbidden-external-call');
  assert.ok(entry);
  assert.equal(DECLARED_STATUSES.includes(entry.status), false, `status ${entry.status} is now declared; update this test`);
  const r = checkProperties([{ id: entry.id, kind: entry.kind }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'status-not-in-vocabulary');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
});

test('a kind whose coverage line is "none" has no implementation whatever an entry claims', () => {
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-remain-unobservable'), false);
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-survive'), true);
  const r = checkProperties([{ id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'kind-unimplemented');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
});

test('asking for an implemented property at a checkpoint it is not implemented at is a finding', () => {
  // `survive.secure-wipe` is implemented at the IR checkpoints and nowhere
  // else. Asking for it at `object` is asking a question nothing answers.
  const r = checkProperties([{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['object'] }], CATALOGUE);
  assert.equal(r.complete, false);
  assert.equal(r.entries[0].verdict, 'no-reachable-checkpoint');
  assert.match(r.findings[0].detail, /pre-opt-ir/);
});

test('several requested properties are all reported, not just the first', () => {
  const r = checkProperties([
    { id: 'survive.secure-wipe', kind: 'must-survive' },
    { id: 'survive.no-such-thing', kind: 'must-survive' },
    { id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' },
  ], CATALOGUE);
  assert.equal(r.requested, 3);
  assert.equal(r.checked, 3);
  assert.equal(r.usable, 1);
  assert.equal(r.unanswerable, 2);
  assert.equal(r.findings.length, 2);
});

// ---------------------------------------------------------------------------
// Empty is not "all requirements met"
// ---------------------------------------------------------------------------

test('an empty properties[] is legal and says requested=0 in as many words', () => {
  const r = checkProperties([], CATALOGUE);
  assert.equal(r.configured, true);
  assert.equal(r.requested, 0);
  assert.equal(r.usable, 0);
  assert.equal(r.complete, true);
  assert.equal(r.verdict, 'no-properties-requested');
  assert.match(r.claim, /requested=0/);
  assert.equal(/all requirements met|all requested/i.test(r.claim), false, r.claim);
});

test('an absent properties[] is a different state from an empty one', () => {
  const absent = checkProperties(undefined, CATALOGUE);
  assert.equal(absent.configured, false);
  assert.equal(absent.verdict, 'not-configured');
  assert.notEqual(absent.verdict, checkProperties([], CATALOGUE).verdict);
});

test('the counting line states all three numbers', () => {
  assert.equal(countingLine({ inputs: 0, checked: 0, skipped: 0 }), 'inputs=0 checked=0 skipped=0');
  const r = checkProperties([{ id: 'survive.secure-wipe', kind: 'must-survive' }], CATALOGUE);
  assert.equal(countingLine(r), 'inputs=1 checked=1 skipped=0');
});

// ---------------------------------------------------------------------------
// The driver as a process
// ---------------------------------------------------------------------------

/**
 * A fixture the driver can run through on any host: the pin covers a file this
 * test made, so nothing needs a real toolchain to reach the property gate.
 */
function makePropertyFixture(label, properties) {
  const dir = makeScratch(label);
  const src = join(dir, 'src');
  const evidence = join(dir, 'evidence');
  const bin = join(dir, 'bin');
  mkdirSync(src, { recursive: true });
  mkdirSync(evidence, { recursive: true });
  mkdirSync(bin, { recursive: true });

  writeFileSync(join(src, 'hello.c'), 'int main(void){return 0;}\n', 'utf8');
  writeFakeCompiler(bin, 'cc-pinned');
  writeFileSync(
    join(src, 'toolchain.pin.json'),
    `${JSON.stringify(makeSyntheticPin(bin, [{ name: 'cc-pinned' }]), null, 2)}\n`,
    'utf8',
  );

  const policy = {
    policyVersion: 'policy-v0',
    failOn: 'critical',
    verification: { failOnIncomplete: false },
    toolchain: { pin: 'toolchain.pin.json', requireDigestMatch: true },
    flags: { optLevels: ['-O0', '-O2'] },
    evidence: { out: '../evidence', sourceDateEpoch: 1700000000 },
  };
  if (properties !== undefined) policy.properties = properties;
  writeFileSync(join(src, '.vgpolicy.json'), `${JSON.stringify(policy, null, 2)}\n`, 'utf8');

  return { dir, src, bin, evidence };
}

test('a policy naming an unknown property is exit 3, not exit 0', () => {
  const fx = makePropertyFixture('e2e-prop-unknown', [{ id: 'survive.no-such-thing', kind: 'must-survive' }]);
  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 3, r.stderr);
  assert.match(r.stderr, /inputs=1 checked=1 skipped=0/);

  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec, r.stderr);
  assert.equal(rec.record.exitReason, 'policy-properties-unanswerable');
  assert.ok(rec.record.findings.some((f) => f.id === 'VG-CFG-016'));
  assert.equal(rec.record.build.shipping.attempted, false);
});

test('a policy naming a property nothing implements is exit 3, not exit 0', () => {
  const fx = makePropertyFixture('e2e-prop-unimplemented', [
    { id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' },
  ]);
  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 3, r.stderr);
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec.record.findings.some((f) => f.id === 'VG-CFG-018'));
  assert.equal(rec.record.checks.properties.verdict, 'not-all-requested-reachable');
});

test('a policy whose kind disagrees with the catalogue is exit 3, not exit 0', () => {
  const fx = makePropertyFixture('e2e-prop-kind', [{ id: 'survive.secure-wipe', kind: 'must-not-appear' }]);
  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  assert.equal(r.status, 3, r.stderr);
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec.record.findings.some((f) => f.id === 'VG-CFG-017'));
});

test('a policy naming only implemented properties does not trip the gate — the negative fixture', () => {
  const fx = makePropertyFixture('e2e-prop-good', [
    { id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['pre-opt-ir', 'after-pass'] },
  ]);
  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec, r.stderr);
  assert.notEqual(rec.record.exitReason, 'policy-properties-unanswerable');
  assert.equal(rec.record.checks.properties.verdict, 'all-requested-reachable');
  assert.equal(rec.record.checks.properties.usable, 1);
  assert.equal(rec.record.findings.some((f) => ['VG-CFG-016', 'VG-CFG-017', 'VG-CFG-018'].includes(f.id)), false);
});

test('an empty properties[] reaches the record as requested=0, never as a met requirement', () => {
  const fx = makePropertyFixture('e2e-prop-empty', []);
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec);
  const p = rec.record.checks.properties;
  assert.equal(p.configured, true);
  assert.equal(p.requested, 0);
  assert.equal(p.counts.inputs, 0);
  assert.equal(p.verdict, 'no-properties-requested');
  assert.match(p.claim, /requested=0/);
  assert.notEqual(rec.record.exitReason, 'policy-properties-unanswerable');
});

test('an absent properties[] is recorded as not-configured, distinct from empty', () => {
  const fx = makePropertyFixture('e2e-prop-absent', undefined);
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec);
  assert.equal(rec.record.checks.properties.configured, false);
  assert.equal(rec.record.checks.properties.verdict, 'not-configured');
});

test('the catalogue digest is in the record, so a record says which catalogue answered', () => {
  const fx = makePropertyFixture('e2e-prop-catalogue', []);
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.equal(rec.record.checks.properties.catalogue.sha256, CATALOGUE.sha256);
  assert.equal(rec.record.checks.properties.catalogue.path, CATALOGUE_RECORD_PATH);
  assert.equal(rec.record.checks.properties.catalogue.status, 'loaded');
});

// ---------------------------------------------------------------------------
// The standalone runner and its counting contract
// ---------------------------------------------------------------------------

const TOOL = resolve(DRIVER_DIR, 'tools', 'check-gates.mjs');

function runTool(args, env = {}) {
  const r = spawnSync(process.execPath, [TOOL, ...args], {
    encoding: 'utf8', env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

test('the runner exits non-zero on an empty scan and says inputs=0', () => {
  // This has gone wrong in this repository three times: a scan pointed at the
  // wrong directory, finding nothing, reporting success. It cannot here.
  const empty = makeScratch('tool-empty');
  const r = runTool([empty]);
  assert.equal(r.status, 3);
  assert.match(r.stdout, /^inputs=0 checked=0 skipped=0$/m);
  assert.match(r.stderr, /nothing was scanned/);
});

test('--allow-empty is the only way an empty scan is exit 0, and it still prints the counts', () => {
  const empty = makeScratch('tool-empty-allowed');
  const r = runTool([empty, '--allow-empty']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^inputs=0 checked=0 skipped=0$/m);
});

test('the runner passes a policy whose properties and pin are both intact', () => {
  const fx = makePropertyFixture('tool-good', [
    { id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['pre-opt-ir'] },
  ]);
  const r = runTool([fx.src]);
  assert.match(r.stdout, /^inputs=1 checked=1 skipped=0$/m);
  assert.equal(r.status, 0, r.stdout + r.stderr);
});

test('the runner fails the same policy once one property leaves the catalogue', () => {
  const fx = makePropertyFixture('tool-bad', [{ id: 'survive.no-such-thing', kind: 'must-survive' }]);
  const r = runTool([fx.src]);
  assert.equal(r.status, 3, r.stdout + r.stderr);
  assert.match(r.stdout, /^inputs=1 checked=1 skipped=0$/m);
  assert.match(r.stdout, /VG-CFG-016/);
});

test('a skip has to be authorised by name, and every skipped case is listed', () => {
  const fx = makePropertyFixture('tool-skip', [{ id: 'survive.no-such-thing', kind: 'must-survive' }]);
  const unauthorised = runTool([fx.src]);
  assert.equal(unauthorised.status, 3, 'without authorisation the bad policy must fail, not skip');

  const r = runTool([fx.src], { VG_CHECK_GATES_SKIP: 'src' });
  assert.match(r.stdout, /^skip src — authorised by VG_CHECK_GATES_SKIP$/m);
  assert.match(r.stdout, /^inputs=1 checked=0 skipped=1$/m);
});
