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

// Rewritten 2026-09-12, the same way and for the same reason as the block below:
// this test used a REAL catalogue entry as its example of an unreadable status,
// and the catalogue's preamble had declared that status since 2026-08-18. The
// driver's stated rule is "act on the vocabulary the preamble declares, refuse
// what it does not", and while this file read three and the preamble said four,
// `partial` was being refused for the wrong reason -- `status-not-in-vocabulary`
// says the catalogue is malformed, and it was not. Both readings refused, so no
// pass/fail ever moved; only the message a reader was sent to debug did.
//
// So the two questions are separated here as well.

test('a status outside the declared vocabulary is refused rather than guessed at', () => {
  // MECHANISM, on a synthetic catalogue, so that no catalogue edit can make this
  // test stop testing anything. `implausible` is not one of the four and never
  // will be; the driver may not decide what it is worth.
  const synthetic = {
    kindCoverage: { 'must-survive': 'partial -- one extractor, measured' },
    byId: new Map([['synth.odd-status', {
      id: 'synth.odd-status', kind: 'must-survive', status: 'implausible', checkpoints: [],
    }]]),
  };
  const r = checkProperties([{ id: 'synth.odd-status', kind: 'must-survive' }], synthetic);
  assert.equal(r.entries[0].verdict, 'status-not-in-vocabulary');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
  assert.match(r.findings[0].detail, /will not guess/);
});

test('the four statuses this driver acts on are the four the catalogue declares', () => {
  // FACT. If the catalogue grows a fifth, this fails rather than silently
  // refusing every property that carries it for a reason that is not true.
  assert.deepEqual([...DECLARED_STATUSES].sort(), ['candidate', 'implemented', 'partial', 'unimplemented']);
  const inCatalogue = [...new Set([...CATALOGUE.byId.values()].map((e) => e.status))].sort();
  assert.deepEqual(inCatalogue, [...DECLARED_STATUSES].sort(),
    `the catalogue uses statuses this driver does not declare: ${inCatalogue.join(', ')}`);
});

test('a partial property is refused, and told it is half-measured rather than unbuilt', () => {
  // FACT, and the point of the whole change: `partial` is REFUSED. An extractor
  // exists and has measured something; the policy is asking for the whole claim.
  // Two entries carry it -- one of them, unobservable.secret-buffer-residue, is
  // the one compiler/eval/residue-tracer measured on 2026-09-12.
  for (const id of ['notappear.forbidden-external-call', 'unobservable.secret-buffer-residue']) {
    const entry = CATALOGUE.byId.get(id);
    assert.ok(entry, `${id} is no longer in the catalogue`);
    assert.equal(entry.status, 'partial', `${id} is ${entry.status}, not partial; update this test`);
    const r = checkProperties([{ id: entry.id, kind: entry.kind }], CATALOGUE);
    assert.equal(r.entries[0].verdict, 'property-partial', `${id} was not refused as partial`);
    assert.equal(r.findings[0].id, 'VG-CFG-018');
    // and the reason must not claim there is no extractor, because there is one
    assert.match(r.findings[0].detail, /part of what the entry claims/);
    assert.doesNotMatch(r.findings[0].detail, /there is no extractor/);
  }
});

test('declaring partial did not make any property reachable that was not', () => {
  // The danger a vocabulary change carries is that it turns a refusal into a
  // pass. Measured over the whole catalogue rather than argued: exactly seven
  // entries are reachable, and none of them is a partial one.
  const reachable = [...CATALOGUE.byId.values()]
    .filter((e) => checkProperties([{ id: e.id, kind: e.kind }], CATALOGUE).entries[0].verdict === 'reachable')
    .map((e) => e.id).sort();
  assert.equal(reachable.length, 7, `reachable: ${reachable.join(', ')}`);
  for (const id of reachable) {
    assert.equal(CATALOGUE.byId.get(id).status, 'implemented',
      `${id} is reachable but its status is not implemented`);
  }
});

// Rewritten 2026-09-12. This test used to assert
// `kindHasAnyImplementation(CATALOGUE, 'must-remain-unobservable') === false`, and
// that unobservable.secret-literal therefore read `kind-unimplemented`. Both were
// true and both stopped being true on the same day: compiler/eval/residue-tracer
// measured the residency half of unobservable.secret-buffer-residue, so that kind's
// coverage line moved from "none -- ..." to "partial -- ...".
//
// The old test could not survive that, because it used a LIVE catalogue kind as its
// example of a dead one. Nothing in the catalogue is "none" any more, and the next
// kind to be implemented would have broken it again. So the two questions are now
// separated:
//
//   * the MECHANISM -- does kindHasAnyImplementation read a leading "none"? -- is
//     tested against a synthetic catalogue, which no measurement can move.
//   * the FACT -- which kinds are "none" in the shipped catalogue today? -- is
//     asserted as a fact, so that a kind regressing to "none" is still a failure,
//     and so that the day some kind legitimately IS "none" this test says so rather
//     than silently passing.
//
// What has NOT changed is the thing worth guarding: a property whose kind has an
// implementation but which has none of its own is still REFUSED, with the same
// VG-CFG-018. Only the reason sharpens, from kind-unimplemented to
// property-unimplemented. That is checked below, because a promotion that turned a
// refusal into a pass would be the actual danger here.
test('kindHasAnyImplementation reads a leading "none", whatever an entry claims', () => {
  const dead = { kindCoverage: { 'k-dead': 'none -- no extractor, no checkpoint, no measurement' } };
  const live = { kindCoverage: { 'k-live': 'partial -- one extractor, measured' } };
  assert.equal(kindHasAnyImplementation(dead, 'k-dead'), false);
  assert.equal(kindHasAnyImplementation(live, 'k-live'), true);
  // Absent, empty and non-string lines are all "no implementation", never a pass.
  assert.equal(kindHasAnyImplementation({ kindCoverage: {} }, 'k-missing'), false);
  assert.equal(kindHasAnyImplementation({ kindCoverage: { k: '   ' } }, 'k'), false);
  assert.equal(kindHasAnyImplementation({}, 'k'), false);
});

test('no kind in the shipped catalogue is "none" today, and must-survive is implemented', () => {
  const none = Object.keys(CATALOGUE.kindCoverage).filter((k) => !kindHasAnyImplementation(CATALOGUE, k));
  assert.deepEqual(none, [], `kinds with no implementation: ${none.join(', ')}`);
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-survive'), true);
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-remain-unobservable'), true);
});

test('a property with no extractor of its own is still refused, now by property and not by kind', () => {
  const r = checkProperties([{ id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'property-unimplemented');
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

// --- asking for two checkpoints and getting one -------------------------------
//
// Added 2026-09-12, after measuring something else. `checkProperties` filtered
// the catalogue's implemented checkpoints by the ones the policy named and asked
// only whether the result was EMPTY. So a policy naming two checkpoints, one of
// which nothing observes this property at, was answered at the other one and
// reported `reachable`, complete, with no finding -- and the unanswered half
// left no trace in the record for anything downstream to notice.
//
// How it surfaced is worth keeping. Adding `process` to the checkpoint enum made
// `["pre-opt-ir","process"]` schema-VALID where it had been rejected as
// malformed, so it reached this gate for the first time and passed: exit 4 to
// exit 0, which is the one thing properties.json's `_grant` promises a
// vocabulary word cannot do. Measured against HEAD it turned out not to be the
// enum's doing -- `["pre-opt-ir","object"]`, both words legal all along, passed
// here before the change too. The widening exposed an older leniency through a
// new path. Both are closed below, and the second is the one that proves the
// first was not a regression.

test('a checkpoint the policy names and nothing answers is a finding, even when another is answered', () => {
  const e = CATALOGUE.byId.get('survive.secure-wipe');
  // the shape of the catalogue this rests on, asserted rather than assumed
  const impl = e.checkpoints.filter((c) => c.status === 'implemented' && c.extractor);
  assert.deepEqual(impl.map((c) => c.checkpoint), ['pre-opt-ir', 'after-pass']);
  assert.ok(e.checkpoints.some((c) => c.checkpoint === 'object' && c.status !== 'implemented'));

  const r = checkProperties([{ id: e.id, kind: e.kind, observeAt: ['pre-opt-ir', 'object'] }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'some-requested-checkpoints-unreachable');
  assert.equal(r.complete, false);
  assert.equal(r.usable, 0);
  assert.equal(r.findings[0].id, 'VG-CFG-018');
  // the record has to carry BOTH numbers: what was answered and what was not
  assert.deepEqual(r.entries[0].reachableCheckpoints, ['pre-opt-ir']);
  assert.deepEqual(r.entries[0].unansweredCheckpoints, ['object']);
  assert.match(r.findings[0].detail, /is not answering the policy/);
});

test('the same holds for `process`, which is the path the enum widening opened', () => {
  const r = checkProperties(
    [{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['pre-opt-ir', 'process'] }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'some-requested-checkpoints-unreachable');
  assert.equal(r.complete, false);
  assert.equal(r.findings[0].id, 'VG-CFG-018');
  assert.deepEqual(r.entries[0].unansweredCheckpoints, ['process']);
  // order must not matter: a policy is a set of questions, not a sequence
  const flipped = checkProperties(
    [{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['process', 'pre-opt-ir'] }], CATALOGUE);
  assert.equal(flipped.entries[0].verdict, 'some-requested-checkpoints-unreachable');
});

test('naming only checkpoints that ARE answered is still complete, and naming none still means all', () => {
  // The refusal must not have become universal. Both implemented checkpoints,
  // and each alone, still pass; so does omitting observeAt entirely.
  for (const observeAt of [['pre-opt-ir'], ['after-pass'], ['pre-opt-ir', 'after-pass']]) {
    const r = checkProperties([{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt }], CATALOGUE);
    assert.equal(r.entries[0].verdict, 'reachable', JSON.stringify(observeAt));
    assert.equal(r.complete, true, JSON.stringify(observeAt));
    assert.deepEqual(r.entries[0].unansweredCheckpoints, []);
  }
  const any = checkProperties([{ id: 'survive.secure-wipe', kind: 'must-survive' }], CATALOGUE);
  assert.equal(any.entries[0].verdict, 'reachable');
  assert.equal(any.complete, true);
});

test('naming no answerable checkpoint at all is still the older, narrower word', () => {
  // `no-reachable-checkpoint` and `some-requested-checkpoints-unreachable` are
  // different facts and must stay different words: nothing was answered, versus
  // some of it was.
  const r = checkProperties(
    [{ id: 'survive.secure-wipe', kind: 'must-survive', observeAt: ['object', 'ast'] }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'no-reachable-checkpoint');
  assert.deepEqual(r.entries[0].reachableCheckpoints, []);
  assert.deepEqual(r.entries[0].unansweredCheckpoints, ['object', 'ast']);
});

test('the widening still cannot turn a refusal into a pass, measured over every catalogue entry', () => {
  // The guarantee 2.20(f) and properties.json `_grant` both state. Measured over
  // every entry and every checkpoint the enum allows, in every one-and-two-word
  // combination with an implemented checkpoint -- not just the bare `(any)` ask,
  // which is what the first version of this check looked at and why it missed
  // the case above.
  const enumWords = ['invocation', 'ast', 'pre-opt-ir', 'after-pass', 'object', 'linked', 'artifact', 'process'];
  let reachable = 0;
  for (const e of CATALOGUE.byId.values()) {
    for (const a of [null, ...enumWords, ...enumWords.map((w) => ['pre-opt-ir', w])]) {
      const ask = a === null ? { id: e.id, kind: e.kind }
        : { id: e.id, kind: e.kind, observeAt: Array.isArray(a) ? a : [a] };
      const r = checkProperties([ask], CATALOGUE);
      if (r.entries[0].verdict !== 'reachable') continue;
      reachable += 1;
      // Everything that passes must be an implemented property, and every
      // checkpoint it was asked about must be one it is implemented at.
      assert.equal(CATALOGUE.byId.get(e.id).status, 'implemented', `${e.id} ${JSON.stringify(a)}`);
      assert.deepEqual(r.entries[0].unansweredCheckpoints, [], `${e.id} ${JSON.stringify(a)}`);
      if (ask.observeAt) {
        for (const c of ask.observeAt) {
          assert.ok(r.entries[0].reachableCheckpoints.includes(c), `${e.id} passed while ${c} was unanswered`);
        }
      }
    }
  }
  assert.ok(reachable > 0, 'nothing passes at all, so this check is vacuous');
});
