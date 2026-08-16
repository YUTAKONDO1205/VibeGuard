// policy.fallback against a real clang-18.
//
// The fixture is not staged. `guard.c` really does lose the `@vg_authorize`
// call site at -O2 because clang inlines the static callee, really does keep it
// at -O0, and really does still lose it at -O1 — the first test in this file
// measures all three with plain clang before any of the driver tests run, so
// that the success control and the reject control below are known to be
// measuring a difference that exists.
//
// Each claim has its opposite beside it:
//   restored   <-> still lost          (profile -O0 vs -O1, same fixture)
//   fallback fires <-> fallback does not fire   (lost at -O2 vs present at -O0)
//   enabled    <-> disabled            (identical exit code and findings)
//   opted in   <-> never mentioned     (identical evidence digest)

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import {
  OBSERVER_FIXTURE, evidenceRecords, liveBuildSkipReason, makeFixture, runClang, runDriver, sha256File,
} from './helpers.mjs';
import { countCallSites } from './observer-fixture.mjs';

const skip = liveBuildSkipReason();

const PROP = 'survive.authorization-check';

/** A policy that declares the property and opts into fallback. */
function policyFor({ profile, optLevels, failOn = 'critical', enabled = true, rejectIfStillLost }) {
  const fallback = { enabled };
  if (profile !== undefined) fallback.profile = profile;
  if (rejectIfStillLost !== undefined) fallback.rejectIfStillLost = rejectIfStillLost;
  return {
    failOn,
    flags: { required: [], forbidden: ['-fno-stack-protector'], optLevels },
    // The catalogue defines this id as must-survive with an implemented
    // extractor, so §4b passes and the fallback step is actually reached.
    properties: [{ id: PROP, kind: 'must-survive' }],
    fallback,
  };
}

function observerEnv(extra = {}) {
  return { VG_TEST_OBSERVER_PROPERTY: PROP, ...extra };
}

function fallbackOf(fx) {
  const recs = evidenceRecords(fx.evidence);
  assert.equal(recs.length, 1, `expected exactly one evidence record, got ${recs.length}`);
  return recs[0].record;
}

function findingsById(record) {
  const m = new Map();
  for (const f of record.findings) m.set(f.id, f);
  return m;
}

// ---------------------------------------------------------------------------
// The fixture measures something. Without this the two controls below could
// both be true of a file where nothing ever changes.
// ---------------------------------------------------------------------------

test('the fixture really loses the guarded call at -O2, keeps it at -O0, and still loses it at -O1', { skip }, (t) => {
  const fx = makeFixture('fb-ground-truth');
  t.after(fx.cleanup);

  const at = (level) => {
    const out = join(fx.src, `g${level}.ll`);
    const r = runClang(['-c', 'guard.c', level, '-emit-llvm', '-S', '-o', out], { cwd: fx.src });
    assert.equal(r.status, 0, r.stderr);
    const ir = readFileSync(out, 'utf8');
    return {
      guard: countCallSites(ir, 'vg_authorize').sites,
      control: countCallSites(ir, 'vg_control_sum').sites,
    };
  };

  assert.deepEqual(at('-O0'), { guard: 1, control: 1 });
  assert.deepEqual(at('-O1'), { guard: 0, control: 1 });
  assert.deepEqual(at('-O2'), { guard: 0, control: 1 });
});

// ---------------------------------------------------------------------------
// Success control: lost at -O2, restored by the approved -O0 recompile
// ---------------------------------------------------------------------------

test('a property lost at -O2 and restored at -O0 becomes a warning and a recorded candidate', { skip }, (t) => {
  const fx = makeFixture('fb-restored', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  // VG-CFG-020 is `high` when the fallback restored the property, and this
  // policy's failOn is `critical`: the threshold decides, not the driver.
  assert.equal(r.status, 0, r.stderr);

  const record = fallbackOf(fx);
  const fb = record.checks.fallback;
  assert.equal(fb.status, 'observed');
  assert.equal(fb.verdict, 'restored');
  assert.equal(fb.granularity, 'translation-unit');
  assert.equal(fb.profile, '-O0');
  assert.equal(fb.unit, 'guard.c');
  assert.equal(fb.rejectIfStillLost, true);
  assert.deepEqual(fb.counts, { lost: 1, preserved: 0, requested: 1, restored: 1, stillLost: 0, unusable: 0 });
  assert.deepEqual(fb.properties, [{ after: 'PRESENT', before: 'LOST', id: PROP, verdict: 'restored' }]);
  assert.equal(fb.complete, true);
  assert.equal(fb.observer.supplied, true);
  assert.equal(fb.observer.sha256, sha256File(OBSERVER_FIXTURE));

  // The candidate is a real file with real bytes, and it is not the artefact
  // the caller asked for.
  assert.equal(fb.candidate.profile, '-O0');
  assert.match(fb.candidate.sha256, /^[0-9a-f]{64}$/);
  assert.ok(fb.candidate.bytes > 0);
  const candidateAbs = join(fx.src, fb.candidate.path);
  assert.equal(existsSync(candidateAbs), true, 'the record names a candidate that is on disk');
  assert.equal(sha256File(candidateAbs), fb.candidate.sha256);

  const byId = findingsById(record);
  assert.equal(byId.get('VG-CFG-020').severity, 'high');
  assert.equal(byId.has('VG-CFG-021'), false);
  assert.equal(byId.has('VG-CFG-022'), false);

  // Non-invasiveness is untouched: the shipping artefact is still byte-for-byte
  // what plain clang emits for the caller's own command line.
  assert.equal(existsSync(join(fx.src, 'out.o')), true);
  const mine = sha256File(join(fx.src, 'out.o'));
  rmSync(join(fx.src, 'out.o'));
  assert.equal(runClang(['-c', 'guard.c', '-O2', '-o', 'out.o'], { cwd: fx.src }).status, 0);
  assert.equal(mine, sha256File(join(fx.src, 'out.o')));
  assert.notEqual(mine, fb.candidate.sha256, 'the candidate is a different build, or it rescued nothing');
});

// ---------------------------------------------------------------------------
// Reject control: the fallback ran, did not restore, and did not let it through
// ---------------------------------------------------------------------------

test('a property still lost after the -O1 recompile is rejected, with no candidate kept', { skip }, (t) => {
  const fx = makeFixture('fb-reject', policyFor({ profile: '-O1', optLevels: ['-O2', '-O1'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(r.status, 2, r.stderr);
  assert.equal(existsSync(join(fx.src, 'out.o')), false, 'fail-closed: a rejected build produces nothing to ship');

  const record = fallbackOf(fx);
  const fb = record.checks.fallback;
  assert.equal(fb.verdict, 'reject');
  assert.equal(fb.reason, 'still-lost');
  assert.deepEqual(fb.counts, { lost: 1, preserved: 0, requested: 1, restored: 0, stillLost: 1, unusable: 0 });
  assert.deepEqual(fb.properties, [{ after: 'LOST', before: 'LOST', id: PROP, verdict: 'still-lost' }]);
  assert.equal(fb.candidate, null, 'an artefact that does not preserve the property is not a candidate');

  const byId = findingsById(record);
  assert.equal(byId.get('VG-CFG-020').severity, 'critical');
  assert.equal(byId.get('VG-CFG-021').severity, 'critical');
});

test('rejectIfStillLost:false is not a way through — the build is still exit 2', { skip }, (t) => {
  // The whole point of the reject control: there must be no setting of
  // `fallback` that turns a lost must-survive property into a pass. This is the
  // most permissive setting the schema allows, at the highest failOn it allows.
  const fx = makeFixture('fb-reject-soft', policyFor({
    profile: '-O1', optLevels: ['-O2', '-O1'], rejectIfStillLost: false,
  }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(r.status, 2, r.stderr);
  assert.equal(existsSync(join(fx.src, 'out.o')), false);

  const record = fallbackOf(fx);
  assert.equal(record.checks.fallback.rejectIfStillLost, false);
  assert.equal(record.checks.fallback.candidate, null);
  const byId = findingsById(record);
  // The switch moves VG-CFG-021 down a rung and leaves VG-CFG-020 where it is.
  assert.equal(byId.get('VG-CFG-021').severity, 'high');
  assert.equal(byId.get('VG-CFG-020').severity, 'critical');
});

// ---------------------------------------------------------------------------
// The fallback does not fire when nothing was lost
// ---------------------------------------------------------------------------

test('a property that is present at the shipping level recompiles nothing', { skip }, (t) => {
  const fx = makeFixture('fb-no-loss', policyFor({ profile: '-O0', optLevels: ['-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O0', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(r.status, 0, r.stderr);

  const record = fallbackOf(fx);
  const fb = record.checks.fallback;
  assert.equal(fb.verdict, 'no-loss');
  assert.deepEqual(fb.counts, { lost: 0, preserved: 1, requested: 1, restored: 0, stillLost: 0, unusable: 0 });
  assert.deepEqual(fb.properties, [{ after: null, before: 'PRESENT', id: PROP, verdict: 'preserved' }]);
  assert.equal(fb.candidate, null);
  assert.deepEqual(record.findings, []);
  assert.equal(existsSync(join(fx.src, 'out.o')), true);
});

// ---------------------------------------------------------------------------
// The default path, unmoved
// ---------------------------------------------------------------------------

test('a policy that never mentions fallback gets the same record whether or not --vg-observer is passed', { skip }, (t) => {
  const fx = makeFixture('fb-absent');
  t.after(fx.cleanup);

  const a = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o'], { cwd: fx.src, env: observerEnv() });
  assert.equal(a.status, 0, a.stderr);
  const first = evidenceRecords(fx.evidence);
  assert.equal(first.length, 1);
  assert.equal(Object.prototype.hasOwnProperty.call(first[0].record.checks, 'fallback'), false,
    'an unasked-for feature must not add a key to everyone else\'s record');

  const b = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(b.status, 0, b.stderr);
  // Content-addressed: one file means the two runs digested identically, so the
  // flag on its own changed nothing that the evidence covers.
  const after = evidenceRecords(fx.evidence);
  assert.equal(after.length, 1);
  assert.equal(after[0].record.evidenceDigest, first[0].record.evidenceDigest);
});

test('enabled:false leaves the exit code and the findings exactly as they were', { skip }, (t) => {
  // Same command line, same losing configuration, same observer available. The
  // only difference between the two fixtures is the fallback block, and with
  // `enabled: false` it must make no difference at all.
  const off = makeFixture('fb-off', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'], enabled: false }));
  const none = makeFixture('fb-none', {
    failOn: 'critical',
    flags: { required: [], forbidden: ['-fno-stack-protector'], optLevels: ['-O2', '-O0'] },
    properties: [{ id: PROP, kind: 'must-survive' }],
  });
  t.after(off.cleanup);
  t.after(none.cleanup);

  const argv = ['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE];
  const a = runDriver(argv, { cwd: off.src, env: observerEnv() });
  const b = runDriver(argv, { cwd: none.src, env: observerEnv() });
  assert.equal(a.status, 0, a.stderr);
  assert.equal(b.status, a.status);

  const withBlock = fallbackOf(off);
  const without = fallbackOf(none);
  assert.deepEqual(withBlock.findings, without.findings);
  assert.deepEqual(withBlock.findings, []);
  assert.deepEqual(withBlock.build.artifacts.map((x) => x.sha256), without.build.artifacts.map((x) => x.sha256));

  // The disabled block is recorded as disabled, and nothing was observed.
  assert.equal(withBlock.checks.fallback.status, 'disabled');
  assert.equal(withBlock.checks.fallback.verdict, 'disabled');
  assert.deepEqual(withBlock.checks.fallback.properties, []);
  assert.equal(withBlock.checks.fallback.observer.supplied, false);
  assert.equal(Object.prototype.hasOwnProperty.call(without.checks, 'fallback'), false);
});

// ---------------------------------------------------------------------------
// UNSUPPORTED: enabled and unable, which is never a pass
// ---------------------------------------------------------------------------

test('fallback enabled with no observer is exit 3, not a clean build', { skip }, (t) => {
  const fx = makeFixture('fb-no-observer', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o'], { cwd: fx.src, env: observerEnv() });
  assert.equal(r.status, 3, r.stderr);

  const record = fallbackOf(fx);
  assert.equal(record.exitReason, 'checks-incomplete');
  assert.equal(record.checks.fallback.status, 'unsupported');
  assert.equal(record.checks.fallback.reason, 'no-observer');
  assert.equal(record.checks.fallback.complete, false);
  assert.equal(findingsById(record).get('VG-CFG-022').severity, 'high');
});

test('a multi-source invocation is refused rather than recompiled wholesale', { skip }, (t) => {
  const fx = makeFixture('fb-multi', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', 'hello.c', '-O2', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(r.status, 3, r.stderr);
  const fb = fallbackOf(fx).checks.fallback;
  assert.equal(fb.reason, 'multi-source-invocation');
  assert.equal(fb.granularity, 'translation-unit');
});

test('an observer whose own control did not survive is not quoted as a reading', { skip }, (t) => {
  // The mutation control for the control check: the same run that reports
  // `restored` above reports nothing usable when the instrument says it broke.
  const fx = makeFixture('fb-broken-control', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv({ VG_TEST_OBSERVER_MODE: 'control-broken' }),
  });
  assert.equal(r.status, 3, r.stderr);

  const record = fallbackOf(fx);
  const fb = record.checks.fallback;
  assert.equal(fb.verdict, 'unusable');
  assert.deepEqual(fb.counts, { lost: 0, preserved: 0, requested: 1, restored: 0, stillLost: 0, unusable: 1 });
  assert.deepEqual(fb.properties, [{ after: null, before: 'LOST', id: PROP, verdict: 'unusable' }]);
  assert.equal(fb.candidate, null);
  assert.equal(findingsById(record).has('VG-CFG-020'), false, 'an unreadable instrument is not a finding about the program');
  assert.equal(findingsById(record).get('VG-CFG-022').severity, 'high');
});

test('an observer that writes something other than an observation record is refused', { skip }, (t) => {
  const fx = makeFixture('fb-bad-record', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv({ VG_TEST_OBSERVER_MODE: 'not-json' }),
  });
  assert.equal(r.status, 3, r.stderr);
  const fb = fallbackOf(fx).checks.fallback;
  assert.equal(fb.status, 'unsupported');
  assert.equal(fb.reason, 'observer-record-not-json');
});

test('an observer that exits non-zero is a missing verdict, not an absent loss', { skip }, (t) => {
  const fx = makeFixture('fb-observer-fails', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv({ VG_TEST_OBSERVER_MODE: 'nonzero' }),
  });
  assert.equal(r.status, 3, r.stderr);
  assert.equal(fallbackOf(fx).checks.fallback.reason, 'observer-failed');
});

test('a profile the policy has not evaluated is refused, even though the file is right there', { skip }, (t) => {
  const fx = makeFixture('fb-unevaluated', policyFor({ profile: '-O0', optLevels: ['-O2'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv(),
  });
  assert.equal(r.status, 3, r.stderr);
  assert.equal(fallbackOf(fx).checks.fallback.reason, 'profile-not-in-evaluated-opt-levels');
});

test('an observer that names a path in its diagnostics still leaves a record behind', { skip }, async (t) => {
  // Without the redaction in fallback.mjs this run writes NO record at all: the
  // path reaches a finding, the finding reaches the record, and the driver's own
  // absolute-path gate refuses the whole file — so the one artefact that could
  // have explained the failure is the one thing that does not get written.
  const fx = makeFixture('fb-observer-path', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const r = runDriver(['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE], {
    cwd: fx.src, env: observerEnv({ VG_TEST_OBSERVER_MODE: 'stderr-path' }),
  });
  assert.equal(r.status, 3, r.stderr);

  const record = fallbackOf(fx);
  assert.equal(record.checks.fallback.reason, 'observer-failed');
  const detail = findingsById(record).get('VG-CFG-022').detail;
  assert.equal(detail.includes('/opt/vg'), false, 'the observer\'s path must not be quoted into the record');
  assert.match(detail, /<path>/);

  // Checked with the evidence component's own gate, not the driver's.
  const { findAbsolutePaths } = await import('../../evidence/paths.mjs');
  assert.deepEqual(findAbsolutePaths(record, { mode: 'strict' }), []);
});

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

test('two identical fallback runs write one record, so nothing volatile leaked into it', { skip }, (t) => {
  const fx = makeFixture('fb-determinism', policyFor({ profile: '-O0', optLevels: ['-O2', '-O0'] }));
  t.after(fx.cleanup);

  const argv = ['-c', 'guard.c', '-O2', '-o', 'out.o', '--vg-observer', OBSERVER_FIXTURE];
  assert.equal(runDriver(argv, { cwd: fx.src, env: observerEnv() }).status, 0);
  const first = evidenceRecords(fx.evidence);
  assert.equal(first.length, 1);
  assert.equal(runDriver(argv, { cwd: fx.src, env: observerEnv() }).status, 0);

  const after = evidenceRecords(fx.evidence);
  assert.equal(after.length, 1, 'the fallback block must not carry a duration, a path or a clock');
  assert.equal(after[0].record.evidenceDigest, first[0].record.evidenceDigest);
});
