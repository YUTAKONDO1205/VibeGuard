// policy.fallback, without a compiler.
//
// Everything here is a decision the driver makes before it spawns anything, so
// it runs on every host. The `compiler` handed to `evaluateFallback` below is a
// path that does not exist, deliberately: if any of these cases ever reaches a
// spawn, the test fails instead of quietly measuring something.
//
// The live half — a real clang-18 that really loses the guarded call at -O2,
// really keeps it at -O0 and really still loses it at -O1 — is in
// fallback-e2e.test.mjs.

import test from 'node:test';
import assert from 'node:assert/strict';

import { normalise } from '../lib/cmdline.mjs';
import { splitDriverArgs } from '../lib/cmdline.mjs';
import {
  GRANULARITY, OBSERVATION_VERSION, PRESERVED_STATE, evaluateFallback, mustSurviveIds,
  parseObservation, readFallbackPolicy, usable,
} from '../lib/fallback.mjs';
import { countCallSites } from './observer-fixture.mjs';

// Relative and non-existent on purpose. If any case below ever reaches a spawn
// the test fails loudly instead of quietly measuring a real compiler, and the
// name carries no absolute path for a record to trip over.
const NOWHERE = 'clang-that-must-never-be-spawned';

function ctx(argv, policy, extra = {}) {
  return {
    policy,
    normalised: normalise(argv, { mode: 'c' }),
    compilerArgv: argv,
    compiler: NOWHERE,
    cwd: process.cwd(),
    root: process.cwd(),
    workDir: 'work-dir-never-written',
    observer: null,
    env: {},
    blocked: null,
    ...extra,
  };
}

const BASE_POLICY = {
  policyVersion: 'policy-v0',
  failOn: 'high',
  properties: [{ id: 'survive.authorization-check', kind: 'must-survive' }],
};

// ---------------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------------

test('an absent fallback block reads as configured:false and enabled:false', () => {
  assert.deepEqual(readFallbackPolicy({ policyVersion: 'policy-v0' }), {
    configured: false, enabled: false, profile: null, rejectIfStillLost: true,
  });
});

test('an empty fallback block is configured but not enabled — the schema default is false', () => {
  // The one that must never invert. `{}` meaning "on" would turn a policy that
  // mentions fallback into a policy that runs it.
  assert.deepEqual(readFallbackPolicy({ fallback: {} }), {
    configured: true, enabled: false, profile: null, rejectIfStillLost: true,
  });
});

test('rejectIfStillLost defaults to true and is not overwritten when stated', () => {
  assert.deepEqual(readFallbackPolicy({ fallback: { enabled: true, profile: '-O0' } }), {
    configured: true, enabled: true, profile: '-O0', rejectIfStillLost: true,
  });
  assert.deepEqual(readFallbackPolicy({ fallback: { enabled: true, profile: '-O1', rejectIfStillLost: false } }), {
    configured: true, enabled: true, profile: '-O1', rejectIfStillLost: false,
  });
});

test('enabled is true only for the boolean true, never for a truthy value', () => {
  assert.equal(readFallbackPolicy({ fallback: { enabled: 'yes' } }).enabled, false);
  assert.equal(readFallbackPolicy({ fallback: { enabled: 1 } }).enabled, false);
  assert.equal(readFallbackPolicy({ fallback: { enabled: true } }).enabled, true);
});

test('mustSurviveIds keeps policy order, drops other kinds, and de-duplicates', () => {
  const ids = mustSurviveIds({
    properties: [
      { id: 'survive.b', kind: 'must-survive' },
      { id: 'configured.ndebug', kind: 'must-be-configured' },
      { id: 'survive.a', kind: 'must-survive' },
      { id: 'survive.b', kind: 'must-survive' },
      { kind: 'must-survive' },
    ],
  });
  assert.deepEqual(ids, ['survive.b', 'survive.a']);
});

// ---------------------------------------------------------------------------
// The observer's answer, checked rather than trusted
// ---------------------------------------------------------------------------

const GOOD_RECORD = {
  observationVersion: OBSERVATION_VERSION,
  properties: [{
    id: 'survive.authorization-check',
    kind: 'must-survive',
    control: { unit: 'vg_control_sum', state: 'PRESENT' },
    historyComplete: true,
    finalState: 'LOST',
  }],
};

test('a well-formed observation parses to exactly the fields the driver reads', () => {
  const r = parseObservation(JSON.stringify(GOOD_RECORD));
  assert.equal(r.ok, true);
  assert.deepEqual(r.byId.get('survive.authorization-check'), {
    id: 'survive.authorization-check',
    kind: 'must-survive',
    finalState: 'LOST',
    historyComplete: true,
    controlState: 'PRESENT',
  });
});

test('a wrong observationVersion is refused rather than read anyway', () => {
  const r = parseObservation(JSON.stringify({ ...GOOD_RECORD, observationVersion: 'observation-v1' }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-version');
});

test('a state outside the declared six is refused by name', () => {
  const bad = structuredClone(GOOD_RECORD);
  bad.properties[0].finalState = 'PROBABLY_FINE';
  const r = parseObservation(JSON.stringify(bad));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unknown-state');
  assert.match(r.detail, /PROBABLY_FINE/);
});

test('an entry with no control is refused — a reading with no control is not a reading', () => {
  const bad = structuredClone(GOOD_RECORD);
  delete bad.properties[0].control;
  assert.deepEqual(
    (({ ok, reason }) => ({ ok, reason }))(parseObservation(JSON.stringify(bad))),
    { ok: false, reason: 'bad-control' },
  );
});

test('output that is not JSON is not an empty observation', () => {
  assert.equal(parseObservation('clang: error: no such file\n').reason, 'not-json');
});

test('usable() requires both a complete history and a surviving control', () => {
  const base = { finalState: 'PRESENT', historyComplete: true, controlState: PRESERVED_STATE };
  assert.equal(usable(base), true);
  assert.equal(usable({ ...base, historyComplete: false }), false);
  assert.equal(usable({ ...base, controlState: 'LOST' }), false);
  assert.equal(usable(undefined), false);
});

// ---------------------------------------------------------------------------
// The decisions taken before anything is spawned
// ---------------------------------------------------------------------------

test('enabled:false does nothing, says so, and adds no finding', () => {
  const r = evaluateFallback(ctx(['-c', 'guard.c', '-O2'], { ...BASE_POLICY, fallback: { enabled: false, profile: '-O0' } }));
  assert.deepEqual(r.findings, []);
  assert.equal(r.complete, true);
  assert.equal(r.record.status, 'disabled');
  assert.equal(r.record.verdict, 'disabled');
  assert.deepEqual(r.record.properties, []);
  assert.equal(r.record.candidate, null);
  assert.equal(r.record.observer.supplied, false);
});

test('a blocked build is not given a second opinion, and that is not incompleteness', () => {
  const r = evaluateFallback(ctx(
    ['-c', 'guard.c', '-O2'],
    { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
    { blocked: 'toolchain-or-policy-integrity' },
  ));
  assert.deepEqual(r.findings, []);
  assert.equal(r.complete, true);
  assert.equal(r.record.status, 'not-attempted');
  assert.equal(r.record.reason, 'toolchain-or-policy-integrity');
});

const REFUSALS = [
  {
    name: 'no profile',
    reason: 'no-profile',
    argv: ['-c', 'guard.c', '-O2'],
    policy: { ...BASE_POLICY, fallback: { enabled: true } },
  },
  {
    name: 'a profile the policy has never evaluated',
    reason: 'profile-not-in-evaluated-opt-levels',
    argv: ['-c', 'guard.c', '-O2'],
    policy: { ...BASE_POLICY, flags: { optLevels: ['-O2'] }, fallback: { enabled: true, profile: '-O0' } },
  },
  {
    name: 'no must-survive property to rescue',
    reason: 'no-must-survive-property',
    argv: ['-c', 'guard.c', '-O2'],
    policy: { policyVersion: 'policy-v0', failOn: 'high', properties: [], fallback: { enabled: true, profile: '-O0' } },
  },
  {
    name: 'no observer',
    reason: 'no-observer',
    argv: ['-c', 'guard.c', '-O2'],
    policy: { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
  },
  {
    name: 'more than one translation unit',
    reason: 'multi-source-invocation',
    argv: ['-c', 'guard.c', 'hello.c', '-O2'],
    policy: { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
    observer: 'anything',
  },
  {
    name: 'no source at all',
    reason: 'no-source-to-recompile',
    argv: ['a.o', 'b.o', '-o', 'app'],
    policy: { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
    observer: 'anything',
  },
  {
    name: 'an action that produces no IR',
    reason: 'action-produces-no-ir',
    argv: ['-fsyntax-only', 'guard.c'],
    policy: { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
    observer: 'anything',
  },
  {
    name: 'nowhere to put the work',
    reason: 'no-evidence-work-directory',
    argv: ['-c', 'guard.c', '-O2'],
    policy: { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
    workDir: null,
  },
];

for (const c of REFUSALS) {
  test(`fallback refuses to run with ${c.name}, and refusing is incomplete rather than clean`, () => {
    const { argv, policy, name, reason, ...extra } = c;
    const r = evaluateFallback(ctx(argv, policy, extra));
    assert.equal(r.record.status, 'unsupported');
    assert.equal(r.record.verdict, 'unsupported');
    assert.equal(r.record.reason, reason);
    assert.equal(r.complete, false, 'a fallback that could not run must not report a complete check');
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].id, 'VG-CFG-022');
    assert.equal(r.findings[0].severity, 'high');
  });
}

test('the refusals are ordered so that the first unmet precondition is the one reported', () => {
  // Every precondition unmet at once. The reported reason is the first in the
  // order the code checks them, not an arbitrary one — otherwise the message
  // sends the reader to fix a thing that was never the problem.
  const r = evaluateFallback(ctx(['-fsyntax-only', 'guard.c', 'hello.c'], {
    ...BASE_POLICY, flags: { optLevels: ['-O2'] }, fallback: { enabled: true },
  }, { workDir: null }));
  assert.equal(r.record.reason, 'no-profile');
});

test('every record this module produces names its granularity, and it is the translation unit', () => {
  assert.equal(GRANULARITY, 'translation-unit');
  for (const policy of [
    { ...BASE_POLICY, fallback: { enabled: false } },
    { ...BASE_POLICY, fallback: { enabled: true } },
    { ...BASE_POLICY, fallback: { enabled: true, profile: '-O0' } },
  ]) {
    const r = evaluateFallback(ctx(['-c', 'guard.c', '-O2'], policy));
    assert.equal(r.record.granularity, 'translation-unit');
  }
});

test('--vg-observer is the driver\'s own flag and never reaches the compiler', () => {
  const { own, compilerArgv } = splitDriverArgs(['-c', 'guard.c', '--vg-observer', '/o.mjs', '-O2']);
  assert.equal(own.observer, '/o.mjs');
  assert.deepEqual(compilerArgv, ['-c', 'guard.c', '-O2']);

  const joined = splitDriverArgs(['-c', 'guard.c', '--vg-observer=/o.mjs']);
  assert.equal(joined.own.observer, '/o.mjs');
  assert.deepEqual(joined.compilerArgv, ['-c', 'guard.c']);

  const missing = splitDriverArgs(['--vg-observer']);
  assert.deepEqual(missing.errors, ['--vg-observer requires a value']);
});

// ---------------------------------------------------------------------------
// The fixture observer's counting rule, so that the live tests below rest on
// something that has itself been checked
// ---------------------------------------------------------------------------

test('the fixture observer counts call sites, not the declaration that outlives them', () => {
  const ir = [
    'declare i32 @vg_authorize(i32)',
    'define i32 @open_vault(i32 %0) {',
    '  %2 = call i32 @vg_authorize(i32 %0)',
    '  ret i32 %2',
    '}',
  ].join('\n');
  assert.deepEqual(countCallSites(ir, 'vg_authorize'), { sites: 1, declares: 1 });

  // The shape that defeats a symbol grep: the call is gone, the declaration is
  // not. A naive oracle reports 1 here and blames whatever finally sweeps it.
  const swept = ['declare i32 @vg_authorize(i32)', 'define i32 @open_vault(i32 %0) {', '  ret i32 0', '}'].join('\n');
  assert.deepEqual(countCallSites(swept, 'vg_authorize'), { sites: 0, declares: 1 });
});
