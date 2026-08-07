import test from 'node:test';
import assert from 'node:assert/strict';

import { normalise } from '../lib/cmdline.mjs';
import { checkFlags, tokenMatches } from '../lib/flags.mjs';
import { CFG } from '../lib/findings.mjs';

const base = { policyVersion: 'policy-v0', failOn: 'high' };

test('matching is exact unless the pattern asks for more', () => {
  assert.equal(tokenMatches('-O2', '-O2'), true);
  // The failure a substring check makes: a different flag that shares a prefix.
  assert.equal(tokenMatches('-fstack-protector-strong', '-fstack-protector'), false);
  assert.equal(tokenMatches('-fstack-protector-strong', '-fstack-protector*'), true);
  assert.equal(tokenMatches('-fsanitize=address', '-fsanitize='), true);
  assert.equal(tokenMatches('-fsanitize', '-fsanitize='), false);
  // And the failure it makes in the other direction: a longer flag matching a shorter pattern.
  assert.equal(tokenMatches('-O2x', '-O2'), false);
});

test('a forbidden flag is VG-CFG-002', () => {
  const n = normalise(['a.c', '-fno-stack-protector']);
  const { findings } = checkFlags(n, { ...base, flags: { forbidden: ['-fno-stack-protector'] } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.FORBIDDEN_FLAG);
  assert.equal(findings[0].severity, 'high');
  assert.equal(findings[0].where.kind, 'invocation');
});

test('a forbidden flag hidden behind -Xclang is still found, and the finding says so', () => {
  const n = normalise(['a.c', '-Xclang', '-load', '-Xclang', 'libEvil.so']);
  const { findings } = checkFlags(n, { ...base, flags: { forbidden: ['-load'] } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.FORBIDDEN_FLAG);
  assert.match(findings[0].detail, /-Xclang/);
});

test('a missing required flag is VG-CFG-004', () => {
  const n = normalise(['a.c']);
  const { findings } = checkFlags(n, { ...base, flags: { required: ['-fstack-protector-strong'] } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.REQUIRED_FLAG_MISSING);
});

test('a required flag that is present produces nothing', () => {
  const n = normalise(['a.c', '-fstack-protector-strong']);
  const { findings, detail } = checkFlags(n, { ...base, flags: { required: ['-fstack-protector-strong'] } });
  assert.equal(findings.length, 0);
  assert.deepEqual(detail.required, [{ pattern: '-fstack-protector-strong', present: true }]);
});

test('an optimisation level outside the evaluated set is VG-CFG-003', () => {
  const n = normalise(['a.c', '-O3']);
  const { findings } = checkFlags(n, { ...base, flags: { optLevels: ['-O1', '-O2'] } });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.OPT_LEVEL_NOT_EVALUATED);
  assert.equal(findings[0].severity, 'medium');
});

test('no -O at all means -O0, which a policy that lists only -O2 has not evaluated', () => {
  const n = normalise(['a.c']);
  const { findings, detail } = checkFlags(n, { ...base, flags: { optLevels: ['-O2'] } });
  assert.equal(detail.optLevel.effective, '-O0');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.OPT_LEVEL_NOT_EVALUATED);
});

test('an absent flags block constrains nothing', () => {
  const n = normalise(['a.c', '-O3', '-fno-stack-protector']);
  const { findings } = checkFlags(n, base);
  assert.equal(findings.length, 0);
});

// ── The command line is argv edited by the environment ─────────────────────
//
// clang rewrites its own argument list from CCC_OVERRIDE_OPTIONS before it does
// anything else. A flag check that reads argv alone answers about a command
// line that was not compiled — measured: `CCC_OVERRIDE_OPTIONS='+-O0'` on a
// `-O2` invocation produced an object byte-identical to a plain `-O0` build
// while the record said `-O2` and filed no finding at all. These cases exist so
// that regression is visible as a red test rather than as a quiet pass.

test('a forbidden flag appended from the environment is still forbidden', () => {
  const n = normalise(['a.c', '-O2']);
  const policy = { ...base, flags: { forbidden: ['-fno-stack-protector'] } };
  assert.equal(checkFlags(n, policy).findings.length, 0, 'argv alone is clean');
  const { findings, complete } = checkFlags(n, policy, {
    CCC_OVERRIDE_OPTIONS: '+-fno-stack-protector',
  });
  assert.equal(complete, true);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.FORBIDDEN_FLAG);
});

test('the prepend operator is covered too, not just append', () => {
  const n = normalise(['a.c', '-O2']);
  const { findings } = checkFlags(n, { ...base, flags: { forbidden: ['-load'] } }, {
    CCC_OVERRIDE_OPTIONS: '^-load',
  });
  assert.equal(findings.length, 1);
});

test('an appended -O beats the one in argv, because clang takes the last', () => {
  const n = normalise(['a.c', '-O2']);
  const policy = { ...base, flags: { optLevels: ['-O2'] } };
  assert.equal(checkFlags(n, policy).detail.optLevel.effective, '-O2');

  const { findings, detail } = checkFlags(n, policy, { CCC_OVERRIDE_OPTIONS: '+-O0' });
  assert.equal(detail.optLevel.effective, '-O0');
  assert.equal(detail.optLevel.fromEnvironment, true);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.OPT_LEVEL_NOT_EVALUATED);
});

test('a prepended -O loses to argv, for the same reason', () => {
  const n = normalise(['a.c', '-O2']);
  const { detail } = checkFlags(n, { ...base, flags: { optLevels: ['-O2'] } }, {
    CCC_OVERRIDE_OPTIONS: '^-O0',
  });
  assert.equal(detail.optLevel.effective, '-O2');
});

test('a rewrite operator makes the check incomplete, not a finding about the build', () => {
  const n = normalise(['a.c', '-O2']);
  const { findings, complete, detail } = checkFlags(n, { ...base, flags: { forbidden: ['-load'] } }, {
    CCC_OVERRIDE_OPTIONS: 's/-O2/-O0/',
  });
  assert.equal(complete, false, 'an unreplayable edit is not a completed check');
  assert.equal(detail.environmentOverride.recoverable, false);
  // Reported, but below any threshold that would call it a violation: we did
  // not find something wrong, we found that we cannot tell.
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, CFG.COMMAND_LINE_UNRECOVERABLE);
  assert.equal(findings[0].severity, 'low');
});

test('an unrecognised operator is unrecoverable rather than ignored', () => {
  const n = normalise(['a.c']);
  const { complete } = checkFlags(n, base, { CCC_OVERRIDE_OPTIONS: '!-O0' });
  assert.equal(complete, false);
});

test('an empty or absent override changes nothing', () => {
  const n = normalise(['a.c', '-O2']);
  for (const env of [{}, { CCC_OVERRIDE_OPTIONS: '' }, { CCC_OVERRIDE_OPTIONS: '   ' }]) {
    const { findings, complete, detail } = checkFlags(n, { ...base, flags: { optLevels: ['-O2'] } }, env);
    assert.equal(complete, true);
    assert.equal(findings.length, 0);
    assert.equal(detail.environmentOverride.present, false);
  }
});
