// The plugin allowlist, tested from the driver's side of the boundary.
//
// WHY THIS FILE EXISTS
//
// The integrity component had a passing suite of its own, and the driver had a
// passing suite of its own, and between them nothing checked that the driver's
// answer depends on the allowlist at all. An audit made that concrete: gut the
// allowlist comparison in plugin-integrity/integrity.mjs and the driver suite
// still reported every test passing, because no test in it named
// `-fpass-plugin`, `allowedPassPlugins` or any VG-PLG rule. The one test that
// mentions a plugin flag (`-Xclang -load` in driver-e2e) is asserting the
// FORBIDDEN-FLAG exit, and passes identically whether or not a plugin is ever
// examined.
//
// So the claim "an unauthorised plugin is refused" was, from this side, untested.
// These are the tests that fail when it stops being true.
//
// WHY THEY NEED NO COMPILER
//
// checkPlugins does two separable things: it decides about the plugins named on
// a command line (resolve, digest, compare against the policy), and it captures
// the pass pipeline by running a shadow invocation. Only the second needs a real
// clang. Every assertion here is about the first, so these run everywhere the
// driver's own code runs — including the Windows host, where the live-build
// tests skip. An invocation with no source input never reaches the shadow run,
// which is what keeps `argv[0]` from being executed.
//
// The pipeline's absence is itself asserted, once, so that the day someone makes
// this file compile something the change is visible rather than silent.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkPlugins } from '../plugin-integrity/integrity.mjs';

/** A file with known bytes, standing in for a compiled plugin. */
function makePlugin(dir, name, bytes) {
  const path = join(dir, name);
  writeFileSync(path, bytes);
  return { path, name, sha256: createHash('sha256').update(bytes).digest('hex') };
}

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), 'vg-plg-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A policy that authorises exactly the given pass plugins. */
function policyAllowing(...plugins) {
  return {
    policyVersion: 'policy-v0',
    failOn: 'high',
    toolchain: {
      allowedPassPlugins: plugins.map((p) => ({ name: p.name, sha256: p.sha256 })),
      allowedFrontendPlugins: [],
    },
  };
}

const ids = (r) => r.findings.map((f) => f.id);

// ── The pair the audit found missing ────────────────────────────────────────
//
// Positive and negative control over the SAME fixture: the only difference
// between them is whether the policy lists the plugin. A mutant that drops the
// allowlist comparison, or that returns no findings at all, passes the first and
// fails the second. That asymmetry is the whole point of writing them together.

test('an authorised plugin produces no finding', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libObserver.so', 'authorised bytes');

  const r = await checkPlugins({
    policy: policyAllowing(plug),
    argv: ['clang-18', `-fpass-plugin=${plug.path}`, '-c'],
    env: {},
  });

  assert.deepEqual(ids(r), [], `expected a clean verdict, got ${JSON.stringify(r.findings, null, 1)}`);
});

test('a plugin the policy does not list is VG-PLG-002', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libMarker.so', 'unlisted bytes');

  const r = await checkPlugins({
    policy: policyAllowing(), // lists nothing
    argv: ['clang-18', `-fpass-plugin=${plug.path}`, '-c'],
    env: {},
  });

  assert.deepEqual(ids(r), ['VG-PLG-002']);
  assert.equal(r.findings[0].severity, 'high');
  // The digest is reported even though the plugin is refused: "we did not look"
  // and "we looked and it is not listed" are different answers.
  assert.match(r.findings[0].detail, new RegExp(plug.sha256));
  // interfaces.md section 5: no absolute path reaches a record.
  assert.ok(!r.findings[0].detail.includes(dir), 'the record must not carry the absolute path');
});

// ── The other two verdicts ─────────────────────────────────────────────────

test('a listed plugin whose bytes changed is VG-PLG-003, and critical', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libObserver.so', 'the bytes that were vouched for');
  const policy = policyAllowing(plug);

  // Same name, same path, different contents — the substitution the digest exists to catch.
  writeFileSync(plug.path, 'different bytes entirely');

  const r = await checkPlugins({ policy, argv: ['clang-18', `-fpass-plugin=${plug.path}`, '-c'], env: {} });

  assert.deepEqual(ids(r), ['VG-PLG-003']);
  assert.equal(r.findings[0].severity, 'critical', 'a substituted plugin outranks an unlisted one');
});

test('a plugin that cannot be read is VG-PLG-001 and makes the check incomplete', async (t) => {
  const dir = fixture(t);

  const r = await checkPlugins({
    policy: policyAllowing(),
    argv: ['clang-18', `-fpass-plugin=${join(dir, 'libNotThere.so')}`, '-c'],
    env: {},
  });

  assert.deepEqual(ids(r), ['VG-PLG-001']);
  assert.equal(r.complete, false, 'an unresolvable load is not a clean check');
});

// ── The spellings a one-flag checker walks past ────────────────────────────

test('-Xclang -fpass-plugin= is the same load as the bare spelling', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libMarker.so', 'unlisted bytes');

  const r = await checkPlugins({
    policy: policyAllowing(),
    argv: ['clang-18', '-Xclang', `-fpass-plugin=${plug.path}`, '-c'],
    env: {},
  });

  assert.deepEqual(ids(r), ['VG-PLG-002']);
  assert.match(r.findings[0].detail, /-Xclang/);
});

test('a frontend plugin is governed by the frontend list, not the pass list', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libFront.so', 'frontend bytes');

  // Listed as a PASS plugin, loaded into the FRONTEND slot: the two lists are
  // different slots, and crossing them must not authorise anything.
  const r = await checkPlugins({
    policy: policyAllowing(plug),
    argv: ['clang-18', '-Xclang', '-load', '-Xclang', plug.path, '-c'],
    env: {},
  });

  assert.deepEqual(ids(r), ['VG-PLG-002']);
  assert.match(r.findings[0].detail, /allowedFrontendPlugins/);
});

test('a plugin injected through the environment is still checked', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libMarker.so', 'unlisted bytes');

  // Nothing in argv names a plugin. CCC_OVERRIDE_OPTIONS appends one.
  const r = await checkPlugins({
    policy: policyAllowing(),
    argv: ['clang-18', '-c'],
    env: { CCC_OVERRIDE_OPTIONS: `+-fpass-plugin=${plug.path}` },
  });

  assert.deepEqual(ids(r), ['VG-PLG-002']);
  assert.match(r.findings[0].detail, /CCC_OVERRIDE_OPTIONS/);
});

test('an environment that rewrites arguments makes the check incomplete rather than clean', async (t) => {
  fixture(t);

  const r = await checkPlugins({
    policy: policyAllowing(),
    argv: ['clang-18', '-c'],
    // A substitution operator: what it produces cannot be known without
    // replaying the driver's own edit.
    env: { CCC_OVERRIDE_OPTIONS: 's/-O0/-O2/' },
  });

  assert.deepEqual(ids(r), [], 'an opaque edit is not itself a finding');
  assert.equal(r.complete, false, 'but it is not a clean check either');
});

// ── The boundary this file deliberately does not cross ─────────────────────

test('no pipeline is captured here, and that is reported rather than assumed', async (t) => {
  const dir = fixture(t);
  const plug = makePlugin(dir, 'libObserver.so', 'authorised bytes');

  const r = await checkPlugins({
    policy: policyAllowing(plug),
    argv: ['clang-18', `-fpass-plugin=${plug.path}`, '-c'],
    env: {},
  });

  assert.equal(r.pipeline.available, false);
  assert.match(r.pipeline.reason, /source input/);
  assert.equal(r.complete, false, 'a pipeline that was not captured is not a pipeline that agreed');
});
