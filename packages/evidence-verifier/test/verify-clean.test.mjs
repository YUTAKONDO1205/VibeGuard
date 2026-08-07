import assert from 'node:assert/strict';
import { test } from 'node:test';

import { LIMITS, VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { buildFixtureBundle } from './_fixture.mjs';

// ── The negative direction ──────────────────────────────────────────────────
//
// Every other test in this package breaks something and asserts it is caught.
// Without this one they would all pass against a verifier that rejects
// everything, which is a false-positive factory with a perfect detection rate.

test('an untouched bundle verifies CLEAN, with nothing left unchecked', () => {
  const built = buildFixtureBundle({ prefix: 'eca-clean-' });
  try {
    const result = verifyBundle(built.bundleDir);
    assert.deepEqual(result.findings, [], JSON.stringify(result.findings, null, 2));
    assert.deepEqual(
      result.unchecked,
      [],
      `unchecked must be empty or the verdict would be INCOMPLETE: ${result.unchecked.join(', ')}`,
    );
    assert.equal(result.verdict, VERDICT.CLEAN);
    assert.equal(result.evidenceDigest, built.evidenceDigest);
    assert.equal(result.bundleDigest, built.bundleDigest);
  } finally {
    built.scratch.dispose();
  }
});

test('the clean verdict names what it did check', () => {
  const built = buildFixtureBundle({ prefix: 'eca-checked-' });
  try {
    const { checked } = verifyBundle(built.bundleDir);
    for (const name of [
      'bundleDigest',
      'contextDigest',
      'manifest.evidenceDigest',
      'files[]',
      'evidenceDigest',
      'manifest.binds.evidenceDigest',
      'artifact.sha256',
      'manifest.binds.artifact',
      'oracle.controls',
      'properties.states',
    ]) {
      assert.ok(checked.includes(name), `${name} should have been checked; got ${checked.join(', ')}`);
    }
  } finally {
    built.scratch.dispose();
  }
});

test('a clean run still states what it cannot see', () => {
  const built = buildFixtureBundle({ prefix: 'eca-limits-' });
  try {
    const result = verifyBundle(built.bundleDir);
    assert.equal(result.limits, LIMITS);
    assert.ok(result.limits.length >= 3);
    assert.match(result.limits[0], /REGENERATED/);
    assert.match(result.limits[0], /signature/);
  } finally {
    built.scratch.dispose();
  }
});

test('a bundle whose artefact is absent is INCOMPLETE, never CLEAN', () => {
  // A record naming no artefact has nothing to be checked against. "We did not
  // look" and "it is fine" are different answers and this is the one that keeps
  // them apart.
  const built = buildFixtureBundle({ prefix: 'eca-noart-', artifact: null });
  try {
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    assert.ok(result.unchecked.length > 0);
  } finally {
    built.scratch.dispose();
  }
});
