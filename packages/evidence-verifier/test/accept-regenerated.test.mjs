import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { LIMITS, VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { ARTIFACT_BYTES, buildFixtureBundle, demoRecord } from './_fixture.mjs';

// ── THE LIMIT, DEMONSTRATED RATHER THAN DISCLAIMED ──────────────────────────
//
// Every other test here breaks a bundle and asserts it is caught. This one
// forges a bundle and asserts it is NOT caught, because that is the truth and
// writing it down as a passing test is the only way it stays true in the
// reader's mind. A limit stated in a README is a limit people skim; a limit
// with a test called "verifies CLEAN" next to it is one they remember.
//
// WHAT IS BEING FORGED. Take the real artefact — the same bytes, unchanged —
// and write a NEW record claiming the security property survived to the end.
// Seal it properly. Build the manifest properly. Nothing is inconsistent,
// because nothing was tampered with: the bundle was simply made by someone
// else, saying something else.
//
// WHY NO AMOUNT OF HASHING FIXES IT. Every digest in the bundle is computed
// FROM THE BUNDLE. A forger who can write the directory can compute them all.
// The only thing that would separate the real bundle from the forged one is a
// value the forger cannot compute — a signature by a key they do not hold —
// and there is none in this package. That is not an omission to be repaired by
// a stronger hash; it is what hashes are.
//
// WHAT WOULD CLOSE IT: a detached signature over the canonical text (the same
// bytes the digest is taken over, so "the signature verifies" and "the digest
// matches" cannot come apart), plus a way to distribute the public half, plus a
// decision about who holds the private half. All three are policy questions
// this package does not get to answer on its own.

test('a REGENERATED bundle verifies CLEAN — this is the limit, not a bug', () => {
  const honest = buildFixtureBundle({ prefix: 'eca-honest-' });
  let forged;
  try {
    const honestRecord = JSON.parse(readFileSync(join(honest.bundleDir, 'evidence.json'), 'utf8'));

    // The forgery: same artefact bytes, a record that says the property was
    // never lost. In the honest bundle the second checkpoint is LOST with an
    // effect count of zero.
    const lying = demoRecord();
    lying.properties[0].states[1] = {
      checkpoint: 'ir-post',
      verdict: 'PRESENT',
      state: 'PRESENT',
      effect: 1,
      control: 1,
    };
    delete lying.properties[0].firstLoss;
    lying.properties[0].fragility = { lost: 0, evaluated: 4 };

    forged = buildFixtureBundle({ prefix: 'eca-forged-', record: lying });

    const forgedRecord = JSON.parse(readFileSync(join(forged.bundleDir, 'evidence.json'), 'utf8'));
    assert.notEqual(
      forgedRecord.evidenceDigest,
      honestRecord.evidenceDigest,
      'the two records really are different records',
    );
    assert.equal(
      forgedRecord.artifact.sha256,
      honestRecord.artifact.sha256,
      'and they describe the very same artefact bytes',
    );

    const result = verifyBundle(forged.bundleDir);
    assert.equal(
      result.verdict,
      VERDICT.CLEAN,
      'the forged bundle verifies clean; nothing here can tell it from the honest one',
    );
    assert.deepEqual(result.findings, []);
  } finally {
    honest.scratch.dispose();
    forged?.scratch.dispose();
  }
});

test('the honest and the forged bundle are indistinguishable to this verifier', () => {
  const honest = buildFixtureBundle({ prefix: 'eca-h2-' });
  const lying = demoRecord();
  lying.properties[0].states[1] = {
    checkpoint: 'ir-post',
    verdict: 'PRESENT',
    state: 'PRESENT',
    effect: 1,
    control: 1,
  };
  delete lying.properties[0].firstLoss;
  lying.properties[0].fragility = { lost: 0, evaluated: 4 };
  const forged = buildFixtureBundle({ prefix: 'eca-f2-', record: lying });
  try {
    const a = verifyBundle(honest.bundleDir);
    const b = verifyBundle(forged.bundleDir);
    assert.equal(a.verdict, b.verdict);
    assert.deepEqual(a.findings, b.findings);
    assert.deepEqual(a.checked.sort(), b.checked.sort());
    assert.equal(ARTIFACT_BYTES.length > 0, true);
  } finally {
    honest.scratch.dispose();
    forged.scratch.dispose();
  }
});

test('the limit is carried in the result, not only in the prose', () => {
  const built = buildFixtureBundle({ prefix: 'eca-limit-' });
  try {
    const result = verifyBundle(built.bundleDir);
    const first = result.limits[0];
    assert.match(first, /REGENERATED/);
    assert.match(first, /internally consistent/);
    assert.match(first, /signature/);
    assert.equal(LIMITS[0], first);
  } finally {
    built.scratch.dispose();
  }
});
