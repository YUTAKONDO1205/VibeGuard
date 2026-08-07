import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { rederiveDigest, sha256Hex } from '../src/rederive.mjs';
import { VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { ARTIFACT_BYTES, buildFixtureBundle } from './_fixture.mjs';

// The record says the artefact hashes to X. The bytes hash to Y. That is a
// disagreement between the artefact and the evidence that describes it, and it
// is the one check that makes the pair an EVIDENCE-CARRYING artefact rather
// than an artefact next to a file.
//
// There are two ways to arrive at it and both are covered: change the bytes, or
// change the claim. They must both be caught, and for the second one the
// manifest has to be re-sealed first — otherwise the test would be catching the
// stale manifest rather than the false claim, and would pass against a verifier
// that never compared the artefact at all.

/** Re-seal the manifest around whatever evidence.json currently says. */
function resealManifest(bundleDir) {
  const manifestPath = join(bundleDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const record = JSON.parse(readFileSync(join(bundleDir, 'evidence.json'), 'utf8'));

  for (const entry of manifest.files) {
    const bytes = readFileSync(join(bundleDir, entry.path));
    entry.bytes = bytes.length;
    entry.sha256 = sha256Hex(bytes);
  }
  manifest.evidenceDigest = record.evidenceDigest;
  manifest.binds.evidenceDigest = record.evidenceDigest;
  manifest.binds.artifact = { path: record.artifact.path, sha256: record.artifact.sha256 };
  delete manifest.bundleDigest;
  manifest.bundleDigest = rederiveDigest(manifest, { selfKey: 'bundleDigest' });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return manifest;
}

test("the artefact's bytes not matching the record is CRITICAL", () => {
  const built = buildFixtureBundle({ prefix: 'eca-artdig-' });
  const file = join(built.bundleDir, 'artifact', 'wipe.o');
  try {
    // Same length, different content: this is a digest question, not a length
    // question, and the two must not be conflated.
    const swapped = Buffer.from(ARTIFACT_BYTES);
    swapped[0] = swapped[0] === 0x41 ? 0x42 : 0x41;
    assert.equal(swapped.length, ARTIFACT_BYTES.length);
    writeFileSync(file, swapped);

    const result = verifyBundle(built.bundleDir);
    const critical = result.findings.filter((f) => f.id === 'VG-ART-061');
    assert.equal(critical.length, 1, JSON.stringify(result.findings.map((f) => f.id)));
    assert.equal(critical[0].severity, 'critical');
    assert.match(critical[0].detail, /the record says/);
    assert.match(critical[0].detail, /the bytes hash to/);
    assert.equal(critical[0].where.path, 'artifact/wipe.o');
  } finally {
    built.scratch.dispose();
  }
});

test('a FALSE CLAIM in the record is caught even when everything else is re-sealed', () => {
  const built = buildFixtureBundle({ prefix: 'eca-artclaim-' });
  const recordPath = join(built.bundleDir, 'evidence.json');
  try {
    // Change what the record CLAIMS about the artefact, re-seal the record's
    // own digest, then re-seal the manifest around it. Every internal digest
    // now agrees; the only thing that does not is the artefact on disk.
    const record = JSON.parse(readFileSync(recordPath, 'utf8'));
    record.artifact.sha256 = 'a'.repeat(64);
    delete record.evidenceDigest;
    record.evidenceDigest = rederiveDigest(record);
    writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
    resealManifest(built.bundleDir);

    const result = verifyBundle(built.bundleDir);
    const ids = result.findings.map((f) => f.id);
    assert.deepEqual(ids, ['VG-ART-061'], `only the artefact check should fire: ${ids.join(',')}`);
    assert.equal(result.verdict, VERDICT.FINDINGS);
  } finally {
    built.scratch.dispose();
  }
});

test('the manifest and the record disagreeing about the artefact is caught', () => {
  const built = buildFixtureBundle({ prefix: 'eca-artbind-' });
  const manifestPath = join(built.bundleDir, 'manifest.json');
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.binds.artifact.sha256 = 'b'.repeat(64);
    delete manifest.bundleDigest;
    manifest.bundleDigest = rederiveDigest(manifest, { selfKey: 'bundleDigest' });
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    const result = verifyBundle(built.bundleDir);
    const ids = result.findings.map((f) => f.id);
    assert.ok(ids.includes('VG-ART-087'), ids.join(','));
  } finally {
    built.scratch.dispose();
  }
});

test('the negative direction: an artefact that DOES match is not flagged', () => {
  const built = buildFixtureBundle({ prefix: 'eca-artok-' });
  try {
    const result = verifyBundle(built.bundleDir);
    assert.ok(!result.findings.some((f) => f.id === 'VG-ART-061'));
    assert.ok(result.checked.includes('artifact.sha256'));
    assert.equal(result.verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});
