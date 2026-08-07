import assert from 'node:assert/strict';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { buildFixtureBundle } from './_fixture.mjs';

// "Truncated" has three meanings and they fail differently, so each gets its
// own assertion rather than one test that passes for whichever reason arrives
// first. The length is recorded next to the digest for exactly this: a copy
// that stopped early and an edit have different causes, and a report that
// cannot tell them apart is a report someone has to reproduce by hand.

test('an artefact truncated to fewer bytes is rejected as a LENGTH difference', () => {
  const built = buildFixtureBundle({ prefix: 'eca-trunc-art-' });
  const file = join(built.bundleDir, 'artifact', 'wipe.o');
  try {
    const original = readFileSync(file);
    for (const keep of [0, 1, original.length - 1]) {
      writeFileSync(file, original.subarray(0, keep));
      const result = verifyBundle(built.bundleDir);
      assert.equal(result.verdict, VERDICT.FINDINGS, `truncating to ${keep} bytes`);
      const ids = result.findings.map((f) => f.id);
      assert.ok(ids.includes('VG-ART-084'), `truncating to ${keep}: got ${ids.join(',')}`);
      assert.ok(
        !ids.includes('VG-ART-085'),
        'a length difference is reported as a length difference, not as a content difference',
      );
      // The record's own binding to the artefact notices independently.
      assert.ok(ids.includes('VG-ART-061'), `truncating to ${keep}: got ${ids.join(',')}`);
    }
    writeFileSync(file, original);
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

test('a record truncated mid-JSON is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-trunc-rec-' });
  const file = join(built.bundleDir, 'evidence.json');
  try {
    const original = readFileSync(file);
    writeFileSync(file, original.subarray(0, Math.floor(original.length / 2)));
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    const ids = result.findings.map((f) => f.id);
    assert.ok(
      ids.includes('VG-ART-084'),
      `the manifest notices the length before anything tries to parse it: ${ids.join(',')}`,
    );
    writeFileSync(file, original);
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

test('a bundle truncated by deleting a whole file is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-trunc-file-' });
  try {
    rmSync(join(built.bundleDir, 'artifact', 'wipe.o'));
    const result = verifyBundle(built.bundleDir);
    assert.equal(result.verdict, VERDICT.FINDINGS);
    const ids = result.findings.map((f) => f.id);
    assert.ok(ids.includes('VG-ART-083'), `a listed file is missing: ${ids.join(',')}`);
    assert.ok(ids.includes('VG-ART-060'), `the record's artefact is missing: ${ids.join(',')}`);
  } finally {
    built.scratch.dispose();
  }
});

test('a bundle truncated to the artefact alone is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-trunc-all-' });
  try {
    rmSync(join(built.bundleDir, 'evidence.json'));
    rmSync(join(built.bundleDir, 'manifest.json'));
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    assert.match(result.error ?? '', /evidence\.json/);
  } finally {
    built.scratch.dispose();
  }
});

test('a zero-length manifest is rejected rather than treated as absent', () => {
  const built = buildFixtureBundle({ prefix: 'eca-trunc-man-' });
  try {
    writeFileSync(join(built.bundleDir, 'manifest.json'), '');
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    assert.match(result.error ?? '', /does not parse/);
  } finally {
    built.scratch.dispose();
  }
});
