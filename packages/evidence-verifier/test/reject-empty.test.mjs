import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { VERDICT, findBundleDirs, verifyBundle } from '../src/verify-bundle.mjs';
import { buildFixtureBundle, scratchDir } from './_fixture.mjs';

// An empty bundle is the case that has to fail loudest, because it is the one
// that fails quietly by default. A directory with nothing in it makes no claim,
// and a verifier that answers "verified" to no claim has replaced a check with
// a green tick. This repository has shipped that failure three times.

test('an EMPTY directory is INCOMPLETE, and says nothing was verified', () => {
  const scratch = scratchDir('eca-empty-');
  try {
    const dir = join(scratch.dir, 'bundle');
    mkdirSync(dir, { recursive: true });
    const result = verifyBundle(dir);
    assert.equal(result.verdict, VERDICT.INCOMPLETE);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    assert.deepEqual(result.findings, []);
    assert.deepEqual(result.unchecked, ['*']);
    assert.match(result.error ?? '', /contains no files/);
    assert.match(result.error ?? '', /different answer from "verified"/);
  } finally {
    scratch.dispose();
  }
});

test('a directory that does not exist is INCOMPLETE, not CLEAN', () => {
  const scratch = scratchDir('eca-missing-');
  try {
    const result = verifyBundle(join(scratch.dir, 'nowhere'));
    assert.equal(result.verdict, VERDICT.INCOMPLETE);
    assert.match(result.error ?? '', /not a directory/);
  } finally {
    scratch.dispose();
  }
});

test('an empty evidence.json is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-empty-rec-' });
  try {
    writeFileSync(join(built.bundleDir, 'evidence.json'), '');
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
    const ids = result.findings.map((f) => f.id);
    assert.ok(ids.includes('VG-ART-084'), `zero length against a recorded length: ${ids.join(',')}`);
  } finally {
    built.scratch.dispose();
  }
});

test('a bundle whose files are all empty is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-empty-all-' });
  try {
    for (const rel of ['evidence.json', 'manifest.json', 'artifact/wipe.o']) {
      writeFileSync(join(built.bundleDir, rel), '');
    }
    const result = verifyBundle(built.bundleDir);
    assert.notEqual(result.verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

test('a manifest that lists nothing is a finding, not an empty pass', () => {
  const built = buildFixtureBundle({ prefix: 'eca-empty-files-' });
  try {
    const file = join(built.bundleDir, 'manifest.json');
    const manifest = JSON.parse(readFileSync(file, 'utf8'));
    manifest.files = [];
    writeFileSync(file, JSON.stringify(manifest, null, 2), 'utf8');
    const result = verifyBundle(built.bundleDir);
    assert.ok(result.findings.some((f) => f.id === 'VG-ART-082'));
  } finally {
    built.scratch.dispose();
  }
});

test('scanning a root with no bundles finds none — the caller must not read that as clean', () => {
  const scratch = scratchDir('eca-nobundles-');
  try {
    mkdirSync(join(scratch.dir, 'a'), { recursive: true });
    mkdirSync(join(scratch.dir, 'b'), { recursive: true });
    assert.deepEqual(findBundleDirs(scratch.dir), []);
    // And a root that does hold one finds exactly it.
    const built = buildFixtureBundle({ prefix: 'eca-onebundle-' });
    try {
      assert.deepEqual(findBundleDirs(built.bundleDir), [built.bundleDir]);
      assert.deepEqual(findBundleDirs(built.scratch.dir), [built.bundleDir]);
    } finally {
      built.scratch.dispose();
    }
  } finally {
    rmSync(scratch.dir, { recursive: true, force: true });
  }
});
