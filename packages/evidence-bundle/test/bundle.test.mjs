import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  ARTIFACT_DIR,
  BUNDLE_SCHEMA_VERSION,
  BundleError,
  EVIDENCE_FILE,
  MANIFEST_FILE,
  contextDigestOf,
  writeBundle,
} from '../src/bundle.mjs';
import { canonicalTextRaw, digestExcludingSelf, evidenceDigest } from '../src/canon.mjs';
import { ARTIFACT_BYTES, FIXED_CONTEXT, buildFixtureBundle, demoRecord, scratchDir } from './_fixture.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest('hex');

test('a bundle has the layout the verifier expects', () => {
  const built = buildFixtureBundle();
  try {
    assert.ok(existsSync(join(built.bundleDir, EVIDENCE_FILE)));
    assert.ok(existsSync(join(built.bundleDir, MANIFEST_FILE)));
    assert.ok(existsSync(join(built.bundleDir, ARTIFACT_DIR, 'wipe.o')));
  } finally {
    built.scratch.dispose();
  }
});

test('the record seals itself and names the artefact it describes', () => {
  const built = buildFixtureBundle();
  try {
    const record = JSON.parse(readFileSync(join(built.bundleDir, EVIDENCE_FILE), 'utf8'));
    assert.equal(record.evidenceDigest, evidenceDigest(record));
    assert.equal(record.artifact.path, 'artifact/wipe.o');
    assert.equal(record.artifact.sha256, sha256(ARTIFACT_BYTES));
  } finally {
    built.scratch.dispose();
  }
});

test('the manifest covers every file in the bundle except itself', () => {
  const built = buildFixtureBundle();
  try {
    const manifest = JSON.parse(readFileSync(join(built.bundleDir, MANIFEST_FILE), 'utf8'));
    assert.equal(manifest.schemaVersion, BUNDLE_SCHEMA_VERSION);
    const listed = manifest.files.map((f) => f.path).sort();
    assert.deepEqual(listed, ['artifact/wipe.o', 'evidence.json']);
    for (const entry of manifest.files) {
      const bytes = readFileSync(join(built.bundleDir, entry.path));
      assert.equal(entry.sha256, sha256(bytes), entry.path);
      assert.equal(entry.bytes, bytes.length, entry.path);
    }
    assert.ok(!listed.includes(MANIFEST_FILE), 'a file cannot commit to its own bytes');
  } finally {
    built.scratch.dispose();
  }
});

test('bundleDigest seals the manifest without sealing itself', () => {
  const built = buildFixtureBundle();
  try {
    const manifest = JSON.parse(readFileSync(join(built.bundleDir, MANIFEST_FILE), 'utf8'));
    assert.equal(manifest.bundleDigest, digestExcludingSelf(manifest, 'bundleDigest'));
    // Rule 1 keeps the top-level evidenceDigest out of the digest, which is
    // exactly why the same value is also carried one level down.
    assert.equal(manifest.binds.evidenceDigest, manifest.evidenceDigest);
    const moved = { ...manifest, evidenceDigest: 'f'.repeat(64) };
    assert.equal(
      digestExcludingSelf(moved, 'bundleDigest'),
      manifest.bundleDigest,
      'the outer copy is outside the digest; that is what binds.evidenceDigest is for',
    );
    const movedInner = { ...manifest, binds: { ...manifest.binds, evidenceDigest: 'f'.repeat(64) } };
    assert.notEqual(digestExcludingSelf(movedInner, 'bundleDigest'), manifest.bundleDigest);
  } finally {
    built.scratch.dispose();
  }
});

test('contextDigest commits to the subtree rule 1 excludes', () => {
  const built = buildFixtureBundle();
  try {
    const manifest = JSON.parse(readFileSync(join(built.bundleDir, MANIFEST_FILE), 'utf8'));
    assert.equal(
      manifest.contextDigest,
      sha256(Buffer.from(canonicalTextRaw(manifest.context), 'utf8')),
    );
    const edited = { ...manifest.context, generatedAt: '2031-12-31T23:59:59.000Z' };
    assert.notEqual(contextDigestOf(edited), manifest.contextDigest);
  } finally {
    built.scratch.dispose();
  }
});

test("a manifest context that cannot be canonicalised is refused, with the reason", () => {
  assert.throws(() => contextDigestOf({ elapsedSeconds: 41.9 }), BundleError);
  assert.throws(() => contextDigestOf({ elapsedSeconds: 41.9 }), /must be canonicalisable/);
  assert.doesNotThrow(() => contextDigestOf({ elapsed: { num: 419, den: 10 } }));
});

test('a bundle built twice from the same inputs is byte-identical', () => {
  const a = buildFixtureBundle();
  const b = buildFixtureBundle();
  try {
    for (const rel of [EVIDENCE_FILE, MANIFEST_FILE, `${ARTIFACT_DIR}/wipe.o`]) {
      assert.equal(
        sha256(readFileSync(join(a.bundleDir, rel))),
        sha256(readFileSync(join(b.bundleDir, rel))),
        rel,
      );
    }
  } finally {
    a.scratch.dispose();
    b.scratch.dispose();
  }
});

test('an artefact name with a path separator is refused', () => {
  const scratch = scratchDir('eca-bad-name-');
  try {
    assert.throws(
      () =>
        writeBundle(join(scratch.dir, 'bundle'), {
          record: demoRecord(),
          artifact: { name: '../escape.o', bytes: ARTIFACT_BYTES },
          context: FIXED_CONTEXT,
        }),
      BundleError,
    );
  } finally {
    scratch.dispose();
  }
});

test('extra files land in the manifest too', () => {
  const scratch = scratchDir('eca-extra-');
  try {
    const dir = join(scratch.dir, 'bundle');
    writeBundle(dir, {
      record: demoRecord(),
      artifact: { name: 'wipe.o', bytes: ARTIFACT_BYTES },
      extraFiles: [{ path: 'logs/pass-pipeline.txt', bytes: Buffer.from('AlwaysInlinerPass\n') }],
      context: FIXED_CONTEXT,
    });
    const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_FILE), 'utf8'));
    assert.deepEqual(
      manifest.files.map((f) => f.path).sort(),
      ['artifact/wipe.o', 'evidence.json', 'logs/pass-pipeline.txt'],
    );
  } finally {
    scratch.dispose();
  }
});
