import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { MalformedRecordError, rederiveCanonicalTextRaw, rederiveDigest, sha256Hex } from '../src/rederive.mjs';
import { VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { buildFixtureBundle } from './_fixture.mjs';

/** A verdict that is not CLEAN, i.e. the bundle was rejected in some way. */
function rejected(dir) {
  const r = verifyBundle(dir);
  return { rejected: r.verdict !== VERDICT.CLEAN, result: r };
}

/**
 * Flip one bit of one byte. A flip rather than a random replacement: it always
 * changes the byte, it is reproducible, and it keeps the file the same length
 * so this test is about MODIFICATION and the truncation test is about length.
 */
function flip(bytes, index) {
  const copy = Buffer.from(bytes);
  copy[index] ^= 0x01;
  return copy;
}

// ── Every byte of every covered file ────────────────────────────────────────
//
// `artifact/wipe.o` and `evidence.json` are covered byte-for-byte by
// manifest.files[], so there is no argument to have about which flips matter:
// all of them must be caught, and the sweep is exhaustive rather than sampled.

test('a one-byte change ANYWHERE in the artefact is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-flip-art-' });
  const file = join(built.bundleDir, 'artifact', 'wipe.o');
  try {
    const original = readFileSync(file);
    assert.ok(original.length > 0);
    let tested = 0;
    for (let i = 0; i < original.length; i += 1) {
      writeFileSync(file, flip(original, i));
      const { rejected: wasRejected, result } = rejected(built.bundleDir);
      assert.ok(wasRejected, `byte ${i} of the artefact was not rejected`);
      // Two independent bindings should both notice: the manifest's file
      // digest and the record's own artifact.sha256.
      const ids = result.findings.map((f) => f.id);
      assert.ok(ids.includes('VG-ART-085'), `byte ${i}: manifest file digest, got ${ids.join(',')}`);
      assert.ok(ids.includes('VG-ART-061'), `byte ${i}: record artefact digest, got ${ids.join(',')}`);
      tested += 1;
    }
    writeFileSync(file, original);
    assert.equal(tested, original.length);
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN, 'restoring must restore');
  } finally {
    built.scratch.dispose();
  }
});

test('a one-byte change ANYWHERE in evidence.json is rejected', () => {
  const built = buildFixtureBundle({ prefix: 'eca-flip-rec-' });
  const file = join(built.bundleDir, 'evidence.json');
  try {
    const original = readFileSync(file);
    assert.ok(original.length > 100);
    for (let i = 0; i < original.length; i += 1) {
      writeFileSync(file, flip(original, i));
      const { rejected: wasRejected, result } = rejected(built.bundleDir);
      assert.ok(wasRejected, `byte ${i} of evidence.json was not rejected`);
      // Whatever else it does, the manifest's byte-level coverage catches it.
      // That holds even for a flip that makes the file stop being JSON, where
      // the record-level checks cannot run at all.
      const ids = result.findings.map((f) => f.id);
      assert.ok(
        ids.includes('VG-ART-085'),
        `byte ${i}: expected the manifest file digest to notice, got ${ids.join(',')} / ${result.error ?? ''}`,
      );
    }
    writeFileSync(file, original);
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

// ── manifest.json: every byte that changes what the file MEANS ──────────────
//
// The manifest is the one file nothing else covers, because a file cannot
// commit to its own bytes. What it commits to is its canonical MEANING, so the
// honest claim is narrower and is asserted exactly:
//
//   a flip is rejected  IF AND ONLY IF  it changes the parsed meaning.
//
// The flips that do not are insignificant whitespace, and they are counted and
// checked to be whitespace rather than waved at.

test('a one-byte change in manifest.json is rejected exactly when it changes the meaning', () => {
  const built = buildFixtureBundle({ prefix: 'eca-flip-man-' });
  const file = join(built.bundleDir, 'manifest.json');
  try {
    const original = readFileSync(file);
    const strip = (o) => {
      const copy = { ...o };
      delete copy.bundleDigest; // cannot commit to itself
      delete copy.context; // committed to by contextDigest instead
      return copy;
    };
    const base = JSON.parse(original.toString('utf8'));
    const baseCanonical = rederiveCanonicalTextRaw(strip(base));
    const baseContextText = rederiveCanonicalTextRaw(base.context ?? null);

    /** Does this byte sequence still MEAN what the original meant? */
    const meaningChanged = (bytes) => {
      let parsed;
      try {
        parsed = JSON.parse(bytes.toString('utf8'));
      } catch {
        return true;
      }
      if (parsed.bundleDigest !== base.bundleDigest) return true;
      try {
        if (rederiveCanonicalTextRaw(strip(parsed)) !== baseCanonical) return true;
        if (rederiveCanonicalTextRaw(parsed.context ?? null) !== baseContextText) return true;
      } catch (e) {
        if (e instanceof MalformedRecordError) return true;
        throw e;
      }
      return false;
    };

    let semantic = 0;
    let formattingOnly = 0;
    for (let i = 0; i < original.length; i += 1) {
      const bytes = flip(original, i);
      writeFileSync(file, bytes);
      const wasRejected = verifyBundle(built.bundleDir).verdict !== VERDICT.CLEAN;
      if (meaningChanged(bytes)) {
        assert.ok(wasRejected, `byte ${i} changed the manifest's meaning and was not rejected`);
        semantic += 1;
      } else {
        // Reachable in principle and, with a single-bit flip, not in practice:
        // JSON's only whitespace is space, tab, LF and CR, and flipping the low
        // bit of any of them produces a character JSON.parse refuses. The
        // branch is here so the claim this test makes is EXACT — "rejected if
        // and only if the meaning changed" — rather than true by luck.
        assert.ok(
          !wasRejected,
          `byte ${i} changed only formatting and was rejected; a canonical form exists precisely ` +
            'so that reformatting is not a finding',
        );
        formattingOnly += 1;
      }
    }

    writeFileSync(file, original);
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
    assert.ok(semantic > 0, 'the sweep must actually have exercised the semantic branch');
    assert.equal(semantic + formattingOnly, original.length);
    // Recorded so a future change that starts letting flips through is visible
    // as a number rather than as a silently smaller sweep.
    assert.equal(formattingOnly, 0, 'measured: no single-bit flip of this manifest is meaning-preserving');
  } finally {
    built.scratch.dispose();
  }
});

test('reformatting the manifest is NOT a finding — the other direction of the same rule', () => {
  // The complement of the sweep above. The manifest commits to its canonical
  // meaning, so re-indenting it, or writing it on one line, must verify clean.
  // A check that reddened here would be telling the truth about bytes and
  // lying about evidence, and it is the shape of check people switch off.
  const built = buildFixtureBundle({ prefix: 'eca-reformat-' });
  const file = join(built.bundleDir, 'manifest.json');
  try {
    const manifest = JSON.parse(readFileSync(file, 'utf8'));
    writeFileSync(file, JSON.stringify(manifest), 'utf8'); // no whitespace at all
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
    writeFileSync(file, JSON.stringify(manifest, null, 8), 'utf8'); // different indent
    assert.equal(verifyBundle(built.bundleDir).verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

test('an edit confined to the manifest context is caught by contextDigest alone', () => {
  // Rule 1 removes `context` from every digest, so without `contextDigest` the
  // whole volatile block could be rewritten and every other digest would still
  // check out. Here `bundleDigest` is re-sealed after the edit, so the excluded
  // subtree is the ONLY thing wrong and exactly one finding may fire.
  const built = buildFixtureBundle({ prefix: 'eca-ctx-' });
  const file = join(built.bundleDir, 'manifest.json');
  try {
    const manifest = JSON.parse(readFileSync(file, 'utf8'));
    manifest.context.generatedAt = '2031-12-31T23:59:59.000Z';
    delete manifest.bundleDigest;
    manifest.bundleDigest = rederiveDigest(manifest, { selfKey: 'bundleDigest' });
    writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');

    const result = verifyBundle(built.bundleDir);
    const ids = result.findings.map((f) => f.id);
    assert.deepEqual(ids, ['VG-ART-092'], ids.join(','));
  } finally {
    built.scratch.dispose();
  }
});

test('an added file nobody listed is rejected, even though nothing was changed', () => {
  const built = buildFixtureBundle({ prefix: 'eca-added-' });
  try {
    writeFileSync(join(built.bundleDir, 'notes.txt'), 'one byte too many');
    const result = verifyBundle(built.bundleDir);
    assert.equal(result.verdict, VERDICT.FINDINGS);
    assert.ok(result.findings.some((f) => f.id === 'VG-ART-086'));
  } finally {
    built.scratch.dispose();
  }
});

test('the digest functions themselves move when one byte moves', () => {
  // A sanity check on the machinery the sweep depends on. If sha256Hex or
  // rederiveDigest were constant, every assertion above would still pass in the
  // rejected direction and the suite would be measuring nothing.
  assert.notEqual(sha256Hex(Buffer.from('a')), sha256Hex(Buffer.from('b')));
  assert.notEqual(rederiveDigest({ x: 1 }), rederiveDigest({ x: 2 }));
});
