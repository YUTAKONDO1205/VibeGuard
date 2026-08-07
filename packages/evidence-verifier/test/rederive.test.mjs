import assert from 'node:assert/strict';
import { test } from 'node:test';

import { calibrate } from '../src/calibrate.mjs';
import {
  MalformedRecordError,
  canonicalisationProblems,
  rederiveCanonicalText,
  rederiveCanonicalTextRaw,
  rederiveDigest,
} from '../src/rederive.mjs';
import { VECTORS_EXPECTED, VECTORS_FINGERPRINT, loadVectors } from '../src/vectors.mjs';

// ── Calibration ─────────────────────────────────────────────────────────────

test('the re-derivation reproduces every digest vector byte for byte', () => {
  const result = calibrate();
  assert.deepEqual(result.failed, []);
  assert.equal(result.inputs, VECTORS_EXPECTED.vectors + VECTORS_EXPECTED.mustFail);
  assert.equal(result.passed, result.inputs);
  assert.equal(result.skipped, 0);
});

test('this package pins the same contract as the generator', () => {
  const { fingerprint } = loadVectors();
  assert.equal(fingerprint, VECTORS_FINGERPRINT);
});

// ── Two implementations, one contract ───────────────────────────────────────
//
// The cross-check that makes the independence worth having. The generator and
// the verifier were written from the rules in different shapes — an iterative
// emitter with a hand-rolled escaper against a two-phase recursive one using
// JSON.stringify — so agreeing on every vector is a real comparison rather than
// one function called twice.

test('the generator and the verifier agree on every vector', async () => {
  const generator = await import('../../evidence-bundle/src/canon.mjs');
  const { parsed } = loadVectors();
  for (const v of parsed.vectors) {
    assert.equal(generator.canonicalText(v.input), rederiveCanonicalText(v.input), v.name);
    assert.equal(generator.evidenceDigest(v.input), rederiveDigest(v.input), v.name);
  }
  for (const v of parsed.mustFail) {
    assert.throws(() => generator.canonicalText(v.input), undefined, `generator: ${v.name}`);
    assert.throws(() => rederiveCanonicalText(v.input), undefined, `verifier: ${v.name}`);
  }
});

test('the two escapers agree on the awkward strings, not just the easy ones', async () => {
  const generator = await import('../../evidence-bundle/src/canon.mjs');
  const awkward = {
    quote: 'a "quoted" word',
    backslash: 'a\\b',
    lowControls: '\u0000\u0001\u001f',
    shorts: '\b\t\n\f\r',
    slash: 'a/b',
    astral: '𝄞',
    combining: 'é',
    precomposed: 'é',
    del: '\u007f',
    nbsp: '\u00a0',
  };
  assert.equal(generator.canonicalTextRaw(awkward), rederiveCanonicalTextRaw(awkward));
  assert.equal(rederiveCanonicalTextRaw(awkward), JSON.stringify(sortKeys(awkward)));
});

function sortKeys(o) {
  const out = {};
  for (const k of Object.keys(o).sort()) out[k] = o[k];
  return out;
}

// ── Two-phase validation, which is what makes this implementation different ─

test('every problem is reported, not only the first one reached', () => {
  const problems = canonicalisationProblems({ a: 0.5, b: { c: undefined }, d: [1, 2.5] });
  assert.equal(problems.length, 3, JSON.stringify(problems));
  assert.deepEqual(
    problems.map((p) => p.where).sort(),
    ['$.a', '$.b.c', '$.d[1]'],
  );
});

test('a well-formed record has no problems', () => {
  assert.deepEqual(canonicalisationProblems({ a: 1, b: [null, true, 'x'], c: { d: -1 } }), []);
});

test('the thrown error still names the first problem and counts the rest', () => {
  assert.throws(
    () => rederiveCanonicalText({ a: 0.5, b: 1.5 }),
    (e) => e instanceof MalformedRecordError && /and 1 more/.test(e.message),
  );
});

// ── Rule 1, and the raw variant the manifest needs ──────────────────────────

test('rule 1 strips the top level only', () => {
  const record = { context: { x: 1 }, evidenceDigest: 'ff', inner: { context: 1 }, v: 2 };
  assert.equal(rederiveCanonicalText(record), '{"inner":{"context":1},"v":2}');
  assert.equal(
    rederiveCanonicalTextRaw(record),
    '{"context":{"x":1},"evidenceDigest":"ff","inner":{"context":1},"v":2}',
  );
});

test('selfKey removes one more top-level field and nothing else', () => {
  const manifest = { schemaVersion: 'x', bundleDigest: 'aaa', files: [] };
  const a = rederiveDigest(manifest, { selfKey: 'bundleDigest' });
  const b = rederiveDigest({ ...manifest, bundleDigest: 'bbb' }, { selfKey: 'bundleDigest' });
  assert.equal(a, b);
  const c = rederiveDigest({ ...manifest, files: [{ path: 'x' }] }, { selfKey: 'bundleDigest' });
  assert.notEqual(a, c);
});
