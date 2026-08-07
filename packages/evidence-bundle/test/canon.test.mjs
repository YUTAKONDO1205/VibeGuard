import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  CanonError,
  canonicalText,
  canonicalTextRaw,
  compareCodeUnits,
  digestExcludingSelf,
  evidenceDigest,
  isArrayIndexKey,
} from '../src/canon.mjs';
import { calibrate } from '../src/calibrate.mjs';
import { VECTORS_EXPECTED, VECTORS_FINGERPRINT, loadVectors } from '../src/vectors.mjs';

// ── The compatibility oracle ────────────────────────────────────────────────
//
// This is the only claim worth making about a canonicaliser, and it is a claim
// about bytes: the expected values came from a reference implementation outside
// this repository, and this one reproduces them exactly.

test('every digest vector is reproduced byte for byte', () => {
  const result = calibrate();
  assert.deepEqual(result.failed, [], 'no vector may fail');
  assert.equal(result.inputs, VECTORS_EXPECTED.vectors + VECTORS_EXPECTED.mustFail);
  assert.equal(result.passed, result.inputs);
  assert.equal(result.skipped, 0, 'a skipped vector is an unreproduced vector');
});

test('the vectors are the pinned ones', () => {
  const { parsed, fingerprint } = loadVectors();
  assert.equal(fingerprint, VECTORS_FINGERPRINT);
  assert.equal(parsed.vectors.length, VECTORS_EXPECTED.vectors);
  assert.equal(parsed.mustFail.length, VECTORS_EXPECTED.mustFail);
});

test('the pin moves when a vector moves, and not otherwise', async () => {
  const { fingerprintVectors } = await import('../src/vectors.mjs');
  const { parsed } = loadVectors();
  const tampered = structuredClone(parsed);
  tampered.vectors[0].digest = 'f'.repeat(64);
  assert.notEqual(fingerprintVectors(tampered), VECTORS_FINGERPRINT);
  assert.equal(fingerprintVectors(parsed), VECTORS_FINGERPRINT);
});

// ── The five rules, asked directly ──────────────────────────────────────────

test('rule 1 removes context and evidenceDigest from the top level only', () => {
  const text = canonicalText({
    context: { anything: 'at all' },
    evidenceDigest: 'ffff',
    inner: { context: 'kept', evidenceDigest: 'kept' },
    value: 1,
  });
  assert.equal(text, '{"inner":{"context":"kept","evidenceDigest":"kept"},"value":1}');
});

test('rule 1 does not apply to a sub-object', () => {
  assert.equal(canonicalTextRaw({ context: 1, evidenceDigest: 2 }), '{"context":1,"evidenceDigest":2}');
});

test('rule 2 sorts keys at every level and never sorts an array', () => {
  assert.equal(
    canonicalTextRaw({ b: [3, 1, 2], a: { z: 1, y: 2 } }),
    '{"a":{"y":2,"z":1},"b":[3,1,2]}',
  );
});

test('rule 4 refuses a float rather than rounding it', () => {
  assert.throws(() => canonicalTextRaw({ ratio: 0.75 }), CanonError);
  assert.doesNotThrow(() => canonicalTextRaw({ ratio: { num: 3, den: 4 } }));
});

test('rule 5 is sha256 of the canonical text', async () => {
  const { createHash } = await import('node:crypto');
  const record = { a: 1, context: { volatile: 'x' } };
  assert.equal(
    evidenceDigest(record),
    createHash('sha256').update(canonicalText(record), 'utf8').digest('hex'),
  );
});

// ── Strictness beyond the rules: both directions ────────────────────────────

test('a cycle is reported as a cycle, not as a hang', () => {
  const a = { name: 'a' };
  a.self = a;
  assert.throws(() => canonicalTextRaw(a), /cycle/);
});

test('an object appearing twice as a sibling is not a cycle', () => {
  const shared = { k: 1 };
  assert.equal(canonicalTextRaw({ a: shared, b: shared }), '{"a":{"k":1},"b":{"k":1}}');
});

test('undefined is refused; null is accepted', () => {
  assert.throws(() => canonicalTextRaw({ x: undefined }), /undefined/);
  assert.equal(canonicalTextRaw({ x: null }), '{"x":null}');
});

test('a class instance is refused rather than serialised as {}', () => {
  assert.throws(() => canonicalTextRaw({ when: new Date(0) }), /plain objects only/);
  assert.throws(() => canonicalTextRaw({ m: new Map() }), /plain objects only/);
  assert.doesNotThrow(() => canonicalTextRaw({ when: '1970-01-01T00:00:00.000Z' }));
});

test('an unpaired surrogate is refused, because it has no UTF-8 encoding', () => {
  assert.throws(() => canonicalTextRaw({ s: '\ud834' }), /surrogate/);
  assert.throws(() => canonicalTextRaw({ s: '\udd1e' }), /surrogate/);
  // The paired form is the astral character the vectors already cover.
  assert.equal(canonicalTextRaw({ s: '𝄞' }), '{"s":"𝄞"}');
});

test('an array-index key is refused; a prefixed one is accepted', () => {
  assert.equal(isArrayIndexKey('0'), true);
  assert.equal(isArrayIndexKey('10'), true);
  assert.equal(isArrayIndexKey('k10'), false);
  assert.equal(isArrayIndexKey('-1'), false);
  assert.throws(() => canonicalTextRaw({ 10: 'x' }), /array index/);
  assert.equal(canonicalTextRaw({ k10: 'x' }), '{"k10":"x"}');
});

test('the key comparator is by code unit, not by locale', () => {
  assert.ok(compareCodeUnits('Z', 'a') < 0, 'uppercase sorts before lowercase by code unit');
  assert.ok(compareCodeUnits('a', 'a') === 0);
  assert.ok(compareCodeUnits('ab', 'abc') < 0);
});

// ── The self-digest helper ──────────────────────────────────────────────────

test('digestExcludingSelf ignores the named field and nothing else', () => {
  const base = { schemaVersion: 'x', payload: [1, 2, 3] };
  const a = digestExcludingSelf({ ...base, selfDigest: null }, 'selfDigest');
  const b = digestExcludingSelf({ ...base, selfDigest: 'anything' }, 'selfDigest');
  assert.equal(a, b, 'the excluded field cannot move the digest');
  const c = digestExcludingSelf({ ...base, payload: [1, 2, 4], selfDigest: null }, 'selfDigest');
  assert.notEqual(a, c, 'every other field must move it');
});
