// Evidence canonicalisation, against the five rules in interfaces.md section 5.

import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalJson, digestOf, findAbsolutePaths, makeFinding } from '../lib/record.mjs';

test('keys sort at every level, including inside arrays of objects', () => {
  const a = { b: 1, a: [{ z: 1, y: 2 }] };
  const b = { a: [{ y: 2, z: 1 }], b: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b));
  assert.equal(canonicalJson(a), '{"a":[{"y":2,"z":1}],"b":1}');
});

test('array order is significant and is never sorted', () => {
  assert.notEqual(canonicalJson({ a: [1, 2] }), canonicalJson({ a: [2, 1] }));
});

test('context and evidenceDigest are removed as whole subtrees, at the top level only', () => {
  const withCtx = { a: 1, context: { generatedAt: 'now' }, evidenceDigest: 'x' };
  assert.equal(canonicalJson(withCtx), '{"a":1}');
  // Nested keys of the same name are data, not metadata, and stay.
  assert.equal(canonicalJson({ a: { context: 1 } }), '{"a":{"context":1}}');
});

test('a non-integer number is a malformed record and is refused, not rounded', () => {
  assert.throws(() => canonicalJson({ ratio: 0.75 }), /non-integer number at \/ratio/);
  assert.throws(() => canonicalJson({ a: [{ b: 1.5 }] }), /non-integer number at \/a\/0\/b/);
  // The shape a ratio is supposed to take.
  assert.equal(canonicalJson({ ratio: { den: 4, num: 3 } }), '{"ratio":{"den":4,"num":3}}');
});

test('the digest moves when the record does, and only then', () => {
  const r = { a: 1, b: [2, 3] };
  assert.equal(digestOf(r), digestOf({ b: [2, 3], a: 1 }));
  assert.equal(digestOf(r), digestOf({ ...r, context: { host: 'anything' } }));
  assert.notEqual(digestOf(r), digestOf({ a: 1, b: [3, 2] }));
  assert.match(digestOf(r), /^[0-9a-f]{64}$/);
});

test('absolute paths are found anywhere in a record, not only at the top', () => {
  assert.deepEqual(findAbsolutePaths({ a: 1, b: 'src/x.c' }), []);
  const hits = findAbsolutePaths({ a: [{ detail: 'loaded from /opt/toolchain/x.so' }] });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].pointer, '/a/0/detail');
  assert.equal(findAbsolutePaths({ p: 'C:\\Users\\somebody\\x' }).length, 1);
});

test('a finding has the one shape, with nulls meaning not applicable', () => {
  const f = makeFinding({
    id: 'VG-PROP-010', severity: 'medium', title: 't', detail: 'd', where: { kind: 'ir', unit: '@x' },
  });
  assert.deepEqual(Object.keys(f).sort(), ['detail', 'id', 'severity', 'title', 'where']);
  assert.deepEqual(f.where, { kind: 'ir', pass: null, path: null, unit: '@x' });
  // A record made of findings canonicalises without complaint.
  assert.match(digestOf({ findings: [f] }), /^[0-9a-f]{64}$/);
});

test('a record must be an object, and undefined cannot appear in one', () => {
  assert.throws(() => canonicalJson([1, 2]), /a record is a JSON object/);
  assert.throws(() => canonicalJson({ a: undefined }), /cannot appear in a record/);
});
