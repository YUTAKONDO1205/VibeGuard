// Two things are asserted here and they are not the same thing.
//
//   1. This canonicaliser reproduces the shared vectors, so a record written by
//      this component digests to the same bytes as one written anywhere else in
//      compiler/.
//   2. It REFUSES the same inputs. Two canonicalisers that agree on every valid
//      record and disagree about what is malformed are not the same
//      canonicaliser, and the failure mode — a record written here and rejected
//      as malformed by the verifier next door, with nothing wrong with the
//      measurement — costs a re-run of everything downstream.
//
// The vectors are compiler/evidence/testdata/digest-vectors.json. If that file
// is unreadable this suite FAILS rather than skipping: an uncalibrated
// canonicaliser reporting green is the situation the whole file exists to rule
// out.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { canonicalBytes, evidenceDigest, seal, sha256Hex } from '../lib/canonical.mjs';
import { HERE } from './helpers.mjs';
import { findAbsolutePaths, scrubText, classifyAbsolutePath } from '../lib/hygiene.mjs';

const VECTORS = resolve(HERE, '..', '..', 'evidence', 'testdata', 'digest-vectors.json');

test('context and evidenceDigest are dropped at the top level only', () => {
  assert.equal(
    canonicalBytes({ b: 1, a: 2, context: { x: 1 }, evidenceDigest: 'z', inner: { context: { keep: 1 } } }).toString(),
    '{"a":2,"b":1,"inner":{"context":{"keep":1}}}',
  );
});

test('keys sort at every level, including inside arrays; array order is kept', () => {
  assert.equal(canonicalBytes({ a: [{ z: 1, y: 2 }] }).toString(), '{"a":[{"y":2,"z":1}]}');
  assert.equal(canonicalBytes({ a: [3, 1, 2] }).toString(), '{"a":[3,1,2]}');
});

test('a non-integer number is refused, never rounded', () => {
  assert.throws(() => canonicalBytes({ ratio: 0.75 }), /non-integer number/);
});

test('sealing is idempotent and ignores context', () => {
  const a = seal({ x: 1, context: { generatedAt: 'A' } });
  const b = seal({ x: 1, context: { generatedAt: 'B' } });
  assert.equal(a.evidenceDigest, b.evidenceDigest);
  assert.match(a.evidenceDigest, /^[0-9a-f]{64}$/);
  assert.equal(evidenceDigest(a), a.evidenceDigest);
});

test('this canonicaliser agrees with the shared vectors, and refuses what they refuse', () => {
  let v;
  try {
    v = JSON.parse(readFileSync(VECTORS, 'utf8'));
  } catch (err) {
    assert.fail(`the shared digest vectors could not be read (${err.message}). An uncalibrated canonicaliser must not report green.`);
  }
  const disagreed = [];
  for (const t of v.vectors ?? []) {
    let mine;
    try {
      mine = canonicalBytes(t.input).toString('utf8');
    } catch (err) {
      disagreed.push(`${t.name}: threw ${err.message.slice(0, 60)}`);
      continue;
    }
    if (mine !== t.canonicalText) disagreed.push(`${t.name}: ${mine.slice(0, 60)}`);
  }
  assert.deepEqual(disagreed, []);
  assert.ok((v.vectors ?? []).length > 0, 'the vector file carried no vectors');

  const accepted = [];
  for (const t of v.mustFail ?? []) {
    try {
      canonicalBytes(t.input);
      accepted.push(t.name);
    } catch { /* refused, as required */ }
  }
  assert.deepEqual(accepted, []);
  assert.ok((v.mustFail ?? []).length > 0, 'the vector file carried no must-fail cases');
});

test('sha256Hex is lowercase hex over the bytes', () => {
  assert.equal(sha256Hex(Buffer.from('')), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

// ── path hygiene ─────────────────────────────────────────────────────────────

test('an absolute path is found in a key as well as in a value', () => {
  const hits = findAbsolutePaths({ '/etc/passwd': 1, ok: '/usr/lib/x' });
  assert.equal(hits.length, 2);
  assert.deepEqual(hits.map((h) => h.in).sort(), ['key', 'value']);
});

test('context is excluded from the scan, because it is excluded from the digest', () => {
  assert.deepEqual(findAbsolutePaths({ context: { host: '/anything' } }, { skipTopLevelKeys: ['context'] }), []);
});

test('the portable ref forms are not mistaken for absolute paths', () => {
  for (const s of ['main.o', 'libarch.a(arch.o)', 'system:lib/x86_64-linux-gnu/Scrt1.o', 'withheld:rogue.o']) {
    assert.equal(classifyAbsolutePath(s), null, `${s} was flagged`);
  }
});

test('a drive letter, a UNC path and a tilde are all absolute', () => {
  assert.equal(classifyAbsolutePath('C:\\build\\app').kind, 'windows-drive');
  assert.equal(classifyAbsolutePath('\\\\server\\share').kind, 'unc');
  assert.equal(classifyAbsolutePath('~/build/app').kind, 'home-relative');
});

test('scrubbing an option keeps the option and replaces the path', () => {
  assert.equal(scrubText('-rpath=/usr/lib/x', '/fixtures'), '-rpath=system:usr/lib/x');
  assert.equal(scrubText('-z now', '/fixtures'), '-z now');
  assert.equal(classifyAbsolutePath(scrubText('loaded /home/somebody/x.o', '/fixtures')), null);
});
