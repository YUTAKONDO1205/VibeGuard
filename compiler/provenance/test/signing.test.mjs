// Detached signatures: both directions.
//
// A detector tested only against the bad input is a false-positive factory, so
// every tamper case here has a matching case in which the good thing is NOT
// flagged — and one of those is stronger than it looks: a record REFORMATTED
// (pretty-printed differently, keys reordered) must still verify, because the
// signature is over the canonical form and not over the file.

import { strict as assert } from 'node:assert';
import test from 'node:test';

import { canonicalJson } from '../../evidence/canon.mjs';
import { generateSigningKeyPair, keyId, publicKeyFromBase64 } from '../lib/keys.mjs';
import { buildProvenanceRecord } from '../lib/record.mjs';
import { buildStatement } from '../lib/statement.mjs';
import { contextDigest, signRecord, signingBytes, verifyDetached } from '../lib/signing.mjs';
import { fakeCommit } from './helpers.mjs';

function sampleRecord() {
  const statement = buildStatement({
    commitSha: fakeCommit('a'),
    environment: { arch: 'x64', platform: 'linux', sourceDateEpoch: 1700000000 },
    materials: [{ sha256: 'c'.repeat(64), uri: 'urn:vibeguard:material:source:src/wipe.c' }],
    parameters: { cflags: '-O2 -g' },
    subjects: [{ name: 'out/app', sha256: 'b'.repeat(64) }],
    toolchainDigest: 'd'.repeat(64),
  });
  return buildProvenanceRecord({
    statement,
    toolchain: { clang: '18.1.3', digest: 'd'.repeat(64), packages: [] },
  });
}

function signed(record) {
  const pair = generateSigningKeyPair();
  const envelope = signRecord({
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    record,
    subjectFile: 'record.json',
  });
  return { envelope, pair };
}

test('NEGATIVE FIXTURE: an untouched signed record verifies', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  const r = verifyDetached({ envelope, record, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, true, r.reasons.join(', '));
  assert.deepEqual(r.reasons, []);
});

test('NEGATIVE FIXTURE: reformatting the file does not break the signature', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  // Round-trip through JSON with the members in a different insertion order and
  // with different whitespace — the same claim, different bytes on disk.
  const reordered = {};
  for (const k of Object.keys(record).reverse()) reordered[k] = record[k];
  const roundTripped = JSON.parse(JSON.stringify(reordered, null, 4));
  assert.notEqual(JSON.stringify(roundTripped), JSON.stringify(record), 'the file bytes must differ for this test to mean anything');
  assert.equal(canonicalJson(roundTripped), canonicalJson(record), 'the canonical form must not');
  const r = verifyDetached({ envelope, record: roundTripped, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, true, r.reasons.join(', '));
});

test('the signature covers the canonical text, and the envelope says how many bytes', () => {
  const record = sampleRecord();
  const { envelope } = signed(record);
  assert.equal(envelope.payload.bytes, signingBytes(record).length);
  assert.equal(envelope.payload.kind, 'evidence-canonical-text');
  assert.equal(envelope.subject.evidenceDigest, record.evidenceDigest);
});

test('POSITIVE FIXTURE: tampering with the commit sha breaks the signature', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  record.statement.predicate.invocation.configSource.digest.sha1 = fakeCommit('b');
  const r = verifyDetached({ envelope, record, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('canonical-digest-mismatch'), r.reasons.join(', '));
  assert.ok(r.reasons.includes('signature-does-not-verify'), r.reasons.join(', '));
});

test('POSITIVE FIXTURE: tampering with the toolchain digest breaks the signature', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  record.statement.predicate.materials[0].digest.sha256 = 'e'.repeat(64);
  const r = verifyDetached({ envelope, record, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('signature-does-not-verify'));
});

test('POSITIVE FIXTURE: a signature made by another key is refused even though it is self-consistent', () => {
  const record = sampleRecord();
  const trusted = generateSigningKeyPair();
  const rogue = generateSigningKeyPair();
  // The forger signs the record they want with their own key and packages that
  // key with it. Everything inside the envelope agrees with everything else.
  const envelope = signRecord({
    privateKey: rogue.privateKey,
    publicKey: rogue.publicKey,
    record,
    subjectFile: 'record.json',
  });
  assert.equal(keyId(publicKeyFromBase64(envelope.publicKey)), envelope.keyId, 'the forgery is internally consistent');

  const r = verifyDetached({ envelope, record, trustedPublicKey: trusted.publicKey });
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('untrusted-key'), r.reasons.join(', '));
  assert.ok(r.reasons.includes('signature-does-not-verify'), r.reasons.join(', '));
});

test('the context subtree is outside the digest — which is why contextDigest exists', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  const before = canonicalJson(record);

  record.context.generatedAt = '1999-12-31T23:59:59Z';

  assert.equal(canonicalJson(record), before,
    'editing context must not move the canonical text; if it did, rule 1 would be broken');
  const r = verifyDetached({ envelope, record, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, true, 'the signature alone cannot see this edit — that is the hole');

  assert.notEqual(contextDigest(record.context), record.contextDigest,
    'contextDigest is what closes it, and verify-core.mjs is what reports the mismatch');
});

test('a truncated or reshaped envelope is refused before any crypto runs', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  for (const mutate of [
    (e) => { delete e.signature; },
    (e) => { e.algorithm = 'rsa'; },
    (e) => { e.sigVersion = 'detached-sig-v1'; },
    (e) => { e.canonicalDigest = 'not hex'; },
    (e) => { e.payload = { bytes: 1, kind: 'something-else' }; },
  ]) {
    const broken = JSON.parse(JSON.stringify(envelope));
    mutate(broken);
    const r = verifyDetached({ envelope: broken, record, trustedPublicKey: pair.publicKey });
    assert.equal(r.ok, false);
    assert.ok(r.reasons.every((x) => x.startsWith('malformed:')), r.reasons.join(', '));
  }
});

test('an envelope whose embedded key is not the key its keyId names is caught', () => {
  const record = sampleRecord();
  const { envelope, pair } = signed(record);
  const other = generateSigningKeyPair();
  envelope.publicKey = other.publicPem
    ? Buffer.from(other.publicKey.export({ format: 'der', type: 'spki' })).toString('base64')
    : envelope.publicKey;
  const r = verifyDetached({ envelope, record, trustedPublicKey: pair.publicKey });
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('embedded-key-disagrees-with-its-own-id'), r.reasons.join(', '));
});
