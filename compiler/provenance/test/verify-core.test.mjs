// Verification, end to end, in memory.
//
// The two layers are tested separately and the difference between them is the
// point of the file:
//
//   layer 1  an attacker WITHOUT the key edits a field. The signature fails.
//   layer 2  an attacker WITH the key edits a field and re-signs. The signature
//            passes, and the claim is caught only where the verifier was given
//            something independent to re-derive it from.
//
// If layer 2 were not tested, the honest sentence in README.md about what a key
// holder can do would be a sentence nobody had checked.

import { strict as assert } from 'node:assert';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_OK } from '../../driver/lib/exit.mjs';
import { evidenceDigest } from '../../evidence/canon.mjs';
import { generateSigningKeyPair } from '../lib/keys.mjs';
import { declaredToolchainDigest } from '../lib/pin.mjs';
import { buildProvenanceRecord } from '../lib/record.mjs';
import { contextDigest, signRecord } from '../lib/signing.mjs';
import { buildStatement, statementProblems } from '../lib/statement.mjs';
import { ART, CFG, exitCodeFor, verifyProvenance } from '../lib/verify-core.mjs';
import { fakeCommit, makeTemp, removeTemp, writeFakePin } from './helpers.mjs';

const COMMIT = fakeCommit('a');

function scenario({ pinBump = 0 } = {}) {
  const dir = makeTemp('verify');
  const { pin } = writeFakePin(dir, { bump: pinBump });
  const toolchainDigest = declaredToolchainDigest(pin);
  const artefact = Buffer.from('the artefact bytes\n');
  writeFileSync(join(dir, 'app'), artefact);
  const statement = buildStatement({
    commitSha: COMMIT,
    environment: { arch: 'x64', platform: 'linux', sourceDateEpoch: 1700000000 },
    materials: [{ sha256: 'c'.repeat(64), uri: 'urn:vibeguard:material:source:src/wipe.c' }],
    parameters: { cflags: '-O2' },
    subjects: [{ name: 'app', sha256: createHash('sha256').update(artefact).digest('hex') }],
    toolchainDigest,
  });
  const record = buildProvenanceRecord({
    statement,
    toolchain: { clang: '18.1.3', digest: toolchainDigest, packages: [] },
  });
  const pair = generateSigningKeyPair();
  const envelope = signRecord({ privateKey: pair.privateKey, publicKey: pair.publicKey, record, subjectFile: 'record.json' });
  return { dir, envelope, pair, pin, record, toolchainDigest };
}

function resign(record, pair) {
  return signRecord({ privateKey: pair.privateKey, publicKey: pair.publicKey, record, subjectFile: 'record.json' });
}

function ids(findings) {
  return findings.map((f) => f.id).sort();
}

test('NEGATIVE FIXTURE: a clean record with every input supplied verifies, exit 0', () => {
  const s = scenario();
  try {
    const { checks, findings } = verifyProvenance({
      artifactRoot: s.dir,
      envelope: s.envelope,
      expectCommit: COMMIT,
      pin: s.pin,
      record: s.record,
      trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(findings, [], JSON.stringify(findings, null, 2));
    assert.equal(checks.filter((c) => c.state === 'NOT_OBSERVED').length, 0);
    assert.ok(checks.every((c) => c.state === 'PRESENT'), JSON.stringify(checks, null, 2));
    assert.equal(exitCodeFor({ checks, findings, strict: true }), EXIT_OK);
  } finally { removeTemp(s.dir); }
});

test('layer 1: the commit sha is edited and not re-signed — exit 4', () => {
  const s = scenario();
  try {
    s.record.statement.predicate.invocation.configSource.digest.sha1 = fakeCommit('b');
    const { checks, findings } = verifyProvenance({
      envelope: s.envelope, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.ok(ids(findings).includes(ART.SIGNATURE_INVALID), ids(findings).join(','));
    assert.ok(ids(findings).includes(ART.SIGNED_OTHER_BYTES), ids(findings).join(','));
    assert.ok(ids(findings).includes(ART.EVIDENCE_DIGEST_MISMATCH), ids(findings).join(','));
    assert.equal(exitCodeFor({ checks, findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('layer 1: the toolchain digest is edited and not re-signed — exit 4', () => {
  const s = scenario();
  try {
    s.record.statement.predicate.materials[0].digest.sha256 = 'f'.repeat(64);
    const { checks, findings } = verifyProvenance({
      envelope: s.envelope, pin: s.pin, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.ok(ids(findings).includes(ART.SIGNATURE_INVALID));
    assert.ok(ids(findings).includes(CFG.TOOLCHAIN_NOT_THE_PIN), ids(findings).join(','));
    assert.ok(ids(findings).includes(ART.TOOLCHAIN_SELF_DISAGREEMENT), ids(findings).join(','));
    assert.equal(exitCodeFor({ checks, findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('layer 1: a subject digest is edited and not re-signed — exit 4', () => {
  const s = scenario();
  try {
    s.record.statement.subject[0].digest.sha256 = '0'.repeat(64);
    const { checks, findings } = verifyProvenance({
      artifactRoot: s.dir, envelope: s.envelope, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.ok(ids(findings).includes(ART.SIGNATURE_INVALID));
    assert.ok(ids(findings).includes(ART.SUBJECT_BYTES_DIFFER));
    assert.equal(exitCodeFor({ checks, findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('layer 1: the context subtree is edited — the digest does not move, the signature holds, and it is still caught', () => {
  const s = scenario();
  try {
    s.record.context.generatedAt = '1999-12-31T23:59:59Z';
    const { checks, findings } = verifyProvenance({
      envelope: s.envelope, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.ok(!ids(findings).includes(ART.SIGNATURE_INVALID), 'the signature cannot see a context edit');
    assert.ok(ids(findings).includes(ART.CONTEXT_ALTERED), ids(findings).join(','));
    assert.equal(exitCodeFor({ checks, findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('layer 2: the key holder re-signs a false commit — the signature passes, the comparison catches it', () => {
  const s = scenario();
  try {
    s.record.statement.predicate.invocation.configSource.digest.sha1 = fakeCommit('b');
    // Re-seal so evidenceDigest and the signature agree with the edited claim.
    // That is exactly what someone holding the key would do, and it leaves a
    // document with nothing wrong inside it.
    const resealed = buildProvenanceRecord({
      context: s.record.context,
      statement: s.record.statement,
      toolchain: s.record.toolchain,
    });
    const envelope = resign(resealed, s.pair);

    const clean = verifyProvenance({
      envelope, record: resealed, trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(clean.findings, [], 'with nothing to compare against, the forgery verifies');
    assert.equal(exitCodeFor({ checks: clean.checks, findings: clean.findings }), EXIT_OK);
    assert.ok(clean.checks.some((c) => c.name === 'commit-matches-checkout' && c.state === 'NOT_OBSERVED'));
    assert.equal(exitCodeFor({ checks: clean.checks, findings: clean.findings, strict: true }), EXIT_INCOMPLETE,
      '--strict refuses to call a run clean when it made none of the independent checks');

    const caught = verifyProvenance({
      envelope, expectCommit: COMMIT, record: resealed, trustedPublicKey: s.pair.publicKey,
    });
    assert.ok(ids(caught.findings).includes(CFG.COMMIT_NOT_THE_CHECKOUT), ids(caught.findings).join(','));
    assert.equal(exitCodeFor({ checks: caught.checks, findings: caught.findings }), EXIT_FINDINGS);
  } finally { removeTemp(s.dir); }
});

test('layer 2: the key holder re-signs a false toolchain digest — the pin catches it', () => {
  const s = scenario();
  try {
    const wrong = 'f'.repeat(64);
    s.record.statement.predicate.materials[0].digest.sha256 = wrong;
    const resealed = buildProvenanceRecord({
      context: s.record.context,
      statement: s.record.statement,
      toolchain: { ...s.record.toolchain, digest: wrong },
    });
    const envelope = resign(resealed, s.pair);

    const clean = verifyProvenance({ envelope, record: resealed, trustedPublicKey: s.pair.publicKey });
    assert.deepEqual(clean.findings, [], 'internally consistent, correctly signed, and false');

    const caught = verifyProvenance({ envelope, pin: s.pin, record: resealed, trustedPublicKey: s.pair.publicKey });
    assert.deepEqual(ids(caught.findings), [CFG.TOOLCHAIN_NOT_THE_PIN]);
    assert.equal(exitCodeFor({ checks: caught.checks, findings: caught.findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('layer 2: a different pin is a mismatch — the pin comparison is not vacuous', () => {
  const s = scenario();
  const other = makeTemp('otherpin');
  try {
    const { pin: differentPin } = writeFakePin(other, { bump: 1 });
    assert.notEqual(declaredToolchainDigest(differentPin), s.toolchainDigest);
    const r = verifyProvenance({
      envelope: s.envelope, pin: differentPin, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(ids(r.findings), [CFG.TOOLCHAIN_NOT_THE_PIN]);
  } finally { removeTemp(s.dir); removeTemp(other); }
});

test('layer 2: an artefact byte flips under a correctly signed record', () => {
  const s = scenario();
  try {
    writeFileSync(join(s.dir, 'app'), Buffer.from('the artefact bytes!\n'));
    const { checks, findings } = verifyProvenance({
      artifactRoot: s.dir, envelope: s.envelope, record: s.record, trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(ids(findings), [ART.SUBJECT_BYTES_DIFFER]);
    assert.equal(exitCodeFor({ checks, findings }), EXIT_FINDINGS);
  } finally { removeTemp(s.dir); }
});

test('the generation gate refuses to seal an absolute subject name at all', () => {
  const s = scenario();
  try {
    for (const name of ['/etc/passwd', 'C:/Windows/win.ini']) {
      assert.throws(() => buildProvenanceRecord({
        context: s.record.context,
        statement: { ...s.record.statement, subject: [{ digest: { sha256: '0'.repeat(64) }, name }] },
        toolchain: s.record.toolchain,
      }), /absolute path/i, `${name} was sealed`);
    }
  } finally { removeTemp(s.dir); }
});

test('a hand-built subject name that escapes the artefact root is refused, not read', () => {
  const s = scenario();
  try {
    // Hand-built, because `buildProvenanceRecord` will not seal an absolute
    // path — which is the point of the test above. An attacker writes the JSON
    // themselves and is under no such constraint, so the verifier cannot rely on
    // the generator's gate having run.
    for (const name of ['../outside', '/etc/passwd', 'C:/Windows/win.ini', 'a/../../b']) {
      const record = {
        recordVersion: 'provenance-record-v0',
        component: 'provenance',
        statement: { ...s.record.statement, subject: [{ digest: { sha256: '0'.repeat(64) }, name }] },
        toolchain: s.record.toolchain,
        contextDigest: contextDigest(s.record.context),
        context: s.record.context,
      };
      record.evidenceDigest = evidenceDigest(record);
      const envelope = resign(record, s.pair);
      const { findings } = verifyProvenance({
        artifactRoot: s.dir, envelope, record, trustedPublicKey: s.pair.publicKey,
      });
      assert.ok(findings.some((f) => f.id === ART.SUBJECT_BYTES_DIFFER && /absolute or climbs out/.test(f.detail)),
        `${name}: ${JSON.stringify(ids(findings))}`);
    }
  } finally { removeTemp(s.dir); }
});

test('NOT_OBSERVED is reported for every check the caller gave the verifier no way to make', () => {
  const s = scenario();
  try {
    const { checks } = verifyProvenance({ envelope: s.envelope, record: s.record, trustedPublicKey: s.pair.publicKey });
    const notObserved = checks.filter((c) => c.state === 'NOT_OBSERVED').map((c) => c.name).sort();
    assert.deepEqual(notObserved, ['commit-matches-checkout', 'subject-bytes', 'toolchain-matches-pin']);
    assert.ok(checks.every((c) => c.state !== 'LOST' && c.state !== 'REINTRODUCED'),
      'a single observation point cannot produce LOST or REINTRODUCED');
  } finally { removeTemp(s.dir); }
});

test('a file that is not a provenance record is refused before any field is read', () => {
  const s = scenario();
  try {
    const { checks, findings } = verifyProvenance({
      envelope: s.envelope, record: { hello: 'world' }, trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(ids(findings), [ART.RECORD_MALFORMED]);
    assert.equal(checks.length, 1);
    assert.equal(exitCodeFor({ checks, findings }), EXIT_INTEGRITY);
  } finally { removeTemp(s.dir); }
});

test('a statement missing a required SLSA field is a finding, not a crash', () => {
  const s = scenario();
  try {
    const stripped = JSON.parse(JSON.stringify(s.record.statement));
    delete stripped.predicate.builder;
    delete stripped.predicate.invocation.configSource.digest;
    assert.ok(statementProblems(stripped).length >= 2);
    const resealed = buildProvenanceRecord({
      context: s.record.context, statement: stripped, toolchain: s.record.toolchain,
    });
    const envelope = resign(resealed, s.pair);
    const { checks, findings } = verifyProvenance({
      envelope, record: resealed, trustedPublicKey: s.pair.publicKey,
    });
    assert.deepEqual(ids(findings), [ART.STATEMENT_INCOMPLETE]);
    assert.equal(exitCodeFor({ checks, findings }), EXIT_FINDINGS);
  } finally { removeTemp(s.dir); }
});
