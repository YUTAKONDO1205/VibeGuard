// The executables, run as executables.
//
// THE COUNTING CONTRACT IS TESTED FIRST AND AGAINST AN EMPTY DIRECTORY
//
//   An empty scan reporting exit 0 has happened in this repository three times.
//   Every runner here prints `inputs=N checked=N skipped=S` and exits non-zero
//   when N is 0. The proof is below, and it is run against a directory that
//   really is empty rather than against a mocked one.

import { strict as assert } from 'node:assert';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_INTEGRITY, EXIT_OK } from '../../driver/lib/exit.mjs';
import { TOOLS, fakeCommit, makeTemp, removeTemp, writeFakePin } from './helpers.mjs';

const COMMIT = fakeCommit('a');

function node(tool, argv, opts = {}) {
  const r = spawnSync(process.execPath, [tool, ...argv], { encoding: 'utf8', ...opts });
  return { out: `${r.stdout ?? ''}${r.stderr ?? ''}`, status: r.status, stdout: r.stdout ?? '' };
}

function counts(text) {
  const m = /inputs=(\d+) checked=(\d+) skipped=(\d+)/.exec(text);
  return m === null ? null : { checked: Number(m[2]), inputs: Number(m[1]), skipped: Number(m[3]) };
}

/** keygen + a pin + one artefact + a signed provenance record. */
function stage(label) {
  const dir = makeTemp(label);
  const keys = join(dir, 'keys');
  const kg = node(TOOLS.keygen, ['--dir', keys]);
  assert.equal(kg.status, EXIT_OK, kg.out);
  const pin = writeFakePin(dir).path;
  mkdirSync(join(dir, 'out'), { recursive: true });
  writeFileSync(join(dir, 'out', 'app'), 'the artefact bytes\n');
  writeFileSync(join(dir, 'src.c'), 'int main(void){return 0;}\n');
  const record = join(dir, 'records', 'provenance.json');
  const mk = node(TOOLS.makeProvenance, [
    '--artifact-root', dir,
    '--subject', 'out/app',
    '--source', 'src.c',
    '--pin', pin,
    '--commit', COMMIT,
    '--out', record,
    '--key', join(keys, 'signing-key.pem'),
    '--build-param', 'cflags=-O2',
  ]);
  assert.equal(mk.status, EXIT_OK, mk.out);
  return {
    dir,
    pin,
    publicKey: join(keys, 'signing-key.pub.pem'),
    privateKey: join(keys, 'signing-key.pem'),
    record,
    signature: join(dir, 'records', 'provenance.sig.json'),
  };
}

// ── the counting contract ───────────────────────────────────────────────────

test('EMPTY SCAN: verify-provenance over an empty directory exits 3 and says inputs=0', () => {
  const s = stage('empty-verify');
  const empty = join(s.dir, 'nothing-here');
  mkdirSync(empty, { recursive: true });
  try {
    const r = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--dir', empty]);
    assert.deepEqual(counts(r.out), { checked: 0, inputs: 0, skipped: 0 });
    assert.equal(r.status, EXIT_INCOMPLETE, r.out);
    assert.match(r.out, /An empty run is not a clean run/);
  } finally { removeTemp(s.dir); }
});

test('EMPTY SCAN: --allow-empty is the only way to get 0 out of an empty directory', () => {
  const s = stage('empty-allow');
  const empty = join(s.dir, 'nothing-here');
  mkdirSync(empty, { recursive: true });
  try {
    const r = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--dir', empty, '--allow-empty']);
    assert.deepEqual(counts(r.out), { checked: 0, inputs: 0, skipped: 0 });
    assert.equal(r.status, EXIT_OK, r.out);
    assert.match(r.out, /proves nothing about anything/);
  } finally { removeTemp(s.dir); }
});

test('EMPTY SCAN: sign-evidence over an empty directory exits 3 as well', () => {
  const s = stage('empty-sign');
  const empty = join(s.dir, 'nothing-here');
  mkdirSync(empty, { recursive: true });
  try {
    const r = node(TOOLS.signEvidence, ['--key', s.privateKey, '--dir', empty]);
    assert.deepEqual(counts(r.out), { checked: 0, inputs: 0, skipped: 0 });
    assert.equal(r.status, EXIT_INCOMPLETE, r.out);
  } finally { removeTemp(s.dir); }
});

test('EMPTY SCAN: rebuild-compare with no case selected cannot report success', () => {
  const s = stage('empty-rebuild');
  try {
    // `--case` matching nothing is refused up front; selecting none is what an
    // empty input set looks like here, and it is reachable through the filter.
    const r = node(TOOLS.rebuildCompare, ['--work', join(s.dir, 'w'), '--case', 'no-such-case']);
    assert.notEqual(r.status, EXIT_OK, r.out);
    assert.match(r.out, /no such case/);
  } finally { removeTemp(s.dir); }
});

test('every runner prints the counting line, and the counts add up', () => {
  const s = stage('counting');
  try {
    const v = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record]);
    const c = counts(v.out);
    assert.deepEqual(c, { checked: 1, inputs: 1, skipped: 0 });
    assert.equal(c.checked + c.skipped, c.inputs);
  } finally { removeTemp(s.dir); }
});

// ── the tools, end to end ───────────────────────────────────────────────────

test('make-provenance writes a SLSA-shaped statement and a detached signature', () => {
  const s = stage('shape');
  try {
    const rec = JSON.parse(readFileSync(s.record, 'utf8'));
    assert.equal(rec.recordVersion, 'provenance-record-v0');
    assert.equal(rec.statement._type, 'https://in-toto.io/Statement/v0.1');
    assert.equal(rec.statement.predicateType, 'https://slsa.dev/provenance/v0.2');
    assert.equal(rec.statement.subject.length, 1);
    assert.equal(rec.statement.subject[0].name, 'out/app');
    assert.match(rec.statement.predicate.builder.id, /^urn:/);
    assert.equal(rec.statement.predicate.invocation.configSource.digest.sha1, COMMIT);
    assert.ok(rec.statement.predicate.materials.length >= 2);
    assert.match(rec.evidenceDigest, /^[0-9a-f]{64}$/);
    assert.match(rec.contextDigest, /^[0-9a-f]{64}$/);

    assert.ok(existsSync(s.signature));
    const sig = JSON.parse(readFileSync(s.signature, 'utf8'));
    assert.equal(sig.sigVersion, 'detached-sig-v0');
    assert.equal(sig.algorithm, 'ed25519');
    assert.match(sig.keyId, /^[0-9a-f]{64}$/);
  } finally { removeTemp(s.dir); }
});

test('make-provenance refuses to write a record naming a file it could not read', () => {
  const s = stage('missing-subject');
  try {
    const out = join(s.dir, 'records', 'missing.json');
    const r = node(TOOLS.makeProvenance, [
      '--artifact-root', s.dir, '--subject', 'out/not-there', '--pin', s.pin,
      '--commit', COMMIT, '--out', out,
    ]);
    assert.equal(r.status, EXIT_INCOMPLETE, r.out);
    assert.equal(existsSync(out), false, 'no record may be written when a named file was unreadable');
    assert.match(r.out, /no record was written/);
  } finally { removeTemp(s.dir); }
});

test('verify-provenance with everything supplied exits 0 and observes every check', () => {
  const s = stage('clean');
  try {
    const r = node(TOOLS.verifyProvenance, [
      '--public-key', s.publicKey, '--record', s.record,
      '--pin', s.pin, '--expect-commit', COMMIT, '--artifact-root', s.dir, '--strict',
    ]);
    assert.equal(r.status, EXIT_OK, r.out);
    assert.match(r.out, /verdict=ok \(0\)/);
    assert.ok(!/NOT_OBSERVED/.test(r.out), r.out);
  } finally { removeTemp(s.dir); }
});

test('verify-provenance refuses to run without a trust anchor', () => {
  const s = stage('no-key');
  try {
    const r = node(TOOLS.verifyProvenance, ['--record', s.record]);
    assert.equal(r.status, EXIT_INCOMPLETE, r.out);
    assert.match(r.out, /--public-key <file> is required/);
  } finally { removeTemp(s.dir); }
});

test('the commit sha edited on disk fails verification — exit 4', () => {
  const s = stage('tamper-commit');
  try {
    const rec = JSON.parse(readFileSync(s.record, 'utf8'));
    rec.statement.predicate.invocation.configSource.digest.sha1 = fakeCommit('b');
    writeFileSync(s.record, `${JSON.stringify(rec, null, 2)}\n`, 'utf8');
    const r = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record]);
    assert.equal(r.status, EXIT_INTEGRITY, r.out);
    assert.match(r.out, /VG-ART-120/);
    assert.match(r.out, /verdict=integrity \(4\)/);
  } finally { removeTemp(s.dir); }
});

test('the toolchain digest edited on disk fails verification — exit 4', () => {
  const s = stage('tamper-toolchain');
  try {
    const rec = JSON.parse(readFileSync(s.record, 'utf8'));
    const m = rec.statement.predicate.materials.find((x) => x.uri === 'urn:vibeguard:material:toolchain-pin');
    m.digest.sha256 = 'f'.repeat(64);
    writeFileSync(s.record, `${JSON.stringify(rec, null, 2)}\n`, 'utf8');
    const r = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record, '--pin', s.pin]);
    assert.equal(r.status, EXIT_INTEGRITY, r.out);
    assert.match(r.out, /VG-ART-120/);
    assert.match(r.out, /VG-CFG-030/);
  } finally { removeTemp(s.dir); }
});

test('a record re-signed by a different key is refused — exit 4', () => {
  const s = stage('rogue-key');
  const rogueDir = join(s.dir, 'rogue');
  try {
    assert.equal(node(TOOLS.keygen, ['--dir', rogueDir]).status, EXIT_OK);
    const rs = node(TOOLS.signEvidence, ['--key', join(rogueDir, 'signing-key.pem'), '--record', s.record]);
    assert.equal(rs.status, EXIT_OK, rs.out);
    const r = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record]);
    assert.equal(r.status, EXIT_INTEGRITY, r.out);
    assert.match(r.out, /VG-ART-122/);
  } finally { removeTemp(s.dir); }
});

test('an artefact byte flipped under a valid record is a finding — exit 2', () => {
  const s = stage('artefact');
  try {
    writeFileSync(join(s.dir, 'out', 'app'), 'the artefact bytes!\n');
    const r = node(TOOLS.verifyProvenance, [
      '--public-key', s.publicKey, '--record', s.record, '--artifact-root', s.dir,
    ]);
    assert.equal(r.status, EXIT_FINDINGS, r.out);
    assert.match(r.out, /VG-ART-126/);
  } finally { removeTemp(s.dir); }
});

test('--strict turns a check nobody made into exit 3, and the plain run lists it', () => {
  const s = stage('strict');
  try {
    const plain = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record]);
    assert.equal(plain.status, EXIT_OK, plain.out);
    assert.match(plain.out, /not-observed=3/);
    assert.match(plain.out, /Those are checks nobody made/);

    const strict = node(TOOLS.verifyProvenance, ['--public-key', s.publicKey, '--record', s.record, '--strict']);
    assert.equal(strict.status, EXIT_INCOMPLETE, strict.out);
  } finally { removeTemp(s.dir); }
});

test('keygen refuses to overwrite a key without --force, and writes no key to the source tree', () => {
  const s = stage('keygen');
  try {
    const again = node(TOOLS.keygen, ['--dir', join(s.dir, 'keys')]);
    assert.equal(again.status, EXIT_INCOMPLETE, again.out);
    assert.match(again.out, /invalidates every/);
    const forced = node(TOOLS.keygen, ['--dir', join(s.dir, 'keys'), '--force']);
    assert.equal(forced.status, EXIT_OK, forced.out);
  } finally { removeTemp(s.dir); }
});

test('sign-evidence --skip-signed names every skip instead of counting it silently', () => {
  const s = stage('skip-named');
  try {
    const r = node(TOOLS.signEvidence, [
      '--key', s.privateKey, '--dir', join(s.dir, 'records'), '--skip-signed',
    ]);
    assert.deepEqual(counts(r.out), { checked: 0, inputs: 1, skipped: 1 });
    assert.match(r.out, /skipped: provenance\.json \(already signed/);
    assert.equal(r.status, EXIT_OK, r.out);
  } finally { removeTemp(s.dir); }
});

test('rebuild-compare fails rather than skips when the compiler is absent', () => {
  const s = stage('no-compiler');
  try {
    const env = { ...process.env };
    delete env.PROVENANCE_ALLOW_MISSING_TOOLS;
    const r = node(TOOLS.rebuildCompare, ['--work', join(s.dir, 'w'), '--cc', 'clang-does-not-exist-18'], { env });
    assert.equal(r.status, EXIT_INCOMPLETE, r.out);
    assert.match(r.out, /That is a failure, not a skip/);
  } finally { removeTemp(s.dir); }
});

test('rebuild-compare turns that into a NAMED skip only when the environment authorises it', () => {
  const s = stage('authorised-skip');
  try {
    const r = node(TOOLS.rebuildCompare, [
      '--work', join(s.dir, 'w'), '--cc', 'clang-does-not-exist-18', '--case', 'same-path-clean',
    ], { env: { ...process.env, PROVENANCE_ALLOW_MISSING_TOOLS: '1' } });
    assert.deepEqual(counts(r.out), { checked: 0, inputs: 1, skipped: 1 });
    assert.match(r.out, /skipped: same-path-clean \(clang-does-not-exist-18 is not installed/);
  } finally { removeTemp(s.dir); }
});
