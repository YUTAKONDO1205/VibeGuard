// The SLSA shape, and the record rules it has to live inside.

import { strict as assert } from 'node:assert';
import test from 'node:test';

import { canonicalJson } from '../../evidence/canon.mjs';
import { findAbsolutePaths } from '../../evidence/paths.mjs';
import { buildProvenanceRecord, recordProblems } from '../lib/record.mjs';
import {
  PREDICATE_TYPE, STATEMENT_TYPE, TOOLCHAIN_MATERIAL_URI,
  buildStatement, recordedCommitSha, recordedToolchainDigest, statementProblems, subjects,
} from '../lib/statement.mjs';
import { declaredToolchainDigest } from '../lib/pin.mjs';
import { makeTemp, removeTemp, writeFakePin, fakeCommit } from './helpers.mjs';

function good() {
  return buildStatement({
    commitSha: fakeCommit('a'),
    environment: { arch: 'x64', platform: 'linux', sourceDateEpoch: 1700000000 },
    materials: [{ sha256: 'c'.repeat(64), uri: 'urn:vibeguard:material:source:src/wipe.c' }],
    parameters: { cflags: '-O2 -g' },
    subjects: [{ name: 'out/app', sha256: 'b'.repeat(64) }],
    toolchainDigest: 'd'.repeat(64),
  });
}

test('NEGATIVE FIXTURE: a complete statement has no problems', () => {
  assert.deepEqual(statementProblems(good()), []);
});

test('the four required things are where SLSA v0.2 puts them', () => {
  const st = good();
  assert.equal(st._type, STATEMENT_TYPE);
  assert.equal(st.predicateType, PREDICATE_TYPE);
  assert.deepEqual(subjects(st), [{ name: 'out/app', sha256: 'b'.repeat(64) }]);
  assert.match(st.predicate.builder.id, /^urn:/);
  assert.equal(recordedCommitSha(st), fakeCommit('a'));
  assert.equal(recordedToolchainDigest(st), 'd'.repeat(64));
  assert.equal(st.predicate.materials[0].uri, TOOLCHAIN_MATERIAL_URI);
});

test('POSITIVE FIXTURES: each required field missing is reported, and all of them at once', () => {
  const cases = [
    ['_type', (s) => { s._type = 'nope'; }],
    ['predicateType', (s) => { s.predicateType = 'nope'; }],
    ['subject', (s) => { s.subject = []; }],
    ['subject digest', (s) => { s.subject[0].digest.sha256 = 'short'; }],
    ['builder', (s) => { delete s.predicate.builder; }],
    ['buildType', (s) => { delete s.predicate.buildType; }],
    ['invocation', (s) => { delete s.predicate.invocation; }],
    ['commit sha', (s) => { s.predicate.invocation.configSource.digest.sha1 = 'nope'; }],
    ['materials', (s) => { s.predicate.materials = []; }],
    ['the toolchain material', (s) => { s.predicate.materials = [{ digest: { sha256: 'a'.repeat(64) }, uri: 'urn:other' }]; }],
    ['reproducible', (s) => { s.predicate.metadata.reproducible = 'maybe'; }],
  ];
  for (const [what, mutate] of cases) {
    const st = good();
    mutate(st);
    assert.ok(statementProblems(st).length > 0, `${what} was accepted`);
  }
  const empty = good();
  delete empty.predicate.builder;
  delete empty.predicate.buildType;
  empty.subject = [];
  assert.ok(statementProblems(empty).length >= 3, 'every problem is reported, not just the first');
});

test('reproducible is true, false, or null — and null is not false', () => {
  assert.equal(good().predicate.metadata.reproducible, null, 'not observed by default');
  assert.deepEqual(statementProblems(buildStatement({
    commitSha: fakeCommit('a'), reproducible: true, subjects: [{ name: 'a', sha256: 'b'.repeat(64) }],
    toolchainDigest: 'd'.repeat(64), environment: { platform: 'linux' }, parameters: { x: 'y' },
  })), []);
});

test('a sealed record carries no absolute path and no non-integer number', () => {
  const record = buildProvenanceRecord({
    statement: good(),
    toolchain: { clang: '18.1.3', digest: 'd'.repeat(64), packages: [] },
  });
  assert.deepEqual(recordProblems(record), []);
  assert.deepEqual(findAbsolutePaths(record), []);
  // The canonicaliser is the authority on the integer rule; if a float had got
  // in, sealing would already have thrown.
  assert.ok(canonicalJson(record).length > 0);
});

test('the gate refuses a record that carries an absolute path, before it is digested', () => {
  const st = good();
  st.predicate.invocation.parameters.workdir = 'C:/Users/somebody/build';
  assert.throws(
    () => buildProvenanceRecord({ statement: st, toolchain: { clang: null, digest: 'd'.repeat(64), packages: [] } }),
    /absolute path/i,
  );
});

test('the toolchain digest is a function of the pin and changes when the pin does', () => {
  const dir = makeTemp('pin');
  try {
    const a = writeFakePin(dir, { bump: 0, name: 'a.json' }).pin;
    const b = writeFakePin(dir, { bump: 1, name: 'b.json' }).pin;
    const c = writeFakePin(dir, { bump: 0, name: 'c.json' }).pin;
    assert.equal(declaredToolchainDigest(a), declaredToolchainDigest(c), 'the same pin gives the same digest');
    assert.notEqual(declaredToolchainDigest(a), declaredToolchainDigest(b), 'a different pin gives a different one');
    assert.match(declaredToolchainDigest(a), /^[0-9a-f]{64}$/);
  } finally { removeTemp(dir); }
});

test('recordProblems catches a file that is JSON but not one of these', () => {
  assert.ok(recordProblems({ hello: 'world' }).length >= 4);
  assert.ok(recordProblems(null).length === 1);
  assert.ok(recordProblems([1, 2]).length === 1);
});
