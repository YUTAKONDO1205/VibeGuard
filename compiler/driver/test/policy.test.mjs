import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { validate } from '../lib/jsonschema.mjs';
import {
  COMPILER_DIR, failOnIncomplete, findPolicyFile, loadPolicy, requireDigestMatch,
} from '../lib/policy.mjs';
import { makeScratch } from './helpers.mjs';

const MINIMAL = { policyVersion: 'policy-v0', failOn: 'high' };

function fixture(policy, { name = '.vgpolicy.json' } = {}) {
  const dir = makeScratch('policy');
  mkdirSync(join(dir, 'a', 'b'), { recursive: true });
  writeFileSync(join(dir, name), typeof policy === 'string' ? policy : JSON.stringify(policy), 'utf8');
  return dir;
}

test('the policy is found by searching upward from the working directory', () => {
  const dir = fixture(MINIMAL);
  assert.equal(findPolicyFile(join(dir, 'a', 'b')), join(dir, '.vgpolicy.json'));
});

test('searching upward terminates at the filesystem root instead of looping', () => {
  const dir = makeScratch('policy-none');
  assert.equal(findPolicyFile(dir), null);
});

test('a policy that is not JSON does not load', () => {
  const dir = fixture('{ not json');
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'not-json');
});

test('a policy that breaks the schema does not load, and the error names the field', () => {
  const dir = fixture({ policyVersion: 'policy-v0', failOn: 'catastrophic' });
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'schema-invalid');
  assert.match(r.detail, /failOn/);
});

test('an unknown top-level key is rejected rather than ignored', () => {
  const dir = fixture({ ...MINIMAL, failClosed: true });
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
  assert.match(r.detail, /failClosed/);
});

test('a plugin entry without a digest is rejected — a name is not an identity', () => {
  const dir = fixture({
    ...MINIMAL,
    toolchain: { allowedPassPlugins: [{ name: 'libPropertyObserver.so' }] },
  });
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
  assert.match(r.detail, /sha256/);
});

test('a plugin digest that is not 64 hex characters is rejected', () => {
  const dir = fixture({
    ...MINIMAL,
    toolchain: { allowedPassPlugins: [{ name: 'x.so', sha256: 'DEADBEEF' }] },
  });
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
});

test('evidence.out that resolves inside compiler/ is refused', () => {
  const dir = fixture({ ...MINIMAL, evidence: { out: COMPILER_DIR } });
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'evidence-out-inside-compiler');
});

test('a valid policy loads, is digested, and its defaults are the schema defaults', () => {
  const dir = fixture(MINIMAL);
  const r = loadPolicy({ cwd: dir });
  assert.equal(r.ok, true);
  assert.match(r.sha256, /^[0-9a-f]{64}$/);
  assert.equal(failOnIncomplete(r.policy), true);
  assert.equal(requireDigestMatch(r.policy), true);
});

test('--policy overrides the upward search', () => {
  const dir = fixture(MINIMAL, { name: 'other.json' });
  const r = loadPolicy({ cwd: dir, policyPath: 'other.json' });
  assert.equal(r.ok, true);
});

test('the validator refuses a schema keyword it does not implement', () => {
  // A silently ignored keyword is a policy field nobody checks.
  const errors = validate({ type: 'object', properties: { a: { type: 'string', minLength: 3 } } }, { a: 'xy' });
  assert.equal(errors.length, 1);
  assert.match(errors[0].message, /unsupported keyword/);
});
