import test from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { loadPin, pinnedSet, resolveCompiler, verifyPin } from '../lib/toolchain.mjs';
import { CLANG, liveBuildSkipReason, makePin, makeScratch, sha256File } from './helpers.mjs';

function writePin(pin) {
  const dir = makeScratch('pin');
  const p = join(dir, 'toolchain.pin.json');
  writeFileSync(p, typeof pin === 'string' ? pin : JSON.stringify(pin), 'utf8');
  return p;
}

test('a pin with the wrong version does not load', () => {
  const r = loadPin(writePin({ pinVersion: 'toolchain-pin-v1', packages: [] }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-version');
});

test('a pin that pins nothing is not a pin', () => {
  const r = loadPin(writePin({ pinVersion: 'toolchain-pin-v0', packages: [] }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-packages');
});

test('a package entry without a well-formed digest does not load', () => {
  const r = loadPin(writePin({
    pinVersion: 'toolchain-pin-v0',
    packages: [{ name: 'clang-18', path: 'usr/bin/clang-18', sha256: 'nope' }],
  }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-package');
});

test('a missing pin file is reported, not treated as an empty pin', () => {
  const r = loadPin(join(makeScratch('pin-missing'), 'absent.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unreadable');
});

test('the installed toolchain matches a pin generated from it', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'match', JSON.stringify(v.mismatches));
  assert.equal(v.reportedClang, pin.clang);
});

test('one changed character in a pinned digest is a mismatch', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const original = pin.packages[0].sha256;
  pin.packages[0].sha256 = flipOneHexChar(original);
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  const m = v.mismatches.find((x) => x.kind === 'digest');
  assert.ok(m, 'expected a digest mismatch');
  assert.equal(m.actual, original);
});

test('a pinned file that is not there is a mismatch of its own kind', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  pin.packages[0].path = 'usr/bin/clang-18-that-does-not-exist';
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  assert.equal(v.mismatches[0].kind, 'missing');
});

test('a version disagreement is a mismatch even when every digest matches', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  pin.clang = '17.0.6';
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  assert.equal(v.mismatches.find((m) => m.kind === 'version').actual, '18.1.3');
});

test('the digested pinned set carries no path', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const set = pinnedSet(pin, verifyPin(pin, { ccPath: CLANG }));
  assert.equal(JSON.stringify(set).includes('/'), false, JSON.stringify(set));
});

test('the compiler comes from the pin when the pin names one', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  assert.equal(resolveCompiler({ mode: 'c', pin, override: null }).source, 'pin');
  assert.equal(resolveCompiler({ mode: 'c', pin: null, override: null }).path, 'clang-18');
  assert.equal(resolveCompiler({ mode: 'cxx', pin: null, override: null }).path, 'clang++-18');
});

function flipOneHexChar(hex) {
  const c = hex[0];
  return (c === '0' ? '1' : '0') + hex.slice(1);
}
