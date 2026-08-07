// (B) `verify.mjs --self-test` over an empty vector file.
//
// REPRODUCED BEFORE IT WAS FIXED. With `{"vectors":[]}` the runner printed
// "vectors: 0/0 reproduced, must-fail: 0/0 refused", the cross-check agreed
// with canon.mjs on all nought vectors, and the process exited 0. Nothing in
// the output was false; the exit code was.
//
// Both directions are here: the empty file must exit 3, and the real vector
// file must still exit 0. A fix that returned 3 unconditionally would pass the
// first test alone, and would take the component's only calibration with it.

import { strict as assert } from 'node:assert';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { cleanup, countingOf, makeScratch, run, VERIFY } from './helpers.mjs';

test('an empty vector file exits 3, not 0', () => {
  const dir = makeScratch('selftest-empty');
  try {
    const f = join(dir, 'empty-vectors.json');
    writeFileSync(f, '{"vectors":[]}\n', 'utf8');
    const r = run(VERIFY, ['--self-test', '--vectors', f]);
    assert.equal(r.status, 3, `expected 3, got ${r.status}\n${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 0, checked: 0, skipped: 0 });
    assert.match(`${r.stdout}${r.stderr}`, /no vector was examined/);
  } finally {
    cleanup(dir);
  }
});

test('a vector file with only must-fail entries is still counted', () => {
  const dir = makeScratch('selftest-half');
  try {
    const f = join(dir, 'half.json');
    writeFileSync(f, JSON.stringify({ vectors: [], mustFail: [{ name: 'a-float', input: { a: 1.5 } }] }), 'utf8');
    const r = run(VERIFY, ['--self-test', '--vectors', f]);
    assert.deepEqual(countingOf(r), { inputs: 1, checked: 1, skipped: 0 });
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  } finally {
    cleanup(dir);
  }
});

test('an empty vector file exits 0 when --allow-empty says it was expected', () => {
  const dir = makeScratch('selftest-allow');
  try {
    const f = join(dir, 'empty-vectors.json');
    writeFileSync(f, '{"vectors":[]}\n', 'utf8');
    const r = run(VERIFY, ['--self-test', '--vectors', f, '--allow-empty']);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 0, checked: 0, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('the real vector file still reproduces and still exits 0', () => {
  const r = run(VERIFY, ['--self-test']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const c = countingOf(r);
  assert.ok(c && c.inputs >= 30, `expected at least 30 vectors, counted ${JSON.stringify(c)}`);
  assert.equal(c.checked, c.inputs);
  assert.equal(c.skipped, 0);
  assert.match(r.stdout, /cross-check: canon\.mjs agrees/);
});

test('a tampered vector still fails, so the counting change did not mask it', () => {
  const dir = makeScratch('selftest-tampered');
  try {
    const f = join(dir, 'tampered.json');
    writeFileSync(
      f,
      JSON.stringify({
        vectors: [{ name: 'wrong-digest', input: { a: 1 }, canonicalText: '{"a":1}', digest: 'f'.repeat(64) }],
      }),
      'utf8',
    );
    const r = run(VERIFY, ['--self-test', '--vectors', f]);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /FAIL wrong-digest/);
    assert.deepEqual(countingOf(r), { inputs: 1, checked: 1, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('the clock audit prints the counting line and still passes here', () => {
  const r = run(VERIFY, ['--clock-audit']);
  const c = countingOf(r);
  assert.ok(c, 'no counting line');
  assert.ok(c.inputs > 0, 'the audit examined nothing');
  assert.equal(c.checked + c.skipped, c.inputs);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
});

test('the clock audit over a directory holding nothing but exemptions exits 3', () => {
  const dir = makeScratch('clock-exempt-only');
  try {
    writeFileSync(join(dir, 'clock.mjs'), 'export const x = 1;\n', 'utf8');
    const r = run(VERIFY, ['--clock-audit', dir]);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 1, checked: 0, skipped: 1 });
  } finally {
    cleanup(dir);
  }
});

test('the clock audit over an empty directory exits 3', () => {
  const dir = makeScratch('clock-empty');
  try {
    const r = run(VERIFY, ['--clock-audit', dir]);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    assert.deepEqual(countingOf(r), { inputs: 0, checked: 0, skipped: 0 });
  } finally {
    cleanup(dir);
  }
});

test('the clock audit still catches a real clock read', () => {
  const dir = makeScratch('clock-dirty');
  try {
    writeFileSync(join(dir, 'stage.mjs'), 'export const t = () => Date.now();\n', 'utf8');
    const r = run(VERIFY, ['--clock-audit', dir]);
    assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
    assert.match(r.stdout, /Date\.now/);
  } finally {
    cleanup(dir);
  }
});
