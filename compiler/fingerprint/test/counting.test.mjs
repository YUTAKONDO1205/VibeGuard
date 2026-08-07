// The counting contract, and the proof that an empty scan cannot report a
// clean one.
//
// The unit tests below pin the rule; the two spawn tests at the end run the
// real CLI against a real empty directory, because a rule that only holds in
// the function it was written in is the rule that got skipped three times.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { EXIT, reportCounts, skipAuthorised, SKIP_ENV } from '../lib/count.mjs';
import { PKG, TESTDATA } from './helpers.mjs';

const FP = join(PKG, 'cli', 'fp.mjs');

function capture() {
  const lines = [];
  return { lines, out: (s) => lines.push(s) };
}

test('a normal count prints the mandatory line and passes', () => {
  const c = capture();
  assert.equal(reportCounts({ inputs: 3, checked: 3, skipped: 0, out: c.out }), EXIT.OK);
  assert.equal(c.lines[0], 'inputs=3 checked=3 skipped=0');
});

test('zero inputs is INCOMPLETE, never OK', () => {
  const c = capture();
  assert.equal(reportCounts({ inputs: 0, checked: 0, skipped: 0, out: c.out }), EXIT.INCOMPLETE);
  assert.equal(c.lines[0], 'inputs=0 checked=0 skipped=0');
});

test('zero inputs is OK only when the caller said an empty set was expected', () => {
  const c = capture();
  assert.equal(reportCounts({
    inputs: 0, checked: 0, skipped: 0, allowEmpty: true, out: c.out,
  }), EXIT.OK);
});

test('a skip must name every case, or the run is INCOMPLETE', () => {
  const c = capture();
  assert.equal(reportCounts({
    inputs: 2, checked: 1, skipped: 1, skippedNames: [], out: c.out,
  }), EXIT.INCOMPLETE);

  const d = capture();
  assert.equal(reportCounts({
    inputs: 2, checked: 1, skipped: 1, skippedNames: ['b.ll (no definitions)'], out: d.out,
  }), EXIT.OK);
  assert.equal(d.lines.some((l) => l.includes('b.ll (no definitions)')), true);
});

test('the accounting has to close', () => {
  const c = capture();
  assert.equal(reportCounts({
    inputs: 5, checked: 2, skipped: 1, skippedNames: ['x.ll'], out: c.out,
  }), EXIT.INCOMPLETE);
  assert.equal(c.lines.some((l) => l.includes('accounting does not close')), true);
});

test('counts must be non-negative integers', () => {
  assert.throws(() => reportCounts({ inputs: 1.5, checked: 1, skipped: 0, out: () => {} }), TypeError);
  assert.throws(() => reportCounts({ inputs: -1, checked: 0, skipped: 0, out: () => {} }), TypeError);
});

test('only the environment variable authorises a skip', () => {
  assert.equal(skipAuthorised({}), false);
  assert.equal(skipAuthorised({ [SKIP_ENV]: '0' }), false);
  assert.equal(skipAuthorised({ [SKIP_ENV]: 'yes' }), false);
  assert.equal(skipAuthorised({ [SKIP_ENV]: '1' }), true);
});

// ── the empty-scan proof, against the real CLI ──────────────────────────────

test('EMPTY SCAN: the CLI against an empty directory exits 3, not 0', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-empty-'));
  try {
    const r = spawnSync(process.execPath, [FP, '--dir', dir], { encoding: 'utf8' });
    assert.equal(r.stdout.includes('inputs=0 checked=0 skipped=0'), true, r.stdout);
    assert.equal(r.status, EXIT.INCOMPLETE, `exit was ${r.status}\n${r.stdout}${r.stderr}`);
    assert.notEqual(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('EMPTY SCAN: --allow-empty is the only way to make it 0, and it is explicit', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-empty-'));
  try {
    const r = spawnSync(process.execPath, [FP, '--dir', dir, '--allow-empty'], { encoding: 'utf8' });
    assert.equal(r.status, EXIT.OK, `${r.stdout}${r.stderr}`);
    assert.equal(r.stdout.includes('inputs=0 checked=0 skipped=0'), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// This test used to assert EXIT.OK here, and that assertion was the bug rather
// than a description of one. `inputs=1 checked=0 skipped=1` is a run that
// fingerprinted nothing: the emptiness moved out of the input set and into the
// checked set, and the `inputs === 0` guard cannot see it there. Returning 0
// for it says "scanned, nothing wrong" about a scan that did not happen, which
// is the exact conflation the counting contract exists to forbid.
//
// Found by an adversarial pass over this package and reproduced by hand: three
// .ll files containing ordinary prose gave `inputs=3 checked=0 skipped=3` and
// exit 0.
test('a directory whose .ll files define nothing is INCOMPLETE, not a clean scan', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-nodefs-'));
  try {
    writeFileSync(join(dir, 'empty.ll'), 'declare void @a()\n', 'utf8');
    const r = spawnSync(process.execPath, [FP, '--dir', dir], { encoding: 'utf8' });
    assert.equal(r.stdout.includes('inputs=1 checked=0 skipped=1'), true, r.stdout);
    assert.equal(r.stdout.includes('empty.ll (no function definitions)'), true, r.stdout);
    assert.equal(r.status, EXIT.INCOMPLETE, r.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// The other direction. `--allow-empty` is the caller stating on the record that
// measuring nothing was the expected outcome, so it may buy a 0 — but it has to
// be asked for, and asking for it is visible in the command line.
test('...unless --allow-empty was asked for, which puts the claim on the record', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-fp-nodefs-ok-'));
  try {
    writeFileSync(join(dir, 'empty.ll'), 'declare void @a()\n', 'utf8');
    const r = spawnSync(process.execPath, [FP, '--dir', dir, '--allow-empty'], { encoding: 'utf8' });
    assert.equal(r.stdout.includes('inputs=1 checked=0 skipped=1'), true, r.stdout);
    assert.equal(r.status, EXIT.OK, r.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the CLI on the tracked testdata reports a non-zero input count and exits 0', () => {
  const r = spawnSync(process.execPath, [FP, '--dir', TESTDATA], { encoding: 'utf8' });
  const m = /inputs=(\d+) checked=(\d+) skipped=(\d+)/.exec(r.stdout);
  assert.notEqual(m, null, r.stdout);
  assert.equal(Number(m[1]) > 0, true);
  assert.equal(Number(m[1]), Number(m[2]) + Number(m[3]));
  assert.equal(r.status, EXIT.OK, `${r.stdout}${r.stderr}`);
});

test('a directory that does not exist is a tool failure, not an empty scan', () => {
  const r = spawnSync(process.execPath, [FP, '--dir', join(tmpdir(), 'vg-fp-no-such-dir-xyz')], { encoding: 'utf8' });
  assert.equal(r.status, EXIT.TOOL_FAILED, `${r.stdout}${r.stderr}`);
});

test('an unknown --without step is refused rather than silently ignored', () => {
  const r = spawnSync(process.execPath, [FP, '--dir', TESTDATA, '--without', 'not-a-step'], { encoding: 'utf8' });
  assert.equal(r.status, EXIT.TOOL_FAILED);
  assert.equal(r.stderr.includes('not a step'), true);
});
