// The CLI, run as a real subprocess.
//
// THE COUNTING CONTRACT IS TESTED HERE AND NOWHERE ELSE, because it is a
// property of the program's exit, not of any function it calls. An empty scan
// reporting success has happened three times in this repository; the test named
// "an empty directory is exit 3" is what makes it impossible here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { RECIPES } from './synth-elf.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'bin', 'vg-artefact-verify.mjs');

function run(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', ...opts });
  return { status: r.status, out: (r.stdout ?? '') + (r.stderr ?? '') };
}

function scratch() {
  const d = mkdtempSync(join(tmpdir(), 'vg-art-'));
  test.after?.(() => { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } });
  return d;
}

function put(dir, name, recipe) {
  const p = join(dir, name);
  writeFileSync(p, RECIPES[recipe]());
  return p;
}

// ── the counting contract ───────────────────────────────────────────────────

test('every run prints inputs=N checked=N skipped=S', () => {
  const d = scratch();
  put(d, 'a.elf', 'hardened');
  put(d, 'b.elf', 'hardened');
  const r = run([d]);
  assert.match(r.out, /inputs=2 checked=2 skipped=0/);
});

test('an empty directory is NOT a pass: exit 3 with a message saying so', () => {
  const d = scratch();
  const r = run([d]);
  assert.match(r.out, /inputs=0 checked=0 skipped=0/);
  assert.notEqual(r.status, 0, 'an empty scan must never exit 0');
  assert.equal(r.status, 3);
  assert.match(r.out, /nothing was checked/);
});

test('no arguments at all is also exit 3', () => {
  const r = run([]);
  assert.equal(r.status, 3);
  assert.match(r.out, /inputs=0 checked=0 skipped=0/);
});

test('--allow-empty is the only way to make zero inputs succeed, and it still prints the counts', () => {
  const d = scratch();
  const r = run([d, '--allow-empty']);
  assert.equal(r.status, 0);
  assert.match(r.out, /inputs=0 checked=0 skipped=0/);
});

test('a file named on the command line that does not exist is exit 3, not a skip', () => {
  const r = run([join(scratch(), 'no-such-file')]);
  assert.equal(r.status, 3);
  assert.match(r.out, /MISSING/);
});

test('skipped cases are listed by name, and skipping is not passing', () => {
  const d = scratch();
  put(d, 'a.elf', 'hardened');
  writeFileSync(join(d, 'notes.txt'), 'this is not an ELF at all');
  mkdirSync(join(d, 'sub'));
  const r = run([d]);
  assert.match(r.out, /inputs=1 checked=1 skipped=2/);
  assert.match(r.out, /skipped cases, by name:/);
  assert.match(r.out, /notes\.txt — no ELF magic/);
  assert.match(r.out, /sub — directory \(no --recursive\)/);
});

test('--recursive walks into subdirectories and the count follows', () => {
  const d = scratch();
  mkdirSync(join(d, 'sub'));
  put(d, 'a.elf', 'hardened');
  put(join(d, 'sub'), 'b.elf', 'hardened');
  const r = run([d, '--recursive']);
  assert.match(r.out, /inputs=2 checked=2 skipped=0/);
});

test('a named file that is not an ELF is INCOMPLETE, never clean', () => {
  const d = scratch();
  const p = join(d, 'plain.bin');
  writeFileSync(p, Buffer.alloc(4096, 0x41));
  const r = run([p]);
  assert.equal(r.status, 3);
  assert.match(r.out, /unreadable|could not be read/);
});

// ── verdicts through the CLI ────────────────────────────────────────────────

const FULL = 'pie,nx,relro-full,stack-protector,fortify,build-id,no-writable-executable-section,no-debug-path';

test('the hardened artefact exits 0 through the CLI', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const r = run([p, '--require', FULL, '--expect', 'artefact-integrity-control-string']);
  assert.equal(r.status, 0, r.out);
  assert.match(r.out, /pie=PRESENT/);
  assert.match(r.out, /findings=0 incomplete=0/);
});

test('the unhardened artefact exits 2 and names every absent property', () => {
  const d = scratch();
  const p = put(d, 'unhardened', 'unhardened');
  const r = run([p, '--require', FULL, '--quiet']);
  assert.equal(r.status, 2, r.out);
  for (const prop of ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id']) {
    assert.match(r.out, new RegExp(`VG-ART-003.*${prop}`), `${prop} was not reported`);
  }
  assert.match(r.out, /VG-ART-006/);
});

test('a W+X section exits 2 with VG-ART-004', () => {
  const d = scratch();
  const p = put(d, 'wx', 'wx-section');
  const r = run([p, '--require', 'no-writable-executable-section', '--quiet']);
  assert.equal(r.status, 2);
  assert.match(r.out, /VG-ART-004/);
});

test('a forbidden string exits 2 with VG-ART-005', () => {
  const d = scratch();
  const p = put(d, 'clean', 'hardened');
  const r = run([p, '--forbid', 'artefact-integrity-control-string', '--quiet']);
  assert.equal(r.status, 2);
  assert.match(r.out, /VG-ART-005/);
});

test('a control string that is absent turns a would-be clean run into exit 3', () => {
  const d = scratch();
  const p = put(d, 'clean', 'hardened');
  const clean = run([p, '--forbid', 'AKIA', '--expect', 'artefact-integrity-control-string']);
  assert.equal(clean.status, 0, clean.out);
  const broken = run([p, '--forbid', 'AKIA', '--expect', 'a-string-that-is-not-in-there']);
  assert.equal(broken.status, 3, broken.out);
  assert.match(broken.out, /NOT FOUND — extractor is broken/);
});

test('a static image exits 3 rather than claiming the protector is present or absent', () => {
  const d = scratch();
  const p = put(d, 'static', 'static-hardened');
  const r = run([p, '--require', 'stack-protector,fortify']);
  assert.equal(r.status, 3, r.out);
  assert.match(r.out, /stack-protector=NOT_OBSERVED/);
  assert.equal(/VG-ART-003/.test(r.out), false, 'NOT_OBSERVED must not become a finding');
});

// ── policy handling ─────────────────────────────────────────────────────────

test('a policy file is read from the compiler policy shape', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const pol = join(d, 'policy.json');
  writeFileSync(pol, JSON.stringify({
    artifact: {
      require: ['pie', 'nx', 'relro-full', 'build-id'],
      forbidStrings: [],
      expectStrings: ['artefact-integrity-control-string'],
      allowedDynamicDependencies: ['libc.so.6'],
    },
  }));
  const r = run([p, '--policy', pol]);
  assert.equal(r.status, 0, r.out);
});

test('a malformed policy is exit 4, not a pass and not a crash', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const bad = join(d, 'bad.json');
  writeFileSync(bad, '{ this is not json');
  assert.equal(run([p, '--policy', bad]).status, 4);

  const wrong = join(d, 'wrong.json');
  writeFileSync(wrong, JSON.stringify({ artifact: { require: 'pie' } }));
  assert.equal(run([p, '--policy', wrong]).status, 4);

  assert.equal(run([p, '--policy', join(d, 'absent.json')]).status, 4);
});

test('a digest pin that does not match is exit 4, and no VG-ART finding is invented', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const r = run([p, '--pin', '0'.repeat(64)]);
  assert.equal(r.status, 4);
  assert.match(r.out, /DIGEST/);
  assert.equal(/VG-ART-00[12]/.test(r.out), false, 'the digest id belongs to the evidence verifier');
});

test('a digest pin that matches leaves the verdict alone', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const first = run([p]);
  const sha = /sha256 ([0-9a-f]{64})/.exec(first.out)[1];
  assert.equal(run([p, '--pin', sha]).status, 0);
});

test('an unknown option fails loudly instead of being ignored', () => {
  const r = run(['--not-an-option']);
  assert.equal(r.status, 1);
  assert.match(r.out, /unknown option/);
});

test('--json writes the whole record', () => {
  const d = scratch();
  const p = put(d, 'hardened', 'hardened');
  const out = join(d, 'rec.json');
  run([p, '--require', FULL, '--json', out, '--expect', 'artefact-integrity-control-string']);
  const rec = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(rec.inputs, 1);
  assert.equal(rec.checked, 1);
  assert.equal(rec.results.length, 1);
  assert.equal(rec.results[0].observation.properties.pie.state, 'PRESENT');
});
