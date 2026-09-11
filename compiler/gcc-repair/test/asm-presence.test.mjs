// Unit tests for scripts/lib/asm-presence.mjs: the reading the fixture-loop
// checker takes of each listing. Synthetic listings only; nothing is compiled.
//
//   node --test compiler/gcc-repair/test/asm-presence.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readEffect, repStosZeroFill, readLab, EFFECT } from '../scripts/lib/asm-presence.mjs';

const fnAsm = (name, body) =>
  [`\t.globl\t${name}`, `\t.type\t${name}, @function`, `${name}:`, ...body.map((l) => `\t${l}`),
    `\t.size\t${name}, .-${name}`, ''].join('\n');

test('the effect is ablation-cell.mjs\'s CONTROL_EFFECT, imported', () => {
  assert.deepEqual(EFFECT, { symbols: ['memset', '__memset_chk'], allowInlineZeroStore: true });
});

test('a memset call is PRESENT through the oracle', () => {
  const asm = fnAsm('handle_request', ['call\tget_secret@PLT', 'call\tmemset@PLT', 'ret']);
  assert.deepEqual(readEffect(asm, 'handle_request'), { verdict: 'PRESENT', via: 'oracle', evidence: 1, reason: null });
});

test('the -O2 zero-fill form (pxor + movaps) is PRESENT through the oracle', () => {
  const asm = fnAsm('handle_request', ['call\tconsume@PLT', 'pxor\t%xmm0, %xmm0', 'movaps\t%xmm0, (%rsp)',
    'movaps\t%xmm0, 16(%rsp)', 'ret']);
  const r = readEffect(asm, 'handle_request');
  assert.equal(r.verdict, 'PRESENT');
  assert.equal(r.via, 'oracle');
  assert.equal(r.evidence, 2);
});

test('the -Os form (xorl + rep stosl) is PRESENT only through the labelled fallback', () => {
  const asm = fnAsm('wipe_kept', ['call\tget_secret@PLT', 'xorl\t%eax, %eax', 'movl\t$8, %ecx', 'rep stosl',
    'call\tconsume@PLT', 'ret']);
  assert.equal(repStosZeroFill(asm, 'wipe_kept'), true);
  assert.deepEqual(readEffect(asm, 'wipe_kept'), { verdict: 'PRESENT', via: 'rep-stos-fallback', evidence: 1, reason: null });
});

test('rep stos without a zeroed eax first is not a zero fill', () => {
  const asm = fnAsm('f', ['movl\t$1, %eax', 'rep stosl', 'ret']);
  assert.equal(repStosZeroFill(asm, 'f'), false);
  assert.equal(readEffect(asm, 'f').verdict, 'ABSENT');
});

test('a body with no wipe is ABSENT, and an unreadable one NOT_OBSERVED', () => {
  const asm = fnAsm('handle_request', ['call\tget_secret@PLT', 'call\tconsume@PLT', 'ret']);
  assert.deepEqual(readEffect(asm, 'handle_request'), { verdict: 'ABSENT', via: 'oracle', evidence: 0, reason: null });
  const missing = readEffect(asm, 'wipe_kept');
  assert.equal(missing.verdict, 'NOT_OBSERVED');
  assert.equal(missing.via, null);
  assert.match(missing.reason, /function-body-not-delimited/);
});

test('an argument set-up to zero is not a wipe (the oracle\'s own rule)', () => {
  const asm = fnAsm('g', ['movl\t$0, %esi', 'call\tuse@PLT', 'ret']);
  assert.equal(readEffect(asm, 'g').verdict, 'ABSENT');
});

test('readLab reads every listing, with its sha256', () => {
  const lab = mkdtempSync(join(tmpdir(), 'wpg-asm-'));
  try {
    mkdirSync(join(lab, 'asm'));
    const both = fnAsm('handle_request', ['call\tmemset@PLT', 'ret']) + fnAsm('wipe_kept', ['call\tmemset@PLT', 'ret']);
    const lost = fnAsm('handle_request', ['ret']) + fnAsm('wipe_kept', ['call\tmemset@PLT', 'ret']);
    writeFileSync(join(lab, 'asm', 'pin-O2.s'), both);
    writeFileSync(join(lab, 'asm', 'base-O2.s'), lost);
    writeFileSync(join(lab, 'asm', 'notes.txt'), 'not a listing');
    const cells = readLab(lab, 'handle_request', 'wipe_kept');
    assert.deepEqual(Object.keys(cells), ['base-O2', 'pin-O2']);
    assert.equal(cells['base-O2'].subject.verdict, 'ABSENT');
    assert.equal(cells['pin-O2'].subject.verdict, 'PRESENT');
    assert.equal(cells['base-O2'].control.verdict, 'PRESENT');
    assert.match(cells['pin-O2'].sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(cells['pin-O2'].sha256, cells['base-O2'].sha256);
  } finally {
    rmSync(lab, { recursive: true, force: true });
  }
});
