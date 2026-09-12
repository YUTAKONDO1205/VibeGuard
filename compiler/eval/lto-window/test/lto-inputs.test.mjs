/**
 * Guard 1's first half, tested on bytes rather than on a build.
 *
 * The failure this guards against is silent by construction:
 * `-Wl,--load-pass-plugin=` on a non-LTO link produces no warning, no message
 * and exit 0, so the only thing standing between the lane and a compile-time
 * reading reported as a link-time one is this check. A guard that is never
 * exercised on its failing input is not a guard, so every case below is a way of
 * getting it wrong.
 *
 * No compiler is required and nothing is measured here.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  objectKind, gradeInputs, ltoFormFromBcanalyzerDump, BITCODE_MAGIC, ELF_MAGIC,
} from '../lib/lto-inputs.mjs';

const withMagic = (magic, rest = 16) => Buffer.concat([Buffer.from(magic), Buffer.alloc(rest, 0x41)]);

test('the four kinds are told apart by the first four bytes', () => {
  assert.equal(objectKind(withMagic(BITCODE_MAGIC)), 'llvm-bitcode');
  assert.equal(objectKind(withMagic(ELF_MAGIC)), 'elf');
  assert.equal(objectKind(Buffer.alloc(0)), 'empty');
  assert.equal(objectKind(Buffer.from('not an object at all')), 'other');
  // A truncated file is not a bitcode file, however it starts.
  assert.equal(objectKind(Buffer.from([0x42, 0x43])), 'other');
  assert.equal(objectKind(null), 'empty');
});

test('an ELF object on an lto input makes the link not an LTO link', () => {
  const g = gradeInputs({
    ltoInputs: [{ name: 'use.o', kind: 'elf' }, { name: 'wipe.o', kind: 'llvm-bitcode' }],
  });
  assert.equal(g.ok, false);
  assert.match(g.problems[0], /use\.o is elf, not LLVM bitcode/);
});

test('an opaque unit that IS bitcode is caught too, because the fixture depends on it not being', () => {
  // This direction matters as much as the other one. The xtu control only holds
  // because io.c stays outside the merged module; compiled -flto by mistake, the
  // control's buffer is promoted away and the cell reports a broken control with
  // no hint of why.
  const g = gradeInputs({
    ltoInputs: [{ name: 'use.o', kind: 'llvm-bitcode' }],
    opaqueInputs: [{ name: 'io.o', kind: 'llvm-bitcode' }],
  });
  assert.equal(g.ok, false);
  assert.match(g.problems[0], /io\.o is bitcode but the fixture requires it to stay outside/);
});

test('a thin object on a link the cell calls full is a mismatch, not a pass', () => {
  const g = gradeInputs({
    ltoInputs: [{ name: 'use.o', kind: 'llvm-bitcode' }, { name: 'wipe.o', kind: 'llvm-bitcode' }],
    forms: { 'use.o': 'thin', 'wipe.o': 'full' },
    expectForm: 'full',
  });
  assert.equal(g.ok, false);
  assert.ok(g.problems.some((p) => /use\.o is a thin-LTO object/.test(p)));
  assert.ok(g.problems.some((p) => /mix forms: full, thin/.test(p)));
});

test('an unreadable dump leaves the form null, which is not a disagreement', () => {
  const g = gradeInputs({
    ltoInputs: [{ name: 'use.o', kind: 'llvm-bitcode' }],
    forms: { 'use.o': null },
    expectForm: 'full',
  });
  assert.equal(g.ok, true);
  assert.equal(g.formFromArtifacts, null);
});

test('the summary block names the form, and full is checked before thin', () => {
  // FULL_LTO_GLOBALVAL_SUMMARY_BLOCK contains GLOBALVAL_SUMMARY_BLOCK as a
  // substring, so testing for thin first would call every full object thin.
  assert.equal(ltoFormFromBcanalyzerDump('... FULL_LTO_GLOBALVAL_SUMMARY_BLOCK ...'), 'full');
  assert.equal(ltoFormFromBcanalyzerDump('... GLOBALVAL_SUMMARY_BLOCK ...'), 'thin');
  assert.equal(ltoFormFromBcanalyzerDump('MODULE_BLOCK only'), null);
  assert.equal(ltoFormFromBcanalyzerDump(''), null);
});

test('a healthy set of inputs passes', () => {
  const g = gradeInputs({
    ltoInputs: [{ name: 'use.o', kind: 'llvm-bitcode' }, { name: 'main.o', kind: 'llvm-bitcode' }],
    opaqueInputs: [{ name: 'io.o', kind: 'elf' }],
    forms: { 'use.o': 'full', 'main.o': 'full' },
    expectForm: 'full',
  });
  assert.deepEqual(g.problems, []);
  assert.equal(g.ok, true);
  assert.equal(g.formFromArtifacts, 'full');
});
