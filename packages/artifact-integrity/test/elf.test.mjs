// The reader. Everything downstream is a function of these fields, so a wrong
// field here is a wrong verdict everywhere, silently.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  readElf, initFunctions, neededLibraries, runPaths, undefinedSymbols,
  definedSymbols, exportedSymbols, pltCallSites, dynstrNames, isDynamicallyLinked,
  NT_GNU_BUILD_ID,
} from '../src/elf.mjs';
import { RECIPES, buildElf } from './synth-elf.mjs';

const of = (name) => readElf(RECIPES[name](), { path: name });

test('a non-ELF input is unsupported, and that is not the same as clean', () => {
  const r = readElf(Buffer.from('this is not an ELF file, not even slightly'.padEnd(200, '.')), { path: 'x' });
  assert.equal(r.supported, false);
  assert.match(r.reason, /ELF magic/);
  assert.equal(r.findings, undefined, 'an unreadable file must not produce a verdict');
});

test('a file too short to hold a header is unsupported', () => {
  assert.equal(readElf(Buffer.alloc(8)).supported, false);
});

test('ELF32 and big-endian are refused rather than guessed at', () => {
  const b = RECIPES.hardened();
  const e32 = Buffer.from(b); e32[4] = 1;
  assert.match(readElf(e32).reason, /ELFCLASS64/);
  const be = Buffer.from(b); be[5] = 2;
  assert.match(readElf(be).reason, /ELFDATA2LSB/);
});

test('the digest is over the whole file', () => {
  const b = RECIPES.hardened();
  assert.equal(readElf(b).sha256, createHash('sha256').update(b).digest('hex'));
});

test('a truncated image reports what it could not read instead of returning short lists', () => {
  const full = RECIPES.hardened();
  const cut = full.subarray(0, full.length - 200);
  const r = readElf(cut, { path: 'cut' });
  assert.equal(r.supported, true);
  assert.ok(r.truncated.length > 0, 'truncation must be recorded, not silently absorbed');
});

test('notes are parsed from the payload: owner, n_type and descsz', () => {
  const elf = of('hardened');
  const n = elf.notes.find((x) => x.n_type === NT_GNU_BUILD_ID);
  assert.ok(n);
  assert.equal(n.owner, 'GNU');
  assert.equal(n.namesz, 4);
  assert.equal(n.descsz, 20);
});

test('imports are keyed on the version-stripped name and keep the versions', () => {
  const buf = buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['__stack_chk_fail@GLIBC_2.4', 'puts'],
  });
  const elf = readElf(buf, { path: 'versioned' });
  const u = undefinedSymbols(elf);
  const scf = u.find((s) => s.name === '__stack_chk_fail');
  assert.ok(scf, 'the version suffix must be stripped for keying');
  assert.deepEqual(scf.versions, ['@GLIBC_2.4']);
});

test('defined, undefined and exported symbols are three different questions', () => {
  const buf = buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], definedSymbols: ['main', 'helper'],
  });
  const elf = readElf(buf, { path: 'syms' });
  assert.deepEqual(undefinedSymbols(elf).map((s) => s.name).sort(), ['puts']);
  const def = definedSymbols(elf).map((s) => s.name).sort();
  assert.ok(def.includes('main') && def.includes('helper'));
  assert.equal(def.includes('puts'), false);
  assert.deepEqual(exportedSymbols(elf).map((s) => s.name).sort(), ['helper', 'main']);
});

test('the PLT call-site surface is read from JUMP_SLOT relocations', () => {
  const elf = of('hardened');
  assert.deepEqual(pltCallSites(elf).map((c) => c.name).sort(), ['__stack_chk_fail', '__strcpy_chk']);
});

test('a name in .dynstr is not a call site', () => {
  const elf = of('fortify-name-only');
  assert.ok(dynstrNames(elf).includes('__strcpy_chk'));
  assert.equal(pltCallSites(elf).length, 0);
});

test('dynamic dependencies and search paths are read from .dynamic', () => {
  assert.deepEqual(neededLibraries(of('hardened')), ['libc.so.6']);
  const rp = runPaths(of('rpath'));
  assert.equal(rp.length, 1);
  assert.equal(rp[0].tag, 'DT_RUNPATH');
  assert.equal(rp[0].value, '/opt/vendor/lib');
});

test('init_array slots resolve to the functions that run before main', () => {
  const entries = initFunctions(of('init-array'));
  assert.equal(entries.length, 2);
  assert.deepEqual(entries.map((e) => e.target), ['frame_dummy', 'backdoor_ctor']);
  for (const e of entries) assert.ok(e.resolvedVia, 'every slot must say how it was resolved');
});

test('an image with no init_array reports an empty list rather than throwing', () => {
  assert.deepEqual(initFunctions(of('hardened')), []);
});

test('a static image is not "dynamically linked"', () => {
  assert.equal(isDynamicallyLinked(of('static-hardened')), false);
  assert.equal(isDynamicallyLinked(of('hardened')), true);
});

test('section flags are decoded into the three booleans the W+X rule uses', () => {
  const elf = of('wx-section');
  const wx = elf.sections.find((s) => s.name === '.vgwx');
  assert.equal(wx.writable, true);
  assert.equal(wx.allocated, true);
  assert.equal(wx.executable, true);
  const text = elf.sections.find((s) => s.name === '.text');
  assert.equal(text.writable, false);
  assert.equal(text.executable, true);
});
