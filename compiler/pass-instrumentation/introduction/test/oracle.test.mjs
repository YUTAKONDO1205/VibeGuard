// The oracle rule, at both levels: never decide presence by searching for a
// name (interfaces.md §4).
//
// The loss side learned this the expensive way -- a naive name search blamed
// the global-cleanup pass for a deletion the store-elimination pass had made,
// nine pass-budget steps earlier. The introduction side has the same trap the
// other way round: a `declare` line is not an external call, and an undefined
// symbol sitting in a symbol table is not a call site either.

import assert from 'node:assert/strict';
import test from 'node:test';

import { normaliseElf, objectElements } from '../lib/elf.mjs';
import { readIrModule } from '../lib/irsyms.mjs';
import { elfDoc, relocGroup, section, symbol } from './helpers.mjs';

const DECLARE_ONLY = `
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg)
declare void @sink(ptr)

define void @control(ptr %p) {
entry:
  call void @sink(ptr %p)
  ret void
}
`;

test('a surviving declaration with no call site is not an external call', () => {
  const m = readIrModule(DECLARE_ONLY);

  // What a naive check would find: the name is right there in the text.
  assert.equal(/llvm\.memset/.test(DECLARE_ONLY), true);
  assert.equal(m.declarations.has('llvm.memset.p0.i64'), true);

  // What the oracle finds: no call site, so no external call.
  assert.equal(m.externalCalls.has('llvm.memset.p0.i64'), false);
  assert.equal(m.callSites.get('llvm.memset.p0.i64'), undefined);

  // And the control, which does have a call site, is counted -- so this is a
  // 0-vs-nonzero measurement rather than a parser that found nothing.
  assert.equal(m.externalCalls.get('sink'), 1);
});

test('call sites are counted, not deduplicated by name', () => {
  const m = readIrModule(`
declare void @sink(ptr)
define void @f(ptr %p) {
  call void @sink(ptr %p)
  call void @sink(ptr %p)
  call void @sink(ptr %p)
  ret void
}
`);
  assert.equal(m.externalCalls.get('sink'), 3);
});

test('a global passed as an argument to an indirect call is not read as the callee', () => {
  const m = readIrModule(`
@table = global [1 x ptr] zeroinitializer
define void @f(ptr %fp) {
  call void %fp(ptr @table)
  ret void
}
`);
  assert.equal(m.callSites.size, 0, 'no callee name should have been invented');
  assert.equal(m.globals.has('table'), true);
});

test('a call to a function defined in this module is not an external call', () => {
  const m = readIrModule(`
define internal void @helper(ptr %p) { ret void }
define void @f(ptr %p) {
  call void @helper(ptr %p)
  ret void
}
`);
  assert.equal(m.callSites.get('helper'), 1);
  assert.equal(m.externalCalls.has('helper'), false);
});

test('quoted names -- every mangled lambda has one -- survive parsing', () => {
  const m = readIrModule(`
declare void @"_ZZ4mainENK3$_0clEv"()
define void @f() {
  call void @"_ZZ4mainENK3$_0clEv"()
  ret void
}
`);
  assert.equal(m.externalCalls.get('_ZZ4mainENK3$_0clEv'), 1);
});

// --- the same rule at object level -----------------------------------------

test('an undefined symbol with no call-shaped relocation is not a call site', () => {
  const elf = normaliseElf(elfDoc({
    sections: [
      section({ index: 0, name: '', type: 'SHT_NULL' }),
      section({ index: 1, name: '.text', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
    ],
    symbols: [
      symbol({ name: '', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'f', sectionName: '.text', sectionIndex: 1 }),
      // Present in the table, referenced by nothing.
      symbol({ name: 'dlopen', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
    ],
    relocations: [],
  }));
  const calls = objectElements(elf).filter((e) => e.kind === 'extcall');
  assert.deepEqual(calls, [], 'a name in the symbol table is not an instruction');
});

test('a call-shaped relocation in an executable section is a call site, and is counted per site', () => {
  const elf = normaliseElf(elfDoc({
    sections: [
      section({ index: 0, name: '', type: 'SHT_NULL' }),
      section({ index: 1, name: '.text', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
      section({ index: 2, name: '.rela.text', type: 'SHT_RELA', info: 1 }),
    ],
    symbols: [
      symbol({ name: '', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'f', sectionName: '.text', sectionIndex: 1 }),
      symbol({ name: 'dlopen', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
    ],
    relocations: [relocGroup(2, [
      { type: 'R_X86_64_PLT32', symbol: 'dlopen', offset: 8 },
      { type: 'R_X86_64_PLT32', symbol: 'dlopen', offset: 32 },
    ])],
  }));
  const calls = objectElements(elf).filter((e) => e.kind === 'extcall');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, 'dlopen');
  assert.equal(calls[0].detail.callSites, 2);
});

test('a reference from a non-executable section is not a call', () => {
  const elf = normaliseElf(elfDoc({
    sections: [
      section({ index: 0, name: '', type: 'SHT_NULL' }),
      section({ index: 1, name: '.data.rel.ro', flags: ['SHF_ALLOC', 'SHF_WRITE'] }),
      section({ index: 2, name: '.rela.data.rel.ro', type: 'SHT_RELA', info: 1 }),
    ],
    symbols: [
      symbol({ name: '', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'vtable', type: 'Object', sectionName: '.data.rel.ro', sectionIndex: 1 }),
      symbol({ name: 'handler', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
    ],
    relocations: [relocGroup(2, [{ type: 'R_X86_64_PC32', symbol: 'handler', offset: 0 }])],
  }));
  const calls = objectElements(elf).filter((e) => e.kind === 'extcall');
  assert.deepEqual(calls, []);
});
