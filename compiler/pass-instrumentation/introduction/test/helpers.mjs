// Shared fixtures for the introduction tests. Not a test file itself --
// `node --test` only picks up `*.test.mjs`.
//
// The ELF builders produce the exact JSON shape `llvm-readelf-18
// --elf-output-style=JSON` emits, taken from a real run rather than invented,
// so the offline tests exercise the same parser the live path does.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The subject programs are under `subjects/`, not `fixtures/`. That is not a
// naming preference: scripts/check-packaging-invariants.mjs fails any path under
// compiler/ containing a `fixtures` or `_results` directory, because measurement
// inputs and outputs carry absolute paths and per-machine toolchain digests and
// belong on the side that produces them. These are source files that get
// compiled, not recorded measurements, so they belong here under a name the
// invariant does not claim.

const HERE = dirname(fileURLToPath(import.meta.url));
export const COMPONENT_DIR = resolve(HERE, '..');
export const SUBJECTS = join(COMPONENT_DIR, 'subjects');
export const SCAN_CLI = join(COMPONENT_DIR, 'cli', 'intro-scan.mjs');
export const PASSES_CLI = join(COMPONENT_DIR, 'cli', 'intro-passes.mjs');
export const LIVE_SH = join(COMPONENT_DIR, 'tools', 'live.sh');

export function section({ index, name, type = 'SHT_PROGBITS', flags = [], link = 0, info = 0, size = 0 }) {
  return {
    Section: {
      Index: index,
      Name: { Name: name, Value: 0 },
      Type: { Name: type, Value: 1 },
      Flags: { Value: 0, Flags: flags },
      Address: 0, Offset: 0, Size: size, Link: link, Info: info,
      AddressAlignment: 1, EntrySize: 0,
    },
  };
}

export function symbol({ name, value = 0, size = 0, binding = 'Global', type = 'Function', sectionName, sectionIndex }) {
  return {
    Symbol: {
      Name: { Name: name, Value: 0 },
      Value: value, Size: size,
      Binding: { Name: binding, Value: 1 },
      Type: { Name: type, Value: 2 },
      Other: { Value: 0, Flags: [] },
      Section: { Name: sectionName, Value: sectionIndex },
    },
  };
}

/** `relaSectionIndex` is the index of the .rela section; its Info names the target. */
export function relocGroup(relaSectionIndex, relocs) {
  return {
    SectionIndex: relaSectionIndex,
    Relocs: relocs.map((r) => ({
      Relocation: {
        Offset: r.offset ?? 0,
        Type: { Name: r.type, Value: 0 },
        Symbol: { Name: r.symbol, Value: 0 },
        Addend: r.addend ?? 0,
      },
    })),
  };
}

export function elfDoc({ sections = [], symbols = [], relocations = [] }) {
  return [{
    FileSummary: { File: 'test.o', Format: 'elf64-x86-64', Arch: 'x86_64' },
    Sections: sections,
    Symbols: symbols,
    Relocations: relocations,
  }];
}

/**
 * The smallest object that contains an injection: one executable section
 * outside the standard set, one defined symbol in it that no baseline explains,
 * one call-shaped relocation to an undefined symbol, and one .init_array slot
 * pointing at the injected symbol.
 */
export function injectedObject() {
  return elfDoc({
    sections: [
      section({ index: 0, name: '', type: 'SHT_NULL' }),
      section({ index: 1, name: '.text', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
      section({ index: 2, name: '.text.injected', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
      section({ index: 3, name: '.rela.text.injected', type: 'SHT_RELA', info: 2 }),
      section({ index: 4, name: '.init_array', type: 'SHT_INIT_ARRAY', flags: ['SHF_WRITE', 'SHF_ALLOC'] }),
      section({ index: 5, name: '.rela.init_array', type: 'SHT_RELA', info: 4 }),
    ],
    symbols: [
      symbol({ name: '', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'honest_fn', sectionName: '.text', sectionIndex: 1 }),
      symbol({ name: 'injected_thunk', sectionName: '.text.injected', sectionIndex: 2 }),
      symbol({ name: 'dlopen', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'memcpy', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
    ],
    relocations: [
      relocGroup(3, [{ type: 'R_X86_64_PLT32', symbol: 'dlopen', offset: 12, addend: 18446744073709551612n }]),
      relocGroup(5, [{ type: 'R_X86_64_64', symbol: 'injected_thunk', offset: 0, addend: 0 }]),
    ],
  });
}

/**
 * The same shape, but honest: the .init_array slot relocates against a *section*
 * symbol, which is how the compiler's own static-initialisation entry appears,
 * and the executable sections are the ones -ffunction-sections produces.
 */
export function honestObject() {
  return elfDoc({
    sections: [
      section({ index: 0, name: '', type: 'SHT_NULL' }),
      section({ index: 1, name: '.text', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
      section({ index: 2, name: '.text.startup', flags: ['SHF_ALLOC', 'SHF_EXECINSTR'] }),
      section({ index: 3, name: '.text._ZNSt6vectorIiSaIiEED2Ev', flags: ['SHF_ALLOC', 'SHF_EXECINSTR', 'SHF_GROUP'] }),
      section({ index: 4, name: '.init_array', type: 'SHT_INIT_ARRAY', flags: ['SHF_WRITE', 'SHF_ALLOC'] }),
      section({ index: 5, name: '.rela.init_array', type: 'SHT_RELA', info: 4 }),
    ],
    symbols: [
      symbol({ name: '', type: 'None', sectionName: 'Undefined', sectionIndex: 0 }),
      symbol({ name: 'app_main', sectionName: '.text', sectionIndex: 1 }),
      symbol({ name: '_GLOBAL__sub_I_app.cpp', binding: 'Local', sectionName: '.text.startup', sectionIndex: 2 }),
      symbol({ name: '.text.startup', binding: 'Local', type: 'Section', sectionName: '.text.startup', sectionIndex: 2 }),
      symbol({ name: '_ZNSt6vectorIiSaIiEED2Ev', binding: 'Weak', sectionName: '.text._ZNSt6vectorIiSaIiEED2Ev', sectionIndex: 3 }),
    ],
    relocations: [
      relocGroup(5, [{ type: 'R_X86_64_64', symbol: '.text.startup', offset: 0, addend: 0 }]),
    ],
  });
}

/** A front-end set, in the shape `classifyOrigin` wants. */
export function frontEnd(functions = [], globals = []) {
  return { functions: new Set(functions), globals: new Set(globals), aliases: new Set() };
}

/** Capture what a CLI printed, so exit codes and output can both be asserted. */
export function captureConsole() {
  const lines = [];
  const errors = [];
  return {
    out: {
      log: (...a) => lines.push(a.join(' ')),
      error: (...a) => errors.push(a.join(' ')),
    },
    get stdout() { return lines.join('\n'); },
    get stderr() { return errors.join('\n'); },
  };
}
