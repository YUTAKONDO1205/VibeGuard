// Reading an object file, and turning it into introduction elements.
//
// The object level exists because the IR level cannot see everything. Module-
// level inline assembly never enters LLVM's symbol table: there is no `define`
// and no `@global` for it, so a symbol, a section and an .init_array slot can
// all arrive in the object with the compiler's own model of the translation
// unit showing no trace of them. That is the shape an assembler wrapper or a
// pass plugin would use, and an IR-only detector is blind to it.
//
// THE ORACLE RULE, AT THIS LEVEL. interfaces.md §4 says to count the call site
// and never the symbol name. Here the call site is a *relocation at a code
// offset* -- an instruction that references the symbol -- not the presence of
// the symbol in the symbol table. An undefined symbol with no call-shaped
// relocation against it is a reference that survived in the table, not a call,
// and this module does not report it as one.
//
// Parsing is split from running: `normaliseElf` takes the decoded JSON and is
// pure, so the shape work is tested without a toolchain, and only the thin
// `readObject` needs one.
//
// Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).

import { execFileSync } from 'node:child_process';

const TWO_64 = 1n << 64n;
const TWO_63 = 1n << 63n;

function signedAddend(v) {
  const b = BigInt(v);
  return b >= TWO_63 ? b - TWO_64 : b;
}

/**
 * Relocation types that can encode a call or a tail jump, per target. A
 * relocation of one of these types, at an offset inside a section carrying the
 * executable flag, is an instruction that transfers control to the symbol.
 *
 * The GOT-indirect forms are included because a call through the global offset
 * table is still a call; they are also used for plain address loads, so an
 * element found only through one of those is reported with `viaGot: true` and
 * the finding says which relocation carried it rather than asserting more than
 * was seen.
 */
const CALL_RELOCS = new Set([
  'R_X86_64_PLT32', 'R_X86_64_PC32', 'R_X86_64_GOTPCRELX', 'R_X86_64_REX_GOTPCRELX',
  'R_X86_64_GOTPCREL', 'R_X86_64_TLSGD', 'R_X86_64_GOTTPOFF',
  'R_386_PLT32', 'R_386_PC32',
  'R_AARCH64_CALL26', 'R_AARCH64_JUMP26',
  'R_ARM_CALL', 'R_ARM_JUMP24', 'R_ARM_THM_CALL', 'R_ARM_PLT32',
  'R_RISCV_CALL', 'R_RISCV_CALL_PLT', 'R_RISCV_JAL',
]);

const GOT_RELOCS = new Set([
  'R_X86_64_GOTPCRELX', 'R_X86_64_REX_GOTPCRELX', 'R_X86_64_GOTPCREL',
  'R_X86_64_TLSGD', 'R_X86_64_GOTTPOFF',
]);

/** Sections holding pointers the C runtime calls before main. */
const INIT_SECTIONS = new Set(['.init_array', '.preinit_array', '.ctors']);

/**
 * Executable sections a normal build produces. Anything else with the X flag
 * has to be explained by what it contains.
 */
export const STANDARD_EXEC_SECTIONS = new Set([
  '.text', '.init', '.fini', '.plt', '.plt.sec', '.plt.got', '.iplt',
  '.text.startup', '.text.exit', '.text.hot', '.text.unlikely',
  '.gnu.warning', '.tdata',
]);

/**
 * Decode `llvm-readelf --elf-output-style=JSON --sections --symbols
 * --relocations` output into the flat shape the rest of this component uses.
 *
 * @param {object[]} raw  the parsed JSON array (one entry per input file)
 */
export function normaliseElf(raw) {
  const doc = Array.isArray(raw) ? raw[0] : raw;
  if (!doc) throw new Error('normaliseElf: empty readelf output');

  const sections = (doc.Sections ?? []).map((s) => {
    const sec = s.Section ?? s;
    return {
      index: sec.Index,
      name: sec.Name?.Name ?? '',
      type: sec.Type?.Name ?? '',
      flags: (sec.Flags?.Flags ?? []).map((f) => (typeof f === 'string' ? f : f.Name)),
      link: sec.Link ?? 0,
      info: sec.Info ?? 0,
      size: sec.Size ?? 0,
      entrySize: sec.EntrySize ?? 0,
    };
  });
  const byIndex = new Map(sections.map((s) => [s.index, s]));

  const symbols = (doc.Symbols ?? []).map((s) => {
    const sym = s.Symbol ?? s;
    return {
      name: sym.Name?.Name ?? '',
      value: Number(sym.Value ?? 0),
      size: Number(sym.Size ?? 0),
      binding: sym.Binding?.Name ?? '',
      type: sym.Type?.Name ?? '',
      sectionName: sym.Section?.Name ?? '',
      sectionIndex: typeof sym.Section?.Value === 'number' ? sym.Section.Value : -1,
    };
  });

  const relocs = [];
  for (const group of doc.Relocations ?? []) {
    // The index reported is the relocation section itself; its `Info` field
    // names the section the relocations apply to.
    const relaIndex = group.SectionIndex;
    const target = byIndex.get(relaIndex)?.info ?? relaIndex;
    for (const r of group.Relocs ?? []) {
      const rel = r.Relocation ?? r;
      relocs.push({
        targetSectionIndex: target,
        targetSectionName: byIndex.get(target)?.name ?? '',
        offset: Number(rel.Offset ?? 0),
        type: rel.Type?.Name ?? '',
        symbol: rel.Symbol?.Name ?? '',
        addend: signedAddend(rel.Addend ?? 0),
      });
    }
  }

  return { sections, symbols, relocs, byIndex };
}

function isExecutable(section) {
  return Boolean(section) && section.flags.includes('SHF_EXECINSTR');
}

function isUndefined(sym) {
  return sym.sectionName === 'Undefined' || sym.sectionIndex === 0;
}

/**
 * Resolve what a relocation points at.
 *
 * A relocation against a *section* symbol names an offset, not a name: the
 * negative fixture's .init_array slot relocates against `.text.startup + 0`,
 * and the initialiser it actually runs is the local function that happens to
 * live at offset 0 of that section. Following that indirection is the
 * difference between "an initialiser this build cannot account for" and
 * "_GLOBAL__sub_I_normal_cxx.cpp, which every C++ file with a global object
 * has".
 */
export function resolveRelocTarget(elf, rel) {
  const named = elf.symbols.find((s) => s.name === rel.symbol && !isUndefined(s));
  if (named && named.type !== 'Section') {
    return { name: named.name, symbol: named, indirect: false };
  }
  const section = elf.sections.find((s) => s.name === rel.symbol);
  if (section) {
    const at = Number(rel.addend);
    const hit = elf.symbols.find(
      (s) => s.sectionIndex === section.index && s.value === at
        && s.type === 'Function' && s.name !== '',
    );
    if (hit) return { name: hit.name, symbol: hit, indirect: true };
    return { name: `${rel.symbol}+${at}`, symbol: null, indirect: true, unresolved: true };
  }
  // An undefined symbol: the name is all there is, and it is enough.
  return { name: rel.symbol, symbol: elf.symbols.find((s) => s.name === rel.symbol) ?? null, indirect: false };
}

/**
 * Every element of an object file that introduction analysis has an opinion
 * about. One flat list, each entry carrying the finding id it would produce if
 * it turned out to be Unexplained.
 */
export function objectElements(elf, { objectName = 'object' } = {}) {
  const elements = [];

  // --- defined symbols: VG-INTRO-001 --------------------------------------
  for (const sym of elf.symbols) {
    if (!sym.name) continue;                    // the null symbol
    if (sym.type === 'File' || sym.type === 'Section') continue;
    if (isUndefined(sym)) continue;
    elements.push({
      kind: 'symbol',
      name: sym.name,
      defined: true,
      finding: 'VG-INTRO-001',
      scope: objectName,
      where: sym.sectionName,
      detail: { binding: sym.binding, type: sym.type, size: sym.size },
    });
  }

  // --- external calls: VG-INTRO-002 ---------------------------------------
  // Counted by relocation at a code offset, never by presence in the symbol
  // table. Two calls to the same target are two call sites.
  const calls = new Map();
  for (const rel of elf.relocs) {
    if (!CALL_RELOCS.has(rel.type)) continue;
    const section = elf.byIndex.get(rel.targetSectionIndex);
    if (!isExecutable(section)) continue;
    const target = elf.symbols.find((s) => s.name === rel.symbol);
    if (!target || !isUndefined(target)) continue;  // a call within this object
    const prev = calls.get(rel.symbol) ?? { sites: 0, viaGot: false, from: new Set() };
    prev.sites += 1;
    if (GOT_RELOCS.has(rel.type)) prev.viaGot = true;
    prev.from.add(rel.targetSectionName);
    calls.set(rel.symbol, prev);
  }
  for (const [name, info] of calls) {
    elements.push({
      kind: 'extcall',
      name,
      defined: false,
      finding: 'VG-INTRO-002',
      scope: objectName,
      where: [...info.from].sort().join(','),
      detail: { callSites: info.sites, viaGot: info.viaGot },
    });
  }

  // --- static initialisers: VG-INTRO-003 ----------------------------------
  for (const rel of elf.relocs) {
    if (!INIT_SECTIONS.has(rel.targetSectionName)) continue;
    const resolved = resolveRelocTarget(elf, rel);
    elements.push({
      kind: 'initialiser',
      name: resolved.name,
      defined: resolved.symbol ? !isUndefined(resolved.symbol) : false,
      finding: 'VG-INTRO-003',
      scope: objectName,
      where: rel.targetSectionName,
      detail: {
        slot: rel.offset,
        viaSectionSymbol: resolved.indirect,
        unresolvedTarget: Boolean(resolved.unresolved),
      },
    });
  }

  // --- executable sections: VG-INTRO-004 ----------------------------------
  for (const section of elf.sections) {
    if (!isExecutable(section)) continue;
    if (section.name === '') continue;
    const contained = elf.symbols
      .filter((s) => s.sectionIndex === section.index && s.name && s.type !== 'Section')
      .map((s) => s.name);
    elements.push({
      kind: 'section',
      name: section.name,
      defined: true,
      finding: 'VG-INTRO-004',
      scope: objectName,
      where: section.name,
      detail: { contains: contained.sort(), size: section.size },
    });
  }

  return elements;
}

/** Run llvm-readelf and decode. The only part of this module that needs a tool. */
export function readObject(path, { readelf = 'llvm-readelf-18', run = execFileSync } = {}) {
  const out = run(readelf, [
    '--sections', '--symbols', '--relocations', '--elf-output-style=JSON', path,
  ], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return normaliseElf(JSON.parse(out));
}
