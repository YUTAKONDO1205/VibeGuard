// ELF reader. Structural fields only.
//
// Nothing in this file parses the output of another program. Every decision the
// classifier makes has to be attributable to a named field at a named offset in
// the file itself, because the two readers installed on this machine do not
// agree on wording: GNU readelf 2.42 prints a PIE as `DYN (Position-Independent
// Executable file)` while llvm-readelf-18 prints `DYN (Shared object file)` for
// the same bytes. A check written against either string is a check that changes
// its answer when the toolchain is upgraded.
//
// Scope: ELF64, two's complement, little-endian. Anything else is reported as
// unreadable rather than guessed at — see `readElf`'s `unsupported` return.

import { readFileSync } from 'node:fs';

export const ET = { NONE: 0, REL: 1, EXEC: 2, DYN: 3, CORE: 4 };

export const PT = {
  NULL: 0, LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, SHLIB: 5, PHDR: 6, TLS: 7,
  GNU_EH_FRAME: 0x6474e550, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552,
  GNU_PROPERTY: 0x6474e553,
};

export const SHT = {
  NULL: 0, PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, HASH: 5, DYNAMIC: 6,
  NOTE: 7, NOBITS: 8, REL: 9, SHLIB: 10, DYNSYM: 11, INIT_ARRAY: 14,
  FINI_ARRAY: 15, PREINIT_ARRAY: 16, GROUP: 17, SYMTAB_SHNDX: 18,
  GNU_HASH: 0x6ffffff6, GNU_verdef: 0x6ffffffd, GNU_verneed: 0x6ffffffe,
  GNU_versym: 0x6fffffff,
};

export const SHF = {
  WRITE: 0x1, ALLOC: 0x2, EXECINSTR: 0x4, MERGE: 0x10, STRINGS: 0x20,
  INFO_LINK: 0x40, LINK_ORDER: 0x80, OS_NONCONFORMING: 0x100, GROUP: 0x200,
  TLS: 0x400,
};

export const STB = { LOCAL: 0, GLOBAL: 1, WEAK: 2, GNU_UNIQUE: 10 };
export const STT = {
  NOTYPE: 0, OBJECT: 1, FUNC: 2, SECTION: 3, FILE: 4, COMMON: 5, TLS: 6,
  GNU_IFUNC: 10,
};
export const STV = { DEFAULT: 0, INTERNAL: 1, HIDDEN: 2, PROTECTED: 3 };

export const SHN = { UNDEF: 0, ABS: 0xfff1, COMMON: 0xfff2, XINDEX: 0xffff };

export const DT = {
  NULL: 0, NEEDED: 1, PLTRELSZ: 2, PLTGOT: 3, HASH: 4, STRTAB: 5, SYMTAB: 6,
  RELA: 7, RELASZ: 8, RELAENT: 9, STRSZ: 10, SYMENT: 11, INIT: 12, FINI: 13,
  SONAME: 14, RPATH: 15, SYMBOLIC: 16, REL: 17, RELSZ: 18, RELENT: 19,
  PLTREL: 20, DEBUG: 21, TEXTREL: 22, JMPREL: 23, BIND_NOW: 24,
  INIT_ARRAY: 25, FINI_ARRAY: 26, INIT_ARRAYSZ: 27, FINI_ARRAYSZ: 28,
  RUNPATH: 29, FLAGS: 30, PREINIT_ARRAY: 32, PREINIT_ARRAYSZ: 33,
  RELACOUNT: 0x6ffffff9, FLAGS_1: 0x6ffffffb,
};

// DT_FLAGS bits
export const DF = { ORIGIN: 0x1, SYMBOLIC: 0x2, TEXTREL: 0x4, BIND_NOW: 0x8, STATIC_TLS: 0x10 };
// DT_FLAGS_1 bits
export const DF_1 = { NOW: 0x1, GLOBAL: 0x2, NODELETE: 0x8, ORIGIN: 0x80, PIE: 0x08000000 };

// x86-64 relocation types this reader needs to resolve pointer slots.
export const R_X86_64 = { NONE: 0, _64: 1, GLOB_DAT: 6, JUMP_SLOT: 7, RELATIVE: 8, IRELATIVE: 37 };

const EI_CLASS = 4, EI_DATA = 5;
const ELFCLASS64 = 2, ELFDATA2LSB = 1;

function cstr(buf, off) {
  if (off < 0 || off >= buf.length) return null;
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.toString('utf8', off, end);
}

/**
 * Read one ELF file into plain structures.
 *
 * Returns `{ supported: false, reason }` when the file is not an ELF64 LSB
 * image. Callers must treat that as "could not look", never as "nothing found";
 * that distinction is the whole point of the Unresolved verdict downstream.
 */
export function readElf(path) {
  const buf = readFileSync(path);
  if (buf.length < 64) return { supported: false, reason: 'file shorter than an ELF64 header', path };
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) {
    return { supported: false, reason: 'no ELF magic in e_ident', path };
  }
  if (buf[EI_CLASS] !== ELFCLASS64) {
    return { supported: false, reason: `e_ident[EI_CLASS]=${buf[EI_CLASS]}, only ELFCLASS64 is read`, path };
  }
  if (buf[EI_DATA] !== ELFDATA2LSB) {
    return { supported: false, reason: `e_ident[EI_DATA]=${buf[EI_DATA]}, only ELFDATA2LSB is read`, path };
  }

  const ehdr = {
    e_type: buf.readUInt16LE(16),
    e_machine: buf.readUInt16LE(18),
    e_version: buf.readUInt32LE(20),
    e_entry: buf.readBigUInt64LE(24),
    e_phoff: Number(buf.readBigUInt64LE(32)),
    e_shoff: Number(buf.readBigUInt64LE(40)),
    e_flags: buf.readUInt32LE(48),
    e_ehsize: buf.readUInt16LE(52),
    e_phentsize: buf.readUInt16LE(54),
    e_phnum: buf.readUInt16LE(56),
    e_shentsize: buf.readUInt16LE(58),
    e_shnum: buf.readUInt16LE(60),
    e_shstrndx: buf.readUInt16LE(62),
  };

  const phdrs = [];
  for (let i = 0; i < ehdr.e_phnum; i++) {
    const o = ehdr.e_phoff + i * ehdr.e_phentsize;
    if (o + 56 > buf.length) break;
    phdrs.push({
      index: i,
      p_type: buf.readUInt32LE(o),
      p_flags: buf.readUInt32LE(o + 4),
      p_offset: Number(buf.readBigUInt64LE(o + 8)),
      p_vaddr: Number(buf.readBigUInt64LE(o + 16)),
      p_paddr: Number(buf.readBigUInt64LE(o + 24)),
      p_filesz: Number(buf.readBigUInt64LE(o + 32)),
      p_memsz: Number(buf.readBigUInt64LE(o + 40)),
      p_align: Number(buf.readBigUInt64LE(o + 48)),
    });
  }

  const rawSections = [];
  for (let i = 0; i < ehdr.e_shnum; i++) {
    const o = ehdr.e_shoff + i * ehdr.e_shentsize;
    if (o + 64 > buf.length) break;
    rawSections.push({
      index: i,
      sh_name: buf.readUInt32LE(o),
      sh_type: buf.readUInt32LE(o + 4),
      sh_flags: Number(buf.readBigUInt64LE(o + 8)),
      sh_addr: Number(buf.readBigUInt64LE(o + 16)),
      sh_offset: Number(buf.readBigUInt64LE(o + 24)),
      sh_size: Number(buf.readBigUInt64LE(o + 32)),
      sh_link: buf.readUInt32LE(o + 40),
      sh_info: buf.readUInt32LE(o + 44),
      sh_addralign: Number(buf.readBigUInt64LE(o + 48)),
      sh_entsize: Number(buf.readBigUInt64LE(o + 56)),
    });
  }

  const shstr = rawSections[ehdr.e_shstrndx];
  const sections = rawSections.map((s) => ({
    ...s,
    name: shstr ? cstr(buf, shstr.sh_offset + s.sh_name) : null,
  }));
  const byName = new Map();
  for (const s of sections) if (s.name && !byName.has(s.name)) byName.set(s.name, s);

  // ---- symbol tables ------------------------------------------------------
  function readSymtab(sec) {
    if (!sec) return [];
    const str = sections[sec.sh_link];
    if (!str) return [];
    const out = [];
    const n = sec.sh_entsize ? Math.floor(sec.sh_size / sec.sh_entsize) : 0;
    for (let i = 0; i < n; i++) {
      const o = sec.sh_offset + i * sec.sh_entsize;
      if (o + 24 > buf.length) break;
      const st_name = buf.readUInt32LE(o);
      const st_info = buf[o + 4];
      out.push({
        index: i,
        table: sec.name,
        name: cstr(buf, str.sh_offset + st_name) ?? '',
        st_name,
        st_info,
        bind: st_info >> 4,
        type: st_info & 0xf,
        st_other: buf[o + 5],
        visibility: buf[o + 5] & 0x3,
        st_shndx: buf.readUInt16LE(o + 6),
        st_value: Number(buf.readBigUInt64LE(o + 8)),
        st_size: Number(buf.readBigUInt64LE(o + 16)),
      });
    }
    return out;
  }

  const symtab = readSymtab(sections.find((s) => s.sh_type === SHT.SYMTAB));
  const dynsym = readSymtab(sections.find((s) => s.sh_type === SHT.DYNSYM));

  // ---- relocations --------------------------------------------------------
  const relocations = [];
  for (const sec of sections) {
    if (sec.sh_type !== SHT.RELA) continue;
    const n = sec.sh_entsize ? Math.floor(sec.sh_size / sec.sh_entsize) : 0;
    const symSec = sections[sec.sh_link];
    const symsFor = symSec && symSec.sh_type === SHT.DYNSYM ? dynsym : symtab;
    for (let i = 0; i < n; i++) {
      const o = sec.sh_offset + i * sec.sh_entsize;
      if (o + 24 > buf.length) break;
      const info = buf.readBigUInt64LE(o + 8);
      const symIdx = Number(info >> 32n);
      relocations.push({
        section: sec.name,
        appliesTo: sections[sec.sh_info]?.name ?? null,
        r_offset: Number(buf.readBigUInt64LE(o)),
        r_type: Number(info & 0xffffffffn),
        r_sym: symIdx,
        symbolName: symsFor[symIdx]?.name ?? null,
        r_addend: buf.readBigInt64LE(o + 16),
      });
    }
  }

  // ---- .dynamic -----------------------------------------------------------
  const dynamic = [];
  const dynSec = sections.find((s) => s.sh_type === SHT.DYNAMIC);
  if (dynSec) {
    const dstr = sections[dynSec.sh_link];
    const n = Math.floor(dynSec.sh_size / 16);
    for (let i = 0; i < n; i++) {
      const o = dynSec.sh_offset + i * 16;
      if (o + 16 > buf.length) break;
      const tag = Number(buf.readBigInt64LE(o));
      const val = buf.readBigUInt64LE(o + 8);
      const e = { tag, value: val };
      if ((tag === DT.NEEDED || tag === DT.SONAME || tag === DT.RUNPATH || tag === DT.RPATH) && dstr) {
        e.string = cstr(buf, dstr.sh_offset + Number(val));
      }
      dynamic.push(e);
      if (tag === DT.NULL) break;
    }
  }

  return {
    supported: true,
    path,
    size: buf.length,
    buf,
    ehdr,
    phdrs,
    sections,
    sectionByName: byName,
    symtab,
    dynsym,
    relocations,
    dynamic,
  };
}

export function dynTag(elf, tag) {
  return elf.dynamic.find((d) => d.tag === tag) ?? null;
}
export function dynTags(elf, tag) {
  return elf.dynamic.filter((d) => d.tag === tag);
}

/**
 * PIE is `ET_DYN` **and** `DT_FLAGS_1 & DF_1_PIE`. Both halves are load-bearing:
 * every shared library is also ET_DYN, so e_type alone reports libstdc++.so as a
 * PIE executable, and glibc's own `ld.so` is the counter-example in the other
 * direction. The returned record names the two fields so a reader of the
 * evidence can re-derive the verdict without trusting this function.
 */
export function decidePie(elf) {
  const f1 = dynTag(elf, DT.FLAGS_1);
  const flags1 = f1 ? Number(f1.value & 0xffffffffn) : null;
  const isDyn = elf.ehdr.e_type === ET.DYN;
  const hasPieBit = flags1 !== null && (flags1 & DF_1.PIE) !== 0;
  return {
    property: 'pie',
    value: isDyn && hasPieBit,
    decidedBy: [
      { field: 'Elf64_Ehdr.e_type', observed: elf.ehdr.e_type, expected: ET.DYN, note: 'ET_DYN=3' },
      { field: 'DT_FLAGS_1', observed: flags1, expectedBit: DF_1.PIE, note: 'DF_1_PIE=0x08000000' },
    ],
    reader: 'compiler/elf-verifier/lib/elf.mjs',
  };
}

/**
 * Full RELRO is `PT_GNU_RELRO` **and** eager binding. Eager binding has two
 * legal spellings — the historical `DT_BIND_NOW` tag and `DT_FLAGS_1 &
 * DF_1_NOW` (and `DT_FLAGS & DF_BIND_NOW`) — and a linker may emit only one of
 * them. Accepting one spelling is how "partial RELRO" gets reported for a fully
 * hardened binary; all three are checked and the record says which fired.
 */
export function decideRelroFull(elf) {
  const relro = elf.phdrs.find((p) => p.p_type === PT.GNU_RELRO) ?? null;
  const bindNowTag = dynTag(elf, DT.BIND_NOW);
  const flags = dynTag(elf, DT.FLAGS);
  const flags1 = dynTag(elf, DT.FLAGS_1);
  const fv = flags ? Number(flags.value & 0xffffffffn) : null;
  const f1v = flags1 ? Number(flags1.value & 0xffffffffn) : null;
  const eager =
    bindNowTag !== null || (fv !== null && (fv & DF.BIND_NOW) !== 0) || (f1v !== null && (f1v & DF_1.NOW) !== 0);
  return {
    property: 'relro-full',
    value: relro !== null && eager,
    decidedBy: [
      { field: 'Elf64_Phdr.p_type', observed: relro ? 'PT_GNU_RELRO present' : 'PT_GNU_RELRO absent', expected: 'PT_GNU_RELRO=0x6474e552' },
      { field: 'DT_BIND_NOW', observed: bindNowTag ? 'present' : 'absent' },
      { field: 'DT_FLAGS', observed: fv, expectedBit: DF.BIND_NOW, note: 'DF_BIND_NOW=0x8' },
      { field: 'DT_FLAGS_1', observed: f1v, expectedBit: DF_1.NOW, note: 'DF_1_NOW=0x1' },
    ],
    reader: 'compiler/elf-verifier/lib/elf.mjs',
  };
}

export function decideNx(elf) {
  const gs = elf.phdrs.find((p) => p.p_type === PT.GNU_STACK) ?? null;
  // No PT_GNU_STACK at all means the kernel falls back to an executable stack,
  // so "absent" is a failure and not an abstention.
  const value = gs !== null && (gs.p_flags & 0x1) === 0;
  return {
    property: 'nx',
    value,
    decidedBy: [
      { field: 'Elf64_Phdr.p_type', observed: gs ? 'PT_GNU_STACK present' : 'PT_GNU_STACK absent' },
      { field: 'Elf64_Phdr.p_flags', observed: gs ? gs.p_flags : null, forbiddenBit: 1, note: 'PF_X=0x1' },
    ],
    reader: 'compiler/elf-verifier/lib/elf.mjs',
  };
}

/**
 * Resolve `.init_array` / `.preinit_array` / `.fini_array` slots to the symbols
 * they point at.
 *
 * Three shapes, and getting any of them wrong silently produces an empty list —
 * which would then read as "no initialisers ran", the most dangerous possible
 * false negative for VG-INTRO-003:
 *
 *   ET_REL  slots are zero; `.rela.init_array` names the symbol per slot.
 *   ET_EXEC slots hold the absolute address; look the address up in .symtab.
 *   ET_DYN  slots are zero; `.rela.dyn` R_X86_64_RELATIVE carries the address
 *           in r_addend (the linker moved the value out of the image so that
 *           the slot can live in the RELRO region).
 */
export function readInitArrays(elf) {
  const kinds = [
    { name: '.preinit_array', type: SHT.PREINIT_ARRAY },
    { name: '.init_array', type: SHT.INIT_ARRAY },
    { name: '.fini_array', type: SHT.FINI_ARRAY },
  ];
  const addrIndex = new Map();
  for (const s of [...elf.symtab, ...elf.dynsym]) {
    if (s.st_shndx === SHN.UNDEF || !s.name) continue;
    if (s.type === STT.SECTION || s.type === STT.FILE) continue;
    if (!addrIndex.has(s.st_value)) addrIndex.set(s.st_value, s.name);
  }
  const out = [];
  for (const kind of kinds) {
    const secs = elf.sections.filter((s) => s.sh_type === kind.type || s.name === kind.name);
    for (const sec of secs) {
      if (!sec || sec.sh_size === 0) continue;
      const slots = Math.floor(sec.sh_size / 8);
      for (let i = 0; i < slots; i++) {
        const fileOff = sec.sh_offset + i * 8;
        const raw = fileOff + 8 <= elf.buf.length ? Number(elf.buf.readBigUInt64LE(fileOff)) : 0;
        const entry = {
          array: sec.name,
          slot: i,
          rawValue: raw,
          target: null,
          resolvedVia: null,
        };
        if (elf.ehdr.e_type === ET.REL) {
          const r = elf.relocations.find((x) => x.appliesTo === sec.name && x.r_offset === i * 8);
          if (r) {
            entry.target = r.symbolName;
            entry.resolvedVia = `Elf64_Rela in ${r.section} (r_type=${r.r_type}, r_sym=${r.r_sym})`;
          }
        } else if (raw !== 0) {
          entry.target = addrIndex.get(raw) ?? null;
          entry.resolvedVia = `Elf64_Sym.st_value == slot value 0x${raw.toString(16)}`;
        } else {
          const vaddr = sec.sh_addr + i * 8;
          const r = elf.relocations.find((x) => x.r_offset === vaddr && x.r_type === R_X86_64.RELATIVE);
          if (r) {
            const a = Number(r.r_addend);
            entry.target = addrIndex.get(a) ?? null;
            entry.resolvedVia = `R_X86_64_RELATIVE r_addend=0x${a.toString(16)} in ${r.section}`;
            entry.rawValue = a;
          } else {
            const ri = elf.relocations.find((x) => x.r_offset === vaddr && x.r_type === R_X86_64.IRELATIVE);
            if (ri) {
              entry.target = null;
              entry.resolvedVia = `R_X86_64_IRELATIVE resolver at 0x${Number(ri.r_addend).toString(16)}`;
            }
          }
        }
        out.push(entry);
      }
    }
  }
  return out;
}

/** Symbols that are *defined here*: everything the file introduces into a link. */
export function definedSymbols(elf) {
  const seen = new Map();
  for (const s of [...elf.symtab, ...elf.dynsym]) {
    if (s.st_shndx === SHN.UNDEF) continue;
    if (!s.name) continue;
    if (s.type === STT.SECTION) continue;
    const prev = seen.get(s.name);
    if (!prev) seen.set(s.name, s);
  }
  return [...seen.values()];
}

/**
 * Symbols this file needs someone else to supply: the external-call surface.
 *
 * Keyed on the version-stripped name. `.symtab` spells an undefined versioned
 * import `_Znwm@GLIBCXX_3.4` while `.dynsym` spells the same import `_Znwm`,
 * and keying on the raw string reports one external call twice — measured: a
 * restricted library allowlist produced eight VG-INTRO-002 findings for four
 * distinct calls. The versions seen are kept on the entry rather than thrown
 * away.
 */
export function undefinedSymbols(elf) {
  const seen = new Map();
  for (const s of [...elf.symtab, ...elf.dynsym]) {
    if (s.st_shndx !== SHN.UNDEF || !s.name) continue;
    const at = s.name.indexOf('@');
    const base = at === -1 ? s.name : s.name.slice(0, at);
    const version = at === -1 ? null : s.name.slice(at);
    const prev = seen.get(base);
    if (prev) {
      if (version && !prev.versions.includes(version)) prev.versions.push(version);
      continue;
    }
    seen.set(base, { ...s, name: base, versions: version ? [version] : [] });
  }
  return [...seen.values()];
}

export function neededLibraries(elf) {
  return dynTags(elf, DT.NEEDED).map((d) => d.string).filter(Boolean);
}

export function bindName(b) {
  return { 0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'GNU_UNIQUE' }[b] ?? `bind${b}`;
}
export function typeName(t) {
  return { 0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE', 5: 'COMMON', 6: 'TLS', 10: 'GNU_IFUNC' }[t] ?? `type${t}`;
}
