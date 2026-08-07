// ELF64 reader for the artefact verifier. Structural fields only.
//
// WHY THIS FILE PARSES BYTES INSTEAD OF CALLING readelf
//
// Measured on the fixture matrix that produced this component's ground-truth
// table: for one and the same binary, GNU objdump 2.42 prints the fortify call
// site as
//
//     call 1090 <__strcpy_chk@plt>
//
// and llvm-objdump 18.1.3 prints
//
//     callq 0x1090 <.plt.sec+0x20>
//
// A fortify detector written against the first spelling reports zero call sites
// under the second, on identical bytes. The same disagreement exists for the
// file type line: GNU readelf prints `DYN (Position-Independent Executable
// file)` where llvm-readelf prints `DYN (Shared object file)`.
//
// So nothing here reads another program's output. Every verdict is attributable
// to a named field at a named offset, and every record says which field decided
// it.
//
// Scope: ELF64, two's complement, little-endian. Anything else returns
// `{ supported: false, reason }`, which callers must treat as "could not look",
// never as "nothing found".

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

export const ET = { NONE: 0, REL: 1, EXEC: 2, DYN: 3, CORE: 4 };

export const PT = {
  NULL: 0, LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, SHLIB: 5, PHDR: 6, TLS: 7,
  GNU_EH_FRAME: 0x6474e550, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552,
  GNU_PROPERTY: 0x6474e553,
};

export const PF = { X: 0x1, W: 0x2, R: 0x4 };

export const SHT = {
  NULL: 0, PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, HASH: 5, DYNAMIC: 6,
  NOTE: 7, NOBITS: 8, REL: 9, SHLIB: 10, DYNSYM: 11, INIT_ARRAY: 14,
  FINI_ARRAY: 15, PREINIT_ARRAY: 16,
};

export const SHF = { WRITE: 0x1, ALLOC: 0x2, EXECINSTR: 0x4 };

export const STB = { LOCAL: 0, GLOBAL: 1, WEAK: 2 };
export const STT = { NOTYPE: 0, OBJECT: 1, FUNC: 2, SECTION: 3, FILE: 4, GNU_IFUNC: 10 };
export const SHN = { UNDEF: 0, ABS: 0xfff1, COMMON: 0xfff2 };

export const DT = {
  NULL: 0, NEEDED: 1, PLTGOT: 3, STRTAB: 5, SYMTAB: 6, SONAME: 14, RPATH: 15,
  BIND_NOW: 24, INIT_ARRAY: 25, FINI_ARRAY: 26, RUNPATH: 29, FLAGS: 30,
  PREINIT_ARRAY: 32, FLAGS_1: 0x6ffffffb,
};

export const DF = { BIND_NOW: 0x8 };
export const DF_1 = { NOW: 0x1, PIE: 0x08000000 };

export const R_X86_64 = { NONE: 0, _64: 1, GLOB_DAT: 6, JUMP_SLOT: 7, RELATIVE: 8, IRELATIVE: 37 };

/** NT_GNU_BUILD_ID. Measured on the fixture matrix: n_type=3, owner "GNU", descsz=20 for --build-id=sha1. */
export const NT_GNU_BUILD_ID = 3;

const EI_CLASS = 4, EI_DATA = 5;
const ELFCLASS64 = 2, ELFDATA2LSB = 1;

function cstr(buf, off) {
  if (!Number.isInteger(off) || off < 0 || off >= buf.length) return null;
  let end = off;
  while (end < buf.length && buf[end] !== 0) end++;
  return buf.toString('latin1', off, end);
}

function inBounds(buf, off, len) {
  return Number.isInteger(off) && off >= 0 && off + len <= buf.length;
}

/**
 * Read one ELF64 LSB image into plain structures.
 *
 * @param {string|Buffer} input path on disk, or the bytes themselves
 * @param {{path?: string}} [opts]
 */
export function readElf(input, opts = {}) {
  const buf = Buffer.isBuffer(input) ? input : readFileSync(input);
  const path = opts.path ?? (typeof input === 'string' ? input : '<buffer>');

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
    e_entry: Number(buf.readBigUInt64LE(24)),
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

  const truncated = [];

  const phdrs = [];
  for (let i = 0; i < ehdr.e_phnum; i++) {
    const o = ehdr.e_phoff + i * ehdr.e_phentsize;
    if (!inBounds(buf, o, 56)) { truncated.push(`program header ${i}`); break; }
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

  const raw = [];
  for (let i = 0; i < ehdr.e_shnum; i++) {
    const o = ehdr.e_shoff + i * ehdr.e_shentsize;
    if (!inBounds(buf, o, 64)) { truncated.push(`section header ${i}`); break; }
    raw.push({
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

  const shstr = raw[ehdr.e_shstrndx];
  const sections = raw.map((s) => ({
    ...s,
    name: shstr ? (cstr(buf, shstr.sh_offset + s.sh_name) ?? '') : '',
    writable: (s.sh_flags & SHF.WRITE) !== 0,
    allocated: (s.sh_flags & SHF.ALLOC) !== 0,
    executable: (s.sh_flags & SHF.EXECINSTR) !== 0,
  }));
  const sectionByName = new Map();
  for (const s of sections) if (s.name && !sectionByName.has(s.name)) sectionByName.set(s.name, s);

  // ---- symbol tables ------------------------------------------------------
  function readSymtab(sec) {
    if (!sec || !sec.sh_entsize) return [];
    const str = sections[sec.sh_link];
    if (!str) return [];
    const out = [];
    const n = Math.floor(sec.sh_size / sec.sh_entsize);
    for (let i = 0; i < n; i++) {
      const o = sec.sh_offset + i * sec.sh_entsize;
      if (!inBounds(buf, o, 24)) { truncated.push(`${sec.name} entry ${i}`); break; }
      const st_name = buf.readUInt32LE(o);
      const st_info = buf[o + 4];
      out.push({
        index: i,
        table: sec.name,
        name: cstr(buf, str.sh_offset + st_name) ?? '',
        st_info,
        bind: st_info >> 4,
        type: st_info & 0xf,
        visibility: buf[o + 5] & 0x3,
        st_shndx: buf.readUInt16LE(o + 6),
        st_value: Number(buf.readBigUInt64LE(o + 8)),
        st_size: Number(buf.readBigUInt64LE(o + 16)),
      });
    }
    return out;
  }

  const symtabSec = sections.find((s) => s.sh_type === SHT.SYMTAB) ?? null;
  const dynsymSec = sections.find((s) => s.sh_type === SHT.DYNSYM) ?? null;
  const symtab = readSymtab(symtabSec);
  const dynsym = readSymtab(dynsymSec);

  // ---- relocations --------------------------------------------------------
  const relocations = [];
  for (const sec of sections) {
    if (sec.sh_type !== SHT.RELA || !sec.sh_entsize) continue;
    const symSec = sections[sec.sh_link];
    const symsFor = symSec && symSec.sh_type === SHT.DYNSYM ? dynsym : symtab;
    const n = Math.floor(sec.sh_size / sec.sh_entsize);
    for (let i = 0; i < n; i++) {
      const o = sec.sh_offset + i * sec.sh_entsize;
      if (!inBounds(buf, o, 24)) { truncated.push(`${sec.name} reloc ${i}`); break; }
      const info = buf.readBigUInt64LE(o + 8);
      const symIdx = Number(info >> 32n);
      relocations.push({
        section: sec.name,
        appliesTo: sections[sec.sh_info]?.name ?? null,
        r_offset: Number(buf.readBigUInt64LE(o)),
        r_type: Number(info & 0xffffffffn),
        r_sym: symIdx,
        symbolName: symsFor[symIdx]?.name ?? null,
        r_addend: Number(buf.readBigInt64LE(o + 16)),
      });
    }
  }

  // ---- .dynamic -----------------------------------------------------------
  const dynamic = [];
  const dynSec = sections.find((s) => s.sh_type === SHT.DYNAMIC) ?? null;
  if (dynSec) {
    const dstr = sections[dynSec.sh_link];
    const n = Math.floor(dynSec.sh_size / 16);
    for (let i = 0; i < n; i++) {
      const o = dynSec.sh_offset + i * 16;
      if (!inBounds(buf, o, 16)) { truncated.push(`.dynamic entry ${i}`); break; }
      const tag = Number(buf.readBigInt64LE(o));
      const value = buf.readBigUInt64LE(o + 8);
      const e = { tag, value };
      if ((tag === DT.NEEDED || tag === DT.SONAME || tag === DT.RUNPATH || tag === DT.RPATH) && dstr) {
        e.string = cstr(buf, dstr.sh_offset + Number(value));
      }
      dynamic.push(e);
      if (tag === DT.NULL) break;
    }
  }

  // ---- notes --------------------------------------------------------------
  //
  // Parsed from the payload, not from the section name. A section *called*
  // `.note.gnu.build-id` whose note is not NT_GNU_BUILD_ID is not a build id,
  // and a detector keyed on the name says it is.
  const notes = [];
  for (const sec of sections) {
    if (sec.sh_type !== SHT.NOTE) continue;
    let o = sec.sh_offset;
    const end = sec.sh_offset + sec.sh_size;
    while (o + 12 <= end && inBounds(buf, o, 12)) {
      const namesz = buf.readUInt32LE(o);
      const descsz = buf.readUInt32LE(o + 4);
      const n_type = buf.readUInt32LE(o + 8);
      const nameOff = o + 12;
      const descOff = nameOff + Math.ceil(namesz / 4) * 4;
      const next = descOff + Math.ceil(descsz / 4) * 4;
      if (!inBounds(buf, nameOff, namesz) || !inBounds(buf, descOff, descsz) || next <= o) break;
      notes.push({
        section: sec.name,
        namesz,
        descsz,
        n_type,
        owner: buf.toString('latin1', nameOff, nameOff + namesz).replace(/\0+$/, ''),
        descHex: buf.toString('hex', descOff, descOff + descsz),
      });
      o = next;
    }
  }

  return {
    supported: true,
    path,
    size: buf.length,
    sha256: createHash('sha256').update(buf).digest('hex'),
    buf,
    ehdr,
    phdrs,
    sections,
    sectionByName,
    symtab,
    dynsym,
    hasSymtab: symtabSec !== null,
    hasDynsym: dynsymSec !== null,
    relocations,
    dynamic,
    notes,
    truncated,
  };
}

export function dynTag(elf, tag) {
  return elf.dynamic.find((d) => d.tag === tag) ?? null;
}
export function dynTags(elf, tag) {
  return elf.dynamic.filter((d) => d.tag === tag);
}
export function dynFlagValue(elf, tag) {
  const d = dynTag(elf, tag);
  return d ? Number(d.value & 0xffffffffn) : null;
}

/**
 * Which of the five shapes this image is.
 *
 * Measured (PT_INTERP / PT_DYNAMIC / e_type over the whole fixture matrix):
 *   exec-pie      ET_DYN  + PT_INTERP                     e.g. the default gcc link here
 *   exec-nonpie   ET_EXEC + PT_INTERP                     -no-pie
 *   exec-static   ET_EXEC + no PT_INTERP + no PT_DYNAMIC  -static
 *   shared-object ET_DYN  + no PT_INTERP + no DF_1_PIE    -shared      (no DT_FLAGS_1 at all)
 *   exec-static-pie ET_DYN + no PT_INTERP + DF_1_PIE      -static-pie
 *
 * The link form is read out of the image, never taken from the command line, so
 * a build whose flags and whose output disagree is caught rather than trusted.
 */
export function linkForm(elf) {
  const hasInterp = elf.phdrs.some((p) => p.p_type === PT.INTERP);
  const hasDynamic = elf.phdrs.some((p) => p.p_type === PT.DYNAMIC) || elf.dynamic.length > 0;
  const f1 = dynFlagValue(elf, DT.FLAGS_1);
  const piebit = f1 !== null && (f1 & DF_1.PIE) !== 0;
  if (elf.ehdr.e_type === ET.REL) return 'relocatable';
  if (elf.ehdr.e_type === ET.EXEC) return hasInterp || hasDynamic ? 'exec-nonpie' : 'exec-static';
  if (elf.ehdr.e_type === ET.DYN) {
    if (hasInterp) return 'exec-pie';
    if (piebit) return 'exec-static-pie';
    return 'shared-object';
  }
  return 'other';
}

/** True when the image resolves symbols at load time — i.e. the import surface is meaningful. */
export function isDynamicallyLinked(elf) {
  return elf.hasDynsym && elf.dynamic.length > 0;
}

/** Undefined symbols, keyed on the version-stripped name, versions kept. */
export function undefinedSymbols(elf) {
  const seen = new Map();
  for (const s of [...elf.dynsym, ...elf.symtab]) {
    if (s.st_shndx !== SHN.UNDEF || !s.name) continue;
    const at = s.name.indexOf('@');
    const base = at === -1 ? s.name : s.name.slice(0, at);
    const version = at === -1 ? null : s.name.slice(at);
    const prev = seen.get(base);
    if (prev) {
      if (version && !prev.versions.includes(version)) prev.versions.push(version);
      if (s.table === '.dynsym') prev.inDynsym = true;
      continue;
    }
    seen.set(base, { ...s, name: base, versions: version ? [version] : [], inDynsym: s.table === '.dynsym' });
  }
  return [...seen.values()];
}

/** Symbols this image defines. */
export function definedSymbols(elf) {
  const seen = new Map();
  for (const s of [...elf.dynsym, ...elf.symtab]) {
    if (s.st_shndx === SHN.UNDEF || !s.name || s.type === STT.SECTION) continue;
    const at = s.name.indexOf('@');
    const base = at === -1 ? s.name : s.name.slice(0, at);
    if (!seen.has(base)) seen.set(base, { ...s, name: base });
  }
  return [...seen.values()];
}

/** Exported symbols: global or weak, default/protected visibility, defined, in .dynsym. */
export function exportedSymbols(elf) {
  const out = new Map();
  for (const s of elf.dynsym) {
    if (s.st_shndx === SHN.UNDEF || !s.name) continue;
    if (s.bind !== STB.GLOBAL && s.bind !== STB.WEAK) continue;
    if (s.visibility !== 0 && s.visibility !== 3) continue;
    const base = s.name.split('@')[0];
    if (!out.has(base)) out.set(base, s);
  }
  return [...out.values()];
}

export function neededLibraries(elf) {
  return dynTags(elf, DT.NEEDED).map((d) => d.string).filter(Boolean);
}

export function runPaths(elf) {
  return [
    ...dynTags(elf, DT.RPATH).map((d) => ({ tag: 'DT_RPATH', value: d.string })),
    ...dynTags(elf, DT.RUNPATH).map((d) => ({ tag: 'DT_RUNPATH', value: d.string })),
  ].filter((x) => x.value);
}

/**
 * The linker-materialised call-site surface: R_X86_64_JUMP_SLOT relocations.
 *
 * This is the artefact-level analogue of the IR oracle rule "count the call
 * site, never the symbol name". A name can sit in `.dynstr` with nothing calling
 * it; a JUMP_SLOT slot exists because the link resolved at least one call
 * through the PLT. Measured on the fixture matrix:
 *   fortify-on  -> .rela.plt JUMP_SLOT __strcpy_chk
 *   fortify-off -> none
 *   sp-on       -> .rela.plt JUMP_SLOT __stack_chk_fail
 *   sp-off      -> none
 */
export function pltCallSites(elf) {
  const out = new Map();
  for (const r of elf.relocations) {
    if (r.r_type !== R_X86_64.JUMP_SLOT || !r.symbolName) continue;
    const base = r.symbolName.split('@')[0];
    if (!out.has(base)) out.set(base, { name: base, slots: 0, section: r.section });
    out.get(base).slots += 1;
  }
  return [...out.values()];
}

/** Every name that appears in `.dynstr`, whether or not any symbol or relocation uses it. */
export function dynstrNames(elf) {
  const sec = elf.sectionByName.get('.dynstr');
  if (!sec) return [];
  const raw = elf.buf.subarray(sec.sh_offset, sec.sh_offset + sec.sh_size).toString('latin1');
  return raw.split('\0').filter(Boolean);
}

/**
 * `.init_array` / `.preinit_array` / `.fini_array` slots resolved to the symbols
 * they point at. Three shapes, and getting any of them wrong yields an empty
 * list, which reads as "nothing runs before main" — the worst false negative
 * available here.
 */
export function initFunctions(elf) {
  const addrIndex = new Map();
  for (const s of [...elf.symtab, ...elf.dynsym]) {
    if (s.st_shndx === SHN.UNDEF || !s.name) continue;
    if (s.type === STT.SECTION || s.type === STT.FILE) continue;
    if (!addrIndex.has(s.st_value)) addrIndex.set(s.st_value, s.name);
  }
  const kinds = [
    ['.preinit_array', SHT.PREINIT_ARRAY],
    ['.init_array', SHT.INIT_ARRAY],
    ['.fini_array', SHT.FINI_ARRAY],
  ];
  const out = [];
  for (const [kindName, kindType] of kinds) {
    for (const sec of elf.sections.filter((s) => s.sh_type === kindType || s.name === kindName)) {
      if (!sec.sh_size) continue;
      const slots = Math.floor(sec.sh_size / 8);
      for (let i = 0; i < slots; i++) {
        const fileOff = sec.sh_offset + i * 8;
        let value = inBounds(elf.buf, fileOff, 8) ? Number(elf.buf.readBigUInt64LE(fileOff)) : 0;
        const entry = { array: sec.name, slot: i, value, target: null, resolvedVia: null };
        if (elf.ehdr.e_type === ET.REL) {
          const r = elf.relocations.find((x) => x.appliesTo === sec.name && x.r_offset === i * 8);
          if (r) {
            entry.target = r.symbolName;
            entry.resolvedVia = `Elf64_Rela in ${r.section}`;
          }
        } else if (value !== 0) {
          entry.target = addrIndex.get(value) ?? null;
          entry.resolvedVia = 'Elf64_Sym.st_value == slot value';
        } else {
          const vaddr = sec.sh_addr + i * 8;
          const rel = elf.relocations.find((x) => x.r_offset === vaddr && x.r_type === R_X86_64.RELATIVE);
          if (rel) {
            entry.value = rel.r_addend;
            entry.target = addrIndex.get(rel.r_addend) ?? null;
            entry.resolvedVia = `R_X86_64_RELATIVE r_addend in ${rel.section}`;
          } else {
            const irel = elf.relocations.find((x) => x.r_offset === vaddr && x.r_type === R_X86_64.IRELATIVE);
            if (irel) entry.resolvedVia = 'R_X86_64_IRELATIVE resolver';
          }
        }
        out.push(entry);
      }
    }
  }
  return out;
}
