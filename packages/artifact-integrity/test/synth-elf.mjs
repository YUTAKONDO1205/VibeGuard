// A minimal ELF64 writer, so that every property has a fixture in BOTH
// directions without needing a compiler on the machine running the tests.
//
// WHY SYNTHESISE RATHER THAN CHECK IN REAL BINARIES
//
// Three reasons, in order of weight:
//
//  1. Some fixtures cannot be produced by a compiler at all, and those are the
//     ones that catch a wrong marker. `__strcpy_chk` sitting in `.dynstr` with
//     no undefined symbol and no JUMP_SLOT relocation is what a naive fortify
//     detector reports as PRESENT; no toolchain will emit it for you.
//  2. The tests must run on the machine this repository is developed on, which
//     has no ELF toolchain outside a subsystem.
//  3. A checked-in binary is opaque; the field a test depends on is invisible
//     in review.
//
// THE FIELD VALUES ARE NOT INVENTED. Every default here is the value measured
// on the real fixture matrix — see the README's table. `tools/verify-real-
// fixtures.mjs` runs the same verifier over the real binaries and asserts the
// same table, so the synthetic fixtures are pinned to reality rather than to
// this file's imagination.

const ET = { REL: 1, EXEC: 2, DYN: 3 };
const PT = { LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, GNU_STACK: 0x6474e551, GNU_RELRO: 0x6474e552 };
const SHT = { NULL: 0, PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, DYNAMIC: 6, NOTE: 7, NOBITS: 8, DYNSYM: 11, INIT_ARRAY: 14 };
const SHF = { WRITE: 0x1, ALLOC: 0x2, EXECINSTR: 0x4 };
const DT = { NULL: 0, NEEDED: 1, STRTAB: 5, SYMTAB: 6, SONAME: 14, RPATH: 15, BIND_NOW: 24, RUNPATH: 29, FLAGS: 30, FLAGS_1: 0x6ffffffb };
const R_JUMP_SLOT = 7;
const BASE = 0x1000;

class StrTab {
  constructor() { this.buf = Buffer.from([0]); this.map = new Map([['', 0]]); }
  add(s) {
    if (this.map.has(s)) return this.map.get(s);
    const off = this.buf.length;
    this.buf = Buffer.concat([this.buf, Buffer.from(s + '\0', 'latin1')]);
    this.map.set(s, off);
    return off;
  }
}

function align(n, a) { return Math.ceil(n / a) * a; }

/**
 * Build one ELF64 LSB image.
 *
 * @param {object} spec
 * @param {'exec-pie'|'exec-nonpie'|'exec-static'|'shared-object'} [spec.form]
 * @param {number|null} [spec.gnuStackFlags]  p_flags for PT_GNU_STACK; null omits the header entirely
 * @param {boolean} [spec.gnuRelro]
 * @param {number|null} [spec.dtFlags]
 * @param {number|null} [spec.dtFlags1]
 * @param {boolean} [spec.dtBindNow]
 * @param {string[]} [spec.needed]
 * @param {string|null} [spec.runpath]
 * @param {string[]} [spec.undefinedSymbols]   undefined imports in .dynsym
 * @param {string[]} [spec.definedSymbols]     defined globals in .dynsym
 * @param {string[]} [spec.jumpSlots]          symbols given a JUMP_SLOT relocation (must also be undefined)
 * @param {string[]} [spec.dynstrOnly]         names put in .dynstr and NOWHERE else
 * @param {null|{n_type:number,owner:string,desc:Buffer}} [spec.buildIdNote]
 * @param {boolean} [spec.buildIdSectionName]  emit a section called .note.gnu.build-id even if the note is not one
 * @param {{name:string,flags:number,size?:number,data?:Buffer}[]} [spec.extraSections]
 * @param {string[]} [spec.debugSections]
 * @param {Buffer|string} [spec.rodata]
 * @param {string[]} [spec.initArray]          symbol names placed in .init_array
 * @returns {Buffer}
 */
export function buildElf(spec = {}) {
  const form = spec.form ?? 'exec-pie';
  const eType = form === 'exec-nonpie' || form === 'exec-static' ? ET.EXEC : ET.DYN;
  const hasInterp = form === 'exec-pie' || form === 'exec-nonpie';
  const isDynamic = form !== 'exec-static';

  const shstr = new StrTab();
  const dynstr = new StrTab();
  const strtab = new StrTab();

  const undef = spec.undefinedSymbols ?? [];
  const defined = spec.definedSymbols ?? [];
  const jumpSlots = spec.jumpSlots ?? [];
  const dynstrOnly = spec.dynstrOnly ?? [];

  // ---- pieces -------------------------------------------------------------
  const pieces = [];      // { name, type, flags, data, entsize, link, info, addralign }
  const byName = new Map();
  const push = (p) => { pieces.push(p); byName.set(p.name, pieces.length); return pieces.length; }; // 1-based (0 is SHN_UNDEF)

  if (hasInterp) push({ name: '.interp', type: SHT.PROGBITS, flags: SHF.ALLOC, data: Buffer.from('/lib64/ld-linux-x86-64.so.2\0', 'latin1') });

  const note = spec.buildIdNote === undefined
    ? { n_type: 3, owner: 'GNU', desc: Buffer.from('a2a9fd890e17018ae61e6f9c1beded5ed3615e9e', 'hex') }
    : spec.buildIdNote;
  if (note) {
    const owner = Buffer.from(note.owner + '\0', 'latin1');
    const nh = Buffer.alloc(12);
    nh.writeUInt32LE(owner.length, 0);
    nh.writeUInt32LE(note.desc.length, 4);
    nh.writeUInt32LE(note.n_type, 8);
    const pad = (b) => Buffer.concat([b, Buffer.alloc(align(b.length, 4) - b.length)]);
    push({
      name: spec.buildIdSectionName === false ? '.note.custom' : '.note.gnu.build-id',
      type: SHT.NOTE, flags: SHF.ALLOC,
      data: Buffer.concat([nh, pad(owner), pad(note.desc)]), addralign: 4,
    });
  } else if (spec.buildIdSectionName) {
    // A section with the right NAME whose note is NOT a build id. This is the
    // fixture that separates "reads the payload" from "reads the section name".
    const owner = Buffer.from('GNU\0', 'latin1');
    const desc = Buffer.from('0123', 'latin1');
    const nh = Buffer.alloc(12);
    nh.writeUInt32LE(owner.length, 0);
    nh.writeUInt32LE(desc.length, 4);
    nh.writeUInt32LE(1, 8); // NT_GNU_ABI_TAG, not NT_GNU_BUILD_ID
    push({ name: '.note.gnu.build-id', type: SHT.NOTE, flags: SHF.ALLOC, data: Buffer.concat([nh, owner, desc]), addralign: 4 });
  }

  // .dynsym / .dynstr
  let dynsymIndexOf = new Map();
  if (isDynamic) {
    for (const n of dynstrOnly) dynstr.add(n);
    const syms = [{ name: '', shndx: 0, info: 0 }];
    for (const n of undef) { dynsymIndexOf.set(n, syms.length); syms.push({ name: n, shndx: 0, info: (1 << 4) | 2 }); }
    for (const n of defined) { dynsymIndexOf.set(n, syms.length); syms.push({ name: n, shndx: 1, info: (1 << 4) | 2 }); }
    const dsData = Buffer.alloc(syms.length * 24);
    syms.forEach((s, i) => {
      const o = i * 24;
      dsData.writeUInt32LE(dynstr.add(s.name), o);
      dsData.writeUInt8(s.info, o + 4);
      dsData.writeUInt8(0, o + 5);
      dsData.writeUInt16LE(s.shndx, o + 6);
      dsData.writeBigUInt64LE(BigInt(s.shndx === 0 ? 0 : 0x2000 + i * 16), o + 8);
      dsData.writeBigUInt64LE(0n, o + 16);
    });
    push({ name: '.dynsym', type: SHT.DYNSYM, flags: SHF.ALLOC, data: dsData, entsize: 24, linkName: '.dynstr', info: 1 });
  }

  const needed = spec.needed ?? (isDynamic ? ['libc.so.6'] : []);
  for (const n of needed) dynstr.add(n);
  if (spec.runpath) dynstr.add(spec.runpath);
  if (spec.soname) dynstr.add(spec.soname);

  if (isDynamic) push({ name: '.dynstr', type: SHT.STRTAB, flags: SHF.ALLOC, data: dynstr.buf });

  if (isDynamic && jumpSlots.length > 0) {
    const rela = Buffer.alloc(jumpSlots.length * 24);
    jumpSlots.forEach((n, i) => {
      const idx = dynsymIndexOf.get(n);
      if (idx === undefined) throw new Error(`jumpSlots names ${n}, which is in neither undefinedSymbols nor definedSymbols`);
      rela.writeBigUInt64LE(BigInt(0x4000 + i * 8), i * 24);
      rela.writeBigUInt64LE((BigInt(idx) << 32n) | BigInt(R_JUMP_SLOT), i * 24 + 8);
      rela.writeBigInt64LE(0n, i * 24 + 16);
    });
    push({ name: '.rela.plt', type: SHT.RELA, flags: SHF.ALLOC, data: rela, entsize: 24, linkName: '.dynsym', info: 0 });
  }

  push({ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.from('f30f1efa4831c0c3', 'hex'), addralign: 16 });

  const rodata = spec.rodata === undefined ? Buffer.from('artefact-integrity-control-string\0', 'latin1')
    : Buffer.isBuffer(spec.rodata) ? spec.rodata : Buffer.from(String(spec.rodata) + '\0', 'latin1');
  push({ name: '.rodata', type: SHT.PROGBITS, flags: SHF.ALLOC, data: rodata });

  for (const s of spec.extraSections ?? []) {
    push({ name: s.name, type: s.type ?? SHT.PROGBITS, flags: s.flags, data: s.data ?? Buffer.alloc(s.size ?? 16) });
  }

  const initArray = spec.initArray ?? [];
  let initArrayIdx = null;
  if (initArray.length > 0) {
    initArrayIdx = push({ name: '.init_array', type: SHT.INIT_ARRAY, flags: SHF.WRITE | SHF.ALLOC, data: Buffer.alloc(initArray.length * 8), entsize: 8 });
  }

  let dynIdx = null;
  if (isDynamic) {
    const entries = [];
    for (const n of needed) entries.push([DT.NEEDED, dynstr.add(n)]);
    if (spec.soname) entries.push([DT.SONAME, dynstr.add(spec.soname)]);
    if (spec.runpath) entries.push([DT.RUNPATH, dynstr.add(spec.runpath)]);
    if (spec.dtBindNow) entries.push([DT.BIND_NOW, 0]);
    if (spec.dtFlags !== null && spec.dtFlags !== undefined) entries.push([DT.FLAGS, spec.dtFlags]);
    if (spec.dtFlags1 !== null && spec.dtFlags1 !== undefined) entries.push([DT.FLAGS_1, spec.dtFlags1]);
    entries.push([DT.NULL, 0]);
    const d = Buffer.alloc(entries.length * 16);
    entries.forEach(([t, v], i) => { d.writeBigInt64LE(BigInt(t), i * 16); d.writeBigUInt64LE(BigInt(v), i * 16 + 8); });
    dynIdx = push({ name: '.dynamic', type: SHT.DYNAMIC, flags: SHF.WRITE | SHF.ALLOC, data: d, entsize: 16, linkName: '.dynstr' });
  }

  push({ name: '.data', type: SHT.PROGBITS, flags: SHF.WRITE | SHF.ALLOC, data: Buffer.alloc(32) });

  for (const name of spec.debugSections ?? []) {
    push({ name, type: SHT.PROGBITS, flags: 0, data: Buffer.from((spec.debugPayload ?? 'compilation unit') + '\0', 'latin1') });
  }

  // .symtab, so `initFunctions` can resolve addresses by symbol value
  const localSyms = [{ name: '', value: 0, shndx: 0 }];
  for (const n of initArray) localSyms.push({ name: n, value: 0x8000 + localSyms.length * 16, shndx: byName.get('.text') ?? 1 });
  for (const n of defined) localSyms.push({ name: n, value: 0x2000 + (dynsymIndexOf.get(n) ?? 1) * 16, shndx: byName.get('.text') ?? 1 });
  if (spec.symtab !== false) {
    const st = Buffer.alloc(localSyms.length * 24);
    localSyms.forEach((s, i) => {
      const o = i * 24;
      st.writeUInt32LE(strtab.add(s.name), o);
      st.writeUInt8(s.name ? (1 << 4) | 2 : 0, o + 4);
      st.writeUInt8(0, o + 5);
      st.writeUInt16LE(s.shndx, o + 6);
      st.writeBigUInt64LE(BigInt(s.value), o + 8);
      st.writeBigUInt64LE(0n, o + 16);
    });
    push({ name: '.symtab', type: SHT.SYMTAB, flags: 0, data: st, entsize: 24, linkName: '.strtab', info: 1 });
    push({ name: '.strtab', type: SHT.STRTAB, flags: 0, data: strtab.buf });
  }

  const shstrIdx = push({ name: '.shstrtab', type: SHT.STRTAB, flags: 0, data: Buffer.alloc(0) });
  for (const p of pieces) shstr.add(p.name);
  pieces[shstrIdx - 1].data = shstr.buf;

  // ---- fill .init_array now that symbol values exist ----------------------
  if (initArrayIdx !== null) {
    const d = pieces[initArrayIdx - 1].data;
    initArray.forEach((n, i) => {
      const s = localSyms.find((x) => x.name === n);
      d.writeBigUInt64LE(BigInt(s ? s.value : 0), i * 8);
    });
  }

  // ---- lay out ------------------------------------------------------------
  const phdrCount =
    (hasInterp ? 1 : 0) + 1 /* LOAD */ + (isDynamic ? 1 : 0) +
    (spec.gnuStackFlags === null ? 0 : 1) + (spec.gnuRelro === false ? 0 : 1);
  let off = align(64 + phdrCount * 56, 16);
  for (const p of pieces) {
    const a = p.addralign ?? 8;
    off = align(off, a);
    p.offset = off;
    p.addr = p.flags & SHF.ALLOC ? BASE + off : 0;
    off += p.data.length;
  }
  const shoff = align(off, 8);
  const total = shoff + (pieces.length + 1) * 64;
  const buf = Buffer.alloc(total);

  // ehdr
  buf.write('\x7fELF', 0, 'latin1');
  buf[4] = 2; buf[5] = 1; buf[6] = 1; buf[7] = 0;
  buf.writeUInt16LE(eType, 16);
  buf.writeUInt16LE(0x3e, 18);       // EM_X86_64
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(BigInt(BASE + (byName.has('.text') ? pieces[byName.get('.text') - 1].offset : 0)), 24);
  buf.writeBigUInt64LE(64n, 32);
  buf.writeBigUInt64LE(BigInt(shoff), 40);
  buf.writeUInt32LE(0, 48);
  buf.writeUInt16LE(64, 52);
  buf.writeUInt16LE(56, 54);
  buf.writeUInt16LE(phdrCount, 56);
  buf.writeUInt16LE(64, 58);
  buf.writeUInt16LE(pieces.length + 1, 60);
  buf.writeUInt16LE(shstrIdx, 62);

  // phdrs
  let po = 64;
  const phdr = (type, flags, offset, vaddr, filesz, memsz, alignv) => {
    buf.writeUInt32LE(type, po);
    buf.writeUInt32LE(flags, po + 4);
    buf.writeBigUInt64LE(BigInt(offset), po + 8);
    buf.writeBigUInt64LE(BigInt(vaddr), po + 16);
    buf.writeBigUInt64LE(BigInt(vaddr), po + 24);
    buf.writeBigUInt64LE(BigInt(filesz), po + 32);
    buf.writeBigUInt64LE(BigInt(memsz), po + 40);
    buf.writeBigUInt64LE(BigInt(alignv), po + 48);
    po += 56;
  };
  if (hasInterp) {
    const p = pieces[byName.get('.interp') - 1];
    phdr(PT.INTERP, 4, p.offset, p.addr, p.data.length, p.data.length, 1);
  }
  phdr(PT.LOAD, spec.loadFlags ?? 5, 0, BASE, off, off, 0x1000);
  if (isDynamic) {
    const p = pieces[dynIdx - 1];
    phdr(PT.DYNAMIC, 6, p.offset, p.addr, p.data.length, p.data.length, 8);
  }
  if (spec.gnuStackFlags !== null) phdr(PT.GNU_STACK, spec.gnuStackFlags ?? 6, 0, 0, 0, 0, 0x10);
  if (spec.gnuRelro !== false) {
    const p = pieces[(dynIdx ?? byName.get('.data')) - 1];
    phdr(PT.GNU_RELRO, 4, p.offset, p.addr, p.data.length, p.data.length, 1);
  }

  // section contents
  for (const p of pieces) p.data.copy(buf, p.offset);

  // section headers (index 0 is the mandatory all-zero entry)
  const writeShdr = (i, s) => {
    const o = shoff + i * 64;
    buf.writeUInt32LE(s.name, o);
    buf.writeUInt32LE(s.type, o + 4);
    buf.writeBigUInt64LE(BigInt(s.flags), o + 8);
    buf.writeBigUInt64LE(BigInt(s.addr), o + 16);
    buf.writeBigUInt64LE(BigInt(s.offset), o + 24);
    buf.writeBigUInt64LE(BigInt(s.size), o + 32);
    buf.writeUInt32LE(s.link, o + 40);
    buf.writeUInt32LE(s.info, o + 44);
    buf.writeBigUInt64LE(BigInt(s.addralign), o + 48);
    buf.writeBigUInt64LE(BigInt(s.entsize), o + 56);
  };
  writeShdr(0, { name: 0, type: 0, flags: 0, addr: 0, offset: 0, size: 0, link: 0, info: 0, addralign: 0, entsize: 0 });
  pieces.forEach((p, i) => writeShdr(i + 1, {
    name: shstr.map.get(p.name),
    type: p.type,
    flags: p.flags,
    addr: p.addr,
    offset: p.offset,
    size: p.data.length,
    link: p.linkName ? byName.get(p.linkName) : 0,
    info: p.info ?? 0,
    addralign: p.addralign ?? 8,
    entsize: p.entsize ?? 0,
  }));

  return buf;
}

export const FLAGS = { SHF, PT, DT, ET, SHT };

// ── The measured matrix, as fixture recipes ─────────────────────────────────
//
// Each entry reproduces the structural fields recorded for the same-named real
// binary in the measured table.
export const RECIPES = {
  // gcc 13.3.0 default link on this distribution: PIE, full RELRO, NX, build id.
  hardened: () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, gnuRelro: true,
    dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['__stack_chk_fail', '__strcpy_chk', 'puts', 'strlen'],
    jumpSlots: ['__stack_chk_fail', '__strcpy_chk'],
  }),
  // -O0 -fno-stack-protector -U_FORTIFY_SOURCE -no-pie -z norelro -z execstack
  // --build-id=none -g
  unhardened: () => buildElf({
    form: 'exec-nonpie', gnuStackFlags: 7, gnuRelro: false,
    dtFlags: null, dtFlags1: null, buildIdNote: null,
    undefinedSymbols: ['puts', 'strlen', 'strcpy', 'printf'],
    jumpSlots: [],
    debugSections: ['.debug_info', '.debug_line', '.debug_str', '.debug_line_str'],
  }),
  'sp-on': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['__stack_chk_fail', 'puts', 'strcpy'], jumpSlots: ['__stack_chk_fail'],
  }),
  'sp-off': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts', 'strcpy'], jumpSlots: [],
  }),
  'pie-on': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'pie-off': () => buildElf({ form: 'exec-nonpie', gnuStackFlags: 6, dtFlags: null, dtFlags1: null, undefinedSymbols: ['puts'] }),
  'shared-object': () => buildElf({ form: 'shared-object', gnuStackFlags: 6, dtFlags: null, dtFlags1: null, needed: [], soname: 'libshared.so' }),
  'relro-full': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, gnuRelro: true, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'relro-part': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, gnuRelro: true, dtFlags: null, dtFlags1: 0x8000000, undefinedSymbols: ['puts'] }),
  'relro-none': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, gnuRelro: false, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'nx-on': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'nx-off': () => buildElf({ form: 'exec-pie', gnuStackFlags: 7, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'nx-absent': () => buildElf({ form: 'exec-pie', gnuStackFlags: null, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'fortify-on': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['__strcpy_chk', 'puts', 'strlen'], jumpSlots: ['__strcpy_chk'],
  }),
  'fortify-off': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['strcpy', 'printf', 'puts', 'strlen'], jumpSlots: [],
  }),
  // Nothing fortifiable is called: ABSENT would be a lie, NOT_OBSERVED is the truth.
  'fortify-nothing-to-fortify': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['abort', 'exit'], jumpSlots: [],
  }),
  // The wrong-marker fixture: the NAME is in .dynstr, nothing calls it.
  'fortify-name-only': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['strcpy', 'puts'], jumpSlots: [],
    dynstrOnly: ['__strcpy_chk', '__stack_chk_fail'],
  }),
  'buildid-on': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'] }),
  'buildid-off': () => buildElf({ form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'], buildIdNote: null }),
  // Section named .note.gnu.build-id, note payload is NT_GNU_ABI_TAG.
  'buildid-name-only': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], buildIdNote: null, buildIdSectionName: true,
  }),
  'wx-section': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'],
    extraSections: [{ name: '.vgwx', flags: SHF.WRITE | SHF.ALLOC | SHF.EXECINSTR, size: 16 }],
  }),
  'wx-segment': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001, undefinedSymbols: ['puts'],
    loadFlags: 7,
  }),
  'static-hardened': () => buildElf({
    form: 'exec-static', gnuStackFlags: 6, gnuRelro: true,
    definedSymbols: [], undefinedSymbols: [], needed: [],
  }),
  'rpath': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], runpath: '/opt/vendor/lib',
  }),
  'init-array': () => buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], initArray: ['frame_dummy', 'backdoor_ctor'],
  }),
};
