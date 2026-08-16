// A minimal ELF64 LSB WRITER, for the cases the fixture matrix cannot produce.
//
// THIS IS NOT COMPILER OUTPUT. Every image this file builds is assembled byte
// by byte in JavaScript, so a test that passes on one of them proves the
// DECIDER reads the field it claims to read — and proves nothing about what
// gcc, clang or GNU ld actually emit. Wherever a real binary can carry the
// case, the test uses the real binary from `artefact-fixtures.sh` and this file
// is not involved.
//
// It exists for exactly one measured gap: NO row of the 23-fixture matrix has a
// PT_LOAD segment with PF_W|PF_X. `wx-on` is re-flagged by objcopy after the
// link, so its `.vgwx` SECTION is W|A|X while every PT_LOAD stays RW-. Without
// a synthetic image the segment half of the W+X check would have no positive
// control at all, and an untested half of a detector is the half that is
// quietly broken.
//
// It is a writer, not a parser: the reader under test is ../lib/elf.mjs.

import { ET, PT, SHT, SHF, DT } from '../lib/elf.mjs';

const EHDR = 64;
const PHENT = 56;
const SHENT = 64;

function align(n, a) {
  return a <= 1 ? n : Math.ceil(n / a) * a;
}

/**
 * Build one ELF64 LSB image.
 *
 * @param {object} spec
 * @param {number} [spec.type]      e_type (default ET_DYN)
 * @param {number} [spec.machine]   e_machine (default 62, x86-64)
 * @param {Array}  [spec.phdrs]     `{ type, flags, vaddr, memsz, offset, filesz, align }`
 * @param {Array}  [spec.sections]  `{ name, type, flags, addr, data, entsize, link }`
 * @param {Array}  [spec.dynamic]   `[[tag, value], …]`; DT_NULL is appended
 * @returns {Buffer}
 */
export function buildElf64(spec = {}) {
  const type = spec.type ?? ET.DYN;
  const machine = spec.machine ?? 62;
  const phdrs = spec.phdrs ?? [];
  const userSections = [...(spec.sections ?? [])];

  if (spec.dynamic) {
    const entries = [...spec.dynamic, [DT.NULL, 0n]];
    const data = Buffer.alloc(entries.length * 16);
    entries.forEach(([tag, value], i) => {
      data.writeBigInt64LE(BigInt(tag), i * 16);
      data.writeBigUInt64LE(BigInt(value), i * 16 + 8);
    });
    userSections.push({ name: '.dynamic', type: SHT.DYNAMIC, flags: SHF.ALLOC | SHF.WRITE, data, entsize: 16 });
  }

  // Section 0 is the null entry; .shstrtab is always last.
  const names = ['', ...userSections.map((s) => s.name), '.shstrtab'];
  const strtab = Buffer.concat(names.map((n) => Buffer.from(n + '\0', 'latin1')));
  const nameOffsets = [];
  let acc = 0;
  for (const n of names) {
    nameOffsets.push(acc);
    acc += n.length + 1;
  }

  // ── layout ────────────────────────────────────────────────────────────────
  let cursor = align(EHDR + phdrs.length * PHENT, 8);
  const placed = userSections.map((s) => {
    const data = s.data ?? Buffer.alloc(0);
    const off = cursor;
    cursor = align(cursor + data.length, 8);
    return { ...s, data, offset: off };
  });
  const strtabOffset = cursor;
  cursor = align(cursor + strtab.length, 8);
  const shoff = cursor;
  const total = shoff + (placed.length + 2) * SHENT;

  const buf = Buffer.alloc(total);

  // ── e_ident + Elf64_Ehdr ──────────────────────────────────────────────────
  buf[0] = 0x7f; buf[1] = 0x45; buf[2] = 0x4c; buf[3] = 0x46; // \x7fELF
  buf[4] = 2;  // ELFCLASS64
  buf[5] = 1;  // ELFDATA2LSB
  buf[6] = 1;  // EV_CURRENT
  buf.writeUInt16LE(type, 16);
  buf.writeUInt16LE(machine, 18);
  buf.writeUInt32LE(1, 20);
  buf.writeBigUInt64LE(0n, 24);                            // e_entry
  buf.writeBigUInt64LE(BigInt(phdrs.length ? EHDR : 0), 32); // e_phoff
  buf.writeBigUInt64LE(BigInt(shoff), 40);                 // e_shoff
  buf.writeUInt32LE(0, 48);                                // e_flags
  buf.writeUInt16LE(EHDR, 52);
  buf.writeUInt16LE(PHENT, 54);
  buf.writeUInt16LE(phdrs.length, 56);
  buf.writeUInt16LE(SHENT, 58);
  buf.writeUInt16LE(placed.length + 2, 60);                // e_shnum
  buf.writeUInt16LE(placed.length + 1, 62);                // e_shstrndx (.shstrtab is last)

  // ── Elf64_Phdr[] ──────────────────────────────────────────────────────────
  phdrs.forEach((p, i) => {
    const o = EHDR + i * PHENT;
    buf.writeUInt32LE(p.type, o);
    buf.writeUInt32LE(p.flags ?? 0, o + 4);
    buf.writeBigUInt64LE(BigInt(p.offset ?? 0), o + 8);
    buf.writeBigUInt64LE(BigInt(p.vaddr ?? 0), o + 16);
    buf.writeBigUInt64LE(BigInt(p.vaddr ?? 0), o + 24);
    buf.writeBigUInt64LE(BigInt(p.filesz ?? 0), o + 32);
    buf.writeBigUInt64LE(BigInt(p.memsz ?? 0), o + 40);
    buf.writeBigUInt64LE(BigInt(p.align ?? 0x1000), o + 48);
  });

  // ── section contents ──────────────────────────────────────────────────────
  for (const s of placed) s.data.copy(buf, s.offset);
  strtab.copy(buf, strtabOffset);

  // ── Elf64_Shdr[] ──────────────────────────────────────────────────────────
  const writeShdr = (index, f) => {
    const o = shoff + index * SHENT;
    buf.writeUInt32LE(f.nameOff, o);
    buf.writeUInt32LE(f.type, o + 4);
    buf.writeBigUInt64LE(BigInt(f.flags), o + 8);
    buf.writeBigUInt64LE(BigInt(f.addr), o + 16);
    buf.writeBigUInt64LE(BigInt(f.offset), o + 24);
    buf.writeBigUInt64LE(BigInt(f.size), o + 32);
    buf.writeUInt32LE(f.link, o + 40);
    buf.writeUInt32LE(0, o + 44);
    buf.writeBigUInt64LE(BigInt(f.addralign ?? 1), o + 48);
    buf.writeBigUInt64LE(BigInt(f.entsize ?? 0), o + 56);
  };

  writeShdr(0, { nameOff: 0, type: SHT.NULL, flags: 0, addr: 0, offset: 0, size: 0, link: 0 });
  placed.forEach((s, i) => {
    writeShdr(i + 1, {
      nameOff: nameOffsets[i + 1],
      type: s.type ?? SHT.PROGBITS,
      flags: s.flags ?? 0,
      addr: s.addr ?? 0,
      offset: s.offset,
      size: s.data.length,
      link: s.link ?? 0,
      entsize: s.entsize ?? 0,
    });
  });
  writeShdr(placed.length + 1, {
    nameOff: nameOffsets[nameOffsets.length - 1],
    type: SHT.STRTAB,
    flags: 0,
    addr: 0,
    offset: strtabOffset,
    size: strtab.length,
    link: 0,
  });

  return buf;
}

/** A plain, hardened-looking PIE: R-- / R-X / RW- loads, RW- stack, RELRO, eager. */
export function cleanPie(extra = {}) {
  return buildElf64({
    type: ET.DYN,
    phdrs: [
      { type: PT.INTERP, flags: 0x4, vaddr: 0x318, memsz: 0x1c },
      { type: PT.LOAD, flags: 0x4, vaddr: 0x0, memsz: 0x1000 },
      { type: PT.LOAD, flags: 0x5, vaddr: 0x1000, memsz: 0x1000 },
      { type: PT.LOAD, flags: 0x6, vaddr: 0x3000, memsz: 0x1000 },
      { type: PT.GNU_STACK, flags: 0x6, vaddr: 0, memsz: 0 },
      { type: PT.GNU_RELRO, flags: 0x4, vaddr: 0x2df0, memsz: 0x210 },
      ...(extra.phdrs ?? []),
    ],
    sections: [
      { name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, addr: 0x1000, data: Buffer.alloc(64, 0x90) },
      ...(extra.sections ?? []),
    ],
    dynamic: extra.dynamic ?? [[DT.FLAGS, 0x8], [DT.FLAGS_1, 0x8000001]],
  });
}

export { ET, PT, SHT, SHF, DT };
