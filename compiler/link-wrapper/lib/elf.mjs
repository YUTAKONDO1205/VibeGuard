// Just enough ELF to answer two questions about the artefact this link produced:
// where does it start, and is it still the same file.
//
// Deliberately NOT a call to readelf. The wrapper has to run on the machine
// that did the link, and the check that the artefact was not modified after the
// link has to work when readelf is absent — a post-link modification is exactly
// the situation in which one should not assume the surrounding tools are the
// ones that were there before. The header is 64 bytes with fixed offsets, so
// there is nothing to gain by shelling out and a dependency to lose.
//
// Fields read, ELF64 (little- and big-endian both handled because the endianness
// byte is right there and ignoring it is how a checker silently reports 0):
//
//   e_ident[EI_CLASS]  byte 4   1 = ELF32, 2 = ELF64
//   e_ident[EI_DATA]   byte 5   1 = little, 2 = big
//   e_type             +16      2 = EXEC, 3 = DYN (a PIE is DYN)
//   e_entry            +24 (64-bit) / +24 (32-bit is +24 too, but 4 bytes)

export const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);

export const ET = { 0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE' };

/**
 * @param {Buffer} buf
 * @returns {{ok: true, class: 32|64, endian: 'little'|'big', type: string,
 *            typeCode: number, entry: number, machine: number}
 *         | {ok: false, why: string}}
 */
export function readElfHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 24) return { ok: false, why: 'shorter than an ELF header' };
  if (!buf.subarray(0, 4).equals(ELF_MAGIC)) return { ok: false, why: 'no ELF magic' };

  const cls = buf[4];
  const data = buf[5];
  if (cls !== 1 && cls !== 2) return { ok: false, why: `unknown EI_CLASS ${cls}` };
  if (data !== 1 && data !== 2) return { ok: false, why: `unknown EI_DATA ${data}` };
  const little = data === 1;
  const bits = cls === 2 ? 64 : 32;
  const need = bits === 64 ? 64 : 52;
  if (buf.length < need) return { ok: false, why: `truncated ${bits}-bit header` };

  const u16 = (off) => (little ? buf.readUInt16LE(off) : buf.readUInt16BE(off));
  const u32 = (off) => (little ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const u64 = (off) => {
    const v = little ? buf.readBigUInt64LE(off) : buf.readBigUInt64BE(off);
    // Rule 4 of §5: records carry integers. An entry point above 2^53 cannot be
    // one, so it is reported as unreadable rather than rounded into the record.
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) return null;
    return Number(v);
  };

  const typeCode = u16(16);
  const machine = u16(18);
  const entry = bits === 64 ? u64(24) : u32(24);
  if (entry === null) return { ok: false, why: 'entry point is outside the exact-integer range' };

  return { ok: true, class: bits, endian: little ? 'little' : 'big', type: ET[typeCode] ?? `UNKNOWN(${typeCode})`, typeCode, entry, machine };
}
