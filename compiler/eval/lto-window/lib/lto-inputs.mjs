/**
 * Guard 1, first half: what did the linker actually get handed?
 *
 * `-Wl,--load-pass-plugin=` on a NON-LTO link is silently ignored -- not a
 * warning, not a non-zero exit, not even a message when the named file does not
 * exist (`../../docs/toolchain-probes.md` section 2.4, and re-measured by this
 * lane: rc 0, 0 bytes on stderr, and no observer log written at all). A lane
 * without this check would run a non-LTO link, see an empty log, and report a
 * compile-time observation as a link-time one -- or worse, report "observed, no
 * findings" having observed nothing.
 *
 * So the inputs are read as bytes before any cell counts. Everything here is a
 * pure function over a Buffer or over the text a tool printed; nothing here runs
 * a compiler.
 */

/** LLVM bitcode wrapper-free magic: 'B' 'C' 0xC0 0xDE. */
export const BITCODE_MAGIC = Uint8Array.from([0x42, 0x43, 0xc0, 0xde]);

/** ELF: 0x7F 'E' 'L' 'F'. */
export const ELF_MAGIC = Uint8Array.from([0x7f, 0x45, 0x4c, 0x46]);

function startsWith(bytes, magic) {
  if (!bytes || bytes.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (bytes[i] !== magic[i]) return false;
  return true;
}

/**
 * What kind of object this is, by its first four bytes.
 *
 * `llvm-bitcode` is the only answer that makes an input an LTO input for clang.
 * `elf` is the answer for a gcc `-flto` object too -- gcc puts GIMPLE in
 * `.gnu.lto_*` sections of an ordinary ELF object, so this function cannot tell
 * a gcc LTO object from a gcc non-LTO one. That is stated rather than papered
 * over: the gcc route is refused earlier, by the linker, for a different reason
 * (see the README's gcc section).
 */
export function objectKind(bytes) {
  if (!bytes || bytes.length === 0) return 'empty';
  if (startsWith(bytes, BITCODE_MAGIC)) return 'llvm-bitcode';
  if (startsWith(bytes, ELF_MAGIC)) return 'elf';
  return 'other';
}

/**
 * The LTO form an object was actually built as, read from the object rather than
 * from the runner's word.
 *
 * `llvm-bcanalyzer -dump` names the block the module summary sits in:
 * `FULL_LTO_GLOBALVAL_SUMMARY_BLOCK` for `-flto`, `GLOBALVAL_SUMMARY_BLOCK` for
 * `-flto=thin`. Measured on this lane's own objects, both spellings.
 *
 * Returns 'full', 'thin', or null when the dump says neither -- null is "this
 * text does not answer the question", never "not LTO".
 */
export function ltoFormFromBcanalyzerDump(text) {
  if (typeof text !== 'string' || text.length === 0) return null;
  if (text.includes('FULL_LTO_GLOBALVAL_SUMMARY_BLOCK')) return 'full';
  if (text.includes('GLOBALVAL_SUMMARY_BLOCK')) return 'thin';
  return null;
}

/**
 * Grade a set of link inputs against what the cell says it built.
 *
 * `ltoInputs` are the ones that must be bitcode. `opaqueInputs` are the ones the
 * fixture deliberately keeps out of the merged module, and they must NOT be
 * bitcode -- a mistake in that direction is just as fatal to the fixture (an
 * opaque unit that the link can see into stops being opaque, and the control
 * built on it stops being a control), so it is checked in both directions.
 *
 * `forms` maps an lto input's name to what `ltoFormFromBcanalyzerDump` said
 * about it, or null when no dump was available.
 */
export function gradeInputs({ ltoInputs = [], opaqueInputs = [], forms = {}, expectForm = null } = {}) {
  const problems = [];
  for (const { name, kind } of ltoInputs) {
    if (kind !== 'llvm-bitcode') {
      problems.push(`${name} is ${kind}, not LLVM bitcode: this link is not an LTO link`);
    }
  }
  for (const { name, kind } of opaqueInputs) {
    if (kind === 'llvm-bitcode') {
      problems.push(`${name} is bitcode but the fixture requires it to stay outside the merged module`);
    }
  }
  const observedForms = new Set();
  for (const { name } of ltoInputs) {
    const f = forms[name] ?? null;
    if (f === null) continue;
    observedForms.add(f);
    if (expectForm && f !== expectForm) {
      problems.push(`${name} is a ${f}-LTO object on a link this cell calls ${expectForm}`);
    }
  }
  if (observedForms.size > 1) {
    problems.push(`the lto inputs mix forms: ${[...observedForms].sort().join(', ')}`);
  }
  return {
    ok: problems.length === 0,
    problems,
    // null means no dump was readable, which is not the same as "the form
    // disagreed" and must not be reported as one.
    formFromArtifacts: observedForms.size === 1 ? [...observedForms][0] : null,
  };
}
