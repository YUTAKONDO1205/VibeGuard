// The hardening set, decided from structural fields.
//
// EVERY PREDICATE HERE WAS WRITTEN AGAINST A MEASURED TABLE, NOT AGAINST WHAT
// readelf WAS EXPECTED TO PRINT. The table is reproduced in
// `compiler/elf-verifier/artefact-ground-truth.md` and, in the form a reader
// of this package needs, in its README; the three rows that killed
// the obvious implementation are repeated here because they are the reason each
// predicate has the shape it has.
//
//  1. `-Wl,-z,norelro` removes PT_GNU_RELRO but LEAVES DT_FLAGS=BIND_NOW and
//     DT_FLAGS_1=NOW set. A RELRO check keyed on eager binding calls that
//     binary FULL RELRO. Measured: relro-none has DT_FLAGS 0x8, DT_FLAGS_1
//     0x8000001, PT_GNU_RELRO absent.
//  2. `-Wl,-z,relro,-z,lazy` keeps PT_GNU_RELRO and drops eager binding
//     entirely (no DT_FLAGS tag at all, DT_FLAGS_1 = 0x8000000, PIE only). A
//     check keyed on PT_GNU_RELRO calls that binary FULL RELRO.
//  3. DT_BIND_NOW (tag 24) is ABSENT on every one of the twenty-three fixtures.
//     GNU ld 2.42 spells eager binding only through DT_FLAGS / DT_FLAGS_1. A
//     check keyed on DT_BIND_NOW alone reports partial RELRO for everything,
//     including the fully hardened link.
//
// And the one that matters most, because it is the failure the brief names —
// calling a binary CLEAN because the marker was wrong:
//
//  4. In a `-static` image `__stack_chk_fail` is DEFINED whether or not the
//     program was built with the protector (the C library brings it), and the
//     canary-load instruction count is 355 with the protector against 353
//     without. Neither the symbol oracle nor the whole-image instruction oracle
//     can separate those. So a static image is NOT_OBSERVED for
//     stack-protector and fortify — never PRESENT, never ABSENT.

import {
  ET, PT, PF, SHF, DT, DF, DF_1, SHN, NT_GNU_BUILD_ID,
  dynTag, dynFlagValue, linkForm, isDynamicallyLinked,
  undefinedSymbols, definedSymbols, pltCallSites, neededLibraries,
} from './elf.mjs';

/** interfaces.md section 3. "We did not see it" and "it is not there" are different claims. */
export const STATE = {
  PRESENT: 'PRESENT',
  ABSENT: 'ABSENT',
  LOST: 'LOST',
  REINTRODUCED: 'REINTRODUCED',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  NOT_OBSERVED: 'NOT_OBSERVED',
};

export const ALL_STATES = Object.values(STATE);

/** The property names `policy.artifact.require` may contain (compiler/schema/policy.schema.json). */
export const HARDENING_PROPERTIES = [
  'pie',
  'nx',
  'relro-full',
  'stack-protector',
  'fortify',
  'build-id',
];

function record(property, state, decidedBy, note) {
  return { property, state, decidedBy, note: note ?? null };
}

// ── PIE ─────────────────────────────────────────────────────────────────────
//
// ET_DYN **and** DF_1_PIE. Both halves: every shared object is ET_DYN too, and
// the measured shared-object fixture carries no DT_FLAGS_1 at all, so e_type
// alone reports libshared.so as a position-independent executable.
export function decidePie(elf) {
  const form = linkForm(elf);
  const f1 = dynFlagValue(elf, DT.FLAGS_1);
  const isDyn = elf.ehdr.e_type === ET.DYN;
  const hasPieBit = f1 !== null && (f1 & DF_1.PIE) !== 0;
  const decidedBy = [
    { field: 'Elf64_Ehdr.e_type', observed: elf.ehdr.e_type, expected: ET.DYN, note: 'ET_DYN=3' },
    { field: 'DT_FLAGS_1', observed: f1, expectedBit: DF_1.PIE, note: 'DF_1_PIE=0x08000000' },
  ];
  if (form === 'shared-object') {
    return record('pie', STATE.NOT_APPLICABLE, decidedBy,
      'A shared object is position-independent by construction and carries no DF_1_PIE; the executable question has no referent here.');
  }
  if (form === 'relocatable') {
    return record('pie', STATE.NOT_APPLICABLE, decidedBy, 'ET_REL has no load-time layout yet.');
  }
  return record('pie', isDyn && hasPieBit ? STATE.PRESENT : STATE.ABSENT, decidedBy);
}

// ── NX ──────────────────────────────────────────────────────────────────────
//
// PT_GNU_STACK present **and** PF_X clear. Absent is a failure, not an
// abstention: with no PT_GNU_STACK the kernel falls back to an executable stack.
// Measured: p_flags 6 (RW) with -z noexecstack, 7 (RWE) with -z execstack.
export function decideNx(elf) {
  const gs = elf.phdrs.find((p) => p.p_type === PT.GNU_STACK) ?? null;
  const decidedBy = [
    { field: 'Elf64_Phdr.p_type', observed: gs ? 'PT_GNU_STACK present' : 'PT_GNU_STACK absent', expected: 'PT_GNU_STACK=0x6474e551' },
    { field: 'Elf64_Phdr.p_flags', observed: gs ? gs.p_flags : null, forbiddenBit: PF.X, note: 'PF_X=0x1' },
  ];
  const value = gs !== null && (gs.p_flags & PF.X) === 0;
  return record('nx', value ? STATE.PRESENT : STATE.ABSENT, decidedBy,
    gs === null ? 'No PT_GNU_STACK: the kernel falls back to an executable stack.' : null);
}

// ── RELRO ───────────────────────────────────────────────────────────────────
export function decideRelro(elf) {
  const relro = elf.phdrs.find((p) => p.p_type === PT.GNU_RELRO) ?? null;
  const bindNowTag = dynTag(elf, DT.BIND_NOW);
  const fv = dynFlagValue(elf, DT.FLAGS);
  const f1v = dynFlagValue(elf, DT.FLAGS_1);
  const eager =
    bindNowTag !== null ||
    (fv !== null && (fv & DF.BIND_NOW) !== 0) ||
    (f1v !== null && (f1v & DF_1.NOW) !== 0);
  const decidedBy = [
    { field: 'Elf64_Phdr.p_type', observed: relro ? 'PT_GNU_RELRO present' : 'PT_GNU_RELRO absent', expected: 'PT_GNU_RELRO=0x6474e552' },
    { field: 'DT_BIND_NOW', observed: bindNowTag ? 'present' : 'absent', note: 'absent on every measured fixture; GNU ld 2.42 uses the flag words instead' },
    { field: 'DT_FLAGS', observed: fv, expectedBit: DF.BIND_NOW, note: 'DF_BIND_NOW=0x8' },
    { field: 'DT_FLAGS_1', observed: f1v, expectedBit: DF_1.NOW, note: 'DF_1_NOW=0x1' },
  ];
  // A static image has no lazy binding surface at all, so eager binding is not
  // a question that has a referent; the verdict rests on PT_GNU_RELRO alone.
  const dynamicallyLinked = isDynamicallyLinked(elf);
  const full = relro !== null && (eager || !dynamicallyLinked);
  const level = relro === null ? 'none' : (eager || !dynamicallyLinked) ? 'full' : 'partial';
  return {
    ...record('relro-full', full ? STATE.PRESENT : STATE.ABSENT, decidedBy,
      dynamicallyLinked ? null : 'Statically linked: no lazy binding surface, so eager binding is NOT_APPLICABLE and PT_GNU_RELRO decides alone.'),
    level,
    eagerBinding: dynamicallyLinked ? eager : null,
  };
}

// ── STACK PROTECTOR ─────────────────────────────────────────────────────────
//
// Oracle: the linker-materialised CALL SITE (an R_X86_64_JUMP_SLOT relocation
// naming __stack_chk_fail), or the undefined import of the same name. Never the
// mere presence of the string in `.dynstr` — that is the artefact-level twin of
// grepping for `llvm.memset` and matching the surviving `declare`.
const PROTECTOR_NAMES = new Set(['__stack_chk_fail', '__stack_chk_fail_local']);

export function decideStackProtector(elf) {
  const form = linkForm(elf);
  const dynamicallyLinked = isDynamicallyLinked(elf);
  const callSites = pltCallSites(elf).filter((c) => PROTECTOR_NAMES.has(c.name));
  const imports = undefinedSymbols(elf).filter((s) => PROTECTOR_NAMES.has(s.name));
  const decidedBy = [
    { field: 'R_X86_64_JUMP_SLOT', observed: callSites.map((c) => c.name), note: 'the materialised call site, not the name' },
    { field: 'Elf64_Sym st_shndx==SHN_UNDEF', observed: imports.map((s) => s.name) },
    { field: 'link form', observed: form },
  ];
  if (!dynamicallyLinked) {
    const defined = definedSymbols(elf).filter((s) => PROTECTOR_NAMES.has(s.name)).map((s) => s.name);
    return record('stack-protector', STATE.NOT_OBSERVED,
      [...decidedBy, { field: 'defined symbols', observed: defined }],
      'Statically linked. Measured on the fixture matrix: __stack_chk_fail is DEFINED in both the protected and the unprotected static build, and the canary-load instruction count is 355 against 353 — the whole-image oracle cannot separate them. Deciding this needs per-object attribution, which is a different observation point.');
  }
  const present = callSites.length > 0 || imports.length > 0;
  return record('stack-protector', present ? STATE.PRESENT : STATE.ABSENT, decidedBy,
    present ? null : 'No call site and no import of __stack_chk_fail. A build whose functions are all protector-ineligible would look the same; the fixture that produced this rule has a 64-byte stack array and a strcpy into it.');
}

// ── FORTIFY ─────────────────────────────────────────────────────────────────
//
// Oracle: call sites to the `__*_chk` family, minus the two protector symbols
// which belong to the property above.
//
// The extra half — and the reason this is not just a name search — is the
// FORTIFIABLE SURFACE control. Zero `_chk` call sites in a program that also
// makes no fortifiable call is not evidence that fortification is off; it is
// evidence that nothing was there to fortify. That case is NOT_OBSERVED.
const CHK_RE = /^__[A-Za-z0-9_]+_chk$/;
const FORTIFIABLE = new Set([
  'memcpy', 'memmove', 'memset', 'mempcpy', 'strcpy', 'stpcpy', 'strncpy',
  'strcat', 'strncat', 'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
  'printf', 'fprintf', 'vprintf', 'vfprintf', 'gets', 'read', 'realpath',
  'getcwd', 'wcscpy', 'wmemcpy', 'poll', 'ppoll', 'confstr', 'pread',
]);

export function decideFortify(elf) {
  const dynamicallyLinked = isDynamicallyLinked(elf);
  const isChk = (n) => CHK_RE.test(n) && !PROTECTOR_NAMES.has(n) && n !== '__stack_chk_guard';
  const callSites = pltCallSites(elf).filter((c) => isChk(c.name));
  const imports = undefinedSymbols(elf).filter((s) => isChk(s.name));
  const unfortified = undefinedSymbols(elf).filter((s) => FORTIFIABLE.has(s.name)).map((s) => s.name).sort();
  const decidedBy = [
    { field: 'R_X86_64_JUMP_SLOT', observed: callSites.map((c) => c.name) },
    { field: 'Elf64_Sym st_shndx==SHN_UNDEF', observed: imports.map((s) => s.name) },
    { field: 'fortifiable surface (unfortified imports)', observed: unfortified },
  ];
  if (!dynamicallyLinked) {
    const defined = definedSymbols(elf).filter((s) => isChk(s.name)).map((s) => s.name).sort();
    return record('fortify', STATE.NOT_OBSERVED,
      [...decidedBy, { field: 'defined _chk symbols', observed: defined.length }],
      `Statically linked. Measured: the unfortified static build defines 8 __*_chk symbols and the fortified one defines 9, both brought in by the C library. The whole-image oracle cannot separate them.`);
  }
  const n = callSites.length + imports.length;
  if (n > 0) return record('fortify', STATE.PRESENT, decidedBy);
  if (unfortified.length === 0) {
    return record('fortify', STATE.NOT_OBSERVED, decidedBy,
      'No __*_chk call site, and no fortifiable call either. Nothing was there to fortify, so this is not evidence that fortification is off.');
  }
  return record('fortify', STATE.ABSENT, decidedBy,
    `Fortifiable calls are imported unfortified: ${unfortified.join(', ')}.`);
}

// ── BUILD ID ────────────────────────────────────────────────────────────────
//
// Decided from the NOTE PAYLOAD (n_type == NT_GNU_BUILD_ID, owner "GNU",
// descsz > 0), not from a section called `.note.gnu.build-id`. Measured on the
// hardened fixture: namesz=4 descsz=20 n_type=3 owner="GNU".
export function decideBuildId(elf) {
  const note = elf.notes.find((n) => n.n_type === NT_GNU_BUILD_ID && n.owner === 'GNU' && n.descsz > 0) ?? null;
  const namedSection = elf.sectionByName.has('.note.gnu.build-id');
  const decidedBy = [
    { field: 'Elf64_Nhdr.n_type', observed: note ? note.n_type : null, expected: NT_GNU_BUILD_ID, note: 'NT_GNU_BUILD_ID=3' },
    { field: 'Elf64_Nhdr owner', observed: note ? note.owner : null, expected: 'GNU' },
    { field: 'Elf64_Nhdr.n_descsz', observed: note ? note.descsz : null },
    { field: 'section name .note.gnu.build-id', observed: namedSection, note: 'recorded, but not what decides' },
  ];
  return {
    ...record('build-id', note ? STATE.PRESENT : STATE.ABSENT, decidedBy,
      !note && namedSection ? 'A section is named .note.gnu.build-id but holds no NT_GNU_BUILD_ID note.' : null),
    buildId: note ? note.descHex : null,
  };
}

// ── W+X ─────────────────────────────────────────────────────────────────────
//
// Both granularities. A section carries the intent; a PT_LOAD segment carries
// what the kernel will actually map. Measured: the injected `.vgwx` section has
// sh_flags W|A|X; no section in any clean fixture does.
export function findWritableExecutable(elf) {
  const sections = elf.sections
    .filter((s) => s.allocated && s.writable && s.executable)
    .map((s) => ({ kind: 'section', name: s.name, index: s.index, shFlags: s.sh_flags, addr: s.sh_addr, size: s.sh_size }));
  const segments = elf.phdrs
    .filter((p) => p.p_type === PT.LOAD && (p.p_flags & PF.W) !== 0 && (p.p_flags & PF.X) !== 0)
    .map((p) => ({ kind: 'segment', name: `PT_LOAD[${p.index}]`, index: p.index, pFlags: p.p_flags, addr: p.p_vaddr, size: p.p_memsz }));
  return [...sections, ...segments];
}

export function decideNoWritableExecutable(elf) {
  const hits = findWritableExecutable(elf);
  return {
    ...record('no-writable-executable-section',
      hits.length === 0 ? STATE.PRESENT : STATE.ABSENT,
      [
        { field: 'Elf64_Shdr.sh_flags', observed: hits.filter((h) => h.kind === 'section').map((h) => h.name), forbiddenBits: 'SHF_WRITE|SHF_EXECINSTR' },
        { field: 'Elf64_Phdr.p_flags', observed: hits.filter((h) => h.kind === 'segment').map((h) => h.name), forbiddenBits: 'PF_W|PF_X' },
      ]),
    hits,
  };
}

/** The five hardening properties plus build-id, in one call. */
export function decideAll(elf) {
  return {
    pie: decidePie(elf),
    nx: decideNx(elf),
    'relro-full': decideRelro(elf),
    'stack-protector': decideStackProtector(elf),
    fortify: decideFortify(elf),
    'build-id': decideBuildId(elf),
    'no-writable-executable-section': decideNoWritableExecutable(elf),
  };
}

export { linkForm, neededLibraries, SHF, SHN };
