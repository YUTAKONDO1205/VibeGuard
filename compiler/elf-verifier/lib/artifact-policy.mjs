// The consumer `policy.artifact.require` did not have on this side of the tree.
//
// ── WHAT THIS IS, AND WHAT IT IS NOT ────────────────────────────────────────
//
// `compiler/schema/policy.schema.json` lets a policy write
// `artifact.require: ["pie", "nx", "relro-full", …]` and
// `artifact.forbidStrings: [...]`. `compiler/schema/properties.json` records,
// under checkpointOwners.artifact, that nothing in `compiler/` reads either of
// them. A policy key with no consumer is worse than a missing feature: the
// policy file says the build is checked for it and no code ever looks.
//
// This file is that consumer, for the subset it can actually decide. It is NOT
// a second ELF parser: every field comes from `./elf.mjs`, and `decidePie`,
// `decideNx` and `decideRelroFull` there are called rather than rewritten. What
// is added is the three things that reader does not do —
//
//   1. W+X, at BOTH granularities (Elf64_Shdr.sh_flags and Elf64_Phdr.p_flags).
//   2. A forbidden-byte scan whose control string is a REQUIRED argument.
//   3. RELRO as a three-valued level (none / partial / full) instead of a
//      boolean, and PIE/NX as states that can abstain instead of booleans that
//      cannot.
//
// ── HONESTY NOTE, WRITTEN BEFORE THE CODE ───────────────────────────────────
//
// `packages/artifact-integrity/` already implements this question for the
// shipped product, and it is tracked and tested. That package cannot be
// imported here: `packages/**` and `compiler/**` do not reference each other in
// either direction, and `scripts/check-packaging-invariants.mjs` enforces it.
// So this is an independent second implementation over `compiler/`'s own
// reader, which is the same argument `artefact-README.md` already makes for
// `artefact-controls.mjs`. It is not a claim that the question was unanswered
// anywhere in the repository — only that it was unanswered HERE, which is what
// `properties.json` says and what a `compiler/`-side policy would hit.
//
// ── MEASURED, ON THE 23-ROW FIXTURE MATRIX (artefact-fixtures.sh) ───────────
//
//  A. NO fixture has a PT_LOAD segment with PF_W|PF_X — not even `wx-on`, the
//     row built to be writable-executable. `.vgwx` is re-flagged by objcopy
//     AFTER the link, so the section carries W|A|X and the PT_LOAD that
//     contains it is still RW-. A segment-only W+X check reports `wx-on`
//     clean. That is the whole reason this file checks both granularities and
//     reports which one fired.
//  B. The only PF_W|PF_X segments in the whole matrix are PT_GNU_STACK on
//     `nx-off` and `unhardened` (p_flags=7, RWX). Those are the NX property,
//     not a mapped-content property, and folding them into the W+X hit list
//     would report every executable-stack binary twice under two different
//     finding ids. They are counted separately and named in the record.
//  C. `-Wl,-z,norelro` (`relro-none`) leaves DT_FLAGS=0x8 and
//     DT_FLAGS_1=0x8000001 set with PT_GNU_RELRO gone; `-Wl,-z,relro,-z,lazy`
//     (`relro-part`) keeps PT_GNU_RELRO with no DT_FLAGS at all. Either half
//     alone calls one of those two binaries fully hardened.
//  D. DT_BIND_NOW is absent on all 23 rows, including the hardened link.
//  E. `libshared.so` and `wx-on` are built from different sources and do NOT
//     contain the control string the other 21 rows carry. They are the natural
//     positive control for the silence detector in `scanBytes`.

import {
  ET, PT, SHF, DT, DF, DF_1,
  decidePie as decidePieBoolean,
  decideNx as decideNxBoolean,
  decideRelroFull as decideRelroFullBoolean,
  dynTag,
} from './elf.mjs';

/** Elf64_Phdr.p_flags bits. Not exported by ./elf.mjs; three constants, not a parser. */
export const PF = { X: 0x1, W: 0x2, R: 0x4 };

/** interfaces.md section 3. "We did not look" and "it is not there" are different claims. */
export const STATE = {
  PRESENT: 'PRESENT',
  ABSENT: 'ABSENT',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  NOT_OBSERVED: 'NOT_OBSERVED',
};

/**
 * Finding ids inside the VG-ART namespace reserved in
 * `compiler/schema/interfaces.md`.
 *
 * VG-ART-005 is not a free choice: `compiler/schema/policy.schema.json` pins
 * `artifact.forbidStrings` to it ("a hit is VG-ART-005") and
 * `compiler/schema/properties.json` repeats the pin. The other two match the
 * allocation `packages/artifact-integrity/README.md` already published, so the
 * two implementations do not disagree about what a number means.
 */
export const ART = {
  HARDENING_ABSENT: 'VG-ART-003',
  WRITABLE_EXECUTABLE: 'VG-ART-004',
  FORBIDDEN_STRING: 'VG-ART-005',
};

export const SEVERITY = {
  'VG-ART-003': 'high',
  'VG-ART-004': 'critical',
  'VG-ART-005': 'critical',
};

const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * The eight names `policy.artifact.require` accepts, split by whether anything
 * in `compiler/` can decide them.
 *
 * The second list is the point. A consumer that silently ignores the five names
 * it cannot decide turns a policy asking for a stack protector into a clean
 * run. Every name in UNSUPPORTED that a policy requires becomes exit 3 with its
 * own sentence, never a pass.
 */
export const SUPPORTED_REQUIREMENTS = [
  'pie',
  'nx',
  'relro-full',
  'no-writable-executable-section',
];

export const UNSUPPORTED_REQUIREMENTS = {
  'stack-protector':
    'no consumer in compiler/. The oracle is the materialised __stack_chk_fail call site, ' +
    'and on a statically linked image the symbol is defined either way (measured: 355 canary ' +
    'loads against 353), so the honest answer needs per-object attribution this component ' +
    'does not have.',
  fortify:
    'no consumer in compiler/. Counting __*_chk call sites needs a fortifiable-surface control ' +
    'as well, or a program with nothing to fortify reads as fortification-off.',
  'no-debug-path':
    'no consumer in compiler/. This is a build-host-path scan over the string and debug ' +
    'sections, which is a different extractor from the literal scan below.',
  'build-id':
    'no consumer in compiler/. ./elf.mjs does not parse Elf64_Nhdr, and deciding this from a ' +
    'section NAMED .note.gnu.build-id rather than from the note payload is exactly the ' +
    'name-lookup mistake this directory exists to avoid.',
};

export const ALL_REQUIREMENTS = [
  ...SUPPORTED_REQUIREMENTS,
  ...Object.keys(UNSUPPORTED_REQUIREMENTS),
];

function record(property, state, decidedBy, note) {
  return { property, state, decidedBy, note: note ?? null, reader: 'compiler/elf-verifier/lib/artifact-policy.mjs' };
}

// ── link form ───────────────────────────────────────────────────────────────

/**
 * Which of the four shapes this image is, from its own header.
 *
 * Read from the bytes rather than taken from a command line, because a build
 * whose flags and whose output disagree is the case worth catching.
 *
 * Known limit, stated rather than hidden: a static-PIE is ET_DYN with no
 * PT_INTERP and is reported `shared-object` here. Nothing in the fixture matrix
 * builds one, so the row is not measured and this reader does not pretend to
 * separate it.
 */
export function linkForm(elf) {
  if (elf.ehdr.e_type === ET.REL) return 'relocatable';
  const interp = elf.phdrs.some((p) => p.p_type === PT.INTERP);
  if (elf.ehdr.e_type === ET.DYN) return interp ? 'exec-pie' : 'shared-object';
  return interp ? 'exec-nonpie' : 'exec-static';
}

/** Has a .dynamic — i.e. there is a lazy-binding surface for RELRO to be about. */
export function isDynamicallyLinked(elf) {
  return elf.dynamic.length > 0 || elf.phdrs.some((p) => p.p_type === PT.DYNAMIC);
}

// ── 3. PIE / NX / RELRO, as states rather than booleans ─────────────────────

/**
 * PIE. Wraps `decidePie` from ./elf.mjs — the two-field rule is not
 * re-implemented — and adds the abstention that a boolean cannot express.
 *
 * `decidePie` returns `false` for `libshared.so`, which is arithmetically right
 * (it is not a position-independent EXECUTABLE) and misleading as a policy
 * answer: a shared object carries no DF_1_PIE by construction, so "pie" has no
 * referent there and reporting ABSENT would make every library fail a policy
 * that requires it. That difference from `artefact-controls.mjs`'s VERDICTS
 * table is deliberate; the table records `decidePie`'s output, this records
 * what a policy should be told.
 */
export function decidePieState(elf) {
  const base = decidePieBoolean(elf);
  const form = linkForm(elf);
  if (form === 'shared-object') {
    return record('pie', STATE.NOT_APPLICABLE, base.decidedBy,
      'A shared object is position-independent by construction and carries no DF_1_PIE. ' +
      'The executable question has no referent here. (lib/elf.mjs decidePie returns false for it.)');
  }
  if (form === 'relocatable') {
    return record('pie', STATE.NOT_APPLICABLE, base.decidedBy, 'ET_REL has no load-time layout yet.');
  }
  return record('pie', base.value ? STATE.PRESENT : STATE.ABSENT, base.decidedBy);
}

/**
 * NX. Wraps `decideNx`. Absent PT_GNU_STACK is ABSENT, not an abstention: with
 * no PT_GNU_STACK the kernel falls back to an executable stack.
 * Measured: p_flags 6 (RW-) with -z noexecstack, 7 (RWX) with -z execstack.
 */
export function decideNxState(elf) {
  const base = decideNxBoolean(elf);
  const gs = elf.phdrs.find((p) => p.p_type === PT.GNU_STACK) ?? null;
  return record('nx', base.value ? STATE.PRESENT : STATE.ABSENT, base.decidedBy,
    gs === null ? 'No PT_GNU_STACK: the kernel falls back to an executable stack.' : null);
}

/**
 * RELRO as three values, because two is the shape that produced the two
 * measured wrong answers (note C at the top of this file).
 *
 * `level`:
 *   `none`    PT_GNU_RELRO absent — whatever the flag words say.
 *   `partial` PT_GNU_RELRO present, lazy binding still on.
 *   `full`    PT_GNU_RELRO present and binding eager.
 *
 * Eager binding has three legal spellings and GNU ld 2.42 emits only the flag
 * words; all three are read and the record says which fired.
 *
 * A statically linked image has no lazy-binding surface, so eager binding is
 * NOT_APPLICABLE there and PT_GNU_RELRO decides alone. `decideRelroFull` in
 * ./elf.mjs requires eager binding unconditionally and therefore returns false
 * for `static-hardened`; that value is carried through in `libVerdict` so the
 * disagreement is visible rather than quietly corrected.
 */
export function decideRelroLevel(elf) {
  const relro = elf.phdrs.find((p) => p.p_type === PT.GNU_RELRO) ?? null;
  const bindNowTag = dynTag(elf, DT.BIND_NOW);
  const flags = dynTag(elf, DT.FLAGS);
  const flags1 = dynTag(elf, DT.FLAGS_1);
  const fv = flags ? Number(flags.value & 0xffffffffn) : null;
  const f1v = flags1 ? Number(flags1.value & 0xffffffffn) : null;
  const eager =
    bindNowTag !== null ||
    (fv !== null && (fv & DF.BIND_NOW) !== 0) ||
    (f1v !== null && (f1v & DF_1.NOW) !== 0);
  const dynamic = isDynamicallyLinked(elf);
  const level = relro === null ? 'none' : (eager || !dynamic) ? 'full' : 'partial';
  const decidedBy = [
    { field: 'Elf64_Phdr.p_type', observed: relro ? 'PT_GNU_RELRO present' : 'PT_GNU_RELRO absent', expected: 'PT_GNU_RELRO=0x6474e552' },
    { field: 'DT_BIND_NOW', observed: bindNowTag ? 'present' : 'absent', note: 'absent on all 23 measured fixtures; GNU ld 2.42 spells eager binding in the flag words' },
    { field: 'DT_FLAGS', observed: fv, expectedBit: DF.BIND_NOW, note: 'DF_BIND_NOW=0x8' },
    { field: 'DT_FLAGS_1', observed: f1v, expectedBit: DF_1.NOW, note: 'DF_1_NOW=0x1' },
  ];
  return {
    ...record('relro-full', level === 'full' ? STATE.PRESENT : STATE.ABSENT, decidedBy,
      dynamic ? null : 'Statically linked: no lazy-binding surface, so eager binding is NOT_APPLICABLE and PT_GNU_RELRO decides alone.'),
    level,
    eagerBinding: dynamic ? eager : null,
    libVerdict: decideRelroFullBoolean(elf).value,
  };
}

// ── 1. W+X, at both granularities ───────────────────────────────────────────

/**
 * Every mapped region that is writable and executable at the same time.
 *
 * Sections carry the intent (`Elf64_Shdr.sh_flags` SHF_ALLOC|SHF_WRITE|
 * SHF_EXECINSTR); PT_LOAD segments carry what the kernel will actually map
 * (`Elf64_Phdr.p_flags` PF_W|PF_X). Measured note A above: the two DISAGREE on
 * the one fixture built to be W+X, so a checker that reads either alone has a
 * silent hole. Both are read, and each hit says which field decided it.
 *
 * PT_GNU_STACK is deliberately NOT a hit. It is not a mapped image region and
 * an executable stack is the NX property; the two segments in the matrix that
 * carry PF_W|PF_X are exactly those two, and folding them in here would report
 * every `-z execstack` binary under two finding ids. They are returned
 * separately as `otherWritableExecutableSegments` so nothing is dropped in
 * silence.
 */
export function findWritableExecutable(elf) {
  const sections = elf.sections
    .filter((s) => s.index > 0)
    .filter((s) => (s.sh_flags & SHF.ALLOC) !== 0 && (s.sh_flags & SHF.WRITE) !== 0 && (s.sh_flags & SHF.EXECINSTR) !== 0)
    .map((s) => ({
      kind: 'section',
      name: s.name,
      index: s.index,
      shFlags: s.sh_flags,
      addr: s.sh_addr,
      size: s.sh_size,
      decidedBy: 'Elf64_Shdr.sh_flags & (SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR)',
    }));
  const segments = elf.phdrs
    .filter((p) => p.p_type === PT.LOAD && (p.p_flags & PF.W) !== 0 && (p.p_flags & PF.X) !== 0)
    .map((p) => ({
      kind: 'segment',
      name: `PT_LOAD[${p.index}]`,
      index: p.index,
      pFlags: p.p_flags,
      addr: p.p_vaddr,
      size: p.p_memsz,
      decidedBy: 'Elf64_Phdr.p_flags & (PF_W|PF_X)',
    }));
  return [...sections, ...segments];
}

/** PF_W|PF_X segments that are not PT_LOAD. Recorded, not reported as W+X. */
export function otherWritableExecutableSegments(elf) {
  return elf.phdrs
    .filter((p) => p.p_type !== PT.LOAD && (p.p_flags & PF.W) !== 0 && (p.p_flags & PF.X) !== 0)
    .map((p) => ({
      name: p.p_type === PT.GNU_STACK ? 'PT_GNU_STACK' : `p_type=0x${p.p_type.toString(16)}`,
      index: p.index,
      pFlags: p.p_flags,
      note: p.p_type === PT.GNU_STACK
        ? 'An executable stack. Reported by the nx property, not as a writable-executable image region.'
        : 'A non-PT_LOAD segment with PF_W|PF_X.',
    }));
}

export function decideNoWritableExecutable(elf) {
  const hits = findWritableExecutable(elf);
  const others = otherWritableExecutableSegments(elf);
  return {
    ...record('no-writable-executable-section',
      hits.length === 0 ? STATE.PRESENT : STATE.ABSENT,
      [
        { field: 'Elf64_Shdr.sh_flags', observed: hits.filter((h) => h.kind === 'section').map((h) => h.name), forbiddenBits: 'SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR' },
        { field: 'Elf64_Phdr.p_flags (PT_LOAD only)', observed: hits.filter((h) => h.kind === 'segment').map((h) => h.name), forbiddenBits: 'PF_W|PF_X' },
        { field: 'Elf64_Phdr.p_flags (other segments)', observed: others.map((o) => o.name), note: 'recorded; decided by the nx property instead' },
      ]),
    hits,
    otherSegments: others,
  };
}

// ── 2. The byte scan, and the control that makes it mean anything ───────────

/** Which section a file offset falls inside, for attribution. */
export function sectionAt(elf, offset) {
  for (const s of elf.sections) {
    if (s.index === 0) continue;
    if (s.sh_type === 8 /* SHT_NOBITS */ || s.sh_size === 0) continue;
    if (offset >= s.sh_offset && offset < s.sh_offset + s.sh_size) return s.name;
  }
  return null;
}

/**
 * Scan the artefact's bytes for sequences a policy forbids — and prove first
 * that the scan can find anything at all.
 *
 * `expect` IS A REQUIRED ARGUMENT. This is the point of the function.
 *
 * A byte scanner has two failure modes that both end in a clean report: it was
 * pointed at the wrong file, and it stopped reading. Neither produces an error;
 * both produce zero hits, which is indistinguishable from a clean artefact. The
 * only thing that separates them is a sequence that MUST be there. So:
 *
 *   * `expect` missing, not an array, or empty      -> BROKEN
 *   * any string in `expect` not found in the bytes -> BROKEN
 *   * otherwise                                     -> CLEAN or HITS
 *
 * BROKEN is not a finding and it is not clean. The caller maps it to exit 3.
 *
 * Forbidden hits found during a BROKEN scan are counted in `unverifiedHits` and
 * NOT returned as `hits`: if the file may be the wrong one, a hit in it is not
 * evidence about the artefact under policy. Counting them anyway keeps the
 * number visible instead of discarding it.
 *
 * Searched with `Buffer.indexOf` over the whole image rather than against an
 * extracted printable-run list: a secret can straddle a non-printable byte, and
 * a run-based extractor would miss it and report clean.
 */
export function scanBytes(elf, { forbid = [], expect } = {}) {
  if (!Array.isArray(expect)) {
    throw new TypeError(
      'scanBytes: `expect` is required and must be an array. A byte scan with no control ' +
      'string cannot tell "nothing is there" from "this scanner read nothing", and the ' +
      'second one reports clean.');
  }
  const controls = expect
    .filter((n) => typeof n === 'string' && n.length > 0)
    .map((needle) => ({ needle, found: elf.buf.indexOf(Buffer.from(needle, 'utf8')) !== -1 }));

  const brokenReasons = [];
  if (controls.length === 0) {
    brokenReasons.push(
      'no control string was supplied. A scan that cannot demonstrate it finds anything ' +
      'must not be allowed to report zero.');
  }
  for (const c of controls) {
    if (!c.found) {
      brokenReasons.push(
        `the control string ${JSON.stringify(c.needle)} is not in ${elf.path}. Either this is ` +
        'not the artefact the policy is about, or the scan is not reading it. Not clean.');
    }
  }

  const raw = [];
  for (const needle of forbid) {
    if (typeof needle !== 'string' || needle.length === 0) continue;
    const pat = Buffer.from(needle, 'utf8');
    let from = 0;
    for (;;) {
      const at = elf.buf.indexOf(pat, from);
      if (at === -1) break;
      raw.push({ needle, offset: at, section: sectionAt(elf, at) });
      from = at + 1;
      if (raw.length > 10000) break;
    }
  }

  const broken = brokenReasons.length > 0;
  return {
    verdict: broken ? 'BROKEN' : raw.length > 0 ? 'HITS' : 'CLEAN',
    broken,
    brokenReasons,
    controls,
    controlsChecked: controls.length,
    hits: broken ? [] : raw,
    unverifiedHits: broken ? raw.length : 0,
    bytesScanned: elf.buf.length,
  };
}

// ── the policy consumer ─────────────────────────────────────────────────────

function finding(id, title, detail, path, unit) {
  return {
    id,
    severity: SEVERITY[id],
    title,
    detail,
    where: { kind: 'artifact', path: path ?? null, unit: unit ?? null, pass: null },
  };
}

function describe(rec) {
  return rec.decidedBy
    .map((d) => `${d.field}=${Array.isArray(d.observed) ? `[${d.observed.join(', ')}]` : String(d.observed)}`)
    .join('; ') + (rec.note ? `. ${rec.note}` : '.');
}

/** Everything read out of one image, before any policy is applied. */
export function observe(elf) {
  return {
    path: elf.path,
    size: elf.size,
    eType: elf.ehdr.e_type,
    eMachine: elf.ehdr.e_machine,
    linkForm: linkForm(elf),
    dynamicallyLinked: isDynamicallyLinked(elf),
    segments: elf.phdrs.map((p) => ({ index: p.index, type: p.p_type, flags: p.p_flags, vaddr: p.p_vaddr, memsz: p.p_memsz })),
    properties: {
      pie: decidePieState(elf),
      nx: decideNxState(elf),
      'relro-full': decideRelroLevel(elf),
      'no-writable-executable-section': decideNoWritableExecutable(elf),
    },
  };
}

/**
 * Apply `policy.artifact` to one image.
 *
 * @param {object} elf     the result of `readElf`
 * @param {object} policy  `{ require, forbidStrings, expectStrings }`
 * @returns {{observation, findings, incomplete, notObserved, unsupported, scan}}
 */
export function applyArtifactPolicy(elf, policy = {}) {
  const required = policy.require ?? [];
  const forbid = policy.forbidStrings ?? [];
  const expect = policy.expectStrings ?? [];

  const observation = observe(elf);
  const findings = [];
  const incomplete = [];
  const notObserved = [];
  const unsupported = [];

  for (const name of required) {
    if (Object.prototype.hasOwnProperty.call(UNSUPPORTED_REQUIREMENTS, name)) {
      unsupported.push({ property: name, why: UNSUPPORTED_REQUIREMENTS[name] });
      incomplete.push(`${name}: required by the policy and NOT CHECKED here — ${UNSUPPORTED_REQUIREMENTS[name]}`);
      continue;
    }
    const rec = observation.properties[name];
    if (!rec) {
      incomplete.push(`${name}: not a name policy.artifact.require accepts (${ALL_REQUIREMENTS.join(', ')})`);
      continue;
    }
    if (rec.state === STATE.PRESENT) continue;
    if (rec.state === STATE.NOT_APPLICABLE) continue;
    if (rec.state === STATE.NOT_OBSERVED) {
      notObserved.push({ property: name, why: rec.note });
      incomplete.push(`${name}: NOT_OBSERVED — ${rec.note ?? 'no reason recorded'}`);
      continue;
    }
    if (name === 'no-writable-executable-section') {
      for (const hit of rec.hits) {
        findings.push(finding(ART.WRITABLE_EXECUTABLE,
          'A mapped region is both writable and executable',
          `${hit.kind} ${hit.name} at 0x${hit.addr.toString(16)} (${hit.size} bytes), decided by ${hit.decidedBy} ` +
          `= 0x${(hit.kind === 'section' ? hit.shFlags : hit.pFlags).toString(16)}.`,
          elf.path, hit.name));
      }
      continue;
    }
    findings.push(finding(ART.HARDENING_ABSENT,
      `A required hardening property is ${rec.state}: ${name}`,
      describe(rec), elf.path, name));
  }

  // ── the byte scan ─────────────────────────────────────────────────────────
  // Run whenever the policy asks anything of the bytes. `expect` is passed
  // through even when empty, so that a policy which forbids strings and names
  // no control is BROKEN rather than quietly trusted.
  let scan = null;
  if (forbid.length > 0 || expect.length > 0) {
    scan = scanBytes(elf, { forbid, expect });
    for (const reason of scan.brokenReasons) {
      incomplete.push(`forbidden-string scan is BROKEN: ${reason}`);
    }
    if (scan.unverifiedHits > 0) {
      incomplete.push(
        `the scan matched ${scan.unverifiedHits} forbidden sequence(s) while its control was broken; ` +
        'they are recorded but not reported as findings, because a hit in a file that may not be the ' +
        'artefact under policy is not evidence about the artefact.');
    }
    for (const h of scan.hits) {
      findings.push(finding(ART.FORBIDDEN_STRING,
        'A forbidden byte sequence survived into the artefact',
        `${JSON.stringify(h.needle)} at file offset 0x${h.offset.toString(16)}` +
        (h.section ? ` in ${h.section}` : ' (outside any section)') + '.',
        elf.path, h.section));
    }
  }
  observation.scan = scan;

  if (required.length === 0 && forbid.length === 0 && expect.length === 0) {
    incomplete.push(
      'the policy asked nothing of the artefact: require, forbidStrings and expectStrings are all ' +
      'empty. A check that examined nothing is not a clean check.');
  }

  return { observation, findings, incomplete, notObserved, unsupported, scan };
}

/**
 * Exit code for one result. `compiler/schema/interfaces.md` section 7.
 * Findings outrank incompleteness — a finding is a thing that was seen — but
 * 3 is never collapsed into 0.
 */
export function exitCodeFor({ findings, incomplete }, failOn = 'medium') {
  const floor = SEV_RANK[failOn] ?? 1;
  const failing = findings.filter((f) => (SEV_RANK[f.severity] ?? 0) >= floor);
  if (failing.length > 0) return 2;
  if (incomplete.length > 0) return 3;
  return 0;
}
