// Tests for lib/artifact-policy.mjs — the policy.artifact.require consumer.
//
//   node --test compiler/elf-verifier/test/
//
// TWO KINDS OF INPUT, AND THE REASON THE FILE SAYS WHICH IS WHICH.
//
//   REAL   the 23-row matrix built by ../artefact-fixtures.sh with gcc and GNU
//          ld. Everything a real link can express is asserted against these.
//          Looked for in ../_results/artefact-matrix/bin (git-ignored) or in
//          $VG_ART_MATRIX.
//   SYNTH  images assembled byte by byte in ./synth-elf64.mjs. Used for exactly
//          one thing a real link would not give: a PT_LOAD segment with
//          PF_W|PF_X. Measured — no row of the matrix has one, not even `wx-on`,
//          because objcopy re-flags `.vgwx` after the link and the containing
//          PT_LOAD stays RW-.
//
// A synthetic pass proves the decider reads the field it says it reads. It does
// not prove any toolchain emits that field, and no assertion below claims it
// does.
//
// The suite refuses to be silently vacuous: `assert.ok(readElf(...).supported)`
// runs on the first synthetic image, so a writer that produced garbage fails
// loudly instead of making every later assertion pass against an empty parse.

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

import { readElf, ET, PT, SHT, SHF, DT } from '../lib/elf.mjs';
import {
  STATE, ART, PF,
  linkForm, decidePieState, decideNxState, decideRelroLevel,
  findWritableExecutable, otherWritableExecutableSegments, decideNoWritableExecutable,
  scanBytes, applyArtifactPolicy, exitCodeFor, observe,
} from '../lib/artifact-policy.mjs';
import { buildElf64, cleanPie } from './synth-elf64.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, '..', 'artefact-require.mjs');

// ── where the real fixtures are ─────────────────────────────────────────────
const MATRIX = (() => {
  const candidates = [
    process.env.VG_ART_MATRIX,
    join(HERE, '..', '_results', 'artefact-matrix', 'bin'),
  ].filter(Boolean);
  for (const c of candidates) if (existsSync(c)) return c;
  return null;
})();

const MATRIX_ROWS = [
  'sp-on', 'sp-off', 'pie-on', 'pie-off', 'relro-full', 'relro-part', 'relro-none',
  'nx-on', 'nx-off', 'fortify-on', 'fortify-off', 'buildid-on', 'buildid-off',
  'dbg-on', 'dbg-off', 'rpath', 'hardened', 'hardened-stripped', 'unhardened',
  'static-hardened', 'static-plain', 'libshared.so', 'wx-on',
];

const CONTROL = 'artefact-control-string-always-present';
// The needle `scanBytes` is measured against: AWS's own documentation example
// key, the EXAMPLE-suffixed one, valid against nothing. A residue scanner
// cannot be tested without residue to detect. Named rather than wildcarded, and
// line-scoped rather than file-scoped, so a key written anywhere else in this
// suite still reports. Same standing as the entry `.vibeguardrc.json` already
// carries for ../artefact-fixtures.sh, which compiles this string INTO the
// fixture binaries these tests read.
const SECRET = 'AKIAIOSFODNN7EXAMPLE'; // vibeguard:disable-line VG-SEC-001 VG-SEC-003

const skipReal = MATRIX
  ? false
  : 'no fixture matrix. Build it with `bash compiler/elf-verifier/artefact-fixtures.sh ' +
    '<workdir>` and copy <workdir>/bin to compiler/elf-verifier/_results/artefact-matrix/bin, ' +
    'or set VG_ART_MATRIX. A skip here is NOT a pass.';

let TMP;
before(() => { TMP = mkdtempSync(join(tmpdir(), 'vg-art-')); });

function fixture(name) {
  const elf = readElf(join(MATRIX, name));
  assert.ok(elf.supported, `${name}: ${elf.reason ?? 'unreadable'}`);
  return elf;
}

function synth(buf, name) {
  const p = join(TMP, name);
  writeFileSync(p, buf);
  return readElf(p);
}

// ════════════════════════════════════════════════════════════════════════════
// SYNTH — the byte writer itself, before anything is asserted through it
// ════════════════════════════════════════════════════════════════════════════

describe('SYNTH: the writer produces something ../lib/elf.mjs can read', () => {
  test('a clean PIE parses, with the segments and sections it was given', () => {
    const elf = synth(cleanPie(), 'clean-pie');
    assert.ok(elf.supported, `synthetic image was not readable: ${elf.reason}`);
    assert.equal(elf.ehdr.e_type, ET.DYN);
    assert.equal(elf.phdrs.length, 6);
    assert.ok(elf.sections.some((s) => s.name === '.text'), 'section names did not survive the shstrtab');
    assert.ok(elf.sections.some((s) => s.name === '.dynamic'));
    // If .dynamic did not parse, every RELRO assertion below would be vacuous.
    assert.ok(elf.dynamic.length >= 2, 'no .dynamic entries were read');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 1. W+X, both granularities
// ════════════════════════════════════════════════════════════════════════════

describe('W+X', () => {
  test('the PF bits are the psABI values, not whatever made the tests pass', () => {
    // Added because a mutation SURVIVED: swapping PF.X and PF.W changes nothing
    // in `(f & W) && (f & X)`, so every W+X assertion in this file is blind to
    // the two constants being wrong. They are symmetric in the only expression
    // that currently reads them, and the next expression that reads one alone
    // would inherit the error silently. Pinned to the numbers instead.
    assert.equal(PF.X, 0x1);
    assert.equal(PF.W, 0x2);
    assert.equal(PF.R, 0x4);
  });

  test('SYNTH: a PT_LOAD with PF_W|PF_X is a hit, and says p_flags decided it', () => {
    const elf = synth(cleanPie({
      phdrs: [{ type: PT.LOAD, flags: PF.R | PF.W | PF.X, vaddr: 0x5000, memsz: 0x1000 }],
    }), 'wx-segment');
    const hits = findWritableExecutable(elf);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].kind, 'segment');
    assert.equal(hits[0].pFlags, 7);
    assert.match(hits[0].decidedBy, /Elf64_Phdr\.p_flags/);
    assert.equal(decideNoWritableExecutable(elf).state, STATE.ABSENT);
  });

  test('SYNTH: a clean image has no hits at either granularity', () => {
    const elf = synth(cleanPie(), 'wx-clean');
    assert.deepEqual(findWritableExecutable(elf), []);
    assert.equal(decideNoWritableExecutable(elf).state, STATE.PRESENT);
  });

  test('SYNTH: a SHF_ALLOC|WRITE|EXECINSTR section is a hit even when every PT_LOAD is clean', () => {
    const elf = synth(cleanPie({
      sections: [{
        name: '.vgwx', type: SHT.PROGBITS,
        flags: SHF.ALLOC | SHF.WRITE | SHF.EXECINSTR,
        addr: 0x4000, data: Buffer.alloc(16, 0x90),
      }],
    }), 'wx-section');
    const hits = findWritableExecutable(elf);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].kind, 'section');
    assert.equal(hits[0].name, '.vgwx');
    assert.match(hits[0].decidedBy, /Elf64_Shdr\.sh_flags/);
  });

  test('SYNTH: PT_GNU_STACK RWX is NOT a W+X hit — it is the nx property', () => {
    const elf = synth(buildElf64({
      type: ET.DYN,
      phdrs: [
        { type: PT.INTERP, flags: 0x4 },
        { type: PT.LOAD, flags: PF.R | PF.X, vaddr: 0x1000, memsz: 0x1000 },
        { type: PT.LOAD, flags: PF.R | PF.W, vaddr: 0x3000, memsz: 0x1000 },
        { type: PT.GNU_STACK, flags: PF.R | PF.W | PF.X },
      ],
      sections: [{ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.alloc(8) }],
      dynamic: [[DT.FLAGS_1, 0x8000001]],
    }), 'execstack');
    assert.deepEqual(findWritableExecutable(elf), []);
    const others = otherWritableExecutableSegments(elf);
    assert.equal(others.length, 1);
    assert.equal(others[0].name, 'PT_GNU_STACK');
    assert.equal(decideNxState(elf).state, STATE.ABSENT);
    assert.equal(decideNoWritableExecutable(elf).state, STATE.PRESENT,
      'an executable stack must not also be reported as a writable-executable image region');
  });

  test('REAL: wx-on has a W+X section and NO W+X segment — the measured disagreement', { skip: skipReal }, () => {
    const elf = fixture('wx-on');
    const hits = findWritableExecutable(elf);
    const sections = hits.filter((h) => h.kind === 'section').map((h) => h.name);
    const segments = hits.filter((h) => h.kind === 'segment');
    assert.deepEqual(sections, ['.vgwx']);
    assert.deepEqual(segments, [],
      'measured: objcopy re-flags .vgwx after the link, so the containing PT_LOAD stays RW-. ' +
      'A segment-only W+X check reports this binary clean.');
  });

  test('REAL: nx-off has an RWX PT_GNU_STACK and still no W+X image region', { skip: skipReal }, () => {
    const elf = fixture('nx-off');
    assert.deepEqual(findWritableExecutable(elf), []);
    assert.deepEqual(otherWritableExecutableSegments(elf).map((o) => o.name), ['PT_GNU_STACK']);
    assert.equal(decideNxState(elf).state, STATE.ABSENT);
  });

  test('REAL: every other row of the matrix is clean at both granularities', { skip: skipReal }, () => {
    const dirty = [];
    for (const name of MATRIX_ROWS) {
      if (name === 'wx-on') continue;
      const hits = findWritableExecutable(fixture(name));
      if (hits.length > 0) dirty.push(`${name}: ${hits.map((h) => `${h.kind} ${h.name}`).join(', ')}`);
    }
    assert.deepEqual(dirty, []);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 2. The byte scan and its control — the silence detector
// ════════════════════════════════════════════════════════════════════════════

describe('byte scan', () => {
  const withStrings = (extra) => cleanPie({
    sections: [{
      name: '.rodata', type: SHT.PROGBITS, flags: SHF.ALLOC,
      addr: 0x2000, data: Buffer.from(extra, 'latin1'),
    }],
  });

  test('SYNTH: calling without `expect` is a programmer error, not a clean scan', () => {
    const elf = synth(withStrings(`\0${CONTROL}\0`), 'scan-noexpect');
    assert.throws(() => scanBytes(elf, { forbid: [SECRET] }), TypeError);
    assert.throws(() => scanBytes(elf), TypeError);
  });

  test('SYNTH: an empty control list is BROKEN, not CLEAN', () => {
    const elf = synth(withStrings(`\0${CONTROL}\0`), 'scan-emptyexpect');
    const r = scanBytes(elf, { forbid: [SECRET], expect: [] });
    assert.equal(r.verdict, 'BROKEN');
    assert.equal(r.controlsChecked, 0);
    assert.match(r.brokenReasons.join(' '), /no control string/);
  });

  test('SYNTH: control present, forbidden sequence present -> HITS, attributed to a section', () => {
    const elf = synth(withStrings(`\0${CONTROL}\0${SECRET}\0`), 'scan-hit');
    const r = scanBytes(elf, { forbid: [SECRET], expect: [CONTROL] });
    assert.equal(r.verdict, 'HITS');
    assert.equal(r.hits.length, 1);
    assert.equal(r.hits[0].section, '.rodata');
    assert.equal(r.unverifiedHits, 0);
  });

  test('SYNTH: control present, nothing forbidden found -> CLEAN', () => {
    const elf = synth(withStrings(`\0${CONTROL}\0`), 'scan-clean');
    const r = scanBytes(elf, { forbid: [SECRET], expect: [CONTROL] });
    assert.equal(r.verdict, 'CLEAN');
    assert.equal(r.hits.length, 0);
  });

  test('SYNTH: control ABSENT while the forbidden sequence is present -> BROKEN, hits withheld', () => {
    // The sharpest case. The file really does contain the secret, so a scanner
    // that reported findings would look like it worked. But the control says
    // this is not the artefact the policy is about, and an accusation drawn
    // from the wrong file is worse than an abstention.
    const elf = synth(withStrings(`\0${SECRET}\0`), 'scan-broken-with-secret');
    const r = scanBytes(elf, { forbid: [SECRET], expect: [CONTROL] });
    assert.equal(r.verdict, 'BROKEN');
    assert.deepEqual(r.hits, []);
    assert.equal(r.unverifiedHits, 1);
    assert.match(r.brokenReasons.join(' '), /control string .* is not in/);
  });

  test('SYNTH: a sequence straddling a non-printable byte is still found', () => {
    // Buffer.indexOf over the whole image, not a printable-run extractor: a
    // run-based scan would split this and report the artefact clean.
    const needle = 'AB\x00CD';
    const elf = synth(withStrings(`\0${CONTROL}\0AB\0CD\0`), 'scan-straddle');
    const r = scanBytes(elf, { forbid: [needle], expect: [CONTROL] });
    assert.equal(r.verdict, 'HITS');
    assert.equal(r.hits.length, 1);
  });

  test('REAL: hardened carries the control and the secret', { skip: skipReal }, () => {
    const r = scanBytes(fixture('hardened'), { forbid: [SECRET], expect: [CONTROL] });
    assert.equal(r.verdict, 'HITS');
    assert.ok(r.hits.length >= 1);
    assert.ok(r.controls.every((c) => c.found));
  });

  test('REAL: libshared.so lacks the control -> BROKEN on a real binary', { skip: skipReal }, () => {
    // Measured: libshared.so and wx-on are built from lib.c / wx.c, so neither
    // carries the marker the other 21 rows do. Pointing the scan at one of them
    // is exactly the "wrong file" mistake the control exists to catch.
    const r = scanBytes(fixture('libshared.so'), { forbid: [SECRET], expect: [CONTROL] });
    assert.equal(r.verdict, 'BROKEN');
    assert.equal(r.controls.length, 1);
    assert.equal(r.controls[0].found, false);
  });

  test('REAL: 21 of the 23 rows carry the control string', { skip: skipReal }, () => {
    const without = MATRIX_ROWS.filter((n) => !scanBytes(fixture(n), { expect: [CONTROL] }).controls[0].found);
    assert.deepEqual(without.sort(), ['libshared.so', 'wx-on']);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 3. PIE / NX / RELRO
// ════════════════════════════════════════════════════════════════════════════

describe('PIE / NX / RELRO', () => {
  test('SYNTH: ET_DYN with DF_1_PIE and PT_INTERP is a PIE', () => {
    const elf = synth(cleanPie(), 'pie-yes');
    assert.equal(linkForm(elf), 'exec-pie');
    assert.equal(decidePieState(elf).state, STATE.PRESENT);
  });

  test('SYNTH: ET_EXEC with PT_INTERP is not', () => {
    const elf = synth(buildElf64({
      type: ET.EXEC,
      phdrs: [{ type: PT.INTERP, flags: 0x4 }, { type: PT.GNU_STACK, flags: 0x6 }],
      sections: [{ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.alloc(8) }],
    }), 'pie-no');
    assert.equal(linkForm(elf), 'exec-nonpie');
    assert.equal(decidePieState(elf).state, STATE.ABSENT);
  });

  test('SYNTH: a shared object abstains rather than failing a pie requirement', () => {
    const elf = synth(buildElf64({
      type: ET.DYN,
      phdrs: [{ type: PT.LOAD, flags: PF.R | PF.X, vaddr: 0x1000, memsz: 0x1000 }, { type: PT.GNU_STACK, flags: 0x6 }],
      sections: [{ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.alloc(8) }],
      dynamic: [[DT.SONAME, 0]],
    }), 'sharedobj');
    assert.equal(linkForm(elf), 'shared-object');
    assert.equal(decidePieState(elf).state, STATE.NOT_APPLICABLE);
  });

  test('SYNTH: PT_GNU_RELRO absent is level "none" even with DT_FLAGS=BIND_NOW set', () => {
    // The measured -Wl,-z,norelro shape: the flag words survive the option.
    const elf = synth(buildElf64({
      type: ET.DYN,
      phdrs: [{ type: PT.INTERP, flags: 0x4 }, { type: PT.GNU_STACK, flags: 0x6 }],
      sections: [{ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.alloc(8) }],
      dynamic: [[DT.FLAGS, 0x8], [DT.FLAGS_1, 0x8000001]],
    }), 'relro-none-synth');
    const r = decideRelroLevel(elf);
    assert.equal(r.level, 'none');
    assert.equal(r.state, STATE.ABSENT);
    assert.equal(r.eagerBinding, true, 'eager binding really is on; it is just not sufficient');
  });

  test('SYNTH: PT_GNU_RELRO with lazy binding is level "partial"', () => {
    const elf = synth(buildElf64({
      type: ET.DYN,
      phdrs: [{ type: PT.INTERP, flags: 0x4 }, { type: PT.GNU_STACK, flags: 0x6 }, { type: PT.GNU_RELRO, flags: 0x4 }],
      sections: [{ name: '.text', type: SHT.PROGBITS, flags: SHF.ALLOC | SHF.EXECINSTR, data: Buffer.alloc(8) }],
      dynamic: [[DT.FLAGS_1, 0x8000000]], // DF_1_PIE only, no DF_1_NOW
    }), 'relro-part-synth');
    const r = decideRelroLevel(elf);
    assert.equal(r.level, 'partial');
    assert.equal(r.state, STATE.ABSENT);
  });

  test('REAL: the hardening rows decide as the ground-truth table says', { skip: skipReal }, () => {
    const want = {
      hardened: { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'full' },
      'hardened-stripped': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'full' },
      'pie-on': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'full' },
      // `partial`, not `full`, and this row was written wrong the first time.
      // `artefact-ground-truth.md` / artefact-controls.mjs TABLE: pie-off has
      // DT_FLAGS=null and DT_FLAGS_1=null. `-no-pie` costs it the flag words
      // along with the PIE bit, so PT_GNU_RELRO is present with lazy binding.
      // The measurement was right and the expectation was the thing that had to
      // change; the same row in VERDICTS says relroFull=false, which agrees.
      'pie-off': { pie: STATE.ABSENT, nx: STATE.PRESENT, relro: 'partial' },
      'nx-on': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'full' },
      'nx-off': { pie: STATE.PRESENT, nx: STATE.ABSENT, relro: 'full' },
      'relro-full': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'full' },
      'relro-part': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'partial' },
      'relro-none': { pie: STATE.PRESENT, nx: STATE.PRESENT, relro: 'none' },
      unhardened: { pie: STATE.ABSENT, nx: STATE.ABSENT, relro: 'none' },
      // Same correction: the shared object carries neither DT_FLAGS nor
      // DT_FLAGS_1, so PT_GNU_RELRO alone is `partial`.
      'libshared.so': { pie: STATE.NOT_APPLICABLE, nx: STATE.PRESENT, relro: 'partial' },
    };
    const got = {};
    for (const name of Object.keys(want)) {
      const elf = fixture(name);
      got[name] = {
        pie: decidePieState(elf).state,
        nx: decideNxState(elf).state,
        relro: decideRelroLevel(elf).level,
      };
    }
    assert.deepEqual(got, want);
  });

  test('REAL: relro-none really does still carry DT_FLAGS=BIND_NOW', { skip: skipReal }, () => {
    // Without this row the "none" verdict above could be produced by a check
    // that simply reads the flag words wrong.
    const r = decideRelroLevel(fixture('relro-none'));
    assert.equal(r.level, 'none');
    assert.equal(r.eagerBinding, true);
    const flags = r.decidedBy.find((d) => d.field === 'DT_FLAGS');
    assert.equal(flags.observed, 0x8);
  });

  test('REAL: relro-part carries PT_GNU_RELRO and no DT_FLAGS at all', { skip: skipReal }, () => {
    const r = decideRelroLevel(fixture('relro-part'));
    assert.equal(r.level, 'partial');
    assert.equal(r.eagerBinding, false);
    assert.equal(r.decidedBy.find((d) => d.field === 'DT_FLAGS').observed, null);
    assert.equal(r.decidedBy.find((d) => d.field === 'DT_BIND_NOW').observed, 'absent');
  });

  test('REAL: DT_BIND_NOW is absent on all 23 rows, hardened included', { skip: skipReal }, () => {
    const withTag = MATRIX_ROWS.filter((n) =>
      decideRelroLevel(fixture(n)).decidedBy.find((d) => d.field === 'DT_BIND_NOW').observed === 'present');
    assert.deepEqual(withTag, []);
  });

  test('REAL: a static image is full RELRO here and false in lib/elf.mjs — recorded, not hidden', { skip: skipReal }, () => {
    const r = decideRelroLevel(fixture('static-hardened'));
    assert.equal(linkForm(fixture('static-hardened')), 'exec-static');
    assert.equal(r.level, 'full');
    assert.equal(r.eagerBinding, null, 'no lazy-binding surface, so the question has no referent');
    assert.equal(r.libVerdict, false, 'lib/elf.mjs decideRelroFull requires eager binding unconditionally');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// The policy consumer and its exit codes
// ════════════════════════════════════════════════════════════════════════════

describe('applyArtifactPolicy', () => {
  test('SYNTH: a requirement this component cannot decide is exit 3, never a pass', () => {
    const elf = synth(cleanPie(), 'unsupported-req');
    const r = applyArtifactPolicy(elf, { require: ['pie', 'stack-protector', 'fortify'] });
    assert.equal(r.findings.length, 0);
    assert.equal(r.unsupported.length, 2);
    assert.deepEqual(r.unsupported.map((u) => u.property).sort(), ['fortify', 'stack-protector']);
    assert.equal(exitCodeFor(r), 3);
  });

  test('SYNTH: a name the schema does not accept is exit 3', () => {
    const elf = synth(cleanPie(), 'unknown-req');
    const r = applyArtifactPolicy(elf, { require: ['pie', 'wishful-thinking'] });
    assert.equal(exitCodeFor(r), 3);
    assert.match(r.incomplete.join(' '), /not a name policy\.artifact\.require accepts/);
  });

  test('SYNTH: a policy that asks for nothing is exit 3, not exit 0', () => {
    const elf = synth(cleanPie(), 'empty-policy');
    const r = applyArtifactPolicy(elf, {});
    assert.equal(exitCodeFor(r), 3);
  });

  test('SYNTH: forbidStrings with no expectStrings is exit 3', () => {
    const elf = synth(cleanPie(), 'forbid-nocontrol');
    const r = applyArtifactPolicy(elf, { require: ['pie'], forbidStrings: [SECRET] });
    assert.equal(exitCodeFor(r), 3);
    assert.match(r.incomplete.join(' '), /BROKEN/);
  });

  test('SYNTH: a satisfied policy with a working control is exit 0', () => {
    const elf = synth(cleanPie({
      sections: [{ name: '.rodata', type: SHT.PROGBITS, flags: SHF.ALLOC, addr: 0x2000, data: Buffer.from(`\0${CONTROL}\0`, 'latin1') }],
    }), 'all-good');
    const r = applyArtifactPolicy(elf, {
      require: ['pie', 'nx', 'relro-full', 'no-writable-executable-section'],
      forbidStrings: [SECRET],
      expectStrings: [CONTROL],
    });
    assert.deepEqual(r.findings, []);
    assert.deepEqual(r.incomplete, []);
    assert.equal(exitCodeFor(r), 0);
  });

  test('SYNTH: a W+X segment produces VG-ART-004 at critical', () => {
    const elf = synth(cleanPie({
      phdrs: [{ type: PT.LOAD, flags: PF.R | PF.W | PF.X, vaddr: 0x5000, memsz: 0x1000 }],
      sections: [{ name: '.rodata', type: SHT.PROGBITS, flags: SHF.ALLOC, addr: 0x2000, data: Buffer.from(`\0${CONTROL}\0`, 'latin1') }],
    }), 'policy-wx');
    const r = applyArtifactPolicy(elf, { require: ['no-writable-executable-section'], expectStrings: [CONTROL] });
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].id, ART.WRITABLE_EXECUTABLE);
    assert.equal(r.findings[0].severity, 'critical');
    assert.equal(exitCodeFor(r), 2);
  });

  test('REAL: hardened satisfies the four decidable requirements', { skip: skipReal }, () => {
    const r = applyArtifactPolicy(fixture('hardened'), {
      require: ['pie', 'nx', 'relro-full', 'no-writable-executable-section'],
      expectStrings: [CONTROL],
    });
    assert.deepEqual(r.findings, []);
    assert.deepEqual(r.incomplete, []);
    assert.equal(exitCodeFor(r), 0);
  });

  test('REAL: unhardened fails three of them', { skip: skipReal }, () => {
    const r = applyArtifactPolicy(fixture('unhardened'), {
      require: ['pie', 'nx', 'relro-full', 'no-writable-executable-section'],
      expectStrings: [CONTROL],
    });
    assert.deepEqual(r.findings.map((f) => f.where.unit).sort(), ['nx', 'pie', 'relro-full']);
    assert.ok(r.findings.every((f) => f.id === ART.HARDENING_ABSENT));
    assert.equal(exitCodeFor(r), 2);
  });

  test('REAL: the secret in hardened is VG-ART-005', { skip: skipReal }, () => {
    const r = applyArtifactPolicy(fixture('hardened'), {
      require: ['pie'], forbidStrings: [SECRET], expectStrings: [CONTROL],
    });
    const hits = r.findings.filter((f) => f.id === ART.FORBIDDEN_STRING);
    assert.ok(hits.length >= 1);
    assert.equal(hits[0].severity, 'critical');
    assert.equal(exitCodeFor(r), 2);
  });

  test('REAL: pointing the scan at the wrong binary is exit 3, not exit 2 and not exit 0', { skip: skipReal }, () => {
    const r = applyArtifactPolicy(fixture('libshared.so'), {
      require: ['nx'], forbidStrings: [SECRET], expectStrings: [CONTROL],
    });
    assert.equal(r.findings.length, 0);
    assert.equal(exitCodeFor(r), 3);
    assert.match(r.incomplete.join(' '), /BROKEN/);
  });

  test('SYNTH: observe() records the segment table so a reader can re-derive the verdict', () => {
    const elf = synth(cleanPie(), 'observe');
    const o = observe(elf);
    assert.equal(o.segments.length, 6);
    assert.ok(o.properties.pie.decidedBy.some((d) => d.field === 'Elf64_Ehdr.e_type'));
    assert.ok(o.properties.nx.decidedBy.some((d) => d.field === 'Elf64_Phdr.p_flags'));
  });
});

// ════════════════════════════════════════════════════════════════════════════
// The CLI, end to end
// ════════════════════════════════════════════════════════════════════════════

function runCli(args) {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

describe('artefact-require CLI', () => {
  test('REAL: hardened, four requirements, a working control -> exit 0', { skip: skipReal }, () => {
    const r = runCli(['--artifact', join(MATRIX, 'hardened'),
      '--require', 'pie,nx,relro-full,no-writable-executable-section',
      '--expect', CONTROL]);
    assert.equal(r.code, 0, r.stdout + (r.stderr ?? ''));
    assert.match(r.stdout, /scan=CLEAN/);
    assert.match(r.stdout, /findings=0 incomplete=0/);
  });

  test('REAL: the same policy against libshared.so -> exit 3', { skip: skipReal }, () => {
    const r = runCli(['--artifact', join(MATRIX, 'libshared.so'),
      '--require', 'nx', '--forbid', SECRET, '--expect', CONTROL]);
    assert.equal(r.code, 3, r.stdout);
    assert.match(r.stdout, /scan=BROKEN/);
  });

  // The shape of expectStrings, not its contents. A scalar there used to reach
  // the spread at artefact-require.mjs and become one control per character;
  // every single character is present in every artefact, so every control was
  // "found", the scan reported CLEAN and the process exited 0 -- on libshared.so,
  // which is the very binary the control exists to catch. The two tests below are
  // a pair on purpose: the scalar must be refused, and the array form against the
  // same binary must still reach BROKEN, so a future fix cannot buy the first by
  // breaking the second.
  test('REAL: a policy whose expectStrings is a scalar is refused, not silently exploded', { skip: skipReal }, () => {
    const p = join(TMP, 'policy-scalar-expect.json');
    writeFileSync(p, JSON.stringify({ artifact: { expectStrings: CONTROL } }));
    const r = runCli(['--artifact', join(MATRIX, 'libshared.so'), '--policy', p]);
    assert.equal(r.code, 4, r.stdout + (r.stderr ?? ''));
    assert.match(r.stderr ?? '', /expectStrings must be an array/);
    assert.doesNotMatch(r.stdout, /scan=CLEAN/,
      'a refused policy must not also have produced a clean scan');
  });

  test('REAL: the array form of that same policy still reaches BROKEN', { skip: skipReal }, () => {
    const p = join(TMP, 'policy-array-expect.json');
    writeFileSync(p, JSON.stringify({ artifact: { expectStrings: [CONTROL] } }));
    const r = runCli(['--artifact', join(MATRIX, 'libshared.so'), '--policy', p]);
    assert.equal(r.code, 3, r.stdout + (r.stderr ?? ''));
    assert.match(r.stdout, /scan=BROKEN/);
    assert.match(r.stdout, /controls=1/,
      'one control, not one per character');
  });

  test('REAL: a policy file naming stack-protector -> exit 3 with a reason', { skip: skipReal }, () => {
    const p = join(TMP, 'policy.json');
    writeFileSync(p, JSON.stringify({
      policyVersion: 'policy-v0', failOn: 'medium',
      artifact: { require: ['pie', 'stack-protector'], forbidStrings: [], expectStrings: [CONTROL] },
    }));
    const r = runCli(['--artifact', join(MATRIX, 'hardened'), '--policy', p]);
    assert.equal(r.code, 3, r.stdout);
    assert.match(r.stdout, /stack-protector: required by the policy and NOT CHECKED here/);
  });

  test('REAL: wx-on -> exit 2 with VG-ART-004 naming the section', { skip: skipReal }, () => {
    const r = runCli(['--artifact', join(MATRIX, 'wx-on'),
      '--require', 'no-writable-executable-section', '--expect', 'GCC:']);
    assert.equal(r.code, 2, r.stdout);
    assert.match(r.stdout, /VG-ART-004/);
    assert.match(r.stdout, /\.vgwx/);
  });

  test('a file that is not ELF64 LSB is exit 3, never exit 0', () => {
    const p = join(TMP, 'not-an-elf');
    writeFileSync(p, 'this is not an ELF image, it is a sentence.\n');
    const r = runCli(['--artifact', p, '--require', 'pie']);
    assert.equal(r.code, 3, r.stdout);
    assert.match(r.stdout, /unreadable/);
  });

  test('no --artifact is a tool failure, not a pass', () => {
    const r = runCli(['--require', 'pie']);
    assert.equal(r.code, 1);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// The suite refuses to report a green tick for a run that examined nothing
// ════════════════════════════════════════════════════════════════════════════

describe('coverage of this run', () => {
  test('the fixture matrix is either complete or absent — never partial', () => {
    if (!MATRIX) {
      assert.notEqual(process.env.VG_ART_MATRIX_REQUIRED, '1',
        'VG_ART_MATRIX_REQUIRED=1 was set and no fixture matrix was found. ' + skipReal);
      // Loud, so a green run cannot be mistaken for a full one.
      process.stdout.write(`# NOTE: ${MATRIX_ROWS.length} real-binary assertions were SKIPPED. ${skipReal}\n`);
      return;
    }
    const have = new Set(readdirSync(MATRIX));
    const missing = MATRIX_ROWS.filter((n) => !have.has(n));
    assert.deepEqual(missing, [],
      'the matrix directory exists but does not hold every row. A table with holes reads as agreement.');
  });
});
