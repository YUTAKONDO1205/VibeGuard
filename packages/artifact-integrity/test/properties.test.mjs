// The hardening set, both directions, against the measured table.
//
// Every `assert` here has a row in the measured table behind it (README, and
// `compiler/elf-verifier/artefact-ground-truth.md` in full). The
// negative fixtures are not decoration: for each property the test asserts both
// that the protection is seen when it is there AND that it is reported missing
// when it is not, because a one-directional test is a false-positive factory
// and a detector that only ever says PRESENT is worse than no detector.

import test from 'node:test';
import assert from 'node:assert/strict';

import { readElf, linkForm, dynstrNames, pltCallSites, undefinedSymbols } from '../src/elf.mjs';
import {
  STATE, decidePie, decideNx, decideRelro, decideStackProtector, decideFortify,
  decideBuildId, decideNoWritableExecutable, decideAll,
} from '../src/properties.mjs';
import { RECIPES, buildElf, FLAGS } from './synth-elf.mjs';

function elfFor(name) {
  const f = RECIPES[name];
  assert.ok(f, `no recipe named ${name}`);
  const elf = readElf(f(), { path: name });
  assert.equal(elf.supported, true, `recipe ${name} did not produce a readable ELF64`);
  return elf;
}

test('every recipe produces a readable ELF64 LSB image', () => {
  const names = Object.keys(RECIPES);
  assert.ok(names.length >= 20, `expected the measured matrix, got ${names.length} recipes`);
  for (const n of names) {
    const elf = readElf(RECIPES[n](), { path: n });
    assert.equal(elf.supported, true, `${n}: ${elf.reason}`);
    assert.deepEqual(elf.truncated, [], `${n} is truncated`);
  }
});

// ── link form ───────────────────────────────────────────────────────────────

test('link form is read out of the image, not taken from a flag', () => {
  assert.equal(linkForm(elfFor('hardened')), 'exec-pie');
  assert.equal(linkForm(elfFor('pie-off')), 'exec-nonpie');
  assert.equal(linkForm(elfFor('shared-object')), 'shared-object');
  assert.equal(linkForm(elfFor('static-hardened')), 'exec-static');
});

// ── PIE ─────────────────────────────────────────────────────────────────────

test('PIE: present when ET_DYN and DF_1_PIE, absent when ET_EXEC', () => {
  assert.equal(decidePie(elfFor('pie-on')).state, STATE.PRESENT);
  assert.equal(decidePie(elfFor('pie-off')).state, STATE.ABSENT);
});

test('PIE: e_type == ET_DYN alone does not make a shared object a PIE', () => {
  // Measured: libshared.so is ET_DYN(3) and carries no DT_FLAGS_1 at all. A
  // check on e_type alone reports it as a position-independent executable.
  const elf = elfFor('shared-object');
  assert.equal(elf.ehdr.e_type, 3, 'the fixture must be ET_DYN or it proves nothing');
  const rec = decidePie(elf);
  assert.equal(rec.state, STATE.NOT_APPLICABLE);
  assert.notEqual(rec.state, STATE.PRESENT);
});

test('PIE: the record names both deciding fields', () => {
  const fields = decidePie(elfFor('pie-off')).decidedBy.map((d) => d.field);
  assert.deepEqual(fields, ['Elf64_Ehdr.e_type', 'DT_FLAGS_1']);
});

// ── NX ──────────────────────────────────────────────────────────────────────

test('NX: PF_X clear is present, PF_X set is absent', () => {
  assert.equal(decideNx(elfFor('nx-on')).state, STATE.PRESENT);
  assert.equal(decideNx(elfFor('nx-off')).state, STATE.ABSENT);
});

test('NX: a missing PT_GNU_STACK is ABSENT, not NOT_OBSERVED', () => {
  // With no PT_GNU_STACK the kernel falls back to an executable stack, so the
  // honest answer is "the protection is not there", not "we did not look".
  const rec = decideNx(elfFor('nx-absent'));
  assert.equal(rec.state, STATE.ABSENT);
  assert.match(rec.note, /executable stack/);
});

// ── RELRO ───────────────────────────────────────────────────────────────────

test('RELRO: full requires PT_GNU_RELRO and eager binding', () => {
  const rec = decideRelro(elfFor('relro-full'));
  assert.equal(rec.state, STATE.PRESENT);
  assert.equal(rec.level, 'full');
});

test('RELRO: -z norelro keeps BIND_NOW set — eager binding alone must not pass', () => {
  // THE MEASURED TRAP. relro-none has DT_FLAGS=0x8 and DT_FLAGS_1=0x8000001,
  // exactly like the fully hardened link; only PT_GNU_RELRO is gone. A checker
  // keyed on eager binding calls this binary FULL RELRO.
  const elf = elfFor('relro-none');
  const flags = elf.dynamic.find((d) => d.tag === 30);
  const flags1 = elf.dynamic.find((d) => d.tag === 0x6ffffffb);
  assert.equal(Number(flags.value), 0x8, 'fixture must still carry DF_BIND_NOW or it proves nothing');
  assert.equal(Number(flags1.value), 0x8000001, 'fixture must still carry DF_1_NOW');
  const rec = decideRelro(elf);
  assert.equal(rec.state, STATE.ABSENT);
  assert.equal(rec.level, 'none');
});

test('RELRO: -z lazy keeps PT_GNU_RELRO — the segment alone must not pass', () => {
  // The trap in the other direction. relro-part has PT_GNU_RELRO, no DT_FLAGS
  // tag at all, and DT_FLAGS_1 = 0x8000000 (PIE only, NOW clear).
  const elf = elfFor('relro-part');
  assert.ok(elf.phdrs.some((p) => p.p_type === 0x6474e552), 'fixture must keep PT_GNU_RELRO');
  const rec = decideRelro(elf);
  assert.equal(rec.state, STATE.ABSENT);
  assert.equal(rec.level, 'partial');
});

test('RELRO: DT_BIND_NOW is absent on every measured fixture, so it cannot be the only spelling checked', () => {
  for (const name of ['relro-full', 'hardened']) {
    const elf = elfFor(name);
    assert.equal(elf.dynamic.some((d) => d.tag === 24), false,
      `${name}: the fixture must reproduce the measured absence of DT_BIND_NOW`);
    assert.equal(decideRelro(elf).level, 'full',
      `${name}: full RELRO must be recognised through DT_FLAGS/DT_FLAGS_1 alone`);
  }
});

test('RELRO: the third legal spelling, DT_BIND_NOW, is also accepted', () => {
  const buf = buildElf({ form: 'exec-pie', gnuStackFlags: 6, gnuRelro: true, dtBindNow: true, dtFlags: null, dtFlags1: 0x8000000 });
  const rec = decideRelro(readElf(buf, { path: 'bindnow' }));
  assert.equal(rec.level, 'full');
});

// ── STACK PROTECTOR ─────────────────────────────────────────────────────────

test('stack protector: present with a __stack_chk_fail call site, absent without', () => {
  assert.equal(decideStackProtector(elfFor('sp-on')).state, STATE.PRESENT);
  assert.equal(decideStackProtector(elfFor('sp-off')).state, STATE.ABSENT);
});

test('stack protector: the oracle is the call site, not the name in .dynstr', () => {
  const elf = elfFor('fortify-name-only');
  assert.ok(dynstrNames(elf).includes('__stack_chk_fail'),
    'the fixture must carry the name in .dynstr or it proves nothing');
  assert.equal(undefinedSymbols(elf).some((s) => s.name === '__stack_chk_fail'), false);
  assert.equal(pltCallSites(elf).some((c) => c.name === '__stack_chk_fail'), false);
  assert.equal(decideStackProtector(elf).state, STATE.ABSENT);
});

test('stack protector: a static image is NOT_OBSERVED, never PRESENT and never ABSENT', () => {
  // Measured: __stack_chk_fail is DEFINED in both the protected and the
  // unprotected static build, and the canary-load count is 355 against 353.
  // Neither oracle separates them at whole-image granularity.
  const rec = decideStackProtector(elfFor('static-hardened'));
  assert.equal(rec.state, STATE.NOT_OBSERVED);
  assert.match(rec.note, /355 against 353|per-object attribution/);
});

// ── FORTIFY ─────────────────────────────────────────────────────────────────

test('fortify: present with a __*_chk call site, absent when the plain call is imported instead', () => {
  assert.equal(decideFortify(elfFor('fortify-on')).state, STATE.PRESENT);
  const off = decideFortify(elfFor('fortify-off'));
  assert.equal(off.state, STATE.ABSENT);
  assert.match(off.note, /strcpy/);
});

test('fortify: the name in .dynstr with nothing calling it is ABSENT', () => {
  const elf = elfFor('fortify-name-only');
  assert.ok(dynstrNames(elf).includes('__strcpy_chk'));
  assert.equal(decideFortify(elf).state, STATE.ABSENT);
});

test('fortify: nothing fortifiable in the program is NOT_OBSERVED, not ABSENT', () => {
  // Zero _chk call sites in a program that makes no fortifiable call is not
  // evidence that fortification is off.
  const rec = decideFortify(elfFor('fortify-nothing-to-fortify'));
  assert.equal(rec.state, STATE.NOT_OBSERVED);
});

test('fortify: __stack_chk_fail is not counted as a fortify call site', () => {
  // It ends in _chk and belongs to the other property. Counting it would report
  // every protector build as fortified.
  const rec = decideFortify(elfFor('sp-on'));
  assert.notEqual(rec.state, STATE.PRESENT);
});

test('fortify: a static image is NOT_OBSERVED', () => {
  assert.equal(decideFortify(elfFor('static-hardened')).state, STATE.NOT_OBSERVED);
});

// ── BUILD ID ────────────────────────────────────────────────────────────────

test('build id: present from the note payload, absent when the note is gone', () => {
  const on = decideBuildId(elfFor('buildid-on'));
  assert.equal(on.state, STATE.PRESENT);
  assert.equal(on.buildId.length, 40, 'sha1 build id is 20 bytes / 40 hex characters');
  assert.equal(decideBuildId(elfFor('buildid-off')).state, STATE.ABSENT);
});

test('build id: a section NAMED .note.gnu.build-id holding another note is ABSENT', () => {
  const elf = elfFor('buildid-name-only');
  assert.ok(elf.sectionByName.has('.note.gnu.build-id'),
    'the fixture must carry the section name or it proves nothing');
  const rec = decideBuildId(elf);
  assert.equal(rec.state, STATE.ABSENT);
  assert.match(rec.note, /holds no NT_GNU_BUILD_ID/);
});

// ── W+X ─────────────────────────────────────────────────────────────────────

test('W+X: a section with SHF_WRITE|SHF_EXECINSTR is caught', () => {
  const rec = decideNoWritableExecutable(elfFor('wx-section'));
  assert.equal(rec.state, STATE.ABSENT);
  assert.equal(rec.hits.length, 1);
  assert.equal(rec.hits[0].name, '.vgwx');
  assert.equal(rec.hits[0].kind, 'section');
});

test('W+X: a PT_LOAD with PF_W|PF_X is caught even when no section is W+X', () => {
  const rec = decideNoWritableExecutable(elfFor('wx-segment'));
  assert.equal(rec.state, STATE.ABSENT);
  assert.ok(rec.hits.some((h) => h.kind === 'segment'));
  assert.equal(rec.hits.some((h) => h.kind === 'section'), false);
});

test('W+X: an ordinary binary is not flagged — .data is W, .text is X, neither is both', () => {
  for (const name of ['hardened', 'unhardened', 'pie-off', 'static-hardened', 'shared-object']) {
    const elf = elfFor(name);
    assert.ok(elf.sections.some((s) => s.writable && s.allocated), `${name} must have a writable section`);
    assert.ok(elf.sections.some((s) => s.executable), `${name} must have an executable section`);
    assert.equal(decideNoWritableExecutable(elf).state, STATE.PRESENT, `${name} was flagged W+X and should not be`);
  }
});

// ── the matrix as a whole ───────────────────────────────────────────────────

test('the fully hardened fixture has every property PRESENT', () => {
  const p = decideAll(elfFor('hardened'));
  for (const [name, rec] of Object.entries(p)) {
    assert.equal(rec.state, STATE.PRESENT, `hardened: ${name} is ${rec.state}`);
  }
});

test('the unhardened fixture has every hardening property ABSENT', () => {
  const p = decideAll(elfFor('unhardened'));
  for (const name of ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id']) {
    assert.equal(p[name].state, STATE.ABSENT, `unhardened: ${name} is ${p[name].state}, expected ABSENT`);
  }
});

test('no decider ever returns a state outside the vocabulary', () => {
  const allowed = new Set(Object.values(STATE));
  for (const name of Object.keys(RECIPES)) {
    for (const [prop, rec] of Object.entries(decideAll(elfFor(name)))) {
      assert.ok(allowed.has(rec.state), `${name}/${prop}: ${rec.state}`);
    }
  }
});

test('every decider explains itself: decidedBy is never empty', () => {
  for (const name of Object.keys(RECIPES)) {
    for (const [prop, rec] of Object.entries(decideAll(elfFor(name)))) {
      assert.ok(Array.isArray(rec.decidedBy) && rec.decidedBy.length > 0, `${name}/${prop}`);
      for (const d of rec.decidedBy) assert.ok(typeof d.field === 'string' && d.field.length > 0);
    }
  }
});

test('flag constants match the psABI values the table was read with', () => {
  assert.equal(FLAGS.SHF.WRITE, 0x1);
  assert.equal(FLAGS.SHF.ALLOC, 0x2);
  assert.equal(FLAGS.SHF.EXECINSTR, 0x4);
  assert.equal(FLAGS.PT.GNU_STACK, 0x6474e551);
  assert.equal(FLAGS.PT.GNU_RELRO, 0x6474e552);
});
