/**
 * The gcc LTO probe's pure parts (tools/lib/lto-gcc.mjs). Nothing here compiles
 * or links. The shapes are the ones that would let a non-LTO measurement, a
 * record from the other plugin or a vacuous control pass silently: a plain ELF
 * object where a gcc LTO object was wanted, a link that wrote another layout, a
 * refusal printed once instead of twice, a WipePin record handed to a WipePinGcc
 * reader, a grade over nothing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  GCC_COMPONENT, gccCompileFlags, gccLinkArgs, elfSections, gccObjectKind, sectionText, optsNamePlugin, gccExpectedOutputs,
  gccLayoutOf, LAYOUTS, EXPECTED_LAYOUT, GCC_LTO_REFUSAL, EXPECTED_REFUSALS, stderrLines, wipePinGccLines, refusalReading,
  gradeLinkPluginGcc, gccLtoOutcome, selectIds, summarizeGccGroup, brokenReasons,
  gimpleBodyOf, zeroMemsetsInGimple, gimpleControlOk, carriesWipe,
} from '../tools/lib/lto-gcc.mjs';
import { pickOutput, SENTINEL, linkPluginState } from '../tools/lib/lto.mjs';
import { validatePinRecord } from '../lib/pin-record.mjs';
import { evidenceDigest, canonicalJsonRaw, sha256Hex } from '../../../evidence/canon.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const WIPEPINGCC_CPP = join(HERE, '..', '..', '..', 'gcc-repair', 'src', 'WipePinGcc.cpp');
const FIXTURE_CHECKER = join(HERE, '..', '..', '..', 'gcc-repair', 'scripts', 'check-gcc-fixture-loop.py');

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';
const v = (verdict) => ({ verdict, control: 'PRESENT', control_via: 'oracle' });
const FLAGS = ['-S', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none'];

/**
 * A minimal ELF64 little-endian relocatable file: a null section, the named
 * sections with the given contents, and the section-name table last.
 */
function elf64(sections, { klass = 2, data = 1, extended = false } = {}) {
  const names = ['', ...sections.map((s) => s.name), '.shstrtab'];
  const nameOff = [];
  let strtab = '';
  for (const n of names) { nameOff.push(strtab.length); strtab += n + '\0'; }
  const bodies = [Buffer.alloc(0), ...sections.map((s) => Buffer.from(s.content ?? '', 'latin1')), Buffer.from(strtab, 'latin1')];
  let off = 64;
  const offsets = bodies.map((b) => { const o = off; off += b.length; return o; });
  const shoff = off;
  const n = names.length;
  const buf = Buffer.alloc(shoff + n * 64);
  buf.set([0x7f, 0x45, 0x4c, 0x46, klass, data, 1], 0);
  buf.writeUInt16LE(1, 0x10); // ET_REL
  buf.writeUInt16LE(62, 0x12); // EM_X86_64
  buf.writeBigUInt64LE(BigInt(shoff), 0x28);
  buf.writeUInt16LE(64, 0x34);
  buf.writeUInt16LE(64, 0x3a);
  buf.writeUInt16LE(extended ? 0 : n, 0x3c);
  buf.writeUInt16LE(extended ? 0xffff : n - 1, 0x3e);
  bodies.forEach((b, i) => b.copy(buf, offsets[i]));
  for (let i = 0; i < n; i++) {
    const h = shoff + i * 64;
    buf.writeUInt32LE(nameOff[i], h);
    buf.writeUInt32LE(i === 0 ? 0 : i === n - 1 ? 3 : 1, h + 4);
    buf.writeBigUInt64LE(BigInt(i === 0 ? 0 : offsets[i]), h + 24);
    buf.writeBigUInt64LE(BigInt(i === 0 ? (extended ? n : 0) : bodies[i].length), h + 32);
    if (i === 0 && extended) buf.writeUInt32LE(n - 1, h + 40);
  }
  return buf;
}
const LTO_SECTIONS = [
  { name: '.gnu.lto_.decls.dfee91bb45121f09', content: 'x' },
  { name: '.gnu.lto_.opts', content: "'-fno-openmp' '-fPIC' '-O2' '-flto'" },
  { name: '.comment', content: 'GCC' },
];

test('gccCompileFlags: -S becomes -c and -flto is appended; nothing else, not -fPIC', () => {
  assert.deepEqual(gccCompileFlags(FLAGS), ['-c', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none', '-flto']);
  assert.ok(!gccCompileFlags(FLAGS).some((f) => /^-f(PIC|pic|PIE|pie)$/.test(f)));
  assert.throws(() => gccCompileFlags(FLAGS.slice(1)), /-S 0 time/);
  assert.throws(() => gccCompileFlags([...FLAGS, '-flto=auto']), /already decide/);
});

test('gccLinkArgs: one object, -shared, -save-temps; the plugin only when asked', () => {
  assert.deepEqual(gccLinkArgs({ opt: '-O2' }), ['-O2', '-flto', '-shared', '-save-temps']);
  assert.deepEqual(gccLinkArgs({ opt: '-Os', linkPlugin: 'p.so' }), ['-Os', '-flto', '-shared', '-save-temps', '-fplugin=p.so']);
  // never a partitioning choice of its own: the probe measures gcc's default
  for (const o of ['-O1', '-O2', '-O3', '-Os']) assert.ok(!gccLinkArgs({ opt: o }).some((a) => /partition|-fPIC/.test(a)));
  assert.throws(() => gccLinkArgs({ opt: '-Og' }), /bad opt/);
});

test('elfSections: names, offsets and sizes from the bytes; extended numbering followed', () => {
  const s = elfSections(elf64(LTO_SECTIONS));
  assert.equal(s.ok, true);
  assert.deepEqual(s.sections.map((x) => x.name), ['', ...LTO_SECTIONS.map((x) => x.name), '.shstrtab']);
  assert.equal(s.sections[2].size, LTO_SECTIONS[1].content.length);
  const ext = elfSections(elf64(LTO_SECTIONS, { extended: true }));
  assert.deepEqual(ext.sections.map((x) => x.name), s.sections.map((x) => x.name));
});

test('elfSections: anything it cannot read is refused with the reason, never guessed', () => {
  assert.equal(elfSections(null).problem, 'too short for an ELF64 header');
  assert.equal(elfSections(Buffer.alloc(80)).problem, 'not ELF');
  assert.equal(elfSections(elf64(LTO_SECTIONS, { klass: 1 })).problem, 'not ELF64');
  assert.equal(elfSections(elf64(LTO_SECTIONS, { data: 2 })).problem, 'not little-endian');
  const whole = elf64(LTO_SECTIONS);
  assert.match(elfSections(whole.subarray(0, whole.length - 10)).problem, /runs past the end/);
});

test('gccObjectKind: gcc-lto only with a .gnu.lto_ section; a plain ELF object, bitcode, empty and missing are named', () => {
  assert.equal(gccObjectKind(elf64(LTO_SECTIONS)), 'gcc-lto');
  // what a compile without -flto writes: sections, none of them .gnu.lto_
  assert.equal(gccObjectKind(elf64([{ name: '.text', content: '\xc3' }, { name: '.data' }])), 'elf');
  // a name that only resembles one
  assert.equal(gccObjectKind(elf64([{ name: '.gnu.lto', content: '' }, { name: 'gnu.lto_.opts' }])), 'elf');
  assert.equal(gccObjectKind(elf64(LTO_SECTIONS, { klass: 1 })), 'elf-unreadable');
  assert.equal(gccObjectKind(Buffer.from([0x42, 0x43, 0xc0, 0xde, 0x35, 0x14])), 'bitcode');
  assert.equal(gccObjectKind(Buffer.alloc(0)), 'empty');
  assert.equal(gccObjectKind(null), 'missing');
});

test('sectionText / optsNamePlugin: whether the compile\'s options name a -fplugin', () => {
  const on = elf64([{ name: '.gnu.lto_.opts', content: "'-O2' '-flto' '-fplugin=/lab/libWipePinGcc.so'" }]);
  assert.equal(optsNamePlugin(on), true);
  assert.equal(optsNamePlugin(elf64(LTO_SECTIONS)), false);
  assert.equal(optsNamePlugin(elf64([{ name: '.text' }])), null);
  assert.equal(sectionText(elf64(LTO_SECTIONS), '.comment'), 'GCC');
  assert.equal(sectionText(Buffer.alloc(3), '.comment'), null);
});

test('gccExpectedOutputs: the eleven names gcc 13.3 writes for a one-partition link, all after -o', () => {
  const x = gccExpectedOutputs({ outBase: 'stock1.so' });
  assert.equal(x.read, 'stock1.so.ltrans0.ltrans.s');
  assert.equal(x.so, 'stock1.so');
  assert.equal(x.expected.length, 11);
  assert.deepEqual(x.expected, [...x.expected].sort());
  for (const n of ['stock1.so', 'stock1.so.res', 'stock1.so.wpa.args.0', 'stock1.so.ltrans0.o', 'stock1.so.ltrans0.ltrans.o', 'stock1.so.lto_wrapper_args']) {
    assert.ok(x.expected.includes(n), n);
  }
  assert.throws(() => gccExpectedOutputs({ outBase: 'a/b.so' }), /bad output basename/);
  assert.throws(() => gccExpectedOutputs({ outBase: '' }), /bad output basename/);
});

test('gccLayoutOf and pickOutput: the layout says how lto1 ran, and only the expected one passes', () => {
  const want = gccExpectedOutputs({ outBase: 'o.so' });
  const names = (layout) => LAYOUTS[layout].map((s) => `o.so${s}`);
  assert.equal(gccLayoutOf(names('wpa+1-ltrans'), 'o.so'), EXPECTED_LAYOUT);
  assert.deepEqual(pickOutput([...names('wpa+1-ltrans')].reverse(), want), { ok: true, name: 'o.so.ltrans0.ltrans.s', problem: null });
  // -flto-partition=none: one lto1, no partition files, the assembly is .lto.o.s
  assert.equal(gccLayoutOf(names('partition-none'), 'o.so'), 'partition-none');
  assert.match(pickOutput(names('partition-none'), want).problem, /unexpected output\(s\) o\.so\.lto\.o,o\.so\.lto\.o\.args\.0,o\.so\.lto\.o\.s/);
  // an object without .gnu.lto_ sections: ld links it and lto1 never runs
  assert.equal(gccLayoutOf(['o.so'], 'o.so'), 'no-lto');
  assert.equal(pickOutput(['o.so'], want).ok, false);
  assert.equal(gccLayoutOf([], 'o.so'), 'nothing-written');
  const two = [...names('wpa+1-ltrans'), 'o.so.ltrans1.o', 'o.so.ltrans1.ltrans.o', 'o.so.ltrans1.ltrans.s', 'o.so.ltrans1.ltrans_args', 'o.so.ltrans1.ltrans.args.0'];
  assert.equal(gccLayoutOf(two, 'o.so'), 'wpa+2-ltrans');
  assert.equal(gccLayoutOf([...names('wpa+1-ltrans'), 'core'], 'o.so'), 'other');
  assert.equal(pickOutput([...names('wpa+1-ltrans'), 'core'], want).ok, false);
});

test('GCC_LTO_REFUSAL is the line WipePinGcc.cpp prints in lto1, and the fixture checker\'s LTO_REFUSAL', () => {
  const src = readFileSync(WIPEPINGCC_CPP, 'utf8');
  const m = /"GNU GIMPLE"\) == 0\) \{\s*fprintf\(stderr,([\s\S]*?)\);/.exec(src);
  assert.ok(m, 'the lto1 refusal was not found in WipePinGcc.cpp');
  const line = [...m[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]).join('');
  assert.equal(line, `${GCC_LTO_REFUSAL}\\n`);
  const py = readFileSync(FIXTURE_CHECKER, 'utf8');
  const p = /LTO_REFUSAL = \(([\s\S]*?)\)\n/.exec(py);
  assert.ok(p, 'LTO_REFUSAL not found in check-gcc-fixture-loop.py');
  assert.equal([...p[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]).join(''), GCC_LTO_REFUSAL);
  assert.equal(EXPECTED_REFUSALS, Number(/LTO_REFUSALS = (\d+)/.exec(py)[1]));
});

test('refusalReading: twice and otherwise the stock link\'s stderr; once, three times or extra text is not it', () => {
  const R = GCC_LTO_REFUSAL;
  assert.deepEqual(refusalReading(`${R}\n${R}\n`, ''), { count: 2, restIsStock: true, exact: true });
  assert.equal(refusalReading(`${R}\r\n${R}\r\n`, '').exact, true);
  // -flto-partition=none: lto1 runs once
  assert.deepEqual(refusalReading(`${R}\n`, ''), { count: 1, restIsStock: true, exact: false });
  assert.equal(refusalReading(`${R}\n${R}\n${R}\n`, '').exact, false);
  // lto1's own warnings are allowed exactly when the stock link printed the same ones
  const warn = "x.w.c:9:3: warning: 'memset' writing 64 bytes into a region of size 32";
  assert.equal(refusalReading(`${R}\n${warn}\n${R}\n`, `${warn}\n`).exact, true);
  assert.deepEqual(refusalReading(`${R}\n${R}\n${warn}\n`, ''), { count: 2, restIsStock: false, exact: false });
  assert.equal(refusalReading(`${R}\n${R}\n`, `${warn}\n`).restIsStock, false);
  assert.deepEqual(refusalReading(null, ''), { count: 0, restIsStock: false, exact: false });
  // a refusal for another reason is not the LTO refusal
  assert.equal(refusalReading('WipePinGcc: refusing to install: no target\n', '').count, 0);
  assert.deepEqual(stderrLines('a\r\n\nb\n'), ['a', 'b']);
});

test('wipePinGccLines: any WipePinGcc line counts on a stock link', () => {
  assert.equal(wipePinGccLines(''), 0);
  assert.equal(wipePinGccLines(`${GCC_LTO_REFUSAL}\nlto-wrapper: note: x\nWipePinGcc: target f not-in-module\n`), 2);
  assert.equal(wipePinGccLines(null), 0);
});

test('the (ii) sentinel reading is ./lto.mjs\'s: removed means the load cleared WPIN_OUT', () => {
  assert.equal(linkPluginState({ exists: false, text: null }), 'removed');
  assert.equal(linkPluginState({ exists: true, text: SENTINEL }), 'sentinel-kept');
});

test('gradeLinkPluginGcc: every (ii) link refused twice, cleared WPIN_OUT, and matched the stock link', () => {
  const good = { rc: 0, state: 'removed', refusals: 2, restIsStock: true, layout: EXPECTED_LAYOUT, asmEqualsStock: true, soEqualsStock: true };
  const row = (id, w, wo = good, outcome = 'RETAINED') => ({ id, opt: '-O2', outcome, linkPlugin: { w, wo } });
  assert.deepEqual(gradeLinkPluginGcc([row('a', good), row('b', good)]), { held: true, links: 4, violations: [] });
  // -flto-partition=none on the link line: one refusal, another layout, and no assembly read to compare
  const once = gradeLinkPluginGcc([row('a', { ...good, refusals: 1, layout: 'partition-none', asmEqualsStock: null })]);
  assert.equal(once.held, false);
  assert.match(once.violations[0], /^a -O2 w: the LTO refusal printed 1 time\(s\), expected 2/);
  assert.match(once.violations[1], /partition-none layout, expected wpa\+1-ltrans/);
  assert.match(once.violations[2], /post-LTO assembly could not be compared with the stock link's/);
  assert.match(gradeLinkPluginGcc([row('a', { ...good, asmEqualsStock: false })]).violations[0], /post-LTO assembly is not byte-identical to the stock link's/);
  assert.match(gradeLinkPluginGcc([row('a', { ...good, state: 'sentinel-kept' })]).violations[0], /sentinel-kept, expected removed/);
  assert.match(gradeLinkPluginGcc([row('a', { ...good, state: 'record-written' })]).violations[0], /record-written/);
  assert.match(gradeLinkPluginGcc([row('a', { ...good, restIsStock: false })]).violations[0], /less the refusal lines/);
  assert.match(gradeLinkPluginGcc([row('a', good, { ...good, soEqualsStock: null })]).violations[0], /^a -O2 wo: the shared object/);
  assert.match(gradeLinkPluginGcc([row('a', { ...good, rc: 1 })]).violations[0], /exited 1/);
  assert.equal(gradeLinkPluginGcc([row('a', undefined)]).held, false);
  // NOT_LTO cells are not graded here, and a grade over nothing is a failure
  assert.equal(gradeLinkPluginGcc([row('a', { refusals: 0 }, { refusals: 0 }, 'NOT_LTO'), row('b', good)]).links, 2);
  const vac = gradeLinkPluginGcc([row('a', good, good, 'NOT_LTO')]);
  assert.equal(vac.held, false);
  assert.match(vac.violations[0], /vacuous/);
});

// ---- records: a sealed wipe-pin-v2 record, as the plugins write it ---------------
function toolchainOf(key, version) {
  const packages = [{ name: key === 'clang' ? 'llvm' : key, version }];
  return { [key]: version, packages, digest: sha256Hex(canonicalJsonRaw({ [key]: version, packages })) };
}
function sealed(over = {}) {
  const rec = {
    schemaVersion: 'wipe-pin-v2', component: 'WipePinGcc', module: 'fable_N_aeskey_r1.w.c', optLevel: { speedup: 2, size: 0 },
    scope: 'functions', requested: ['encrypt_blob'],
    resolution: [{ name: 'encrypt_blob', resolution: 'resolved', exact: true, linkage: 'external' }],
    dryRun: false,
    pinned: [{ function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41, followedByUse: false }],
    pinnedCount: 1, wouldPinCount: 1,
    seen: { zeroFillMemsetInScope: 1, zeroFillMemsetInModule: 2 },
    unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 },
    toolchain: toolchainOf('gcc', '13.3.0'),
    ...over,
  };
  rec.evidenceDigest = evidenceDigest(rec);
  rec.context = { generatedAt: 1, sourceDateEpoch: null, timeSource: 'wall-clock' };
  return rec;
}
const EXPECT = { component: GCC_COMPONENT, scope: 'functions', dryRun: false, opt: '-O2', module: 'fable_N_aeskey_r1.w.c', requested: ['encrypt_blob'] };

test('a WipePin record read as this probe reads it -- component WipePinGcc -- is refused; its own is not', () => {
  assert.equal(validatePinRecord(sealed(), EXPECT).ok, true);
  // a genuine, sealed clang record of the same unit: the three fields the clang probe reads would pass it
  const clang = validatePinRecord(sealed({ component: 'WipePin', toolchain: toolchainOf('clang', '18.1.3') }), EXPECT);
  assert.equal(clang.ok, false);
  assert.ok(clang.problems.some((p) => /wrong-compile: component WipePin, this compile loaded WipePinGcc/.test(p)), clang.problems.join('; '));
});

test('gccLtoOutcome: NOT_LTO first, then the repair loop\'s outcomeOf over the records pin-record.mjs read', () => {
  const rW = validatePinRecord(sealed(), EXPECT);
  const rWo = validatePinRecord(sealed({ module: 'fable_N_aeskey_r1.wo.c', pinned: [], pinnedCount: 0, wouldPinCount: 0,
    seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 1 } }), { ...EXPECT, module: 'fable_N_aeskey_r1.wo.c' });
  assert.equal(rW.ok && rWo.ok, true);
  const base = { notLto: [], recordW: rW, recordWo: rWo, controlOnOk: true };
  const nl = gccLtoOutcome({ ...base, notLto: ['w.off object is elf'], baseline: v(E), repaired: v(S) });
  assert.deepEqual(nl, { outcome: 'NOT_LTO', reason: 'w.off object is elf' });
  assert.equal(gccLtoOutcome({ ...base, baseline: v(E), repaired: v(S) }).outcome, 'RETAINED');
  assert.equal(gccLtoOutcome({ ...base, baseline: v(E), repaired: v(E) }).outcome, 'PIN_INEFFECTIVE');
  assert.equal(gccLtoOutcome({ ...base, baseline: v(S), repaired: v(S) }).outcome, 'ALREADY_SURVIVED');
  assert.equal(gccLtoOutcome({ ...base, baseline: v('COMPILE_ERROR'), repaired: v(S) }).outcome, 'NOT_SCORED');
  // a refused record, or a control missing from a plugin-on link, is BROKEN_REPAIR, as in the repair loop
  const refused = validatePinRecord(sealed({ component: 'WipePin', toolchain: toolchainOf('clang', '18.1.3') }), EXPECT);
  const b = gccLtoOutcome({ ...base, baseline: v(E), repaired: v(S), recordW: refused });
  assert.equal(b.outcome, 'BROKEN_REPAIR');
  assert.match(b.reason, /wrong-compile: component WipePin/);
  assert.equal(gccLtoOutcome({ ...base, baseline: v(E), repaired: v(S), controlOnOk: false }).outcome, 'BROKEN_REPAIR');
  // a requested name the w record did not resolve
  const unres = validatePinRecord(sealed({ resolution: [{ name: 'encrypt_blob', resolution: 'not-in-module', exact: null, linkage: null }],
    pinned: [], pinnedCount: 0, wouldPinCount: 0, seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 1 } }), EXPECT);
  assert.equal(unres.ok, true);
  assert.equal(gccLtoOutcome({ ...base, baseline: v(E), repaired: v(E), recordW: unres }).outcome, 'BROKEN_REPAIR');
});

test('selectIds: eliminated at the level, or with allRemovable every removable file there; one compiler', () => {
  const r = (id, opt, baseline, idiom = 'removable', cc = 'gcc-13', kind = 'erasure') => ({ id, opt, baseline, idiom, cc, kind });
  const rows = [
    r('b', '-O2', E), r('a', '-O2', E), r('a', '-O1', S), r('c', '-O2', S), r('d', '-O2', E, 'both'),
    r('e', '-O2', E, 'removable', 'clang-18'), r('f', '-O2', null, null, 'gcc-13', 'none'), r('g', '-O2', 'NOT_OBSERVED'),
  ];
  assert.deepEqual(selectIds(rows, { cc: 'gcc-13', opt: '-O2' }), ['a', 'b', 'd']);
  assert.deepEqual(selectIds(rows, { cc: 'gcc-13', opt: '-O2', allRemovable: true }), ['a', 'b', 'c', 'g']);
  assert.deepEqual(selectIds(rows, { cc: 'gcc-13', opt: '-O1' }), []);
  assert.deepEqual(selectIds(null, { cc: 'gcc-13', opt: '-O2' }), []);
});

test('summarizeGccGroup and brokenReasons: counts, the tracked-row differences, relinks of all six objects', () => {
  const ok = { ok: true, dryRun: true, pinnedCount: 0 };
  const lpOk = { rc: 0, state: 'removed', refusals: 2, restIsStock: true, layout: EXPECTED_LAYOUT, asmEqualsStock: true, soEqualsStock: true };
  const det = (x = true) => Object.fromEntries(['w.off', 'w.on', 'w.dry', 'wo.off', 'wo.on', 'wo.dry'].map((k) => [k, { asm: x, so: x }]));
  const mk = (id, baseline, tracked, outcome, extra = {}) => ({
    id, mode: '-flto', opt: '-O2', baseline, tracked, outcome, dry: baseline, recDryW: ok, recDryWo: ok,
    linkPlugin: { verdict: baseline, w: lpOk, wo: lpOk }, deterministic: det(),
    dryAsmEqualsOff: { w: true, wo: true }, drySoEqualsOff: { w: true, wo: true },
    stockStderr: { links: 12, withWipePinGccLine: 0, nonEmpty: 0 }, labelsOnly: { baseline: false, repaired: false },
    ...extra,
  });
  const rows = [
    mk('a', E, E, 'RETAINED'),
    mk('b', E, S, 'RETAINED', { labelsOnly: { baseline: false, repaired: true } }),
    mk('c', S, E, 'ALREADY_SURVIVED', { deterministic: { ...det(), 'wo.dry': { asm: true, so: null } } }),
  ];
  const s = summarizeGccGroup(rows);
  assert.equal(s.cells, 3);
  assert.deepEqual([s.baselineEliminated, s.baselineSurvived, s.baselineOther], [2, 1, 0]);
  assert.deepEqual(s.trackedDiff, [{ id: 'b', tracked: S, lto: E, outcome: 'RETAINED' }, { id: 'c', tracked: E, lto: S, outcome: 'ALREADY_SURVIVED' }]);
  assert.deepEqual(s.addedEliminations, [{ id: 'b', outcome: 'RETAINED' }]);
  assert.equal(s.outcomes.RETAINED, 2);
  assert.equal(s.dry.held, true);
  assert.deepEqual([s.linkPlugin.links, s.linkPlugin.removed, s.linkPlugin.grade.held], [6, 6, true]);
  assert.deepEqual(s.linkPlugin.refusalHistogram, { 2: 6 });
  // six objects, assembly and shared object each: 36 pairs; one could not be compared (null) and is not identical
  assert.deepEqual(s.determinism, { pairs: 36, identical: 35 });
  assert.deepEqual(s.stockLinks, { links: 36, withWipePinGccLine: 0, nonEmpty: 0 });
  assert.deepEqual(s.labelsOnly, { baseline: 0, repaired: 1 });
  assert.deepEqual(brokenReasons([{ opt: '-O2', s }]), ['-O2: 1 relink(s) not byte-identical']);

  const fine = summarizeGccGroup([mk('a', E, E, 'RETAINED')]);
  assert.deepEqual(brokenReasons([{ opt: '-O2', s: fine }]), []);
  const bad = summarizeGccGroup([
    mk('a', E, E, 'NOT_LTO'),
    mk('b', E, E, 'RETAINED', { dry: S, linkPlugin: { verdict: E, w: { ...lpOk, refusals: 1 }, wo: lpOk },
      stockStderr: { links: 12, withWipePinGccLine: 2, nonEmpty: 2 } }),
  ]);
  const why = brokenReasons([{ opt: '-O1', s: bad }]);
  assert.deepEqual(why, ['-O1: 1 NOT_LTO cell(s)', '-O1: the dry-run red control did not hold', '-O1: configuration (ii) FAILED',
    '-O1: WipePinGcc printed on 2 stock link(s)']);
  assert.deepEqual(bad.linkPlugin.refusalHistogram, { 1: 1, 2: 1 });
});

// ---- the GIMPLE reader: lto-dump-13 -dump-body output, as gcc-13 13.3.0 prints it ------
// fable_N_aeskey_r1 at -O2: `encrypt_blob` as the plugin-off and the plugin-on objects
// carry it, and the find step's positive control; the lines as lto-dump-13 wrote them.
const gimpleFn = (tail) => [
  'int encrypt_blob (const char * passphrase, unsigned char * buf, size_t n)',
  '{',
  '  unsigned char key[32];',
  '  <bb 4> [local count: 1046569762]:',
  '  kdf (passphrase_6(D), &key);',
  '  aes256_encrypt (&key, buf_7(D), n_8(D));',
  ...tail,
  '',
  '  <bb 5> [local count: 1073741824]:',
  '  key ={v} {CLOBBER(eol)};',
  '  return _4;',
  '',
  '}',
  '',
].join('\n');
const W_OFF = gimpleFn([]);
const W_ON = gimpleFn(['  __builtin_memset (&key, 0, 32);', '  __asm__ __volatile__("" :  : "g" &key : "memory");']);
const CONTROL_BODY = [
  'void vgctl_control ()', '{', '  unsigned char vgctl_secret[32];', '',
  '  <bb 2> [local count: 1073741824]:',
  '  vgctl_fill (&vgctl_secret, 32);',
  '  vgctl_use (&vgctl_secret, 32);',
  '  __builtin_memset (&vgctl_secret, 0, 32);',
  '  vgctl_use (&vgctl_secret, 32);',
  '  vgctl_secret ={v} {CLOBBER(eol)};',
  '  return;', '', '}', '',
].join('\n');

test('gimpleBodyOf: the body is on stderr, the stdout line says one was printed; "not found" exits 0', () => {
  const printed = { rc: 0, stdout: 'GIMPLE body of function: encrypt_blob\n\n', stderr: W_ON };
  assert.deepEqual(gimpleBodyOf(printed, 'encrypt_blob'), { state: 'body', body: W_ON });
  // a declaration, a static function inlined away, or any name in an object without .gnu.lto_ sections
  assert.deepEqual(gimpleBodyOf({ rc: 0, stdout: '', stderr: 'lto-dump-13: error: Function not found.\n' }, 'kdf'), { state: 'not-defined', body: null });
  // a file it cannot open
  const fatal = { rc: 1, stdout: '', stderr: 'lto-dump-13: fatal error: open x.o failed: No such file or directory\ncompilation terminated.\n' };
  assert.equal(gimpleBodyOf(fatal, 'f').state, 'unreadable');
  // the trap the reader exists to avoid: the stdout line alone is not a body, and stdout is never read as one
  assert.equal(gimpleBodyOf({ rc: 0, stdout: 'GIMPLE body of function: encrypt_blob\n', stderr: '' }, 'encrypt_blob').state, 'unreadable');
  assert.equal(gimpleBodyOf({ rc: 0, stdout: `GIMPLE body of function: encrypt_blob\n${W_ON}`, stderr: '' }, 'encrypt_blob').state, 'unreadable');
  // a body printed for another name, a spawn failure, nothing at all
  assert.equal(gimpleBodyOf({ rc: 0, stdout: 'GIMPLE body of function: other\n', stderr: W_ON }, 'encrypt_blob').state, 'unreadable');
  assert.equal(gimpleBodyOf({ rc: -1, stdout: '', stderr: 'spawn lto-dump-13 ENOENT' }, 'f').state, 'unreadable');
  assert.equal(gimpleBodyOf(null, 'f').state, 'unreadable');
});

test('zeroMemsetsInGimple: a zero-fill memset is pinned only when the barrier naming its destination follows', () => {
  assert.deepEqual(zeroMemsetsInGimple({ encrypt_blob: W_OFF }), { defined: ['encrypt_blob'], plain: 0, pinned: 0, helperCalls: 0 });
  assert.deepEqual(zeroMemsetsInGimple({ encrypt_blob: W_ON }), { defined: ['encrypt_blob'], plain: 0, pinned: 1, helperCalls: 0 });
  // a barrier that names another buffer, or none, is not a pin
  const other = gimpleFn(['  __builtin_memset (&key, 0, 32);', '  __asm__ __volatile__("" :  : "g" &iv : "memory");']);
  assert.deepEqual(zeroMemsetsInGimple({ f: other }), { defined: ['f'], plain: 1, pinned: 0, helperCalls: 0 });
  const clobberOnly = gimpleFn(['  __builtin_memset (&key, 0, 32);', '  __asm__ __volatile__("" :  :  : "memory");']);
  assert.deepEqual(zeroMemsetsInGimple({ f: clobberOnly }), { defined: ['f'], plain: 1, pinned: 0, helperCalls: 0 });
  // the spellings a zero fill takes: a call with a result, the checking form, a tail call
  const forms = gimpleFn(['  _17 = memset (&key, 0, 32);', '  __builtin___memset_chk (p_2(D), 0, n_3(D), _4);',
    '  __builtin_memset (buf_7(D), 0, n_8(D)); [tail call]', '  __asm__ __volatile__("" :  : "g" buf_7(D) : "memory");']);
  assert.deepEqual(zeroMemsetsInGimple({ f: forms }), { defined: ['f'], plain: 2, pinned: 1, helperCalls: 0 });
  // not a zero fill, and not a memset
  const notZero = gimpleFn(['  __builtin_memset (&key, 255, 32);', '  __builtin_memset (&key, c_3(D), 32);', '  memcpy (&key, buf_7(D), 32);']);
  assert.deepEqual(zeroMemsetsInGimple({ f: notZero }), { defined: ['f'], plain: 0, pinned: 0, helperCalls: 0 });
  // brackets keep an argument whole, commas inside them included
  assert.equal(zeroMemsetsInGimple({ f: gimpleFn(['  __builtin_memset (&MEM <char[2][4]> [(void *)&k + 4B], 0, 4);']) }).plain, 1);
  assert.equal(zeroMemsetsInGimple({ f: gimpleFn(['  __builtin_memset (&BIT_FIELD_REF <k, 32, 0>, 0, 4);']) }).plain, 1);
});

test('zeroMemsetsInGimple: a wipe behind a call to a named helper is counted as a call; an undefined helper is skipped', () => {
  const fn = gimpleFn(['  secure_zero (&key, 32);']);
  const helper = 'void secure_zero (void * p, size_t n)\n{\n  <bb 2> :\n  __builtin_memset (p_2(D), 0, n_3(D));\n  return;\n\n}\n';
  assert.deepEqual(zeroMemsetsInGimple({ encrypt_blob: fn, secure_zero: helper }),
    { defined: ['encrypt_blob', 'secure_zero'], plain: 1, pinned: 0, helperCalls: 1 });
  // inlined away (a static helper): not defined in the object, and the target no longer calls it
  assert.deepEqual(zeroMemsetsInGimple({ encrypt_blob: W_OFF, secure_zero: null }), { defined: ['encrypt_blob'], plain: 0, pinned: 0, helperCalls: 0 });
  assert.deepEqual(zeroMemsetsInGimple(null), { defined: [], plain: 0, pinned: 0, helperCalls: 0 });
});

test('gimpleControlOk: the positive control reads as exactly one plain memset, or the reading is not used', () => {
  assert.equal(gimpleControlOk(CONTROL_BODY), true);
  assert.equal(gimpleControlOk(CONTROL_BODY.replace('  __builtin_memset (&vgctl_secret, 0, 32);\n', '')), false);
  assert.equal(gimpleControlOk(CONTROL_BODY.replace('  vgctl_use (&vgctl_secret, 32);\n  vgctl_secret',
    '  __asm__ __volatile__("" :  : "g" &vgctl_secret : "memory");\n  vgctl_secret')), false);
  assert.equal(gimpleControlOk(null), false);
  assert.equal(gimpleControlOk(''), false);
});

test('carriesWipe and the stage counts: w/off against wo/off, pinned in w/on, unread kept apart', () => {
  const g = (plain, pinned = 0, helperCalls = 0) => ({ plain, pinned, helperCalls, defined: ['f'] });
  assert.equal(carriesWipe(g(1), g(0)), true);
  assert.equal(carriesWipe(g(0), g(0)), false);
  // a memset the ablated unit holds too (not the wipe) does not count as carrying it
  assert.equal(carriesWipe(g(1), g(1)), false);
  assert.equal(carriesWipe(g(0, 0, 1), g(0)), true);
  assert.equal(carriesWipe(null, g(0)), null);
  const ok = { ok: true, dryRun: true, pinnedCount: 0 };
  const row = (id, baseline, gimple) => ({ id, mode: '-flto', opt: '-O2', baseline, tracked: baseline,
    outcome: baseline === E ? 'RETAINED' : 'ALREADY_SURVIVED', dry: baseline, recDryW: ok, recDryWo: ok, gimple });
  const s = summarizeGccGroup([
    row('a', E, { wOff: g(0), woOff: g(0), wOn: g(0, 1) }),
    row('b', E, { wOff: g(1), woOff: g(1), wOn: g(1, 1) }),
    row('c', E, { wOff: g(1), woOff: g(0), wOn: g(0, 1) }),
    row('d', E, { wOff: null, woOff: g(0), wOn: g(0, 1), wOffProblem: 'the positive control read not-defined' }),
    row('e', E, null),
    row('f', S, { wOff: g(1), woOff: g(0), wOn: g(0, 1) }),
    row('g', S, { wOff: g(0), woOff: g(0), wOn: g(0, 0) }),
  ]);
  assert.deepEqual(s.stage, { eliminated: 5, wOffCarries: 1, wOffHoldsNone: 1, wOnPinned: 3, unread: 2,
    survived: 2, survivedWOffCarries: 1, survivedUnread: 0 });
});
