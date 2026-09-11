/**
 * The LTO probe's pure parts (tools/lib/lto.mjs). Nothing here compiles or
 * links. The shapes are the ones that would let a non-LTO measurement, a stale
 * record or a vacuous control pass silently: an ELF object where bitcode was
 * wanted, a link that wrote the other backend's file name, a record from
 * another unit, a dry run that pinned, a red control with nothing to control.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  MODES, ltoCompileFlags, ltoLinkArgs, llcOptFor, objectKind, expectedOutputs, pickOutput, readRecordFields,
  ltoOutcome, LTO_OUTCOMES, gradeDryRun, SENTINEL, linkPluginState, LINK_LINE_REMOVED, linkLineStderr,
  gradeLinkPlugin, zeroMemsetsInFunctions, evenSample, summarizeGroup, insideRepo,
} from '../tools/lib/lto.mjs';

const WIPEPIN_CPP = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'llvm-repair', 'src', 'WipePin.cpp');

const E = 'WIPE_ELIMINATED';
const S = 'WIPE_SURVIVED';
const v = (verdict) => ({ verdict, control: 'PRESENT', control_via: 'oracle' });
const rec = (pinnedCount, extra = {}) => ({ ok: true, problems: [], dryRun: false, pinnedCount, module: 'x.w.c', ...extra });
const FLAGS = ['-S', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none'];

test('ltoCompileFlags: -S becomes -c, the LTO flag is appended, everything else is kept in order', () => {
  assert.deepEqual(ltoCompileFlags(FLAGS, 'full'), ['-c', '-std=gnu11', '-w', '-Wno-error=implicit-function-declaration', '-fcf-protection=none', '-flto']);
  assert.deepEqual(ltoCompileFlags(FLAGS, 'thin').slice(-1), ['-flto=thin']);
  assert.ok(!ltoCompileFlags(FLAGS, 'thin').includes('-S'));
});

test('ltoCompileFlags: refuses flags it cannot rewrite exactly', () => {
  assert.throws(() => ltoCompileFlags(FLAGS.slice(1), 'full'), /-S 0 time/);
  assert.throws(() => ltoCompileFlags(['-S', ...FLAGS], 'full'), /-S 2 time/);
  assert.throws(() => ltoCompileFlags([...FLAGS, '-flto'], 'full'), /already decide/);
  assert.throws(() => ltoCompileFlags([...FLAGS, '-fno-lto'], 'full'), /already decide/);
  assert.throws(() => ltoCompileFlags([...FLAGS, '-emit-llvm'], 'thin'), /already decide/);
  assert.throws(() => ltoCompileFlags(FLAGS, 'fat'), /unknown LTO mode/);
  assert.throws(() => ltoCompileFlags('-S', 'full'), /not an array/);
});

test('ltoLinkArgs: one object, -shared, lld, the emit switch; thin pins one backend job', () => {
  assert.deepEqual(ltoLinkArgs({ opt: '-O2', mode: 'full' }), ['-O2', '-flto', '-fuse-ld=lld', '-shared', '-Wl,--lto-emit-asm']);
  assert.deepEqual(ltoLinkArgs({ opt: '-Os', mode: 'thin' }),
    ['-Os', '-flto=thin', '-Wl,--thinlto-jobs=1', '-fuse-ld=lld', '-shared', '-Wl,--lto-emit-asm']);
  // the fallback keeps --lto-emit-asm (nothing is linked) and adds --save-temps
  assert.deepEqual(ltoLinkArgs({ opt: '-O2', mode: 'full', emit: 'llvm+llc' }).slice(-2), ['-Wl,--lto-emit-asm', '-Wl,--save-temps']);
  assert.equal(ltoLinkArgs({ opt: '-O1', mode: 'full', linkPlugin: 'p.so' }).at(-1), '-Wl,--load-pass-plugin=p.so');
  // never --lto-emit-llvm (lld 18.1.3 does not know it) and never --plugin-opt=emit-llvm
  // (measured: it writes the module before the LTO optimisation pipeline runs)
  for (const m of Object.keys(MODES)) {
    for (const e of ['asm', 'llvm+llc']) assert.ok(!ltoLinkArgs({ opt: '-O2', mode: m, emit: e }).some((a) => /emit-llvm/.test(a)));
  }
  assert.throws(() => ltoLinkArgs({ opt: '-O4', mode: 'full' }), /bad opt/);
  assert.throws(() => ltoLinkArgs({ opt: '-O2', mode: 'full', emit: 'obj' }), /unknown emit/);
});

test('llcOptFor: -Os is LTO level 2, as the driver asks of lld', () => {
  assert.deepEqual(['-O0', '-O1', '-O2', '-O3', '-Os'].map(llcOptFor), ['-O0', '-O1', '-O2', '-O3', '-O2']);
  assert.throws(() => llcOptFor('-Oz'), /bad opt/);
});

test('objectKind: only the bitcode magic is bitcode; ELF, empty and missing are named', () => {
  assert.equal(objectKind(Buffer.from([0x42, 0x43, 0xc0, 0xde, 0x35, 0x14])), 'bitcode');
  assert.equal(objectKind(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1])), 'elf');
  assert.equal(objectKind(Buffer.from('\t.text\n')), 'other');
  assert.equal(objectKind(Buffer.from([0x42, 0x43])), 'other');
  assert.equal(objectKind(Buffer.alloc(0)), 'empty');
  assert.equal(objectKind(null), 'missing');
});

test('expectedOutputs: the measured lld 18.1.3 names, which also say which backend ran', () => {
  assert.deepEqual(expectedOutputs({ mode: 'full', emit: 'asm', outBase: 'stock1.s', objStem: 'u' }),
    { expected: ['stock1.s.lto.s'], read: 'stock1.s.lto.s' });
  assert.deepEqual(expectedOutputs({ mode: 'thin', emit: 'asm', outBase: 'stock1.s', objStem: 'u' }),
    { expected: ['stock1.s.lto.u.s'], read: 'stock1.s.lto.u.s' });
  const f = expectedOutputs({ mode: 'full', emit: 'llvm+llc', outBase: 'x.s', objStem: 'u' });
  assert.equal(f.read, 'x.s.0.5.precodegen.bc');
  assert.deepEqual(f.expected, ['x.s.0.0.preopt.bc', 'x.s.0.2.internalize.bc', 'x.s.0.4.opt.bc', 'x.s.0.5.precodegen.bc',
    'x.s.lto.s', 'x.s.resolution.txt']);
  const t = expectedOutputs({ mode: 'thin', emit: 'llvm+llc', outBase: 'x.s', objStem: 'u' });
  // ThinLTO's per-module temps are named after the object, not after -o
  assert.equal(t.read, 'u.o.5.precodegen.bc');
  assert.equal(t.expected.length, 12);
  assert.ok(t.expected.includes('x.s.lto.u.s') && t.expected.includes('x.s.index.bc') && t.expected.includes('u.o.4.opt.bc'));
  assert.deepEqual(t.expected, [...t.expected].sort());
  assert.throws(() => expectedOutputs({ mode: 'full', emit: 'obj', outBase: 'a', objStem: 'u' }), /unknown emit/);
});

test('pickOutput: exactly the expected set, nothing more and nothing missing', () => {
  const full = expectedOutputs({ mode: 'full', emit: 'asm', outBase: 'stock1.s', objStem: 'u' });
  const thin = expectedOutputs({ mode: 'thin', emit: 'asm', outBase: 'stock1.s', objStem: 'u' });
  assert.deepEqual(pickOutput(['stock1.s.lto.s'], full), { ok: true, name: 'stock1.s.lto.s', problem: null });
  assert.equal(pickOutput([], full).problem, 'no output written');
  // a thin object that lld linked as full LTO writes the full-LTO name
  assert.match(pickOutput(['stock1.s.lto.s'], thin).problem, /unexpected output\(s\) stock1\.s\.lto\.s; missing stock1\.s\.lto\.u\.s/);
  assert.equal(pickOutput(['stock1.s.lto.s', 'stock1.s'], full).ok, false);
  // the fallback: every save-temps file must be there, and the read file is the pre-codegen bitcode
  const fb = expectedOutputs({ mode: 'full', emit: 'llvm+llc', outBase: 'x.s', objStem: 'u' });
  assert.deepEqual(pickOutput([...fb.expected].reverse(), fb), { ok: true, name: 'x.s.0.5.precodegen.bc', problem: null });
  assert.match(pickOutput(fb.expected.filter((n) => !n.includes('precodegen')), fb).problem, /missing x\.s\.0\.5\.precodegen\.bc/);
});

test('readRecordFields: three fields, read strictly, matched to the compile that should have written them', () => {
  const t = (o) => JSON.stringify(o);
  const good = { schemaVersion: 'wipe-pin-v1', module: 'a.w.c', dryRun: false, pinnedCount: 1, anything: 'else' };
  assert.deepEqual(readRecordFields(t(good), { dryRun: false, module: 'a.w.c' }), { ok: true, problems: [], dryRun: false, pinnedCount: 1, module: 'a.w.c' });
  assert.deepEqual(readRecordFields(null).problems, ['record-missing']);
  assert.deepEqual(readRecordFields('{').problems, ['not-json']);
  assert.deepEqual(readRecordFields('[]').problems, ['not-an-object']);
  assert.deepEqual(readRecordFields(SENTINEL).problems, ['not-json']);
  assert.deepEqual(readRecordFields(t({ ...good, pinnedCount: -1 })).problems, ['pinnedCount-not-a-count']);
  assert.deepEqual(readRecordFields(t({ ...good, pinnedCount: 1.5 })).problems, ['pinnedCount-not-a-count']);
  assert.deepEqual(readRecordFields(t({ ...good, dryRun: 'no' })).problems, ['dryRun-not-boolean']);
  assert.deepEqual(readRecordFields(t({ ...good, module: '/lab/a.w.c' })).problems, ['module-not-a-basename']);
  assert.deepEqual(readRecordFields(t(good), { module: 'a.wo.c' }).problems, ['module-mismatch']);
  assert.deepEqual(readRecordFields(t(good), { dryRun: true }).problems, ['dryRun-false-expected-true']);
  assert.deepEqual(readRecordFields(t({ ...good, dryRun: true }), { dryRun: true }).problems, ['dry-run-pinned']);
  assert.equal(readRecordFields(t({ ...good, dryRun: true, pinnedCount: 0 }), { dryRun: true, module: 'a.w.c' }).ok, true);
});

test('ltoOutcome: NOT_LTO is first, ahead of everything a non-LTO cell could otherwise read as', () => {
  const o = ltoOutcome({ notLto: ['w.off object is elf'], baseline: v(E), repaired: v(S), recW: rec(1), recWo: rec(0), controlOnW: true, controlOnWo: true });
  assert.equal(o.outcome, 'NOT_LTO');
  assert.match(o.reason, /elf/);
});

test('ltoOutcome: the repair loop precedence over the three record fields', () => {
  const base = { notLto: [], recW: rec(1), recWo: rec(0), controlOnW: true, controlOnWo: true };
  assert.equal(ltoOutcome({ ...base, baseline: v('COMPILE_ERROR'), repaired: v(S) }).outcome, 'NOT_SCORED');
  // a missing record outranks an unscorable repaired verdict
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v('NOT_OBSERVED'), recW: { ok: false, problems: ['record-missing'] } }).outcome, 'BROKEN_REPAIR');
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v(S), controlOnWo: false }).outcome, 'BROKEN_REPAIR');
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v(S), recWo: undefined }).outcome, 'BROKEN_REPAIR');
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v('NOT_OBSERVED') }).outcome, 'NOT_SCORED');
  assert.equal(ltoOutcome({ ...base, baseline: v(S), repaired: v(S) }).outcome, 'ALREADY_SURVIVED');
  assert.equal(ltoOutcome({ ...base, baseline: v(S), repaired: v(E) }).outcome, 'REGRESSED');
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v(S) }).outcome, 'RETAINED');
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v(S), recW: rec(0) }).outcome, 'SURVIVED_WITHOUT_PIN');
  const ineff = ltoOutcome({ ...base, baseline: v(E), repaired: v(E) });
  assert.equal(ineff.outcome, 'PIN_INEFFECTIVE');
  assert.match(ineff.reason, /LTO backend/);
  assert.equal(ltoOutcome({ ...base, baseline: v(E), repaired: v(E), recW: rec(0) }).outcome, 'PIN_NOT_APPLIED');
  for (const x of ['NOT_LTO', 'RETAINED', 'PIN_INEFFECTIVE']) assert.ok(LTO_OUTCOMES.includes(x));
});

test('gradeDryRun: held only when every eliminated baseline stays eliminated with valid dry-run records', () => {
  const ok = { ok: true, problems: [], pinnedCount: 0 };
  const row = (id, baseline, dry, extra = {}) => ({ id, mode: 'full', opt: '-O2', outcome: 'X', baseline, dry, recDryW: ok, recDryWo: ok, ...extra });
  const held = gradeDryRun([row('a', E, E), row('b', S, S)]);
  assert.deepEqual([held.held, held.considered, held.stillEliminated], [true, 1, 1]);
  const failed = gradeDryRun([row('a', E, E), row('b', E, S)]);
  assert.equal(failed.held, false);
  assert.match(failed.violations[0], /^b full -O2: the dry run reads WIPE_SURVIVED/);
  assert.equal(gradeDryRun([row('a', E, E, { recDryW: { ok: false, problems: ['dry-run-pinned'] } })]).held, false);
  assert.equal(gradeDryRun([row('a', E, E, { recDryWo: undefined })]).held, false);
  // vacuous: nothing to control is a failure, not a pass
  const vac = gradeDryRun([row('b', S, S), row('c', E, E, { outcome: 'NOT_LTO' })]);
  assert.equal(vac.held, false);
  assert.match(vac.violations[0], /vacuous/);
  assert.equal(gradeDryRun([]).held, false);
});

test('linkPluginState: sentinel kept, removed, a record, or something else', () => {
  assert.equal(linkPluginState({ exists: true, text: SENTINEL }), 'sentinel-kept');
  assert.equal(linkPluginState({ exists: false, text: null }), 'removed');
  assert.equal(linkPluginState({ exists: true, text: JSON.stringify({ schemaVersion: 'wipe-pin-v1', pinnedCount: 0 }) }), 'record-written');
  assert.equal(linkPluginState({ exists: true, text: JSON.stringify({ schemaVersion: 'wipe-pin-v2' }) }), 'record-written');
  assert.equal(linkPluginState({ exists: true, text: '{"schemaVersion": 3}' }), 'other-file');
  assert.equal(linkPluginState({ exists: true, text: '' }), 'other-file');
});

test('LINK_LINE_REMOVED is the line WipePin.cpp prints when its load removed a file at WPIN_OUT', () => {
  // Rebuilt from the string literals of noPipelineStartLine in the plugin's
  // source: every literal before the "removed" branch is the common prefix.
  const src = readFileSync(WIPEPIN_CPP, 'utf8');
  const m = /std::string noPipelineStartLine\(bool Removed\) \{([\s\S]*?)\n\}\n/.exec(src);
  assert.ok(m, 'noPipelineStartLine not found in WipePin.cpp');
  const lits = [...m[1].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => x[1]);
  const at = lits.findIndex((l) => l.includes('removed when the plugin loaded'));
  assert.ok(at > 0, 'the removed branch is not a literal of its own');
  assert.equal(lits.slice(0, at).join('') + lits[at], LINK_LINE_REMOVED);
  assert.match(lits[at + 1], /^there was no file at WPIN_OUT/);
});

test('linkLineStderr: the line exactly once and nothing else; empty stderr is not it', () => {
  assert.deepEqual(linkLineStderr(`${LINK_LINE_REMOVED}\n`), { count: 1, exactlyOnce: true, other: [] });
  assert.equal(linkLineStderr(`${LINK_LINE_REMOVED}\r\n`).exactlyOnce, true);
  // what the probe used to accept as the right answer
  assert.deepEqual(linkLineStderr(''), { count: 0, exactlyOnce: false, other: [] });
  assert.equal(linkLineStderr(null).exactlyOnce, false);
  const twice = linkLineStderr(`${LINK_LINE_REMOVED}\n${LINK_LINE_REMOVED}\n`);
  assert.deepEqual([twice.count, twice.exactlyOnce], [2, false]);
  const extra = linkLineStderr(`${LINK_LINE_REMOVED}\nld.lld: warning: something\n`);
  assert.deepEqual([extra.count, extra.exactlyOnce, extra.other], [1, false, ['ld.lld: warning: something']]);
  // the other form (nothing was at WPIN_OUT) is not the one (ii) expects: the sentinel is always there
  const none = LINK_LINE_REMOVED.replace('the file at WPIN_OUT was removed when the plugin loaded', 'there was no file at WPIN_OUT when the plugin loaded');
  assert.deepEqual([linkLineStderr(none).count, linkLineStderr(none).exactlyOnce], [0, false]);
  assert.equal(linkLineStderr(LINK_LINE_REMOVED.slice(0, -1)).count, 0);
});

test('gradeLinkPlugin: every (ii) link removed the sentinel, said the line once, and matched the stock assembly', () => {
  const good = { state: 'removed', asmEqualsStock: true, stderrLineCount: 1, stderrExactlyLine: true };
  const row = (id, w, wo = good, outcome = 'RETAINED') => ({ id, mode: 'full', opt: '-O2', outcome, linkPlugin: { w, wo } });
  assert.deepEqual(gradeLinkPlugin([row('a', good), row('b', good)]), { held: true, links: 4, violations: [] });
  // the pre-change plugin: silent link
  const silent = gradeLinkPlugin([row('a', { ...good, stderrLineCount: 0, stderrExactlyLine: false })]);
  assert.equal(silent.held, false);
  assert.match(silent.violations[0], /^a full -O2 w: the linker's stderr carries the link-time line 0 time\(s\), expected exactly once/);
  assert.match(gradeLinkPlugin([row('a', { ...good, stderrExactlyLine: false })]).violations[0], /among other text/);
  assert.match(gradeLinkPlugin([row('a', { ...good, state: 'record-written' })]).violations[0], /record-written, expected removed/);
  assert.match(gradeLinkPlugin([row('a', { ...good, state: 'sentinel-kept' })]).violations[0], /sentinel-kept/);
  assert.match(gradeLinkPlugin([row('a', good, { ...good, asmEqualsStock: false })]).violations[0], /^a full -O2 wo: the assembly/);
  assert.equal(gradeLinkPlugin([row('a', undefined)]).held, false);
  // NOT_LTO cells are not graded here, and a grade over nothing is a failure
  assert.deepEqual(gradeLinkPlugin([row('a', { state: 'x' }, { state: 'x' }, 'NOT_LTO'), row('b', good)]).links, 2);
  const vac = gradeLinkPlugin([row('a', good, good, 'NOT_LTO')]);
  assert.equal(vac.held, false);
  assert.match(vac.violations[0], /vacuous/);
  assert.equal(gradeLinkPlugin([]).held, false);
});

test('zeroMemsetsInFunctions: zero-fill memsets in the named functions only, split by the volatile operand', () => {
  const ll = [
    'define dso_local void @encrypt_blob(ptr noundef %0) local_unnamed_addr #0 {',
    '  %4 = alloca [32 x i8], align 16',
    '  call void @llvm.memset.p0.i64(ptr nonnull align 16 %4, i8 0, i64 32, i1 true), !dbg !7',
    '  tail call void @llvm.memset.p0.i64(ptr align 1 %0, i8 0, i64 16, i1 false)',
    '  call void @llvm.memset.p0.i64(ptr align 1 %0, i8 -86, i64 16, i1 false)',
    '  ret void',
    '}',
    'define internal fastcc void @secure_wipe(ptr %p) {',
    '  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 8, i1 false)',
    '  ret void',
    '}',
    'define dso_local void @vgctl_control() {',
    '  call void @llvm.memset.p0.i64(ptr %s, i8 0, i64 32, i1 false)',
    '}',
    'declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg)',
  ].join('\n');
  assert.deepEqual(zeroMemsetsInFunctions(ll, ['encrypt_blob']), { defined: ['encrypt_blob'], volatile: 1, plain: 1 });
  assert.deepEqual(zeroMemsetsInFunctions(ll, ['encrypt_blob', 'secure_wipe']), { defined: ['encrypt_blob', 'secure_wipe'], volatile: 1, plain: 2 });
  assert.equal(zeroMemsetsInFunctions(ll, ['absent']), null);
  assert.equal(zeroMemsetsInFunctions(null, ['encrypt_blob']), null);
});

test('evenSample: spread, ordered, and the whole list when k does not cut it', () => {
  const l = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'];
  assert.deepEqual(evenSample(l, 3), ['a', 'd', 'g']);
  assert.deepEqual(evenSample(l, 5), ['a', 'c', 'e', 'g', 'i']);
  assert.deepEqual(evenSample(l, 10), l);
  assert.deepEqual(evenSample(l, 99), l);
  assert.deepEqual(evenSample(l, undefined), l);
  assert.deepEqual(evenSample([], 3), []);
});

test('summarizeGroup: counts, the tracked-row differences by id, and the determinism pairs', () => {
  const ok = { ok: true, problems: [], pinnedCount: 0 };
  const lpOk = { state: 'removed', asmEqualsStock: true, stderrLineCount: 1, stderrExactlyLine: true };
  const mk = (id, baseline, tracked, outcome, extra = {}) => ({
    id, mode: 'thin', opt: '-O2', baseline, tracked, outcome, dry: baseline, recDryW: ok, recDryWo: ok,
    linkPlugin: { verdict: baseline, w: lpOk, wo: lpOk },
    deterministic: { 'w.off': true, 'wo.off': true, 'w.on': true, 'wo.on': true },
    dryObjectEqualsOff: { w: true, wo: true }, dryAsmEqualsOff: { w: true, wo: true },
    bitcode: { wOff: { volatile: 0, plain: 0 }, wOn: { volatile: 1, plain: 0 } },
    ...extra,
  });
  const s = summarizeGroup([
    mk('a', E, E, 'RETAINED'),
    mk('b', S, E, 'ALREADY_SURVIVED'),
    mk('c', E, S, 'RETAINED', { deterministic: { 'w.off': true, 'wo.off': false, 'w.on': true, 'wo.on': null } }),
  ]);
  assert.equal(s.cells, 3);
  assert.equal(s.baselineEliminated, 2);
  assert.equal(s.baselineSurvived, 1);
  assert.deepEqual(s.trackedDiff, [{ id: 'b', tracked: E, lto: S }, { id: 'c', tracked: S, lto: E }]);
  assert.equal(s.outcomes.RETAINED, 2);
  assert.equal(s.dry.held, true);
  assert.equal(s.linkPlugin.links, 6);
  assert.equal(s.linkPlugin.callbackRan, 6);
  assert.equal(s.linkPlugin.recordWritten, 0);
  assert.equal(s.linkPlugin.stderrExactlyLine, 6);
  assert.equal(s.linkPlugin.grade.held, true);
  assert.equal(s.linkPlugin.verdictEqualsBaseline, 3);
  // a pair that could not be compared (null) is not counted as identical
  assert.deepEqual(s.determinism, { pairs: 12, identical: 10 });
  assert.deepEqual(s.stage, { eliminated: 2, wOffBitcodeHoldsPlainMemset: 0, wOffBitcodeHoldsNone: 2, wOnBitcodeHoldsVolatile: 2, unread: 0 });
});

test('insideRepo: the lab must not be the repository or under it', () => {
  assert.equal(insideRepo('/r/repo', '/r/repo'), true);
  assert.equal(insideRepo('/r/repo/x/lab', '/r/repo'), true);
  assert.equal(insideRepo('/r/repo-lab', '/r/repo'), false);
  assert.equal(insideRepo('/r/lab', '/r/repo/'), false);
  assert.equal(insideRepo('C:\\r\\repo\\lab', 'C:\\r\\repo', '\\'), true);
});
