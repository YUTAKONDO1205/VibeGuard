/**
 * The vendor a run drives, the plugin flag and record component that follow
 * from it, the per-compiler data file names, the _FORTIFY_SOURCE reading and the
 * full-run check on a tracked rows file. No compiler.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { vendorOf, vendorConfig, VENDORS, dataFileNames, fullRunCheck, fortifyFromDefines, LEGACY_CC } from '../lib/vendor.mjs';
import { COMPONENTS } from '../lib/pin-record.mjs';
import { absolutePathHits } from '../lib/provenance.mjs';

test('vendorOf: every spelling the runner used to refuse as gcc is gcc now', () => {
  for (const cc of ['gcc', 'gcc-13', 'g++', 'g++-13', 'gcc-13.3', 'x86_64-linux-gnu-gcc-13', 'x86_64-linux-gnu-g++-13', '/usr/bin/gcc-13']) {
    assert.equal(vendorOf(cc), 'gcc', cc);
  }
});

test('vendorOf: clang spellings are clang, from the basename only', () => {
  for (const cc of ['clang', 'clang-18', 'clang++', 'clang++-18', 'x86_64-linux-gnu-clang-18', '/usr/lib/llvm-18/bin/clang', 'C:\\llvm\\bin\\clang-18']) {
    assert.equal(vendorOf(cc), 'clang', cc);
  }
  // a directory named after one vendor does not decide the other's basename
  assert.equal(vendorOf('/opt/gcc-13/bin/clang-18'), 'clang');
  assert.equal(vendorOf('/opt/clang-18/bin/gcc-13'), 'gcc');
});

test('vendorOf: a basename that names neither is null, never a guess', () => {
  for (const cc of ['cc', 'c99', 'icx', 'gcc-ar-13', 'clang-tidy-18', 'clang-18.sh', 'mygcc', '', null, undefined, 3]) {
    assert.equal(vendorOf(cc), null, String(cc));
  }
});

test('vendorConfig: the flag and the component per vendor; the flag carries the plugin path and nothing else', () => {
  assert.deepEqual(vendorConfig('clang', '/x/libWipePin.so'), { vendor: 'clang', component: 'WipePin', pluginArg: '-fpass-plugin=/x/libWipePin.so' });
  assert.deepEqual(vendorConfig('gcc', '/x/libWipePinGcc.so'), { vendor: 'gcc', component: 'WipePinGcc', pluginArg: '-fplugin=/x/libWipePinGcc.so' });
  assert.throws(() => vendorConfig('icx', '/x/y.so'), /unknown vendor/);
  // every component the reader knows is one vendor's, and no vendor names one it does not
  assert.deepEqual(Object.values(VENDORS).map((v) => v.component).sort(), [...COMPONENTS].sort());
});

test('dataFileNames: clang-18 keeps the tracked names; every other compiler gets its own pair', () => {
  assert.equal(LEGACY_CC, 'clang-18');
  assert.deepEqual(dataFileNames('clang-18'), { rows: 'r2-repair-rows.json', results: 'r2-repair-results.txt' });
  assert.deepEqual(dataFileNames('gcc-13'), { rows: 'r2-repair-rows-gcc-13.json', results: 'r2-repair-results-gcc-13.txt' });
  // a second clang does not overwrite clang-18's file
  assert.deepEqual(dataFileNames('clang-19'), { rows: 'r2-repair-rows-clang-19.json', results: 'r2-repair-results-clang-19.txt' });
  assert.deepEqual(dataFileNames('g++-13'), { rows: 'r2-repair-rows-g++-13.json', results: 'r2-repair-results-g++-13.txt' });
  for (const bad of ['../gcc-13', 'a/b', '', null]) assert.throws(() => dataFileNames(bad), /not a compiler basename/);
  for (const cc of ['clang-18', 'gcc-13']) {
    for (const n of Object.values(dataFileNames(cc))) assert.deepEqual(absolutePathHits(n), []);
  }
});

test('fortifyFromDefines: the value as spelled, empty for a bare definition, null when undefined', () => {
  const gccO2 = '#define __STDC__ 1\n#define _FORTIFY_SOURCE 3\n#define __OPTIMIZE__ 1\n';
  assert.equal(fortifyFromDefines(gccO2), '3');
  assert.equal(fortifyFromDefines('#define _FORTIFY_SOURCE 2\r\n'), '2');
  assert.equal(fortifyFromDefines('#define _FORTIFY_SOURCE \n'), '');
  assert.equal(fortifyFromDefines('#define _FORTIFY_SOURCE\n'), '');
  assert.equal(fortifyFromDefines('#define __STDC__ 1\n#define __clang__ 1\n'), null);
  // a longer name is not the macro
  assert.equal(fortifyFromDefines('#define _FORTIFY_SOURCE_X 3\n#define __USE_FORTIFY_LEVEL 3\n'), null);
  assert.equal(fortifyFromDefines(null), null);
});

const ALL = ['-O0', '-O1', '-O2', '-O3', '-Os'];
const row = (id, opt, extra = {}) => ({ id, opt, kind: 'erasure', cc: 'gcc-13', scope: 'functions', dryRun: false, targetSuffix: null, ...extra });
const fullRows = (ids, noneIds = []) => [
  ...ids.flatMap((id) => ALL.map((o) => row(id, o))),
  ...noneIds.flatMap((id) => ALL.map((o) => row(id, o, { kind: 'none' }))),
  { id: 'cfg', opt: '-O2', kind: 'configguard', cc: 'gcc-13', scope: 'module', dryRun: false },
];

test('fullRunCheck: every corpus erasure id at every level, one compiler, functions scope, no red control', () => {
  const r = fullRunCheck(fullRows(['a', 'b'], ['n']), { cc: 'gcc-13', allOpts: ALL, erasureIds: ['a', 'b', 'n'] });
  assert.deepEqual(r, { full: true, why: [] });
});

test('fullRunCheck: each way a file can fall short is named', () => {
  const ids = ['a', 'b'];
  const opts = { cc: 'gcc-13', allOpts: ALL, erasureIds: ids };
  const missing = fullRows(['a', 'b']).filter((x) => !(x.id === 'b' && x.opt === '-Os'));
  assert.deepEqual(fullRunCheck(missing, opts), { full: false, why: ['1 (file, level) cell(s) of the corpus have no row'] });
  const subset = fullRows(['a']);
  assert.match(fullRunCheck(subset, opts).why.join(), /5 \(file, level\) cell/);
  const dry = fullRows(ids).map((x) => (x.kind === 'erasure' ? { ...x, dryRun: true } : x));
  assert.deepEqual(fullRunCheck(dry, opts).why, ['a dry-run row']);
  const suffix = fullRows(ids).map((x, i) => (i === 0 ? { ...x, targetSuffix: '__absent' } : x));
  assert.deepEqual(fullRunCheck(suffix, opts).why, ['a row with a target suffix']);
  const moduleScope = fullRows(ids).map((x, i) => (i === 3 ? { ...x, scope: 'module' } : x));
  assert.deepEqual(fullRunCheck(moduleScope, opts).why, ['a row not in functions scope']);
  const clangRows = fullRows(ids).map((x) => ({ ...x, cc: 'clang-18' }));
  assert.equal(fullRunCheck(clangRows, opts).full, false);
  assert.match(fullRunCheck(clangRows, opts).why[0], /rows for clang-18, not only gcc-13/);
  assert.deepEqual(fullRunCheck({}, opts), { full: false, why: ['not a list of rows'] });
  assert.equal(fullRunCheck([], opts).full, false);
});
