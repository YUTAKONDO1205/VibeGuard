import test from 'node:test';
import assert from 'node:assert/strict';

import { parseLinkCommand, screenLinkCommand, MAP_OPTIONS } from '../lib/cmdline.mjs';

const screen = (argv) => screenLinkCommand(parseLinkCommand(argv));

test('a plain link is read: program, linker, output, positional inputs', () => {
  const p = parseLinkCommand(['clang-18', '-fuse-ld=lld', '-O2', 'main.o', 'helper.o', '-o', 'app']);
  assert.equal(p.program, 'clang-18');
  assert.equal(p.linker, 'lld');
  assert.equal(p.output, 'app');
  assert.deepEqual(p.positionalInputs, ['main.o', 'helper.o']);
  assert.equal(p.direct, false);
});

test('-oapp is the same as -o app', () => {
  assert.equal(parseLinkCommand(['clang-18', 'main.o', '-oapp']).output, 'app');
});

test('a linker invoked directly is recognised, and its options are not behind -Wl,', () => {
  const p = parseLinkCommand(['ld.lld-18', 'main.o', '-o', 'app']);
  assert.equal(p.direct, true);
  assert.equal(p.linker, 'ld.lld-18');
});

// THE CENTRAL REFUSAL. Each spelling below reaches the same linker behaviour,
// and a check that knows only `-Map` lets the other four through — after which
// the caller, not the wrapper, decides what the verdict is computed from.
test('every spelling that names the map is refused', () => {
  const spellings = [
    ['clang-18', 'main.o', '-Wl,-Map=theirs.txt', '-o', 'app'],
    ['clang-18', 'main.o', '-Wl,-Map,theirs.txt', '-o', 'app'],
    ['clang-18', 'main.o', '-Wl,--Map=theirs.txt', '-o', 'app'],
    ['clang-18', 'main.o', '-Wl,--print-map', '-o', 'app'],
    ['clang-18', 'main.o', '-Wl,-M', '-o', 'app'],
    ['ld.lld-18', 'main.o', '-Map=theirs.txt', '-o', 'app'],
    ['ld.lld-18', 'main.o', '--print-map', '-o', 'app'],
  ];
  for (const argv of spellings) {
    const s = screen(argv);
    assert.equal(s.refusals.length > 0, true, `not refused: ${argv.join(' ')}`);
    assert.match(s.refusals[0].why, /produced by the wrapper/);
  }
});

test('an ordinary link is not refused — the negative direction of the same check', () => {
  const s = screen(['clang-18', '-fuse-ld=lld', '-O2', '-Wl,-z,relro', 'main.o', '-o', 'app']);
  assert.deepEqual(s.refusals, []);
  assert.deepEqual(s.opaque, []);
});

test('a flag that merely starts with -M is not refused', () => {
  // `-MD` is a dependency-file flag and has nothing to do with the map. A
  // prefix test would refuse it and make the wrapper unusable on real builds.
  const s = screen(['clang-18', '-MD', '-MF', 'dep.d', 'main.o', '-o', 'app']);
  assert.deepEqual(s.refusals, []);
});

test('the refused set is stated, not derived from a prefix', () => {
  assert.ok(MAP_OPTIONS.includes('-Map'));
  assert.ok(MAP_OPTIONS.includes('--print-map'));
  assert.ok(MAP_OPTIONS.includes('-M'));
  assert.equal(MAP_OPTIONS.includes('-MD'), false);
});

test('a response file makes the command line unobservable rather than clean', () => {
  const s = screen(['clang-18', '@args.rsp', '-o', 'app']);
  assert.deepEqual(s.refusals, []);
  assert.equal(s.opaque.length, 1);
  assert.match(s.opaque[0].why, /not fully observed/);
});

test('every spelling of a linker script is found', () => {
  const cases = [
    [['clang-18', '-Wl,-T,extra.ld', 'main.o'], 'extra.ld'],
    [['clang-18', '-Wl,-Textra.ld', 'main.o'], 'extra.ld'],
    [['clang-18', '-Wl,--script=extra.ld', 'main.o'], 'extra.ld'],
    [['clang-18', '-Wl,--script,extra.ld', 'main.o'], 'extra.ld'],
    [['ld.lld-18', '-T', 'extra.ld', 'main.o'], 'extra.ld'],
    [['clang-18', 'main.o', 'layout.lds'], 'layout.lds'],
  ];
  for (const [argv, want] of cases) {
    const p = parseLinkCommand(argv);
    assert.ok(p.linkerScripts.includes(want), `${argv.join(' ')} -> ${JSON.stringify(p.linkerScripts)}`);
  }
});

test('a link with no script reports none — a detector that always fires detects nothing', () => {
  assert.deepEqual(parseLinkCommand(['clang-18', '-fuse-ld=lld', 'main.o', '-o', 'app']).linkerScripts, []);
});

// -Ttext=0x1000 places a section. It is spelled like -T and is not a script,
// and reporting it as one is a false positive at `high` on any embedded build.
test('the section-address options are not mistaken for scripts', () => {
  for (const opt of ['-Wl,-Ttext=0x1000', '-Wl,-Tdata=0x2000', '-Wl,-Tbss=0x3000', '-Wl,-Ttext-segment=0x0']) {
    assert.deepEqual(parseLinkCommand(['clang-18', opt, 'main.o']).linkerScripts, [], opt);
  }
});

test('linker options are collected, comma-separated groups included', () => {
  const p = parseLinkCommand(['clang-18', '-Wl,-z,now,-z,relro', '-Wl,--as-needed', 'main.o']);
  assert.deepEqual(p.linkerOptions, ['-z', 'now', '-z', 'relro', '--as-needed']);
});

test('an already-requested trace is noticed rather than duplicated blindly', () => {
  assert.equal(parseLinkCommand(['clang-18', '-Wl,-t', 'main.o']).traceAlreadyRequested, true);
  assert.equal(parseLinkCommand(['clang-18', 'main.o']).traceAlreadyRequested, false);
});
