import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  expandResponseFiles, expectedArtifacts, normalise, splitDriverArgs, tokenizeResponseFile,
} from '../lib/cmdline.mjs';
import { makeScratch } from './helpers.mjs';

test('response file tokenising follows the quoting rules clang uses', () => {
  assert.deepEqual(tokenizeResponseFile('-O2 -o app\nhello.c\n'), ['-O2', '-o', 'app', 'hello.c']);
  assert.deepEqual(tokenizeResponseFile('-I"a b" -Dx=\'y z\''), ['-Ia b', '-Dx=y z']);
  assert.deepEqual(tokenizeResponseFile('a\\ b'), ['a b']);
  assert.deepEqual(tokenizeResponseFile('   \n\t '), []);
  // An empty quoted string is a token, not nothing.
  assert.deepEqual(tokenizeResponseFile('-D ""'), ['-D', '']);
});

test('response files expand recursively, and a cycle is reported rather than hung on', () => {
  const dir = makeScratch('rsp');
  writeFileSync(join(dir, 'a.rsp'), '-O2 @b.rsp\n');
  writeFileSync(join(dir, 'b.rsp'), '-o app hello.c\n');
  const ok = expandResponseFiles(['@a.rsp'], { cwd: dir });
  assert.deepEqual(ok.argv, ['-O2', '-o', 'app', 'hello.c']);
  assert.equal(ok.notes.length, 0);
  assert.equal(ok.expanded.length, 2);

  writeFileSync(join(dir, 'loop.rsp'), '@loop.rsp\n');
  const cyc = expandResponseFiles(['@loop.rsp'], { cwd: dir });
  assert.equal(cyc.notes.length, 1);
  assert.equal(cyc.notes[0].kind, 'cycle');
});

test('an unreadable response file is a note, never a silent empty expansion', () => {
  const dir = makeScratch('rsp-missing');
  const r = expandResponseFiles(['@nope.rsp', 'hello.c'], { cwd: dir });
  assert.equal(r.notes.length, 1);
  assert.equal(r.notes[0].kind, 'unreadable');
  // The token survives, so the record shows what was asked for.
  assert.ok(r.argv.includes('@nope.rsp'));
});

test('-Xclang values are consumed, not mistaken for source files', () => {
  const n = normalise(['-Xclang', 'hello.c', 'real.c', '-o', 'app']);
  assert.deepEqual(n.sources, ['real.c']);
  assert.deepEqual(n.cc1Tokens, ['hello.c']);
  assert.equal(n.output, 'app');
});

test('a flag hidden behind -Xclang is still in the space the policy is matched against', () => {
  const n = normalise(['-Xclang', '-load', '-Xclang', 'libEvil.so', 'a.c']);
  assert.ok(n.cc1Tokens.includes('-load'));
  assert.ok(n.matchSpace.includes('-load'));
  assert.deepEqual(n.plugins.legacyLoad, ['libEvil.so']);
  assert.deepEqual(n.sources, ['a.c']);
});

test('a trailing -Xclang with no value is recorded as unpaired rather than ignored', () => {
  const n = normalise(['a.c', '-Xclang']);
  assert.equal(n.unpairedXclang.length, 1);
});

test('-o is found in both the separate and the joined spelling', () => {
  assert.equal(normalise(['a.c', '-o', 'x']).output, 'x');
  assert.equal(normalise(['a.c', '-ox']).output, 'x');
  assert.equal(normalise(['a.c', '--output=x']).output, 'x');
  assert.equal(normalise(['a.c', '--output', 'x']).output, 'x');
  // -O2 is not -o 2.
  assert.equal(normalise(['a.c', '-O2']).output, null);
});

test('values of separate-value flags never become sources', () => {
  const n = normalise(['-I', 'inc', '-include', 'pre.h', '-D', 'N=1', '-MF', 'dep.d', 'a.c']);
  assert.deepEqual(n.sources, ['a.c']);
  assert.deepEqual(n.linkInputs, []);
});

test('link inputs are classified apart from sources', () => {
  const n = normalise(['a.c', 'b.o', 'libx.a', '-o', 'app']);
  assert.deepEqual(n.sources, ['a.c']);
  assert.deepEqual(n.linkInputs, ['b.o', 'libx.a']);
  assert.equal(n.action, 'link');
});

test('-Wl, and -Xlinker tokens reach the match space', () => {
  const n = normalise(['a.c', '-Wl,-z,norelro', '-Xlinker', '--no-warn-execstack']);
  assert.ok(n.linkerTokens.includes('-z'));
  assert.ok(n.linkerTokens.includes('norelro'));
  assert.ok(n.matchSpace.includes('--no-warn-execstack'));
});

test('the outputs clang will write are derived the way clang derives them', () => {
  assert.deepEqual(expectedArtifacts({ action: 'link', output: null, sources: ['a.c'] }), ['a.out']);
  assert.deepEqual(expectedArtifacts({ action: 'compile', output: null, sources: ['x/a.c', 'b.c'] }), ['a.o', 'b.o']);
  assert.deepEqual(expectedArtifacts({ action: 'assemble', output: null, sources: ['a.c'] }), ['a.s']);
  assert.deepEqual(expectedArtifacts({ action: 'link', output: 'app', sources: ['a.c'] }), ['app']);
});

test('the last -O on the line is the effective one, and a bare -O is -O1', () => {
  assert.deepEqual(normalise(['a.c', '-O0', '-O3']).optLevels, ['-O0', '-O3']);
  assert.deepEqual(normalise(['a.c', '-O']).optLevels, ['-O1']);
});

test('driver flags are split off and never reach the compiler argv', () => {
  const { own, compilerArgv } = splitDriverArgs(['--policy', 'p.json', 'a.c', '--vg-verbose', '-O2']);
  assert.equal(own.policy, 'p.json');
  assert.equal(own.verbose, true);
  assert.deepEqual(compilerArgv, ['a.c', '-O2']);
});

test('splitDriverArgs preserves the caller spelling of everything else', () => {
  const argv = ['@build.rsp', '-Iinc', '-o', 'app'];
  const { compilerArgv } = splitDriverArgs(argv);
  assert.deepEqual(compilerArgv, argv);
});

// ── the configuration axes fallback.mjs matches a measured row against ──────
//
// Each of these is recovered from a token that is on the line. None of them is
// a convention about what an absent flag probably meant — the one convention
// in this area ("no -target is the envelope's host") lives in fallback.mjs,
// where it can be stated, and this file leaves `target` null instead.

test('-target is read in both spellings, and the last one wins', () => {
  assert.equal(normalise(['a.c', '-target', 'arm-none-eabi']).target, 'arm-none-eabi');
  assert.equal(normalise(['a.c', '--target=arm-none-eabi']).target, 'arm-none-eabi');

  // clang reads this option with getLastArgValue and both spellings are the
  // same option to it, so the last occurrence wins whichever way it is written.
  // Mixed spellings included, because a build system that appends a triple to
  // CFLAGS rarely appends it in the spelling the base flags used.
  assert.equal(normalise(['a.c', '-target', 'x', '--target=y']).target, 'y');
  assert.equal(normalise(['a.c', '--target=y', '-target', 'x']).target, 'x');
  assert.equal(normalise(['a.c', '-target', 'x', '-target', 'y']).target, 'y');
  assert.equal(normalise(['a.c', '--target=x', '--target=y']).target, 'y');
  assert.equal(normalise(['a.c', '-target', 'x', '--target=y']).targetForm, 'joined');

  // Not stated is null, not a triple this file invented.
  assert.equal(normalise(['a.c', '-O2']).target, null);
  assert.equal(normalise(['a.c', '-O2']).targetForm, null);

  // The value of -target is still not a source file.
  assert.deepEqual(normalise(['-target', 'arm-none-eabi', 'a.c']).sources, ['a.c']);
});

test('NDEBUG is tracked through -D and -U in argv order, in both spellings', () => {
  assert.equal(normalise(['a.c']).ndebug, false);
  assert.equal(normalise(['a.c', '-DNDEBUG']).ndebug, true);
  assert.equal(normalise(['a.c', '-D', 'NDEBUG']).ndebug, true);
  // `-DNDEBUG=0` still DEFINES NDEBUG; assert.h asks whether it is defined.
  assert.equal(normalise(['a.c', '-DNDEBUG=0']).ndebug, true);

  // Last wins, both ways round, both spellings.
  assert.equal(normalise(['a.c', '-DNDEBUG', '-UNDEBUG']).ndebug, false);
  assert.equal(normalise(['a.c', '-UNDEBUG', '-DNDEBUG']).ndebug, true);
  assert.equal(normalise(['a.c', '-D', 'NDEBUG', '-U', 'NDEBUG']).ndebug, false);
  assert.equal(normalise(['a.c', '-DNDEBUG', '-U', 'NDEBUG']).ndebug, false);

  // Another macro that merely starts with the letters is not this one.
  assert.equal(normalise(['a.c', '-DNDEBUGGING']).ndebug, false);
  assert.equal(normalise(['a.c', '-DNDEBUG', '-UNDEBUGGING']).ndebug, true);

  // and none of this turned a macro name into a source file.
  assert.deepEqual(normalise(['-D', 'NDEBUG', 'a.c']).sources, ['a.c']);
});

test('-ffreestanding and -fhosted are read, last one winning', () => {
  assert.equal(normalise(['a.c']).freestanding, false);
  assert.equal(normalise(['a.c', '-ffreestanding']).freestanding, true);
  assert.equal(normalise(['a.c', '-fhosted']).freestanding, false);
  // A line ending -fhosted compiles hosted however it began.
  assert.equal(normalise(['a.c', '-ffreestanding', '-fhosted']).freestanding, false);
  assert.equal(normalise(['a.c', '-fhosted', '-ffreestanding']).freestanding, true);
});

test('LTO tokens are collected rather than resolved to a mode', () => {
  // `-flto=thin` does not say whether the envelope's thin-prelink or
  // thin-backend cell is the one to compare against — the two differ by when
  // the observation was taken, which is nowhere on this line. So the tokens are
  // reported and fallback.mjs drops the axis; only an EMPTY list is a reading.
  assert.deepEqual(normalise(['a.c', '-O2']).ltoTokens, []);
  assert.deepEqual(normalise(['a.c', '-flto']).ltoTokens, ['-flto']);
  assert.deepEqual(normalise(['a.c', '-flto=thin']).ltoTokens, ['-flto=thin']);
  assert.deepEqual(normalise(['a.c', '-fno-lto']).ltoTokens, ['-fno-lto']);
  assert.deepEqual(normalise(['a.c', '-flto=full', '-flto-jobs=4']).ltoTokens, ['-flto=full', '-flto-jobs=4']);
  // Deliberately wider than the three documented spellings: an unrecognised
  // -flto* token makes the axis unreadable, which is the safe direction.
  assert.deepEqual(normalise(['a.c', '-flto-partition=none']).ltoTokens, ['-flto-partition=none']);
  // and they are still in the space the flag policy is matched against.
  assert.ok(normalise(['a.c', '-flto=thin']).matchSpace.includes('-flto=thin'));
});

test('the new axis fields did not disturb the tokens that were already read', () => {
  const n = normalise(['-c', 'a.c', '-O2', '-DNDEBUG', '-target', 'arm-none-eabi', '-ffreestanding', '-flto=thin', '-o', 'a.o']);
  assert.deepEqual(n.sources, ['a.c']);
  assert.deepEqual(n.linkInputs, []);
  assert.equal(n.output, 'a.o');
  assert.equal(n.action, 'compile');
  assert.deepEqual(n.optLevels, ['-O2']);
  assert.deepEqual(n.expectedArtifacts, ['a.o']);
});

test('the long aliases of -D and -U are read, because clang honours them', () => {
  // Measured on clang-18 with an `#ifdef NDEBUG` probe rather than assumed:
  // `--define-macro` really does define. Reading only `-D` reported
  // `ndebug: false` for a line that compiles with NDEBUG defined.
  assert.equal(normalise(['a.c', '--define-macro=NDEBUG']).ndebug, true);
  assert.equal(normalise(['a.c', '--define-macro', 'NDEBUG']).ndebug, true);
  // The dangerous direction: this build has NDEBUG UNDEFINED, and before the
  // alias was read it was reported as defined.
  assert.equal(normalise(['a.c', '-DNDEBUG', '--undefine-macro=NDEBUG']).ndebug, false);
  assert.equal(normalise(['a.c', '-DNDEBUG', '--undefine-macro', 'NDEBUG']).ndebug, false);
  // Order still decides, both spellings sharing one variable.
  assert.equal(normalise(['a.c', '--undefine-macro=NDEBUG', '-DNDEBUG']).ndebug, true);
});

test('a macro that arrives through an opaque channel makes the axis unreadable, not false', () => {
  // `-Wp,` and `-Xpreprocessor` hand tokens to the preprocessor, and `-Xclang`
  // to cc1. This file can see the text but cannot order it against the plain
  // -D/-U around it, so the honest answer is "not read" — the same answer -flto
  // already gets. `false` would be a statement about the build nobody made.
  assert.equal(normalise(['a.c', '-Wp,-DNDEBUG']).ndebug, null);
  assert.equal(normalise(['a.c', '-Xpreprocessor', '-DNDEBUG']).ndebug, null);
  assert.equal(normalise(['a.c', '-Xclang', '-DNDEBUG']).ndebug, null);
  assert.equal(normalise(['a.c', '-Xclang', '-ffreestanding']).freestanding, null);
  // A line with none of them still reads as a plain boolean.
  assert.equal(normalise(['a.c', '-O2']).ndebug, false);
  assert.equal(normalise(['a.c', '-O2']).freestanding, false);
});

test('-m32 changes the triple, so target stops being readable', () => {
  // No `-target` on the line normally means the envelope's `host`. With `-m32`
  // it does not: the build is a different architecture from the one measured.
  assert.equal(normalise(['a.c', '-m32']).targetOpaque, true);
  assert.equal(normalise(['a.c', '-m64']).targetOpaque, true);
  assert.equal(normalise(['a.c', '-O2']).targetOpaque, false);
});
