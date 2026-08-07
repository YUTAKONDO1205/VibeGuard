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
