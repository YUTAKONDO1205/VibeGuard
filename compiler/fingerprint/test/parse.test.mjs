// The parts of the parser that are easy to get wrong and expensive to get
// wrong: the implicit entry-block name, the value/label namespace split, and
// comment stripping inside string literals.

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseModule } from '../lib/parse.mjs';
import { tokenize, stripComment, labelOperandIndices } from '../lib/tokens.mjs';
import { load } from './helpers.mjs';

test('a `;` inside a string literal does not start a comment', () => {
  assert.equal(stripComment('@s = constant [2 x i8] c";\\00"'), '@s = constant [2 x i8] c";\\00"');
  assert.equal(stripComment('  br label %x  ; preds = %y'), '  br label %x  ');
});

test('a block label written as `; preds = ...` decoration is not an instruction', () => {
  const mod = load('block-b.ll.txt');
  const f = mod.byName.get('@f');
  assert.equal(f.blocks.length, 4);
});

test('the entry block, which LLVM never prints a header for, gets its implicit number', () => {
  const mod = load('block-b.ll.txt');
  const f = mod.byName.get('@f');
  // %0 is the parameter, so the counter is at 1 when the entry block is named.
  assert.equal(f.blocks[0].label, '1');
  assert.equal(f.blocks[0].implicit, true);
  assert.deepEqual(f.blocks.map((b) => b.label), ['1', '2', '3', '4']);
});

test('every successor named by a terminator resolves to a block', () => {
  const mod = load('block-b.ll.txt');
  const f = mod.byName.get('@f');
  const labels = new Set(f.blocks.map((b) => b.label));
  for (const b of f.blocks) {
    const term = b.insts[b.insts.length - 1];
    for (const i of labelOperandIndices(term.tokens)) {
      assert.equal(labels.has(term.tokens[i].slice(1)), true, `${term.tokens[i]} dangles`);
    }
  }
});

test('a phi names blocks in its second position and values in its first', () => {
  const t = tokenize('%r = phi i32 [ %a, %bb1 ], [ 22, %bb2 ]');
  // The instruction tokens start after `%r =`.
  const idx = labelOperandIndices(t.slice(2));
  const named = idx.map((i) => t.slice(2)[i]);
  assert.deepEqual(named, ['%bb1', '%bb2']);
});

test('a `label` keyword marks the token after it, and nothing else', () => {
  const t = tokenize('br i1 %c, label %t, label %f');
  assert.deepEqual(labelOperandIndices(t).map((i) => t[i]), ['%t', '%f']);
});

test('a switch names every one of its destinations', () => {
  const t = tokenize('switch i32 %v, label %def [ i32 0, label %a i32 1, label %b ]');
  assert.deepEqual(labelOperandIndices(t).map((i) => t[i]), ['%def', '%a', '%b']);
});

test('declared-only symbols are recorded and are not functions', () => {
  const mod = load('sym-a.ll.txt');
  assert.equal(mod.byName.has('@helper'), false);
  assert.equal(mod.declares.has('@helper'), true);
  assert.deepEqual(mod.functions.map((f) => f.name), ['@f']);
});

test('a module with no definitions parses to no functions rather than throwing', () => {
  const mod = parseModule('declare void @a()\ntarget triple = "x86_64-pc-linux-gnu"\n');
  assert.deepEqual(mod.functions, []);
  assert.equal(mod.declares.has('@a'), true);
});

test('parameters keep their types and their names', () => {
  const mod = load('sym-a.ll.txt');
  const f = mod.byName.get('@f');
  assert.deepEqual(f.params.map((p) => p.type), ['ptr', 'i32']);
  assert.deepEqual(f.params.map((p) => p.name), ['%p', '%x']);
});

test('a named struct type is not mistaken for a value', () => {
  // `%struct.s` in a type position must survive canonicalisation unrenamed;
  // renaming it would collide with a real value of the same canonical index.
  const mod = parseModule([
    '%struct.s = type { i32, i32 }',
    'define i32 @f() {',
    'entry:',
    '  %p = alloca %struct.s, align 4',
    '  %q = getelementptr %struct.s, ptr %p, i32 0, i32 1',
    '  %v = load i32, ptr %q, align 4',
    '  ret i32 %v',
    '}',
  ].join('\n'));
  const f = mod.byName.get('@f');
  assert.equal(f.blocks[0].insts.length, 4);
});
