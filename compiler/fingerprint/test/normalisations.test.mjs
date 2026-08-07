// The seven normalisations, each checked three ways.
//
//   PERTURBATION  a change that must not move the fingerprint
//   ISOLATION     the same pair with only that normalisation disabled, which
//                 must now move -- otherwise the line above proves nothing,
//                 because `return 0` passes it
//   SEMANTIC      a real difference in the same shape, which must move it
//
// The middle one is the load-bearing one. Every test in this file that asserts
// two fingerprints are EQUAL has a partner immediately below it asserting they
// stop being equal when the responsible step is switched off.

import test from 'node:test';
import assert from 'node:assert/strict';

import { fp, stepsWithout } from './helpers.mjs';
import { SEVEN, HYGIENE, undecorateSymbol } from '../lib/normalise.mjs';

// ── 1. SSA value numbers ────────────────────────────────────────────────────

test('1 ssa-values PERTURBATION: renaming every local leaves the fingerprint alone', () => {
  assert.equal(fp('ssa-a.ll.txt'), fp('ssa-b.ll.txt'));
});

test('1 ssa-values ISOLATION: with the step off, the rename moves it', () => {
  const off = stepsWithout('ssa-values');
  assert.notEqual(fp('ssa-a.ll.txt', '@f', off), fp('ssa-b.ll.txt', '@f', off));
});

test('1 ssa-values SEMANTIC: rewiring one use moves it', () => {
  assert.notEqual(fp('ssa-a.ll.txt'), fp('ssa-sem.ll.txt'));
});

// ── 2. Block names ──────────────────────────────────────────────────────────

test('2 block-names PERTURBATION: renaming labels, including to the implicit numeric form, leaves it alone', () => {
  assert.equal(fp('block-a.ll.txt'), fp('block-b.ll.txt'));
});

test('2 block-names ISOLATION: with the step off, the rename moves it', () => {
  const off = stepsWithout('block-names');
  assert.notEqual(fp('block-a.ll.txt', '@f', off), fp('block-b.ll.txt', '@f', off));
});

test('2 block-names SEMANTIC: swapping the two arms of a conditional moves it', () => {
  assert.notEqual(fp('block-a.ll.txt'), fp('block-sem.ll.txt'));
});

// ── 3. Instruction order ────────────────────────────────────────────────────

test('3 instruction-order PERTURBATION: swapping two independent pure instructions leaves it alone', () => {
  assert.equal(fp('order-a.ll.txt'), fp('order-b.ll.txt'));
});

test('3 instruction-order ISOLATION: with the step off, the swap moves it', () => {
  const off = stepsWithout('instruction-order');
  assert.notEqual(fp('order-a.ll.txt', '@f', off), fp('order-b.ll.txt', '@f', off));
});

test('3 instruction-order SEMANTIC: swapping two stores to the same address moves it', () => {
  assert.notEqual(fp('order-sem-a.ll.txt'), fp('order-sem-b.ll.txt'));
});

// ── 4. Inlined calls ────────────────────────────────────────────────────────

test('4 inlined-calls PERTURBATION: the out-of-line and the inlined form agree', () => {
  assert.equal(fp('inline-a.ll.txt'), fp('inline-b.ll.txt'));
});

test('4 inlined-calls PERTURBATION: the same holds when the callee has several blocks', () => {
  assert.equal(fp('inline-multiblock-a.ll.txt'), fp('inline-multiblock-b.ll.txt'));
});

test('4 inlined-calls ISOLATION: with the step off, the two forms disagree', () => {
  const off = stepsWithout('inlined-calls');
  assert.notEqual(fp('inline-a.ll.txt', '@f', off), fp('inline-b.ll.txt', '@f', off));
  assert.notEqual(fp('inline-multiblock-a.ll.txt', '@f', off), fp('inline-multiblock-b.ll.txt', '@f', off));
});

test('4 inlined-calls SEMANTIC: a caller written identically, calling a callee whose body differs, moves it', () => {
  assert.notEqual(fp('inline-a.ll.txt'), fp('inline-sem.ll.txt'));
});

test('4 inlined-calls: and with the step off those two collapse, which is why the step is not decorative', () => {
  // The callers are character-for-character identical. Only the expansion can
  // tell them apart, so this is the measurement of what the step buys.
  const off = stepsWithout('inlined-calls');
  assert.equal(fp('inline-a.ll.txt', '@f', off), fp('inline-sem.ll.txt', '@f', off));
});

// ── 5. Commutative operand order ────────────────────────────────────────────

test('5 commutative-operands PERTURBATION: flipping add operands, and slt into sgt, leaves it alone', () => {
  assert.equal(fp('comm-a.ll.txt'), fp('comm-b.ll.txt'));
});

test('5 commutative-operands ISOLATION: with the step off, the flip moves it', () => {
  const off = stepsWithout('commutative-operands');
  assert.notEqual(fp('comm-a.ll.txt', '@f', off), fp('comm-b.ll.txt', '@f', off));
});

test('5 commutative-operands SEMANTIC: sub is not commutative, so swapping its operands moves it', () => {
  assert.notEqual(fp('comm-sem-sub.ll.txt'), fp('comm-sem-sub-swapped.ll.txt'));
});

test('5 commutative-operands SEMANTIC: changing the predicate without swapping operands moves it', () => {
  assert.notEqual(fp('comm-sem-pred-base.ll.txt'), fp('comm-sem-pred.ll.txt'));
});

// ── 6. Debug paths ──────────────────────────────────────────────────────────

test('6 debug-paths PERTURBATION: a different source path, different line numbers and a dropped value intrinsic leave it alone', () => {
  assert.equal(fp('dbg-a.ll.txt', '@sink'), fp('dbg-b.ll.txt', '@sink'));
});

test('6 debug-paths ISOLATION: with the step off, the debug difference moves it', () => {
  const off = stepsWithout('debug-paths');
  assert.notEqual(fp('dbg-a.ll.txt', '@sink', off), fp('dbg-b.ll.txt', '@sink', off));
});

test('6 debug-paths SEMANTIC: identical debug information, one store operand changed, moves it', () => {
  // Catches a stripper that deletes from the first `!` to end of line: it would
  // have deleted the store's operands too and this pair would collapse.
  assert.notEqual(fp('dbg-a.ll.txt', '@sink'), fp('dbg-sem.ll.txt', '@sink'));
});

// ── 7. Symbol decoration ────────────────────────────────────────────────────

test('7 symbol-decoration PERTURBATION: a uniquing suffix on the callee leaves it alone', () => {
  assert.equal(fp('sym-a.ll.txt'), fp('sym-b.ll.txt'));
});

test('7 symbol-decoration ISOLATION: with the step off, the suffix moves it', () => {
  const off = stepsWithout('symbol-decoration');
  assert.notEqual(fp('sym-a.ll.txt', '@f', off), fp('sym-b.ll.txt', '@f', off));
});

test('7 symbol-decoration SEMANTIC: a different callee moves it', () => {
  assert.notEqual(fp('sym-a.ll.txt'), fp('sym-sem-other.ll.txt'));
});

test('7 symbol-decoration SEMANTIC: @helper2 is not a clone of @helper', () => {
  assert.notEqual(fp('sym-a.ll.txt'), fp('sym-sem-digit.ll.txt'));
});

test('7 symbol-decoration: an intrinsic name is never undecorated', () => {
  // `@llvm.memset.p0.i64` ends in a dotted suffix that is not digits, but the
  // rule is stated positively rather than relying on that: never touch `llvm.`.
  assert.equal(undecorateSymbol('@llvm.memset.p0.i64'), '@llvm.memset.p0.i64');
  assert.equal(undecorateSymbol('@llvm.lifetime.start.p0'), '@llvm.lifetime.start.p0');
});

test('7 symbol-decoration: the suffixes it does and does not strip', () => {
  assert.equal(undecorateSymbol('@wipe.llvm.918273645'), '@wipe');
  assert.equal(undecorateSymbol('@wipe.1'), '@wipe');
  assert.equal(undecorateSymbol('@wipe.constprop.0'), '@wipe');
  assert.equal(undecorateSymbol('@wipe.isra.0'), '@wipe');
  assert.equal(undecorateSymbol('@wipe.cold'), '@wipe');
  assert.equal(undecorateSymbol('@wipe2'), '@wipe2');
  assert.equal(undecorateSymbol('@wipe_1'), '@wipe_1');
  assert.equal(undecorateSymbol('@wipe'), '@wipe');
  // A name that is nothing but decoration keeps its own spelling rather than
  // becoming the empty symbol.
  assert.equal(undecorateSymbol('@.1'), '@.1');
});

// ── the set itself ──────────────────────────────────────────────────────────

test('the seven are the seven, and the hygiene steps are named separately', () => {
  assert.deepEqual([...SEVEN].sort(), [
    'block-names', 'commutative-operands', 'debug-paths', 'inlined-calls',
    'instruction-order', 'ssa-values', 'symbol-decoration',
  ]);
  assert.equal(SEVEN.length, 7);
  assert.deepEqual([...HYGIENE].sort(), ['lexical', 'metadata-hints']);
  for (const h of HYGIENE) assert.equal(SEVEN.includes(h), false);
});

test('every one of the seven is load-bearing on at least one tracked pair', () => {
  // A step that can be switched off with no effect anywhere is not implemented.
  // This walks all seven rather than trusting that the tests above cover them.
  const pairs = {
    'ssa-values': [['ssa-a.ll.txt', '@f'], ['ssa-b.ll.txt', '@f']],
    'block-names': [['block-a.ll.txt', '@f'], ['block-b.ll.txt', '@f']],
    'instruction-order': [['order-a.ll.txt', '@f'], ['order-b.ll.txt', '@f']],
    'inlined-calls': [['inline-a.ll.txt', '@f'], ['inline-b.ll.txt', '@f']],
    'commutative-operands': [['comm-a.ll.txt', '@f'], ['comm-b.ll.txt', '@f']],
    'debug-paths': [['dbg-a.ll.txt', '@sink'], ['dbg-b.ll.txt', '@sink']],
    'symbol-decoration': [['sym-a.ll.txt', '@f'], ['sym-b.ll.txt', '@f']],
  };
  assert.deepEqual(Object.keys(pairs).sort(), [...SEVEN].sort());
  for (const step of SEVEN) {
    const [[fa, na], [fb, nb]] = pairs[step];
    assert.equal(fp(fa, na), fp(fb, nb), `${step}: the pair should agree with all steps on`);
    const off = stepsWithout(step);
    assert.notEqual(fp(fa, na, off), fp(fb, nb, off), `${step}: switching it off changed nothing, so it does nothing`);
  }
});
