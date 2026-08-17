/**
 * Unit tests for the battery's independent leg.
 *
 * These are the three structural readings that decide what an effect count cannot:
 * the stack a body reserves, whether an unaccounted write to %rsp makes that number
 * meaningless, and whether a call stayed indirect. They are pure functions over
 * lines of assembly, so no compiler is required and nothing here is a measurement --
 * which is the point. The frame witness was UNSOUND as first written and nothing in
 * the tree would have caught it, because the only exercise it ever got was the
 * listings that happened to be in the lab.
 *
 * The soundness argument being tested: `stackFrameBytes` is an upper bound on what a
 * body reserves EXACTLY WHEN `unrecognisedStackWrites` is empty, and `frameVerdict`
 * may only conclude "ruled-out" under that condition. Every test below is either
 * that condition holding or that condition failing.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  stackFrameBytes,
  unrecognisedStackWrites,
  frameVerdict,
  detectIndirectCallLike,
  RED_ZONE_BYTES,
} from '../scripts/witness-asm.mjs';

const lines = (...l) => l;

test('the accounted-for forms are totalled: max sub, plus 8 per push', () => {
  assert.equal(stackFrameBytes(lines('  pushq %rbx', '  subq $208, %rsp')), 216);
  // The larger sub wins rather than the two being summed: two adjustments in one
  // body are usually a frame and a call-argument area, and adding them would
  // overstate the reservation. Overstating is the safe direction -- it costs a
  // reading rather than producing a wrong one -- but it is still not what is meant.
  assert.equal(stackFrameBytes(lines('  subq $32, %rsp', '  subq $208, %rsp')), 208);
  assert.equal(stackFrameBytes(lines('  pushq %rbx', '  pushq %r14', '  pushq %r15')), 24);
  assert.equal(stackFrameBytes(lines('  retq')), 0);
  // A comment must not change the reading, and clang appends one to most lines.
  assert.equal(stackFrameBytes(lines('  subq $208, %rsp   # frame')), 208);
});

test('%rsp as a SOURCE is not a write, and is not flagged', () => {
  // `movq %rsp, %rbx` is how a body takes the address of its own frame. Flagging it
  // would make almost every listing undecidable, which is a witness that declines
  // on everything -- indistinguishable from having no witness.
  assert.deepEqual(unrecognisedStackWrites(lines('  movq %rsp, %rbx')), []);
  assert.deepEqual(unrecognisedStackWrites(lines('  leaq 16(%rsp), %rbx')), []);
});

test('the epilogue forms are accounted for: they give space back', () => {
  assert.deepEqual(
    unrecognisedStackWrites(lines('  subq $208, %rsp', '  addq $208, %rsp', '  popq %rbx')),
    [],
  );
});

test('an unaccounted write to %rsp is flagged, one entry is enough', () => {
  // The alignment idiom. It makes the reservation depend on the incoming value of
  // %rsp, which cannot be totalled from the body alone.
  assert.deepEqual(unrecognisedStackWrites(lines('  andq $-32, %rsp')), ['andq $-32, %rsp']);
  // A register operand: the amount is not in the instruction at all.
  assert.deepEqual(unrecognisedStackWrites(lines('  subq %rax, %rsp')), ['subq %rax, %rsp']);
  // A lea or a move into %rsp sets it outright.
  assert.deepEqual(unrecognisedStackWrites(lines('  leaq -64(%rsp), %rsp')), ['leaq -64(%rsp), %rsp']);
  assert.deepEqual(unrecognisedStackWrites(lines('  movq %rbp, %rsp')), ['movq %rbp, %rsp']);
});

test('frameVerdict rules an object out only when the frame is an upper bound', () => {
  const big = RED_ZONE_BYTES + 71;            // 199, the size cal-wipe-napp uses
  assert.equal(frameVerdict(0, big, []).verdict, 'ruled-out');
  assert.equal(frameVerdict(big - 1, big, []).verdict, 'ruled-out');
  assert.equal(frameVerdict(big, big, []).verdict, 'present-in-frame');
  assert.equal(frameVerdict(big + 8, big, []).verdict, 'present-in-frame');
});

test('an unaccounted write makes the verdict undecidable, whatever the number says', () => {
  // The soundness repair, and the case that was wrong. With an unaccounted write the
  // real reservation may exceed the total, so a small reading is NOT evidence that
  // anything left memory -- and the original code concluded exactly that.
  const v = frameVerdict(0, 199, ['andq $-32, %rsp']);
  assert.equal(v.verdict, 'undecidable');
  assert.match(v.reason, /not bounded from here/);
  assert.deepEqual(v.unrecognisedStackWrites, ['andq $-32, %rsp']);
  // It is checked BEFORE the size threshold, because an unaccounted write makes the
  // number meaningless and the threshold question moot.
  assert.equal(frameVerdict(0, 8, ['subq %rax, %rsp']).verdict, 'undecidable');
});

test('an object at or below the red zone is declined, never ruled out', () => {
  // A leaf function may use 128 bytes below %rsp with no adjustment at all, so a
  // frame of 0 is perfectly consistent with such an object being in memory.
  for (const size of [1, 64, RED_ZONE_BYTES]) {
    const v = frameVerdict(0, size, []);
    assert.equal(v.verdict, 'undecidable', `${size} bytes must be declined, not ruled out`);
    assert.match(v.reason, /red zone/);
  }
  assert.equal(frameVerdict(0, RED_ZONE_BYTES + 1, []).verdict, 'ruled-out');
});

test('a non-integer or absent size is declined rather than guessed at', () => {
  for (const bad of [undefined, null, 'big', 12.5, NaN]) {
    assert.equal(frameVerdict(0, bad, []).verdict, 'undecidable');
  }
});

test('indirect transfers are recognised, and direct ones are not mistaken for them', () => {
  // The two indirect probes write a direct call in C and rely on the compiler keeping
  // it indirect. If a listing showed a DIRECT call the specimen would have been
  // devirtualised and the probe would not be probing what it claims.
  assert.equal(detectIndirectCallLike(lines('  callq *%rax')).length, 1);
  assert.equal(detectIndirectCallLike(lines('  callq *cw_wiper(%rip)')).length, 1);
  assert.equal(detectIndirectCallLike(lines('  jmpq *%rdx')).length, 1);
  assert.equal(detectIndirectCallLike(lines('  callq memset@PLT')).length, 0);
  assert.equal(detectIndirectCallLike(lines('  jmp cb_deny@PLT')).length, 0);
  const both = detectIndirectCallLike(lines('  callq memset@PLT', '  callq *%rax'));
  assert.equal(both.length, 1);
  assert.equal(both[0].mnemonic, 'callq');
});

test('the red zone is the x86-64 value and is not quietly a different number', () => {
  // cal-wipe-napp's 199 bytes and cal-wipe-zeroinit's 181 were both chosen against
  // this constant. If it moved, those choices would stop meaning what their
  // expectations say they mean.
  assert.equal(RED_ZONE_BYTES, 128);
});
