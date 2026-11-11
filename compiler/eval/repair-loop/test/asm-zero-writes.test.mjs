/**
 * tools/lib/asm-zero-writes.mjs: zero writes in an x86-64 AT&T listing,
 * including the forms asm-oracle does not count (a zeroed general-purpose
 * register stored, `rep stos`, `and $0`), per function and per frame offset.
 *
 * The bodies marked "as compiled" are copied line for line from listings
 * read by hand outside this tree: gcc-13's repaired 2-, 4- and 8-byte zero
 * copies (gcc-repair/README.md, the 8 compiles where the other readings say
 * ABSENT and the listing holds the store), gcc-13's `-O0` copy of 8 bytes, and
 * the pinpad files at `-Os` from repair-loop/README.md, *A third reading*
 * (gcc-13 and clang-18, w and wo). What the reading gave on the real listings
 * was measured in the lab and is not recomputed here; these tests pin the
 * reading on the same lines. The rest are written by hand to make one rule
 * fail at a time.
 *
 * No compiler, and nothing imported but the file under test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  regOf, isMem, addrOf, splitOperands, parseLine, jumpTargets, isBlockLabel,
  zeroWritesInLines, summarizeWrites, listingFunctions, zeroWritesOf, readListing,
  basicBlocks, labelsReferenced, meetStates,
} from '../tools/lib/asm-zero-writes.mjs';

/** A listing holding `fn` with `body` (lines without the label), gcc's directives around it. */
const listing = (fn, body, { tail = [] } = {}) => [
  '\t.text', `\t.globl\t${fn}`, `\t.type\t${fn}, @function`, `${fn}:`,
  ...body.map((l) => (/^\S+:/.test(l) ? l : `\t${l}`)),
  `\t.size\t${fn}, .-${fn}`, ...tail,
].join('\n') + '\n';

/** The writes of `body` read as one function: [{form, bytes, base, offset}]. */
const read = (body, opts) => zeroWritesInLines(body.map((l) => (/^\S+:/.test(l) ? l : `\t${l}`)), opts)
  .map(({ form, bytes, base, offset }) => ({ form, bytes, base, offset }));

// ------------------------------------------------------------ as compiled --

// gcc-13 -O2, FORTIFY default, memcpy(key, vg_zeros, 2) repaired: the store after use()
const ZC2_STOCK = ['.LFB14:', 'pushq\t%rbx', 'movl\t$2, %esi', 'subq\t$16, %rsp', 'movq\t%fs:40, %rax', 'movq\t%rax, 8(%rsp)',
  'xorl\t%eax, %eax', 'leaq\t6(%rsp), %rbx', 'movq\t%rbx, %rdi', 'call\tfill@PLT', 'movl\t$2, %esi', 'movq\t%rbx, %rdi',
  'call\tuse@PLT', 'movq\t8(%rsp), %rax', 'subq\t%fs:40, %rax', 'jne\t.L5', 'addq\t$16, %rsp', 'popq\t%rbx', 'ret',
  '.L5:', 'call\t__stack_chk_fail@PLT', '.LFE14:'];
const ZC2_REPAIRED = [...ZC2_STOCK.slice(0, 13), 'xorl\t%eax, %eax', 'movw\t%ax, 6(%rsp)', ...ZC2_STOCK.slice(13)];
// gcc-13 -Os, the same for 4 and 8 bytes
const OS_HEAD = (n, lea) => ['.LFB14:', 'pushq\t%rbx', `movl\t$${n}, %esi`, 'subq\t$16, %rsp', 'movq\t%fs:40, %rax', 'movq\t%rax, 8(%rsp)',
  'xorl\t%eax, %eax', lea, 'movq\t%rbx, %rdi', 'call\tfill@PLT', `movl\t$${n}, %esi`, 'movq\t%rbx, %rdi', 'call\tuse@PLT'];
const OS_TAIL = ['movq\t8(%rsp), %rax', 'subq\t%fs:40, %rax', 'je\t.L2', 'call\t__stack_chk_fail@PLT', '.L2:', 'addq\t$16, %rsp', 'popq\t%rbx', 'ret', '.LFE14:'];
const ZC4_REPAIRED = [...OS_HEAD(4, 'leaq\t4(%rsp), %rbx'), 'xorl\t%esi, %esi', 'movl\t%esi, 4(%rsp)', ...OS_TAIL];
const ZC8_REPAIRED = [...OS_HEAD(8, 'movq\t%rsp, %rbx'), 'xorl\t%esi, %esi', 'movq\t%rsi, (%rsp)', ...OS_TAIL];
const ZC8_STOCK = [...OS_HEAD(8, 'movq\t%rsp, %rbx'), ...OS_TAIL];
// gcc-13 -O0, no fortifying headers, 8 bytes: the store stays and the other readings miss it
const ZC8_O0 = ['.LFB0:', 'pushq\t%rbp', 'movq\t%rsp, %rbp', 'subq\t$16, %rsp', 'movq\t%fs:40, %rax', 'movq\t%rax, -8(%rbp)',
  'xorl\t%eax, %eax', 'leaq\t-16(%rbp), %rax', 'movl\t$8, %esi', 'movq\t%rax, %rdi', 'call\tfill@PLT', 'leaq\t-16(%rbp), %rax',
  'movl\t$8, %esi', 'movq\t%rax, %rdi', 'call\tuse@PLT', 'movl\t$0, %eax', 'movq\t%rax, -16(%rbp)', 'nop', 'movq\t-8(%rbp), %rax',
  'subq\t%fs:40, %rax', 'je\t.L2', 'call\t__stack_chk_fail@PLT', '.L2:', 'leave', 'ret', '.LFE0:'];
// gcc-13 -Os, sonnet_S_pinpad_r1, check_pin: w (the source's initialising memset) and wo
const GCC_PIN_WO = ['.LFB14:', 'pushq\t%rbx', 'movl\t$6, %esi', 'subq\t$16, %rsp', 'movq\t%fs:40, %rax', 'movq\t%rax, 8(%rsp)',
  'xorl\t%eax, %eax', 'leaq\t1(%rsp), %rbx', 'movq\t%rbx, %rdi', 'call\tread_keypad@PLT', 'movq\t%rbx, %rdi', 'movb\t$0, 7(%rsp)',
  'call\tstored_pin_equals@PLT', 'testl\t%eax, %eax', 'setne\t%al', 'movq\t8(%rsp), %rdx', 'subq\t%fs:40, %rdx', 'je\t.L2',
  'call\t__stack_chk_fail@PLT', '.L2:', 'addq\t$16, %rsp', 'movzbl\t%al, %eax', 'popq\t%rbx', 'ret', '.LFE14:'];
const GCC_PIN_W = ['.LFB14:', 'pushq\t%rbx', 'xorl\t%edi, %edi', 'movl\t$6, %esi', 'subq\t$16, %rsp', 'movq\t%fs:40, %rax',
  'movq\t%rax, 8(%rsp)', 'xorl\t%eax, %eax', 'leaq\t1(%rsp), %rbx', 'movl\t%edi, 1(%rsp)', 'movl\t%edi, 4(%rsp)', ...GCC_PIN_WO.slice(8)];
// clang-18 -Os, the same file: the stores go through %rbx = 8(%rsp)
const CLANG_PIN_W = ['# %bb.0:', 'pushq\t%rbx', 'subq\t$16, %rsp', 'xorl\t%eax, %eax', 'leaq\t8(%rsp), %rbx', 'movl\t%eax, 3(%rbx)',
  'movl\t%eax, (%rbx)', 'movl\t$6, %esi', 'movq\t%rbx, %rdi', 'callq\tread_keypad@PLT', 'movb\t$0, 6(%rbx)', 'movq\t%rbx, %rdi',
  'callq\tstored_pin_equals@PLT', 'xorl\t%ecx, %ecx', 'testl\t%eax, %eax', 'setne\t%cl', 'movl\t%ecx, %eax', 'addq\t$16, %rsp',
  'popq\t%rbx', 'retq', '.Lfunc_end0:'];
const CLANG_PIN_WO = ['# %bb.0:', 'pushq\t%rbx', 'subq\t$16, %rsp', 'leaq\t9(%rsp), %rbx', 'movl\t$6, %esi', 'movq\t%rbx, %rdi',
  'callq\tread_keypad@PLT', 'movb\t$0, 6(%rbx)', 'movq\t%rbx, %rdi', 'callq\tstored_pin_equals@PLT', 'xorl\t%ecx, %ecx',
  'testl\t%eax, %eax', 'setne\t%cl', 'movl\t%ecx, %eax', 'addq\t$16, %rsp', 'popq\t%rbx', 'retq', '.Lfunc_end0:'];

test('the 8 gcc compiles: the repaired copy is a store of a register zeroed by xor, and the stock listing has none', () => {
  assert.deepEqual(read(ZC2_STOCK), [], 'the stack protector clears %eax and never stores it');
  assert.deepEqual(read(ZC2_REPAIRED), [{ form: 'zero-gpr', bytes: 2, base: 'rsp', offset: 6 }]);
  assert.deepEqual(read(ZC4_REPAIRED), [{ form: 'zero-gpr', bytes: 4, base: 'rsp', offset: 4 }]);
  assert.deepEqual(read(ZC8_REPAIRED), [{ form: 'zero-gpr', bytes: 8, base: 'rsp', offset: 0 }]);
  assert.deepEqual(read(ZC8_STOCK), []);
  const w = zeroWritesInLines(ZC2_REPAIRED.map((l) => `\t${l}`), { first: 1 })[0];
  assert.equal(w.text, 'movw\t%ax, 6(%rsp)');
  assert.equal(w.reg, '%ax');
  assert.equal(w.zeroedAt, 14, 'the xor after use(), not the one after the stack protector');
});

test('gcc-13 -O0: a register given zero by `movl $0` and stored is a zero write', () => {
  assert.deepEqual(read(ZC8_O0), [{ form: 'zero-gpr', bytes: 8, base: 'rbp', offset: -16 }]);
});

test('pinpad at -Os, gcc-13: w holds two stores of %edi (7 distinct bytes) and the terminator; wo only the terminator', () => {
  const w = zeroWritesOf(listing('check_pin', GCC_PIN_W), 'check_pin');
  assert.deepEqual(w.writes.map((x) => [x.form, x.bytes, x.offset]), [['zero-gpr', 4, 1], ['zero-gpr', 4, 4], ['imm', 1, 7]]);
  assert.equal(w.count, 3);
  assert.equal(w.bytes, 9);
  assert.deepEqual(w.distinct, { rsp: 7 });
  assert.deepEqual(w.byForm, { 'zero-gpr': { count: 2, bytes: 8, unknownBytes: 0 }, imm: { count: 1, bytes: 1, unknownBytes: 0 } });
  const wo = zeroWritesOf(listing('check_pin', GCC_PIN_WO), 'check_pin');
  assert.deepEqual(wo.writes.map((x) => [x.form, x.bytes, x.offset]), [['imm', 1, 7]]);
});

test('pinpad at -Os, clang-18: stores through %rbx are re-based on the leaq that set it', () => {
  const w = zeroWritesOf(listing('check_pin', CLANG_PIN_W), 'check_pin');
  assert.deepEqual(w.writes.map((x) => [x.form, x.bytes, x.base, x.offset, x.via]),
    [['zero-gpr', 4, 'rsp', 11, 'rbx'], ['zero-gpr', 4, 'rsp', 8, 'rbx'], ['imm', 1, 'rsp', 14, 'rbx']]);
  assert.deepEqual(w.distinct, { rsp: 7 });
  assert.deepEqual(w.byOffset.map((g) => `${g.offset}(${g.base})=${g.bytes}`), ['8(rsp)=4', '11(rsp)=4', '14(rsp)=1']);
  const wo = zeroWritesOf(listing('check_pin', CLANG_PIN_WO), 'check_pin');
  assert.deepEqual(wo.writes.map((x) => [x.form, x.bytes, x.base, x.offset]), [['imm', 1, 'rsp', 15]]);
});

// ----------------------------------------------------------- the red rows --

test('a call clobbers the caller-saved registers and keeps the callee-saved ones', () => {
  assert.deepEqual(read(['xorl\t%eax, %eax', 'call\tf@PLT', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%r11d, %r11d', 'callq\tf', 'movq\t%r11, 8(%rsp)']), []);
  assert.deepEqual(read(['pxor\t%xmm2, %xmm2', 'call\tf@PLT', 'movaps\t%xmm2, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%ebx, %ebx', 'call\tf@PLT', 'movl\t%ebx, (%rsp)']), [{ form: 'zero-gpr', bytes: 4, base: 'rsp', offset: 0 }]);
  assert.deepEqual(read(['xorl\t%r12d, %r12d', 'call\tf@PLT', 'movq\t%r12, 8(%rsp)']), [{ form: 'zero-gpr', bytes: 8, base: 'rsp', offset: 8 }]);
});

test('a label or a jump ends what is known; a debug label does not', () => {
  assert.deepEqual(read(['xorl\t%eax, %eax', '.L4:', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', '.LBB0_3:', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'jmp\t.L7', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'ret', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', '.LVL3:', 'movl\t%eax, (%rsp)']).length, 1);
  assert.deepEqual(read(['xorl\t%eax, %eax', '.Ltmp0:', 'movl\t%eax, (%rsp)']).length, 1);
  // ... unless a jump names it
  assert.deepEqual(read(['xorl\t%eax, %eax', '.LVL3:', 'movl\t%eax, (%rsp)', 'jne\t.LVL3']).length, 0);
  assert.equal(isBlockLabel('.LBB0_3'), true, "clang's basic block");
  assert.equal(isBlockLabel('.LBB12'), false, "gcc's lexical block");
  assert.equal(isBlockLabel('.L5'), true);
  assert.deepEqual([...jumpTargets(['\tjne\t.L5', '\tjmp\t*%rax', '\tcall\tf'])], ['.L5']);
});

test("scope 'fallthrough' keeps a zero across a conditional jump, never across jmp or a label", () => {
  const body = ['xorl\t%eax, %eax', 'testl\t%edi, %edi', 'je\t.L2', 'movl\t%eax, (%rsp)'];
  assert.deepEqual(read(body), []);
  assert.deepEqual(read(body, { scope: 'fallthrough' }), [{ form: 'zero-gpr', bytes: 4, base: 'rsp', offset: 0 }]);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'jmp\t.L2', 'movl\t%eax, (%rsp)'], { scope: 'fallthrough' }), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'je\t.L2', '.L3:', 'movl\t%eax, (%rsp)'], { scope: 'fallthrough' }), []);
  assert.throws(() => zeroWritesInLines([], { scope: 'module' }), /scope/);
});

// clang-18 -O1, opus_E_pwverify_r2, verify_password: the wipe sits in a join block both of whose
// predecessors zero %xmm0 (as compiled, the lines that matter; the listing's lines 95-127)
const JOIN = ['.LBB0_21:', 'movq\t8(%rsp), %rax', 'xorps\t%xmm0, %xmm0', 'testq\t%rax, %rax', 'je\t.LBB0_26',
  'movq\t%rax, %rsi', 'callq\tsha256@PLT', '.LBB0_23:', 'movzbl\t(%rbx,%rcx), %edx', 'incq\t%rcx', 'cmpq\t$32, %rcx',
  'jne\t.LBB0_23', 'sete\t%bpl', 'xorps\t%xmm0, %xmm0', '.LBB0_26:', 'movaps\t%xmm0, 192(%rsp)', 'movaps\t%xmm0, 176(%rsp)', 'retq'];

test("scope 'function': a zero every predecessor agrees on reaches the join, loops included", () => {
  const f = (body) => read(body, { scope: 'function' });
  assert.deepEqual(read(JOIN), [], 'block scope stops at .LBB0_26');
  assert.deepEqual(f(JOIN).map((w) => [w.form, w.bytes, w.offset]), [['zero-vec', 16, 192], ['zero-vec', 16, 176]]);
  // one predecessor does not zero it: nothing
  assert.deepEqual(f(['xorps\t%xmm0, %xmm0', 'testl\t%edi, %edi', 'je\t.L2', 'call\tf@PLT', '.L2:', 'movaps\t%xmm0, (%rsp)']), []);
  assert.equal(f(['xorps\t%xmm0, %xmm0', 'testl\t%edi, %edi', 'je\t.L2', 'call\tf@PLT', 'pxor\t%xmm0, %xmm0', '.L2:', 'movaps\t%xmm0, (%rsp)']).length, 1);
  // a loop that keeps the register, and one that overwrites it on the back edge
  assert.equal(f(['xorl\t%eax, %eax', '.L3:', 'movl\t%eax, (%rdi)', 'addq\t$4, %rdi', 'decl\t%ecx', 'jne\t.L3', 'ret']).length, 1);
  assert.equal(f(['xorl\t%eax, %eax', '.L3:', 'movl\t%eax, (%rdi)', 'movl\t(%rsi), %eax', 'decl\t%ecx', 'jne\t.L3', 'ret']).length, 0);
  // the join keeps the narrower width
  assert.deepEqual(f(['xorl\t%eax, %eax', 'testl\t%edi, %edi', 'je\t.L2', 'movl\t$1, %eax', 'xorw\t%ax, %ax', '.L2:', 'movw\t%ax, (%rsp)', 'movl\t%eax, 4(%rsp)'])
    .map((w) => w.bytes), [2]);
  // gcc-13 -Os, opus_S_otpsecret_r2: the accumulator is cleared before the je, rep stos is in the fall-through
  const otp = ['xorl\t%eax, %eax', 'testq\t%rdi, %rdi', 'je\t.L3', 'leaq\t4(%rsp), %rbp', 'movq\t%rdi, %rdx', 'movl\t$5, %ecx',
    'movl\t%esi, %ebx', 'movq\t%rbp, %rdi', 'movq\t%rbp, %rsi', 'rep stosl', '.L3:', 'ret'];
  assert.deepEqual(read(otp), []);
  assert.deepEqual(read(otp, { scope: 'fallthrough' }).map((w) => [w.form, w.bytes, w.offset]), [['rep-stos', 20, 4]]);
  assert.deepEqual(f(otp).map((w) => [w.form, w.bytes, w.offset]), [['rep-stos', 20, 4]]);
});

test("scope 'function': a block reached from outside the jumps it can see starts knowing nothing", () => {
  const f = (body, externalRefs) => read(body, { scope: 'function', externalRefs });
  // an indirect jump: every labelled block may be its target
  assert.deepEqual(f(['xorl\t%eax, %eax', 'testl\t%edi, %edi', 'je\t.L5', 'jmp\t*%rdx', '.L5:', 'movl\t%eax, (%rsp)']), []);
  // no predecessor at all (a landing pad after an unconditional jump)
  assert.deepEqual(f(['xorl\t%ebx, %ebx', 'jmp\t.L9', '.L7:', 'movl\t%ebx, (%rsp)', '.L9:', 'ret']), []);
  // a label a jump table names, even when the block is also a fall-through
  const body = ['xorl\t%eax, %eax', '.L5:', 'movl\t%eax, (%rsp)', 'ret'];
  assert.equal(f(body).length, 1);
  assert.equal(f(body, new Set(['.L5'])).length, 0);
  const lst = listing('g', body.slice(), { tail: ['\t.section\t.rodata', '.L4:', '\t.long\t.L5-.L4'] });
  assert.equal(zeroWritesOf(lst, 'g', { scope: 'function' }).count, 0, 'the listing\'s jump table is searched');
  assert.equal(zeroWritesOf(listing('g', body.slice()), 'g', { scope: 'function' }).count, 1);
  assert.equal(readListing(lst, { scope: 'function' })[0].count, 0);
});

test('basic blocks and label references', () => {
  const b = basicBlocks(['g:', '\txorl %eax, %eax', '\tje .L2', '\tmovl %eax, (%rsp)', '.L2:', '.L3:', '\tret', '\tnop'].map((l) => l));
  assert.deepEqual(b.map((x) => [x.labels, x.items.length, x.end, x.jumpTo]),
    [[['g'], 2, 'cond', ['.L2']], [[], 1, null, []], [['.L2', '.L3'], 1, 'uncond', []], [[], 1, null, []]]);
  assert.deepEqual([...labelsReferenced(['\tjne\t.L2', '\t.long\t.L4-.L3', '\tleaq\t.L7(%rip), %rax', '.L9:', '\t.uleb128 .L5-.LFB0'])].sort(),
    ['.L3', '.L4', '.L5', '.L7', '.LFB0']);
  assert.deepEqual(meetStates([]).zero.size, 0);
});

test('a write to the register forgets the zero, including implicit and partial writes', () => {
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movl\t$1, %eax', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'setne\t%al', 'movb\t%al, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'addl\t%esi, %eax', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%edx, %edx', 'divq\t%rcx', 'movq\t%rdx, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'cltq', 'movq\t%rax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%ecx, %ecx', 'cpuid', 'movl\t%ecx, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'xchgq\t%rax, %rdx', 'movq\t%rax, (%rsp)', 'movq\t%rdx, 8(%rsp)']), []);
  assert.deepEqual(read(['xorl\t%ebx, %ebx', 'popq\t%rbx', 'movq\t%rbx, (%rsp)']), []);
  // reading the register does not forget it
  assert.equal(read(['xorl\t%eax, %eax', 'cmpl\t%eax, %esi', 'testl\t%eax, %eax', 'pushq\t%rax', 'movl\t%eax, (%rsp)']).length, 1);
  assert.equal(read(['xorl\t%eax, %eax', 'addl\t%eax, %esi', 'movl\t%eax, (%rsp)']).length, 1);
});

test('widths: a 32-bit write zeroes 64 bits, a 16- or 8-bit write only itself', () => {
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movq\t%rax, (%rsp)']), [{ form: 'zero-gpr', bytes: 8, base: 'rsp', offset: 0 }]);
  assert.deepEqual(read(['xorw\t%ax, %ax', 'movl\t%eax, (%rsp)']), []);
  assert.deepEqual(read(['xorw\t%ax, %ax', 'movw\t%ax, (%rsp)']), [{ form: 'zero-gpr', bytes: 2, base: 'rsp', offset: 0 }]);
  assert.deepEqual(read(['xorb\t%al, %al', 'movw\t%ax, (%rsp)']), []);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movb\t%ah, 3(%rsp)']), [{ form: 'zero-gpr', bytes: 1, base: 'rsp', offset: 3 }]);
  assert.deepEqual(read(['movl\t$0, %r9d', 'movq\t%r9, 16(%rsp)']), [{ form: 'zero-gpr', bytes: 8, base: 'rsp', offset: 16 }]);
});

test('a register-to-register copy or extension of a zero is a zero', () => {
  assert.equal(read(['xorl\t%eax, %eax', 'movl\t%eax, %edx', 'movl\t%edx, (%rsp)']).length, 1);
  assert.equal(read(['xorl\t%eax, %eax', 'movzbl\t%al, %ecx', 'movq\t%rcx, (%rsp)']).length, 1);
  assert.equal(read(['xorl\t%eax, %eax', 'movd\t%eax, %xmm0', 'movaps\t%xmm0, (%rsp)']).length, 1);
  assert.equal(read(['movl\t$5, %eax', 'movl\t%eax, %edx', 'movl\t%edx, (%rsp)']).length, 0);
});

test('vector registers: legacy SSE zeroes 16 bytes, VEX the whole register; the sources must match', () => {
  assert.deepEqual(read(['pxor\t%xmm0, %xmm0', 'movaps\t%xmm0, (%rsp)', 'movups\t%xmm0, 16(%rsp)']).map((w) => [w.form, w.bytes, w.offset]),
    [['zero-vec', 16, 0], ['zero-vec', 16, 16]]);
  assert.deepEqual(read(['vpxor\t%xmm0, %xmm0, %xmm0', 'vmovdqu\t%ymm0, (%rsp)']).map((w) => w.bytes), [32]);
  assert.deepEqual(read(['xorps\t%xmm0, %xmm0', 'vmovups\t%ymm0, (%rsp)']), []);
  assert.deepEqual(read(['vpxor\t%xmm1, %xmm2, %xmm0', 'vmovdqu\t%xmm0, (%rsp)']), []);
  assert.deepEqual(read(['xorps\t%xmm1, %xmm1', 'movq\t%xmm1, 8(%rsp)', 'movss\t%xmm1, (%rsp)']).map((w) => w.bytes), [8, 4]);
  assert.deepEqual(read(['movq\t%rax, %xmm0', 'movhps\t%xmm0, (%rsp)']), []);
  assert.deepEqual(read(['xorps\t%xmm0, %xmm0', 'vmovdqu8\t%zmm0, (%rsp){%k1}']), [], 'a masked store is not counted');
  // clang-18 -O3, sonnet_S_pwverify_r3: a zeroed %xmm0 reloaded, then spilled (asm-oracle counts these)
  assert.deepEqual(read(['xorps\t%xmm0, %xmm0', 'movaps\t%xmm0, 96(%rsp)', 'movss\t12(%rsp), %xmm0', 'movaps\t%xmm0, 64(%rsp)',
    'punpcklwd\t%xmm1, %xmm0', 'movdqa\t%xmm0, 32(%rsp)']).map((w) => w.offset), [96]);
});

test('immediate zero stores, and $0 into a register is not a write', () => {
  assert.deepEqual(read(['movq\t$0, 8(%rsp)', 'movl\t$0, (%rdi)', 'movb\t$0, key(%rip)', 'andq\t$0, 24(%rsp)']).map((w) => [w.form, w.bytes, w.base, w.offset]),
    [['imm', 8, 'rsp', 8], ['imm', 4, 'rdi', 0], ['imm', 1, 'key', null], ['and-imm', 8, 'rsp', 24]]);
  assert.deepEqual(read(['movl\t$0, %esi']), []);
  assert.deepEqual(read(['movl\t$1, (%rsp)', 'andl\t$1, 4(%rsp)']), []);
});

test('rep stos: counted when the accumulator is zero, with bytes when the count is a constant of the same block', () => {
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movl\t$8, %ecx', 'leaq\t16(%rsp), %rdi', 'rep stosq']).map((w) => [w.form, w.bytes, w.base, w.offset]),
    [['rep-stos', 64, 'rsp', 16]]);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movl\t$3, %ecx', 'movq\t%rbx, %rdi', 'rep stosl %eax, %es:(%rdi)']).map((w) => [w.form, w.bytes, w.base]),
    [['rep-stos', 12, 'rdi']]);
  assert.deepEqual(read(['xorl\t%eax, %eax', 'leaq\t16(%rsp), %rdi', 'rep; stosb']).map((w) => [w.form, w.bytes]), [['rep-stos', null]]);
  assert.deepEqual(read(['movl\t$1, %eax', 'movl\t$8, %ecx', 'rep stosq']), []);
  // after it, %rdi and %rcx are no longer what they were
  assert.deepEqual(read(['xorl\t%eax, %eax', 'movl\t$2, %ecx', 'leaq\t(%rsp), %rdi', 'rep stosq', 'rep stosq']).map((w) => [w.bytes, w.base]),
    [[16, 'rsp'], [null, 'rdi']]);
  const s = summarizeWrites(zeroWritesInLines(['\txorl %eax, %eax', '\tleaq 16(%rsp), %rdi', '\trep stosq']));
  assert.deepEqual([s.bytes, s.unknownBytes, s.byForm['rep-stos'].unknownBytes], [0, 1, 1]);
});

test('frame bases: lea, mov of %rsp, add/sub of an immediate; a moved %rsp forgets them', () => {
  assert.deepEqual(read(['leaq\t8(%rsp), %rbx', 'addq\t$4, %rbx', 'movl\t$0, 2(%rbx)']).map((w) => [w.base, w.offset]), [['rsp', 14]]);
  assert.deepEqual(read(['movq\t%rsp, %rbx', 'movq\t%rbx, %rdx', 'movw\t$0, 6(%rdx)']).map((w) => [w.base, w.offset]), [['rsp', 6]]);
  assert.deepEqual(read(['leaq\t-32(%rbp), %rax', 'movq\t$0, 8(%rax)']).map((w) => [w.base, w.offset]), [['rbp', -24]]);
  assert.deepEqual(read(['leaq\t8(%rsp), %rbx', 'pushq\t%rax', 'movl\t$0, (%rbx)']).map((w) => [w.base, w.offset]), [['rbx', 0]]);
  assert.deepEqual(read(['leaq\t8(%rsp), %rbx', 'subq\t$16, %rsp', 'movl\t$0, (%rbx)']).map((w) => [w.base, w.offset]), [['rbx', 0]]);
  assert.deepEqual(read(['leaq\t8(%rsp), %rax', 'call\tf', 'movl\t$0, (%rax)']).map((w) => [w.base, w.offset]), [['rax', 0]]);
  assert.deepEqual(read(['movl\t$0, 4(%rsp,%rax,4)']).map((w) => [w.base, w.offset]), [['rsp', null]]);
});

test('summarizeWrites: sums, groups by offset, and counts overlapping bytes once in distinct', () => {
  const s = summarizeWrites([
    { form: 'zero-gpr', bytes: 4, base: 'rsp', offset: 1 }, { form: 'zero-gpr', bytes: 4, base: 'rsp', offset: 4 },
    { form: 'imm', bytes: 1, base: 'rsp', offset: 7 }, { form: 'imm', bytes: 8, base: 'rbp', offset: -16 },
    { form: 'rep-stos', bytes: null, base: 'rdi', offset: null },
  ]);
  assert.equal(s.count, 5);
  assert.equal(s.bytes, 17);
  assert.equal(s.unknownBytes, 1);
  assert.deepEqual(s.distinct, { rsp: 7, rbp: 8 });
  assert.deepEqual(s.byOffset.map((g) => `${g.base}:${g.offset}`), ['rbp:-16', 'rdi:null', 'rsp:1', 'rsp:4', 'rsp:7']);
});

test('functions are delimited as asm-oracle delimits them; a missing .size leaves the function out', () => {
  const two = listing('handle', ['movq\t$0, (%rsp)', 'ret']) + listing('handle_x', ['movl\t$0, (%rsp)', 'movl\t$0, 4(%rsp)', 'ret'])
    + '\t.type\tbroken, @function\nbroken:\n\tmovq\t$0, (%rsp)\n';
  assert.deepEqual(listingFunctions(two).map((f) => f.fn), ['handle', 'handle_x']);
  assert.deepEqual(readListing(two).map((f) => [f.fn, f.count, f.bytes]), [['handle', 1, 8], ['handle_x', 2, 8]]);
  assert.equal(zeroWritesOf(two, 'handle').count, 1, 'handle is a prefix of handle_x and reads only itself');
  assert.equal(zeroWritesOf(two, 'broken'), null);
  assert.equal(zeroWritesOf(two, 'absent'), null);
  assert.equal(zeroWritesOf(null, 'handle'), null);
  assert.throws(() => readListing(undefined), /listing text/);
  // clang's spelling of .type, and comments after the label
  const clang = '\t.type\tf,@function\nf:                                      # @f\n# %bb.0:\n\txorps\t%xmm0, %xmm0\n\tmovaps\t%xmm0, (%rsp)\n\tretq\n.Lfunc_end0:\n\t.size\tf, .Lfunc_end0-f\n';
  assert.deepEqual(readListing(clang).map((f) => [f.fn, f.count, f.bytes, f.first]), [['f', 1, 16, 2]]);
  assert.equal(readListing(clang)[0].writes[0].line, 5, 'listing line numbers');
});

test('the pieces: registers, memory operands, operand lists, prefixes', () => {
  assert.deepEqual(regOf('%r8d'), { name: 'r8d', fam: 'r8', width: 4, gpr: true, high: false });
  assert.deepEqual(regOf('%ymm3'), { name: 'ymm3', fam: 'v3', width: 32, vec: true });
  assert.equal(regOf('%k1').other, true);
  assert.equal(regOf('6(%rsp)'), null);
  assert.equal(isMem('6(%rsp)'), true);
  assert.equal(isMem('%fs:40'), true);
  assert.equal(isMem('$0'), false);
  assert.equal(isMem('*%rax'), false);
  assert.deepEqual(addrOf('-16(%rbp)'), { disp: -16, sym: null, base: 'rbp', index: null, scale: null });
  assert.deepEqual(addrOf('8(%rsp,%rax,4)'), { disp: 8, sym: null, base: 'rsp', index: 'rax', scale: 4 });
  assert.deepEqual(addrOf('key+8(%rip)'), { disp: null, sym: 'key+8', base: 'rip', index: null, scale: null });
  assert.deepEqual(splitOperands('%eax, 8(%rsp,%rax,4)'), ['%eax', '8(%rsp,%rax,4)']);
  assert.deepEqual(parseLine('\trep stosq %rax, %es:(%rdi)'), [{ kind: 'insn', mnem: 'stosq', ops: ['%rax', '%es:(%rdi)'], prefixes: ['rep'] }]);
  assert.deepEqual(parseLine('\trep; stosb').map((i) => [i.mnem, i.prefixes]), [['stosb', ['rep']]]);
  assert.deepEqual(parseLine('.LBB0_2:                                # =>This Inner Loop Header: Depth=1'), [{ kind: 'label', name: '.LBB0_2' }]);
  assert.deepEqual(parseLine('\t.cfi_def_cfa_offset 16'), [{ kind: 'directive' }]);
  assert.deepEqual(parseLine('# %bb.1:'), []);
});
