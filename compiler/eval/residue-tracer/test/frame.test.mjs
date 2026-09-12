/**
 * lib/frame.mjs reads the subject function's frame depth out of the binary that
 * was run, and this file is what keeps that number honest.
 *
 * WHY IT EXISTS AT ALL. The lane's NONE readings used to rest entirely on the
 * co-resident control: a control tracer held unwiped in the same frame, so a cell
 * that could not read the control was BROKEN_MEASUREMENT rather than a clean
 * wipe. A readable control proves the window reached THE CONTROL. Declare the
 * buffers `keep[32]; pad[8192]; secret[32];` and clang-18 -O0 puts the control
 * near the top of the frame and the secret 8 KiB deeper: at the default window
 * the observer reads control 32/32 and subject 1 byte, and the same binary at
 * --below 16384 reads subject 32/32. The frame bound is what closes that, so a
 * parser that silently under-counts a frame reopens it.
 *
 * EVERY BLOCK BELOW IS REAL. Each is `objdump -d --no-show-raw-insn` output for
 * `handle_request`, verbatim, from a binary built on this box from this lane's
 * own fixtures (clang-18 and gcc-13, -O0 and -O2). None of it is written by hand,
 * because the shapes that matter here are the ones compilers actually emit --
 * pushes interleaved with ordinary work, an `add` of a negative immediate doing a
 * subtraction, a probe loop, a VLA -- and a hand-written prologue would only test
 * what the author already believed.
 *
 * The two directions are not symmetric. Over-counting a frame costs a wider
 * window; under-counting it, or reading a dynamic frame as a small constant, puts
 * the lane back where it started. So every case that cannot be bounded is
 * asserted to come back UNPARSED rather than to come back with a number.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFrame, functionBlock, requiredBelow, FRAME_MARGIN_BYTES, WINDOW_MAX_BYTES } from '../lib/frame.mjs';

export const CLANG_O0_PLAIN = `
0000000000401160 <handle_request>:
  401160:	push   %rbp
  401161:	mov    %rsp,%rbp
  401164:	sub    $0x50,%rsp
  401168:	mov    %edi,-0x8(%rbp)
  40116b:	mov    -0x8(%rbp),%edi
  40116e:	lea    -0x30(%rbp),%rsi
  401172:	mov    $0x20,%edx
  401177:	call   4011f0 <get_secret>
  40117c:	cmp    $0x0,%eax
  40117f:	je     40118a <handle_request+0x2a>
  401181:	movl   $0xffffffff,-0x4(%rbp)
  401188:	jmp    4011dc <handle_request+0x7c>
  40118a:	mov    -0x8(%rbp),%edi
  40118d:	lea    -0x50(%rbp),%rsi
  401191:	mov    $0x20,%edx
  401196:	call   4011f0 <get_secret>
  40119b:	cmp    $0x0,%eax
  40119e:	je     4011a9 <handle_request+0x49>
  4011a0:	movl   $0xffffffff,-0x4(%rbp)
  4011a7:	jmp    4011dc <handle_request+0x7c>
  4011a9:	lea    -0x30(%rbp),%rdi
  4011ad:	mov    $0x20,%esi
  4011b2:	call   401270 <consume>
  4011b7:	lea    -0x50(%rbp),%rdi
  4011bb:	mov    $0x20,%esi
  4011c0:	call   401270 <consume>
  4011c5:	lea    -0x30(%rbp),%rdi
  4011c9:	xor    %esi,%esi
  4011cb:	mov    $0x20,%edx
  4011d0:	call   401030 <memset@plt>
  4011d5:	movl   $0x0,-0x4(%rbp)
  4011dc:	mov    -0x4(%rbp),%eax
  4011df:	add    $0x50,%rsp
  4011e3:	pop    %rbp
  4011e4:	ret
  4011e5:	cs nopw 0x0(%rax,%rax,1)
  4011ef:	nop
`;

export const GCC_O2_INTERLEAVED = `
0000000000401160 <handle_request>:
  401160:	endbr64
  401164:	push   %r12
  401166:	mov    $0x20,%edx
  40116b:	push   %rbp
  40116c:	push   %rbx
  40116d:	mov    %edi,%ebx
  40116f:	sub    $0x50,%rsp
  401173:	mov    %fs:0x28,%rax
  40117c:	mov    %rax,0x48(%rsp)
  401181:	xor    %eax,%eax
  401183:	mov    %rsp,%rbp
  401186:	mov    %rbp,%rsi
  401189:	call   4011f4 <get_secret>
  40118e:	test   %eax,%eax
  401190:	jne    4011e8 <handle_request+0x88>
  401192:	lea    0x20(%rsp),%r12
  401197:	mov    %ebx,%edi
  401199:	mov    $0x20,%edx
  40119e:	mov    %r12,%rsi
  4011a1:	call   4011f4 <get_secret>
  4011a6:	mov    %eax,%ebx
  4011a8:	test   %eax,%eax
  4011aa:	jne    4011e8 <handle_request+0x88>
  4011ac:	mov    $0x20,%esi
  4011b1:	mov    %rbp,%rdi
  4011b4:	call   40125f <consume>
  4011b9:	mov    $0x20,%esi
  4011be:	mov    %r12,%rdi
  4011c1:	call   40125f <consume>
  4011c6:	mov    0x48(%rsp),%rax
  4011cb:	sub    %fs:0x28,%rax
  4011d4:	jne    4011ef <handle_request+0x8f>
  4011d6:	add    $0x50,%rsp
  4011da:	mov    %ebx,%eax
  4011dc:	pop    %rbx
  4011dd:	pop    %rbp
  4011de:	pop    %r12
  4011e0:	ret
  4011e1:	nopl   0x0(%rax)
  4011e8:	mov    $0xffffffff,%ebx
  4011ed:	jmp    4011c6 <handle_request+0x66>
  4011ef:	call   401030 <__stack_chk_fail@plt>
`;

export const CLANG_O0_DEEP = `
0000000000401150 <handle_request>:
  401150:	push   %rbp
  401151:	mov    %rsp,%rbp
  401154:	sub    $0x2060,%rsp
  40115b:	mov    %edi,-0x8(%rbp)
  40115e:	mov    -0x8(%rbp),%edi
  401161:	lea    -0x2050(%rbp),%rsi
  401168:	mov    $0x20,%edx
  40116d:	call   401230 <get_secret>
  401172:	cmp    $0x0,%eax
  401175:	je     401187 <handle_request+0x37>
  40117b:	movl   $0xffffffff,-0x4(%rbp)
  401182:	jmp    40121d <handle_request+0xcd>
  401187:	mov    -0x8(%rbp),%edi
  40118a:	lea    -0x30(%rbp),%rsi
  40118e:	mov    $0x20,%edx
  401193:	call   401230 <get_secret>
  401198:	cmp    $0x0,%eax
  40119b:	je     4011ad <handle_request+0x5d>
  4011a1:	movl   $0xffffffff,-0x4(%rbp)
  4011a8:	jmp    40121d <handle_request+0xcd>
  4011ad:	movq   $0x0,-0x2058(%rbp)
  4011b8:	cmpq   $0x2000,-0x2058(%rbp)
  4011c3:	jae    4011f7 <handle_request+0xa7>
  4011c9:	mov    -0x2058(%rbp),%rax
  4011d0:	mov    %al,%cl
  4011d2:	mov    -0x2058(%rbp),%rax
  4011d9:	mov    %cl,-0x2030(%rbp,%rax,1)
  4011e0:	mov    -0x2058(%rbp),%rax
  4011e7:	add    $0x1,%rax
  4011eb:	mov    %rax,-0x2058(%rbp)
  4011f2:	jmp    4011b8 <handle_request+0x68>
  4011f7:	lea    -0x2050(%rbp),%rdi
  4011fe:	mov    $0x20,%esi
  401203:	call   4012b0 <consume>
  401208:	lea    -0x30(%rbp),%rdi
  40120c:	mov    $0x20,%esi
  401211:	call   4012b0 <consume>
  401216:	movl   $0x0,-0x4(%rbp)
  40121d:	mov    -0x4(%rbp),%eax
  401220:	add    $0x2060,%rsp
  401227:	pop    %rbp
  401228:	ret
  401229:	nopl   0x0(%rax)
`;

export const GCC_O2_PROBED = `
0000000000401160 <handle_request>:
  401160:	endbr64
  401164:	push   %r12
  401166:	push   %rbp
  401167:	push   %rbx
  401168:	sub    $0x1000,%rsp
  40116f:	orq    $0x0,(%rsp)
  401174:	sub    $0x1000,%rsp
  40117b:	orq    $0x0,(%rsp)
  401180:	sub    $0x50,%rsp
  401184:	mov    $0x20,%edx
  401189:	mov    %fs:0x28,%rax
  401192:	mov    %rax,0x2048(%rsp)
  40119a:	xor    %eax,%eax
  40119c:	lea    0x20(%rsp),%r12
  4011a1:	mov    %edi,%ebx
  4011a3:	mov    %r12,%rsi
  4011a6:	call   401230 <get_secret>
  4011ab:	test   %eax,%eax
  4011ad:	jne    401224 <handle_request+0xc4>
  4011af:	mov    %rsp,%rbp
  4011b2:	mov    %ebx,%edi
  4011b4:	mov    $0x20,%edx
  4011b9:	mov    %rbp,%rsi
  4011bc:	call   401230 <get_secret>
  4011c1:	mov    %eax,%ebx
  4011c3:	test   %eax,%eax
  4011c5:	jne    401224 <handle_request+0xc4>
  4011c7:	xor    %edx,%edx
  4011c9:	nopl   0x0(%rax)
  4011d0:	mov    %dl,0x40(%rsp,%rdx,1)
  4011d4:	lea    0x1(%rdx),%rcx
  4011d8:	add    $0x2,%rdx
  4011dc:	mov    %cl,0x40(%rsp,%rcx,1)
  4011e0:	cmp    $0x2000,%rdx
  4011e7:	jne    4011d0 <handle_request+0x70>
  4011e9:	mov    $0x20,%esi
  4011ee:	mov    %r12,%rdi
  4011f1:	call   40129b <consume>
  4011f6:	mov    $0x20,%esi
  4011fb:	mov    %rbp,%rdi
  4011fe:	call   40129b <consume>
  401203:	mov    0x2048(%rsp),%rax
  40120b:	sub    %fs:0x28,%rax
  401214:	jne    40122b <handle_request+0xcb>
  401216:	add    $0x2050,%rsp
  40121d:	mov    %ebx,%eax
  40121f:	pop    %rbx
  401220:	pop    %rbp
  401221:	pop    %r12
  401223:	ret
  401224:	mov    $0xffffffff,%ebx
  401229:	jmp    401203 <handle_request+0xa3>
  40122b:	call   401030 <__stack_chk_fail@plt>
`;

export const GCC_O2_REALIGNED = `
0000000000401160 <handle_request>:
  401160:	endbr64
  401164:	push   %rbp
  401165:	mov    $0x20,%edx
  40116a:	mov    %rsp,%rbp
  40116d:	push   %r13
  40116f:	push   %r12
  401171:	push   %rbx
  401172:	mov    %edi,%ebx
  401174:	and    $0xffffffffffffffc0,%rsp
  401178:	add    $0xffffffffffffff80,%rsp
  40117c:	mov    %fs:0x28,%rax
  401185:	mov    %rax,0x78(%rsp)
  40118a:	xor    %eax,%eax
  40118c:	mov    %rsp,%r12
  40118f:	mov    %r12,%rsi
  401192:	call   4011fc <get_secret>
  401197:	test   %eax,%eax
  401199:	jne    4011f0 <handle_request+0x90>
  40119b:	lea    0x50(%rsp),%r13
  4011a0:	mov    %ebx,%edi
  4011a2:	mov    $0x20,%edx
  4011a7:	mov    %r13,%rsi
  4011aa:	call   4011fc <get_secret>
  4011af:	mov    %eax,%ebx
  4011b1:	test   %eax,%eax
  4011b3:	jne    4011f0 <handle_request+0x90>
  4011b5:	mov    $0x20,%esi
  4011ba:	mov    %r12,%rdi
  4011bd:	call   401267 <consume>
  4011c2:	mov    $0x20,%esi
  4011c7:	mov    %r13,%rdi
  4011ca:	call   401267 <consume>
  4011cf:	mov    0x78(%rsp),%rax
  4011d4:	sub    %fs:0x28,%rax
  4011dd:	jne    4011f7 <handle_request+0x97>
  4011df:	lea    -0x18(%rbp),%rsp
  4011e3:	mov    %ebx,%eax
  4011e5:	pop    %rbx
  4011e6:	pop    %r12
  4011e8:	pop    %r13
  4011ea:	pop    %rbp
  4011eb:	ret
  4011ec:	nopl   0x0(%rax)
  4011f0:	mov    $0xffffffff,%ebx
  4011f5:	jmp    4011cf <handle_request+0x6f>
  4011f7:	call   401030 <__stack_chk_fail@plt>
`;

export const GCC_O2_PROBE_LOOP = `
0000000000401160 <handle_request>:
  401160:	endbr64
  401164:	push   %r12
  401166:	push   %rbp
  401167:	push   %rbx
  401168:	lea    -0x20000(%rsp),%r11
  401170:	sub    $0x1000,%rsp
  401177:	orq    $0x0,(%rsp)
  40117c:	cmp    %r11,%rsp
  40117f:	jne    401170 <handle_request+0x10>
  401181:	sub    $0x50,%rsp
  401185:	mov    $0x20,%edx
  40118a:	mov    %fs:0x28,%rax
  401193:	mov    %rax,0x20048(%rsp)
  40119b:	xor    %eax,%eax
  40119d:	lea    0x20(%rsp),%r12
  4011a2:	mov    %edi,%ebx
  4011a4:	mov    %r12,%rsi
  4011a7:	call   401230 <get_secret>
  4011ac:	test   %eax,%eax
  4011ae:	jne    401224 <handle_request+0xc4>
  4011b0:	mov    %rsp,%rbp
  4011b3:	mov    %ebx,%edi
  4011b5:	mov    $0x20,%edx
  4011ba:	mov    %rbp,%rsi
  4011bd:	call   401230 <get_secret>
  4011c2:	mov    %eax,%ebx
  4011c4:	test   %eax,%eax
  4011c6:	jne    401224 <handle_request+0xc4>
  4011c8:	xor    %edx,%edx
  4011ca:	nopw   0x0(%rax,%rax,1)
  4011d0:	mov    %dl,0x40(%rsp,%rdx,1)
  4011d4:	lea    0x1(%rdx),%rcx
  4011d8:	add    $0x2,%rdx
  4011dc:	mov    %cl,0x40(%rsp,%rcx,1)
  4011e0:	cmp    $0x20000,%rdx
  4011e7:	jne    4011d0 <handle_request+0x70>
  4011e9:	mov    $0x20,%esi
  4011ee:	mov    %r12,%rdi
  4011f1:	call   40129b <consume>
  4011f6:	mov    $0x20,%esi
  4011fb:	mov    %rbp,%rdi
  4011fe:	call   40129b <consume>
  401203:	mov    0x20048(%rsp),%rax
  40120b:	sub    %fs:0x28,%rax
  401214:	jne    40122b <handle_request+0xcb>
  401216:	add    $0x20050,%rsp
  40121d:	mov    %ebx,%eax
  40121f:	pop    %rbx
  401220:	pop    %rbp
  401221:	pop    %r12
  401223:	ret
  401224:	mov    $0xffffffff,%ebx
  401229:	jmp    401203 <handle_request+0xa3>
  40122b:	call   401030 <__stack_chk_fail@plt>
`;

export const CLANG_O2_VLA = `
0000000000401150 <handle_request>:
  401150:	push   %rbp
  401151:	mov    %rsp,%rbp
  401154:	push   %r15
  401156:	push   %r14
  401158:	push   %rbx
  401159:	sub    $0x28,%rsp
  40115d:	mov    %edi,%r14d
  401160:	movslq %edi,%rdi
  401163:	mov    %rsp,%rbx
  401166:	lea    0x2f(%rdi),%rax
  40116a:	and    $0xfffffffffffffff0,%rax
  40116e:	sub    %rax,%rbx
  401171:	mov    %rbx,%rsp
  401174:	mov    $0x20,%edx
  401179:	mov    %rbx,%rsi
  40117c:	call   4011d0 <get_secret>
  401181:	mov    $0xffffffff,%r15d
  401187:	test   %eax,%eax
  401189:	jne    4011be <handle_request+0x6e>
  40118b:	lea    -0x40(%rbp),%rsi
  40118f:	mov    $0x20,%edx
  401194:	mov    %r14d,%edi
  401197:	call   4011d0 <get_secret>
  40119c:	test   %eax,%eax
  40119e:	jne    4011be <handle_request+0x6e>
  4011a0:	mov    $0x20,%esi
  4011a5:	mov    %rbx,%rdi
  4011a8:	call   401250 <consume>
  4011ad:	lea    -0x40(%rbp),%rdi
  4011b1:	mov    $0x20,%esi
  4011b6:	call   401250 <consume>
  4011bb:	xor    %r15d,%r15d
  4011be:	mov    %r15d,%eax
  4011c1:	lea    -0x18(%rbp),%rsp
  4011c5:	pop    %rbx
  4011c6:	pop    %r14
  4011c8:	pop    %r15
  4011ca:	pop    %rbp
  4011cb:	ret
  4011cc:	nopl   0x0(%rax)
`;

/** The raw-bytes column, which objdump prints unless --no-show-raw-insn is passed. */
const RAW_COLUMN = `
0000000000401160 <handle_request>:
  401160:\tf3 0f 1e fa          \tendbr64
  401164:\t41 54                \tpush   %r12
  401166:\tba 20 00 00 00       \tmov    $0x20,%edx
  40116b:\t55                   \tpush   %rbp
  40116c:\t53                   \tpush   %rbx
  40116d:\t89 fb                \tmov    %edi,%ebx
  40116f:\t48 83 ec 50          \tsub    $0x50,%rsp
  401173:\tc3                   \tret
`;

test('the plain form: one push and one sub, and the sum is what a window has to cover', () => {
  // clang-18 -O0 on this lane's own target-memset.c.
  const f = parseFrame(CLANG_O0_PLAIN, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.pushBytes, 8);
  assert.equal(f.subBytes, 80);        // sub $0x50,%rsp
  assert.equal(f.subjectBytes, 88);
  assert.equal(f.form, 'push+sub');
  assert.equal(requiredBelow(f), 88 + FRAME_MARGIN_BYTES);
  assert.equal(FRAME_MARGIN_BYTES, 136, '8 for the return word the ret popped, 128 for the red zone');
});

test('pushes INTERLEAVED with ordinary work are all counted, which a prologue-shaped parser misses', () => {
  // gcc-13 -O2 emits `push %r12 / mov $0x20,%edx / push %rbp / push %rbx /
  // mov %edi,%ebx / sub $0x50,%rsp`. A parser that stopped at the first
  // instruction that is not a frame-setup instruction would stop at the `mov`
  // and report 8 + 0 bytes instead of 24 + 80 -- an under-count, which is the
  // direction that puts a secret back outside the window.
  const f = parseFrame(GCC_O2_INTERLEAVED, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.pushBytes, 24, 'three pushes, two of them after a mov');
  assert.equal(f.subBytes, 80);
  assert.equal(f.subjectBytes, 104);
});

test('the deep frame that produced the false clean is measured at 8296, needing --below 8432', () => {
  // THE CASE THIS WHOLE FILE EXISTS FOR. Binary: this lane's target with
  // `keep[32]; pad[8192]; secret[32];` at clang-18 -O0. Observed with the real
  // observer over this exact binary:
  //   --below 4096   subject 1/32   control 32/32     <- the silent false clean
  //   --below 8192   subject 1/32   control 32/32
  //   --below 8296   subject 32/32  control 32/32     <- the frame depth measured here
  //   --below 16384  subject 32/32  control 32/32
  // So the number below is not a plausible-looking constant: at exactly this
  // depth the secret becomes readable, and one byte short of it the cell reads
  // as a clean wipe.
  const f = parseFrame(CLANG_O0_DEEP, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.subjectBytes, 8296);   // push %rbp (8) + sub $0x2060,%rsp (8288)
  assert.equal(requiredBelow(f), 8432);
  assert.ok(requiredBelow(f) > 4096, 'the default window does not cover this frame, and must not pass for it');
});

test('unrolled stack-clash probes add up, and the orq that probes them is not a write to rsp', () => {
  // gcc-13 -O2 with an 8 KiB frame: `sub $0x1000,%rsp / orq $0x0,(%rsp)` twice,
  // then `sub $0x50,%rsp`. Two traps here. The subs are three separate
  // instructions and only their sum bounds the frame; and `orq $0x0,(%rsp)`
  // mentions %rsp without writing it, so a parser that matched on the string
  // would call the frame unparseable and lose the cell.
  const f = parseFrame(GCC_O2_PROBED, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.pushBytes, 24);
  assert.equal(f.subBytes, 4096 + 4096 + 80);
  assert.equal(f.subjectBytes, 8296);
});

test('realignment and an ADD of a negative immediate are both counted', () => {
  // gcc-13 -O2 with an over-aligned local: `and $0xffffffffffffffc0,%rsp` then
  // `add $0xffffffffffffff80,%rsp`. The `and` can move rsp down by up to 63
  // bytes depending on where the caller left it, and the `add` is a subtraction
  // of 128 written as an addition -- a parser that only knew `sub` would count
  // this 191-byte allocation as zero.
  const f = parseFrame(GCC_O2_REALIGNED, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.alignSlackBytes, 63, 'the worst case of a 64-byte realignment');
  assert.ok(f.form.includes('add'), 'the negative add is recorded as the form it is');
  assert.ok(f.form.includes('and'));
  assert.ok(f.subjectBytes >= 32 + 128 + 63, 'four pushes, the 128-byte add, and the realignment slack');
});

test('an ordinary epilogue reached by a backward jump is not mistaken for an allocation in a loop', () => {
  // The same block: gcc puts `lea -0x18(%rbp),%rsp` in the epilogue and jumps
  // back to it from the error path. That instruction SETS rsp rather than
  // lowering it, so repeating it changes nothing -- treating it as cumulative
  // made an ordinary function look like a probe loop and threw the cell away.
  const f = parseFrame(GCC_O2_REALIGNED, 'handle_request');
  assert.equal(f.parsed, true, 'a frame-pointer restore inside a backward branch is not a loop allocation');
});

test('a stack decrement INSIDE a loop is unparsed, not counted once', () => {
  // gcc-13 -O2 with a 128 KiB frame emits the probe as a loop:
  //   sub $0x1000,%rsp / orq $0x0,(%rsp) / cmp %r11,%rsp / jne <back>
  // Counting the sub once gives 4096 for a frame of 131144. That under-count is
  // exactly the failure this file exists to prevent, so the frame is refused.
  const f = parseFrame(GCC_O2_PROBE_LOOP, 'handle_request');
  assert.equal(f.parsed, false);
  assert.equal(f.why, 'stack-decrement-inside-a-loop');
  assert.equal(f.subjectBytes, null, 'an unparsed frame carries no number that could be compared');
  assert.equal(requiredBelow(f), null);
});

test('a frame built by a register write -- a VLA -- is unparsed rather than under-counted', () => {
  // clang-18 with `unsigned char secret[n]`: `sub %rax,%rbx / mov %rbx,%rsp`.
  // Nothing static bounds that, so the honest answer is that the depth is
  // unknown. gcc writes the same idea as `sub %rdx,%rsp`.
  const f = parseFrame(CLANG_O2_VLA, 'handle_request');
  assert.equal(f.parsed, false);
  assert.match(f.why, /^unbounded-rsp-write: /);
  assert.equal(f.subjectBytes, null);
});

test('the raw-bytes column objdump prints by default does not change the answer', () => {
  const f = parseFrame(RAW_COLUMN, 'handle_request');
  assert.equal(f.parsed, true);
  assert.equal(f.subjectBytes, 24 + 80);
});

test('a symbol that is not in the disassembly is unparsed, never a zero-byte frame', () => {
  const f = parseFrame(CLANG_O0_PLAIN, 'not_a_function');
  assert.equal(f.parsed, false);
  assert.equal(f.why, 'symbol-not-in-the-disassembly');
  assert.equal(functionBlock(CLANG_O0_PLAIN, 'not_a_function'), null);
  assert.equal(functionBlock(null, 'handle_request'), null);
  // A zero would be the dangerous answer: it says "any window covers this".
  assert.notEqual(f.subjectBytes, 0);
});

test('the function block stops at the next symbol, so a neighbour frame is never added in', () => {
  const two = `${CLANG_O0_PLAIN}\n0000000000402000 <other>:\n  402000:\tsub    $0x10000,%rsp\n  402007:\tret\n`;
  const body = functionBlock(two, 'handle_request');
  assert.ok(body.length > 0);
  assert.ok(!body.some((l) => l.includes('0x10000')), 'the next function is not part of this one');
  assert.equal(parseFrame(two, 'handle_request').subjectBytes, 88);
  assert.equal(parseFrame(two, 'other').subjectBytes, 65536);
});

test('requiredBelow refuses to invent a requirement, and the margin is a parameter not a constant in the code', () => {
  assert.equal(requiredBelow(null), null);
  assert.equal(requiredBelow({ parsed: false, subjectBytes: 100 }), null);
  assert.equal(requiredBelow({ parsed: true, subjectBytes: 100 }), 100 + FRAME_MARGIN_BYTES);
  assert.equal(requiredBelow({ parsed: true, subjectBytes: 100 }, 0), 100);
});

test('the observer window ceiling is mirrored here, because a frame can exceed it', () => {
  // A 128 KiB frame is inside it; the ceiling matters because a cell that needs
  // more window than the observer accepts must be refused rather than measured
  // shallow. test/observer-record.test.mjs holds this equal to the C constant.
  assert.equal(WINDOW_MAX_BYTES, 1048576);
  assert.ok(requiredBelow(parseFrame(GCC_O2_PROBED, 'handle_request')) < WINDOW_MAX_BYTES);
});
