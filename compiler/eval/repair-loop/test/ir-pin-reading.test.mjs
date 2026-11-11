/**
 * tools/lib/ir-pin-reading.mjs: per function, the barriers WipePin and
 * WipePinGcc place, WipePin's volatile memsets and volatile zero stores, in
 * clang's optimised IR text and gcc's -fdump-tree-optimized text.
 *
 * The functions marked "as printed" are copied from clang-18 and gcc-13
 * output of one small file compiled in the lab with and without the plugins
 * (WPIN_BUFFER_BARRIER=1, WPIN_BARRIER_CALLS=1 with -D_FORTIFY_SOURCE=2, and
 * the default pin). The same compiles' records gave the totals the last two
 * tests check: at -O2, pinned 3 and bufferBarriers 2 on clang-18; pinned 1 and
 * bufferBarriers 2 on gcc-13, where a source barrier written with "g" prints
 * exactly as the plugin's. Those runs are not recomputed here.
 *
 * No compiler, and nothing imported but the file under test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  splitArgs, irTypeBytes, irFunctions, isWipePinBarrier, readIrBody, readIr,
  gimpleFunctions, parseGimpleAsm, isWipePinGccBarrier, readGimpleBody, readGimple, totals,
} from '../tools/lib/ir-pin-reading.mjs';

// clang-18 -O2, WPIN_BUFFER_BARRIER=1 -- as printed
const IR_BB = `define dso_local void @wipe_memset() local_unnamed_addr #0 {
  %1 = alloca [32 x i8], align 16
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %1) #4
  call void @fill(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @use(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @llvm.memset.p0.i64(ptr nonnull align 16 %1, i8 0, i64 32, i1 true)
  call void asm sideeffect "", "r,~{memory}"(ptr nonnull %1) #4
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %1) #4
  ret void
}

; Function Attrs: nounwind uwtable
define dso_local void @wipe_loop() local_unnamed_addr #0 {
  %1 = alloca [32 x i8], align 16
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %1) #4
  call void @fill(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @use(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(32) %1, i8 0, i64 32, i1 false), !tbaa !5
  call void asm sideeffect "", "r,~{memory}"(ptr nonnull %1) #4
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %1) #4
  ret void
}

declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #3
`;

// clang-18 -O2 -D_FORTIFY_SOURCE=2, WPIN_BARRIER_CALLS=1: the plugin's barrier beside one the source wrote -- as printed
const IR_USER = `define dso_local void @user_bar() local_unnamed_addr #0 {
  %1 = alloca [32 x i8], align 16
  call void @llvm.lifetime.start.p0(i64 32, ptr nonnull %1) #4
  call void @fill(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @use(ptr noundef nonnull %1, i64 noundef 32) #4
  call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(32) %1, i8 noundef 0, i64 noundef 32, i1 noundef false) #4
  call void asm sideeffect "", "r,~{memory}"(ptr nonnull %1) #4
  call void asm sideeffect "", "r,~{memory},~{dirflag},~{fpsr},~{flags}"(ptr nonnull %1) #4, !srcloc !5
  call void @llvm.lifetime.end.p0(i64 32, ptr nonnull %1) #4
  ret void
}
`;

// clang-18 -O2, no plugin: a volatile store of zero, and a loop of byte stores -- as printed (the loop cut to 3 stores)
const IR_VOL = `define dso_local void @vol_one() local_unnamed_addr #0 {
  %1 = alloca i64, align 8
  call void @llvm.lifetime.start.p0(i64 8, ptr nonnull %1) #4
  call void @fill(ptr noundef nonnull %1, i64 noundef 8) #4
  call void @use(ptr noundef nonnull %1, i64 noundef 8) #4
  store volatile i64 0, ptr %1, align 8, !tbaa !10
  call void @llvm.lifetime.end.p0(i64 8, ptr nonnull %1) #4
  ret void
}
define dso_local void @vol_loop() local_unnamed_addr #0 {
  %1 = alloca [32 x i8], align 16
  store volatile i8 0, ptr %1, align 16, !tbaa !7
  %2 = getelementptr inbounds i8, ptr %1, i64 1
  store volatile i8 0, ptr %2, align 1, !tbaa !7
  %3 = getelementptr inbounds i8, ptr %1, i64 2
  store volatile i8 0, ptr %3, align 2, !tbaa !7
  store volatile i8 7, ptr %3, align 2, !tbaa !7
  store i8 0, ptr %3, align 2, !tbaa !7
  ret void
}
`;

// gcc-13 -O2, WPIN_BUFFER_BARRIER=1 -- as printed
const GIMPLE_BB = `
;; Function wipe_memset (wipe_memset, funcdef_no=14, decl_uid=3044, cgraph_uid=15, symbol_order=14)

void wipe_memset ()
{
  unsigned char k[32];

  <bb 2> [local count: 1073741824]:
  fill (&k, 32);
  use (&k, 32);
  __builtin_memset (&k, 0, 32);
  __asm__ __volatile__("" :  : "g" &k : "memory");
  __asm__ __volatile__("" :  : "g" &k : "memory");
  k ={v} {CLOBBER(eol)};
  return;

}



;; Function wipe_loop (wipe_loop, funcdef_no=15, decl_uid=3048, cgraph_uid=16, symbol_order=15)

void wipe_loop ()
{
  unsigned char k[32];

  <bb 2> [local count: 32534376]:
  fill (&k, 32);
  use (&k, 32);
  __builtin_memset (&k, 0, 32);
  __asm__ __volatile__("" :  : "g" &k : "memory");
  k ={v} {CLOBBER(eol)};
  return;

}



;; Function user_bar (user_bar, funcdef_no=16, decl_uid=3057, cgraph_uid=17, symbol_order=16)

void user_bar ()
{
  unsigned char k[32];

  <bb 2> [local count: 1073741824]:
  fill (&k, 32);
  use (&k, 32);
  __builtin_memset (&k, 0, 32);
  __asm__ __volatile__("" :  : "r" &k : "memory");
  k ={v} {CLOBBER(eol)};
  return;

}



;; Function user_barg (user_barg, funcdef_no=17, decl_uid=3061, cgraph_uid=18, symbol_order=17)

void user_barg ()
{
  unsigned char k[32];

  <bb 2> [local count: 1073741824]:
  fill (&k, 32);
  use (&k, 32);
  __builtin_memset (&k, 0, 32);
  __asm__ __volatile__("" :  : "g" &k : "memory");
  k ={v} {CLOBBER(eol)};
  return;

}
`;

// gcc-13 -O0 with the plugin: memset prints without __builtin_, and a volatile store -- as printed
const GIMPLE_O0 = `;; Function wipe_memset (wipe_memset, funcdef_no=0, decl_uid=2957, cgraph_uid=1, symbol_order=0)

void wipe_memset ()
{
  unsigned char k[32];

  <bb 2> :
  fill (&k, 32);
  use (&k, 32);
  memset (&k, 0, 32);
  __asm__ __volatile__("" :  : "g" &k : "memory");
  k ={v} {CLOBBER(eol)};
  return;

}


;; Function vol_one (vol_one, funcdef_no=5, decl_uid=2988, cgraph_uid=6, symbol_order=5)

void vol_one ()
{
  long unsigned int k;
  long unsigned int * k.0_1;

  <bb 2> :
  fill (&k, 8);
  use (&k, 8);
  k.0_1 = &k;
  MEM[(volatile long unsigned int *)k.0_1] ={v} 0;
  k ={v} {CLOBBER(eol)};
  return;

}
`;

const byFn = (fns) => Object.fromEntries(fns.map((f) => [f.fn, f]));

// ------------------------------------------------------------------ LLVM --

test("WipePin's barrier is the exact asm; the source's barrier, with clang's x86 clobbers, is another memory asm", () => {
  const f = byFn(readIr(IR_USER)).user_bar;
  assert.equal(f.wipePinBarriers, 1);
  assert.equal(f.otherMemoryAsm, 1);
  assert.equal(f.volatileMemsetZero, 0, 'under FORTIFY the call is barriered, not made volatile');
  assert.equal(f.memsetZero, 1, 'i8 noundef 0 is read by its last token');
  assert.equal(isWipePinBarrier('  call void asm sideeffect "", "r,~{memory}"(ptr nonnull %1) #4'), true);
  assert.equal(isWipePinBarrier('  tail call void asm sideeffect "", "r,~{memory}"(i8* nonnull %1)'), true, 'typed pointers');
  assert.equal(isWipePinBarrier('  call void asm sideeffect "", "r,r,~{memory}"(ptr %1, ptr %2)'), false);
  assert.equal(isWipePinBarrier('  call void asm sideeffect "", "r,~{memory},~{dirflag},~{fpsr},~{flags}"(ptr %1)'), false);
  assert.equal(isWipePinBarrier('  call void asm sideeffect "nop", "r,~{memory}"(ptr %1)'), false);
  assert.equal(isWipePinBarrier('  call void asm sideeffect inteldialect "", "r,~{memory}"(ptr %1)'), false);
});

test('the buffer barrier and the pin, per function', () => {
  const f = byFn(readIr(IR_BB));
  assert.deepEqual(Object.keys(f), ['wipe_memset', 'wipe_loop'], 'declarations are not functions');
  assert.deepEqual([f.wipe_memset.wipePinBarriers, f.wipe_memset.volatileMemsetZero, f.wipe_memset.memsetZero], [1, 1, 0]);
  assert.deepEqual([f.wipe_loop.wipePinBarriers, f.wipe_loop.volatileMemsetZero, f.wipe_loop.memsetZero], [1, 0, 1]);
  assert.deepEqual(f.wipe_memset.lines.map((l) => [l.line, l.kind, l.length ?? null]), [[6, 'volatileMemsetZero', 32], [7, 'wipePinBarrier', null]]);
  const t = totals(readIr(IR_BB));
  assert.deepEqual([t.functions, t.wipePinBarriers, t.volatileMemsetZero, t.memsetZero], [2, 2, 1, 1]);
});

test('volatile stores: zero ones counted with their bytes, non-zero and non-volatile ones not', () => {
  const f = byFn(readIr(IR_VOL));
  assert.deepEqual([f.vol_one.volatileZeroStores, f.vol_one.volatileZeroStoreBytes], [1, 8]);
  assert.deepEqual([f.vol_loop.volatileZeroStores, f.vol_loop.volatileZeroStoreBytes], [3, 3]);
  const c = readIrBody([
    '  store volatile <16 x i8> zeroinitializer, ptr %p, align 16',
    '  store volatile ptr null, ptr %q, align 8',
    '  store atomic volatile i32 0, ptr %r seq_cst, align 4',
    '  store volatile %struct.s zeroinitializer, ptr %s, align 4',
    '  store volatile i8 0, i8* %t, align 1',
  ]);
  assert.deepEqual([c.volatileZeroStores, c.volatileZeroStoreBytes, c.volatileZeroStoresUnsized], [5, 29, 1]);
});

test('memset intrinsics: the volatile flag and the value decide the column; library calls are counted by name', () => {
  const c = readIrBody([
    '  call void @llvm.memset.p0.i64(ptr align 1 %a, i8 0, i64 16, i1 true)',
    '  call void @llvm.memset.inline.p0.i64(ptr align 1 %a, i8 0, i64 16, i1 true)',
    '  call void @llvm.memset.p0i8.i64(i8* align 1 %a, i8 0, i64 %n, i1 true)',
    '  call void @llvm.memset.p0.i64(ptr align 1 %a, i8 -1, i64 16, i1 true)',
    '  call void @llvm.memset.p0.i64(ptr align 1 %a, i8 0, i64 16, i1 false)',
    '  call void @explicit_bzero(ptr noundef %a, i64 noundef 16)',
    '  %r = call ptr @memset.inline(ptr noundef %a, i32 noundef 0, i64 noundef 16)',
    '  invoke void @sodium_memzero(ptr %a, i64 16) to label %ok unwind label %lp',
    '  call void @memcpy(ptr %a, ptr %b, i64 16)',
  ]);
  assert.deepEqual([c.volatileMemsetZero, c.volatileMemsetNonZero, c.memsetZero], [3, 1, 1]);
  assert.deepEqual(c.lines.filter((l) => l.kind === 'volatileMemsetZero').map((l) => l.length), [16, 16, null]);
  assert.deepEqual(c.zeroCalls, { explicit_bzero: 1, 'memset.inline': 1, sodium_memzero: 1 });
});

test('IR functions run from define to the closing brace; quoted names keep their text', () => {
  const ir = 'define internal void @"a.b c"(ptr %p) {\n  call void asm sideeffect "", "r,~{memory}"(ptr %p)\n  ret void\n}\ndefine void @open() {\n  ret void\n';
  assert.deepEqual(irFunctions(ir).map((f) => [f.fn, f.first, f.lines.length]), [['a.b c', 1, 4]]);
  assert.equal(readIr(ir)[0].wipePinBarriers, 1);
  assert.throws(() => readIr(null), /IR text/);
  assert.deepEqual(splitArgs('ptr noundef nonnull align 16 dereferenceable(32) %1, i8 0, i64 32, i1 true'),
    ['ptr noundef nonnull align 16 dereferenceable(32) %1', 'i8 0', 'i64 32', 'i1 true']);
  assert.deepEqual([irTypeBytes('i64'), irTypeBytes('<4 x i32>'), irTypeBytes('[3 x i16]'), irTypeBytes('ptr'), irTypeBytes('i1'), irTypeBytes('%struct.s')],
    [8, 16, 6, 8, null, null]);
});

// ---------------------------------------------------------------- GIMPLE --

test("WipePinGcc's barrier is the exact \"g\" asm; a source barrier in that form is indistinguishable, one with \"r\" is not", () => {
  const f = byFn(readGimple(GIMPLE_BB));
  assert.deepEqual(Object.keys(f), ['wipe_memset', 'wipe_loop', 'user_bar', 'user_barg']);
  assert.deepEqual([f.wipe_memset.wipePinGccBarriers, f.wipe_memset.memsetZeroCalls], [2, 1], 'the pin and the buffer barrier');
  assert.deepEqual([f.wipe_loop.wipePinGccBarriers, f.wipe_loop.memsetZeroCalls], [1, 1], 'loop distribution made the loop a memset');
  assert.deepEqual([f.user_bar.wipePinGccBarriers, f.user_bar.otherMemoryAsm], [0, 1]);
  assert.deepEqual([f.user_barg.wipePinGccBarriers, f.user_barg.otherMemoryAsm], [1, 0], 'written by the source, read as the plugin\'s');
  const t = totals(readGimple(GIMPLE_BB));
  assert.equal(t.wipePinGccBarriers, 4, 'pinned 1 + bufferBarriers 2 + the source\'s one');
  assert.equal(t.volatileZeroStores ?? 0, 0, 'a {CLOBBER} is not a store of zero');
});

test('GIMPLE at -O0: memset without __builtin_, and a volatile store of zero', () => {
  const f = byFn(readGimple(GIMPLE_O0));
  assert.deepEqual([f.wipe_memset.wipePinGccBarriers, f.wipe_memset.memsetZeroCalls, f.wipe_memset.zeroCalls.memset], [1, 1, 1]);
  assert.deepEqual([f.vol_one.volatileZeroStores, f.vol_one.volatileZeroStoresUnsized], [1, 1]);
  const c = readGimpleBody([
    '  key ={v} {};', '  *p_3 ={v} 0B;', '  *p_3 ={v} 1;', '  k ={v} {CLOBBER};', '  k ={v} {CLOBBER(eos)};',
    '  _1 = __builtin_memset (&k, 0, 32);', '  __builtin_memset (&k, 1, 32);', '  __builtin___memset_chk (&k, 0, 32, 32);',
    '  explicit_bzero (&k, 32);',
  ]);
  assert.deepEqual([c.volatileZeroStores, c.memsetZeroCalls], [2, 2]);
  assert.deepEqual(c.zeroCalls, { memset: 1, __memset_chk: 1, explicit_bzero: 1 });
});

test('the GIMPLE asm statement parser, and what is not the barrier', () => {
  assert.deepEqual(parseGimpleAsm('  __asm__ __volatile__("" :  : "g" &k : "memory");'),
    { volatile: true, template: '', outputs: [], inputs: [{ constraint: 'g', operand: '&k' }], clobbers: ['memory'], labels: [] });
  assert.equal(parseGimpleAsm('  fill (&k, 32);'), null);
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("" :  : "g" p_5 : "memory");'), true);
  assert.equal(isWipePinGccBarrier('  __asm__("" :  : "g" &k : "memory");'), false, 'not volatile');
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("" :  : "g" &k, "g" &j : "memory");'), false, 'two inputs');
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("" :  :  : "memory");'), false, 'no input: the clobber alone is not a pin');
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("" : "=g" x_1 : "g" &k : "memory");'), false, 'an output');
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("nop" :  : "g" &k : "memory");'), false, 'not empty');
  assert.equal(isWipePinGccBarrier('  __asm__ __volatile__("" :  : "g" &k : "memory", "cc");'), false, 'two clobbers');
  assert.deepEqual(gimpleFunctions(GIMPLE_O0).map((f) => [f.fn, f.first]), [['wipe_memset', 1], ['vol_one', 18]]);
  const cxx = ';; Function int f(int) (_Z1fi, funcdef_no=0, decl_uid=1, cgraph_uid=1, symbol_order=0) (executed once)\n\n  __asm__ __volatile__("" :  : "g" &k : "memory");\n';
  assert.deepEqual(readGimple(cxx).map((f) => [f.fn, f.display, f.wipePinGccBarriers]), [['_Z1fi', 'int f(int)', 1]]);
  assert.throws(() => readGimple(undefined), /dump text/);
});
