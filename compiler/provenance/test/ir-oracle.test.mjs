// The oracle rule, as vectors. interfaces.md §4.
//
// The load-bearing case is `declaration-survives-the-call`: IR in which the
// call has been deleted and the `declare` line has not. A name search reports
// the effect as present there. The call-site oracle reports it as gone, which
// is what happened.

import { strict as assert } from 'node:assert';
import test from 'node:test';

import { countMemsetCallSites } from '../lib/ir-oracle.mjs';

const AT_O0 = `; ModuleID = 'wipe.c'
define dso_local void @control_wipe() #0 {
entry:
  call void @llvm.memset.p0.i64(ptr align 16 @control_buffer, i8 0, i64 4096, i1 false)
  call void @observe(ptr noundef @control_buffer, i64 noundef 4096)
  ret void
}

define dso_local void @wipe_secret(ptr noundef %in) #0 {
entry:
  %buf = alloca [64 x i8], align 16
  call void @llvm.memset.p0.i64(ptr align 16 %buf, i8 0, i64 64, i1 false)
  ret void
}

declare void @observe(ptr noundef, i64 noundef) #1
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #2
`;

// The same module after store elimination removed the target's call. The
// declaration is still there — that is the point.
const AT_O2 = `; ModuleID = 'wipe.c'
define dso_local void @control_wipe() local_unnamed_addr #0 {
entry:
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 16 dereferenceable(4096) @control_buffer, i8 0, i64 4096, i1 false)
  tail call void @observe(ptr noundef nonnull @control_buffer, i64 noundef 4096)
  ret void
}

define dso_local void @wipe_secret(ptr nocapture noundef readnone %in) local_unnamed_addr #1 {
entry:
  ret void
}

declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #2
`;

test('at -O0 both functions carry a memset call site, and the declaration is separate', () => {
  const r = countMemsetCallSites(AT_O0);
  assert.equal(r.perFunction.control_wipe, 1);
  assert.equal(r.perFunction.wipe_secret, 1);
  assert.equal(r.total, 2);
  assert.equal(r.declares, 1);
});

test('at -O2 the target loses its call site, the control keeps its own, the declaration remains', () => {
  const r = countMemsetCallSites(AT_O2);
  assert.equal(r.perFunction.wipe_secret, 0, 'the target must fall to zero');
  assert.equal(r.perFunction.control_wipe, 1, 'the control must not — a control at zero is a broken measurement');
  assert.equal(r.total, 1);
  assert.equal(r.declares, 1, 'the declaration survives the call it declared');
});

test('a naive name search would disagree, which is why this oracle exists', () => {
  const naive = AT_O2.split('\n').filter((l) => l.includes('llvm.memset')).length;
  const r = countMemsetCallSites(AT_O2);
  assert.equal(naive, 2, 'the name appears twice: one call and one declaration');
  assert.equal(r.total, 1, 'only one of those is an effect');
  assert.notEqual(naive, r.total);
});

test('a module whose only mention of the intrinsic is the declaration counts zero call sites', () => {
  const r = countMemsetCallSites(`define dso_local void @f() {
entry:
  ret void
}

declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg)
`);
  assert.equal(r.total, 0);
  assert.equal(r.declares, 1);
});

test('call sites are attributed to the function they are in, not to the module', () => {
  const r = countMemsetCallSites(`define void @a() {
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 1, i1 false)
  ret void
}
define void @b() {
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 1, i1 false)
  call void @llvm.memset.p0.i64(ptr null, i8 0, i64 2, i1 false)
  ret void
}
`);
  assert.deepEqual(r.perFunction, { a: 1, b: 2 });
  assert.equal(r.total, 3);
});

test('a comment naming the intrinsic outside any function is not a call site', () => {
  const r = countMemsetCallSites(`; this module used to call @llvm.memset and no longer does
define void @f() {
  ret void
}
`);
  assert.equal(r.total, 0);
  assert.equal(r.declares, 0);
});
