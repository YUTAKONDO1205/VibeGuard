// The targeted baseline, and the specific way the naive version is wrong.
//
// The rule this file pins is interfaces.md section 4: count the zeroing
// instruction, never the symbol name. A grep for `llvm.memset` also matches the
// surviving `declare` line, which is how a first loss gets attributed to a
// declaration-cleanup pass instead of to the pass that deleted the call.

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseModule } from '../lib/parse.mjs';
import {
  countCallSites, naiveNameHits, resolveCallee, targetedWipeState, hasDataDependentBranch,
} from '../lib/oracle.mjs';
import { load } from './helpers.mjs';

const WITH_CALL = [
  'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)',
  '',
  'define void @wipe(ptr %p) {',
  'entry:',
  '  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 32, i1 false)',
  '  ret void',
  '}',
].join('\n');

// The same module after the call has been deleted. The declaration survives,
// exactly as it does in real output.
const WITHOUT_CALL = [
  'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)',
  '',
  'define void @wipe(ptr %p) {',
  'entry:',
  '  ret void',
  '}',
].join('\n');

test('the call-site oracle counts one call, then none', () => {
  const a = parseModule(WITH_CALL);
  const b = parseModule(WITHOUT_CALL);
  assert.equal(countCallSites(a.byName.get('@wipe'), 'llvm.memset'), 1);
  assert.equal(countCallSites(b.byName.get('@wipe'), 'llvm.memset'), 0);
});

test('the naive name search still finds the effect after it is gone', () => {
  // This is the misattribution, demonstrated rather than asserted in prose:
  // the count only falls when some later pass sweeps the declaration away.
  assert.equal(naiveNameHits(WITH_CALL, 'llvm.memset'), 2);
  assert.equal(naiveNameHits(WITHOUT_CALL, 'llvm.memset'), 1);
  assert.notEqual(naiveNameHits(WITHOUT_CALL, 'llvm.memset'), 0);
});

test('the state vocabulary distinguishes ABSENT from NOT_OBSERVED', () => {
  const a = parseModule(WITH_CALL);
  const b = parseModule(WITHOUT_CALL);
  assert.deepEqual(targetedWipeState(a, '@wipe'), { state: 'PRESENT', callSites: 1 });
  assert.deepEqual(targetedWipeState(b, '@wipe'), { state: 'ABSENT', callSites: 0 });
  // A function that is not in the module was not looked at. Reporting that as
  // ABSENT would be the substitution exit code 3 exists to prevent.
  assert.deepEqual(targetedWipeState(b, '@not_here'), { state: 'NOT_OBSERVED', callSites: 0 });
});

test('counting is per IR unit, not per module', () => {
  const two = parseModule([
    'declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)',
    'define void @a(ptr %p) {',
    'entry:',
    '  call void @llvm.memset.p0.i64(ptr %p, i8 0, i64 32, i1 false)',
    '  ret void',
    '}',
    'define void @b(ptr %p) {',
    'entry:',
    '  ret void',
    '}',
  ].join('\n'));
  assert.equal(countCallSites(two.byName.get('@a'), 'llvm.memset'), 1);
  assert.equal(countCallSites(two.byName.get('@b'), 'llvm.memset'), 0);
});

test('the callee is resolved from the instruction, and an indirect call resolves to nothing', () => {
  const mod = parseModule([
    'define void @f(ptr %fp) {',
    'entry:',
    '  call void %fp()',
    '  ret void',
    '}',
  ].join('\n'));
  const call = mod.byName.get('@f').blocks[0].insts[0];
  assert.equal(resolveCallee(call), null);
});

test('a decorated callee still resolves to the undecorated symbol', () => {
  const mod = load('sym-b.ll.txt');
  const call = mod.byName.get('@f').blocks[0].insts[1];
  assert.equal(resolveCallee(call), '@helper');
});

test('a branch on a constant is not a data-dependent branch', () => {
  const live = parseModule([
    'define i32 @f(i1 %c) {',
    'entry:',
    '  br i1 %c, label %t, label %e',
    't:',
    '  ret i32 1',
    'e:',
    '  ret i32 0',
    '}',
  ].join('\n'));
  const folded = parseModule([
    'define i32 @f(i1 %c) {',
    'entry:',
    '  br i1 true, label %t, label %e',
    't:',
    '  ret i32 1',
    'e:',
    '  ret i32 0',
    '}',
  ].join('\n'));
  assert.equal(hasDataDependentBranch(live.byName.get('@f')), true);
  assert.equal(hasDataDependentBranch(folded.byName.get('@f')), false);
});
