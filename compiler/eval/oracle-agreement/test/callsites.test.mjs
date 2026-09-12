/**
 * The IR call-site counter, over IR text rather than over a compiler.
 *
 * Every fixture here is a fragment of `-O0` LLVM IR in the shape clang-18 emits
 * it. No compiler runs: the question these tests ask is whether the counting
 * rule is the one the README's table claims was applied, and that question is
 * about text.
 *
 * The first two tests are the ones that matter. The README records a false trail
 * -- a first pass grepped the SOURCE for `memset(` and found five exclusions
 * apparently calling it, because the word was inside the files' own comments --
 * and the IR has the same trap in two more forms: every module that uses an
 * intrinsic also DECLARES it, and a wipe can appear as an argument rather than
 * as a callee. A counter that fell for either would report exactly the "perfect
 * split" the README claims, off by the number of files that declare what they
 * never call.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  symbolsOf, calleeMatches, countIrCallSites, splitByCallSites, splitIsPerfect, splitTotal,
  irArgs, irPathOf, emitIrAtO0,
} from '../lib/callsites.mjs';

/** The registry's `wipe-5-observer` literal, as the runner hands it over. */
const LITERAL = 'llvm.memset,memset,explicit_bzero,bzero,__memset_chk';
const SYMS = symbolsOf(LITERAL);

test('the symbol list is the registry literal, split -- not a list spelled here', () => {
  assert.deepEqual(SYMS, ['llvm.memset', 'memset', 'explicit_bzero', 'bzero', '__memset_chk']);
  assert.throws(() => symbolsOf(['memset']), TypeError);
  assert.throws(() => symbolsOf(' , '), /empty/);
});

test('a DECLARATION is not a call site', () => {
  // Every module that emits llvm.memset also declares it. A counter that reads
  // declarations reports at least one call site for every module that mentions
  // a wipe anywhere -- including the twenty-three the README says have none.
  const ir = [
    'declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #1',
    'declare ptr @memset(ptr, i32, i64) #2',
    'define dso_local void @wipe_it(ptr noundef %p) #0 {',
    '  ret void',
    '}',
  ].join('\n');
  const c = countIrCallSites(ir, SYMS, 'wipe_it');
  assert.equal(c.inFile, 0);
  assert.equal(c.inFunction, 0);
  assert.equal(c.functionSeen, true);
});

test('a wipe symbol passed as an ARGUMENT is not a call site either', () => {
  // `call void @register(ptr @memset)` names memset, and the callee is
  // `register`. The last `@name(` on the line is the one a first-match regex
  // gets wrong, which is why the callee is read as the last and not the first.
  const ir = [
    'define dso_local void @setup() #0 {',
    '  call void @register_handler(ptr noundef @memset)',
    '  ret void',
    '}',
  ].join('\n');
  assert.equal(countIrCallSites(ir, SYMS, 'setup').inFile, 0);
});

test('an intrinsic is matched through its overload suffix, and only an intrinsic is', () => {
  assert.equal(calleeMatches('llvm.memset.p0.i64', SYMS), 'llvm.memset');
  assert.equal(calleeMatches('memset', SYMS), 'memset');
  assert.equal(calleeMatches('__memset_chk', SYMS), '__memset_chk');
  // Not a wipe in this list, and not reachable by widening the suffix rule.
  assert.equal(calleeMatches('memset_s', SYMS), null);
  assert.equal(calleeMatches('memset.part.0', SYMS), null);
  assert.equal(calleeMatches('my_memset', SYMS), null);
});

test('call, tail call and invoke all count, and an indirect call does not', () => {
  const ir = [
    'define dso_local void @wipe_it(ptr noundef %p) #0 {',
    '  call void @llvm.memset.p0.i64(ptr align 16 %p, i8 0, i64 32, i1 false)',
    '  %c = tail call ptr @memset(ptr noundef %p, i32 noundef 0, i64 noundef 32)',
    '  invoke void @explicit_bzero(ptr noundef %p, i64 noundef 32)',
    '  call void %fp(ptr noundef %p)',
    '  ret void',
    '}',
  ].join('\n');
  const c = countIrCallSites(ir, SYMS, 'wipe_it');
  assert.equal(c.inFile, 3);
  assert.equal(c.inFunction, 3);
  assert.deepEqual(c.bySymbol, {
    'llvm.memset': 1, memset: 1, explicit_bzero: 1, bzero: 0, __memset_chk: 0,
  });
});

test('the function-scoped count is the subject’s own, and the file count is everyone’s', () => {
  const ir = [
    'define dso_local void @other(ptr noundef %p) #0 {',
    '  call void @llvm.memset.p0.i64(ptr align 1 %p, i8 0, i64 8, i1 false)',
    '  ret void',
    '}',
    '',
    'define dso_local void @subject(ptr noundef %p) #0 {',
    '  call void @explicit_bzero(ptr noundef %p, i64 noundef 8)',
    '  ret void',
    '}',
  ].join('\n');
  const c = countIrCallSites(ir, SYMS, 'subject');
  assert.equal(c.inFile, 2);
  assert.equal(c.inFunction, 1);
  assert.equal(c.functionSeen, true);
  // A subject the IR does not define at all is a different fact from a subject
  // that defines no wipe, and the count alone cannot tell them apart.
  const missing = countIrCallSites(ir, SYMS, 'not_here');
  assert.equal(missing.functionSeen, false);
  assert.equal(missing.inFunction, 0);
});

test('a volatile pointer loop -- the shape O2 cannot be asked about -- counts zero', () => {
  // This is the whole point of the diagnosis. The wipe is real, O1 sees it in
  // the assembly differential, and there is no call site for O2 to watch.
  const ir = [
    'define dso_local void @wipe_loop(ptr noundef %p, i64 noundef %n) #0 {',
    'for.body:',
    '  %q = load volatile ptr, ptr %p, align 8',
    '  store volatile i8 0, ptr %q, align 1',
    '  br label %for.cond',
    '}',
  ].join('\n');
  assert.equal(countIrCallSites(ir, SYMS, 'wipe_loop').inFile, 0);
});

test('a closing brace in column 0 ends the function, so the next call is not the subject’s', () => {
  const ir = [
    'define dso_local void @subject(ptr noundef %p) #0 {',
    '  ret void',
    '}',
    '',
    'define dso_local void @after(ptr noundef %p) #0 {',
    '  call void @memset(ptr noundef %p, i32 noundef 0, i64 noundef 8)',
    '  ret void',
    '}',
  ].join('\n');
  const c = countIrCallSites(ir, SYMS, 'subject');
  assert.equal(c.inFile, 1);
  assert.equal(c.inFunction, 0);
});

test('the split counts CELLS and the four figures sum to the total', () => {
  // The arithmetic behind "48 of 48": a split whose parts do not sum to the
  // number of cells is a split someone dropped a row from.
  const cells = [
    ...Array.from({ length: 23 }, () => ({ excluded: true, count: 0 })),
    ...Array.from({ length: 25 }, () => ({ excluded: false, count: 1 })),
  ];
  const s = splitByCallSites(cells);
  assert.deepEqual(s, { excludedZero: 23, excludedNonZero: 0, gradedZero: 0, gradedNonZero: 25 });
  assert.equal(splitTotal(s), 48);
  assert.equal(splitIsPerfect(s), true);
});

test('the IR is asked for at -O0, from the corpus file, and written into the lab', () => {
  // Three things that would each produce a plausible count instead of an error.
  // `-O2` would count what the pipeline left rather than what the front end
  // emitted; the lab source (the one with `CONTROL` appended) would give every
  // module a wipe call site by construction; and an output path inside the
  // repository would write a build artefact into the checkout.
  const args = irArgs({ srcPath: 'gen.c', llPath: 'out.ll' });
  assert.deepEqual(args, ['-O0', '-S', '-emit-llvm', 'gen.c', '-o', 'out.ll']);
  assert.equal(args[0], '-O0');
  assert.ok(!args.includes('-c'), 'the IR step compiles to text, not to an object');
  assert.match(irPathOf({ lab: 'LAB', id: 'fable_E_dbpass_r3', cc: 'clang-18' }), /oa\.ir\.fable_E_dbpass_r3\.clang-18\.ll$/);
});

test('the IR step refuses a lab inside the repository, before it runs anything', async () => {
  // No compiler is reached: insideRepo throws first, which is what makes this
  // testable here at all.
  await assert.rejects(
    () => emitIrAtO0({ cc: 'clang-18', srcPath: 'x.c', lab: process.cwd(), id: 'x' }),
    /inside the repository/,
  );
});

test('a split is NOT perfect when O2 refused a cell that had a call site to watch', () => {
  assert.equal(splitIsPerfect(splitByCallSites([
    { excluded: true, count: 1 }, { excluded: false, count: 1 },
  ])), false);
  assert.equal(splitIsPerfect(splitByCallSites([
    { excluded: true, count: 0 }, { excluded: false, count: 0 },
  ])), false);
  // An empty split is not perfect. Nothing was compared.
  assert.equal(splitIsPerfect(splitByCallSites([])), false);
});
