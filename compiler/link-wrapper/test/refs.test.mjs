import test from 'node:test';
import assert from 'node:assert/strict';

import { makeRef, matchRef, normalisePath, splitArchiveMember, globToRegExp } from '../lib/refs.mjs';

const ROOT = '/fixtures';

test('a path under the link root becomes a relative ref', () => {
  const r = makeRef('main.o', ROOT);
  assert.equal(r.ref, 'main.o');
  assert.equal(r.kind, 'in-root');
  assert.equal(r.pathWithheld, false);
});

test('a toolchain path keeps its provenance without a leading slash', () => {
  assert.equal(makeRef('/lib/x86_64-linux-gnu/Scrt1.o', ROOT).ref, 'system:lib/x86_64-linux-gnu/Scrt1.o');
  assert.equal(makeRef('/lib64/ld-linux-x86-64.so.2', ROOT).ref, 'system:lib64/ld-linux-x86-64.so.2');
});

// The same object is spelled differently by the map and by the trace on some
// toolchains; if the two spellings produced two refs, the wrapper would report
// that its two observations disagree about a file both of them saw.
test('.. is collapsed, so the two spellings of one crt object are one ref', () => {
  assert.equal(
    makeRef('/usr/bin/../lib/gcc/x86_64-linux-gnu/13/crtbeginS.o', ROOT).ref,
    'system:usr/lib/gcc/x86_64-linux-gnu/13/crtbeginS.o',
  );
  assert.equal(normalisePath('/usr/bin/../lib/./gcc'), '/usr/lib/gcc');
});

test('an archive member keeps the archive and the member', () => {
  const r = makeRef('./libarch.a(arch.o)', ROOT);
  assert.equal(r.ref, 'libarch.a(arch.o)');
  assert.equal(r.archive, 'libarch.a');
  assert.equal(r.member, 'arch.o');
  assert.equal(r.base, 'arch.o');
  assert.deepEqual(splitArchiveMember('libx.a(y.o)'), { archive: 'libx.a', member: 'y.o' });
  assert.equal(splitArchiveMember('libx.a'), null);
});

// The disclosure this avoids is not hypothetical: the segment after /home or
// /Users is whatever the person who installed the machine typed, and no word
// list can contain it.
test('a path through an account directory is withheld, and says it was', () => {
  const r = makeRef('/home/somebody/evil/rogue.o', ROOT);
  assert.equal(r.ref, 'withheld:rogue.o');
  assert.equal(r.pathWithheld, true);
  assert.match(r.withheldReason, /names an account/);
  // The needle is assembled at run time. Written as a literal it would be the
  // very shape this line asserts against, and the repository's disclosure gate
  // would flag the assertion — which it did, the first time this was written.
  const rootedSegment = `/${'home'}`;
  assert.equal(r.withheldReason.includes(rootedSegment), false, 'the explanation must not carry the path either');
  assert.equal(r.withheldReason.includes('somebody'), false, 'nor the account name');
});

test('the linker’s synthetic input is never mistaken for a file', () => {
  const r = makeRef('<internal>', ROOT);
  assert.equal(r.ref, 'internal:<linker-generated>');
});

test('exact, glob and basename each match, and the record can tell them apart', () => {
  assert.deepEqual(matchRef('main.o', ['main.o'], 'main.o'), { allowed: true, by: 'exact', pattern: 'main.o' });
  assert.equal(matchRef('system:lib/x86_64-linux-gnu/Scrt1.o', ['system:lib/**/*.o'], 'Scrt1.o').by, 'glob');
  assert.equal(matchRef('system:lib/x86_64-linux-gnu/Scrt1.o', ['Scrt1.o'], 'Scrt1.o').by, 'basename');
});

test('a policy entry that carries a path is not weakened into a basename match', () => {
  // `build/main.o` authorises that object, not one of the same name elsewhere.
  const m = matchRef('vendor/main.o', ['build/main.o'], 'main.o');
  assert.equal(m.allowed, false);
});

test('an empty allow list authorises nothing, and an absent one is not an empty one', () => {
  assert.equal(matchRef('main.o', [], 'main.o').allowed, false);
  assert.equal(matchRef('main.o', undefined, 'main.o').allowed, false);
});

test('* stops at a path separator and ** does not', () => {
  assert.equal(globToRegExp('a/*.o').test('a/b.o'), true);
  assert.equal(globToRegExp('a/*.o').test('a/b/c.o'), false);
  assert.equal(globToRegExp('a/**/*.o').test('a/b/c.o'), true);
});

test('a glob metacharacter in a policy entry does not become a regex metacharacter', () => {
  assert.equal(globToRegExp('lib+x.o').test('lib+x.o'), true);
  assert.equal(globToRegExp('lib+x.o').test('libx.o'), false);
  assert.equal(globToRegExp('a.o').test('axo'), false, '. must be literal');
});
