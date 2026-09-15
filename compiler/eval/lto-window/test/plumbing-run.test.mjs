// The which-wipe pipe, end to end, with the compiler taken out of it.
//
// WHY THIS FILE EXISTS
//
// The integration check (tools/check-which-wipe-plumbing.mjs) is the real
// answer: it rebuilds the family and compares against the tracked row. It needs
// clang and lld, so it runs in one CI job and on the development machine, and it
// cannot be the only thing standing under the wiring -- most of the failures it
// exists to catch are failures a fake compiler can produce on demand, and none
// of them should need a toolchain to be TESTED for.
//
// So lib/plumbing-run.mjs takes its builder as an argument, and this file drives
// it with builders that return readings. What is under test here is the wiring:
//
//   that the three sources handed to the compiler are the three the cut made,
//   and that they are three DIFFERENT sources;
//   that the reading of each build reaches the byte count it is supposed to;
//   that the two silent failure modes the ledger names -- a variant that was not
//   rebuilt, a fill counted in another body -- stop at the gates instead of
//   becoming a word;
//   that the positive control's arithmetic really does come out as survival, so
//   the family in lib/pc-fixture.mjs is a control and not decoration.
//
// What it is NOT: evidence about any compiler. Every number here is written by
// the test.

import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { PC_EXPECTED } from '../lib/pc-fixture.mjs';
import { GATE } from '../lib/plumbing-gates.mjs';
import { VARIANTS, gradeFill, runFamily, wordKeyOf } from '../lib/plumbing-run.mjs';
import { WHICH_WIPE } from '../lib/record.mjs';
import { cutWipeVariants } from '../lib/variant-cut.mjs';

/** A use.c with one of each wipe line, in the spelling the cut looks for. */
const SOURCE = [
  'void handle(void) {',
  '    unsigned char key[32];',
  '    derive(key, sizeof key);',
  '    use(key, sizeof key);',
  '    secure_wipe(key, sizeof key);',
  '}',
  'void wipe_kept(void) {',
  '    unsigned char keep[32];',
  '    derive(keep, sizeof keep);',
  '    memset(keep, 0, sizeof keep);',
  '    use(keep, sizeof keep);',
  '}',
].join('\n');

const SPEC = { label: 'fake', caller: 'main', helper: 'secure_wipe', bufferBytes: 32 };

const reading = (bytes, { where = 'main', verdict = 'PRESENT', memsetCalls = 0 } = {}) => ({ verdict, where, bytes, memsetCalls });

/**
 * A builder that answers from a table of byte counts, records what it was asked
 * to compile, and digests the source text it was given -- so "three distinct
 * digests" means "three distinct sources", exactly as it does for the real one.
 */
function fakeBuilder(bytesByTag, opts = {}) {
  const seen = [];
  const build = (spec) => {
    seen.push({ tag: spec.tag, useSource: spec.useSource });
    const b = bytesByTag[spec.tag];
    return {
      tag: spec.tag,
      // digested the way the real builder digests its object: from the bytes
      // that went in, so "three distinct digests" means "three distinct sources"
      // here too. (The two cuts happen to remove lines of equal length, so a
      // digest made of the length would collide -- which is the kind of thing a
      // digest is for.)
      useDigest: opts.frozenDigest ?? createHash('sha256').update(spec.useSource).digest('hex'),
      // and the source that was on disk when the compiler read it, which the
      // real builder reports after reading it back. The object digest is only
      // evidence because the path no longer carries the variant's tag; the
      // source digest is evidence on its own.
      sourceDigest: opts.frozenSource ?? createHash('sha256').update(`src:${spec.useSource}`).digest('hex'),
      subject: reading(b, opts.subject?.[spec.tag] ?? opts.subject ?? {}),
      control: reading(opts.controlBytes ?? b, opts.control ?? {}),
      exe: `/fake/app_${spec.tag}`,
    };
  };
  return [build, seen];
}

test('the three sources that reach the compiler are the cut\'s three, and they differ', () => {
  const variants = cutWipeVariants(SOURCE);
  const [build, seen] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 });
  runFamily({ spec: SPEC, variants, build });

  assert.deepEqual(seen.map((s) => s.tag), [...VARIANTS], 'built in the documented order');
  assert.equal(new Set(seen.map((s) => s.useSource)).size, 3, 'three different sources');
  // and each one is the right cut, not merely different
  assert.equal(seen[0].useSource, SOURCE);
  assert.ok(!/secure_wipe\(key/.test(seen[1].useSource), 'the subject-cut build must not carry the subject wipe');
  assert.ok(/memset\(keep/.test(seen[1].useSource), 'the subject-cut build must still carry the control wipe');
  assert.ok(!/memset\(keep/.test(seen[2].useSource), 'the control-cut build must not carry the control wipe');
  assert.ok(/secure_wipe\(key/.test(seen[2].useSource), 'the control-cut build must still carry the subject wipe');
});

test("the lane's published shape grades as `already gone`, through the gates", () => {
  const [build] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 });
  const r = runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build });
  assert.equal(r.result.failed, null);
  assert.equal(r.word, 'SUBJECT_GONE');
  assert.deepEqual(r.fill, { asWritten: 32, subjectCut: 32, controlCut: 0 });
});

test('the positive control\'s shape grades as survival -- the tool can say the other word', () => {
  // 64 bytes as written (two un-removable wipes in one absorbed body), and each
  // cut takes exactly one of them away. This is the arithmetic the family in
  // lib/pc-fixture.mjs is built to produce; the compiler's part of it is what
  // tools/check-which-wipe-plumbing.mjs checks.
  const both = PC_EXPECTED.controlBytes;
  const one = PC_EXPECTED.subjectBytes;
  const [build] = fakeBuilder({ asWritten: both, subjectCut: one, controlCut: one }, { controlBytes: both });
  const r = runFamily({
    spec: { ...SPEC, bufferBytes: one, controlBytes: both },
    variants: cutWipeVariants(SOURCE),
    build,
  });
  assert.equal(r.result.failed, null);
  assert.equal(r.word, PC_EXPECTED.reading);
  assert.equal(r.fill.asWritten, r.fill.subjectCut + r.fill.controlCut, 'the check requires this to be additive');
});

test('a variant that was not rebuilt never becomes a word', () => {
  // The same digest for all three: a stale work directory, a write that did not
  // land, a cut that deleted nothing. The byte counts below would grade as the
  // lane's published answer if anything were allowed to grade them.
  const [build] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 }, { frozenDigest: 'same' });
  const r = runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build });
  assert.equal(r.result.failed, GATE.DISTINCT_COMPILATIONS);
  assert.equal(r.word, null);
  assert.equal(gradeFill(r.fill).reading, WHICH_WIPE.SUBJECT_GONE, 'and that is what it would have said');
});

test('a cut that removed nothing never becomes a word, before any object is looked at', () => {
  // The three `variants` here are the same text three times: the shape a cut
  // whose pattern matched nothing produces. Every byte count below is the
  // as-written one, which is what makes this the failure mode that reads as
  // the lane's headline answer rather than as an error.
  const noop = { asWritten: SOURCE, subjectCut: { text: SOURCE }, controlCut: { text: SOURCE } };
  const [build, seen] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 });
  const r = runFamily({ spec: SPEC, variants: noop, build });
  assert.equal(new Set(seen.map((x) => x.useSource)).size, 1, 'the three builds saw one source');
  assert.equal(r.result.failed, GATE.DISTINCT_SOURCES);
  assert.equal(r.word, null);
  assert.equal(gradeFill(r.fill).reading, WHICH_WIPE.SUBJECT_GONE, 'and that is what it would have said');
});

test('a fill counted in another body never becomes a word', () => {
  const [build] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 }, { subject: { where: 'wipe_kept' } });
  const r = runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build });
  assert.equal(r.result.failed, GATE.READER_ON_NAMED_BODY);
  assert.equal(r.word, null);
});

test('a blind as-written control never becomes a word', () => {
  const [build] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 }, { control: { verdict: 'ABSENT' } });
  const r = runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build });
  assert.equal(r.result.failed, GATE.CONTROL_PRESENT);
  assert.equal(r.word, null);
});

test('a surviving memset call is refused, not counted as the bytes that are visible', () => {
  const [build] = fakeBuilder({ asWritten: 32, subjectCut: 32, controlCut: 0 }, { subject: { memsetCalls: 1 } });
  const r = runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build });
  assert.deepEqual(r.memsetIn, [...VARIANTS]);
  assert.equal(r.word, 'INCONCLUSIVE');
  assert.match(r.result.subject.why, /whose length this reading cannot see/);
});

test('gradeFill is the one grader, and it names the memset refusal over the arithmetic', () => {
  // The tool and the check both call this. If they ever grade differently, it
  // is because one of them stopped calling it.
  assert.equal(gradeFill({ asWritten: 32, subjectCut: 0, controlCut: 0 }).reading, WHICH_WIPE.SUBJECT_PRESENT);
  assert.equal(gradeFill({ asWritten: 32, subjectCut: 0, controlCut: 0 }, ['asWritten']).reading, WHICH_WIPE.INCONCLUSIVE);
  assert.equal(wordKeyOf(gradeFill({ asWritten: 0, subjectCut: 0, controlCut: 0 })), 'BLIND');
  assert.equal(wordKeyOf(null), null);
});

test('a builder that throws is not caught here -- the caller decides what a failed build means', () => {
  const boom = () => { throw new Error('did not link'); };
  assert.throws(() => runFamily({ spec: SPEC, variants: cutWipeVariants(SOURCE), build: boom }), /did not link/);
});
