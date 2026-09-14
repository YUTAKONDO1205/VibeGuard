/**
 * The gcc `-fdisable-tree-<pass>` channel, checked without a compiler.
 *
 * `../tools/intervene.mjs` drives gcc and therefore cannot be unit-tested; what
 * it decides with lives in `../lib/gcc-disable-tree.mjs`, which is pure, and
 * this file is where those decisions are pinned. The ones that matter are the
 * ones that keep a reading from being taken when nothing was measured:
 *
 *   - a dump that does not hold the function is NOT_OBSERVED, never a loss;
 *   - a build that succeeded without gcc announcing the disable is `no-note`,
 *     which is fatal -- an ignored flag and an honoured flag exit the same way;
 *   - a survival whose control went missing is not a property coming back.
 *
 * The two gcc messages quoted here are the ones gcc-13 printed on the machine
 * this channel was written for; they are quoted verbatim so that a change in
 * gcc's wording fails here, loudly, rather than turning every control into a
 * silent false.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  STAGES, DUMP_SUFFIX_RE, READING_STATUSES, FATAL_READING_STATUSES,
  WALK_STATUSES, FATAL_WALK_STATUSES, MAX_UNPAIRED_SHARE, GCC_EXIT_REASONS,
  dumpSuffix, orderDumps, gimpleRegionOf, dumpState, memsetTokenPresent,
  buildDumpSequence, firstIndifferentDump, observedDumps, transitionsOf, flipBacks,
  unpairedReading, refusalSplit, brokenBecause,
  disableTreeFlag, disableNoteSeen, unknownPassRefused, misspell,
  readingStatus, cameBack,
} from '../lib/gcc-disable-tree.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LANE = path.resolve(HERE, '..');

/** gcc-13, `-O2 -c x.c -fdisable-tree-dse1`, on stderr, exit 0. */
const NOTE = 'cc1: note: disable pass tree-dse1 for functions in the range of [0, 4294967295]\n';
/** gcc-13, `-O2 -c x.c -fdisable-tree-dsexx`, on stderr, exit 1. */
const REFUSAL = "cc1: error: unknown pass tree-dsexx specified in '-fdisable'\n";

/** A dump region for `fn`, as gcc lays one out. */
const dump = (fn, body, extra = '') =>
  `\n;; Function ${fn} (${fn}, funcdef_no=0, decl_uid=1234, cgraph_uid=1, symbol_order=0)\n\n`
  + `${fn} ()\n{\n${body}\n}\n${extra}`;

// ---------------------------------------------------------------------------
// reading gcc's dump file names

test('a dump file name is read for its number, its stage and its pass, and nothing else is', () => {
  assert.deepEqual(dumpSuffix('out.s.042t.dse1'), { num: 42, stage: 't', pass: 'dse1', key: '042t.dse1' });
  assert.deepEqual(dumpSuffix('w.c.229r.final'), { num: 229, stage: 'r', pass: 'final', key: '229r.final' });
  assert.deepEqual(dumpSuffix('out.s.000i.cgraph'), { num: 0, stage: 'i', pass: 'cgraph', key: '000i.cgraph' });
  // the things that share the directory with the dumps
  for (const f of ['out.s', 'out.o', 'w.c', 'run-log.txt', 'out.s.dot']) {
    assert.equal(dumpSuffix(f), null, `${f} is not a dump file`);
  }
  assert.ok(DUMP_SUFFIX_RE.test('x.042t.dse1'));
});

test('the walk is in gcc\'s order, which is numeric and not lexical', () => {
  const files = ['out.s.116t.dse2', 'out.s.009t.omplower', 'out.s.042t.dse1', 'out.s.229r.final', 'out.s.043t.cddce1'];
  assert.deepEqual(orderDumps(files).map((d) => d.key),
    ['009t.omplower', '042t.dse1', '043t.cddce1', '116t.dse2', '229r.final']);
  // gcc pads to three digits, so on this list lexical order happens to agree.
  // It is the NUMBER that orders them, and an unpadded list is where the two part:
  const unpadded = ['x.42t.b', 'x.9t.a'];
  assert.deepEqual(orderDumps(unpadded).map((d) => d.key), ['9t.a', '42t.b']);
  assert.deepEqual([...unpadded].sort(), ['x.42t.b', 'x.9t.a'], 'sorted as text, 42 comes first');
  // anything that is not a dump is dropped rather than ordered somewhere
  assert.deepEqual(orderDumps(['out.s', 'out.s.042t.dse1']).map((d) => d.key), ['042t.dse1']);
});

test('only the GIMPLE stage is in this channel; RTL and IPA name their own flag and are not driven', () => {
  assert.deepEqual(Object.keys(STAGES).sort(), ['i', 'r', 't']);
  assert.equal(STAGES.t.inScope, true);
  assert.equal(STAGES.t.flag, '-fdisable-tree-');
  assert.equal(STAGES.r.inScope, false);
  assert.equal(STAGES.i.inScope, false);
  assert.equal(disableTreeFlag('dse1'), '-fdisable-tree-dse1');
});

// ---------------------------------------------------------------------------
// slicing one function out of a dump

test('a region is the function\'s body: the header line with its uids is not part of it', () => {
  const text = dump('handle_request', '  __builtin_memset (&secret, 0, 32);\n  return;')
    + dump('wipe_kept', '  __builtin_memset (&s2, 0, 32);');
  const r = gimpleRegionOf(text, 'handle_request');
  assert.ok(!r.includes('decl_uid'), 'the uid-carrying header must not be compared as if it were the body');
  assert.ok(r.includes('__builtin_memset (&secret, 0, 32);'));
  assert.ok(!r.includes('&s2'), 'the region must stop at the next function');
  // blank lines are formatting, and the region holds none
  assert.ok(!r.split('\n').some((l) => l.trim() === ''));
});

test('a dump that does not hold the function returns null, which is not an empty body', () => {
  assert.equal(gimpleRegionOf(dump('wipe_kept', '  x;'), 'handle_request'), null);
  assert.equal(gimpleRegionOf('', 'handle_request'), null);
  assert.notEqual(gimpleRegionOf(dump('handle_request', ''), 'handle_request'), null);
});

test('a name that only PREFIXES the function\'s name is a different function', () => {
  const text = dump('handle_request_helper', '  a;') + dump('handle_request', '  b;');
  assert.equal(gimpleRegionOf(text, 'handle_request'), 'handle_request ()\n{\n  b;\n}');
});

// ---------------------------------------------------------------------------
// the differential state of one dump

test('the state of a dump is differential, exactly as every other verdict in this lane is', () => {
  const withWipe = dump('handle_request', '  consume (&secret);\n  __builtin_memset (&secret, 0, 32);');
  const ablated = dump('handle_request', '  consume (&secret);');
  const same = dump('handle_request', '  consume (&secret);');
  assert.equal(dumpState(withWipe, ablated, 'handle_request'), 'WIPE_SURVIVED');
  assert.equal(dumpState(same, ablated, 'handle_request'), 'WIPE_ELIMINATED');
});

test('a dump that saw nothing is NOT_OBSERVED and is never read as a loss', () => {
  const held = dump('handle_request', '  a;');
  const missing = dump('wipe_kept', '  a;');
  assert.equal(dumpState(held, missing, 'handle_request'), 'NOT_OBSERVED');
  assert.equal(dumpState(missing, held, 'handle_request'), 'NOT_OBSERVED');
  assert.equal(dumpState(missing, missing, 'handle_request'), 'NOT_OBSERVED',
    'two dumps that both lack the function are two blind readings, not an elimination');
});

test('the token reading is beside the verdict and is not one', () => {
  assert.equal(memsetTokenPresent(dump('handle_request', '  __builtin_memset (&s, 0, 32);'), 'handle_request'), true);
  assert.equal(memsetTokenPresent(dump('handle_request', '  MEM[(char *)&s] = 0;'), 'handle_request'), false);
  assert.equal(memsetTokenPresent(dump('wipe_kept', '  x;'), 'handle_request'), null,
    'no function is not "no memset"');
});

// ---------------------------------------------------------------------------
// the walk

const seqOf = (states) => states.map((state, i) => ({
  key: `${String(i).padStart(3, '0')}t.p${i}`, num: i, stage: 't', pass: `p${i}`, state, memsetToken: null,
}));

test('firstIndifferentDump is the first dump at which the wipe stops making a difference', () => {
  const r = firstIndifferentDump(seqOf(['WIPE_SURVIVED', 'WIPE_SURVIVED', 'WIPE_ELIMINATED', 'WIPE_ELIMINATED']));
  assert.equal(r.status, 'first-indifferent-dump-located');
  assert.equal(r.entry.key, '002t.p2');
  assert.equal(r.entry.pass, 'p2');
});

test('a wipe that never made a difference locates nothing, and says that rather than naming dump 0', () => {
  const r = firstIndifferentDump(seqOf(['WIPE_ELIMINATED', 'WIPE_ELIMINATED']));
  assert.equal(r.status, 'indifferent-from-first-dump');
  assert.equal(r.entry, null);
});

test('a wipe that still made a difference in the last dump locates nothing either', () => {
  const r = firstIndifferentDump(seqOf(['WIPE_SURVIVED', 'WIPE_SURVIVED']));
  assert.equal(r.status, 'no-indifference-observed');
  assert.equal(r.entry, null);
});

test('a dump nobody could read does not start the walk, and does not end it', () => {
  const r = firstIndifferentDump(seqOf(['NOT_OBSERVED', 'WIPE_ELIMINATED', 'WIPE_SURVIVED', 'WIPE_ELIMINATED']));
  assert.equal(r.status, 'first-indifferent-dump-located');
  assert.equal(r.entry.key, '003t.p3', 'the leading NOT_OBSERVED cannot make dump 1 a disappearance');
});

// ---------------------------------------------------------------------------
// THE WALK'S POSITIVE CONTROL: a walk that read nothing is not a reading
//
// This is the silent pass the channel shipped with. A walk in which NOT ONE dump
// held the function answered `absent-from-first-dump` -- documented as the
// substantive finding "the wipe made no difference in any dump gcc emits" -- and
// the run exited 0. The apparatus finding nothing to read and the wipe making no
// difference are different words now, and only one of them is a result.

test('a walk in which no dump held the function is an apparatus failure, not a finding about the wipe', () => {
  const r = firstIndifferentDump(seqOf(['NOT_OBSERVED', 'NOT_OBSERVED', 'NOT_OBSERVED']));
  assert.equal(r.status, 'function-in-no-dump');
  assert.equal(r.entry, null);
  assert.ok(FATAL_WALK_STATUSES.includes(r.status), 'a walk that compared nothing must be fatal, not a result');
  assert.notEqual(r.status, 'indifferent-from-first-dump',
    'a walk that read nothing must not answer in the words of a walk that read something and found no difference');
});

test('the two answers that look alike are told apart by whether the function was read at all', () => {
  const readNothing = seqOf(['NOT_OBSERVED', 'NOT_OBSERVED']);
  const readSomething = seqOf(['NOT_OBSERVED', 'WIPE_ELIMINATED']);
  assert.equal(observedDumps(readNothing), 0);
  assert.equal(observedDumps(readSomething), 1);
  assert.equal(firstIndifferentDump(readNothing).status, 'function-in-no-dump');
  assert.equal(firstIndifferentDump(readSomething).status, 'indifferent-from-first-dump');
  assert.equal(observedDumps([]), 0, 'an empty walk read nothing either');
  assert.deepEqual([...WALK_STATUSES].sort(),
    ['first-indifferent-dump-located', 'function-in-no-dump', 'indifferent-from-first-dump', 'no-indifference-observed']);
  assert.deepEqual([...FATAL_WALK_STATUSES], ['function-in-no-dump']);
});

// ---------------------------------------------------------------------------
// the dump sets themselves, compared

test('dumps present in one unit and not the other are counted, shared and thresholded', () => {
  const none = unpairedReading({ paired: 122, onlyW: [], onlyWo: [] });
  assert.deepEqual([none.unpaired, none.union, none.share, none.overThreshold], [0, 122, 0, false]);
  const few = unpairedReading({ paired: 120, onlyW: ['042t.dse1'], onlyWo: [] });
  assert.equal(few.overThreshold, false, '1 of 121 is under the threshold: reported, not refused');
  const many = unpairedReading({ paired: 5, onlyW: ['a', 'b', 'c'], onlyWo: ['d'] });
  assert.equal(many.unpaired, 4);
  assert.equal(many.union, 9);
  assert.equal(many.overThreshold, true, 'a walk that dropped 4 of 9 dumps is not the walk either compilation produced');
  assert.equal(many.maxShare, MAX_UNPAIRED_SHARE);
  assert.equal(unpairedReading({ paired: 0, onlyW: [], onlyWo: [] }).overThreshold, false,
    'a walk with no dumps at all is NO_DUMPS, which is a different refusal');
});

// ---------------------------------------------------------------------------
// gcc's refusal, read in both units of the differential

test('a refusal counts when BOTH units refused; one-sided is asymmetric and is not a refusal', () => {
  const refused = { code: 1, stderr: REFUSAL };
  const built = { code: 0, stderr: '' };
  const both = refusalSplit(refused, refused, ['dsexx']);
  assert.deepEqual(both.refusedBy, ['dsexx']);
  assert.deepEqual(both.asymmetric, []);
  const oneSided = refusalSplit(refused, built, ['dsexx']);
  assert.deepEqual(oneSided.refusedBy, [], 'half a refusal is not a refusal in a differential channel');
  assert.deepEqual(oneSided.asymmetric, ['dsexx']);
  assert.deepEqual(oneSided.refusedInW, ['dsexx']);
  assert.deepEqual(oneSided.refusedInWo, []);
  // and the reading built from it is fatal rather than a refusal the walk moves past
  assert.equal(readingStatus({ refusedBy: oneSided.refusedBy, codes: { w: 1, wo: 0 }, noteOk: false }), 'compile-failed');
  assert.equal(readingStatus({ refusedBy: both.refusedBy, codes: { w: 1, wo: 1 }, noteOk: false }), 'refused-by-gcc');
});

// ---------------------------------------------------------------------------
// the refusal reasons, which are what a reader transcribes

test('every refusal this channel can make has a name, a true sentence, and no other way to say it', () => {
  for (const [key, sentence] of Object.entries(GCC_EXIT_REASONS)) {
    assert.match(key, /^[A-Z_]+$/, `${key} is not a machine-readable reason key`);
    assert.ok(sentence.length > 30, `${key}: the reason has to say what happened`);
    const v = brokenBecause(key);
    assert.equal(v.verdict, 'BROKEN_MEASUREMENT');
    assert.equal(v.reason, key);
    assert.equal(v.why, sentence);
  }
  assert.equal(brokenBecause('NO_DUMPS', 'the walk compared 0 dumps').why,
    `${GCC_EXIT_REASONS.NO_DUMPS} -- the walk compared 0 dumps`);
  assert.throws(() => brokenBecause('SOMETHING_ELSE'), /not one of this channel/,
    'a refusal nobody named must not be able to become a sentence');
  // the no-note fatality in particular: it used to be reported with the gate's
  // sentence about a control that had in fact been PRESENT
  assert.ok(!/positive control/.test(GCC_EXIT_REASONS.INTERVENTION_NOT_ANNOUNCED),
    'the no-note reason must not be stated as a control failure: the controls held, and the disable was not announced');
  assert.match(GCC_EXIT_REASONS.INTERVENTION_NOT_ANNOUNCED, /announc/);
});

test('PIN-FAMILIES.md names every refusal reason, so none of them is a word only the code knows', () => {
  const prose = readFileSync(path.join(LANE, 'PIN-FAMILIES.md'), 'utf8');
  for (const key of Object.keys(GCC_EXIT_REASONS)) {
    assert.ok(prose.includes(key), `PIN-FAMILIES.md does not name the exit reason ${key}`);
  }
  for (const w of WALK_STATUSES) {
    assert.ok(prose.includes(w), `PIN-FAMILIES.md does not name the walk outcome ${w}`);
  }
});

test('the whole sequence is kept: every state change, and every flip back', () => {
  const seq = seqOf(['WIPE_SURVIVED', 'WIPE_ELIMINATED', 'WIPE_SURVIVED', 'WIPE_ELIMINATED']);
  assert.deepEqual(transitionsOf(seq).map((t) => `${t.from}->${t.to}@${t.at}`),
    ['WIPE_SURVIVED->WIPE_ELIMINATED@001t.p1', 'WIPE_ELIMINATED->WIPE_SURVIVED@002t.p2', 'WIPE_SURVIVED->WIPE_ELIMINATED@003t.p3']);
  assert.deepEqual(flipBacks(seq), ['002t.p2'], 'a walk that is not monotone must say so');
  assert.deepEqual(flipBacks(seqOf(['WIPE_SURVIVED', 'WIPE_ELIMINATED'])), []);
});

test('buildDumpSequence reads each dump pair once, in the order it was given', () => {
  const dumps = [
    { key: '042t.dse1', num: 42, stage: 't', pass: 'dse1', w: dump('f', '  __builtin_memset (&s, 0, 32);'), wo: dump('f', '  x;') },
    { key: '116t.dse2', num: 116, stage: 't', pass: 'dse2', w: dump('f', '  x;'), wo: dump('f', '  x;') },
  ];
  const seq = buildDumpSequence(dumps, 'f');
  assert.deepEqual(seq.map((e) => [e.key, e.state, e.memsetToken]),
    [['042t.dse1', 'WIPE_SURVIVED', true], ['116t.dse2', 'WIPE_ELIMINATED', false]]);
  assert.equal(firstIndifferentDump(seq).entry.pass, 'dse2');
});

// ---------------------------------------------------------------------------
// control (a): gcc announces the disable, or the intervention did not happen

test('the disable note must name the pass that was asked for', () => {
  assert.equal(disableNoteSeen(NOTE, 'dse1'), true);
  assert.equal(disableNoteSeen('', 'dse1'), false, 'no note is no intervention');
  assert.equal(disableNoteSeen('cc1: some other warning\n', 'dse1'), false);
});

test('a note naming a DIFFERENT pass does not satisfy the one that was asked for', () => {
  const other = 'cc1: note: disable pass tree-dse11 for functions in the range of [0, 4294967295]\n';
  assert.equal(disableNoteSeen(other, 'dse1'), false, 'tree-dse11 is not tree-dse1');
  assert.equal(disableNoteSeen(NOTE, 'dse11'), false);
  assert.equal(disableNoteSeen(other, 'dse11'), true);
  // and the sentence has to be the disable one, not the pass name appearing anywhere
  assert.equal(disableNoteSeen('cc1: note: pass tree-dse1 ran\n', 'dse1'), false);
});

// ---------------------------------------------------------------------------
// control (b): gcc checks the channel, so a missing note means something

test('a pass name gcc does not know must FAIL the build to count as a refusal', () => {
  assert.equal(unknownPassRefused({ code: 1, stderr: REFUSAL }, 'dsexx'), true);
  assert.equal(unknownPassRefused({ code: 0, stderr: REFUSAL }, 'dsexx'), false,
    'a message with exit 0 is not a build that failed, and this control is about failing closed');
  assert.equal(unknownPassRefused({ code: 1, stderr: 'cc1: error: something else\n' }, 'dsexx'), false);
  assert.equal(unknownPassRefused({ code: 1, stderr: REFUSAL }, 'dse1'), false,
    'the refusal has to be about the name that was sent');
  assert.equal(unknownPassRefused(null, 'dsexx'), false);
});

test('the misspelling is built so that it cannot accidentally name a real pass', () => {
  assert.equal(misspell('dse1'), 'dse1xx');
  assert.equal(misspell('dse1', ['dse1', 'dse2']), 'dse1xx');
  assert.equal(misspell('dse1', ['dse1xx']), 'dse1xxx', 'a collision with a pass the run saw is extended, not shipped');
  assert.equal(misspell('dse1', ['dse1xx', 'dse1xxx']), 'dse1xxxx');
});

// ---------------------------------------------------------------------------
// what a reading is, and when the property came back

const reading = (over = {}) => ({
  refusedBy: [], codes: { w: 0, wo: 0 }, noteOk: true,
  asm: { verdict: 'WIPE_SURVIVED', control: 'PRESENT' },
  fixtureControl: { verdict: 'PRESENT', via: 'oracle' },
  ...over,
});

test('a build that succeeded without the note is `no-note`, and `no-note` is fatal', () => {
  assert.equal(readingStatus(reading({ noteOk: false })), 'no-note');
  assert.ok(FATAL_READING_STATUSES.includes('no-note'));
  assert.ok(FATAL_READING_STATUSES.includes('compile-failed'));
  assert.ok(!FATAL_READING_STATUSES.includes('refused-by-gcc'),
    'gcc refusing a name it does not know is the channel working, not a broken run');
  assert.deepEqual([...READING_STATUSES].sort(), ['compile-failed', 'intervened', 'no-note', 'refused-by-gcc']);
});

test('the four reading words, each from the state that produces it', () => {
  assert.equal(readingStatus(reading()), 'intervened');
  assert.equal(readingStatus(reading({ refusedBy: ['optimized'], codes: { w: 1, wo: 1 }, noteOk: false })), 'refused-by-gcc');
  assert.equal(readingStatus(reading({ codes: { w: 1, wo: 0 } })), 'compile-failed');
  assert.equal(readingStatus(reading({ codes: { w: 0, wo: 1 } })), 'compile-failed',
    'the ablated unit failing is as fatal as the written one failing: the verdict is differential');
});

test('"it came back" needs the intervention to have happened AND both controls to have held', () => {
  assert.equal(cameBack(reading()), true);
  assert.equal(cameBack(reading({ noteOk: false })), false, 'nothing was disabled, so nothing came back');
  assert.equal(cameBack(reading({ asm: { verdict: 'WIPE_ELIMINATED', control: 'PRESENT' } })), false);
  assert.equal(cameBack(reading({ asm: { verdict: 'WIPE_SURVIVED', control: 'ABSENT' } })), false,
    'a survival read where the co-resident control went missing is a blind oracle');
  assert.equal(cameBack(reading({ fixtureControl: { verdict: 'ABSENT', via: null } })), false);
  assert.equal(cameBack(reading({ refusedBy: ['optimized'] })), false);
});

// ---------------------------------------------------------------------------
// the vocabulary rule, as a test rather than as a sentence in a header

test('neither the gcc channel nor the tool emits clang\'s word for its result', () => {
  for (const rel of ['lib/gcc-disable-tree.mjs', 'tools/intervene.mjs']) {
    const src = readFileSync(path.join(LANE, rel), 'utf8');
    const hits = src.split('\n').filter((l) => /firstLossPass/.test(l) && !/never|not emit|emits no|doesNotEmit/.test(l));
    assert.deepEqual(hits, [],
      `${rel} names firstLossPass outside the sentence that refuses it; that word belongs to the pass-plugin observer, not to gcc's self-report`);
  }
  const tool = readFileSync(path.join(LANE, 'tools', 'intervene.mjs'), 'utf8');
  assert.ok(tool.includes('firstIndifferentDump'), 'the gcc channel emits firstIndifferentDump');
  // and the gcc rows do not land in the clang column: the keys differ by name
  assert.ok(tool.includes('firstIndifferentDumpAfter'));
  assert.ok(tool.includes('disabledPasses'));
  // NOR under the NEIGHBOURING gcc probe's name. That probe reads ONE unit's
  // dump region for a memset token; this channel compares the two units'
  // regions. Same dumps, different oracle, different statement -- so the word is
  // not reused as a field name, and both files say why in the place it is used.
  for (const rel of ['lib/gcc-disable-tree.mjs', 'tools/intervene.mjs']) {
    const src = readFileSync(path.join(LANE, rel), 'utf8');
    assert.equal(/firstAbsentDump\s*:/.test(src), false,
      `${rel} uses firstAbsentDump as a field name; that word is the token-oracle probe's, in ../../second-vendor`);
    assert.equal(/\.firstAbsentDump\b/.test(src), false, `${rel} reads a firstAbsentDump field`);
    assert.ok(/different oracle|SEARCHING ONE UNIT|memset token/.test(src),
      `${rel} must state how its reading differs from the neighbour's, since the two are one word apart`);
  }
});
