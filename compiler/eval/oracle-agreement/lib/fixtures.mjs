/**
 * The synthetic sources the two apparatus checks put questions to.
 *
 * WHY THEY ARE HERE AND NOT IN THE CHECKS THAT USE THEM
 *
 * A fixture whose expected answer is written beside it is only a control if the
 * fixture is the thing it is supposed to be. These were twice not:
 *
 *   `void handle(void)` — `wipeSpans` classifies a VOID function whose body
 *   zeroes as a wipe HELPER, and the helper's own definition then matches the
 *   call-name scan, so the fixture came back with two spans and was refused as
 *   multi-span. Every erasure subject in the corpus returns `int`, which is why
 *   the corpus never hits it.
 *
 *   `__builtin_memset` — the call-name scan is `\bmemset\s*\(`, and the
 *   character before `memset` in that spelling is an underscore, which is a word
 *   character, so there is no boundary and the fixture held NO wipe at all.
 *
 * Either mistake makes a check report a WORKING read-out as broken. A control
 * that cries wolf is worth less than no control, because the first thing anybody
 * does with one is stop running it.
 *
 * So the fixtures live in a module with no side effects, and
 * `../test/fixtures.test.mjs` puts them through `locateWipe` — the same function
 * the lane uses — on every host, with no compiler. The shape is checked where it
 * is cheap to check; the compiler answers the question the shape was built to
 * ask.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

/** The buffer every fixture here wipes. The one literal a fixture is allowed. */
export const FIXTURE_BYTES = Object.freeze({ kept: 48, short: 64, apparatus: 32 });

/**
 * A subject in the corpus's shape: returns `int`, wipes with `memset`, and takes
 * its buffer from a producer and hands it to a consumer that the caller cannot
 * see into.
 *
 * @param {object} o
 * @param {number} o.bytes      the buffer's size
 * @param {string} [o.len]      the wipe's length argument (default `sizeof key`)
 * @param {boolean} [o.readAfter] read the buffer after the wipe, which makes the
 *   wipe unremovable at every level -- the difference between the two apparatus
 *   fixtures and nothing else
 * @param {string} [o.fn]       the subject's name
 * @param {boolean} [o.noinline] keep the subject a function the disassembly
 *   reader can be pointed at
 * @param {boolean} [o.runtimeLength] take the buffer and its length as
 *   parameters, so the wipe's length is not a constant expression
 */
export function subjectSource({
  bytes, len = 'sizeof key', readAfter = false, fn = 'handle',
  noinline = false, runtimeLength = false, producer = 'fill', consumer = 'use',
} = {}) {
  const lines = [
    '#include <string.h>',
    `void ${producer}(unsigned char *p, unsigned long n);`,
    `void ${consumer}(const unsigned char *p, unsigned long n);`,
  ];
  if (noinline) lines.push('__attribute__((noinline))');
  if (runtimeLength) {
    lines.push(`int ${fn}(unsigned char *key, unsigned long n) {`);
    lines.push(`  ${producer}(key, n);`);
    lines.push('  memset(key, 0, n);');
  } else {
    lines.push(`int ${fn}(void) {`);
    lines.push(`  unsigned char key[${bytes}];`);
    lines.push(`  ${producer}(key, sizeof key);`);
    lines.push(`  ${consumer}(key, sizeof key);`);
    lines.push(`  memset(key, 0, ${len});`);
  }
  if (readAfter) lines.push(`  ${consumer}(key, sizeof key);`);
  lines.push('  return 0;');
  lines.push('}');
  return `${lines.join('\n')}\n`;
}

/**
 * THERE IS NO SECOND TRANSLATION UNIT HERE, AND THAT IS DELIBERATE.
 *
 * `../../lto-window/tools/make-lto-fixtures.sh` writes a separate `io.c` so that
 * the producer and consumer are opaque to the compiler. This lane does not need
 * one: `lib/disasm.mjs` links a fragment by stubbing exactly the symbols the
 * LINKER named as unresolved, in their own unit, so `vg_derive`, `vg_use` and
 * the control's `vgctl_fill` / `vgctl_use` get empty definitions the link is
 * satisfied by.
 *
 * The opacity survives, because the opacity is a COMPILE-time property. This is
 * not an LTO link; the subject's object is already emitted when the stubs are
 * produced, and at the point the compiler decided whether the wipe was a dead
 * store, `vg_use` was an external function it could not see into. A written-out
 * `io.c` would have been a second source of the same opacity and one more file
 * for the two fixtures to drift apart through.
 */

/**
 * The apparatus fixture set's own shape, pinned.
 *
 * Two fixtures, named, in this order. `check-o3-apparatus.mjs` reads them by
 * name and compares their two readings; a set of any other size or naming makes
 * that comparison a comparison of nothing, which is why the numbers are here
 * rather than implied by the array below.
 */
export const APPARATUS_FIXTURE_NAMES = Object.freeze(['kept', 'removed']);
export const APPARATUS_FIXTURE_COUNT = APPARATUS_FIXTURE_NAMES.length;

/** The subject name the apparatus fixtures use. */
export const APPARATUS_FN = 'vg_handle';

/**
 * The two fixtures the O3 apparatus check reads, and the word each must produce.
 *
 * They differ by ONE line — whether the buffer is read after the wipe — so
 * "nothing else changed between the positive control and the discriminating
 * half" is a property of this generator rather than a claim in a comment.
 */
export const APPARATUS_FIXTURES = Object.freeze([
  Object.freeze({
    name: 'kept',
    expect: 'PRESENT',
    why: 'the buffer is read after the wipe by a function the link cannot see into',
    src: subjectSource({
      bytes: FIXTURE_BYTES.apparatus, fn: APPARATUS_FN, noinline: true, readAfter: true,
      producer: 'vg_derive', consumer: 'vg_use',
    }),
  }),
  Object.freeze({
    name: 'removed',
    expect: 'ABSENT',
    why: 'the wipe is the last use of the buffer, so it is a dead store at this level',
    src: subjectSource({
      bytes: FIXTURE_BYTES.apparatus, fn: APPARATUS_FN, noinline: true, readAfter: false,
      producer: 'vg_derive', consumer: 'vg_use',
    }),
  }),
]);

/**
 * THE INVENTORY THE APPARATUS CHECK IS ENTITLED TO ASSUME, as a function rather
 * than as a comment.
 *
 * `tools/check-o3-apparatus.mjs` loops over `APPARATUS_FIXTURES`, collects one
 * reading per fixture, and then asks whether the two readings differ. Written
 * that way, an EMPTY list -- or a renamed fixture, or two fixtures that expect
 * the same word -- makes every one of those steps succeed over nothing: the loop
 * runs zero times, the comparison of `readings.kept` against `readings.removed`
 * compares `undefined` with `undefined` behind an `undefined` guard, and the
 * tool exits 0 having compiled nothing and discriminated nothing. A positive
 * control that reports "no problem" when it was never run is worse than none.
 *
 * So the check reads the shape of its own fixture set FIRST, and this is the
 * function that decides it. Pure, so `../test/fixtures.test.mjs` can hand it a
 * mutilated inventory on a host with no compiler.
 *
 * @param {ReadonlyArray<object>} fixtures defaults to the real set
 * @returns {string[]} empty only when the set can carry the check
 */
export function apparatusInventoryProblems(fixtures = APPARATUS_FIXTURES) {
  const problems = [];
  if (!Array.isArray(fixtures) || fixtures.length !== APPARATUS_FIXTURE_COUNT) {
    problems.push(`the apparatus fixture set holds ${Array.isArray(fixtures) ? fixtures.length : 'no'} `
      + `fixture(s) and the check is written for ${APPARATUS_FIXTURE_COUNT}`);
    return problems;
  }
  const names = fixtures.map((f) => f && f.name);
  for (const want of APPARATUS_FIXTURE_NAMES) {
    if (!names.includes(want)) problems.push(`the apparatus fixture named \`${want}\` is gone; the check reads it by name`);
  }
  for (const f of fixtures) {
    if (!f || typeof f.src !== 'string' || !f.src.length) problems.push(`${f && f.name}: the fixture carries no source`);
    if (!f || !f.expect) problems.push(`${f && f.name}: the fixture does not say which word it must produce`);
  }
  // The discriminating half is a property of the SET, not of a run: two fixtures
  // that expect the same word cannot tell a stuck instrument from a working one,
  // however cleanly they both read it.
  const expected = new Set(fixtures.map((f) => f && f.expect));
  if (expected.size < 2) {
    problems.push(`both apparatus fixtures expect ${[...expected].join('/')}: the set cannot discriminate, `
      + 'so a run over it would pass on an instrument stuck on one word');
  }
  return problems;
}

/**
 * What the readings say -- every problem the check reports as a WRONG ANSWER.
 *
 * Pure, and it counts before it compares: a fixture that produced no reading is
 * a problem in its own right, so the discriminating half can never be reached
 * over an empty or partial set and quietly answer "no problem".
 *
 * @param {Record<string,string>} readings fixture name -> the word O3 read
 * @param {ReadonlyArray<object>} fixtures defaults to the real set
 */
export function apparatusProblems(readings, fixtures = APPARATUS_FIXTURES) {
  const problems = apparatusInventoryProblems(fixtures);
  if (problems.length) return problems;
  const taken = Object.keys(readings || {});
  for (const fx of fixtures) {
    if (!Object.prototype.hasOwnProperty.call(readings || {}, fx.name)) {
      problems.push(`${fx.name}: no reading was taken, so the check below would have compared nothing`);
    } else if (readings[fx.name] !== fx.expect) {
      problems.push(`${fx.name}: read ${readings[fx.name]}, expected ${fx.expect} -- ${fx.why}`);
    }
  }
  for (const name of taken) {
    if (!fixtures.some((f) => f.name === name)) problems.push(`a reading was recorded for \`${name}\`, which is not a fixture of this check`);
  }
  if (problems.length) return problems;
  // Only now, with one reading per fixture and every one of them the word it was
  // supposed to be: did the two words actually differ.
  const words = new Set(fixtures.map((f) => readings[f.name]));
  if (words.size < 2) {
    problems.push(`both fixtures read ${[...words][0]}: O3 is not discriminating on this host, so a table built `
      + 'from it would be a table of one word however it came out');
  }
  return problems;
}

/** The three the byte-count read-out is checked against, with the answer each must give. */
export const READOUT_FIXTURES = Object.freeze([
  Object.freeze({
    name: 'known',
    fn: 'handle',
    src: subjectSource({ bytes: FIXTURE_BYTES.kept, readAfter: true }),
    establishes: FIXTURE_BYTES.kept,
    refusalMatches: null,
  }),
  Object.freeze({
    name: 'runtime',
    fn: 'handle',
    src: subjectSource({ bytes: 0, runtimeLength: true }),
    establishes: null,
    refusalMatches: 'not an integer constant expression',
  }),
  Object.freeze({
    name: 'short',
    fn: 'handle',
    // A constant, and NOT the buffer's size: without step 5 of the read-out this
    // would be established as 16 and O3 would then grade a full 64-byte wipe as
    // PARTIAL against it.
    src: subjectSource({ bytes: FIXTURE_BYTES.short, len: '16' }),
    establishes: null,
    refusalMatches: 'sizeof(key)',
  }),
]);
