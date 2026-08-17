/**
 * Tests for the frontier comparator and the sidecar deriver.
 *
 * The rung readings below are the ones measured on 2026-08-17 with clang 18.1.3
 * through the real IrCheckpoints plugin — 132 observations, twelve rungs across
 * eleven exposures — and they are here because a comparator tested only on
 * invented data proves that object comparison works, not that this instrument
 * discriminates anything. Three of them do real work:
 *
 *   O2 vs F3   differs on exactly six rungs, and those six are the whole value
 *              of the guard: the two command lines produce a byte-identical
 *              nominal config key.
 *   O2 vs FM   differs on exactly one rung (c2), which is the smallest real
 *              discrimination the ladder made.
 *   F2 vs F3   are IDENTICAL. A measured limit, asserted here so that it cannot
 *              be quietly lost.
 *
 * The documents below carry `exposure` and `toolchain.cc` and no `config`,
 * which is what `build-ladder-frontier.py` actually writes. The deriver reads
 * the key off that invocation with the driver's own `normalise()` +
 * `driverConfigAxes()`, so the tests in section 4b pin the SPELLINGS that come
 * out. That is the one failure in this file with no visible symptom: a key the
 * driver spells differently is not a mismatch, it is a lookup that misses, and a
 * sidecar with nothing to say about any build reads from the driver's side
 * exactly like a clean run.
 *
 * Test data is inline rather than in a directory beside this file. A path
 * segment named `fixtures` under compiler/ is a committable measurement input
 * and scripts/check-packaging-invariants.mjs fails the build on one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BROKEN_RUNG,
  EXPOSURE_RESULTS,
  FAILURE_DIRECTION,
  FrontierInputError,
  HEALTH_INVARIANTS,
  LADDER_FRONTIER_SCHEMA_VERSION,
  RESULT_CONSISTENT,
  RESULT_INCOMPARABLE,
  RESULT_MISMATCH,
  brokenRungsOf,
  compareFrontiers,
  declaresUnhealthy,
  exitCodeFor,
} from '../frontier-match.mjs';
import {
  CONFIG_KEYS,
  EXIT_INCOMPLETE,
  EXIT_OK,
  EXIT_USAGE,
  UNUSABLE,
  configFromDocument,
  configKey,
  deriveSidecar,
  main as deriveMain,
} from '../derive-frontier-sidecar.mjs';
// The driver's own reader, imported here for the same reason the deriver
// imports it: the assertions below are about the sidecar being keyed by the key
// the driver will look it up with, and a test that rebuilt the key from a
// literal would go green on the day the two sides stopped agreeing.
import { normalise } from '../../driver/lib/cmdline.mjs';
import { driverConfigAxes } from '../../driver/lib/config-axes.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const MATCH_CLI = join(HERE, '..', 'frontier-match.mjs');

/** A stand-in ladder digest: 64 lowercase hex, as interfaces.md section 5 asks. */
const LADDER_SHA = 'a'.repeat(64);
const OTHER_SHA = 'b'.repeat(64);

/** Measured, clang 18.1.3, 2026-08-17. Twelve rungs per exposure. */
const MEASURED = {
  O0: {
    a0: 'PRESENT', a1: 'PRESENT', a2: 'PRESENT', a3: 'ABSENT',
    'b1-intr': 'PRESENT', 'b1-lib': 'ABSENT', 'b1-chk': 'ABSENT',
    c1: 'PRESENT', c2: 'PRESENT',
    'd1-printf': 'PRESENT', 'd1-puts': 'ABSENT', 'd1-chk': 'ABSENT',
  },
  O2: {
    a0: 'NOT_APPLICABLE', a1: 'LOST', a2: 'LOST', a3: 'ABSENT',
    'b1-intr': 'PRESENT', 'b1-lib': 'ABSENT', 'b1-chk': 'ABSENT',
    c1: 'LOST', c2: 'PRESENT',
    'd1-printf': 'LOST', 'd1-puts': 'PRESENT', 'd1-chk': 'ABSENT',
  },
  // -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
  F2: {
    a0: 'NOT_APPLICABLE', a1: 'LOST', a2: 'LOST', a3: 'ABSENT',
    'b1-intr': 'ABSENT', 'b1-lib': 'LOST', 'b1-chk': 'PRESENT',
    c1: 'LOST', c2: 'PRESENT',
    'd1-printf': 'ABSENT', 'd1-puts': 'ABSENT', 'd1-chk': 'PRESENT',
  },
  // -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
  F3: {
    a0: 'NOT_APPLICABLE', a1: 'LOST', a2: 'LOST', a3: 'ABSENT',
    'b1-intr': 'ABSENT', 'b1-lib': 'LOST', 'b1-chk': 'PRESENT',
    c1: 'LOST', c2: 'PRESENT',
    'd1-printf': 'ABSENT', 'd1-puts': 'ABSENT', 'd1-chk': 'PRESENT',
  },
  // -O2 -ffast-math
  FM: {
    a0: 'NOT_APPLICABLE', a1: 'LOST', a2: 'LOST', a3: 'ABSENT',
    'b1-intr': 'PRESENT', 'b1-lib': 'ABSENT', 'b1-chk': 'ABSENT',
    c1: 'LOST', c2: 'LOST',
    'd1-printf': 'LOST', 'd1-puts': 'PRESENT', 'd1-chk': 'ABSENT',
  },
};

/**
 * The nominal key all five of the -O2 exposures above collapse onto — written
 * out here in the spellings `derive-fallback-table.mjs`'s rows use, and asserted
 * against the derived one below rather than fed into the deriver. The documents
 * carry no `config` at all: the deriver reads `exposure` + `toolchain.cc`, which
 * is what a real one carries.
 */
const O2_CONFIG = Object.freeze({
  cc: 'clang-18',
  freestanding: false,
  lto: 'none',
  ndebug: false,
  opt: '-O2',
  target: 'host',
});

/**
 * A well-formed frontier document; each test overrides only what it is about.
 *
 * The fields are the ones `build-ladder-frontier.py` writes, including the three
 * health invariants and `exposure`, because a helper that carried a shape no
 * assembler produces would test the deriver against a document that cannot
 * arrive.
 */
function doc(over = {}) {
  return {
    schemaVersion: LADDER_FRONTIER_SCHEMA_VERSION,
    exposure: { id: 'O2', opt: '-O2', extraArgs: [] },
    ladder: { sourceSha256: LADDER_SHA, generatorVersion: '1' },
    toolchain: { cc: 'clang-18', clang: '18.1.3', digest: 'c'.repeat(64) },
    health: { broken: false, twinsHeld: true, chainMonotone: true, spellingExclusive: true },
    frontier: { ...MEASURED.O2 },
    ...over,
  };
}

/** The invocation an exposure was measured under, as the assembler records it. */
function exposure(id, opt = '-O2', extraArgs = []) {
  return { id, opt, extraArgs };
}

// --- 1. the comparison itself -----------------------------------------------

test('identical frontiers are exposure-consistent, and the word is never upgraded', () => {
  // The day-0 determinism check: -O2 measured twice gave the same frontier.
  const cmp = compareFrontiers(doc(), doc());
  assert.equal(cmp.result, RESULT_CONSISTENT);
  assert.deepEqual(cmp.differingRungs, []);
  assert.match(cmp.reason, /all 12 rungs responded identically/);
  // Necessary, never sufficient. Nothing in this module may say otherwise.
  assert.doesNotMatch(cmp.reason, /verified|matched|same exposure/i);
});

test('one differing rung is a mismatch and the rung is named', () => {
  // -O2 against -O2 -ffast-math: measured to differ on c2 and nothing else.
  const cmp = compareFrontiers(doc(), doc({ frontier: { ...MEASURED.FM } }));
  assert.equal(cmp.result, RESULT_MISMATCH);
  assert.deepEqual(cmp.differingRungs, ['c2']);
  assert.match(cmp.reason, /c2: PRESENT on a, LOST on b/);
});

test('the six rungs that separate -O2 from FORTIFY=3 under one nominal key', () => {
  // The defect this instrument closes: both command lines produce the same
  // six-axis key, so without the ladder the driver would quote one cell for the
  // other. The rung list is the measured one, not an example.
  const f3 = doc({
    exposure: exposure('F3', '-O2', ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3']),
    frontier: { ...MEASURED.F3 },
  });
  const cmp = compareFrontiers(doc(), f3);
  assert.equal(cmp.result, RESULT_MISMATCH);
  assert.deepEqual(cmp.differingRungs, ['b1-chk', 'b1-intr', 'b1-lib', 'd1-chk', 'd1-printf', 'd1-puts']);
  // And the premise, derived from the two real command lines rather than
  // asserted: the guard is only worth having because these two key the same.
  assert.equal(
    configKey(configFromDocument(doc(), 'O2').config),
    configKey(configFromDocument(f3, 'F3').config),
    'the two builds share one nominal key',
  );
});

test('FORTIFY=2 and FORTIFY=3 are indistinguishable to this rung set — a measured limit', () => {
  const cmp = compareFrontiers(doc({ frontier: { ...MEASURED.F2 } }), doc({ frontier: { ...MEASURED.F3 } }));
  assert.equal(cmp.result, RESULT_CONSISTENT);
  // The limit is stated in the instrument's own failure direction, so a reader
  // of a consistent verdict is told what it does not cover.
  assert.match(FAILURE_DIRECTION, /_FORTIFY_SOURCE=2 and =3/);
  assert.match(FAILURE_DIRECTION, /-O2, -O3 and -Os are indistinguishable/);
  assert.match(FAILURE_DIRECTION, /^Fails towards exposure-consistent\./);
});

test('an opt-responsive ladder: -O0 and -O2 separate', () => {
  const cmp = compareFrontiers(doc({ frontier: { ...MEASURED.O0 } }), doc());
  assert.equal(cmp.result, RESULT_MISMATCH);
  assert.ok(cmp.differingRungs.includes('a1'), 'a1 survives -O0 and is lost at -O2');
});

// --- 2. the gates, which produce incomparable and never mismatch -------------

test('a differing ladder sourceSha256 is incomparable, not a mismatch', () => {
  const other = doc({
    ladder: { sourceSha256: OTHER_SHA, generatorVersion: '1' },
    // Deliberately also differing on six rungs: a version skew must not be
    // reported as a discrimination the instrument made.
    frontier: { ...MEASURED.F3 },
  });
  const cmp = compareFrontiers(doc(), other);
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.deepEqual(cmp.differingRungs, []);
  assert.match(cmp.reason, /ladder\.sourceSha256 differs/);
});

test('a differing generatorVersion is incomparable', () => {
  const cmp = compareFrontiers(doc(), doc({ ladder: { sourceSha256: LADDER_SHA, generatorVersion: '2' } }));
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, /generatorVersion differs/);
});

test('a BROKEN rung on either side is incomparable, even when other rungs differ', () => {
  const withBroken = doc({ frontier: { ...MEASURED.F3, c1: BROKEN_RUNG } });
  assert.deepEqual(brokenRungsOf(withBroken), ['c1']);

  for (const [a, b] of [[doc(), withBroken], [withBroken, doc()]]) {
    const cmp = compareFrontiers(a, b);
    assert.equal(cmp.result, RESULT_INCOMPARABLE, 'a rung nobody measured cannot show sameness');
    assert.deepEqual(cmp.differingRungs, [], 'nothing was compared, so nothing differed');
    assert.match(cmp.reason, /c1/);
    assert.match(cmp.reason, /broken measurement rather than a finding/);
  }
});

test('NOT_OBSERVED is treated exactly as BROKEN is', () => {
  const cmp = compareFrontiers(doc(), doc({ frontier: { ...MEASURED.O2, a3: 'NOT_OBSERVED' } }));
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, /a3/);
});

test('health.broken on either side is incomparable and short-circuits the shape rules', () => {
  // Broken documents are not required to carry a frontier at all — the sidecar
  // writes exactly this shape for a key it refused to resolve.
  const broken = { health: { broken: true, reason: 'control-did-not-hold' }, frontier: null, ladder: null };
  for (const [a, b, side] of [[doc(), broken, 'b'], [broken, doc(), 'a']]) {
    const cmp = compareFrontiers(a, b);
    assert.equal(cmp.result, RESULT_INCOMPARABLE);
    assert.match(cmp.reason, new RegExp(`health\\.broken is true on ${side}`));
    assert.match(cmp.reason, /control-did-not-hold/);
  }
});

test('frontiers that do not cover the same rungs are incomparable', () => {
  const partial = { ...MEASURED.O2 };
  delete partial['d1-chk'];
  const cmp = compareFrontiers(doc(), doc({ frontier: partial }));
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, /do not cover the same rungs/);
  assert.match(cmp.reason, /d1-chk/);
});

test('a document of another vintage is incomparable rather than read approximately', () => {
  const cmp = compareFrontiers(doc(), doc({ schemaVersion: 'vibeguard.ladder-frontier/2' }));
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, /schemaVersion/);
});

// --- 3. shape failures are refused, never bucketed as a reading -------------

test('generatorVersion is read in both spellings the tree uses, and never coerced', () => {
  // The assembler writes an integer (section 5 rule 4); the driver-side
  // documents write a string. Both are identity labels and both are read.
  const asInt = { sourceSha256: LADDER_SHA, generatorVersion: 1 };
  assert.equal(compareFrontiers(doc({ ladder: asInt }), doc({ ladder: asInt })).result, RESULT_CONSISTENT);

  // Mixed spellings are incomparable rather than coerced into agreement.
  const mixed = compareFrontiers(doc({ ladder: asInt }), doc());
  assert.equal(mixed.result, RESULT_INCOMPARABLE);
  assert.match(mixed.reason, /generatorVersion differs/);
});

test('a document that is not the documented shape is refused, not called incomparable', () => {
  const cases = [
    [doc({ health: {} }), /health\.broken must be a boolean/],
    [doc({ ladder: { sourceSha256: LADDER_SHA.toUpperCase(), generatorVersion: '1' } }), /64 lowercase hex/],
    [doc({ ladder: { sourceSha256: LADDER_SHA, generatorVersion: 1.5 } }), /integer or a non-empty string/],
    [doc({ frontier: {} }), /non-empty object/],
    [doc({ frontier: { a0: 'MOSTLY_PRESENT' } }), /not one of/],
  ];
  for (const [bad, pattern] of cases) {
    assert.throws(() => compareFrontiers(doc(), bad), (err) => {
      assert.ok(err instanceof FrontierInputError);
      assert.equal(err.exitCode, 3);
      assert.match(err.message, pattern);
      return true;
    });
  }
});

test('the exit codes are the ones interfaces.md section 7 fixes', () => {
  assert.equal(exitCodeFor(RESULT_CONSISTENT), 0);
  assert.equal(exitCodeFor(RESULT_MISMATCH), 2);
  assert.equal(exitCodeFor(RESULT_INCOMPARABLE), 3);
  assert.throws(() => exitCodeFor('ok'), FrontierInputError);
});

// --- 4. the sidecar ---------------------------------------------------------

/**
 * A frontier document for one exposure. `exposure.id` follows the file name by
 * default, because a document whose two identifiers disagree is a case of its
 * own and tripping it in every other test would bury it.
 */
function source(id, frontier, over = {}) {
  return { id, doc: doc({ exposure: exposure(id), frontier: { ...frontier }, ...over }) };
}

test('two exposures under one nominal key that disagree produce an anomaly, not a merge', () => {
  // The headline case, and it is the real one: `-O2` and
  // `-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3` produce the same six-axis key.
  // The FORTIFY flags are on the document, not on a hand-written config, so the
  // collision is one the deriver found rather than one this test arranged.
  const { sidecar, exitCode } = deriveSidecar([
    source('O2', MEASURED.O2),
    source('F3', MEASURED.F3, {
      exposure: exposure('F3', '-O2', ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3']),
    }),
  ]);
  assert.equal(exitCode, EXIT_OK);
  assert.equal(sidecar.entries.length, 1, 'one key, because that is the defect');
  const [entry] = sidecar.entries;

  assert.equal(entry.usable, false);
  assert.equal(entry.unusableReason, UNUSABLE.COLLISION);
  assert.equal(entry.frontier, null, 'no winner was picked');
  assert.deepEqual(entry.sources, ['F3', 'O2'], 'both sources are named');
  assert.equal(sidecar.counts.collisions, 1);

  const collision = sidecar.anomalies.filter((a) => a.startsWith('config-key-collision:'));
  assert.equal(collision.length, 1);
  assert.match(collision[0], /"b1-chk","b1-intr","b1-lib","d1-chk","d1-printf","d1-puts"/);
  assert.match(collision[0], /not merged, not averaged, not last-one-wins/i);

  // And the point of marking it: a consumer that hands the entry back to the
  // comparator is told it cannot look, rather than being given a coin toss.
  const cmp = compareFrontiers(doc(), entry, { whereA: 'measured', whereB: 'sidecar' });
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, new RegExp(UNUSABLE.COLLISION));
});

test('two exposures under one key that agree are one usable entry with two sources', () => {
  const { sidecar, exitCode } = deriveSidecar([
    source('O2', MEASURED.O2),
    source('O2bis', MEASURED.O2),
  ]);
  assert.equal(exitCode, EXIT_OK);
  assert.equal(sidecar.entries.length, 1);
  assert.equal(sidecar.entries[0].usable, true);
  assert.deepEqual(sidecar.entries[0].sources, ['O2', 'O2bis']);
  assert.deepEqual(sidecar.entries[0].frontier, MEASURED.O2);
  assert.equal(sidecar.counts.usableKeys, 1);
  assert.equal(sidecar.counts.collisions, 0);

  // A usable entry is itself a comparable document.
  assert.equal(compareFrontiers(doc(), sidecar.entries[0]).result, RESULT_CONSISTENT);
});

test('distinct keys stay distinct, and every input is accounted for exactly once', () => {
  const { sidecar, exitCode } = deriveSidecar([
    source('O0', MEASURED.O0, { exposure: exposure('O0', '-O0') }),
    source('O2', MEASURED.O2),
    source('FM', MEASURED.FM, { exposure: exposure('FM', '-O2', ['-ffast-math']) }),
  ]);
  assert.equal(exitCode, EXIT_OK);
  assert.equal(sidecar.counts.documents, 3);
  assert.equal(sidecar.counts.keys, 2);
  // -O2 and -O2 -ffast-math collide on one key; -O0 is a key of its own.
  assert.equal(sidecar.counts.collisions, 1);
  assert.equal(sidecar.counts.usableKeys, 1);
  const named = sidecar.entries.flatMap((e) => e.sources).sort();
  assert.deepEqual(named, ['FM', 'O0', 'O2']);
});

test('a source that declares itself broken makes its key unusable and is still named', () => {
  const brokenSource = source('O2', MEASURED.O2);
  brokenSource.doc.health = { broken: true, reason: 'control-did-not-hold on c1' };
  const { sidecar, exitCode } = deriveSidecar([brokenSource]);
  assert.equal(exitCode, EXIT_OK);
  assert.equal(sidecar.entries[0].usable, false);
  assert.equal(sidecar.entries[0].unusableReason, UNUSABLE.BROKEN);
  assert.equal(sidecar.counts.brokenDocuments, 1);
  assert.match(sidecar.anomalies.join('\n'), /broken-measurement: O2/);
});

test('a ladder skew under one key is incomparable, and is kept apart from a collision', () => {
  const { sidecar } = deriveSidecar([
    source('O2', MEASURED.O2),
    source('O2new', MEASURED.F3, { ladder: { sourceSha256: OTHER_SHA, generatorVersion: '1' } }),
  ]);
  assert.equal(sidecar.entries[0].unusableReason, UNUSABLE.INCOMPARABLE);
  assert.equal(sidecar.counts.collisions, 0, 'nothing was shown to differ');
  assert.match(sidecar.anomalies.join('\n'), /config-key-incomparable:/);
});

test('the sidecar carries the failure direction and the six key axes', () => {
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2)]);
  assert.equal(sidecar.schemaVersion, 'vibeguard.ladder-frontiers/1');
  assert.equal(sidecar.instrument.failureDirection, FAILURE_DIRECTION);
  assert.match(sidecar.instrument.use, /guard-only/);
  assert.deepEqual(sidecar.instrument.resultVocabulary, [...EXPOSURE_RESULTS]);
  // The same six names, in the same order, as derive-fallback-table's CONFIG_KEYS.
  assert.deepEqual([...CONFIG_KEYS], ['cc', 'freestanding', 'lto', 'ndebug', 'opt', 'target']);
  assert.deepEqual(sidecar.configKeys, [...CONFIG_KEYS]);
  assert.deepEqual(Object.keys(sidecar.entries[0].config), [...CONFIG_KEYS]);
});

test('a document with no exposure at all is refused, not filed under six nulls', () => {
  // The assembler records the invocation as `exposure.opt` + `exposure.extraArgs`,
  // and that is what the key is derived from. A document that carries neither
  // has stated no invocation; filing it anyway would put it under an all-null
  // key, collect every such document into one pile-up and report that pile-up
  // as a collision — a property of the nominal key that nobody measured.
  const noExposure = source('O2', MEASURED.O2);
  delete noExposure.doc.exposure;
  const { sidecar, exitCode, problems } = deriveSidecar([noExposure, source('F3', MEASURED.F3)]);
  assert.equal(sidecar, null);
  assert.equal(exitCode, EXIT_INCOMPLETE);
  assert.match(problems.join('\n'), /states no `exposure` object/);
  assert.match(problems.join('\n'), /none of them is guessed/);
});

test('a document with no toolchain.cc is refused rather than filed under a compiler nobody used', () => {
  // `cc` is the one axis no command line states, so it is the one axis that has
  // to be read off the document. Guessing it — from `toolchain.clang`, or as
  // null — would file readings taken by two different compilers under one key
  // and report the resulting disagreement as a property of the exposures.
  const noCc = source('O2', MEASURED.O2, { toolchain: { clang: '18.1.3' } });
  const { sidecar, exitCode, problems } = deriveSidecar([noCc]);
  assert.equal(sidecar, null);
  assert.equal(exitCode, EXIT_INCOMPLETE);
  assert.match(problems.join('\n'), /states no `toolchain\.cc`/);
  assert.match(problems.join('\n'), /not guessed from `toolchain\.clang`/);
});

test('an axis nobody recorded is reported rather than accepted quietly', () => {
  // `-m32` changes the triple without a `-target` on the line, so `target` is
  // not readable from this invocation and the key carries a null there.
  const { sidecar } = deriveSidecar([
    source('M32', MEASURED.O2, { exposure: exposure('M32', '-O2', ['-m32']) }),
  ]);
  assert.equal(sidecar.entries[0].config.target, null);
  assert.match(sidecar.anomalies.join('\n'), /underspecified-axis: .*axis=target/);
});

test('nothing to derive from is refused, never written as an empty sidecar', () => {
  const { sidecar, exitCode } = deriveSidecar([]);
  assert.equal(sidecar, null);
  assert.equal(exitCode, EXIT_INCOMPLETE);
});

// --- 4b. the key a reading is filed under -----------------------------------

test('the derived key uses derive-fallback-table\'s spellings — a drift here is a silent key miss, not a mismatch, and the guard stops guarding', () => {
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2)]);
  const [entry] = sidecar.entries;

  // Exactly the six names, in CONFIG_KEYS order, carrying the values a
  // `derive-fallback-table.mjs` row carries: `cc` is the driver the sweep
  // invoked (`clang-18`, not the version `18.1.3`), a line with no `-target` is
  // `"host"`, a line with no LTO token is `"none"`, and the other two are
  // booleans rather than the strings a shell-side derivation would have
  // produced.
  assert.deepEqual(entry.config, {
    cc: 'clang-18', freestanding: false, lto: 'none', ndebug: false, opt: '-O2', target: 'host',
  });
  assert.deepEqual(Object.keys(entry.config), [...CONFIG_KEYS]);
  assert.equal(typeof entry.config.ndebug, 'boolean');
  assert.equal(typeof entry.config.freestanding, 'boolean');

  // The assertion that actually matters. The driver looks this sidecar up by
  // the key ITS reader produces, so a spelling that drifts does not report a
  // disagreement — the lookup misses, the sidecar has nothing to say about any
  // build, and from the driver's side that is indistinguishable from a clean
  // run. The key is therefore compared against the driver's own reader here.
  assert.equal(entry.configKey, configKey({ cc: 'clang-18', ...driverConfigAxes(normalise(['-O2'])) }));
});

test('the whole invocation is read into the key, not `exposure.opt` alone', () => {
  const cases = [
    [['-ffreestanding'], { freestanding: true }],
    [['-DNDEBUG'], { ndebug: true }],
    [['--target=arm-none-eabi'], { target: 'arm-none-eabi' }],
    // clang takes the last `-O` on the line, so `extraArgs` after `opt` wins
    // here exactly as it wins there.
    [['-O0'], { opt: '-O0' }],
    // Neither of these is an axis, which is the whole reason the ladder exists.
    [['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3'], {}],
    [['-fno-builtin-memset'], {}],
  ];
  for (const [extraArgs, expected] of cases) {
    const { config, problem } = configFromDocument(doc({ exposure: exposure('x', '-O2', extraArgs) }), 'x');
    assert.equal(problem, null);
    assert.deepEqual(config, { ...O2_CONFIG, ...expected }, extraArgs.join(' '));
  }
});

test('a config stated by a producer is recorded and not read', () => {
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2, { config: { ...O2_CONFIG, opt: '-O0' } })]);
  assert.equal(sidecar.entries[0].config.opt, '-O2', 'the invocation decides the key, never a stated copy of it');
  assert.match(sidecar.anomalies.join('\n'), /config-stated-not-read: O2/);
});

test('a document whose exposure.id disagrees with its file name is named rather than reconciled', () => {
  // The check this exercises used to read `doc.exposureId`, a field no producer
  // in this tree writes, so it could not fire at all. Constructing the
  // disagreement the assembler can actually produce is what catches that.
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2, { exposure: exposure('F3') })]);
  assert.match(sidecar.anomalies.join('\n'), /document-id-mismatch: file O2 carries exposure\.id="F3"/);

  // And it stays quiet when the two agree, so the anomaly says something.
  const agreeing = deriveSidecar([source('O2', MEASURED.O2)]).sidecar.anomalies;
  assert.deepEqual(agreeing.filter((a) => a.startsWith('document-id-mismatch')), []);
});

test('a frontier that is not a reading is refused as the document enters, not only when two are compared', () => {
  // A key with one document is never compared against anything, so until this
  // ran on the way in, a lone document carrying `frontier: {}` was written out
  // `usable: true` and would have cleared a build — while `compareFrontiers`,
  // handed that same document, refuses an empty frontier by name.
  const empty = deriveSidecar([source('O2', {})]);
  assert.equal(empty.sidecar, null);
  assert.equal(empty.exitCode, EXIT_INCOMPLETE);
  assert.match(empty.problems.join('\n'), /O2\.frontier must be a non-empty object/);

  // The same validator, so the same refusals: a word that is not one of the
  // known readings, and a ladder digest that is not a digest.
  const badWord = deriveSidecar([source('O2', { ...MEASURED.O2, c1: 'MOSTLY_PRESENT' })]);
  assert.equal(badWord.exitCode, EXIT_INCOMPLETE);
  assert.match(badWord.problems.join('\n'), /O2\.frontier\.c1/);

  const badSha = deriveSidecar([
    source('O2', MEASURED.O2, { ladder: { sourceSha256: LADDER_SHA.toUpperCase(), generatorVersion: '1' } }),
  ]);
  assert.equal(badSha.exitCode, EXIT_INCOMPLETE);
  assert.match(badSha.problems.join('\n'), /64 lowercase hex/);
});

// --- 4c. health on the path that clears builds -------------------------------

test('declaresUnhealthy names the invariants a document declares false, and is falsy when it declares none', () => {
  // Callers branch on this directly on the path that clears a build, so the
  // healthy answer must be falsy. An empty array would be truthy.
  assert.ok(!declaresUnhealthy(doc()), 'a healthy document must be falsy');
  assert.equal(declaresUnhealthy(doc()), null);
  assert.equal(declaresUnhealthy(doc({ health: { broken: false } })), null, 'an absent invariant is not a false one');
  assert.equal(declaresUnhealthy(undefined), null, 'a non-document declares nothing');

  assert.deepEqual(declaresUnhealthy(doc({ health: { broken: false, twinsHeld: false } })), ['twinsHeld']);
  assert.deepEqual(
    declaresUnhealthy(doc({
      health: { broken: false, twinsHeld: false, chainMonotone: false, spellingExclusive: false },
    })),
    [...HEALTH_INVARIANTS],
  );
  assert.deepEqual([...HEALTH_INVARIANTS], ['chainMonotone', 'spellingExclusive', 'twinsHeld']);
});

test('a document that declares a health invariant false is incomparable, whatever its rungs say', () => {
  const fell = doc({ health: { broken: false, twinsHeld: false, chainMonotone: true, spellingExclusive: true } });
  for (const [a, b, side] of [[doc(), fell, 'b'], [fell, doc(), 'a']]) {
    const cmp = compareFrontiers(a, b);
    assert.equal(cmp.result, RESULT_INCOMPARABLE);
    assert.match(cmp.reason, new RegExp(`${side} declares twinsHeld false`));
    assert.deepEqual(cmp.differingRungs, [], 'nothing was compared, so nothing differed');
  }

  // Not a mismatch even when the rungs differ as well: an invariant of the
  // instrument is not a rung, and a ladder that has stopped being ordered has
  // not measured a difference between two exposures.
  const alsoDiffers = doc({ frontier: { ...MEASURED.F3 }, health: { broken: false, chainMonotone: false } });
  const cmp = compareFrontiers(doc(), alsoDiffers);
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, /chainMonotone false/);
});

test('a ladder that measurably stopped being a ladder makes its key unusable and clears nothing', () => {
  const fell = source('O2', MEASURED.O2, {
    health: { broken: false, twinsHeld: false, chainMonotone: true, spellingExclusive: true },
  });
  const { sidecar, exitCode } = deriveSidecar([fell]);
  assert.equal(exitCode, EXIT_OK);
  const [entry] = sidecar.entries;
  assert.equal(entry.usable, false);
  assert.equal(entry.unusableReason, UNUSABLE.INVARIANT);
  assert.equal(entry.frontier, null, 'no reading is offered for a key nobody successfully measured');
  assert.equal(sidecar.counts.unhealthyDocuments, 1);
  assert.equal(sidecar.counts.brokenDocuments, 0, 'a false invariant is not health.broken and is not filed as one');
  assert.match(sidecar.anomalies.join('\n'), /health-invariant-false: O2 .* declares twinsHeld false/);

  // The entry leaves by the same door a collision leaves by: a consumer that
  // hands it back to the comparator is told it cannot look.
  const cmp = compareFrontiers(doc(), entry);
  assert.equal(cmp.result, RESULT_INCOMPARABLE);
  assert.match(cmp.reason, new RegExp(UNUSABLE.INVARIANT));
});

test('a usable entry carries the invariants every one of its sources stated', () => {
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2), source('O2bis', MEASURED.O2)]);
  const [entry] = sidecar.entries;
  assert.deepEqual(entry.health, { broken: false, chainMonotone: true, spellingExclusive: true, twinsHeld: true });
  assert.equal(declaresUnhealthy(entry), null, 'the entry answers the same way its sources do');

  // An invariant one source states and another does not is left off: absent
  // means "this producer does not state it", and writing `true` over that would
  // put a claim on the entry that no single reading makes.
  const mixed = deriveSidecar([
    source('O2', MEASURED.O2),
    source('O2bis', MEASURED.O2, { health: { broken: false } }),
  ]).sidecar.entries[0];
  assert.deepEqual(mixed.health, { broken: false });
});

test('the failure direction discloses what a frontier does not bind, and where the guard has no coverage at all', () => {
  // Binding is of the flag sequence and the compiler. FORTIFY is a header
  // rewrite, so the one thing a reader would most reasonably assume — that an
  // identical argv and clang mean an identical exposure — is the thing that
  // needs saying, together with the operational contract that closes it.
  assert.match(FAILURE_DIRECTION, /not the header set/);
  assert.match(FAILURE_DIRECTION, /no rung reads a header/);
  assert.match(FAILURE_DIRECTION, /THE LADDER IS MEASURED IN THE SAME IMAGE AND THE SAME JOB AS THE BUILD IT GUARDS/);
  // And the builds that cannot be guarded at all, rather than guarded loosely.
  assert.match(FAILURE_DIRECTION, /--sysroot=\/opt\/vendor/);
  assert.match(FAILURE_DIRECTION, /vendor-sysroot and cross builds are therefore outside/);

  // It travels with the artefact rather than living only in this tree.
  const { sidecar } = deriveSidecar([source('O2', MEASURED.O2)]);
  assert.equal(sidecar.instrument.failureDirection, FAILURE_DIRECTION);
});

// --- 5. the two CLIs --------------------------------------------------------

function writeDoc(dir, name, document) {
  const p = join(dir, `${name}.json`);
  writeFileSync(p, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  return p;
}

function runMatch(a, b) {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [MATCH_CLI, a, b], { encoding: 'utf8' }) };
  } catch (err) {
    return { code: err.status, stdout: String(err.stdout ?? ''), stderr: String(err.stderr ?? '') };
  }
}

test('the comparator CLI exits 0 / 2 / 3 for the three words', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-frontier-'));
  const o2 = writeDoc(dir, 'O2', doc());
  const f3 = writeDoc(dir, 'F3', doc({ frontier: { ...MEASURED.F3 } }));
  const skew = writeDoc(dir, 'skew', doc({ ladder: { sourceSha256: OTHER_SHA, generatorVersion: '1' } }));

  const consistent = runMatch(o2, o2);
  assert.equal(consistent.code, 0);
  assert.match(consistent.stdout, /exposure-consistent/);
  assert.match(consistent.stdout, /necessary, never sufficient/i);

  const mismatch = runMatch(o2, f3);
  assert.equal(mismatch.code, 2);
  assert.match(mismatch.stdout, /exposure-mismatch/);
  assert.match(mismatch.stdout, /differing rungs: b1-chk, b1-intr, b1-lib, d1-chk, d1-printf, d1-puts/);

  const incomparable = runMatch(o2, skew);
  assert.equal(incomparable.code, 3);
  assert.match(incomparable.stdout, /exposure-incomparable/);
});

test('the deriver CLI writes a sidecar and reports the collision on stderr', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vg-sidecar-'));
  writeDoc(dir, 'O2', doc());
  writeDoc(dir, 'F3', doc({
    exposure: exposure('F3', '-O2', ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=3']),
    frontier: { ...MEASURED.F3 },
  }));
  const out = join(dir, 'out', 'ladder-frontiers.json');

  const streams = () => {
    const out = [];
    const err = [];
    return { out, err, io: { stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) } } };
  };

  const first = streams();
  assert.equal(deriveMain(['--out', out, '--dir', dir], first.io), EXIT_OK);
  assert.match(first.out.join(''), /ladder-frontiers\.json/);
  // The counting line is always the last thing on stderr: a run that finished
  // quietly would let a sidecar in which nothing is usable read like one in
  // which everything is.
  assert.match(first.err.join(''), /documents=2 keys=1 usable=0 unusable=1 collisions=1/);

  const written = JSON.parse(readFileSync(out, 'utf8'));
  assert.equal(written.entries[0].usable, false);
  assert.equal(written.entries[0].frontier, null);

  // Deterministic: the same inputs produce the same bytes.
  const again = join(dir, 'out', 'again.json');
  assert.equal(deriveMain(['--out', again, '--dir', dir], streams().io), EXIT_OK);
  assert.equal(readFileSync(again, 'utf8'), readFileSync(out, 'utf8'));
});

test('the deriver refuses a command line with no output path', () => {
  const err = [];
  const code = deriveMain([], { stdout: { write: () => {} }, stderr: { write: (s) => err.push(s) } });
  assert.equal(code, EXIT_USAGE);
  assert.match(err.join(''), /--out <path> is required/);
});
