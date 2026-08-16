// The contract test for interfaces.md section 3.1 -- the `measurement` column.
//
//   node --test "compiler/schema/*.test.mjs"
//
// Passing the DIRECTORY to `node --test` throws MODULE_NOT_FOUND on this
// runtime. Always glob.
//
// WHY THIS FILE EXISTS
//
// Section 3 fixes six property states, and it opens by saying that "we did not
// see it" and "it is not there" are different claims and that merging them is
// how a checker starts lying. When the apparatus verdict was moved out of that
// column into a new one, the new column's three words were written into the
// comments of the three components that use it and nowhere else -- which is the
// same position section 3's vocabulary would be in if section 3 did not exist.
// A fourth component spelling it `MEASUREMENT_BROKEN` would then have broken no
// contract, because there was no contract; it would just have produced an
// envelope the other three silently mis-grade.
//
// So this file checks three things, and the third is the one that matters:
//
//   1. The vocabulary is refused when it is wrong. A cell whose measurement is
//      not one of the three words is rejected, not bucketed.
//   2. The pairing rule is enforced. A cell that reports no reading and also
//      reports a property state is rejected -- and the legal asymmetry
//      (state=NOT_OBSERVED with measurement=OK) is asserted to still be legal,
//      because a test that only checks the refusal would pass on an
//      implementation that refused both.
//   3. The three implementations and the section agree, checked by reading
//      them. Two are Python and one is JavaScript, so nothing but a source-level
//      comparison can see all four at once.
//
// HOW (3) IS DONE, AND WHAT IT DOES NOT COVER
//
// The section's table is parsed for the words in its first column. The two
// Python files are parsed for their `MEASUREMENT_STATES` tuple. The JavaScript
// is imported and its exported array read directly. All four must be the same
// list in the same order.
//
// The Python side is read as text rather than executed. Executing it would need
// a Python on PATH, and a test that skips on the machines that do not have one
// is a test that reports "pass" where it checked nothing -- for a drift check,
// that is the failure mode it was written to catch. The cost is that the parse
// could go vacuous, so every parse asserts it matched and asserts the shape of
// what it matched; a renamed constant fails here rather than passing quietly.
//
// The behavioural half of the Python side IS covered by execution, and it does
// skip without Python: see the last three tests, which run both scripts against
// a violating input and assert the refusal. The Python enforcement is also
// covered from the other direction by
// compiler/llvm-pass/scripts/envelope-labelling.test.mjs, which asserts the
// state/measurement pair each labelling branch writes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import {
  KNOWN_MEASUREMENTS,
  MEASUREMENT_OK,
  MEASUREMENT_UNSUPPORTED,
  MEASUREMENT_BROKEN,
  DEFAULT_MEASUREMENT,
  STATE_NOT_OBSERVED,
  measurementOf,
  computeFragility,
  classifyCell,
  EXCLUSION_REASONS,
  FragilityInputError,
} from '../envelope/fragility.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const INTERFACES = join(HERE, 'interfaces.md');
const BUILD_ENVELOPE = join(HERE, '..', 'llvm-pass', 'scripts', 'build-envelope.py');
const CHECK_ENVELOPE = join(HERE, '..', 'llvm-pass', 'scripts', 'check-envelope.py');

const read = (p) => readFileSync(p, 'utf8');

// --- reading the contract ---------------------------------------------------

/**
 * The words in the first column of section 3.1's table, in table order.
 *
 * Anchored on the heading and stopped at the next heading, so a table added
 * elsewhere in the file cannot be mistaken for this one.
 */
function vocabularyFromInterfaces(text) {
  const start = text.indexOf('\n## 3.1 ');
  assert.notEqual(start, -1, 'interfaces.md has no section 3.1; the contract this file tests is gone');
  const rest = text.slice(start + 1);
  const end = rest.indexOf('\n## ');
  const section = end === -1 ? rest : rest.slice(0, end);

  const rows = [...section.matchAll(/^\|\s*`([A-Z_]+)`\s*\|/gm)].map((m) => m[1]);
  assert.ok(
    rows.length >= 2,
    `section 3.1's table parsed to ${rows.length} row(s); the parse, not the contract, is what ` +
      `failed if this is 0 or 1`,
  );
  return { section, words: rows };
}

/**
 * The words in a Python `MEASUREMENT_STATES = (...)` tuple, in source order.
 *
 * The tuple is written in terms of the single-word constants, so this resolves
 * those first. Both halves are asserted to have matched: a regex that silently
 * stopped matching would turn this whole file into a test of nothing.
 */
function vocabularyFromPython(path) {
  const text = read(path);
  const consts = new Map();
  for (const m of text.matchAll(/^(MEASUREMENT_[A-Z_]+)\s*=\s*"([A-Z_]+)"\s*$/gm)) {
    consts.set(m[1], m[2]);
  }
  assert.ok(
    consts.size >= 3,
    `${path}: found ${consts.size} MEASUREMENT_* string constant(s), expected at least 3. ` +
      `If they were renamed, this test must be updated with them -- it is the only thing ` +
      `joining this file to the other two.`,
  );

  const tuple = /^MEASUREMENT_STATES\s*=\s*\(([^)]*)\)/m.exec(text);
  assert.ok(tuple, `${path}: no MEASUREMENT_STATES tuple; nothing here names the vocabulary`);
  const names = tuple[1].split(',').map((s) => s.trim()).filter(Boolean);
  assert.ok(names.length > 0, `${path}: MEASUREMENT_STATES is empty`);

  return names.map((n) => {
    assert.ok(
      consts.has(n),
      `${path}: MEASUREMENT_STATES names ${n}, which is not a MEASUREMENT_* string constant. ` +
        `A literal spelled inline here is exactly the drift this file exists to catch.`,
    );
    return consts.get(n);
  });
}

// --- (3) the four lists are one list ----------------------------------------

test('the section and all three implementations carry the same measurement vocabulary', () => {
  const { words } = vocabularyFromInterfaces(read(INTERFACES));

  assert.deepEqual(
    [...KNOWN_MEASUREMENTS],
    words,
    'compiler/envelope/fragility.mjs disagrees with interfaces.md section 3.1',
  );
  assert.deepEqual(
    vocabularyFromPython(BUILD_ENVELOPE),
    words,
    'compiler/llvm-pass/scripts/build-envelope.py disagrees with interfaces.md section 3.1',
  );
  assert.deepEqual(
    vocabularyFromPython(CHECK_ENVELOPE),
    words,
    'compiler/llvm-pass/scripts/check-envelope.py disagrees with interfaces.md section 3.1',
  );
});

test('no implementation spells a measurement word outside its constant block', () => {
  // The point of naming the constants is defeated if a literal survives beside
  // them, because that literal is what a later edit copies. Checked on quoted
  // occurrences only: the prose in these files names the words unquoted and in
  // backticks, and that is documentation rather than a second source of truth.
  for (const path of [BUILD_ENVELOPE, CHECK_ENVELOPE]) {
    const text = read(path)
      // Drop the definition block: the lines that ARE the constants.
      .replace(/^MEASUREMENT_[A-Z_]+\s*=\s*.*$/gm, '')
      .replace(/^STATE_NOT_OBSERVED\s*=\s*.*$/gm, '')
      .replace(/^KNOWN_STATES\s*=\s*\([\s\S]*?\)\s*$/m, '');
    for (const word of KNOWN_MEASUREMENTS) {
      const stray = [...text.matchAll(new RegExp(`["']${word}["']`, 'g'))];
      assert.equal(
        stray.length,
        0,
        `${path} still spells "${word}" as a literal outside the constant block, ` +
          `${stray.length} time(s). Use the constant, so section 3.1 stays the only place ` +
          `the word is decided.`,
      );
    }
  }

  const js = read(join(HERE, '..', 'envelope', 'fragility.mjs'))
    .replace(/^export const MEASUREMENT_[A-Z_]+ = .*$/gm, '')
    .replace(/^export const STATE_NOT_OBSERVED = .*$/gm, '');
  for (const word of KNOWN_MEASUREMENTS) {
    // 'OK' is a common substring in prose; only a quoted whole-token match counts.
    const stray = [...js.matchAll(new RegExp(`(?<![\\w$])['"]${word}['"](?![\\w$])`, 'g'))];
    assert.equal(
      stray.length,
      0,
      `compiler/envelope/fragility.mjs still spells '${word}' as a literal outside its ` +
        `constant block, ${stray.length} time(s).`,
    );
  }
});

test('the section states the pairing rule in both directions', () => {
  // The asymmetry is the part a reader is most likely to get wrong and the part
  // an implementer is most likely to "tidy up" into a symmetric check, so the
  // section is asserted to still say it. Matched on the two claims rather than
  // on a sentence, so the prose can be rewritten without breaking this.
  const { section } = vocabularyFromInterfaces(read(INTERFACES));
  assert.match(
    section,
    /must have `state` = `NOT_OBSERVED`/,
    'section 3.1 no longer states which state a non-OK measurement is paired with',
  );
  assert.match(
    section,
    /converse does not hold/,
    'section 3.1 no longer states that state=NOT_OBSERVED with measurement=OK is legal, ' +
      'which is the half of the rule that keeps "the instrument found nothing to read" ' +
      'distinguishable from "the instrument did not work"',
  );
});

// --- (1) and (2) the rule is enforced, in the component that scores ---------

const cell = (over = {}) => ({
  cellId: 'c1',
  propertyId: 'p',
  config: { opt: '-O2' },
  state: 'PRESENT',
  controlHeld: true,
  completesTheCheck: true,
  ...over,
});

const throws = (over, pattern) =>
  assert.throws(
    () => computeFragility([cell(over)]),
    (err) => {
      assert.ok(err instanceof FragilityInputError, `expected a FragilityInputError, got ${err}`);
      assert.equal(err.exitCode, 3, 'interfaces.md section 7: a check that could not be completed');
      assert.match(err.message, pattern);
      return true;
    },
  );

test('a measurement outside the three words is refused, not bucketed', () => {
  // The exact drift this contract was written to make impossible: a neighbouring
  // tool that spells the same idea a different way.
  throws({ measurement: 'MEASUREMENT_BROKEN', state: STATE_NOT_OBSERVED, controlHeld: null },
    /not one of the three in interfaces\.md section 3\.1/);
  throws({ measurement: 'BROKEN', state: STATE_NOT_OBSERVED, controlHeld: null }, /section 3\.1/);
  throws({ measurement: 'ok' }, /section 3\.1/);             // case is part of the word
  throws({ measurement: '' }, /section 3\.1/);
  throws({ measurement: null }, /section 3\.1/);              // stating nothing is not stating OK
  throws({ measurement: true }, /section 3\.1/);
});

test('a cell that produced no reading may not also report a property state', () => {
  for (const m of [MEASUREMENT_UNSUPPORTED, MEASUREMENT_BROKEN]) {
    for (const state of ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE']) {
      throws(
        { measurement: m, state, controlHeld: true, completesTheCheck: true },
        /Section 3\.1 pairs a cell that produced no reading/,
      );
    }
  }
});

test('a measurement word in the state column is refused, and the refusal says which column', () => {
  // The pre-3.1 envelope format. Refused rather than mapped -- and the message
  // has to name the fix, or the next person reads "not one of the six" and
  // invents a seventh state.
  for (const word of [MEASUREMENT_UNSUPPORTED, MEASUREMENT_BROKEN]) {
    assert.throws(
      () => computeFragility([cell({ state: word, controlHeld: null, completesTheCheck: false })]),
      (err) => {
        assert.match(err.message, /interfaces\.md section 3/);
        assert.match(err.message, /wrong column/);
        assert.match(err.message, /measurement/);
        return true;
      },
      `state=${word} must be refused with a message that names the column it belongs in`,
    );
  }
});

test('the legal asymmetry stays legal: measurement=OK with state=NOT_OBSERVED', () => {
  // An instrument that ran and found nothing to read. The observer writes this
  // when the subject is not in the translation unit at all -- the record hashes,
  // the control was measured, and there is no reading of this property. A
  // symmetric pairing rule would refuse it and force the producer to relabel a
  // working instrument as a broken one.
  const cells = [
    cell({ cellId: 'read', measurement: MEASUREMENT_OK, state: 'LOST' }),
    cell({
      cellId: 'nothing-to-read',
      config: { opt: '-O0' },
      measurement: MEASUREMENT_OK,
      state: STATE_NOT_OBSERVED,
      controlHeld: true,
      completesTheCheck: true,
    }),
  ];
  const report = computeFragility(cells);

  // Legal to state, and still excluded: legality is about what may be recorded,
  // not about what may be scored.
  assert.equal(report.counts.eligible, 1);
  assert.equal(report.excludedByReason[EXCLUSION_REASONS.NOT_OBSERVED], 1);
  assert.deepEqual(
    classifyCell(cells[1]),
    { eligible: false, reason: EXCLUSION_REASONS.NOT_OBSERVED },
    'an unread cell from a working instrument is excluded as unread, not as a broken measurement',
  );
});

test('an absent measurement column reads as OK and changes no score', () => {
  assert.equal(DEFAULT_MEASUREMENT, MEASUREMENT_OK);
  assert.equal(measurementOf({}), MEASUREMENT_OK);
  assert.equal(measurementOf({ measurement: MEASUREMENT_BROKEN }), MEASUREMENT_BROKEN);

  // The adapter in compiler/envelope/ emits cells without the column. The
  // default is only defensible if adding the column that the cell already
  // implies leaves the number alone.
  const without = [cell({ cellId: 'a', state: 'LOST' }), cell({ cellId: 'b', config: { opt: '-O0' } })];
  const with_ = without.map((c) => ({ ...c, measurement: MEASUREMENT_OK }));
  assert.deepEqual(computeFragility(with_).score, computeFragility(without).score);
});

// --- the Python enforcement, executed ---------------------------------------

function python() {
  for (const cmd of ['python3', 'python']) {
    if (spawnSync(cmd, ['-c', 'print(1)'], { encoding: 'utf8' }).status === 0) return cmd;
  }
  return null;
}
const PY = python();

/** The smallest envelope check-envelope.py will read. It disagrees about a great
 *  deal else -- there is no canary in it -- so the assertions below are on the
 *  section 3.1 message, never on the exit code alone. */
function runCheck(cells) {
  const dir = mkdtempSync(join(tmpdir(), 'meas-vocab-'));
  const path = join(dir, 'envelope.json');
  writeFileSync(path, JSON.stringify({
    schemaVersion: 'security-configuration-envelope-v0',
    component: 'IrCheckpoints',
    axes: {},
    pluginSha256Observed: ['deadbeef'],
    pluginSha256Configured: ['deadbeef'],
    counts: { cells: cells.length, graded: 0, unsupported: 0, brokenMeasurement: 0, handshakeOk: 0 },
    cells,
  }));
  const r = spawnSync(PY, [CHECK_ENVELOPE], {
    encoding: 'utf8',
    env: { ...process.env, IRCK_ENVELOPE_JSON: path },
  });
  rmSync(dir, { recursive: true, force: true });
  return r;
}

const envCell = (over = {}) => ({
  cellId: 'c', control: '-', subject: 'erasure', propertyId: 'erasure.wipe',
  extractor: 'ir.wipe-effect', subjectUnit: 'handle_request', controlUnit: 'wipe_kept',
  config: { opt: '-O2', ndebug: false, lto: 'none', target: 'host', freestanding: false, cc: 'clang-18' },
  rc: 0, pluginSha256: 'deadbeef',
  handshake: { recordWritten: true, component: 'IrCheckpoints', schemaVersion: 'ir-checkpoints-v0',
               moduleId: 'target.c', afterPassObservations: 288, digestVerified: true,
               stage: 'compile', pluginSha256: 'deadbeef', ok: true },
  expectedBroken: false, expectedBrokenReason: '',
  state: 'LOST', reason: 'effect removed', controlHeld: true, completesTheCheck: true,
  firstZeroPass: 'DSEPass', findings: ['VG-PROP-001'],
  subjectEffect: { preOpt: 1, postOpt: 0, unitPresentPostOpt: true },
  measurement: MEASUREMENT_OK,
  ...over,
});

test('check-envelope.py refuses a measurement outside the vocabulary', { skip: PY ? false : 'no python on PATH' }, () => {
  const clean = runCheck([envCell()]);
  assert.ok(!/section 3\.1/.test(clean.stderr),
    'the section 3.1 rules must not fire on a well-formed cell');

  const r = runCheck([envCell({ measurement: 'MEASUREMENT_BROKEN' })]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /is not one of interfaces\.md section 3\.1/);
});

/**
 * One cell manifest and one record on disk, then build-envelope.py over it.
 *
 * The record's digest is recomputed here in a third language, as
 * envelope-labelling.test.mjs does and for the same reason: build-envelope.py
 * throws a record away unless it still hashes to the value it carries, so a
 * record this file assembled without a correct digest would be labelled
 * BROKEN_MEASUREMENT and test the wrong branch entirely.
 */
function runBuild(verdictState) {
  const lab = mkdtempSync(join(tmpdir(), 'meas-build-'));
  mkdirSync(join(lab, 'cells'), { recursive: true });
  mkdirSync(join(lab, 'records'), { recursive: true });

  const unit = {
    allocaCount: 1, allocaSizesBytes: [32], allocasEscapingToOpaqueCall: 1,
    effect: 1, effectCallSites: 1, effectTargets: [], forbiddenCallSites: 0,
    liveConditionalBranches: 0, unitPresent: true, zeroStores: 0,
  };
  const rec = {
    schemaVersion: 'ir-checkpoints-v0', component: 'IrCheckpoints',
    propertyId: 'erasure.wipe', extractor: 'ir.wipe-effect',
    source: 'erasure/target.c', module: 'target.c',
    subjectUnit: 'handle_request', controlUnit: 'wipe_kept',
    subject: { preOptIr: { ...unit }, postOptIr: { ...unit, effect: 0, effectCallSites: 0 } },
    control: { held: true, minEffectObserved: 1, preOptIr: { ...unit }, postOptIr: { ...unit } },
    firstZeroTransition: { from: 1, pass: 'DSEPass', unit: 'handle_request' },
    oracleDivergence: { totalAfterPassObservations: 288 },
    verdict: { state: verdictState, reason: 'x', completesTheCheck: true },
    findings: [],
  };
  const canonical = (v) => {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  };
  const stripped = Object.fromEntries(
    Object.entries(rec).filter(([k]) => k !== 'context' && k !== 'evidenceDigest'),
  );
  rec.evidenceDigest = createHash('sha256').update(canonical(stripped), 'utf8').digest('hex');

  const kv = {
    cellId: 'c1', subject: 'erasure', propertyId: 'erasure.wipe',
    extractor: 'ir.wipe-effect', subjectUnit: 'handle_request', controlUnit: 'wipe_kept',
    opt: '-O2', ndebug: '0', lto: 'none', target: 'host', freestanding: '0',
    stage: 'compile', cc: 'clang-18', rc: '0', pluginSha256: 'deadbeef',
    expectedBroken: '0', expectedBrokenReason: '', record: 'records/c1.json',
    extraArgsB64: '', stderrB64: '',
  };
  writeFileSync(join(lab, 'cells', 'c1.kv'),
    Object.entries(kv).map(([k, v]) => `${k}=${v}`).join('\n') + '\n');
  writeFileSync(join(lab, 'records', 'c1.json'), JSON.stringify(rec));

  const r = spawnSync(PY, [BUILD_ENVELOPE], {
    encoding: 'utf8',
    env: { ...process.env, IRCK_ENV_LAB: lab, IRCK_ENVELOPE_OUT: join(lab, 'out') },
  });
  rmSync(lab, { recursive: true, force: true });
  return r;
}

test('build-envelope.py refuses to write an envelope whose label columns are unreadable', { skip: PY ? false : 'no python on PATH' }, () => {
  // A graded cell's state is copied straight out of the record's verdict, so an
  // observer emitting a word section 3 does not define is the input that reaches
  // this guard. Without it the word lands in the state column and is graded.
  const ok = runBuild('LOST');
  assert.equal(ok.status, 0, `a well-formed cell must still assemble: ${ok.stderr}`);

  // The precise confusion section 3.1 exists to stop: a measurement word arriving
  // in the state column.
  const swapped = runBuild(MEASUREMENT_BROKEN);
  assert.equal(swapped.status, 3,
    'interfaces.md section 7: a check that could not be completed is 3, never 0');
  assert.match(swapped.stderr, /interfaces\.md section 3\.1 is not satisfied/);
  assert.match(swapped.stderr, /not one of the six in interfaces\.md section 3/);

  // And any other invented state, so the check above is not passing on a
  // hardcoded list of two words.
  const invented = runBuild('SURVIVED');
  assert.equal(invented.status, 3);
  assert.match(invented.stderr, /not one of the six/);
});

test('check-envelope.py refuses a broken measurement that reports a state', { skip: PY ? false : 'no python on PATH' }, () => {
  const r = runCheck([envCell({ measurement: MEASUREMENT_BROKEN, state: 'PRESENT' })]);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /Section 3\.1 pairs a cell that produced no reading/);

  // The paired form of the same cell must not trip the rule -- otherwise the
  // check above would pass on an implementation that rejected every broken cell.
  const paired = runCheck([envCell({
    measurement: MEASUREMENT_BROKEN, state: STATE_NOT_OBSERVED, controlHeld: null,
    completesTheCheck: false, expectedBroken: true, expectedBrokenReason: 'observer unregistered',
    handshake: { ...envCell().handshake, ok: false }, firstZeroPass: null, findings: [],
  })]);
  assert.ok(!/Section 3\.1 pairs/.test(paired.stderr),
    'a correctly paired broken cell must be accepted by the pairing rule');
});
