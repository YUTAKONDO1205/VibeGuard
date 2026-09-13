/**
 * The drift test: the tracked record of the full gate run, and the README's
 * numbers checked back against it.
 *
 * WHY THIS FILE EXISTS
 *
 * Until 2026-09-12 this lane wrote nothing into the checkout. Everything it had
 * ever measured lived in a lab directory outside the repository, and the only
 * record of it was prose in README.md: eleven configurations, nine of them
 * discriminating, the injection red. Prose cannot fail. Every other lane here
 * keeps its numbers where a test can recompute them -- version-ladder's
 * data/version-ladder-sweep.json, lto-window's four intervention pairs,
 * repair-loop's pin families -- and this one, the lane whose entire subject is
 * refusing measurements that were never checked, was the exception.
 *
 * WHAT IS RECOMPUTED AND WHAT IS READ BACK (the provenance question of
 * repair-loop/PIN-FAMILIES.md, asked of this record):
 *
 *   recomputed  the grades. Every recorded reading is graded again here by
 *               lib/spike.mjs against claims/spike-expected.json, and the
 *               recorded recovery, `held` and `discriminating` must be what
 *               today's grader and today's claims produce. If either moves, the
 *               record no longer describes a run this lane would accept.
 *   read back   the README's numbers. They are extracted with regular
 *               expressions from README.md and compared against the record --
 *               the summary line, the discriminating ratio in three places, the
 *               count of differential readings, the misspelt suffix, and the
 *               command the README says produced the run.
 *   neither     the verdicts themselves. What clang-18 -O2 did to a dead store
 *               is not recomputable without a compiler, and this suite runs
 *               without one. The record is the evidence; these tests are the
 *               guard on it.
 *
 * A MISSING RECORD IS A FAILURE, NOT A SKIP. `{ skip: ... }` on an absent
 * data file is how a suite reports green for a lane that has never run: "we did
 * not look" printed as "it was clean" is the one thing this lane exists to
 * refuse, and it would be absurd for its own test to do it.
 *
 * No compiler is used here. Every check reads tracked files.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { loadExpected, expectedFor, observerExpectedFor, registeredConfigurations } from '../lib/claims.mjs';
import { gradeSpike, NOT_A_READING, SPIKES } from '../lib/spike.mjs';
import { SUBJECTS, MISSPELT_SUFFIX } from '../lib/measure.mjs';
import { RECORD_VERSION, DATA_FILE, unwritableValues } from '../lib/data-record.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const DATA_DIR = join(LANE, 'data');
const DATA_PATH = join(DATA_DIR, DATA_FILE);

const HOW = `Run the lane and record it:\n`
  + `    node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike-final \\\n`
  + `        --cc clang-18,gcc-13 --opt -O0,-O1,-O2,-O3,-Os --inject-at -O0,-O2 \\\n`
  + `        --observer ~/vg-build/pass-observer/libPropertyObserver.so --write-data`;

/**
 * The record, or a failure saying how to produce it.
 *
 * Read lazily, per test, so that an absent file fails every test that needs it
 * with the same instruction rather than killing the file at import time and
 * reporting one error for a dozen unmade checks.
 */
function record() {
  if (!existsSync(DATA_PATH)) {
    assert.fail(`compiler/eval/spike/data/${DATA_FILE} does not exist, so none of this lane's numbers `
      + `is checked by anything. This is a FAILURE and not a skip: a suite that goes green on an `
      + `absent record reports "we did not look" as "it was clean".\n${HOW}`);
  }
  return JSON.parse(readFileSync(DATA_PATH, 'utf8'));
}

const recordText = () => {
  record();
  return readFileSync(DATA_PATH, 'utf8');
};

/** Prose wraps and is marked up; a number is the same number whichever column it broke at. */
const flat = (t) => t.replace(/\s+/g, ' ');
const README = readFileSync(join(LANE, 'README.md'), 'utf8');
const README_FLAT = flat(README);

/** The README spells small counts as words in prose and as digits in the record. */
const NUMBER_WORDS = Object.freeze({
  zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9,
  ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16,
  seventeen: 17, eighteen: 18, nineteen: 19, twenty: 20, thirty: 30, forty: 40, fifty: 50,
});
const numberWord = (w) => {
  const n = NUMBER_WORDS[String(w).toLowerCase()];
  assert.ok(n !== undefined, `the README spells a count as ${JSON.stringify(w)}, which this test cannot read as a number`);
  return n;
};

/** The "What was measured" section, which is the part of the README this record is of. */
function measuredSection() {
  const start = README.indexOf('\n## What was measured');
  assert.ok(start >= 0, 'README.md has no "## What was measured" section');
  const rest = README.slice(start + 1);
  const end = rest.indexOf('\n## ', 1);
  return end < 0 ? rest : rest.slice(0, end);
}

// ------------------------------------------------------------- the record ---

test('the record exists, and data/ holds it and nothing else', () => {
  const r = record();
  assert.equal(r.record, RECORD_VERSION);
  assert.equal(r.schemaVersion, 'vibeguard.spike-gate/1');
  assert.equal(r.established, true, 'only an ESTABLISHED run may be recorded');
  const files = readdirSync(DATA_DIR).filter((f) => !f.startsWith('.')).sort();
  assert.deepEqual(files, [DATA_FILE], 'data/ is the record and nothing else');
});

test('the record carries no float, no machine path and no home directory', () => {
  const r = record();
  // Both directions: the structured walk (which is also what the runner ran
  // before writing) and a scan of the bytes, because a path can hide in a key
  // as easily as in a value.
  assert.deepEqual(unwritableValues(r), []);
  assert.deepEqual(absolutePathHits(recordText()), []);
  assert.doesNotMatch(recordText(), /\d\.\d/, 'a decimal point in the record: interfaces.md section 5 keeps ratios as {num, den}');
});

test('the two spikes in the record are the two the lane mixes in', () => {
  const r = record();
  assert.deepEqual(r.subjects.map((s) => s.spike).sort(), [...SPIKES].sort());
  for (const s of SUBJECTS) {
    const got = r.subjects.find((x) => x.spike === s.spike);
    assert.ok(got, `${s.spike} is not in the record`);
    assert.equal(got.file, s.file);
    assert.equal(got.fn, s.fn);
  }
});

// --------------------------------------------------------- the full matrix ---

test('every registered configuration was measured, plus the observer channel, and all of them held', () => {
  const r = record();
  const doc = loadExpected();
  const registered = registeredConfigurations(doc).map((c) => `${c.vendor} ${c.opt}`).sort();
  const differential = r.configurations.filter((c) => c.channel === 'differential');
  assert.deepEqual(differential.map((c) => `${c.vendor} ${c.opt}`).sort(), registered,
    'the record is not the full matrix of registered configurations');

  const observer = r.configurations.filter((c) => c.channel === 'observer');
  assert.equal(observer.length, 1, 'the second channel is one configuration, and it is not optional in the record');
  assert.equal(r.observerChannel.requested, true);
  assert.equal(r.observerChannel.available, true);
  assert.equal(observer[0].opt, r.observerChannel.opt);

  for (const c of r.configurations) {
    assert.equal(c.held, true, `${c.vendor} ${c.opt} [${c.channel}] did not hold`);
    assert.equal(c.recovery, '2/2', `${c.vendor} ${c.opt} [${c.channel}]`);
    assert.deepEqual(c.recovered, { num: 2, den: 2 });
  }
  assert.deepEqual(r.counting.configurations, { num: r.configurations.length, den: r.configurations.length });
  assert.equal(r.counting.byChannel.differential, differential.length);
  assert.equal(r.counting.byChannel.observer, 1);
});

test('the recorded grades are what today\'s grader and today\'s claims produce', () => {
  // The recomputation. Everything else in this file checks that the record is
  // internally consistent and that the README agrees with it; this checks that
  // the record is still a run this lane would ACCEPT. A claims entry edited to
  // fit a later reading, or a grader that stopped requiring the control, moves
  // the grade here and the drift is the result.
  const r = record();
  const doc = loadExpected();
  for (const c of r.configurations) {
    const expected = c.channel === 'observer' ? observerExpectedFor(doc, c.opt) : expectedFor(doc, c.vendor, c.opt);
    assert.ok(expected, `nothing is registered for ${c.vendor} ${c.opt} [${c.channel}], so the record cannot be graded`);
    const grade = gradeSpike(c.readings, expected);
    assert.deepEqual(grade.violations, [], `${c.vendor} ${c.opt} [${c.channel}] regrades with violations`);
    assert.equal(grade.recovery, c.recovery, `${c.vendor} ${c.opt} [${c.channel}]: recovery`);
    assert.equal(grade.held, c.held, `${c.vendor} ${c.opt} [${c.channel}]: held`);
    assert.equal(grade.discriminating, c.discriminating, `${c.vendor} ${c.opt} [${c.channel}]: discriminating`);
    assert.equal(grade.sharedAnswer, c.sharedAnswer, `${c.vendor} ${c.opt} [${c.channel}]: sharedAnswer`);
  }
});

test('every reading is a reading: a verdict word, and the co-resident control PRESENT', () => {
  const r = record();
  for (const c of r.configurations) {
    assert.equal(c.readings.length, 2, `${c.vendor} ${c.opt} [${c.channel}] recorded ${c.readings.length} readings`);
    assert.deepEqual(c.readings.map((x) => x.spike).sort(), [...SPIKES].sort());
    for (const x of c.readings) {
      assert.equal(NOT_A_READING.includes(x.verdict), false,
        `${c.vendor} ${c.opt} [${c.channel}] ${x.spike}: ${x.verdict} is a word about the instrument, not a reading`);
      assert.equal(x.control, 'PRESENT',
        `${c.vendor} ${c.opt} [${c.channel}] ${x.spike}: the co-resident control was ${x.control}`);
    }
  }
  assert.equal(r.counting.readings, r.configurations.reduce((n, c) => n + c.readings.length, 0));
});

test('the non-discriminating rows are exactly the -O0 rows, and they stay in the matrix', () => {
  // 2/2 at -O0 is also what an instrument that can only ever say WIPE_SURVIVED
  // would score, and that instrument existed: it passed this gate before
  // 2026-09-12. The count is the record's own statement of how much of the run
  // could have caught it.
  const r = record();
  const blind = r.configurations.filter((c) => !c.discriminating);
  assert.deepEqual([...new Set(blind.map((c) => c.opt))], ['-O0'],
    'a configuration above -O0 registers one word twice, or a -O0 row now discriminates');
  for (const c of blind) assert.equal(c.sharedAnswer, 'WIPE_SURVIVED');
  assert.equal(r.counting.discriminating.den, r.configurations.length);
  assert.equal(r.counting.discriminating.num, r.configurations.length - blind.length);
  assert.ok(r.counting.discriminating.num > 0, 'a run of non-discriminating configurations is not ESTABLISHED');
});

test('the injection went red on both vendors and on the observer channel, and the record says why', () => {
  const r = record();
  assert.equal(r.injected.misspeltSuffix, MISSPELT_SUFFIX);
  assert.equal(r.injected.wentRed, true);
  assert.ok(r.injected.configurations.length > 0, 'the gate was never shown to go red');
  assert.equal(r.counting.injectedConfigurations, r.injected.configurations.length);

  const vendors = new Set(r.configurations.filter((c) => c.channel === 'differential').map((c) => c.vendor));
  const injected = new Set(r.injected.configurations.filter((c) => c.channel === 'differential').map((c) => c.vendor));
  assert.deepEqual([...injected].sort(), [...vendors].sort(), 'the injection did not cover every measured vendor');
  assert.ok(r.injected.configurations.some((c) => c.channel === 'observer'),
    'the observer channel was never shown to go red');

  for (const c of r.injected.configurations) {
    // gradeable is the anti-vacuous-pass half: an injection at a configuration
    // nothing is registered for is red whatever came back, so `wentRed` alone
    // would say nothing about the gate's sensitivity.
    assert.equal(c.gradeable, true, `${c.vendor} ${c.opt} [${c.channel}]: the injection was not gradeable`);
    assert.equal(c.wentRed, true, `${c.vendor} ${c.opt} [${c.channel}]: the gate stayed green on a misspelt subject`);
    assert.ok(c.redBecause.length > 0, `${c.vendor} ${c.opt} [${c.channel}]: red for no recorded reason`);
    assert.ok(c.redBecause.includes('NOT_A_READING'),
      `${c.vendor} ${c.opt} [${c.channel}]: refused because of ${c.redBecause.join(', ')}, not because the `
      + 'misspelt subject produced no reading -- the injection tested something other than what it claims to test');
  }
});

// -------------------------------------------------------------- the README ---
//
// Each of these names the README line it reads. A run that moves a number and
// leaves the prose alone fails here rather than shipping a document that
// describes a different run from the one in data/.

test('README: the summary line under "What was measured" is this run\'s summary line', () => {
  const r = record();
  assert.ok(typeof r.summaryLine === 'string' && r.summaryLine.startsWith('spike gate: '),
    'the record carries no summary line');
  assert.ok(measuredSection().includes(r.summaryLine),
    `README.md's "What was measured" block does not carry this run's summary line verbatim:\n  ${r.summaryLine}`);
  // and the two halves of it that a reader quotes on their own
  assert.ok(r.summaryLine.includes('ESTABLISHED'));
  assert.ok(r.summaryLine.includes('injection RED (as required)'),
    'the recorded run did not print the injection as red');
});

test('README: the discriminating ratio agrees with the record in all three places it appears', () => {
  const r = record();
  const { num, den } = r.counting.discriminating;

  // (1) on the summary line: `-- 9/11 discriminating`
  const online = /--\s*(\d+)\/(\d+) discriminating/.exec(r.summaryLine);
  assert.ok(online, `the recorded summary line carries no discriminating ratio: ${r.summaryLine}`);
  assert.deepEqual([Number(online[1]), Number(online[2])], [num, den]);

  // (2) the sentence under the block: "Nine of the eleven configurations discriminate"
  // Searched inside "What was measured" rather than the whole file: a
  // sentence of the same shape anywhere above it would be matched first,
  // and this test would then grade the record against another run's prose.
  const measured = flat(measuredSection());
  const prose = /(\w+) of the (\w+) configurations discriminate/.exec(measured);
  assert.ok(prose, 'README.md no longer says how many configurations discriminate');
  assert.deepEqual([numberWord(prose[1]), numberWord(prose[2])], [num, den],
    'the README\'s sentence about discriminating configurations is not the record\'s count');

  // (3) the paragraph about what the written report carries
  const graded = /(\d+) configurations graded/.exec(measured);
  assert.ok(graded, 'README.md no longer says how many configurations were graded');
  assert.equal(Number(graded[1]), r.configurations.length);
  const cfg = /`verdict\.configurations`\s*`\{num: (\d+), den: (\d+)\}`/.exec(measured);
  const disc = /`verdict\.discriminating`\s*`\{num: (\d+), den: (\d+)\}`/.exec(measured);
  assert.ok(cfg && disc, 'README.md no longer quotes verdict.configurations and verdict.discriminating');
  assert.deepEqual([Number(cfg[1]), Number(cfg[2])], [r.counting.configurations.num, r.counting.configurations.den]);
  assert.deepEqual([Number(disc[1]), Number(disc[2])], [num, den]);
});

test('README: the count of differential readings whose control was PRESENT is the one the prose gives', () => {
  const r = record();
  const controlled = r.configurations
    .filter((c) => c.channel === 'differential')
    .reduce((n, c) => n + c.readings.filter((x) => x.control === 'PRESENT').length, 0);
  const m = /control PRESENT in all (\w+)/.exec(README_FLAT);
  assert.ok(m, 'README.md no longer says in how many readings the control was PRESENT');
  assert.equal(numberWord(m[1]), controlled,
    'the README\'s count of PRESENT controls is not the number of differential readings in the record');
});

test('README: the injection is described with the suffix the record was measured with', () => {
  const r = record();
  assert.ok(README_FLAT.includes(`subject name + "${r.injected.misspeltSuffix}"`),
    `README.md does not show the injection as the subject name plus "${r.injected.misspeltSuffix}"`);
});

test('README: the command quoted in "What was measured" is the command that produced the record', () => {
  // The provenance line. A record whose README shows a different invocation is a
  // record nobody can re-run, which is the defect the fortify probe in the
  // version-ladder lane was written to fix.
  const r = record();
  const block = flat(measuredSection());
  assert.ok(/\$ node compiler\/eval\/spike\/run-spike\.mjs/.test(block),
    'the "What was measured" block no longer quotes the command that was run');
  assert.ok(/--write-data/.test(block),
    'the quoted command does not carry --write-data, so it is not the command that wrote data/' + DATA_FILE);
  const list = (re, what) => {
    const m = re.exec(block);
    assert.ok(m, `the quoted command names no ${what}`);
    return m[1].split(',');
  };
  assert.deepEqual(list(/--cc ([^\s]+)/, '--cc'), r.requested.compilers);
  assert.deepEqual(list(/--opt ([^\s]+)/, '--opt'), r.requested.levels);
  assert.deepEqual(list(/--inject-at ([^\s]+)/, '--inject-at'), r.requested.injectedAt);
  assert.ok(/--observer /.test(block), 'the quoted command does not run the observer channel');
});

test('README: the "Measured" line names every compiler the record was taken on', () => {
  const r = record();
  const line = README.split('\n').find((l) => l.startsWith('Measured 20'));
  assert.ok(line, 'README.md has no "Measured <date> on ..." line');
  const sentence = flat(README.slice(README.indexOf(line), README.indexOf(line) + 400));
  for (const cc of r.requested.compilers) {
    assert.ok(sentence.includes(cc), `the "Measured" line does not name ${cc}`);
  }
});
