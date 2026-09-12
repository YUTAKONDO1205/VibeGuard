/**
 * Tests for the parts of the lane that are not the grader: the separation
 * between the half that measures and the half that holds the answers, the shape
 * of the two subjects, and the claims file.
 *
 * No compiler is used. Every check here reads tracked source or tracked data.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CONTROL, wipeSpans } from '../../ai-generated/lib/ablation-cell.mjs';
import { absolutePathHits } from '../../repair-loop/lib/provenance.mjs';
import { SUBJECTS, MISSPELT_SUFFIX, insideRepo } from '../lib/measure.mjs';
import { loadExpected, expectedFor, registeredConfigurations, observerExpectedFor, claimsLabel } from '../lib/claims.mjs';
import { NOT_A_READING, SPIKES } from '../lib/spike.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const LANE = resolve(HERE, '..');
const REPO = resolve(LANE, '../../..');

const laneFile = (f) => readFileSync(join(LANE, f), 'utf8');
/** Prose wraps; a quotation is the same quotation whichever column it broke at. */
const flat = (text) => text.replace(/\s+/g, ' ');

// ------------------------------------------------------------ separation ---

test('the measuring half cannot reach the answers', () => {
  const src = readFileSync(join(LANE, 'lib', 'measure.mjs'), 'utf8');
  // Not style policing: this is the whole guarantee. An instrument that can read
  // the expected answer can be tuned until it agrees with it, and afterwards
  // nobody can tell whether it was tuned or measured.
  assert.equal(/claims/i.test(src), false, 'lib/measure.mjs must not mention the claims file');
  assert.equal(/spike-expected/.test(src), false);
  assert.equal(/WIPE_ELIMINATED|WIPE_SURVIVED/.test(src), false,
    'lib/measure.mjs must not spell a verdict it could compare against');
});

test('the grader is pure: it reads nothing and runs nothing', () => {
  const src = readFileSync(join(LANE, 'lib', 'spike.mjs'), 'utf8');
  for (const forbidden of ['node:fs', 'node:child_process', 'node:process', 'readFileSync', 'execFile']) {
    assert.equal(src.includes(forbidden), false, `lib/spike.mjs must not use ${forbidden}`);
  }
  assert.equal(/^import /m.test(src), false, 'lib/spike.mjs imports nothing');
});

test('only lib/claims.mjs opens the claims file', () => {
  for (const f of ['lib/measure.mjs', 'lib/spike.mjs', 'lib/observer.mjs', 'run-spike.mjs']) {
    const src = readFileSync(join(LANE, f), 'utf8');
    assert.equal(/spike-expected\.json/.test(src), false, `${f} must not name the claims file`);
  }
  assert.equal(/spike-expected\.json/.test(readFileSync(join(LANE, 'lib', 'claims.mjs'), 'utf8')), true);
});

test('a lab directory inside the repository is refused', () => {
  assert.equal(insideRepo(join(REPO, 'compiler', 'eval', 'spike')), true);
  assert.equal(insideRepo(REPO), true);
  assert.equal(insideRepo(resolve(REPO, '..', 'somewhere-else')), false);
});

// -------------------------------------------------------------- subjects ---

test('each subject presents exactly one wipe span to the shared instrument', () => {
  for (const s of SUBJECTS) {
    const src = readFileSync(join(LANE, 'subjects', s.file), 'utf8') + CONTROL;
    const r = wipeSpans(src, s.fn);
    assert.equal(r.spans.length, 1, `${s.file} should offer one span, got ${r.spans.length}`);
    assert.equal(r.scoped, true, `${s.file}: the target function's body must be found`);
    assert.deepEqual(r.helpers, [], `${s.file}: no function here may be taken for a wipe helper`);
  }
});

test('the misspelt name still reaches the same span, so the injection fails for its own reason', () => {
  // If the misspelt run found NO span it would fail as NO_WIPE_WRITTEN, which is
  // also a refusal -- but a refusal for a second, accidental reason. The
  // injection is only a demonstration of the gate when the reading that comes
  // back is the one the typo causes: no body to read, hence NOT_OBSERVED.
  for (const s of SUBJECTS) {
    const src = readFileSync(join(LANE, 'subjects', s.file), 'utf8') + CONTROL;
    const r = wipeSpans(src, s.fn + MISSPELT_SUFFIX);
    assert.equal(r.spans.length, 1, `${s.file}: the name gate must still find the wipe`);
    assert.equal(r.scoped, false, `${s.file}: the misspelt name must NOT resolve to a body`);
  }
});

test('neither subject returns void', () => {
  // wipeHelpers() treats a VOID function whose body zeroes as a wipe helper and
  // then matches its own definition header as a call to itself; the ablated form
  // loses the header and every cell reads ABLATION_DID_NOT_COMPILE. Measured on
  // 2026-09-12 before the subjects were changed to return int, which is what the
  // r2 corpus's twenty subjects do.
  for (const s of SUBJECTS) {
    const src = readFileSync(join(LANE, 'subjects', s.file), 'utf8');
    assert.equal(new RegExp(`\\bvoid\\s+${s.fn}\\s*\\(`).test(src), false,
      `${s.file} must not declare ${s.fn} as void`);
    assert.equal(new RegExp(`\\bint\\s+${s.fn}\\s*\\(`).test(src), true);
  }
});

test('no subject spells a wipe-symbol list', () => {
  for (const s of SUBJECTS) {
    const src = readFileSync(join(LANE, 'subjects', s.file), 'utf8');
    assert.equal(/(llvm\.memset|memset|explicit_bzero|bzero|__memset_chk|memset_s)(\s*,\s*[A-Za-z0-9_.]+)+/.test(src), false);
  }
});

// ---------------------------------------------------------------- claims ---

test('the claims file registers both vendors at five levels', () => {
  const doc = loadExpected();
  const cfgs = registeredConfigurations(doc);
  assert.equal(cfgs.length, 10);
  for (const vendor of ['clang-18', 'gcc-13']) {
    for (const opt of ['-O0', '-O1', '-O2', '-O3', '-Os']) {
      const e = expectedFor(doc, vendor, opt);
      assert.ok(e, `${vendor} ${opt} must be registered`);
      for (const spike of SPIKES) assert.equal(typeof e[spike], 'string');
    }
  }
});

test('no registered answer is a word that means no reading came back', () => {
  const doc = loadExpected();
  for (const { vendor, opt } of registeredConfigurations(doc)) {
    const e = expectedFor(doc, vendor, opt);
    for (const spike of SPIKES) {
      assert.equal(NOT_A_READING.includes(e[spike]), false, `${vendor} ${opt} ${spike} registers a failure word`);
    }
  }
});

test('an unregistered configuration resolves to null rather than to something permissive', () => {
  const doc = loadExpected();
  assert.equal(expectedFor(doc, 'clang-19', '-O2'), null);
  assert.equal(expectedFor(doc, 'clang-18', '-Ofast'), null);
});

test('the -O0 entries agree with the tracked rows they are grounded in', () => {
  // compiler/eval/ai-generated/data/r2-build-rows.json is tracked measurement,
  // not an assumption: if a future re-measurement ever puts an elimination at
  // -O0 there, the ground under the -O0 expectation has moved and this fails
  // rather than the gate quietly staying green.
  const rows = JSON.parse(readFileSync(join(REPO, 'compiler/eval/ai-generated/data/r2-build-rows.json'), 'utf8'));
  const doc = loadExpected();
  for (const vendor of ['clang-18', 'gcc-13']) {
    const eliminated = rows.filter((r) => r.kind === 'erasure' && r.cc === vendor && r.opt === '-O0'
      && r.verdict === 'WIPE_ELIMINATED').length;
    assert.equal(eliminated, 0, `${vendor} -O0 now has ${eliminated} eliminations in the tracked rows`);
    assert.equal(expectedFor(doc, vendor, '-O0').disappearing, 'WIPE_SURVIVED');
  }
});

test('-O0 registers one word twice, and every vendor also registers a level that does not', () => {
  // The fact the discrimination rule exists for. At -O0 both spikes are
  // registered WIPE_SURVIVED -- correctly, the tracked rows have never put an
  // elimination there -- so 2/2 at -O0 is also what an instrument that can only
  // ever report WIPE_SURVIVED would score. A run of such configurations alone is
  // refused by gateVerdict; this pins that the claims file still offers a way
  // out, per vendor, rather than the rule becoming unsatisfiable.
  const doc = loadExpected();
  for (const vendor of ['clang-18', 'gcc-13']) {
    const o0 = expectedFor(doc, vendor, '-O0');
    assert.equal(o0.disappearing, o0.surviving, `${vendor} -O0 is expected to be non-discriminating`);

    const discriminating = registeredConfigurations(doc)
      .filter((c) => c.vendor === vendor)
      .filter(({ opt }) => {
        const e = expectedFor(doc, vendor, opt);
        return e && e.disappearing !== e.surviving;
      });
    assert.ok(discriminating.length > 0, `${vendor} registers no configuration whose two answers differ`);
    assert.equal(discriminating.some((c) => c.opt === '-O0'), false);
  }
  // And the observer channel's registered pair differs too, so the second
  // channel can be a run's discriminating configuration on its own.
  const obs = observerExpectedFor(doc, '-O2');
  assert.notEqual(obs.disappearing, obs.surviving);
});

// ------------------------------------------------- what an error may say ---

test('an unreadable claims file is named relative to the repository, never by machine path', () => {
  // Node's ENOENT message ends in the absolute path it tried to open; gate.mjs
  // puts that message into verdict.reasons, and run-spike.mjs's own absolute-path
  // guard then fires FIRST -- so the operator was told the report carries a path
  // and never that the expectations were missing. Measured 2026-09-12.
  const missing = join(LANE, 'claims', 'this-file-is-not-here.json');
  assert.throws(() => loadExpected(missing), (err) => {
    assert.deepEqual(absolutePathHits(err.message), [], `the message carries a machine path: ${err.message}`);
    assert.equal(err.message.includes('compiler/eval/spike/claims/this-file-is-not-here.json'), true, err.message);
    assert.equal(err.message.includes('ENOENT'), true, err.message);
    return true;
  });

  // A file outside the repository is named by its basename alone: a
  // repository-relative label of "../../.." would be a machine path with extra
  // steps.
  const outside = join(tmpdir(), `vgspike-lane-test-${process.pid}.json`);
  writeFileSync(outside, '{ "schemaVersion": ', 'utf8');
  try {
    assert.throws(() => loadExpected(outside), (err) => {
      assert.deepEqual(absolutePathHits(err.message), [], `the message carries a machine path: ${err.message}`);
      assert.equal(err.message.includes(`vgspike-lane-test-${process.pid}.json`), true, err.message);
      return true;
    });
  } finally {
    rmSync(outside, { force: true });
  }
  assert.equal(claimsLabel(outside), `vgspike-lane-test-${process.pid}.json`);
});

// ------------------------------------------------------------ the README ---

test('what the README says a run that is not established writes is what run-spike.mjs does', () => {
  // The old sentence was "A run that is not `established` is reported NOT
  // ESTABLISHED and writes nothing." It writes spike-gate.json whenever
  // --no-write was not passed, red or green: only the claim about DATA was true.
  // A README that claims more than the code does is the defect this repository
  // exists to prevent, so the sentence was narrowed rather than the behaviour
  // changed -- the red report is the copy a reader needs.
  const readme = flat(laneFile('README.md'));
  assert.equal(readme.includes('is reported NOT ESTABLISHED and writes nothing'), false,
    'the README claims a red run writes nothing; run-spike.mjs writes spike-gate.json');
  assert.equal(readme.includes('unless `--no-write` is passed'), true,
    'the README must say what actually stops the report being written');

  const cli = laneFile('run-spike.mjs');
  const guard = cli.slice(cli.indexOf('if (args.write) {'));
  assert.equal(guard.includes("writeFileSync(join(lab, 'spike-gate.json')"), true);
  assert.equal(/established/.test(guard.slice(0, guard.indexOf('writeFileSync'))), false,
    'the write is not gated on the verdict, and the README must not say it is');
});

test('the requireControl contract describes a call that exists', () => {
  // The JSDoc said "the observer channel passes false, because its control is a
  // separate reading of its own rather than a column on this one". It does not:
  // gate.mjs calls gradeSpike(main.readings, wantObs) with no options on BOTH
  // channels, and the observer's readings do carry a control column, filled from
  // the plugin's own control SUMMARY row -- measured 2026-09-12, clang-18 -O2,
  // both observer rows control=PRESENT. Someone auditing the co-resident-control
  // invariant was told the wrong thing about which channel enforces it, and the
  // option is exercised only by test/spike.test.mjs.
  assert.equal(/requireControl/.test(laneFile('lib/gate.mjs')), false,
    'gate.mjs passes no requireControl option; the JSDoc must not say it does');
  assert.equal(/observer channel passes false/.test(flat(laneFile('lib/spike.mjs'))), false,
    'lib/spike.mjs documents a call gate.mjs does not make');
});

test('the lane quotes interfaces.md on UNSUPPORTED rather than characterising it', () => {
  // The old sentence said interfaces.md "reserves" that word for a toolchain
  // that refused. Its definition has a second sentence -- "The configuration was
  // asked for and could not be built." -- which can be read to cover a compiler
  // that is not installed, so the file does not settle the question and this lane
  // must not report a selective reading of it as settled. The exit-3 mapping is
  // unchanged; what changed is that the README now quotes the source and says
  // which part is this lane's choice.
  const iface = readFileSync(join(REPO, 'compiler/schema/interfaces.md'), 'utf8');
  const row = iface.split('\n').find((l) => l.startsWith('| `UNSUPPORTED` |'));
  assert.ok(row, 'interfaces.md no longer carries an UNSUPPORTED row');
  const definition = row.split('|')[2].trim();
  // A quotation wraps and carries markdown's blockquote marker; neither changes
  // what was quoted, and both have to go before the text can be compared.
  const readme = flat(laneFile('README.md').replace(/^\s*>\s?/gm, ''));
  for (const sentence of definition.split('. ').map((s) => s.trim()).filter(Boolean)) {
    assert.equal(readme.includes(sentence.replace(/\.$/, '')), true,
      `the README must quote interfaces.md, not paraphrase it: ${sentence}`);
  }
  for (const f of ['README.md', 'lib/measure.mjs', 'lib/gate.mjs', 'run-spike.mjs']) {
    assert.equal(/reserves (that word|it)|3\.1 reserves/.test(laneFile(f)), false,
      `${f} states one reading of interfaces.md section 3.1 as that file's settled meaning`);
  }
});

test('every wiring patch carries the discrimination rule to the file it is asking to change', () => {
  // The patches pass the CALLER's levels straight through, so a caller whose
  // levels are all non-discriminating (-O0 alone) would get a green gate from a
  // blind instrument. The gate now refuses that by itself; the patches are what
  // another lane's owner reads, so each one has to say so.
  const readme = laneFile('README.md');
  const sections = readme.split('\n### ').slice(1);
  const patches = sections.filter((s) => /^[1-4]\. `/.test(s));
  assert.equal(patches.length, 4, `expected the four wiring patches, found ${patches.length}`);
  for (const p of patches) {
    const title = p.split('\n')[0];
    assert.equal(/discriminating/i.test(p), true, `patch "${title}" does not mention the discrimination rule`);
  }
});

test('the observer channel is registered in interfaces.md section 3 words, not ablation verdicts', () => {
  const doc = loadExpected();
  const e = observerExpectedFor(doc, '-O2');
  assert.ok(e);
  const STATES = ['PRESENT', 'ABSENT', 'LOST', 'REINTRODUCED', 'NOT_APPLICABLE', 'NOT_OBSERVED'];
  for (const spike of SPIKES) assert.equal(STATES.includes(e[spike]), true, `${spike}: ${e[spike]} is not a property state`);
  assert.equal(e.disappearing, 'LOST');
  assert.equal(e.surviving, 'PRESENT');
});
