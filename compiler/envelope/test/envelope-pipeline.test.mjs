/**
 * Tests for the envelope pipeline driver.
 *
 * The driver's whole job is what it does with exit codes, so that is what is
 * tested: the order stages run in, the code that comes out, and — the reason
 * this file exists at all — that a stage which says "I could not check" cannot
 * come out the other end as a clean run.
 *
 * The stage runner is injected. That is not a way of avoiding the real stages;
 * the real stages need clang, an LLVM plugin and a linker, and a test that
 * skipped itself on every developer machine would assert nothing on any of them.
 * What is asserted here is the composition rule, which is the part this file
 * added and the part that can silently rot.
 *
 * Test data is inline rather than in a directory beside this file, for the same
 * reason fragility.test.mjs says so: a path segment named `fixtures` under
 * compiler/ is a committable measurement input and
 * scripts/check-packaging-invariants.mjs fails the build on one.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  EXIT,
  REQUIRED_TOOLS,
  PipelineError,
  planStages,
  preflight,
  formatMissingTools,
  decideOutcome,
  runPipeline,
  pipelineRecord,
  pipelineArtefacts,
  parseArgv,
  main,
} from '../envelope-pipeline.mjs';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'envelope-pipeline.mjs');

function tmp() {
  return mkdtempSync(join(tmpdir(), 'envelope-pipeline-'));
}

/** A stage runner that returns a scripted code per stage id, and records order. */
function scripted(codes) {
  const seen = [];
  const runRun = (run) => {
    // The stage is identified from what it was asked to execute, so the double
    // bookkeeping between the plan and the script cannot drift.
    const argv = run.argv.join(' ');
    const id = argv.includes('run-envelope.sh')
      ? 'sweep'
      : argv.includes('build-envelope.py')
        ? 'assemble'
        : argv.includes('check-envelope.py')
          ? 'grade'
          : argv.includes('--json')
            ? 'score-json'
            : 'score-text';
    seen.push(id);
    const code = typeof codes[id] === 'number' ? codes[id] : 0;
    return { code, stdout: `${id} said ${code}\n`, stderr: '' };
  };
  return { runRun, seen };
}

const silent = () => {};

/** Capture what main() would have printed, so the assertions can read it. */
function sink() {
  const out = [];
  const err = [];
  return { out: (s) => out.push(s), err: (s) => err.push(s), stdout: () => out.join(''), stderr: () => err.join('') };
}

// --- the plan ---------------------------------------------------------------

test('the plan ends with the score, which is what makes stopping early safe', () => {
  const { stages } = planStages({ outDir: tmp() });
  assert.deepEqual(
    stages.map((s) => s.id),
    ['sweep', 'assemble', 'grade', 'score'],
  );
});

test('--no-sweep drops only the sweep, never the score', () => {
  const { stages } = planStages({ outDir: tmp(), sweep: false });
  assert.deepEqual(
    stages.map((s) => s.id),
    ['assemble', 'grade', 'score'],
  );
});

test('the assembler writes and the grader reads the same envelope', () => {
  const out = tmp();
  const { stages, envelopeJson } = planStages({ outDir: out });
  const assemble = stages.find((s) => s.id === 'assemble').runs[0];
  const grade = stages.find((s) => s.id === 'grade').runs[0];
  assert.equal(assemble.env.IRCK_ENVELOPE_OUT, out);
  assert.equal(grade.env.IRCK_ENVELOPE_JSON, envelopeJson);
  assert.equal(envelopeJson, join(out, 'envelope.json'));
});

test('the score stage scores the envelope the grader just graded', () => {
  const out = tmp();
  const { stages, envelopeJson } = planStages({ outDir: out });
  const score = stages.find((s) => s.id === 'score');
  for (const run of score.runs) assert.ok(run.argv.includes(envelopeJson));
});

test('the score runs on the interpreter already running, not on a PATH lookup', () => {
  const { stages } = planStages({ outDir: tmp() });
  for (const run of stages.find((s) => s.id === 'score').runs) {
    assert.equal(run.cmd, process.execPath);
  }
});

test('no threshold is passed unless one was asked for', () => {
  const bare = planStages({ outDir: tmp() });
  for (const run of bare.stages.find((s) => s.id === 'score').runs) {
    assert.ok(!run.argv.includes('--max-score'), 'a default threshold would be a policy nobody chose');
  }
  const capped = planStages({ outDir: tmp(), maxScore: '1/2' });
  const argv = capped.stages.find((s) => s.id === 'score').runs[0].argv;
  assert.deepEqual(argv.slice(-2), ['--max-score', '1/2']);
});

test('the sweep is not captured, so a multi-minute run shows its cells as they land', () => {
  const { stages } = planStages({ outDir: tmp() });
  assert.equal(stages.find((s) => s.id === 'sweep').runs[0].capture, false);
});

// --- the rule ---------------------------------------------------------------

test('every stage clean is exit 0', () => {
  const o = decideOutcome([
    { id: 'sweep', code: 0 },
    { id: 'assemble', code: 0 },
    { id: 'grade', code: 0 },
    { id: 'score', code: 0 },
  ]);
  assert.equal(o.exitCode, EXIT.CLEAN);
  assert.equal(o.stoppedAt, null);
});

test('the first non-zero code is passed through unchanged, not remapped to 1', () => {
  for (const code of [1, 2, 3]) {
    const o = decideOutcome([{ id: 'grade', code }, { id: 'score', code: 0 }]);
    assert.equal(o.exitCode, code);
    assert.equal(o.stoppedAt, 'grade');
  }
});

test('a run in which no stage executed is 3, never 0', () => {
  const o = decideOutcome([]);
  assert.equal(o.exitCode, EXIT.INCOMPLETE, 'nothing ran is not nothing wrong');
  assert.match(o.reason, /nothing was checked/);
});

// --- execution --------------------------------------------------------------

test('a clean pipeline runs all four stages and both renderings of the score', () => {
  const plan = planStages({ outDir: tmp() });
  const { runRun, seen } = scripted({});
  const { outcome } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, EXIT.CLEAN);
  assert.deepEqual(seen, ['sweep', 'assemble', 'grade', 'score-text', 'score-json']);
});

test('a grade that finds a disagreement stops the run at 2 and does not score', () => {
  const plan = planStages({ outDir: tmp() });
  const { runRun, seen } = scripted({ grade: 2 });
  const { outcome } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, 2);
  assert.equal(outcome.stoppedAt, 'grade');
  assert.ok(
    !seen.some((s) => s.startsWith('score')),
    'an envelope that failed its own expectations must not be reduced to a quotable number',
  );
});

test('an assembler with nothing to assemble stops the run at 3', () => {
  const plan = planStages({ outDir: tmp() });
  const { runRun, seen } = scripted({ assemble: 3 });
  const { outcome } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, EXIT.INCOMPLETE);
  assert.deepEqual(seen, ['sweep', 'assemble']);
});

test('a score of 3 — nothing eligible — is the pipeline exit code, not a footnote', () => {
  const plan = planStages({ outDir: tmp() });
  const { runRun } = scripted({ 'score-text': 3 });
  const { outcome, results } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, EXIT.INCOMPLETE, 'an unscoreable envelope is not a clean run');
  assert.equal(results.at(-1).id, 'score');
});

test('a score over its threshold is exit 2, and its evidence is still filed', () => {
  const out = tmp();
  const plan = planStages({ outDir: out, maxScore: '1/2' });
  const { runRun, seen } = scripted({ 'score-text': 2, 'score-json': 2 });
  const { outcome } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, 2);
  // 2 is a completed check with an answer, and the run that breached the
  // threshold is the one whose evidence gets read. Treating it like a refusal
  // would throw away the JSON exactly when it matters.
  assert.ok(seen.includes('score-json'));
  assert.ok(existsSync(join(out, 'fragility.json')));
});

test('the second rendering of the score is skipped once the first has refused', () => {
  const plan = planStages({ outDir: tmp() });
  const { runRun, seen } = scripted({ 'score-text': 3 });
  runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.ok(!seen.includes('score-json'), 'a refusal does not need to be produced twice');
});

test('two renderings of one score that disagree is 3, not whichever came last', () => {
  const plan = planStages({ outDir: tmp() });
  // Only reachable if fragility.mjs stops being a pure function of the envelope.
  // The pipeline refuses to choose an answer rather than filing the convenient one.
  const { runRun } = scripted({ 'score-text': 0, 'score-json': 2 });
  const { outcome, results } = runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.equal(outcome.exitCode, EXIT.INCOMPLETE);
  assert.match(results.at(-1).note, /disagreed/);
});

test('stage output is written beside the envelope it describes', () => {
  const out = tmp();
  const plan = planStages({ outDir: out });
  const { runRun } = scripted({});
  runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.ok(existsSync(join(out, 'grade.txt')));
  assert.ok(existsSync(join(out, 'fragility.txt')));
  assert.ok(existsSync(join(out, 'fragility.json')));
  assert.match(readFileSync(join(out, 'fragility.txt'), 'utf8'), /score-text said 0/);
});

test('the machine-readable score is stdout only; the human one keeps the stderr', () => {
  const out = tmp();
  const plan = planStages({ outDir: out, maxScore: '1/100' });
  const runRun = (run) => ({
    code: run.argv.some((a) => a.includes('fragility.mjs')) ? 2 : 0,
    stdout: run.argv.includes('--json') ? '{"score":{"num":1,"den":2}}\n' : 'fragility 0.500\n',
    stderr: run.argv.some((a) => a.includes('fragility.mjs')) ? 'exceeds the threshold 1/100\n' : '',
  });
  runPipeline(plan, { runRun, log: silent, logErr: silent });
  // The bug this pins produced a fragility.json with a sentence of English
  // appended after the closing brace, and it took a parser to notice.
  assert.doesNotThrow(() => JSON.parse(readFileSync(join(out, 'fragility.json'), 'utf8')));
  assert.match(readFileSync(join(out, 'fragility.txt'), 'utf8'), /exceeds the threshold/);
});

test('a run that produced nothing on stdout writes no file at all', () => {
  const out = tmp();
  const plan = planStages({ outDir: out, sweep: false });
  // What fragility.mjs does when it refuses: nothing on stdout, the reason on stderr.
  const runRun = (run) => ({
    code: run.argv.some((a) => a.includes('fragility.mjs')) ? 3 : 0,
    stdout: run.argv.some((a) => a.includes('fragility.mjs')) ? '' : 'ok\n',
    stderr: run.argv.some((a) => a.includes('fragility.mjs')) ? 'no fragility score\n' : '',
  });
  runPipeline(plan, { runRun, log: silent, logErr: silent });
  assert.ok(!existsSync(join(out, 'fragility.json')), 'a zero-byte .json reads like a result');
  assert.match(readFileSync(join(out, 'fragility.txt'), 'utf8'), /no fragility score/);
});

// --- stale artefacts --------------------------------------------------------

test('a failing run does not leave the previous run’s score looking current', () => {
  const out = tmp();
  const opts = { env: {}, probe: () => true, ...sink() };
  // Run one: clean, and it files a score.
  main(['--no-sweep', '--out', out], {
    ...opts,
    runRun: (run) => ({
      code: 0,
      stdout: run.argv.includes('--json') ? '{"ok":1}' : 'fragility 0.100\n',
      stderr: '',
    }),
  });
  assert.match(readFileSync(join(out, 'fragility.txt'), 'utf8'), /0\.100/);

  // Run two: the grader objects, so nothing is scored.
  const code = main(['--no-sweep', '--out', out], {
    ...opts,
    runRun: (run) => ({
      code: run.argv.some((a) => a.includes('check-envelope.py')) ? 2 : 0,
      stdout: 'a disagreement\n',
      stderr: '',
    }),
  });
  assert.equal(code, 2);
  assert.ok(
    !existsSync(join(out, 'fragility.txt')),
    'the score from the run before is not evidence about this one',
  );
  const rec = JSON.parse(readFileSync(join(out, 'pipeline.json'), 'utf8'));
  assert.equal(rec.stoppedAt, 'grade');
});

test('the artefact list is what the pipeline writes, so nothing it writes survives a run', () => {
  const out = tmp();
  const { stages } = planStages({ outDir: out });
  const cleared = new Set(pipelineArtefacts(out));
  const written = stages.flatMap((s) => s.runs.map((r) => r.saveAs)).filter(Boolean);
  for (const f of written) {
    assert.ok(cleared.has(f), `${f} is written by a stage but never cleared, so it can go stale`);
  }
  assert.ok(cleared.has(join(out, 'envelope.json')));
  assert.ok(cleared.has(join(out, 'pipeline.json')));
});

// --- preflight --------------------------------------------------------------

test('a missing tool is refused by name before any cell is compiled', () => {
  const { resolved, missing } = preflight({ env: {}, probe: (exe) => exe === 'bash' });
  assert.equal(resolved.bash, 'bash');
  assert.equal(missing.length, 1);
  assert.equal(missing[0].key, 'python3');
  const text = formatMissingTools(missing);
  assert.match(text, /python3/);
  assert.match(text, /IRCK_PYTHON/, 'the message has to say how to fix it');
});

test('an override is the only candidate tried, so a typo in it is not silently ignored', () => {
  const tried = [];
  const { missing } = preflight({
    env: { IRCK_PYTHON: '/opt/typo/python3' },
    probe: (exe) => {
      tried.push(exe);
      return exe === 'bash';
    },
  });
  assert.ok(tried.includes('/opt/typo/python3'));
  assert.ok(!tried.includes('python3'), 'falling back to PATH would score with an interpreter nobody named');
  assert.equal(missing[0].key, 'python3');
});

test('node is not a probed tool: this file is the node', () => {
  assert.ok(!REQUIRED_TOOLS.some((t) => t.key === 'node'));
});

test('main exits 3 and compiles nothing when a tool is missing', () => {
  let ran = false;
  const io = sink();
  const code = main(['--out', tmp()], {
    env: {},
    probe: (exe) => exe === 'bash',
    out: io.out,
    err: io.err,
    runRun: () => {
      ran = true;
      return { code: 0, stdout: '', stderr: '' };
    },
  });
  assert.equal(code, EXIT.INCOMPLETE);
  assert.equal(ran, false, 'the refusal has to come before the seventy-four cells, not after');
  assert.match(io.stderr(), /not a clean run/);
  assert.equal(io.stdout(), '', 'a refused run prints no summary that could be read as a result');
});

// --- argv -------------------------------------------------------------------

test('argv parsing refuses a flag where a value belongs', () => {
  assert.throws(() => parseArgv(['--max-score', '--no-sweep']), PipelineError);
  assert.throws(() => parseArgv(['--out']), PipelineError);
  assert.throws(() => parseArgv(['--nope']), PipelineError);
  assert.deepEqual(parseArgv(['--no-sweep', '--max-score', '1/3']), {
    sweep: false,
    maxScore: '1/3',
    outDir: undefined,
    help: false,
  });
});

test('a threshold in the environment is used when none was typed', () => {
  const out = tmp();
  let scoreArgv = null;
  const io = sink();
  main(['--no-sweep', '--out', out], {
    env: { IRCK_FRAGILITY_MAX: '2/5' },
    probe: () => true,
    out: io.out,
    err: io.err,
    runRun: (run) => {
      if (run.argv.some((a) => a.includes('fragility.mjs'))) scoreArgv = run.argv;
      return { code: 0, stdout: '', stderr: '' };
    },
  });
  assert.ok(scoreArgv.includes('--max-score'));
  assert.equal(scoreArgv[scoreArgv.indexOf('--max-score') + 1], '2/5');
});

// --- the record -------------------------------------------------------------

test('the record says whether the cells were swept this run', () => {
  const out = tmp();
  const io = sink();
  const code = main(['--no-sweep', '--out', out], {
    env: {},
    probe: () => true,
    out: io.out,
    err: io.err,
    runRun: () => ({ code: 0, stdout: '', stderr: '' }),
  });
  assert.equal(code, EXIT.CLEAN);
  assert.match(io.stdout(), /NOT swept/, 'the summary has to say the cells are not from this run');
  const rec = JSON.parse(readFileSync(join(out, 'pipeline.json'), 'utf8'));
  assert.equal(rec.sweptThisRun, false);
  assert.deepEqual(rec.stagesPlanned, ['assemble', 'grade', 'score']);
  assert.equal(rec.exitCode, 0);
});

test('the record carries the failing stage and its code', () => {
  const out = tmp();
  const io = sink();
  const code = main(['--no-sweep', '--out', out], {
    env: {},
    probe: () => true,
    out: io.out,
    err: io.err,
    runRun: (run) => ({
      code: run.argv.some((a) => a.includes('check-envelope.py')) ? 2 : 0,
      stdout: '',
      stderr: '',
    }),
  });
  assert.equal(code, 2);
  const rec = JSON.parse(readFileSync(join(out, 'pipeline.json'), 'utf8'));
  assert.equal(rec.stoppedAt, 'grade');
  assert.equal(rec.exitCode, 2);
  assert.ok(rec.envelopeJson.startsWith('compiler/') || rec.envelopeJson.includes('..'));
  assert.ok(!/^[A-Za-z]:[\\/]/.test(rec.envelopeJson), 'an absolute path names the machine, not the run');
});

test('the record is written even when the pipeline failed, because that run is the one worth reading', () => {
  const out = tmp();
  main(['--no-sweep', '--out', out], {
    env: {},
    probe: () => true,
    runRun: () => ({ code: 3, stdout: '', stderr: 'nothing to assemble\n' }),
  });
  assert.ok(existsSync(join(out, 'pipeline.json')));
});

// --- the CLI ----------------------------------------------------------------

function runCli(args) {
  try {
    return { code: 0, stdout: execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' }) };
  } catch (err) {
    return { code: err.status, stdout: String(err.stdout ?? ''), stderr: String(err.stderr ?? '') };
  }
}

test('the CLI prints its exit-code contract and exits 0 for --help', () => {
  const res = runCli(['--help']);
  assert.equal(res.code, 0);
  assert.match(res.stdout, /interfaces\.md section 7/);
});

test('the CLI exits 3, not 1, on an option it does not know', () => {
  const res = runCli(['--sweep-but-do-not-score']);
  assert.equal(res.code, EXIT.INCOMPLETE);
});

// --- the shape of the sidecar ----------------------------------------------

test('pipelineRecord reports the planned stages as well as the ones that ran', () => {
  const plan = planStages({ outDir: tmp() });
  const results = [{ id: 'sweep', code: 0, runs: [0], note: null }, { id: 'assemble', code: 3, runs: [3], note: null }];
  const rec = pipelineRecord({
    plan,
    results,
    outcome: decideOutcome(results),
    swept: true,
    tools: { bash: 'bash', python3: 'python3', node: process.version },
  });
  assert.deepEqual(rec.stagesPlanned, ['sweep', 'assemble', 'grade', 'score']);
  assert.deepEqual(rec.stages.map((s) => s.id), ['sweep', 'assemble']);
  assert.equal(rec.stoppedAt, 'assemble');
  assert.ok(
    rec.stagesPlanned.length > rec.stages.length,
    'the gap between planned and run is how a reader sees the pipeline stopped early',
  );
});
