#!/usr/bin/env node
/**
 * The envelope pipeline: one invocation, cells to score.
 *
 * Run it from inside a checkout that has the toolchain (Linux/WSL):
 *
 *   node compiler/envelope/envelope-pipeline.mjs
 *
 * Why this file exists
 * --------------------
 * The sweep already had three stages and they already ran clean:
 *
 *   run-envelope.sh    executes every cell of the configuration envelope
 *   build-envelope.py  joins each reading to the invocation that produced it
 *   check-envelope.py  grades the assembled envelope against declared expectations
 *
 * and then it stopped. `fragility.mjs` — the thing that turns a graded envelope
 * into the one number the envelope exists to produce — had a CLI, had tests, and
 * had no caller. Someone had to remember to type it. A measurement that is only
 * read when a human remembers to look is not a measurement anyone is relying on,
 * and an unread number degrades exactly the way an unrun test does: silently,
 * and only in the direction that looks fine.
 *
 * So the stages are the same stages. What is added is that they run in one go,
 * that the score is the last of them rather than an optional postscript, and
 * that no stage's exit code can be lost on the way out.
 *
 * What this file deliberately does NOT do
 * ---------------------------------------
 * It does not grade, score, assemble or measure anything. Every judgement is
 * still made by the stage that owns it, and this file's only opinion is the
 * order they run in and what to do when one of them refuses. run-envelope.sh
 * says "Decides: nothing" at the top for a reason — the thing that produces the
 * number must not be the thing that grades it — and pushing the grader and the
 * scorer into the sweep would have thrown that away to save one command.
 *
 * Exit codes (compiler/schema/interfaces.md section 7)
 * ----------------------------------------------------
 *   0  every stage ran and none of them objected
 *   1  a stage's underlying tool failed
 *   2  a stage found what it was looking for: a graded expectation was not met,
 *      or the fragility score exceeded a threshold that was asked for
 *   3  a stage could not complete: a tool is missing, nothing was assembled,
 *      nothing was eligible to score
 *
 * The rule is: run the stages in order, stop at the first non-zero, and exit
 * with that stage's code unchanged. Three things follow from it, and each is the
 * reason it is written this way rather than another way.
 *
 *   * The code is passed through, not remapped. Section 7 exists so a caller can
 *     branch without knowing which component ran; a driver that collapsed 2 and
 *     3 into "failed" would be the one place in the chain where "we found
 *     something" and "we could not look" became the same event again.
 *
 *   * Stopping is safe here specifically because the score is LAST. A
 *     stop-at-first-failure rule can hide a later stage — but the only stage it
 *     can hide here is one whose input does not exist or was just declared
 *     untrustworthy. Scoring an envelope that check-envelope.py has said
 *     disagrees with its own expectations produces a number that reads like a
 *     measurement and is not one, and printing it next to the disagreement is
 *     how the number gets quoted without the disagreement.
 *
 *   * Nothing here uses `|| true`, `catch {}` or a discarded stream. The score
 *     stage returns 3 when the envelope left no eligible cell — that is the
 *     single most likely real failure of this pipeline, because it is what an
 *     envelope full of broken measurements looks like — and a driver that
 *     treated the score as decoration would report that run as clean.
 *
 * Where the outputs go
 * --------------------
 * `compiler/llvm-pass/_results/envelope/` (git-ignored), beside the envelope.json
 * the score was computed from, because a score filed away from the envelope it
 * was measured over is the quotable-out-of-context form this directory keeps
 * refusing:
 *
 *   envelope.json   the assembled envelope (build-envelope.py's output)
 *   grade.txt       check-envelope.py's table and verdict
 *   fragility.txt   the human report, exactly as printed
 *   fragility.json  the same report as evidence, stdout only — see the run
 *   pipeline.json   which stages ran, what they returned, whether cells were swept
 *
 * All five are deleted before the run starts. A results directory is reused, and
 * a run that stops at `grade` must not leave the previous run's score sitting
 * next to this run's failure looking current.
 *
 * On `node` not being on PATH
 * ---------------------------
 * The stages are bash, python3, python3, node. This driver is the node one, and
 * it invokes fragility.mjs through `process.execPath` rather than through the
 * name `node` — so the interpreter that scores the envelope is by construction
 * the interpreter that is already running, and there is no PATH lookup to fail.
 * A machine with no `node` cannot start this file at all, which is a loud
 * failure at the shell and not a skipped stage.
 *
 * bash and python3 are a different matter: they are looked up by name, so they
 * are probed before any work starts and a missing one is exit 3 by name (see
 * `preflight`). The probe is up front rather than at the stage that needs it
 * because the alternative is a run that compiles seventy-four cells and then
 * discovers it cannot grade them.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const SCHEMA_VERSION = 'envelope-pipeline-v0';
export const COMPONENT = 'EnvelopePipeline';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HERE, '..', '..');

/** interfaces.md section 7. Named so the numbers below are readable. */
export const EXIT = Object.freeze({
  CLEAN: 0,
  TOOL_FAILED: 1,
  FOUND: 2,
  INCOMPLETE: 3,
});

export class PipelineError extends Error {
  constructor(message, exitCode = EXIT.INCOMPLETE) {
    super(message);
    this.name = 'PipelineError';
    this.exitCode = exitCode;
  }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/**
 * The tools this pipeline looks up by name, with the environment variable that
 * overrides each. `node` is absent on purpose — see the header.
 *
 * python3 carries two candidates because the interpreter is called `python3`
 * where these stages are meant to run and `python` on a Windows checkout. Trying
 * both is not a fallback that hides a problem: whichever answers is named in the
 * output, so a run scored by a different interpreter than you expected says so.
 */
export const REQUIRED_TOOLS = Object.freeze([
  { key: 'bash', envVar: 'IRCK_BASH', candidates: ['bash'], used_for: 'run-envelope.sh' },
  {
    key: 'python3',
    envVar: 'IRCK_PYTHON',
    candidates: ['python3', 'python'],
    used_for: 'build-envelope.py and check-envelope.py',
  },
]);

/** Default probe: does `<exe> --version` start at all? ENOENT means it does not. */
export function probeTool(exe) {
  const res = spawnSync(exe, ['--version'], { stdio: 'ignore' });
  return !(res.error && res.error.code === 'ENOENT');
}

/**
 * Resolve every required tool, or refuse.
 *
 * Returns `{ resolved: {bash: 'bash', python3: 'python3'}, missing: [] }`.
 * `missing` non-empty is exit 3 at the call site — never a stage that is quietly
 * dropped from the plan, because a pipeline that silently ran three stages
 * instead of four still prints three clean stages.
 */
export function preflight({ env = process.env, probe = probeTool } = {}) {
  const resolved = {};
  const missing = [];
  for (const tool of REQUIRED_TOOLS) {
    const override = env[tool.envVar];
    const candidates = override ? [override] : tool.candidates;
    const found = candidates.find((c) => probe(c));
    if (found) resolved[tool.key] = found;
    else missing.push({ ...tool, tried: candidates });
  }
  return { resolved, missing };
}

export function formatMissingTools(missing) {
  return missing
    .map(
      (m) =>
        `${m.key}: not runnable (tried ${m.tried.join(', ')}). It is needed for ${m.used_for}. ` +
        `Set ${m.envVar} to a path if it is installed under another name.`,
    )
    .join('\n');
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/**
 * Build the ordered stage list.
 *
 * A stage is `{ id, title, runs: [...] }` and a run is one subprocess. Only the
 * score stage has more than one run: fragility.mjs renders either the human
 * report or the evidence JSON, never both in one invocation, and this pipeline
 * wants both — the text so the run says something to the person watching it,
 * the JSON so the number is still readable a week later. The two runs are over
 * the same file with the same options, so their exit codes must agree;
 * `runPipeline` makes a disagreement exit 3 rather than picking one, because two
 * verdicts from one input means the scorer is not deterministic and neither
 * answer is worth filing.
 *
 * `capture: false` means the subprocess inherits stdio. That is for the sweep,
 * which runs for minutes and whose per-cell lines are the only sign it is alive;
 * buffering them to print at the end would make a working run look hung.
 */
export function planStages({
  repoRoot = REPO_ROOT,
  python = 'python3',
  bash = 'bash',
  nodeExe = process.execPath,
  outDir,
  sweep = true,
  maxScore = null,
} = {}) {
  const scripts = join(repoRoot, 'compiler', 'llvm-pass', 'scripts');
  const resultsDir = outDir ?? join(repoRoot, 'compiler', 'llvm-pass', '_results', 'envelope');
  const envelopeJson = join(resultsDir, 'envelope.json');

  // build-envelope.py and check-envelope.py each read their own environment
  // variable for where the envelope lives. They are set here from one value so
  // that `--out` cannot move the writer without moving the reader — a grader
  // pointed at a stale envelope from a previous run is the failure this pins.
  const envelopeEnv = { IRCK_ENVELOPE_OUT: resultsDir, IRCK_ENVELOPE_JSON: envelopeJson };

  const scoreArgs = [join(repoRoot, 'compiler', 'envelope', 'fragility.mjs'), envelopeJson];
  if (maxScore) scoreArgs.push('--max-score', maxScore);

  const stages = [];

  if (sweep) {
    stages.push({
      id: 'sweep',
      title: 'run every cell of the configuration envelope',
      // run-envelope.sh returns 0 for a run in which cells failed: an unsupported
      // target and a broken observation are results it exists to record, and it
      // says so where it swallows the per-cell code. A non-zero from it is the
      // sweep itself breaking, which is why it is propagated rather than folded
      // into the cell labels.
      runs: [{ cmd: bash, argv: [join(scripts, 'run-envelope.sh')], env: envelopeEnv, capture: false }],
    });
  }

  stages.push({
    id: 'assemble',
    title: 'join each reading to the invocation that produced it',
    runs: [
      {
        cmd: python,
        argv: [join(scripts, 'build-envelope.py')],
        env: envelopeEnv,
        capture: true,
        echo: true,
      },
    ],
  });

  stages.push({
    id: 'grade',
    title: 'grade the envelope against the expectations written for it',
    runs: [
      {
        cmd: python,
        argv: [join(scripts, 'check-envelope.py')],
        env: envelopeEnv,
        capture: true,
        echo: true,
        saveAs: join(resultsDir, 'grade.txt'),
        saveStderr: true,
      },
    ],
  });

  stages.push({
    id: 'score',
    title: 'reduce the graded envelope to one number, with its envelope attached',
    runs: [
      {
        cmd: nodeExe,
        argv: scoreArgs,
        capture: true,
        echo: true,
        saveAs: join(resultsDir, 'fragility.txt'),
        saveStderr: true,
      },
      {
        cmd: nodeExe,
        argv: [...scoreArgs, '--json'],
        capture: true,
        echo: false,
        saveAs: join(resultsDir, 'fragility.json'),
        // The only run whose file is machine-readable, and the only one that
        // must not carry stderr. fragility.mjs prints a breached threshold to
        // stderr while printing the report to stdout, so folding the two
        // together — which this did, until a real run produced a fragility.json
        // that json.load refused at line 2567 — appends prose to a document
        // whose next reader is a parser. It is echoed to the console and its
        // code is in pipeline.json; it does not also belong in the evidence.
        saveStderr: false,
      },
    ],
  });

  return { stages, resultsDir, envelopeJson };
}

/**
 * The files this pipeline writes into the results directory, and therefore the
 * files it must clear before it starts.
 *
 * A results directory is reused between runs. Without this, a run that fails at
 * `grade` leaves last week's `fragility.txt` sitting beside this run's
 * `pipeline.json`, and the score in it is indistinguishable from one this run
 * produced. That is the same failure the rest of this directory is built
 * against — a stale reading presented as a current one — arriving through the
 * filesystem instead of through a checker.
 *
 * envelope.json is on the list because `assemble` runs in every plan: if it
 * could not assemble one this time, there must not be one lying there from when
 * it could. The cells it is built from are untouched, so `--no-sweep` rebuilds
 * it in a second.
 */
export function pipelineArtefacts(resultsDir) {
  return ['envelope.json', 'grade.txt', 'fragility.txt', 'fragility.json', 'pipeline.json'].map((n) =>
    join(resultsDir, n),
  );
}

// ---------------------------------------------------------------------------
// The rule
// ---------------------------------------------------------------------------

/**
 * Reduce the stage results to the pipeline's exit code.
 *
 * First non-zero wins and is passed through unchanged. See the header for why
 * that is not a way of hiding a later stage: the score is last, so the only
 * stage this rule can stop is one whose input has already been declared missing
 * or untrustworthy by something that said so loudly with its own code.
 *
 * A run that executed no stages at all is exit 3, not 0. That case is not
 * hypothetical — it is what an empty plan, or a plan whose stages were all
 * filtered out by a flag, would produce, and "nothing ran" rendered as "nothing
 * was wrong" is the shape of clean result this whole directory exists to refuse.
 */
export function decideOutcome(results) {
  if (!Array.isArray(results) || results.length === 0) {
    return {
      exitCode: EXIT.INCOMPLETE,
      stoppedAt: null,
      reason: 'no stage ran, so nothing was checked; that is not a clean result',
    };
  }
  for (const r of results) {
    if (r.code !== 0) {
      return {
        exitCode: r.code,
        stoppedAt: r.id,
        reason: `${r.id} exited ${r.code}${r.note ? `: ${r.note}` : ''}`,
      };
    }
  }
  return { exitCode: EXIT.CLEAN, stoppedAt: null, reason: 'every stage ran and none objected' };
}

/** Default stage runner: one subprocess, honestly reported. */
export function spawnRun({ cmd, argv, env, capture, cwd }) {
  const res = spawnSync(cmd, argv, {
    cwd,
    env: { ...process.env, ...(env ?? {}) },
    encoding: 'utf8',
    stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (res.error) {
    // ENOENT here after preflight passed means the tool moved mid-run, or a
    // stage script is not where the plan says. Either way it is 3 — the check
    // did not happen — and it is not turned into "the stage failed" (1), which
    // would suggest the stage ran and disliked what it saw.
    return { code: EXIT.INCOMPLETE, stdout: '', stderr: `${cmd}: ${res.error.message}\n` };
  }
  if (res.status === null) {
    return { code: EXIT.INCOMPLETE, stdout: res.stdout ?? '', stderr: `${cmd}: killed by ${res.signal}\n` };
  }
  return { code: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

/**
 * Execute a plan, stopping at the first stage that returns non-zero.
 *
 * `runRun` is injected so the ordering and exit-code rules can be tested without
 * a toolchain. It is a parameter and not an environment variable on purpose:
 * an env var that replaces a stage command is a supported way to make the score
 * stage `true`, and this pipeline's entire point is that the score cannot be
 * turned off from outside.
 */
export function runPipeline(
  plan,
  {
    runRun = spawnRun,
    write = writeFileSync,
    log = (s) => process.stdout.write(s),
    logErr = (s) => process.stderr.write(s),
  } = {},
) {
  const results = [];

  for (const stage of plan.stages) {
    log(`\n=== ${stage.id}: ${stage.title} ===\n`);
    const codes = [];
    let note = null;

    for (const run of stage.runs) {
      const res = runRun(run);
      codes.push(res.code);
      if (run.capture) {
        if (run.echo && res.stdout) log(res.stdout);
        // A stage's stderr is relayed whatever its exit code. check-envelope.py
        // prints its disagreements there and fragility.mjs prints its refusal
        // there, so a driver that only forwarded stdout would show a failing run
        // its table and hide the sentence saying what was wrong with it.
        if (res.stderr) logErr(res.stderr);
        if (run.saveAs) {
          const body =
            res.stdout + (run.saveStderr && res.stderr ? `\n--- stderr ---\n${res.stderr}` : '');
          // An empty file is not a cheaper way of saying nothing was produced.
          // fragility.mjs writes its refusal to stderr and nothing to stdout, so
          // a run that could not score would otherwise leave a zero-byte
          // fragility.json that reads, to anything opening it, like a result.
          if (body.length > 0) {
            mkdirSync(dirname(run.saveAs), { recursive: true });
            write(run.saveAs, body, 'utf8');
          }
        }
      }
      // Later runs of a stage read the same input as the first, so whether to
      // keep going turns on whether the first produced a verdict at all.
      //
      //   0 or 2  it did. Section 7 makes 2 "findings at or above the
      //           threshold", which is a completed check with an answer — and
      //           it is exactly the run whose evidence someone will want to
      //           read, so the remaining renderings are still produced.
      //   1 or 3  it did not. Running the rest would only file a second copy of
      //           the same refusal under a different extension.
      if (res.code !== 0 && res.code !== EXIT.FOUND) break;
    }

    let code = codes[codes.length - 1] ?? EXIT.INCOMPLETE;
    // Two renderings of one input that disagree on the verdict: neither is
    // filed as the answer. This cannot happen while fragility.mjs is a pure
    // function of the envelope, which is the point — if it ever does, the
    // pipeline says so instead of picking the convenient one.
    if (codes.length > 1 && new Set(codes).size > 1) {
      note = `the runs of this stage disagreed on the verdict (${codes.join(', ')})`;
      code = EXIT.INCOMPLETE;
    }

    results.push({ id: stage.id, code, note, runs: codes });
    if (code !== 0) break;
  }

  const outcome = decideOutcome(results);
  return { results, outcome };
}

/**
 * The durable record of the run.
 *
 * Paths are stored relative to the repository root. Absolute paths name the
 * machine that produced the file, and check-envelope.py already fails an
 * envelope that carries one; a sidecar written beside it should not be the
 * exception that teaches the habit back.
 */
export function pipelineRecord({ plan, results, outcome, swept, tools }) {
  return {
    schemaVersion: SCHEMA_VERSION,
    component: COMPONENT,
    sweptThisRun: swept,
    tools,
    envelopeJson: relative(REPO_ROOT, plan.envelopeJson).split('\\').join('/'),
    stages: results.map((r) => ({ id: r.id, exitCode: r.code, runExitCodes: r.runs, note: r.note ?? null })),
    stagesPlanned: plan.stages.map((s) => s.id),
    exitCode: outcome.exitCode,
    stoppedAt: outcome.stoppedAt,
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export const USAGE = `usage: node envelope-pipeline.mjs [--no-sweep] [--max-score N/D] [--out DIR]

Runs the configuration envelope end to end: cells, assembly, grading, score.
Stops at the first stage that returns non-zero and exits with its code.

  --no-sweep       do not run the cells; score the ones already in the lab.
                   The run says so, and pipeline.json records it, because a
                   score presented as if it came from a fresh sweep when it did
                   not is a claim about configurations nobody just measured.
  --max-score N/D  fail (exit 2) if the fragility score exceeds this ratio.
                   Also read from IRCK_FRAGILITY_MAX. No threshold ships in this
                   file: the number that counts as too fragile is a policy the
                   person running it chooses, and one baked in here would be a
                   measurement wearing a default.
  --out DIR        where to write envelope.json and the score (git-ignored).
                   Everything this pipeline writes there is deleted first, so a
                   failed run cannot leave the previous run's score behind
                   looking like its own.

exit codes (compiler/schema/interfaces.md section 7)
  0  every stage ran and none objected
  1  a stage's underlying tool failed
  2  a graded expectation was not met, or the score exceeded --max-score
  3  a stage could not complete: a tool is missing, nothing was assembled, or
     nothing in the envelope was eligible to score`;

export function parseArgv(argv) {
  const opts = { sweep: true, maxScore: null, outDir: undefined, help: false };
  // A value that is missing, or that is the next flag, is refused rather than
  // consumed. `--max-score --no-sweep` consumed as a ratio would reach
  // fragility.mjs as a threshold it cannot parse, and the run would fail one
  // stage later with a message about a ratio nobody typed.
  const value = (i, flag) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('-')) {
      throw new PipelineError(`${flag} needs a value${v === undefined ? '' : `, got ${v}`}`);
    }
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') opts.help = true;
    else if (a === '--no-sweep') opts.sweep = false;
    else if (a === '--max-score') opts.maxScore = value(i++, a);
    else if (a === '--out') opts.outDir = value(i++, a);
    else throw new PipelineError(`unknown option ${a}\n\n${USAGE}`);
  }
  return opts;
}

/**
 * `out` and `err` are injected for the same reason `runRun` is: so the tests can
 * assert on the decision without thirty copies of a run summary in the test log.
 * They default to the real streams, so the shipped path is the one the tests
 * exercise apart from where the characters land.
 */
export function main(
  argv,
  {
    env = process.env,
    probe = probeTool,
    runRun = spawnRun,
    out = (s) => process.stdout.write(s),
    err = (s) => process.stderr.write(s),
  } = {},
) {
  const opts = parseArgv(argv);
  if (opts.help) {
    out(USAGE + '\n');
    return EXIT.CLEAN;
  }

  const { resolved, missing } = preflight({ env, probe });
  if (missing.length > 0) {
    err(
      `the envelope pipeline cannot run:\n${formatMissingTools(missing)}\n` +
        `Nothing was measured, so this is exit ${EXIT.INCOMPLETE} and not a clean run.\n`,
    );
    return EXIT.INCOMPLETE;
  }

  const plan = planStages({
    python: resolved.python3,
    bash: resolved.bash,
    outDir: opts.outDir,
    sweep: opts.sweep,
    maxScore: opts.maxScore ?? env.IRCK_FRAGILITY_MAX ?? null,
  });

  // Clear this run's outputs before this run starts, so nothing left over from
  // a previous one can be read as belonging to it. See `pipelineArtefacts`.
  mkdirSync(plan.resultsDir, { recursive: true });
  const cleared = [];
  for (const f of pipelineArtefacts(plan.resultsDir)) {
    if (!existsSync(f)) continue;
    rmSync(f);
    cleared.push(f);
  }
  if (cleared.length > 0) {
    out(`cleared ${cleared.length} artefact(s) from a previous run in ${plan.resultsDir}\n`);
  }

  const { results, outcome } = runPipeline(plan, { runRun, log: out, logErr: err });

  const record = pipelineRecord({
    plan,
    results,
    outcome,
    swept: opts.sweep,
    tools: { bash: resolved.bash, python3: resolved.python3, node: process.version },
  });
  writeFileSync(join(plan.resultsDir, 'pipeline.json'), JSON.stringify(record, null, 1) + '\n', 'utf8');

  out(
    `\n=== pipeline: ${outcome.reason} ===\n` +
      results.map((r) => `  ${r.id.padEnd(9)} rc=${r.code}`).join('\n') +
      (opts.sweep ? '' : '\n  (cells were NOT swept this run; they came from the existing lab)') +
      `\n  record: ${relative(REPO_ROOT, join(plan.resultsDir, 'pipeline.json')).split('\\').join('/')}\n`,
  );
  return outcome.exitCode;
}

if (process.argv[1] && /(^|[/\\])envelope-pipeline\.mjs$/.test(process.argv[1].replace(/\\/g, '/'))) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exitCode = err instanceof PipelineError ? err.exitCode : EXIT.INCOMPLETE;
  }
}
