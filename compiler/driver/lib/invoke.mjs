// Running clang.
//
// Two rules, and the whole non-invasiveness claim rests on them:
//
//  1. The *shipping* build gets the caller's argv verbatim, minus the driver's
//     own `--policy`/`--vg-*` flags and nothing else. Not the normalised argv —
//     the original one, response files unexpanded, joined forms still joined.
//     Normalisation exists to decide what to check; if it also decided what to
//     compile, a normalisation bug would become a miscompilation, and the
//     object file the driver blessed would not be the object file anyone else
//     gets from the same command.
//
//  2. Anything the driver adds for its own benefit goes in a *separate*
//     invocation whose output is written somewhere the caller never sees. Not
//     the same run with an extra flag: `-mllvm -print-pipeline-passes` and
//     `-fpass-plugin=` both change what the optimiser does, so a driver that
//     folded observation into the shipping build would be measuring a binary
//     nobody ships and shipping a binary nobody measured.
//
// stdout and stderr are inherited, so diagnostics reach the caller byte for
// byte, in order, with colour intact — the driver never buffers, filters or
// re-prints them.

import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { basename, join } from 'node:path';

/**
 * The shipping build. Diagnostics pass through unchanged; the exit status is
 * clang's own.
 */
export function runShipping({ compiler, argv, cwd, env = process.env }) {
  const started = Date.now();
  const res = spawnSync(compiler, argv, { cwd, env, stdio: 'inherit' });
  const durationMs = Date.now() - started;
  if (res.error) {
    return { ok: false, spawnError: res.error.code ?? res.error.message, exitCode: null, signal: null, durationMs };
  }
  return {
    ok: res.status === 0,
    spawnError: null,
    exitCode: res.status,
    signal: res.signal ?? null,
    durationMs,
  };
}

/**
 * An observation build. `extraFlags` are appended, output is redirected into
 * `scratchDir`, and stdout/stderr are captured rather than inherited so that
 * the caller's diagnostic stream is not doubled.
 *
 * The redirection is done by appending `-o <scratch>`: clang takes the last
 * `-o` on the line, so this overrides the caller's without having to rewrite
 * the argv and risk changing something else.
 */
export function runObservation({ compiler, argv, cwd, scratchDir, extraFlags = [], label = 'obs', env = process.env }) {
  mkdirSync(scratchDir, { recursive: true });
  const out = join(scratchDir, `${label}.out`);
  const full = [...argv, ...extraFlags, '-o', out];
  const started = Date.now();
  const res = spawnSync(compiler, full, { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const durationMs = Date.now() - started;
  return {
    ok: !res.error && res.status === 0,
    spawnError: res.error ? (res.error.code ?? res.error.message) : null,
    exitCode: res.error ? null : res.status,
    signal: res.signal ?? null,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
    outputPath: out,
    extraFlags,
    durationMs,
  };
}

/**
 * Parse `-mllvm -print-pipeline-passes` output into the pipeline string list.
 * Returns null when the run produced nothing parseable — which is a "could not
 * observe", not an empty pipeline.
 */
export function parsePipeline(stdout) {
  const line = stdout.split('\n').map((l) => l.trim()).filter((l) => l.length > 0).pop();
  if (!line || !/[(),]/.test(line)) return null;
  return splitTopLevel(line);
}

function splitTopLevel(s) {
  const out = [];
  let depth = 0;
  let cur = '';
  for (const ch of s) {
    if (ch === '(') { depth += 1; cur += ch; continue; }
    if (ch === ')') { depth -= 1; cur += ch; continue; }
    if (ch === ',' && depth === 0) { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
