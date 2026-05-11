#!/usr/bin/env node
/**
 * Performance benchmark for VibeGuard.
 *
 * Times three representative scan workloads against the targets declared in
 * §11.1 of the design doc (DESIGN.ja.md):
 *
 *   - Single-file fast scan        target: <= 3 s
 *   - Diff-style snippet scan      target: <= 1 s   (proxy for "selection scan")
 *   - Repository-wide scan         target: <= 5 min (proxy for "mid-size repo")
 *
 * Each workload is run three times and the median is reported. The CLI is
 * launched as a child process so we measure what a user actually experiences,
 * including Node.js startup and module resolution.
 *
 * Exit code: non-zero when any workload exceeds 2× its target. The 2× headroom
 * is intentional — CI VMs are noisy, and a strict fail-at-target gate would
 * produce too many false positives. The hard target stays the design contract,
 * but only an egregious regression should block a PR.
 *
 * Usage:
 *
 *   node scripts/perf-bench.mjs          # human-readable table
 *   node scripts/perf-bench.mjs --json   # machine-readable for CI artifacts
 */

import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { stat } from 'node:fs/promises';

const __filename = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(__filename), '..');

const CLI = join(repoRoot, 'apps', 'cli', 'dist', 'index.js');
const RUNS = 3;

/**
 * Workloads to benchmark.
 * `target_ms` mirrors design §11.1. `hard_limit_ms` is 2× that — the CI
 * gate threshold.
 */
const WORKLOADS = [
  {
    name: 'single-file fast scan',
    args: ['packages/rules/src/rules/quality.ts', '--mode', 'fast', '--fail-on', 'never'],
    target_ms: 3000,
    hard_limit_ms: 6000,
  },
  {
    name: 'samples/vulnerable directory',
    args: ['samples/vulnerable', '--mode', 'standard', '--fail-on', 'never'],
    target_ms: 1000,
    hard_limit_ms: 2000,
  },
  {
    name: 'repo-wide scan (ignore samples/dist/node_modules)',
    args: [
      '.',
      '--mode',
      'standard',
      '--ignore',
      'samples',
      '--ignore',
      'dist',
      '--ignore',
      'node_modules',
      '--ignore',
      '.git',
      '--ignore',
      '.github',
      '--fail-on',
      'never',
    ],
    target_ms: 300_000, // 5 min
    hard_limit_ms: 600_000,
  },
];

async function ensureCliBuilt() {
  try {
    await stat(CLI);
  } catch {
    console.error(
      `error: ${CLI} not found. Run \`npm run build\` first.`,
    );
    process.exit(2);
  }
}

function runCli(args) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: repoRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    // Drain stdout to avoid back-pressure stalls, but don't keep it.
    child.stdout.on('data', () => {});
    child.stderr.on('data', (b) => (stderr += b.toString('utf8')));
    child.on('error', reject);
    child.on('close', (code) => {
      const elapsed = performance.now() - start;
      // `--fail-on never` is set above, so a non-zero exit here means the CLI
      // itself errored (parse error, missing file, etc.) and the timing is
      // not comparable.
      if (code !== 0) {
        reject(new Error(`CLI exited ${code}: ${stderr.trim()}`));
        return;
      }
      resolve(elapsed);
    });
  });
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

function formatMs(ms) {
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`;
  return `${(ms / 60_000).toFixed(2)} min`;
}

function verdict(median_ms, target_ms, hard_limit_ms) {
  if (median_ms <= target_ms) return 'ok';
  if (median_ms <= hard_limit_ms) return 'over target';
  return 'FAIL';
}

async function main() {
  const wantJson = process.argv.includes('--json');
  await ensureCliBuilt();

  const results = [];
  for (const workload of WORKLOADS) {
    const samples = [];
    for (let i = 0; i < RUNS; i++) {
      samples.push(await runCli(workload.args));
    }
    const median_ms = median(samples);
    results.push({
      name: workload.name,
      target_ms: workload.target_ms,
      hard_limit_ms: workload.hard_limit_ms,
      samples_ms: samples.map((n) => Number(n.toFixed(2))),
      median_ms: Number(median_ms.toFixed(2)),
      verdict: verdict(median_ms, workload.target_ms, workload.hard_limit_ms),
    });
  }

  if (wantJson) {
    process.stdout.write(`${JSON.stringify({ runs: RUNS, results }, null, 2)}\n`);
  } else {
    const header = '| Workload | Target | Median (n=' + RUNS + ') | Verdict |';
    const divider = '|---|---|---|---|';
    const rows = results.map(
      (r) =>
        `| ${r.name} | ${formatMs(r.target_ms)} | ${formatMs(r.median_ms)} | ${r.verdict} |`,
    );
    process.stdout.write(`${header}\n${divider}\n${rows.join('\n')}\n`);
  }

  const failed = results.find((r) => r.verdict === 'FAIL');
  if (failed) {
    process.stderr.write(
      `\nFAIL: "${failed.name}" exceeded 2× target (${formatMs(failed.hard_limit_ms)})\n`,
    );
    process.exit(1);
  }
}

main().catch((err) => {
  process.stderr.write(`fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(2);
});
