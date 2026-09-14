#!/usr/bin/env node
// bench-fetch — materialise the benchmark corpus from the manifest, at the pins.
//
// WHY A FETCHER AND NOT A VENDORED CORPUS
//
// The entries are third-party repositories with no licence recorded anywhere in
// the inputs this benchmark was built from. Copying them into this repository
// would be redistribution without a licence, so the published artefact is the
// manifest and this script. The corpus is reconstructed on the machine that runs
// the benchmark, at the exact commit the labels were written against.
//
// ★ THE FAILURE THIS SCRIPT IS SHAPED AROUND
//
// A fetcher that cannot reach the network and carries on is the worst component
// in a benchmark, because everything downstream still works. The scorer reads an
// empty corpus, the tool under test finds nothing in it, the scorer reports zero
// findings against the labels, and the leaderboard publishes a tool that "missed
// everything" — when in fact nothing was ever scanned. Every number in that
// chain is real; the chain is a lie.
//
// So: a clone that fails is fatal and NAMED. A partial corpus is fatal and the
// missing entries are listed. A run with zero entries attempted is fatal. There
// is no --continue-on-error, and adding one would need a way for the failure to
// reach the result file, which is a bigger change than it looks.
//
// Usage:
//   node scripts/bench-fetch.mjs --out <dir>
//   node scripts/bench-fetch.mjs --out <dir> --allow-unresolved-licence
//   node scripts/bench-fetch.mjs --plan            # print what would be done
//   node scripts/bench-fetch.mjs --manifest <file> --out <dir>
//
// Exits 0 when every entry is present at its pinned commit, 2 on a usage or
// licence refusal, 3 when the corpus could not be materialised (network,
// missing commit, partial result) — because the honest output of a fetcher that
// fetched nothing is not an empty directory.
import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { EXIT_OK, EXIT_USAGE, EXIT_VACUOUS, readJsonOrFail } from './bench-shared.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_MANIFEST = join(REPO, 'bench', 'ai-code-security-design-smells', 'manifest.json');

/**
 * The git calls, in one place and injectable.
 *
 * Injectable so the tests can exercise the DECISIONS — refuse on an unresolved
 * licence, refuse on a failed clone, refuse on an empty plan — without a
 * network. What is deliberately NOT faked in those tests is the exit code: the
 * child-process assertions spawn this file for real, because the exit code is
 * what an operator and a CI job consume, and a function that returns 3 while the
 * process exits 0 is a bug no unit test of the function can see.
 */
export function realGit(args, cwd) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (r.error !== undefined && r.error !== null) {
    return { ok: false, code: null, stderr: `git could not be started: ${r.error.message}` };
  }
  return { ok: r.status === 0, code: r.status, stderr: r.stderr ?? '', stdout: r.stdout ?? '' };
}

/**
 * Fetch one entry into `<outDir>/<id>` at exactly `entry.commit`.
 *
 * `init` + `fetch --depth 1 <sha>` rather than `clone` + `checkout`: a clone
 * gives whatever the default branch points at today, and a checkout of the pin
 * then succeeds or fails depending on how much history the shallow clone
 * happened to include. Asking the remote for the sha directly makes "this commit
 * is no longer reachable" — a force-push, a rewritten history, a deleted
 * branch — an explicit failure instead of a corpus that is silently a different
 * revision from the one the labels describe.
 */
export function fetchOne(git, entry, outDir) {
  const dest = join(outDir, entry.id);
  if (existsSync(join(dest, '.git'))) {
    const head = git(['rev-parse', 'HEAD'], dest);
    if (head.ok && head.stdout.trim() === entry.commit) {
      return { id: entry.id, status: 'present', dest };
    }
    return {
      id: entry.id,
      status: 'failed',
      dest,
      reason: `already exists at ${head.ok ? head.stdout.trim() : 'an unreadable HEAD'}, not at the pinned ${entry.commit}. Remove it or point --out elsewhere; this script will not rewrite a checkout it did not make.`,
    };
  }

  mkdirSync(dest, { recursive: true });
  const init = git(['init', '--quiet'], dest);
  if (!init.ok) return { id: entry.id, status: 'failed', dest, reason: `git init failed: ${init.stderr.trim()}` };

  const remote = git(['remote', 'add', 'origin', `${entry.repositoryUrl}.git`], dest);
  if (!remote.ok) return { id: entry.id, status: 'failed', dest, reason: `git remote add failed: ${remote.stderr.trim()}` };

  const fetched = git(['fetch', '--depth', '1', 'origin', entry.commit], dest);
  if (!fetched.ok) {
    return {
      id: entry.id,
      status: 'failed',
      dest,
      reason: `git fetch of ${entry.commit} failed: ${fetched.stderr.trim() || `exit ${fetched.code}`}`,
    };
  }

  const checkout = git(['checkout', '--quiet', 'FETCH_HEAD'], dest);
  if (!checkout.ok) return { id: entry.id, status: 'failed', dest, reason: `git checkout failed: ${checkout.stderr.trim()}` };

  return { id: entry.id, status: 'fetched', dest };
}

/**
 * The whole run. Returns a report; the caller decides the exit code, so the same
 * decisions can be asserted in-process and through a real child process.
 */
export function fetchAll(git, manifest, outDir, options = {}) {
  const entries = Array.isArray(manifest.entries) ? manifest.entries : [];
  if (entries.length === 0) {
    return {
      verdict: 'vacuous',
      reason:
        'the manifest lists no entries. A fetcher that attempts nothing and exits 0 hands the ' +
        'scorer an empty corpus, and every zero downstream of that is about an empty directory ' +
        'rather than about a tool.',
      results: [],
    };
  }

  const unresolved = entries.filter((e) => e?.licence?.status !== 'resolved');
  if (unresolved.length > 0 && options.allowUnresolvedLicence !== true) {
    return {
      verdict: 'licence-refused',
      reason:
        `${unresolved.length} of ${entries.length} entries carry licence.status other than ` +
        '"resolved", so this script will not clone them by default. Nothing about the refusal ' +
        'claims the code is unlicensed — it says the licence was never determined, which is a ' +
        'different and honestly worse thing to act on silently. Pass --allow-unresolved-licence ' +
        'to fetch anyway for local evaluation, and do not redistribute what comes back.',
      unresolved: unresolved.map((e) => e.id),
      results: [],
    };
  }

  const results = entries.map((e) => fetchOne(git, e, outDir));
  const failed = results.filter((r) => r.status === 'failed');
  if (failed.length > 0) {
    return { verdict: 'incomplete', results, failed };
  }
  return { verdict: 'complete', results, failed: [] };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function flagValue(argv, name, fallback) {
  const i = argv.indexOf(name);
  return i === -1 || argv[i + 1] === undefined ? fallback : argv[i + 1];
}

export function main(argv, git = realGit) {
  const manifestPath = flagValue(argv, '--manifest', DEFAULT_MANIFEST);
  const outDir = flagValue(argv, '--out', null);
  const plan = argv.includes('--plan');
  const allowUnresolvedLicence = argv.includes('--allow-unresolved-licence');

  let manifest;
  try {
    manifest = readJsonOrFail({ readFileSync }, manifestPath, 'benchmark manifest');
  } catch (err) {
    console.error(`bench-fetch: ${err.message}`);
    return EXIT_USAGE;
  }

  if (plan) {
    const entries = Array.isArray(manifest.entries) ? manifest.entries : [];
    if (entries.length === 0) {
      console.error('bench-fetch --plan: the manifest lists no entries, so there is no plan to print.');
      return EXIT_VACUOUS;
    }
    for (const e of entries) {
      console.log(`${e.id}\t${e.repositoryUrl}\t${e.commit}\tlicence=${e?.licence?.status ?? 'absent'}`);
    }
    console.log(`\n${entries.length} entry(ies). Nothing was fetched: --plan prints and stops.`);
    return EXIT_OK;
  }

  if (outDir === null) {
    console.error('bench-fetch: --out <dir> is required (the corpus is never written inside this repository).');
    return EXIT_USAGE;
  }

  mkdirSync(outDir, { recursive: true });
  const report = fetchAll(git, manifest, outDir, { allowUnresolvedLicence });

  if (report.verdict === 'vacuous') {
    console.error(`bench-fetch: ${report.reason}`);
    return EXIT_VACUOUS;
  }
  if (report.verdict === 'licence-refused') {
    console.error(`bench-fetch: ${report.reason}`);
    for (const id of report.unresolved) console.error(`  unresolved licence: ${id}`);
    return EXIT_USAGE;
  }

  for (const r of report.results) {
    console.log(`${r.status.padEnd(8)} ${r.id}${r.reason === undefined ? '' : ` — ${r.reason}`}`);
  }

  if (report.verdict === 'incomplete') {
    console.error(
      `\n${report.failed.length} of ${report.results.length} entry(ies) were NOT materialised. ` +
        'This is exit 3 and not a warning: a partial corpus scores as a tool that missed the ' +
        'entries nobody fetched, and that reading is indistinguishable from a real miss once the ' +
        'result file is written. Common cause is no network — the git error is quoted above.',
    );
    return EXIT_VACUOUS;
  }

  console.log(`\n${report.results.length} entry(ies) present at their pinned commits in ${outDir}`);
  return EXIT_OK;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
