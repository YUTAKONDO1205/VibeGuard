// The Node half of AI-authorship provenance: the only place in this package
// that touches a filesystem or spawns a process.
//
// ★ WHY THIS IS A SEPARATE ENTRY POINT
//
// `@vibeguard/sarif-adapter` is bundled into the VS Code extension (esbuild,
// `--platform=node`), so a `node:child_process` import in `./index.ts` would
// build today. It is split anyway, behind the package's `./node` subpath,
// mirroring `@vibeguard/analyzer-core`'s `./browser` split for the same hazard
// in the other direction. The cost now is six lines of `exports` map; the cost
// after something bundles `toSarif` for a browser and discovers it drags in a
// process spawner is an emergency refactor of a shipped package. `./index.ts`
// stays importable anywhere.
//
// ★ ZERO TRANSMISSION, RESTATED AS A CODE PROPERTY
//
// Two syscalls happen here: `execFile('git', [...])` and `readFile`. `git log`
// is a purely local read of `.git` — no remote is contacted, no `fetch`, no
// `submodule`, no hook that git would run for a log. There is no network client
// imported in this file or reachable from it.
//
// ★ NO SHELL, EVER
//
// `execFile` with an argument ARRAY, never `exec` with a string. The scan target
// is a path this tool was pointed at, and on a shell path a directory named
// `foo; curl evil` would be a command. This is the same class of defect
// VG-INJ-007 reports in other people's code, and it would be indefensible for
// the tool that reports it to contain one.
//
// ★ FAILURE IS "CHANNEL NOT READ", NOT AN ERROR
//
// Scanning a tarball, a Docker context, a `npm pack` extraction or any directory
// that is not a git repository is completely normal, and so is having no `git`
// on PATH. None of those is a scan failure — the scan's job is finding
// vulnerabilities, not reading history. Every failure path here degrades to
// "this channel produced nothing" and the observation simply does not list the
// channel in `channelsRead`. Nothing in this module throws.

import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { collectAiProvenance, type AiProvenanceObservation } from './provenance.js';

/**
 * NUL-separated records of `<sha>\n<raw body>`.
 *
 * `-z` because NUL is the one byte a commit message cannot contain, so no
 * crafted message can forge a record boundary. `%B` (raw body) rather than `%s`
 * plus `%b`, because trailers live in the body and reassembling the two halves
 * would reintroduce a separator a message could fake.
 *
 * Merges are NOT excluded. GitHub's squash-merge writes the co-author trailers
 * onto the merge commit itself, so `--no-merges` would drop exactly the commits
 * most likely to carry a marker on the most common workflow.
 */
const GIT_LOG_ARGS = (maxCommits: number): string[] => [
  '--no-pager',
  'log',
  '-z',
  `--max-count=${maxCommits}`,
  '--format=%H%n%B',
];

/** Default history window. Large enough to cover a normal repository's recent authorship, small enough to stay a sub-second read. */
const DEFAULT_MAX_COMMITS = 500;

/**
 * Wall-clock ceiling on the git call. A repository with a pathological history
 * (or a `.git` on a stalled network filesystem) must not be able to hang a scan;
 * the timeout degrades to "channel not read" like every other failure.
 */
const GIT_TIMEOUT_MS = 10_000;

/**
 * Output ceiling. `git log` of 500 commits is normally well under a megabyte;
 * 16 MB is the point at which something is wrong and the read should stop
 * rather than buffer the repository into memory.
 */
const GIT_MAX_BUFFER = 16 * 1024 * 1024;

/** Ceiling on a supplied PR body. A PR description is prose; 1 MB of it is not. */
const MAX_PR_BODY_BYTES = 1024 * 1024;

export interface ReadAiProvenanceOptions {
  /** Directory to read history from. The repository under scan. */
  cwd: string;
  /** History window. Defaults to 500; the parser caps at its own maximum regardless. */
  maxCommits?: number;
  /**
   * Path to a file holding the PR body text, supplied by the caller (the GitHub
   * Action has it in the event payload; a human can save it). Read as UTF-8.
   * Absent means the channel is not consulted at all.
   */
  prBodyFile?: string;
  /**
   * Label recorded as the marker's `readFrom`. Defaults to `pr-body` rather than
   * the file's path, deliberately: `readFrom` ends up in a SARIF property bag
   * that gets uploaded, and an absolute path from the machine that ran the scan
   * is a leak with no consumer.
   */
  prBodyLabel?: string;
}

/** Promise wrapper over execFile. Rejects are handled by the single caller below. */
function gitLog(cwd: string, maxCommits: number): Promise<string | undefined> {
  return new Promise((resolve) => {
    execFile(
      'git',
      GIT_LOG_ARGS(maxCommits),
      { cwd, timeout: GIT_TIMEOUT_MS, maxBuffer: GIT_MAX_BUFFER, encoding: 'utf8', windowsHide: true },
      (error, stdout) => {
        // `error` covers all of: git absent, not a repository, empty repository
        // (git exits 128 with "does not have any commits yet"), timeout, buffer
        // overflow. Every one of them is "this channel produced nothing".
        if (error) {
          resolve(undefined);
          return;
        }
        resolve(typeof stdout === 'string' ? stdout : undefined);
      },
    );
  });
}

/**
 * Collect AI-authorship markers from a repository on disk.
 *
 * Returns an observation describing WHAT WAS READ and what was declared in it —
 * including the case where nothing was declared, which is by far the most common
 * outcome and is not a failure. The caller decides whether to emit it; `toSarif`
 * omits the SARIF key when the marker list is empty, and the reasoning for that
 * lives there.
 *
 * Returns `undefined` only when NO channel could be read at all, so a caller can
 * distinguish "looked, found nothing" from "there was nothing to look at".
 */
export async function readAiProvenance(
  options: ReadAiProvenanceOptions,
): Promise<AiProvenanceObservation | undefined> {
  const maxCommits = normaliseMaxCommits(options.maxCommits);
  const log = await gitLog(options.cwd, maxCommits);

  let prBody: string | undefined;
  if (options.prBodyFile) {
    try {
      const text = await readFile(options.prBodyFile, 'utf8');
      prBody = text.length > MAX_PR_BODY_BYTES ? text.slice(0, MAX_PR_BODY_BYTES) : text;
    } catch {
      // Unreadable or absent: the channel was not read. Not an error — the
      // Action passes this path unconditionally and it does not exist on a push
      // event.
      prBody = undefined;
    }
  }

  if (log === undefined && prBody === undefined) return undefined;

  return collectAiProvenance({
    ...(log !== undefined ? { gitLog: log } : {}),
    ...(prBody !== undefined ? { prBody } : {}),
    ...(options.prBodyLabel ? { prBodyLabel: options.prBodyLabel } : {}),
  });
}

/**
 * Clamp the window. A negative or fractional `--max-count` is a git argument
 * error, and a caller-supplied number reaches a command line — so it is coerced
 * to a bounded integer here rather than interpolated as given. `String(n)` of a
 * hostile value can be `'0; rm -rf /'` only if `n` is not a number, which this
 * makes impossible.
 */
function normaliseMaxCommits(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_MAX_COMMITS;
  const n = Math.floor(value);
  if (n < 1) return 1;
  if (n > 5000) return 5000;
  return n;
}
