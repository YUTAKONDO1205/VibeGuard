// One contract, many copies — and a check that they still say the same thing.
//
// ── THE PROBLEM THIS SOLVES, AND THE ONE IT REFUSES TO CREATE ───────────────
//
// The digest vectors are the shared calibration for every canonicaliser in this
// repository. There are now several copies of them: the toolchain workspace has
// the original, and each of the two evidence packages vendors one, because
// nothing under `packages/` may reach into the toolchain directory and a
// package that cannot state its own contract is not self-contained.
//
// The obvious drift check — "compare our copy against the toolchain's" — cannot
// be written here. A quoted path reaching into that directory, in any source
// file under a workspace, is a release-time invariant failure; the boundary is
// enforced by shape, not by intent, and rightly so, because "it is only a test"
// is how the first import always gets justified.
//
// So the check is turned inside out. It does not name a directory at all: it
// asks git for everything that would reach a commit, keeps every file with the
// contract's filename WHEREVER it lives, and requires them all to agree. That
// covers the toolchain copy without pointing at it, it covers a fourth copy
// somebody adds next month without anyone remembering to add it here, and it
// keeps working if the original moves.
//
// ── WHY IT COMPARES CONTENT AND NOT BYTES ───────────────────────────────────
//
// This checkout converts line endings on checkout, and `.gitattributes` pins LF
// for the toolchain directory only. A byte comparison would therefore fail on a
// difference that is not a difference, and a check that cries wolf gets deleted.
// The comparison is over `JSON.stringify(JSON.parse(bytes))`: it moves when a
// vector, an expected digest or a must-fail case moves, and not when an indent
// does.
//
// ── WHY A SINGLE COPY IS A FAILURE ──────────────────────────────────────────
//
// "All copies agree" is trivially true of one copy, and of none. A run that
// found fewer than two has not compared anything, and reporting agreement for
// it is the empty-scan failure this repository has shipped three times. Below
// the floor the run fails and says which files it did find.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The filename that identifies a copy of the contract. */
export const CONTRACT_BASENAME = 'digest-vectors.json';

/** Fewer than this many copies means nothing was compared. */
export const COPY_FLOOR = 2;

export class ContractScanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ContractScanError';
  }
}

/**
 * The repository root, found by walking up for a `.git`.
 *
 * Throws rather than falling back to the working directory. A scan rooted
 * somewhere unintended is exactly the failure that produces a confident,
 * meaningless zero.
 *
 * @param {string} [start]
 * @returns {string}
 */
export function repoRootFrom(start = HERE) {
  let dir = resolve(start);
  for (;;) {
    if (existsSync(join(dir, '.git'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) {
      throw new ContractScanError(
        `no .git found at or above ${start}, so the repository root could not be determined. ` +
          'This check compares every copy of the contract in the repository, and it will not ' +
          'guess at where that is.',
      );
    }
    dir = parent;
  }
}

/**
 * Every path git would let reach a commit — tracked plus untracked-and-not-
 * ignored. That is the set the check cares about: a copy that is on disk and
 * ignored is somebody's scratch file, and a copy that is staged but not yet
 * committed is exactly the one being added right now.
 *
 * A git failure is an ERROR, not a skip. Reporting "all copies agree" on the
 * strength of a subprocess that did not run is the vacuum this whole file is
 * written against. If a caller genuinely has no git checkout, it must say so
 * out loud rather than being handed a green result.
 *
 * @param {string} repoRoot
 * @returns {string[]}
 */
export function committablePaths(repoRoot) {
  let raw;
  try {
    raw = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (e) {
    throw new ContractScanError(
      `git could not list the repository at ${repoRoot}: ${e.message}. This check needs a git ` +
        'checkout. It fails rather than skipping, so "could not check" never reads as "checked".',
    );
  }
  return raw.split('\0').filter(Boolean);
}

/** Formatting-independent fingerprint of one copy. */
export function fingerprintFile(abs) {
  const parsed = JSON.parse(readFileSync(abs, 'utf8'));
  return createHash('sha256').update(JSON.stringify(parsed), 'utf8').digest('hex');
}

/**
 * Compare every copy of the contract in the repository.
 *
 * @param {{repoRoot?: string, basename?: string, floor?: number}} [opts]
 * @returns {{
 *   repoRoot: string,
 *   inputs: number, checked: number, skipped: number, skippedNames: string[],
 *   copies: Array<{path: string, fingerprint: string}>,
 *   groups: Array<{fingerprint: string, paths: string[]}>,
 *   agree: boolean, belowFloor: boolean, floor: number,
 * }}
 */
export function compareContractCopies(opts = {}) {
  const repoRoot = opts.repoRoot ?? repoRootFrom();
  const basename = opts.basename ?? CONTRACT_BASENAME;
  const floor = opts.floor ?? COPY_FLOOR;

  const candidates = committablePaths(repoRoot).filter(
    (p) => p.split('/').pop() === basename,
  );

  const copies = [];
  const skippedNames = [];
  for (const rel of candidates) {
    const abs = join(repoRoot, rel);
    if (!existsSync(abs)) {
      // Staged-then-deleted, or a path git knows and the filesystem does not.
      // Named, never silently dropped.
      skippedNames.push(`${rel} (git lists it, the filesystem does not have it)`);
      continue;
    }
    try {
      copies.push({ path: rel, fingerprint: fingerprintFile(abs) });
    } catch (e) {
      skippedNames.push(`${rel} (does not parse: ${e.message})`);
    }
  }

  const byFingerprint = new Map();
  for (const c of copies) {
    if (!byFingerprint.has(c.fingerprint)) byFingerprint.set(c.fingerprint, []);
    byFingerprint.get(c.fingerprint).push(c.path);
  }
  const groups = [...byFingerprint.entries()]
    .map(([fingerprint, paths]) => ({ fingerprint, paths: paths.sort() }))
    .sort((a, b) => (a.fingerprint < b.fingerprint ? -1 : 1));

  return {
    repoRoot,
    inputs: candidates.length,
    checked: copies.length,
    skipped: skippedNames.length,
    skippedNames,
    copies,
    groups,
    agree: groups.length <= 1,
    belowFloor: copies.length < floor,
    floor,
  };
}
