// Fixture construction for this component's tests. Not a test file itself —
// `node --test` only picks up `*.test.mjs`.
//
// Scratch goes under `vg-lab/`, the same convention the driver's tests use, and
// not to the system temp directory: WSL empties /tmp between sessions and a
// fixture that disappears half way through a run reads as a broken test rather
// than as a missing directory.
//
// NO CLOCK IS READ HERE. `verify.mjs --clock-audit` walks this directory too,
// and a `Date.now()` in a test file is a direct clock read like any other. Unique
// names come from the process id and a counter.

import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const EVIDENCE_DIR = resolve(HERE, '..');
export const REPO_ROOT = resolve(EVIDENCE_DIR, '..', '..');

export const VERIFY = join(EVIDENCE_DIR, 'verify.mjs');
export const VALIDATE = join(EVIDENCE_DIR, 'validate-store.mjs');
export const RECORD_RUN = join(EVIDENCE_DIR, 'record-run.mjs');

export const SCRATCH_ROOT =
  process.env.VG_EVIDENCE_TEST_SCRATCH ?? join(homedir(), 'vg-lab', 'evidence', 'test-scratch');

let counter = 0;

/** A fresh empty directory, outside the checkout. */
export function makeScratch(label) {
  counter += 1;
  const dir = join(SCRATCH_ROOT, `${label}-${process.pid}-${counter}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function cleanup(dir) {
  rmSync(dir, { recursive: true, force: true });
}

/**
 * Make a link and say what kind was made.
 *
 * An unprivileged process on Windows cannot create a FILE symlink (EPERM) but
 * can create a directory junction, which `lstat` reports as a symbolic link and
 * which performs the same redirection. So the tests link a directory: it is a
 * real link on both platforms, it exercises the same `isSymbolicLink()` test
 * over the same component list, and nothing has to be skipped. `kind` is
 * returned so the run says out loud which form it proved.
 *
 * @returns {{kind: 'symlink'|'junction', path: string}}
 */
export function linkDir(target, linkPath) {
  try {
    symlinkSync(target, linkPath, 'dir');
    return { kind: 'symlink', path: linkPath };
  } catch (e) {
    if (process.platform !== 'win32') throw e;
    symlinkSync(target, linkPath, 'junction');
    return { kind: 'junction', path: linkPath };
  }
}

/**
 * Try to link a FILE. Returns null when the platform refuses, which is not
 * treated as a pass anywhere — the caller asserts the directory form instead
 * and names this case in its output.
 */
export function tryLinkFile(target, linkPath) {
  try {
    symlinkSync(target, linkPath, 'file');
    return linkPath;
  } catch {
    return null;
  }
}

/**
 * A tiny git repository nobody else is editing.
 *
 * The writer's byte-identity claim is that the SAME inputs produce the same
 * bytes, and the state of a working tree is one of those inputs. Pointing the
 * test at this checkout instead made it fail against a tree that three other
 * agents were editing concurrently — correctly, since `provenance.diffSha256`
 * really had moved between the two runs, but the test was then measuring the
 * other agents rather than the writer.
 */
export function makeQuiescentRepo(label) {
  const dir = makeScratch(label);
  const git = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  git('init', '-q', '.');
  git('config', 'user.email', 'fixture@invalid');
  git('config', 'user.name', 'fixture');
  git('config', 'commit.gpgsign', 'false');
  writeFileSync(join(dir, 'README'), 'fixture\n', 'utf8');
  git('add', 'README');
  git('commit', '-q', '-m', 'initial');
  return dir;
}

/** Run a node script as a subprocess, so the exit code under test is real. */
export function run(script, argv, opts = {}) {
  const r = execFileSyncSafe(process.execPath, [script, ...argv], opts);
  return r;
}

function execFileSyncSafe(bin, args, opts) {
  try {
    const stdout = execFileSync(bin, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: opts.cwd,
      env: { ...process.env, ...(opts.env ?? {}) },
    });
    return { status: 0, stdout, stderr: '' };
  } catch (e) {
    return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? String(e.message) };
  }
}

/** The counting line a run printed, or null when it printed none. */
export function countingOf({ stdout, stderr }) {
  const m = /^inputs=(\d+) checked=(\d+) skipped=(\d+)$/m.exec(`${stdout}\n${stderr}`);
  return m ? { inputs: Number(m[1]), checked: Number(m[2]), skipped: Number(m[3]) } : null;
}

/** A measurement record that passes every check, sealed through canon.mjs. */
export async function goodRecord(overrides = {}) {
  const { sealRecord } = await import('../canon.mjs');
  return sealRecord(
    {
      schemaVersion: 'measurement-v0',
      recordId: 'fixture',
      provenance: { gitSha: '0'.repeat(40), dirty: false, diffSha256: null },
      toolchain: [{ name: 'cc', version: '18.1.3', path: 'usr/bin/cc', sha256: '1'.repeat(64) }],
      oracle: { kind: 'call-site', pattern: 'call void @llvm.memset' },
      observations: [
        { config: 'O0', subject: 2, control: 1 },
        { config: 'O2', subject: 0, control: 1 },
      ],
      reproduction: { pairId: 'fixture-pair', run: 1 },
      ...overrides,
    },
    { context: { generatedAt: '1970-01-01T00:00:00.000Z', timeSource: 'SOURCE_DATE_EPOCH', sourceDateEpoch: 0 } },
  );
}

/** Write a record into `<store>/<pairId>/run-<n>.json`, sealing it first. */
export async function putRecord(store, pairId, run, overrides = {}) {
  const { sealRecord } = await import('../canon.mjs');
  const base = await goodRecord(overrides);
  const copy = JSON.parse(JSON.stringify(base));
  copy.reproduction = { pairId, run };
  delete copy.evidenceDigest;
  const sealed = sealRecord(copy, { context: copy.context });
  const dir = join(store, pairId);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `run-${run}.json`);
  writeFileSync(file, `${JSON.stringify(sealed, null, 2)}\n`, 'utf8');
  return { file, record: sealed };
}
