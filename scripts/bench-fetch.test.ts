// Tests for scripts/bench-fetch.mjs.
//
// ★ THE FAILURE UNDER TEST, STATED ONCE
//
// A fetcher that cannot reach the network and carries on is the worst component
// in a benchmark, because everything downstream of it still works. The scorer
// reads an empty corpus, the tool under test finds nothing in it, the result
// file records that the tool missed every labelled site, and the leaderboard
// publishes it. Every number in that chain is arithmetically correct and the
// chain is a lie. So the assertions below are almost all about REFUSALS, and the
// exit code is asserted through a real child process as well as in-process,
// because a `main()` that returns 3 while the process exits 0 is a bug no
// in-process assertion can see.
//
// WHY NO TEST HERE TOUCHES THE NETWORK
//
// A test that needed it would be skipped on every machine without it, and a
// skipped fetch test is the same green tick as a passing one. `git` is injected,
// so every decision runs against a recorded transcript — including the one that
// matters most, a `git fetch` that fails the way a missing network fails.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';

// @ts-expect-error — plain ESM module, no type declarations by design.
import { fetchAll, fetchOne, main } from './bench-fetch.mjs';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const FETCHER = join(REPO, 'scripts', 'bench-fetch.mjs');
const BENCH = join(REPO, 'bench', 'ai-code-security-design-smells');
const SEP = String.fromCharCode(92);

const tmpDirs: string[] = [];
function scratch(): string {
  const d = mkdtempSync(join(tmpdir(), 'bench-fetch-'));
  tmpDirs.push(d);
  return d;
}
afterAll(() => {
  for (const d of tmpDirs) rmSync(d, { recursive: true, force: true });
});

const entry = (over: Record<string, unknown> = {}) => ({
  id: 'acme-svc',
  repositoryUrl: 'https://example.invalid/positive-control/acme-svc',
  commit: 'a'.repeat(40),
  licence: { spdx: 'MIT', status: 'resolved' },
  ...over,
});

/** A git that succeeds at everything, recording the argv it was given. */
function happyGit(calls: string[][] = []) {
  return (args: string[]) => {
    calls.push(args);
    return { ok: true, code: 0, stderr: '', stdout: '' };
  };
}

/** A git whose `fetch` fails the way an unreachable remote fails. */
function offlineGit() {
  return (args: string[]) => {
    if (args[0] === 'fetch') {
      return { ok: false, code: 128, stderr: "fatal: unable to access 'https://example.invalid/': Could not resolve host", stdout: '' };
    }
    return { ok: true, code: 0, stderr: '', stdout: '' };
  };
}

function runFetcher(args: string[]): { status: number; out: string } {
  try {
    const out = execFileSync(process.execPath, [FETCHER, ...args], { cwd: REPO, encoding: 'utf8', stdio: 'pipe' });
    return { status: 0, out };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

describe('a fetch that fails is fatal and named', () => {
  it('reports the entry and quotes the git error when the remote is unreachable', () => {
    const report = fetchAll(offlineGit(), { entries: [entry()] }, scratch(), { allowUnresolvedLicence: true });
    expect(report.verdict).toBe('incomplete');
    expect(report.failed).toHaveLength(1);
    expect(report.failed[0].id).toBe('acme-svc');
    expect(report.failed[0].reason).toMatch(/Could not resolve host/);
  });

  it('an incomplete corpus exits 3 through a real process, not 0 with a warning', () => {
    const dir = scratch();
    const manifest = join(dir, 'manifest.json');
    // ★ A `file://` remote pointing at a directory that does not exist, NOT a
    // hostname. This is the one place the genuine `git` runs, and it has to fail
    // for a reason that is the same on every machine. An earlier version pointed
    // at a reserved domain and relied on the name failing to resolve — which is
    // true of a correct resolver and not true of a network that answers every
    // query, and a test that hangs for a TCP timeout on somebody's CI is a test
    // that gets deleted. A missing local path fails immediately, everywhere, and
    // exercises exactly the code path an unreachable remote does: `git fetch`
    // returns non-zero and the run is incomplete.
    writeFileSync(manifest, JSON.stringify({ entries: [entry({ repositoryUrl: `file:///${join(dir, 'no-such-repo').split(SEP).join('/')}` })] }));
    const r = runFetcher(['--manifest', manifest, '--out', join(dir, 'corpus'), '--allow-unresolved-licence']);
    expect(r.status).toBe(3);
    expect(r.out).toMatch(/were NOT materialised/);
    // The git error has to reach the operator, or "it failed" is all anyone gets.
    expect(r.out).toMatch(/git fetch of a{40} failed/);
  });

  it('★ and the exit code is 3, not 0 — a partial corpus must never look like a clean run', () => {
    // Stated separately from the assertion above because it is the whole point:
    // the message is cosmetic, the exit code is what CI consumes.
    const dir = scratch();
    writeFileSync(
      join(dir, 'manifest.json'),
      JSON.stringify({ entries: [entry({ repositoryUrl: `file:///${join(dir, 'no-such-repo').split(SEP).join('/')}` })] }),
    );
    const r = runFetcher(['--manifest', join(dir, 'manifest.json'), '--out', join(dir, 'corpus'), '--allow-unresolved-licence']);
    expect(r.status).not.toBe(0);
  });
});

describe('an empty manifest is refused, not fetched', () => {
  it('fetchAll returns vacuous rather than "complete, 0 entries"', () => {
    const report = fetchAll(happyGit(), { entries: [] }, scratch(), { allowUnresolvedLicence: true });
    expect(report.verdict).toBe('vacuous');
    expect(report.reason).toMatch(/attempts nothing and exits 0/);
  });

  it('and the process exits 3', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ entries: [] }));
    const r = runFetcher(['--manifest', join(dir, 'manifest.json'), '--out', join(dir, 'corpus'), '--allow-unresolved-licence']);
    expect(r.status).toBe(3);
  });
});

describe('the licence gate', () => {
  it('refuses an unresolved licence by default, naming the entries', () => {
    const report = fetchAll(happyGit(), { entries: [entry({ licence: { spdx: null, status: 'unresolved' } })] }, scratch());
    expect(report.verdict).toBe('licence-refused');
    expect(report.unresolved).toEqual(['acme-svc']);
    expect(report.results).toHaveLength(0);
  });

  it('proceeds only when the caller says the word', () => {
    const report = fetchAll(happyGit(), { entries: [entry({ licence: { spdx: null, status: 'unresolved' } })] }, scratch(), {
      allowUnresolvedLicence: true,
    });
    expect(report.verdict).toBe('complete');
  });

  it('the shipped manifest is the unresolved case, so the gate is live and not theoretical', () => {
    // If every entry were resolved this whole gate would be dead code that no
    // run exercises. Asserting the shipped state keeps the test honest about
    // which branch actually runs.
    const r = runFetcher(['--manifest', join(BENCH, 'manifest.json'), '--out', join(scratch(), 'corpus')]);
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/licence\.status other than/);
  });
});

describe('the pinned commit is what gets fetched', () => {
  it('asks the remote for the sha directly rather than cloning a branch', () => {
    const calls: string[][] = [];
    fetchOne(happyGit(calls), entry(), scratch());
    const fetched = calls.find((c) => c[0] === 'fetch');
    expect(fetched).toBeDefined();
    expect(fetched).toContain('a'.repeat(40));
    // No `clone`: a clone gives whatever the default branch points at today, and
    // a later checkout of the pin then succeeds or fails depending on how much
    // history the shallow clone happened to include.
    expect(calls.some((c) => c[0] === 'clone')).toBe(false);
  });

  it('refuses to reuse a checkout sitting at a different commit', () => {
    const out = scratch();
    mkdirSync(join(out, 'acme-svc', '.git'), { recursive: true });
    const git = (args: string[]) =>
      args[0] === 'rev-parse'
        ? { ok: true, code: 0, stdout: `${'b'.repeat(40)}\n`, stderr: '' }
        : { ok: true, code: 0, stdout: '', stderr: '' };
    const r = fetchOne(git, entry(), out);
    expect(r.status).toBe('failed');
    expect(r.reason).toMatch(/not at the pinned/);
  });

  it('accepts a checkout already at the pin, and does not refetch it', () => {
    const out = scratch();
    mkdirSync(join(out, 'acme-svc', '.git'), { recursive: true });
    const calls: string[][] = [];
    const git = (args: string[]) => {
      calls.push(args);
      return args[0] === 'rev-parse'
        ? { ok: true, code: 0, stdout: `${'a'.repeat(40)}\n`, stderr: '' }
        : { ok: true, code: 0, stdout: '', stderr: '' };
    };
    expect(fetchOne(git, entry(), out).status).toBe('present');
    expect(calls.some((c) => c[0] === 'fetch')).toBe(false);
  });
});

describe('--plan', () => {
  it('prints every entry and fetches nothing', () => {
    const r = runFetcher(['--plan']);
    expect(r.status).toBe(0);
    expect(r.out).toMatch(/Nothing was fetched/);
    expect(r.out).toMatch(/licence=unresolved/);
  });

  it('refuses to print a plan over an empty manifest', () => {
    const dir = scratch();
    writeFileSync(join(dir, 'manifest.json'), JSON.stringify({ entries: [] }));
    const r = runFetcher(['--manifest', join(dir, 'manifest.json'), '--plan']);
    expect(r.status).toBe(3);
  });
});

describe('usage', () => {
  it('requires --out, so the corpus is never written inside this repository', () => {
    expect(main(['--manifest', join(BENCH, 'manifest.json')], happyGit())).toBe(2);
  });

  it('a missing manifest is a usage error naming the file', () => {
    const r = runFetcher(['--manifest', join(scratch(), 'nope.json'), '--out', scratch()]);
    expect(r.status).toBe(2);
    expect(r.out).toMatch(/cannot read/);
  });
});
