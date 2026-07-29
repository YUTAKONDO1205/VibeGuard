// vibeguard:disable-file VG-AUTH-004
// Fixtures contain intentional vulnerable code to exercise diff scanning.
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { diffScopePrefix, scanDiff } from './diff.js';

/**
 * The diff channel's two silent-clean failures, pinned.
 *
 * Both produced the same output — zero findings, exit 0, no degradation — which
 * is indistinguishable from a genuinely clean diff. That is the worst shape a
 * security result can take, so these tests assert on the finding COUNT rather
 * than on any warning text: a regression has to fail here, not merely log.
 *
 * A real repository is created rather than feeding `diffText`, because both
 * bugs live in how git is INVOKED and how its output is resolved against the
 * filesystem. A canned diff string exercises neither.
 */
const VULN = 'import requests\nrequests.get("https://x", verify=False)\n';

let repo: string;
const created: string[] = [];

function git(args: string[], cwd: string): string {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

beforeAll(async () => {
  repo = await mkdtemp(join(tmpdir(), 'vg-diffbase-'));
  created.push(repo);
  git(['init', '-q'], repo);
  git(['config', 'user.email', 'test@example.com'], repo);
  git(['config', 'user.name', 'test'], repo);
  git(['config', 'commit.gpgsign', 'false'], repo);

  await writeFile(join(repo, 'README.md'), 'base\n');
  git(['add', '-A'], repo);
  git(['commit', '-qm', 'base'], repo);

  await mkdir(join(repo, 'pkg', 'a'), { recursive: true });
  await mkdir(join(repo, 'pkg', 'b'), { recursive: true });
  await writeFile(join(repo, 'pkg', 'a', 'client.py'), VULN);
  await writeFile(join(repo, 'pkg', 'b', 'client.py'), VULN);
  git(['add', '-A'], repo);
  git(['commit', '-qm', 'add'], repo);
});

afterAll(async () => {
  for (const dir of created) await rm(dir, { recursive: true, force: true });
});

const RANGE = 'HEAD^..HEAD';

describe('diff scan resolves paths against the repository root', () => {
  it('finds both changed files when the target is the repo root', async () => {
    const r = await scanDiff({ cwd: repo, range: RANGE, config: false });
    expect(r.findings.length).toBe(2);
  });

  // The reported bug. Diff headers are repo-root-relative whatever directory
  // git ran in, so joining them onto the TARGET built `pkg/a/pkg/a/client.py`.
  // Every read failed, every failure was swallowed as "file deleted in the new
  // revision", and the scan reported clean.
  it('finds the file under a subdirectory target, and scopes to it', async () => {
    const r = await scanDiff({ cwd: join(repo, 'pkg', 'a'), range: RANGE, config: false });
    expect(r.findings.length).toBe(1);
  });

  // Reading against the repo root must not leak the root basis into what gets
  // REPORTED. A directory scan reports paths relative to the target, and three
  // consumers depend on that: `fix.ts` reads a finding back as
  // `join(target, displayPath)`, config `suppress[].paths` globs are written
  // against it, and the SARIF adapter emits it as the artifact URI. Reporting
  // `pkg/a/client.py` for a scan of `pkg/a` would make `--fix` look for
  // `pkg/a/pkg/a/client.py`.
  it('reports the same path basis as a directory scan of the same target', async () => {
    const r = await scanDiff({ cwd: join(repo, 'pkg', 'a'), range: RANGE, config: false });
    expect(r.findings[0]?.filePath).toBe('client.py');
  });

  it('reports paths relative to the root when the root is the target', async () => {
    const r = await scanDiff({ cwd: repo, range: RANGE, config: false });
    expect(r.findings.map((f) => f.filePath).sort()).toEqual([
      'pkg/a/client.py',
      'pkg/b/client.py',
    ]);
  });

  it('reports nothing for a subdirectory the diff did not touch', async () => {
    await mkdir(join(repo, 'pkg', 'untouched'), { recursive: true });
    const r = await scanDiff({ cwd: join(repo, 'pkg', 'untouched'), range: RANGE, config: false });
    expect(r.findings.length).toBe(0);
  });
});

describe('diff scan survives a hostile gitconfig', () => {
  // `diff.noprefix=true` drops the `a/`/`b/` prefixes the header regex requires.
  // Unlike the subdirectory bug this one fires at the repo root too, so it
  // reaches the GitHub Action — a self-hosted runner or a Docker image with a
  // baked-in gitconfig carries the setting into CI.
  it('still parses headers when diff.noprefix is set', async () => {
    git(['config', 'diff.noprefix', 'true'], repo);
    try {
      const r = await scanDiff({ cwd: repo, range: RANGE, config: false });
      expect(r.findings.length).toBe(2);
    } finally {
      git(['config', '--unset', 'diff.noprefix'], repo);
    }
  });

  it('still parses headers when diff.mnemonicPrefix is set', async () => {
    git(['config', 'diff.mnemonicPrefix', 'true'], repo);
    try {
      const r = await scanDiff({ cwd: repo, range: RANGE, config: false });
      expect(r.findings.length).toBe(2);
    } finally {
      git(['config', '--unset', 'diff.mnemonicPrefix'], repo);
    }
  });

  // git's DEFAULT `core.quotepath=true` octal-escapes non-ASCII bytes and wraps
  // the header in quotes, so `+++ "b/…"` misses a regex anchored on `+++ b/`.
  // Repositories with non-ASCII filenames skipped exactly those files.
  it('scans a file whose name is not ASCII', async () => {
    const nonAscii = join(repo, 'pkg', 'a', '認証.py');
    await writeFile(nonAscii, VULN);
    git(['add', '-A'], repo);
    git(['commit', '-qm', 'non-ascii'], repo);
    try {
      const r = await scanDiff({ cwd: repo, range: 'HEAD^..HEAD', config: false });
      expect(r.findings.length).toBe(1);
      expect(r.findings[0]?.filePath).toContain('認証.py');
    } finally {
      // Throwaway repository — drop the commit so later ranges stay predictable.
      git(['reset', '--hard', '-q', 'HEAD~1'], repo);
    }
  });
});

/**
 * Options that change WHAT gets scanned have to apply on both scan paths.
 * `--known-only` reached `scanPath` and stopped there, so a diff run accepted
 * the flag and scanned exactly the files the user had excluded — a silent
 * no-op, which is the failure mode this whole audit kept finding.
 */
describe('diff scan honours the same admission rules as a directory scan', () => {
  const UNKNOWN = 'conf.unknownext';

  beforeAll(async () => {
    await writeFile(join(repo, UNKNOWN), '.a { background: url("http://example.com/x.png"); }\n');
    git(['add', '-A'], repo);
    git(['commit', '-qm', 'unknown-extension file'], repo);
  });

  it('scans an unknown-extension file by default', async () => {
    const r = await scanDiff({ cwd: repo, range: 'HEAD^..HEAD', config: false });
    expect(r.findings.some((f) => f.filePath === UNKNOWN)).toBe(true);
  });

  it('skips it under knownLanguagesOnly', async () => {
    const r = await scanDiff({
      cwd: repo,
      range: 'HEAD^..HEAD',
      config: false,
      knownLanguagesOnly: true,
    });
    expect(r.findings.some((f) => f.filePath === UNKNOWN)).toBe(false);
  });
});

describe('diffScopePrefix', () => {
  it('is empty when the target is the root', () => {
    expect(diffScopePrefix('/repo', '/repo')).toBe('');
  });

  it('is empty when the target sits outside the root', () => {
    expect(diffScopePrefix('/repo', '/elsewhere')).toBe('');
  });

  it('ends in a slash so a prefix cannot straddle a directory boundary', () => {
    // Without the trailing slash a target of `app` would also admit `apps/`.
    expect(diffScopePrefix('/repo', '/repo/app')).toBe('app/');
    expect('apps/x.ts'.startsWith(diffScopePrefix('/repo', '/repo/app'))).toBe(false);
  });

  it('uses forward slashes regardless of platform separators', () => {
    expect(diffScopePrefix('/repo', '/repo/pkg/a')).toBe('pkg/a/');
  });
});
