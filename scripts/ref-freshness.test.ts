// Tests for scripts/ref-freshness.mjs.
//
// WHAT IS BEING PINNED HERE
//
// The failure this script exists for is not exotic. Everyone in a full audit of
// this repository read `refs/remotes/origin/<branch>`, everyone got an answer,
// and the ref was more than sixty commits behind the remote. A stale ref is
// indistinguishable from a fresh one by inspection; the only way to know is to
// ask the remote and compare, and the only way to keep that comparison honest is
// to assert that it goes RED, with a non-zero exit code, in each of the ways it
// can be hollowed out:
//
//   - a sha differs                     -> red, the ref named
//   - the remote has a branch we do not  -> red
//   - we have a branch the remote deleted-> red
//   - a line of plumbing is unparseable  -> red (NOT silently dropped)
//   - nothing at all was compared        -> red (an empty comparison is
//                                          vacuously "in sync")
//
// and then the other direction, which is the half that gets forgotten: an
// in-sync repository must come back exit 0. A freshness gate that cries wolf is
// switched off inside a week, and then none of the above matters.
//
// WHY BOTH DIRECT IMPORTS AND CHILD PROCESSES
//
// Same split as scripts/packaging-invariants.test.ts and scripts/sec-selftest.
// test.ts. The comparison is a pure function and is imported. The EXIT CODE is
// what CI and an operator actually consume, and the script sets it by returning
// from `main`, so those assertions spawn the script for real.
//
// WHY THE REMOTE SIDE IS INJECTED AND THE LOCAL SIDE IS NOT
//
// A test that needed the network would be skipped on every machine that did not
// have it, and a skipped freshness test is the same green tick as a passing one.
// So `--ls-remote-from` replaces exactly one side with a file. The local side
// stays real: `git for-each-ref` runs against this checkout, which means the
// child-process tests below exercise the actual plumbing — argument passing,
// output parsing, the ref-namespace mapping — and not a mock of it.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  DIVERGED,
  EXIT_FINDINGS,
  EXIT_INCOMPLETE,
  EXIT_INTEGRITY,
  EXIT_OK,
  EXIT_TOOL_FAILED,
  IN_SYNC,
  MISSING_LOCALLY,
  STALE_LOCALLY,
  compareRefs,
  divergentRows,
  logicalKey,
  parseForEachRef,
  parseLsRemote,
} from './ref-freshness.mjs';

const SCRIPTS_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPTS_DIR, '..');
const SCRIPT = join(SCRIPTS_DIR, 'ref-freshness.mjs');

const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const SHA_C = 'c'.repeat(40);

let scratch: string;

function run(args: string[]): { status: number; out: string } {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { status: 0, out: stdout };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { status: e.status ?? -1, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
}

/** The real local tracking refs, in the format `git ls-remote` would print them. */
function lsRemoteFromLocalRefs(): { text: string; count: number; firstBranch: string } {
  const local = execFileSync('git', ['for-each-ref', '--format=%(objectname) %(refname)', 'refs/remotes/origin'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  const lines: string[] = [];
  let firstBranch = '';
  for (const raw of local.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '') continue;
    const [sha, name] = line.split(/\s+/);
    if (name === 'refs/remotes/origin/HEAD') continue;
    const branch = name.slice('refs/remotes/origin/'.length);
    if (firstBranch === '') firstBranch = branch;
    lines.push(`${sha}\trefs/heads/${branch}`);
  }
  return { text: `${lines.join('\n')}\n`, count: lines.length, firstBranch };
}

function fixture(name: string, body: string): string {
  const p = join(scratch, name);
  writeFileSync(p, body, 'utf8');
  return p;
}

beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'vg-reffresh-test-'));
});

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe('ref-freshness: parsing', () => {
  it('reads sha/ref pairs and drops the peeled half of an annotated tag', () => {
    const { refs, malformed } = parseLsRemote(
      [`${SHA_A}\trefs/heads/main`, `${SHA_B}\trefs/tags/v1`, `${SHA_C}\trefs/tags/v1^{}`, ''].join('\n'),
    );
    expect(malformed).toEqual([]);
    expect(refs.get('refs/heads/main')).toBe(SHA_A);
    // The unpeeled sha is the tag object, which is what %(objectname) reports
    // locally. Comparing against the peeled commit would mark every annotated
    // tag as diverged in perpetuity.
    expect(refs.get('refs/tags/v1')).toBe(SHA_B);
    expect(refs.has('refs/tags/v1^{}')).toBe(false);
  });

  // The direction that matters most. Both silent breakages this repository had
  // were a layer DROPPING input and the run still reporting a clean number.
  it('reports a malformed line instead of skipping it', () => {
    const { refs, malformed } = parseLsRemote([`${SHA_A}\trefs/heads/main`, 'this is not a ref line'].join('\n'));
    expect(refs.size).toBe(1);
    expect(malformed).toHaveLength(1);
  });

  it('parses for-each-ref output', () => {
    const { refs, malformed } = parseForEachRef(`${SHA_A} refs/remotes/origin/main\n`);
    expect(malformed).toEqual([]);
    expect(refs.get('refs/remotes/origin/main')).toBe(SHA_A);
  });

  it('maps both namespaces onto one key and refuses the symbolic HEAD', () => {
    expect(logicalKey('refs/heads/main', 'origin')).toBe('heads/main');
    expect(logicalKey('refs/remotes/origin/main', 'origin')).toBe('heads/main');
    expect(logicalKey('refs/tags/v1', 'origin')).toBe('tags/v1');
    expect(logicalKey('refs/remotes/origin/HEAD', 'origin')).toBeNull();
    expect(logicalKey('refs/stash', 'origin')).toBeNull();
    // A slash inside a branch name must survive the mapping.
    expect(logicalKey('refs/remotes/origin/release/v1', 'origin')).toBe('heads/release/v1');
  });
});

describe('ref-freshness: comparison', () => {
  const base = { remote: 'origin', branches: [] as string[], includeTags: false };

  // NEGATIVE FIXTURE. Identical refs must produce no rows to worry about; a
  // gate that fires here is one that gets disabled.
  it('calls identical refs in sync', () => {
    const r = compareRefs({
      ...base,
      remoteRefs: new Map([['refs/heads/main', SHA_A]]),
      localRefs: new Map([['refs/remotes/origin/main', SHA_A]]),
    });
    expect(r.rows).toEqual([{ key: 'heads/main', state: IN_SYNC, remote: SHA_A, local: SHA_A }]);
    expect(divergentRows(r.rows)).toEqual([]);
  });

  // POSITIVE FIXTURE. This is literally the audit failure: same ref name,
  // different commit.
  it('calls a differing sha diverged', () => {
    const r = compareRefs({
      ...base,
      remoteRefs: new Map([['refs/heads/main', SHA_B]]),
      localRefs: new Map([['refs/remotes/origin/main', SHA_A]]),
    });
    expect(r.rows[0].state).toBe(DIVERGED);
    expect(divergentRows(r.rows)).toHaveLength(1);
  });

  it('distinguishes a branch we never fetched from one the remote deleted', () => {
    const r = compareRefs({
      ...base,
      remoteRefs: new Map([['refs/heads/new', SHA_A]]),
      localRefs: new Map([['refs/remotes/origin/gone', SHA_B]]),
    });
    const byKey = Object.fromEntries(r.rows.map((row) => [row.key, row.state]));
    expect(byKey['heads/new']).toBe(MISSING_LOCALLY);
    expect(byKey['heads/gone']).toBe(STALE_LOCALLY);
  });

  it('excludes tags unless asked, and names them as skipped', () => {
    const args = {
      ...base,
      remoteRefs: new Map([
        ['refs/heads/main', SHA_A],
        ['refs/tags/v1', SHA_B],
      ]),
      localRefs: new Map([
        ['refs/remotes/origin/main', SHA_A],
        ['refs/tags/v1', SHA_C],
      ]),
    };
    const without = compareRefs(args);
    expect(without.rows.map((r) => r.key)).toEqual(['heads/main']);
    expect(without.skipped.map(([n]) => n)).toContain('tags/v1');

    const with_ = compareRefs({ ...args, includeTags: true });
    expect(with_.rows.find((r) => r.key === 'tags/v1')?.state).toBe(DIVERGED);
  });

  // The counting contract, at the level of the pure function: nothing may fall
  // out of the union without being counted somewhere.
  it('accounts for every ref: inputs === checked + skipped', () => {
    const r = compareRefs({
      ...base,
      branches: ['main'],
      remoteRefs: new Map([
        ['refs/heads/main', SHA_A],
        ['refs/heads/other', SHA_B],
        ['refs/tags/v1', SHA_C],
      ]),
      localRefs: new Map([
        ['refs/remotes/origin/main', SHA_A],
        ['refs/remotes/origin/HEAD', SHA_A],
      ]),
    });
    expect(r.checked).toBe(1);
    expect(r.inputs).toBe(r.checked + r.skipped.length);
    // Every skip carries a name, not just a count.
    for (const [name, why] of r.skipped) {
      expect(name.length).toBeGreaterThan(0);
      expect(why.length).toBeGreaterThan(0);
    }
  });
});

describe('ref-freshness: the exit code an operator sees', () => {
  it('exits 0 and says IN_SYNC when the remote matches the local tracking refs', () => {
    const { text, count } = lsRemoteFromLocalRefs();
    expect(count).toBeGreaterThan(0); // otherwise the assertion below is vacuous
    const f = fixture('in-sync.txt', text);
    const { status, out } = run(['--ls-remote-from', f]);
    expect(out).toContain(`FRESHNESS: ${IN_SYNC}`);
    expect(out).toMatch(/inputs=\d+ checked=\d+ skipped=\d+/);
    expect(status).toBe(EXIT_OK);
  }, 60_000);

  it('exits 3, names the ref, and says nothing about freshness when one sha differs', () => {
    const { text, firstBranch } = lsRemoteFromLocalRefs();
    const flipped = text.replace(/^[0-9a-f]{40}/m, SHA_A);
    const f = fixture('diverged.txt', flipped);
    const { status, out } = run(['--ls-remote-from', f]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain(DIVERGED);
    expect(out).toContain(firstBranch);
    // No answer is given. This is the whole point: a divergence replaces the
    // verdict, it does not decorate it.
    expect(out).not.toContain(`FRESHNESS: ${IN_SYNC}`);
  }, 60_000);

  it('reports the distance in commits when the remote object is present locally', () => {
    // A real commit one step PAST head stands in for the remote tip of the
    // current branch, which is the shape of the audit failure: local pointing
    // somewhere the remote has moved past. `git rev-list` then has real objects
    // to count, and the count is known in advance, so the assertion below can
    // name it instead of accepting any two digits.
    //
    // WHY THE TIP IS BUILT AND NOT BORROWED FROM HISTORY
    //
    // The earlier version of this read `HEAD~1`, and there is no `HEAD~1` in a
    // depth-1 checkout — which is what `actions/checkout` produces by default,
    // and where this test went red. Deepening CI would have fixed this one job
    // and left the test asserting something about the fetch depth of whoever
    // runs it; the same red would come back on the next shallow clone. So the
    // commit is written here. `commit-tree` adds one unreachable commit object
    // whose parent is head, touching no ref, no index and no working tree, and
    // needing no history beyond head itself. Identity and dates are fixed so
    // the sha is stable — a re-run reuses the same object rather than leaving a
    // new one behind — and so this still works where no user.name is set, which
    // on a CI runner is the normal case.
    const gitEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: 'vibeguard-test',
      GIT_AUTHOR_EMAIL: 'ref-freshness-test@invalid',
      GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
      GIT_COMMITTER_NAME: 'vibeguard-test',
      GIT_COMMITTER_EMAIL: 'ref-freshness-test@invalid',
      GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
    };
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
    const branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
    const remoteTip = execFileSync(
      'git',
      ['commit-tree', 'HEAD^{tree}', '-p', head, '-m', 'ref-freshness test fixture: a remote tip one commit past head'],
      { cwd: REPO_ROOT, encoding: 'utf8', env: gitEnv },
    ).trim();
    expect(remoteTip).not.toBe(head);
    const f = fixture('distance.txt', `${remoteTip}\trefs/heads/${branch}\n`);
    const local = fixture('distance-local.txt', `${head} refs/remotes/origin/${branch}\n`);
    const { status, out } = run(['--ls-remote-from', f, '--local-refs-from', local]);
    expect(status).toBe(EXIT_INCOMPLETE);
    // The exact numbers, not `\d+`: the fixture is built to sit exactly one
    // commit behind, so the answer is known, and `0 behind and 0 ahead` — what a
    // degenerate comparison of two refs that do not really differ would print —
    // satisfies a `\d+` pattern just as well as the right answer does.
    expect(out).toContain('local is 1 commit(s) behind and 0 ahead');
    expect(out).not.toContain('distance NOT_OBSERVED');
  }, 60_000);

  it('says the distance is NOT_OBSERVED rather than guessing it', () => {
    const branch = 'phantom';
    const f = fixture('unknown-remote.txt', `${SHA_A}\trefs/heads/${branch}\n`);
    const local = fixture('unknown-local.txt', `${SHA_B} refs/remotes/origin/${branch}\n`);
    const { status, out } = run(['--ls-remote-from', f, '--local-refs-from', local]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('distance NOT_OBSERVED');
  }, 60_000);

  it('exits 3 on an unparseable plumbing line instead of dropping it', () => {
    const f = fixture('malformed.txt', `${SHA_A}\trefs/heads/main\nnot-a-ref-line\n`);
    const { status, out } = run(['--ls-remote-from', f]);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('UNPARSEABLE');
    expect(out).not.toContain(`FRESHNESS: ${IN_SYNC}`);
  }, 60_000);

  // The counting contract. An empty comparison is vacuously in sync, and this
  // repository has shipped three checks that reported exactly that.
  it('exits 3 when nothing was compared', () => {
    const empty = fixture('empty-remote.txt', '');
    const emptyLocal = fixture('empty-local.txt', '');
    const { status, out } = run(['--ls-remote-from', empty, '--local-refs-from', emptyLocal]);
    expect(out).toContain('inputs=0 checked=0 skipped=0');
    expect(out).toContain('Nothing was compared');
    expect(out).not.toContain(`FRESHNESS: ${IN_SYNC}`);
    expect(status).toBe(EXIT_INCOMPLETE);
  }, 60_000);

  it('exits 0 on an empty comparison only when --allow-empty was passed, and calls it NOT_OBSERVED', () => {
    const empty = fixture('empty-remote2.txt', '');
    const emptyLocal = fixture('empty-local2.txt', '');
    const { status, out } = run(['--ls-remote-from', empty, '--local-refs-from', emptyLocal, '--allow-empty']);
    expect(status).toBe(EXIT_OK);
    expect(out).toContain('NOT_OBSERVED');
    // Still not an answer. `--allow-empty` buys a zero exit code, not a claim.
    expect(out).not.toContain(`FRESHNESS: ${IN_SYNC}`);
  }, 60_000);

  it('exits 3 rather than 0 when the named remote does not exist', () => {
    const { status, out } = run(['--remote', 'no-such-remote-here']);
    expect(status).toBe(EXIT_INCOMPLETE);
    expect(out).toContain('NOT_OBSERVED');
  }, 60_000);
});

// The numbers are shared with every executable in the native toolchain
// directory; a divergence would mean two programs in one pipeline disagreeing
// about what "3" means. Both sides are read as text rather than imported so this
// test does not depend on that directory being built.
describe('ref-freshness: exit codes', () => {
  it('match the canonical definitions', () => {
    const src = readFileSync(join(REPO_ROOT, 'compiler', 'driver', 'lib', 'exit.mjs'), 'utf8');
    const value = (name: string): number => {
      const m = new RegExp(`export const ${name} = (\\d+);`).exec(src);
      expect(m, `${name} not found in the canonical exit module`).not.toBeNull();
      return Number.parseInt(m![1], 10);
    };
    expect(EXIT_OK).toBe(value('EXIT_OK'));
    expect(EXIT_TOOL_FAILED).toBe(value('EXIT_TOOL_FAILED'));
    expect(EXIT_FINDINGS).toBe(value('EXIT_FINDINGS'));
    expect(EXIT_INCOMPLETE).toBe(value('EXIT_INCOMPLETE'));
    expect(EXIT_INTEGRITY).toBe(value('EXIT_INTEGRITY'));
  });
});
