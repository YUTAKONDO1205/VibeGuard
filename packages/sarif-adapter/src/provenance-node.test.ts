// Tests for the Node half of provenance collection.
//
// The parsing is covered by provenance.test.ts; what is pinned here is the
// contract that makes this safe to call unconditionally from a CLI: every way of
// having no history — no repository, no git, no PR body file — is "this channel
// produced nothing", never a thrown error and never a scan failure. Scanning a
// tarball, a Docker build context or an `npm pack` extraction is normal.
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readAiProvenance } from './provenance-node.js';

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vg-prov-'));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('readAiProvenance', () => {
  it('returns undefined when no channel could be read at all', async () => {
    // A fresh temp directory is not a git repository, so `git log` exits
    // non-zero. That is the tarball / build-context case, and it is not a
    // failure — the caller gets "there was nothing to look at".
    expect(await readAiProvenance({ cwd: dir })).toBeUndefined();
  });

  it('reads a PR body file even when there is no repository', async () => {
    const file = join(dir, 'pr-body.md');
    await writeFile(file, '## AI assistance\n\n- [x] Claude Code\n', 'utf8');
    const o = await readAiProvenance({ cwd: dir, prBodyFile: file });
    expect(o?.inspected.channelsRead).toEqual(['pr-body']);
    // The heading is a declaration; the ticked item names the tool.
    expect(o?.observedAuthorshipMarkers.some((m) => m.assistant === 'claude')).toBe(true);
    // No absolute path leaks into the emitted marker: `readFrom` is the label.
    for (const m of o!.observedAuthorshipMarkers) expect(m.readFrom).toBe('pr-body');
  });

  it('treats a missing PR body file as a channel that was not read', async () => {
    // The GitHub Action passes this path unconditionally; on a `push` event the
    // file does not exist. That must not fail the scan.
    const o = await readAiProvenance({ cwd: dir, prBodyFile: join(dir, 'does-not-exist.md') });
    expect(o).toBeUndefined();
  });

  it('reads this repository and finds its declared assistant', async () => {
    // The one test that touches real history. It asserts only what cannot drift:
    // that the git channel was read at all and that whatever markers came back
    // are well-formed. Asserting a COUNT here would make the test fail on every
    // future commit, which is how a test gets deleted rather than fixed.
    const o = await readAiProvenance({ cwd: process.cwd(), maxCommits: 50 });
    expect(o?.inspected.channelsRead).toEqual(['git-log']);
    expect(o?.inspected.commitsInspected).toBeGreaterThan(0);
    for (const m of o!.observedAuthorshipMarkers) {
      expect(m.readFrom).toBe('git-log');
      expect(m.occurrences).toBeGreaterThan(0);
      expect(['email-address', 'display-name', 'declaration-only']).toContain(m.matchedOn);
    }
  });

  it('clamps a hostile maxCommits rather than passing it to a command line', async () => {
    // The value reaches `--max-count=`. Non-numeric input is rejected before it
    // can be stringified into an argument, and the argument array means there is
    // no shell to reach even if it were.
    for (const bad of [Number.NaN, -1, Infinity, 1e9]) {
      await expect(readAiProvenance({ cwd: dir, maxCommits: bad })).resolves.toBeUndefined();
    }
  });
});
