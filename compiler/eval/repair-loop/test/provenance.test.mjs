/**
 * Listing digests, the rows-file label, and the path self-check the runner runs
 * on every text before it is written. The path check has to fire on each shape it
 * names and stay quiet on the texts a clean run produces.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { sha256Text, absolutePathHits, rowsFileLabel, PATH_MARKERS } from '../lib/provenance.mjs';

test('sha256Text hashes the text exactly as read, and nothing for no listing', () => {
  const t = '\t.text\nf:\n\tretq\n';
  assert.equal(sha256Text(t), createHash('sha256').update(Buffer.from(t, 'utf8')).digest('hex'));
  assert.match(sha256Text(''), /^[0-9a-f]{64}$/);
  assert.notEqual(sha256Text(t), sha256Text(t + '\n'));
  assert.equal(sha256Text(null), null);
  assert.equal(sha256Text(undefined), null);
});

// Assembled from fragments so this file does not itself carry a path of the shape it tests.
const sl = '/';
const bs = '\\';
const home = [sl + 'home', 'someone', 'lab', 'x.json'].join(sl);
const root = [sl + 'root', 'lab'].join(sl);
const mnt = [sl + 'mnt', 'c', 'work'].join(sl);
const mac = [sl + 'Users', 'someone', 'lab'].join(sl);
const win = 'C:' + bs + 'work' + bs + 'lab';
const winFwd = 'D:' + sl + 'lab';

test('absolutePathHits fires on every marker, in plain text and inside JSON', () => {
  assert.deepEqual(absolutePathHits(home), ['/home/']);
  assert.deepEqual(absolutePathHits(root), ['/root/']);
  assert.deepEqual(absolutePathHits(mnt), ['/mnt/']);
  assert.deepEqual(absolutePathHits(mac), ['/Users/']);
  assert.deepEqual(absolutePathHits(win), ['drive-letter']);
  assert.deepEqual(absolutePathHits(winFwd), ['drive-letter']);
  // JSON escapes the backslash; still found
  assert.deepEqual(absolutePathHits(JSON.stringify({ plugin: win })), ['drive-letter']);
  assert.deepEqual(absolutePathHits(JSON.stringify({ rowsFile: home, out: mnt })), ['/home/', '/mnt/']);
  assert.equal(PATH_MARKERS.length, 4);
});

test('absolutePathHits stays quiet on what a clean run writes', () => {
  const clean = [
    JSON.stringify({ plugin: { basename: 'libWipePin.so', sha256: 'ab'.repeat(32) }, rowsFile: '(default)' }),
    JSON.stringify({ rowsFile: 'compiler/eval/ai-generated/data/r2-build-rows.json' }),
    'record-w: record-missing; unresolved-wo: f (not-in-module)',
    'eliminations reversed / found: clang-18 1/2, gcc-13 0/3 (no plugin can load), total 1/5',
    'see https://example.org/x',
    'module-scope record                   valid',
    'ratio 3:4, a:b, e: /',
  ];
  for (const t of clean) assert.deepEqual(absolutePathHits(t), [], t);
  assert.deepEqual(absolutePathHits(null), []);
});

test('rowsFileLabel: (default), a repository-relative path, or (outside the repository) -- never absolute', () => {
  const repo = path.resolve('repo-root-for-test');
  const def = path.join(repo, 'compiler', 'eval', 'ai-generated', 'data', 'r2-build-rows.json');
  assert.equal(rowsFileLabel(def, { defaultPath: def, repoRoot: repo }), '(default)');
  const other = path.join(repo, 'compiler', 'eval', 'x', 'rows.json');
  assert.equal(rowsFileLabel(other, { defaultPath: def, repoRoot: repo }), 'compiler/eval/x/rows.json');
  const outside = path.resolve(repo, '..', 'elsewhere', 'rows.json');
  assert.equal(rowsFileLabel(outside, { defaultPath: def, repoRoot: repo }), '(outside the repository)');
  // a sibling whose name starts with the repository's is outside too
  const sibling = path.resolve(repo + '-other', 'rows.json');
  assert.equal(rowsFileLabel(sibling, { defaultPath: def, repoRoot: repo }), '(outside the repository)');
  for (const p of [def, other, outside, sibling]) {
    assert.deepEqual(absolutePathHits(rowsFileLabel(p, { defaultPath: def, repoRoot: repo })), []);
  }
});
