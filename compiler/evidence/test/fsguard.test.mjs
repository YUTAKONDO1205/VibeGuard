// (C) Symlink refusal, both directions.
//
// ON WHAT IS AND IS NOT EXERCISED HERE
//
//   An unprivileged process on Windows cannot create a FILE symlink; it can
//   create a directory junction, which `lstat` reports as a symbolic link and
//   which performs the identical redirection. Every test below therefore links
//   a DIRECTORY, which is a real link on both platforms and needs no skip. The
//   last test additionally tries the file form and asserts the outcome either
//   way — it never passes by not running.
//
//   Both code paths under test are one and the same: `findSymlinks` walks a
//   list of components and asks `isSymbolicLink()` of each. A file symlink and
//   a junction differ in how they are made, not in how they are found.

import { strict as assert } from 'node:assert';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import test from 'node:test';

import { assertNoSymlink, findSymlinks, isWithin, SymlinkRefused } from '../fsguard.mjs';
import { cleanup, linkDir, makeScratch, tryLinkFile } from './helpers.mjs';

test('a real file on a real path is not a link', () => {
  const dir = makeScratch('fsguard-clean');
  try {
    const f = join(dir, 'record.json');
    writeFileSync(f, '{}', 'utf8');
    assert.deepEqual(findSymlinks(f), []);
    assert.equal(assertNoSymlink(f), resolve(f));
  } finally {
    cleanup(dir);
  }
});

test('a linked directory on the path is found and named', () => {
  const dir = makeScratch('fsguard-linked');
  try {
    const real = join(dir, 'real');
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, 'record.json'), '{}', 'utf8');
    const link = linkDir(real, join(dir, 'link'));
    const through = join(dir, 'link', 'record.json');

    const found = findSymlinks(through);
    assert.equal(found.length, 1, `expected one link (made a ${link.kind}), got ${JSON.stringify(found)}`);
    assert.match(found[0].split(/[\\/]/).pop(), /^link$/);

    assert.throws(() => assertNoSymlink(through, { role: 'the record' }), SymlinkRefused);
  } finally {
    cleanup(dir);
  }
});

test('the link itself, handed in directly, is refused', () => {
  const dir = makeScratch('fsguard-direct');
  try {
    const real = join(dir, 'real');
    mkdirSync(real, { recursive: true });
    linkDir(real, join(dir, 'link'));
    assert.throws(() => assertNoSymlink(join(dir, 'link')), SymlinkRefused);
  } finally {
    cleanup(dir);
  }
});

test('ancestors: false looks at the target alone', () => {
  const dir = makeScratch('fsguard-noanc');
  try {
    const real = join(dir, 'real');
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, 'record.json'), '{}', 'utf8');
    linkDir(real, join(dir, 'link'));
    const through = join(dir, 'link', 'record.json');
    assert.deepEqual(findSymlinks(through, { ancestors: false }), []);
    assert.equal(findSymlinks(through).length, 1);
  } finally {
    cleanup(dir);
  }
});

test('a boundary stops the walk, and only when it is really above the target', () => {
  const dir = makeScratch('fsguard-boundary');
  try {
    const real = join(dir, 'real');
    const inner = join(real, 'inner');
    mkdirSync(inner, { recursive: true });
    writeFileSync(join(inner, 'record.json'), '{}', 'utf8');
    linkDir(real, join(dir, 'link'));
    const through = join(dir, 'link', 'inner', 'record.json');

    // Boundary below the link: the link is above it and is not looked at.
    assert.deepEqual(findSymlinks(through, { boundary: join(dir, 'link', 'inner') }), []);
    // Boundary above the link: the link is inside the walk and is found.
    assert.equal(findSymlinks(through, { boundary: dir }).length, 1);
    // A boundary the target is not under cannot stop the walk, so it does not.
    assert.equal(findSymlinks(through, { boundary: join(dir, 'elsewhere') }).length, 1);
  } finally {
    cleanup(dir);
  }
});

test('isWithin says what it means', () => {
  assert.equal(isWithin('/a/b', '/a/b'), true);
  assert.equal(isWithin('/a/b', '/a/b/c'), true);
  assert.equal(isWithin('/a/b', '/a/bc'), false);
  assert.equal(isWithin('/a/b', '/a'), false);
});

test('a missing path is not reported as a link', () => {
  const dir = makeScratch('fsguard-missing');
  try {
    assert.deepEqual(findSymlinks(join(dir, 'nothing-here.json'), { ancestors: false }), []);
  } finally {
    cleanup(dir);
  }
});

test('the file-symlink form, where the platform allows it', () => {
  const dir = makeScratch('fsguard-filelink');
  try {
    const real = join(dir, 'record.json');
    writeFileSync(real, '{}', 'utf8');
    const made = tryLinkFile(real, join(dir, 'link.json'));
    if (made === null) {
      // Not a skip: the directory form above proved the same code path, and
      // this case is named in the output rather than silently passing.
      assert.equal(process.platform, 'win32', 'a file symlink failed on a platform that should allow it');
      console.log('  note: file symlinks need a privilege this process lacks (win32); the junction cases above cover the same findSymlinks() path');
      return;
    }
    assert.equal(findSymlinks(made, { ancestors: false }).length, 1);
    assert.throws(() => assertNoSymlink(made), SymlinkRefused);
  } finally {
    cleanup(dir);
  }
});
