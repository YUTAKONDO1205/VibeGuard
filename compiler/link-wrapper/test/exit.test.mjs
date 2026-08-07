// The exit codes are restated in lib/exit.mjs rather than imported, so this
// component does not depend on another one's load order. That is only safe if
// "restated" can never quietly become "renumbered" — a caller branching on 2
// versus 3 has no way to notice that one component moved.
//
// If compiler/driver/lib/exit.mjs is gone or renamed, this FAILS. The numbers
// are a shared contract and a component that cannot check it against the
// original should not report that it holds.

import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import * as mine from '../lib/exit.mjs';
import { HERE } from './helpers.mjs';
import { LINK } from '../lib/findings.mjs';

const DRIVER_EXIT = resolve(HERE, '..', '..', 'driver', 'lib', 'exit.mjs');

test('the numbers are the ones interfaces.md §7 fixes', () => {
  assert.deepEqual(
    [mine.EXIT_OK, mine.EXIT_TOOL_FAILED, mine.EXIT_FINDINGS, mine.EXIT_INCOMPLETE, mine.EXIT_INTEGRITY],
    [0, 1, 2, 3, 4],
  );
});

test('they are the same numbers the driver uses', async () => {
  assert.ok(existsSync(DRIVER_EXIT), `${DRIVER_EXIT} is missing; the shared exit codes could not be checked`);
  const theirs = await import(pathToFileURL(DRIVER_EXIT).href);
  for (const k of ['EXIT_OK', 'EXIT_TOOL_FAILED', 'EXIT_FINDINGS', 'EXIT_INCOMPLETE', 'EXIT_INTEGRITY']) {
    assert.equal(mine[k], theirs[k], `${k} disagrees between the link wrapper and the driver`);
  }
});

test('every finding id is in the VG-LINK namespace and none is duplicated', () => {
  const ids = Object.values(LINK);
  for (const id of ids) assert.match(id, /^VG-LINK-0\d\d$/);
  assert.equal(new Set(ids).size, ids.length, 'two constants share an id');
});
