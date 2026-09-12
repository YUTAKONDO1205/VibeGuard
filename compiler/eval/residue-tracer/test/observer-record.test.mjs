/**
 * Two constants in observer/residue-observer.c are duplicated on the JavaScript
 * side, and a duplicate that drifts is worse than no duplicate at all. This file
 * reads the C source as text and holds the two copies equal. No compiler runs:
 * the point is the literal in the source, not the behaviour of the binary.
 *
 * WHAT `unobserved` IS FOR. Every row names what no cell looked at, so a reader
 * is not left to infer it from silence -- that is the invariant this lane is
 * built around, UNOBSERVED never being allowed to read as ABSENT. The list used
 * to name `stack-below-the-window` and stop there, which left the whole other
 * side of the window -- the caller frames from the window's top up to the top of
 * the stack -- unnamed, even though the README's prose ("the stack outside that
 * 4160-byte window") already counted them out. A machine-readable field narrower
 * than the prose is the half a script would believe.
 *
 * WHAT `WINDOW_MAX` IS FOR. The observer refuses a window larger than it, with
 * usage() rather than a record, so the runner must know the ceiling to cap the
 * window it grows to cover a subject frame. A frame deeper than the ceiling is a
 * BROKEN_MEASUREMENT carrying the size it needed -- not a shallow reading.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { UNOBSERVED } from '../lib/manifest.mjs';
import { WINDOW_MAX_BYTES } from '../lib/frame.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const C_SRC = readFileSync(join(HERE, '..', 'observer', 'residue-observer.c'), 'utf8');

/** The strings the observer writes into the record's `unobserved` array. */
function observerUnobserved(src) {
  const at = src.indexOf('\\"unobserved\\"');
  assert.notEqual(at, -1, 'the observer must still write an unobserved array');
  const end = src.indexOf('],', at);
  assert.notEqual(end, -1);
  return [...src.slice(at, end).matchAll(/\\"([a-z-]+)\\"/g)].map((m) => m[1]).filter((s) => s !== 'unobserved');
}

test('the observer and the row builder name the same unobserved regions, in the same order', () => {
  assert.deepEqual(observerUnobserved(C_SRC), [...UNOBSERVED]);
});

test('both sides of the window are named, not just the deep side', () => {
  // The regression this file was added for. `stack-below-the-window` alone is a
  // list that silently ends at the window's top edge, and a row is the only
  // place a downstream reader can learn what was not looked at.
  for (const list of [observerUnobserved(C_SRC), [...UNOBSERVED]]) {
    assert.ok(list.includes('stack-below-the-window'), 'the deep side');
    assert.ok(list.includes('stack-above-the-window'), 'the caller frames above the window are unobserved too');
  }
});

test('the window ceiling the runner caps against is the one the observer enforces', () => {
  const m = /#define\s+WINDOW_MAX\s+\(1u\s*<<\s*(\d+)\)/.exec(C_SRC);
  assert.ok(m, 'WINDOW_MAX must still be a shift literal in the observer');
  assert.equal(2 ** Number(m[1]), WINDOW_MAX_BYTES);
});

test('the observer still refuses a window larger than that ceiling rather than truncating it', () => {
  // If this check ever goes, a runner that asks for too much gets a silently
  // smaller window instead of an error, and the frame bound stops meaning
  // anything: the row would say the window covered the frame when it did not.
  assert.match(C_SRC, /below \+ above > WINDOW_MAX\) usage\(\);/);
});
