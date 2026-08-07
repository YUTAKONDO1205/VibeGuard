// The counting contract, and the two ways a scan lies about having run.
//
// An empty scan reporting exit 0 has happened three times in this repository.
// These are the tests that say it cannot happen here.

import assert from 'node:assert/strict';
import test from 'node:test';

import { skipAuthorised, Tally } from '../lib/count.mjs';
import { EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK } from '../lib/exit.mjs';

test('the three numbers are always printed, in order', () => {
  const t = new Tally('x');
  t.input(3).counted().counted();
  t.skip('third.c', 'no reader for this format');
  assert.match(t.render(), /^x: inputs=3 checked=2 skipped=1$/m);
});

test('an empty run is INCOMPLETE, never OK', () => {
  const t = new Tally('x');
  assert.equal(t.inputs, 0);
  assert.equal(t.emptyAndUnauthorised, true);
  assert.equal(t.exitFor(EXIT_OK), EXIT_INCOMPLETE);
});

test('an empty run cannot be argued down to OK by a happy caller', () => {
  // The floor applies whatever the caller passes in: a later step deciding it
  // found nothing wrong is exactly the reasoning that produced the three
  // silent-green scans this contract exists to stop.
  const t = new Tally('x');
  assert.equal(t.exitFor(EXIT_OK), EXIT_INCOMPLETE);
  assert.equal(t.exitFor(EXIT_FINDINGS), EXIT_INCOMPLETE);
});

test('--allow-empty makes the claim on the record and is printed back', () => {
  const t = new Tally('x', { allowEmpty: true });
  assert.equal(t.exitFor(EXIT_OK), EXIT_OK);
  assert.match(t.render(), /allowEmpty=1/);
});

test('a non-empty run keeps the caller\'s code', () => {
  const t = new Tally('x');
  t.input().counted();
  assert.equal(t.exitFor(EXIT_OK), EXIT_OK);
  assert.equal(t.exitFor(EXIT_FINDINGS), EXIT_FINDINGS);
});

test('every skip is listed by name in the output', () => {
  const t = new Tally('x');
  t.input(2).counted();
  t.skip('weird.o', 'not an ELF object');
  const rendered = t.render();
  assert.match(rendered, /skipped=1/);
  assert.match(rendered, /skipped: weird\.o -- not an ELF object/);
});

test('a skip without a reason is refused', () => {
  const t = new Tally('x');
  assert.throws(() => t.skip('a.c', ''), /both are required/);
  assert.throws(() => t.skip('', 'because'), /both are required/);
});

test('a missing prerequisite is a failure, not a skip', () => {
  const t = new Tally('x');
  assert.throws(
    () => skipAuthorised(t, 'clang-18', 'not on PATH', {}),
    /This is a failure, not a skip/,
  );
  assert.equal(t.skipped, 0);
});

test('an authorised skip is allowed and names the case', () => {
  const t = new Tally('x');
  const allowed = skipAuthorised(t, 'clang-18', 'not on PATH', { VG_INTRO_ALLOW_SKIP: '1' });
  assert.equal(allowed, true);
  assert.equal(t.skipped, 1);
  assert.match(t.render(), /skipped: clang-18 -- not on PATH \(skip authorised by VG_INTRO_ALLOW_SKIP=1\)/);
});
