import assert from 'node:assert/strict';
import { test } from 'node:test';

import { repoRootFrom } from '../src/contract-copies.mjs';
import {
  OUR_PACKAGES,
  OUR_TOKENS,
  PACKAGE_LIST,
  TOKEN_LIST,
  arrayLiteralEntries,
  probeFence,
  probeFenceAt,
  remedyFor,
} from '../src/fence-probe.mjs';

// ── WHAT THIS FILE DOES AND DOES NOT ASSERT ─────────────────────────────────
//
// It asserts that the PROBE works, in both directions, against sources the test
// writes itself.
//
// It does NOT assert whether these two packages are, today, fenced. That state
// lives in a file this package may not edit, so a test asserting "fenced" would
// be red until somebody else changes it, and a test asserting "not fenced"
// would go red the day they do — a test that breaks when the bug is fixed is
// worse than no test. What it does assert about the real file is that the probe
// can still FIND its subject there, which is the failure that would make the
// answer meaningless in either direction.
//
// The live answer comes from `npm run check:fence`, which prints it and exits
// non-zero while the gap is open.

const FENCED_SOURCE = `
// prose that mentions @vibeguard/evidence-bundle should not count as a fence
const ${PACKAGE_LIST} = [
  '@vibeguard/analysis-graph',
  '@vibeguard/evidence-bundle',
  '@vibeguard/evidence-verifier',
];
const ${TOKEN_LIST} = ['analysis-graph', 'evidence-bundle', 'evidence-verifier'];
`;

const UNFENCED_SOURCE = `
// @vibeguard/evidence-bundle and @vibeguard/evidence-verifier are discussed at
// length in this comment, and evidence-bundle appears here too.
const ${PACKAGE_LIST} = ['@vibeguard/analysis-graph'];
const ${TOKEN_LIST} = ['analysis-graph'];
`;

const HALF_FENCED_SOURCE = `
const ${PACKAGE_LIST} = ['@vibeguard/evidence-bundle', '@vibeguard/evidence-verifier'];
const ${TOKEN_LIST} = ['evidence-bundle'];
`;

const RENAMED_SOURCE = `
const SOME_OTHER_LIST = ['@vibeguard/evidence-bundle'];
`;

test('a source with both packages on both lists reports them fenced', () => {
  const result = probeFence(FENCED_SOURCE);
  assert.equal(result.determined, true);
  assert.deepEqual(result.fenced, [...OUR_PACKAGES]);
  assert.deepEqual(result.unfenced, []);
});

test('a source that only MENTIONS them in prose reports them unfenced', () => {
  // The whole reason the arrays are parsed rather than grepped: the packaging
  // script is mostly comments, several of which discuss which packages are
  // CLI-only. A substring search would report a fence that does not exist,
  // which is strictly worse than reporting no fence at all.
  const result = probeFence(UNFENCED_SOURCE);
  assert.equal(result.determined, true);
  assert.deepEqual(result.fenced, []);
  assert.equal(result.unfenced.length, 2);
  for (const u of result.unfenced) {
    assert.deepEqual(u.missingFrom, [PACKAGE_LIST, TOKEN_LIST]);
  }
});

test('half a fence is not a fence, and the report says which half', () => {
  const result = probeFence(HALF_FENCED_SOURCE);
  assert.deepEqual(result.fenced, ['@vibeguard/evidence-bundle']);
  assert.equal(result.unfenced.length, 1);
  assert.equal(result.unfenced[0].package, '@vibeguard/evidence-verifier');
  assert.deepEqual(result.unfenced[0].missingFrom, [TOKEN_LIST]);
});

test('a source where the lists were renamed is UNDETERMINED, not "unfenced"', () => {
  const result = probeFence(RENAMED_SOURCE);
  assert.equal(result.determined, false);
  assert.match(result.reason, /UNDETERMINED/);
  assert.match(result.reason, new RegExp(TOKEN_LIST));
  assert.deepEqual(result.fenced, []);
  assert.deepEqual(result.unfenced, []);
});

test('the array parser reads entries and stops at the closing bracket', () => {
  assert.deepEqual(arrayLiteralEntries("const A = ['x', 'y'];\nconst B = ['z'];", 'A'), ['x', 'y']);
  assert.deepEqual(arrayLiteralEntries("const A = ['x', 'y'];\nconst B = ['z'];", 'B'), ['z']);
  assert.equal(arrayLiteralEntries('nothing here', 'A'), null);
  assert.deepEqual(arrayLiteralEntries('const A = [];', 'A'), []);
});

test('the remedy names the exact edit rather than stopping at "something is wrong"', () => {
  const text = remedyFor(probeFence(UNFENCED_SOURCE).unfenced);
  assert.match(text, new RegExp(PACKAGE_LIST));
  assert.match(text, new RegExp(TOKEN_LIST));
  for (const name of OUR_PACKAGES) assert.ok(text.includes(name), name);
  for (const token of OUR_TOKENS) assert.ok(text.includes(token), token);
  assert.equal(remedyFor([]), '');
});

test('the probe can still find its subject in the real packaging script', () => {
  const result = probeFenceAt(repoRootFrom());
  assert.equal(
    result.determined,
    true,
    `${result.reason ?? ''} — if the lists were renamed, rename them in fence-probe.mjs too`,
  );
  assert.ok(Array.isArray(result.packageList) && result.packageList.length > 0);
  assert.ok(Array.isArray(result.tokenList) && result.tokenList.length > 0);
  assert.equal(
    result.fenced.length + result.unfenced.length,
    OUR_PACKAGES.length,
    'every package must land on exactly one side of the answer',
  );
});
