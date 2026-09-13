/**
 * The receipt gate, in both directions.
 *
 * A gate that has only ever been seen to let a run through has not been shown to
 * be a gate, so every test here is either "this is the receipt the controls would
 * have written and it is accepted" or "this is one thing changed and it is
 * refused, with a sentence naming what". The refusals are the load-bearing half:
 * the defect this file exists to fence is `run-second-vendor.mjs` building the
 * 80-cell table with no controls at all, which produced a green envelope for
 * years of convention-following and never once said so.
 *
 * Nothing here compiles anything, runs a compiler, or reads a lab. It writes a
 * few small files into the system temp directory and removes them.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ALL_PASSED, CONTROLS_FILE, RECEIPT_SCHEMA,
  fileDigest, readReceipt, receiptOf, receiptProblems, subjectOf,
} from '../lib/controls-receipt.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SPEC_PATH = path.join(HERE, '..', 'spec.json');
const SPEC = JSON.parse(readFileSync(SPEC_PATH, 'utf8'));

/** A fixtures tree with one target.c per property the real spec declares. */
function makeFixtures(body = 'int main(void){return 0;}\n') {
  const root = mkdtempSync(path.join(tmpdir(), 'sv-receipt-'));
  for (const prop of SPEC.properties) {
    mkdirSync(path.join(root, prop.fixtureId), { recursive: true });
    writeFileSync(path.join(root, prop.fixtureId, 'target.c'), `/* ${prop.fixtureId} */\n${body}`, 'utf8');
  }
  return root;
}

/** The control blocks run-controls.mjs writes when everything held. */
function passingBlocks() {
  const out = [];
  for (const prop of SPEC.properties) {
    for (const vendor of SPEC.vendors) {
      out.push({ propertyId: prop.propertyId, vendor: vendor.vendorId, pass: true });
    }
  }
  return out;
}

function withFixtures(fn) {
  const root = makeFixtures();
  try {
    return fn(root, subjectOf(SPEC, SPEC_PATH, root));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------- the subject

test('the subject digests the spec and one target.c per declared property', () => {
  withFixtures((root, subject) => {
    assert.equal(typeof subject.specSha256, 'string');
    assert.equal(subject.specSha256.length, 64);
    assert.deepEqual(subject.vendors, ['clang-18', 'gcc-13']);
    assert.equal(Object.keys(subject.fixtures).length, SPEC.properties.length);
    for (const prop of SPEC.properties) {
      assert.equal(typeof subject.fixtures[`${prop.fixtureId}/target.c`], 'string',
        `${prop.fixtureId}/target.c is not in the receipt's subject, so a run over it would be `
        + 'gated by a receipt that never saw it');
    }
  });
});

test('a fixture that is not there digests to null rather than to a string nothing wrote', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'sv-receipt-empty-'));
  try {
    const subject = subjectOf(SPEC, SPEC_PATH, root);
    for (const v of Object.values(subject.fixtures)) assert.equal(v, null);
    assert.equal(fileDigest(path.join(root, 'nope.c')), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------------ the green

test('a receipt from a clean control run is accepted over the same bytes', () => {
  withFixtures((root, subject) => {
    const receipt = receiptOf(subject, passingBlocks());
    assert.equal(receipt.schemaVersion, RECEIPT_SCHEMA);
    assert.equal(receipt.verdict, ALL_PASSED);
    assert.equal(receipt.blocks, SPEC.properties.length * SPEC.vendors.length);
    assert.deepEqual(receiptProblems(receipt, subject, 'x'), []);
  });
});

// ------------------------------------------------------------ the eight reds

test('no receipt at all is refused, and the message says to run the controls', () => {
  withFixtures((root, subject) => {
    const problems = receiptProblems(null, subject, 'somewhere/second-vendor-controls.json');
    assert.equal(problems.length, 1);
    assert.match(problems[0], /no controls receipt/);
    assert.match(problems[0], /run-controls\.mjs/);
  });
});

test('a failed control block is refused and the failing block is named', () => {
  withFixtures((root, subject) => {
    const blocks = passingBlocks();
    blocks[3].pass = false;
    const receipt = receiptOf(subject, blocks);
    assert.equal(receipt.verdict, 'CONTROLS_FAILED');
    const problems = receiptProblems(receipt, subject, 'x');
    assert.equal(problems.length, 1);
    assert.match(problems[0], new RegExp(blocks[3].propertyId.replace('.', '\\.')));
    assert.match(problems[0], new RegExp(blocks[3].vendor));
  });
});

test('a verdict forged to ALL_CONTROLS_PASSED over a failed block cannot be built here', () => {
  withFixtures((root, subject) => {
    const blocks = passingBlocks();
    blocks[0].pass = false;
    // receiptOf recomputes rather than copying, which is the whole point: a
    // caller cannot hand it a verdict.
    assert.equal(receiptOf(subject, blocks).verdict, 'CONTROLS_FAILED');
  });
});

test('a receipt over no blocks at all is refused rather than counted as clean', () => {
  withFixtures((root, subject) => {
    const receipt = receiptOf(subject, []);
    assert.notEqual(receipt.verdict, ALL_PASSED);
    const problems = receiptProblems(receipt, subject, 'x');
    assert.ok(problems.some((p) => /receipt for nothing/.test(p)), problems.join('\n'));
  });
});

test('an unknown receipt schema is not read optimistically', () => {
  withFixtures((root, subject) => {
    const receipt = { ...receiptOf(subject, passingBlocks()), schemaVersion: 'something-else/9' };
    const problems = receiptProblems(receipt, subject, 'x');
    assert.equal(problems.length, 1);
    assert.match(problems[0], /schemaVersion/);
  });
});

test('a receipt taken against a different spec.json is refused', () => {
  withFixtures((root, subject) => {
    const receipt = receiptOf({ ...subject, specSha256: 'a'.repeat(64) }, passingBlocks());
    const problems = receiptProblems(receipt, subject, 'x');
    assert.ok(problems.some((p) => /spec\.json/.test(p)), problems.join('\n'));
  });
});

test('a receipt demonstrated on one vendor does not cover a run over two', () => {
  withFixtures((root, subject) => {
    const receipt = receiptOf({ ...subject, vendors: ['clang-18'] }, passingBlocks());
    const problems = receiptProblems(receipt, subject, 'x');
    assert.ok(problems.some((p) => /vendor/.test(p)), problems.join('\n'));
  });
});

test('a fixture edited since the controls ran is refused, with both digests', () => {
  withFixtures((root, subject) => {
    const key = `${SPEC.properties[0].fixtureId}/target.c`;
    const stale = { ...subject, fixtures: { ...subject.fixtures, [key]: 'b'.repeat(64) } };
    const receipt = receiptOf(stale, passingBlocks());
    const problems = receiptProblems(receipt, subject, 'x');
    assert.equal(problems.length, 1);
    assert.match(problems[0], /has changed since the controls ran/);
    assert.match(problems[0], /bbbbbbbbbbbb/);
  });
});

test('a fixture the receipt never covered is refused rather than skipped', () => {
  withFixtures((root, subject) => {
    const key = `${SPEC.properties[1].fixtureId}/target.c`;
    const partial = { ...subject, fixtures: { ...subject.fixtures } };
    delete partial.fixtures[key];
    const receipt = receiptOf(partial, passingBlocks());
    const problems = receiptProblems(receipt, subject, 'x');
    assert.equal(problems.length, 1);
    assert.match(problems[0], /does not cover it/);
  });
});

test('a fixture that has gone missing since the controls ran is refused', () => {
  withFixtures((root, subject) => {
    const key = `${SPEC.properties[0].fixtureId}/target.c`;
    const gone = { ...subject, fixtures: { ...subject.fixtures, [key]: null } };
    const receipt = receiptOf(subject, passingBlocks());
    const problems = receiptProblems(receipt, gone, 'x');
    assert.equal(problems.length, 1);
    assert.match(problems[0], /not readable now/);
  });
});

// ------------------------------------------------------------------ on disk

test('readReceipt finds the block run-controls.mjs writes, and reports an absent file as no receipt', () => {
  const out = mkdtempSync(path.join(tmpdir(), 'sv-receipt-out-'));
  try {
    assert.deepEqual(readReceipt(out), {
      receipt: null, path: path.join(out, CONTROLS_FILE), unreadable: null,
    });

    writeFileSync(path.join(out, CONTROLS_FILE), '{ not json', 'utf8');
    const bad = readReceipt(out);
    assert.equal(bad.receipt, null);
    assert.ok(bad.unreadable, 'a malformed report must say so rather than read as an absent one');

    writeFileSync(path.join(out, CONTROLS_FILE),
      JSON.stringify({ controlsReceipt: { schemaVersion: RECEIPT_SCHEMA, verdict: ALL_PASSED } }), 'utf8');
    assert.equal(readReceipt(out).receipt.verdict, ALL_PASSED);

    // An older report, written before this gate existed, carries no receipt block
    // at all -- and must not be read as one that passed.
    writeFileSync(path.join(out, CONTROLS_FILE),
      JSON.stringify({ summary: { verdict: ALL_PASSED } }), 'utf8');
    assert.equal(readReceipt(out).receipt, null);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// --- the README records runs, not intentions -------------------------------
//
// Everything above is a unit test over synthetic receipts, and that distinction
// is the one this lane got wrong once already: between 2026-09-12 and 2026-09-13
// README.md said the accepting direction "has not been run" and could not be,
// "the machine this was written on has no such set" -- while ten complete fixture
// sets sat in the lab. The claim was not measured; it was assumed, and a unit
// suite passing in both directions was read as covering for it.
//
// All four paths were run on 2026-09-13, and the test below is a REVERT DETECTOR
// for that record -- not a check that the record is true.
//
// That limit is stated here because the limit is real and was demonstrated. A
// prose grep cannot verify a measurement: on copies of this lane, a README whose
// paragraph was rewritten to "NOTHING HERE HAS BEEN RUN … treat every figure as
// fabricated" with the table's strings left in place passed this file 15/15, and so
// did one with every figure in the table falsified — exit 0 → exit 7, the digests
// replaced, all three `exit 3` refusals rewritten to `exit 0`. So do not read a
// green run of this file as "the table is right". What it does catch, measured the
// same way: restoring the pre-2026-09-13 paragraph verbatim, and deleting the
// four-row table. Those are the two ways the record actually goes missing, and they
// are what this is for.
//
// Two assertions were dropped when that was measured rather than left in to pad the
// list: `/CONTROLS_FAILED/` and `/exit 2/` are both satisfied by prose elsewhere in
// the file that predates the runs (README.md's `run-controls.mjs` section), so they
// could never have failed for the right reason. The four that remain occur only in
// the table, and they are matched against the TABLE REGION rather than the whole
// file so that they cannot start being satisfied from somewhere else later.

test('README.md still records the four paths as run — a revert detector, not a proof', () => {
  const readme = readFileSync(path.join(HERE, '..', 'README.md'), 'utf8');

  assert.doesNotMatch(readme, /accepting direction has not been run/i,
    'README.md says the accepting direction is unrun. It was run on 2026-09-13 (exit 0, receipt '
    + 'ALL_CONTROLS_PASSED over 10 blocks, 80 cells). If it has genuinely become unrunnable, say '
    + 'why and when here rather than restoring a sentence that was false the first time.');
  assert.doesNotMatch(readme, /machine this was written on has no such set/i,
    'README.md repeats the claim that this machine has no five-property fixture set. It has ten, '
    + 'verified byte-identical across all five properties.');

  // The four-path table only: from its header row to the blank line after it.
  const table = /\n\| path \| command \| result \|\n([\s\S]*?)\n\n/.exec(readme);
  assert.ok(table, 'README.md no longer carries the four-path table (header `| path | command | '
    + 'result |`). That table IS the record of what was run; its absence is the failure this test '
    + 'exists for.');
  const rows = table[1];
  assert.ok(rows.split('\n').length >= 5,
    `the four-path table parsed to ${rows.split('\n').length} line(s); four paths plus a separator `
    + 'is five');

  for (const [what, re] of [
    ['the accepting run and its verdict', /ALL_CONTROLS_PASSED over 10 block\(s\)/],
    ['the cell count it produced', /totalCells`? \*\*80\*\*/],
    ['the no-receipt refusal', /no controls receipt at/],
    ['the other-bytes refusal', /has changed since the controls ran/],
  ]) {
    assert.match(rows, re,
      `the four-path table no longer records ${what}. The four paths are the evidence that this is `
      + 'a gate rather than a convention; a table that records only the green one records the '
      + 'state this lane was already in.');
  }

  // And the boundary the runs do NOT cross, kept stated.
  // \s+ and not a space: the sentence wraps across a line in the source.
  assert.match(readme, /all ten in the lab share the same `target\.c`\s+bytes/,
    'README.md must keep saying that the ten fixture sets are one set measured once: otherwise '
    + '"ten sets" reads as ten independent confirmations, which is exactly the overclaim this '
    + 'paragraph was rewritten to avoid.');
});
