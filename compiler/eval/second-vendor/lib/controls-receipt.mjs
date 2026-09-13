/**
 * The receipt `run-controls.mjs` leaves behind and `run-second-vendor.mjs` refuses
 * to run without.
 *
 * WHY THIS FILE EXISTS
 *
 * README.md says, of the four scripts in this lane, "Run in this order" and then
 * "`node run-controls.mjs` -- must pass before the table means anything". That
 * sentence was true and unenforced: `run-second-vendor.mjs` never opened
 * `second-vendor-controls.json`, never looked at its verdict, and produced the
 * 80-cell envelope whether the controls had passed, had failed, or had never been
 * run at all. The order was a convention, and a convention is a thing a person
 * remembers -- which is exactly the shape of failure the spike lane next door was
 * built to stop being possible.
 *
 * This is the receipt gate. `run-controls.mjs` writes down what it validated the
 * oracle ON -- the fixture bytes, the spec, the drivers -- and `run-second-vendor.mjs`
 * refuses unless a green receipt for THE SAME BYTES is sitting there. Not a flag,
 * not a timestamp: a digest. A receipt from a run over different fixtures is a
 * receipt about a different oracle, and the whole reason this gate is worth adding
 * is that it cannot be satisfied by running the controls once, long ago, on
 * something else.
 *
 * WHAT IT IS NOT
 *
 * It is not the spike lane's gate and does not pretend to be. `compiler/eval/spike`
 * mixes two translation units of known behaviour into a run and grades them with
 * the same verdictOf the run uses; wiring it in HERE would gate an assembly oracle
 * on a differential-compilation instrument -- a green tick over a different
 * instrument, which is the thing compiler/eval/spike/README.md's own warning about
 * this lane says not to do. What closes the same hole here is this lane's own
 * instrument: C1 is the known positive, C2/C3 are the known negative, C4 is the
 * silent-failure guard, all four run on `lib/asm-oracle.mjs` itself, and this file
 * is the wire that makes the main table depend on them having held.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** The receipt's own schema. A receipt that does not declare this is not read. */
export const RECEIPT_SCHEMA = 'second-vendor-controls-receipt/1';

/** The file `run-controls.mjs` writes and `run-second-vendor.mjs` reads. */
export const CONTROLS_FILE = 'second-vendor-controls.json';

/** The word `run-controls.mjs` writes into `summary.verdict` when nothing failed. */
export const ALL_PASSED = 'ALL_CONTROLS_PASSED';

/**
 * The files of one fixture whose bytes the controls actually stood on.
 *
 * `target.c` is the one the controls compile and mutate. `opaque.c` and `main.c`
 * are scaffolding for the main table's link-and-run step and the controls never
 * touch them, so they are deliberately NOT in the digest: a receipt invalidated by
 * an edit to a file the controls never read would train a reader to re-run the
 * controls for a reason that is not a reason, and a gate people learn to satisfy
 * mechanically has stopped being a gate.
 */
export const DIGESTED_FIXTURE_FILES = ['target.c'];

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * The digest of one file, or null when it is not there.
 *
 * Null is a real answer and the comparison treats it as one. A fixture that has
 * gone missing since the controls ran must not compare equal to anything.
 */
export function fileDigest(p) {
  try {
    return sha256(fs.readFileSync(p));
  } catch {
    return null;
  }
}

/**
 * What this run is about to measure, reduced to the things a receipt can be held
 * against: the spec, the fixture bytes, and the vendor ids.
 *
 * Computed the same way on both sides by the same function, on purpose. Two
 * implementations of "the same bytes" is two chances to disagree about a digest
 * for a reason that has nothing to do with the fixtures.
 *
 * @param {object} spec     the parsed spec.json
 * @param {string} specPath where it was read from
 * @param {string} fixturesRoot
 */
export function subjectOf(spec, specPath, fixturesRoot) {
  const fixtures = {};
  for (const prop of spec.properties) {
    for (const name of DIGESTED_FIXTURE_FILES) {
      fixtures[`${prop.fixtureId}/${name}`] = fileDigest(path.join(fixturesRoot, prop.fixtureId, name));
    }
  }
  return {
    specSha256: fileDigest(specPath),
    vendors: spec.vendors.map((v) => v.vendorId).slice().sort(),
    fixtures,
  };
}

/**
 * The receipt block `run-controls.mjs` embeds in its report.
 *
 * `pass` is not taken from the caller: it is recomputed here from the control
 * blocks, because a receipt whose verdict came from somewhere other than the
 * blocks it is a receipt FOR is the rubber stamp this file exists to remove.
 *
 * @param {object} subject  from subjectOf()
 * @param {Array<object>} controls  report.controls
 */
export function receiptOf(subject, controls) {
  const failed = controls.filter((c) => c.pass !== true).map((c) => `${c.propertyId}/${c.vendor}`);
  return {
    schemaVersion: RECEIPT_SCHEMA,
    // Recomputed, never copied.
    verdict: controls.length > 0 && failed.length === 0 ? ALL_PASSED : 'CONTROLS_FAILED',
    blocks: controls.length,
    failedBlocks: failed,
    subject,
    meaning:
      'run-second-vendor.mjs refuses to build the envelope unless this block says '
      + ALL_PASSED + ' over the same spec, the same vendors and the same fixture bytes it '
      + 'is about to measure. README.md said to run the controls first; until this block '
      + 'existed, nothing checked that anyone had.',
  };
}

/**
 * Why the envelope may not be built. Empty means it may.
 *
 * Every entry is a sentence a person can act on, and the codes are deliberately
 * separate words rather than one "controls failed": "nobody ran them", "they ran
 * and something failed" and "they ran on other bytes" are three different states
 * of the world and a caller that could not tell them apart would re-run the wrong
 * thing.
 *
 * @param {object|null} receipt  the `controlsReceipt` block, or null when absent
 * @param {object} subject       what this run is about to measure, from subjectOf()
 * @param {string} where         how the report was named, for the messages
 */
export function receiptProblems(receipt, subject, where) {
  if (receipt === null || receipt === undefined) {
    return [
      `no controls receipt at ${where}. README.md's script order is not a convention here: `
      + 'the 80-cell table is a table of PRESERVED and LOST verdicts, and a verdict from an '
      + 'oracle nobody demonstrated can report both is not evidence. Run `node run-controls.mjs` '
      + 'with the same --fixtures and --out first.',
    ];
  }
  const problems = [];
  if (receipt.schemaVersion !== RECEIPT_SCHEMA) {
    problems.push(
      `the controls receipt at ${where} declares schemaVersion ${JSON.stringify(receipt.schemaVersion)} `
      + `and this file reads ${RECEIPT_SCHEMA}. A receipt of an unknown shape is not read rather than `
      + 'read optimistically.');
    // Nothing below can be trusted to mean what it is named, so it is not looked at.
    return problems;
  }
  if (receipt.verdict !== ALL_PASSED) {
    const named = (receipt.failedBlocks || []).join(', ') || 'none named';
    problems.push(
      `the controls receipt at ${where} says ${JSON.stringify(receipt.verdict)} (failed: ${named}). `
      + 'A failed control block means the oracle could not be shown to distinguish present from '
      + 'absent for that vendor and property, and run-controls.mjs\'s own words are that the '
      + 'corresponding rows are not evidence. They are not worked around here either.');
  }
  if (!(receipt.blocks > 0)) {
    problems.push(
      `the controls receipt at ${where} reports ${receipt.blocks} control block(s). A receipt over `
      + 'no blocks is a receipt for nothing, and it is refused rather than counted as a pass -- the '
      + 'empty-set failure every check in this tree is written against.');
  }

  const got = receipt.subject || {};
  if (got.specSha256 !== subject.specSha256) {
    problems.push(
      `the controls ran against spec.json ${String(got.specSha256).slice(0, 12)} and this run reads `
      + `${String(subject.specSha256).slice(0, 12)}. The spec names the properties, the levels and the `
      + 'mitigations, so a receipt for a different one is a receipt about a different table.');
  }
  const wantVendors = (subject.vendors || []).join(',');
  const gotVendors = (got.vendors || []).join(',');
  if (gotVendors !== wantVendors) {
    problems.push(
      `the controls were demonstrated on vendor(s) [${gotVendors}] and this run measures [${wantVendors}]. `
      + 'run-controls.mjs\'s own header says an oracle validated on one vendor says nothing about the '
      + 'other, which is why it runs every control per vendor.');
  }
  const gotFix = got.fixtures || {};
  const keys = new Set([...Object.keys(gotFix), ...Object.keys(subject.fixtures)]);
  for (const k of [...keys].sort()) {
    const a = gotFix[k];
    const b = subject.fixtures[k];
    if (a === b) continue;
    if (b === null || b === undefined) {
      problems.push(`fixture ${k} was digested by the controls and is not readable now`);
    } else if (a === null || a === undefined) {
      problems.push(
        `fixture ${k} is about to be measured and the controls receipt does not cover it. A property `
        + 'whose oracle was never demonstrated contributes rows to the correspondence table that '
        + 'nothing stands behind.');
    } else {
      problems.push(
        `fixture ${k} has changed since the controls ran (${a.slice(0, 12)} -> ${b.slice(0, 12)}). The `
        + 'controls delete the defence by LINE NUMBER, so an edited fixture can move the anchor and '
        + 'leave a red demonstration that deleted something else -- re-run them.');
    }
  }
  return problems;
}

/**
 * Read the controls report and return its receipt block, or null.
 *
 * A report that cannot be parsed returns null with the reason, and the caller
 * reports that as "no receipt" rather than crashing: a malformed receipt and an
 * absent one both mean the controls have not been shown to have passed over these
 * bytes, and neither is a reason to proceed.
 */
export function readReceipt(outRoot) {
  const p = path.join(outRoot, CONTROLS_FILE);
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (err) {
    return { receipt: null, path: p, unreadable: err.code === 'ENOENT' ? null : String(err.message) };
  }
  return { receipt: doc.controlsReceipt ?? null, path: p, unreadable: null };
}
