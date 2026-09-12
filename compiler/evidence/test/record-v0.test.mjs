// evidence-v0, unchanged.
//
// WHY THIS FILE EXISTS AT ALL
//
//   `verifyRecord` and `verifyBundle` had no test in this directory before the
//   ledger was added. The README's "What has been measured" table records runs
//   against forty real records and against copied bundles, but those records
//   live outside the checkout and nothing in the suite exercised either
//   function. So "adding evidence-v1 changed nothing about evidence-v0" had
//   nothing to be held against, and this file is that something.
//
//   The fixtures under `testdata/bundles/v0-complete` and `testdata/records/`
//   were written first and run against the verifier as it stood BEFORE the
//   ledger existed; the exit codes and the `checked` / `unchecked` lists
//   asserted below are what that run printed, copied from its output rather
//   than predicted. The comparison is in the README under "Compatibility".
//
//   The assertion that matters most is that a v0 record produces no
//   ledger line and never lands on `unchecked` for a field its schema does not
//   have. Getting that wrong turns every record ever written into
//   VERIFICATION_INCOMPLETE, which is a true statement about nothing.
//
//   AND THE ONE THAT WAS MISSING. Four fixtures are four probes, not a proof
//   about a schema, and "evidence-v0 is unchanged" was asserted on those four.
//   A fifth — a bundle whose `manifest.json` holds the four bytes `null` — had
//   gone from VERIFICATION_INCOMPLETE / exit 3 to VERIFIED_CLEAN / exit 0 when
//   the manifest read was refactored, and nothing here noticed because nothing
//   here looked. The manifest-shape tests at the bottom of this file are that
//   fifth probe and the three shapes either side of it; they are the reason the
//   claim in the README is now a table of six shapes rather than a sentence.

import { strict as assert } from 'node:assert';
import { cpSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { cleanup, countingOf, EVIDENCE_DIR, makeScratch, run, VERIFY } from './helpers.mjs';

const TD = join(EVIDENCE_DIR, 'testdata');
const BUNDLE = join(TD, 'bundles', 'v0-complete');
const RECORDS = join(TD, 'records');

/** `--record --json`: stdout is the report, stderr carries the counting line. */
function record(file, extra = []) {
  const r = run(VERIFY, ['--record', file, '--json', ...extra]);
  return { ...r, report: JSON.parse(r.stdout) };
}

test('a complete v0 bundle still verifies clean and exits 0', () => {
  const r = run(VERIFY, ['--bundle', BUNDLE, '--json']);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  const [b] = JSON.parse(r.stdout);
  assert.equal(b.verdict, 'VERIFIED_CLEAN');
  assert.deepEqual(b.findings, []);
  assert.deepEqual(b.unchecked, []);
  assert.deepEqual(b.checked, [
    'evidenceDigest',
    'pathHygiene',
    'command.argv',
    'properties',
    'coverage',
    'artifact.sha256',
    'manifest.evidenceDigest',
  ]);
  assert.equal(b.ledger, undefined, 'a v0 bundle carries no ledger and must not grow one');
});

test('the counting line is unchanged for a v0 bundle', () => {
  // --json sends the counting line to stderr, and this suite's runner keeps
  // stderr only for a failing process, so the line is read from a plain run.
  const r = run(VERIFY, ['--bundle', BUNDLE]);
  assert.deepEqual(countingOf(r), { inputs: 1, checked: 1, skipped: 0 });
});

test('a complete v0 record still exits 0 with the same checked list', () => {
  const r = record(join(BUNDLE, 'evidence.json'));
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.checked, [
    'evidenceDigest',
    'pathHygiene',
    'command.argv',
    'properties',
    'coverage',
  ]);
  assert.deepEqual(r.report.unchecked, []);
  assert.deepEqual(r.report.findings, []);
});

test('a v0 record with a field nothing could check still exits 3', () => {
  const r = record(join(RECORDS, 'v0-unchecked.json'));
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.unchecked, ['coverage']);
  assert.deepEqual(r.report.findings, []);
});

test('a v0 record with a finding still exits 2 and still names VG-ART-053', () => {
  const r = record(join(RECORDS, 'v0-finding.json'));
  assert.equal(r.status, 2, `${r.stdout}${r.stderr}`);
  assert.deepEqual(
    r.report.findings.map((f) => f.id),
    ['VG-ART-053'],
  );
});

test('no v0 output mentions a ledger, in any mode', () => {
  const outputs = [
    run(VERIFY, ['--bundle', BUNDLE]),
    run(VERIFY, ['--record', join(BUNDLE, 'evidence.json')]),
    run(VERIFY, ['--record', join(RECORDS, 'v0-unchecked.json')]),
    run(VERIFY, ['--record', join(RECORDS, 'v0-finding.json')]),
  ];
  for (const o of outputs) {
    assert.ok(
      !/ledger/i.test(`${o.stdout}${o.stderr}`),
      `a v0 run mentioned a ledger:\n${o.stdout}${o.stderr}`,
    );
  }
});

test('a v0 record is not held to a declaration even when one is named', () => {
  // `--declared` names the accounts for a ledger. A v0 record has none, so the
  // flag is inert rather than retroactive: pointing it at a v0 record must not
  // conjure a check the schema never had.
  const r = record(join(BUNDLE, 'evidence.json'), [
    '--declared',
    join(TD, 'declarations', 'four-properties.json'),
  ]);
  assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  assert.deepEqual(r.report.findings, []);
  assert.equal(r.report.ledger, undefined);
});

test('a schema version this verifier does not know is still UNSUPPORTED, not clean', () => {
  // The version gate grew a second accepted value. It must not have become a
  // gate that accepts anything: an unknown version is UNSUPPORTED and exit 3,
  // exactly as it was when the list had one entry.
  //
  // This test was named for BOTH entry points and exercised only `--bundle`.
  // The `--record` half below is the half that was missing, and the check was
  // missing with it: `KNOWN_RECORD_VERSIONS` was consulted in `verifyBundle`
  // alone, so an unknown version reached `verifyRecord`, where `checkLedger`
  // returns null for anything that is not exactly `evidence-v1` — the ledger was
  // skipped with no finding, no `unchecked` entry, no `ledger:` line and exit 0.
  const dir = makeScratch('v0-unknown-version');
  try {
    const rec = JSON.parse(readFileSync(join(BUNDLE, 'evidence.json'), 'utf8'));
    rec.schemaVersion = 'evidence-v9';
    writeFileSync(join(dir, 'evidence.json'), `${JSON.stringify(rec, null, 2)}\n`, 'utf8');
    const r = run(VERIFY, ['--bundle', dir, '--json']);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    const [b] = JSON.parse(r.stdout);
    assert.equal(b.verdict, 'UNSUPPORTED');
    assert.match(b.error, /evidence-v0, evidence-v1/);

    const viaRecord = record(join(dir, 'evidence.json'));
    assert.equal(viaRecord.status, 3, `${viaRecord.stdout}${viaRecord.stderr}`);
    assert.equal(viaRecord.report.verdict, 'UNSUPPORTED');
    assert.match(viaRecord.report.error, /evidence-v0, evidence-v1/);
    assert.deepEqual(viaRecord.report.findings, []);
    assert.deepEqual(viaRecord.report.checked, []);
  } finally {
    cleanup(dir);
  }
});

test('a sealed record relabelled to an unknown version is UNSUPPORTED on both flags', () => {
  // `testdata/records/v2-relabelled.json` is `v1-unbalanced.json` — two cells in
  // no account, `VG-ART-064` twice, exit 2 — with `schemaVersion` changed to
  // `evidence-v2` and the record RESEALED, so its digest is right for its bytes
  // and every other check passes. Through `--record` it used to print
  // `checked: evidenceDigest, pathHygiene, command.argv, properties, coverage`,
  // no ledger line, no findings, and exit 0. A relabel is not a way to buy a
  // clean verdict over a ledger that does not balance.
  const file = join(RECORDS, 'v2-relabelled.json');
  const r = record(file);
  assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
  assert.equal(r.report.verdict, 'UNSUPPORTED');
  assert.match(r.report.error, /"evidence-v2" is not one of evidence-v0, evidence-v1/);
  assert.deepEqual(r.report.findings, []);
  assert.equal(r.report.ledger, undefined);

  const dir = makeScratch('v2-relabelled-bundle');
  try {
    cpSync(file, join(dir, 'evidence.json'));
    const b = run(VERIFY, ['--bundle', dir, '--json']);
    assert.equal(b.status, 3, `${b.stdout}${b.stderr}`);
    assert.equal(JSON.parse(b.stdout)[0].verdict, 'UNSUPPORTED');
  } finally {
    cleanup(dir);
  }
});

/** A scratch copy of the v0 bundle whose `manifest.json` holds exactly `bytes`, or none. */
function bundleWithManifest(label, bytes) {
  const dir = makeScratch(label);
  cpSync(BUNDLE, dir, { recursive: true });
  if (bytes === null) rmSync(join(dir, 'manifest.json'));
  else writeFileSync(join(dir, 'manifest.json'), bytes, 'utf8');
  return dir;
}

test('a manifest.json that is not a JSON object is UNCHECKED, never silently clean', () => {
  // THE REGRESSION THIS PINS, and the reason this file's claim that v0 was
  // untouched had to be measured past its four fixtures. The manifest used to be
  // read inside one `try` that also held `man.evidenceDigest`, so a manifest.json
  // holding the four bytes `null` threw on the property access and landed on
  // `unchecked` — VERIFICATION_INCOMPLETE, exit 3. Reading the manifest once, so
  // that a `declares` block could reach the ledger, moved the access out of the
  // `try` and guarded it with `manifest !== null`; the same bundle then answered
  // VERIFIED_CLEAN and exit 0. A cross-check nobody performed was reported as one
  // that passed, which is the one conflation these exit codes exist to prevent.
  //
  // The guard is now on the SHAPE and not on which line happens to throw, so
  // `[]`, `"x"` and `3` answer the way `null` does. Those three were silently
  // clean before the change as well; widening to them is deliberate, and it is
  // in the only direction this component moves — toward "nobody checked this",
  // never away from it.
  for (const bytes of ['null', '[]', '"x"', '3']) {
    const dir = bundleWithManifest('v0-manifest-shape', bytes);
    try {
      const r = run(VERIFY, ['--bundle', dir, '--json']);
      assert.equal(r.status, 3, `manifest.json = ${bytes}: ${r.stdout}${r.stderr}`);
      const [b] = JSON.parse(r.stdout);
      assert.equal(b.verdict, 'VERIFICATION_INCOMPLETE', `manifest.json = ${bytes}`);
      assert.deepEqual(b.findings, [], `manifest.json = ${bytes}`);
      assert.ok(b.unchecked.includes('manifest.json'), `unchecked: ${b.unchecked.join(', ')}`);
      assert.ok(!b.checked.includes('manifest.evidenceDigest'), `checked: ${b.checked.join(', ')}`);
    } finally {
      cleanup(dir);
    }
  }
});

test('a manifest that names no evidenceDigest is unchecked for it; an absent manifest is not', () => {
  // Two different things, answering differently on purpose. A manifest that is
  // THERE and carries no `evidenceDigest` is a field of a document the bundle
  // has: nobody compared it, so it is UNCHECKED. Leaving it silent would let a
  // producer buy the clean verdict that a wrong digest costs by deleting one
  // line. A bundle with NO manifest.json has no such document — the same
  // distinction the ledger draws between a v1 record with no `ledger` block and
  // a v0 record, which has no such field at all.
  const withEmpty = bundleWithManifest('v0-manifest-nodigest', '{"schemaVersion":"evidence-bundle-v0"}\n');
  try {
    const r = run(VERIFY, ['--bundle', withEmpty, '--json']);
    assert.equal(r.status, 3, `${r.stdout}${r.stderr}`);
    const [b] = JSON.parse(r.stdout);
    assert.equal(b.verdict, 'VERIFICATION_INCOMPLETE');
    assert.deepEqual(b.unchecked, ['manifest.evidenceDigest']);
    assert.deepEqual(b.findings, []);
  } finally {
    cleanup(withEmpty);
  }
  const without = bundleWithManifest('v0-manifest-absent', null);
  try {
    const r = run(VERIFY, ['--bundle', without, '--json']);
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
    const [b] = JSON.parse(r.stdout);
    assert.equal(b.verdict, 'VERIFIED_CLEAN');
    assert.deepEqual(b.unchecked, []);
  } finally {
    cleanup(without);
  }
});
