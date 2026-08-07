import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import { rederiveDigest, sha256Hex } from '../src/rederive.mjs';
import { VERDICT, verifyBundle } from '../src/verify-bundle.mjs';
import { buildFixtureBundle, demoRecord } from './_fixture.mjs';

/** Build a bundle whose single property has the given state history. */
function withStates(states, prefix) {
  const record = demoRecord();
  record.properties[0].states = states;
  record.coverage = {
    observed: states.filter((s) => s.verdict !== 'UNOBSERVED').length,
    planned: states.length,
  };
  return buildFixtureBundle({ prefix, record });
}

const ok = (checkpoint, state, effect, control) => ({
  checkpoint,
  state,
  verdict: state === 'PRESENT' || state === 'REINTRODUCED' ? 'PRESENT' : 'ABSENT',
  effect,
  control,
});

// ── The oracle rule ─────────────────────────────────────────────────────────
//
// A control that fell to zero means the harness measured nothing. Reporting the
// subject from such a run is how a loss that never happened acquires a
// plausible story, so the verifier refuses to read the run at all.
//
// The generator refuses to SEAL such a record, so these fixtures have to be
// written past it — which is the realistic case anyway: a bundle arriving from
// somewhere else was not sealed by this generator.

test('a control count of zero is a finding, not a loss', () => {
  const record = demoRecord();
  record.properties[0].states = [ok('ir-pre', 'PRESENT', 1, 1), ok('ir-post', 'LOST', 0, 1)];
  const built = buildFixtureBundle({ prefix: 'eca-ctl-', record });
  try {
    // Rewrite the sealed record on disk and re-seal both digests, so the ONLY
    // thing wrong with the bundle is the measurement itself.
    reseal(built.bundleDir, (r) => {
      r.properties[0].states[1].control = 0;
    });
    const result = verifyBundle(built.bundleDir);
    const ids = result.findings.map((f) => f.id);
    assert.deepEqual(ids, ['VG-ART-088'], ids.join(','));
    assert.equal(result.verdict, VERDICT.FINDINGS);
  } finally {
    built.scratch.dispose();
  }
});

test('a verdict that disagrees with its count on zero-versus-nonzero is a finding', () => {
  const built = withStates([ok('ir-pre', 'PRESENT', 1, 1), ok('ir-post', 'LOST', 0, 1)], 'eca-zvn-');
  try {
    reseal(built.bundleDir, (r) => {
      r.properties[0].states[0].effect = 0; // PRESENT with nothing measured
    });
    const ids = verifyBundle(built.bundleDir).findings.map((f) => f.id);
    assert.deepEqual(ids, ['VG-ART-089'], ids.join(','));
  } finally {
    built.scratch.dispose();
  }
});

test('the measured shape is NOT flagged: control nonzero, subject nonzero to zero', () => {
  // Measured on a fresh fixture: -O0 gives 2 call sites of the zeroing
  // instruction, -O2 gives 1 because the CONTROL function keeps its store.
  const built = withStates(
    [ok('ir-pre', 'PRESENT', 2, 1), ok('ir-post', 'LOST', 0, 1)],
    'eca-measured-',
  );
  try {
    const result = verifyBundle(built.bundleDir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.verdict, VERDICT.CLEAN);
    assert.ok(result.checked.includes('oracle.controls'));
  } finally {
    built.scratch.dispose();
  }
});

test('a state entry with no counts is unchecked, never clean', () => {
  const built = buildFixtureBundle({ prefix: 'eca-nocount-' });
  try {
    reseal(built.bundleDir, (r) => {
      delete r.properties[0].states[0].effect;
      delete r.properties[0].states[0].control;
    });
    const result = verifyBundle(built.bundleDir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.verdict, VERDICT.INCOMPLETE);
    assert.ok(result.unchecked.some((u) => u.endsWith('.oracle')), result.unchecked.join(','));
  } finally {
    built.scratch.dispose();
  }
});

// ── The state vocabulary and the whole sequence ─────────────────────────────

test('a state outside the six-state vocabulary is a finding', () => {
  const built = buildFixtureBundle({ prefix: 'eca-vocab-' });
  try {
    reseal(built.bundleDir, (r) => {
      r.properties[0].states[1].state = 'PROBABLY_GONE';
    });
    const ids = verifyBundle(built.bundleDir).findings.map((f) => f.id);
    assert.ok(ids.includes('VG-ART-090'), ids.join(','));
  } finally {
    built.scratch.dispose();
  }
});

test('REINTRODUCED with no preceding loss is a finding', () => {
  const built = buildFixtureBundle({ prefix: 'eca-reintro-bad-' });
  try {
    reseal(built.bundleDir, (r) => {
      r.properties[0].states = [
        { checkpoint: 'ir-pre', verdict: 'PRESENT', state: 'PRESENT', effect: 1, control: 1 },
        { checkpoint: 'ir-post', verdict: 'PRESENT', state: 'REINTRODUCED', effect: 1, control: 1 },
      ];
    });
    const ids = verifyBundle(built.bundleDir).findings.map((f) => f.id);
    assert.deepEqual(ids, ['VG-ART-091'], ids.join(','));
  } finally {
    built.scratch.dispose();
  }
});

test('a full PRESENT / LOST / REINTRODUCED / LOST history is accepted whole', () => {
  // The rule the naive implementation breaks: keep the WHOLE sequence. A
  // verifier that stopped at the first loss would either miss the second one or
  // mis-read the reintroduction as an inconsistency.
  const built = withStates(
    [
      ok('ir-pre', 'PRESENT', 2, 2),
      ok('ir-post', 'LOST', 0, 2),
      ok('asm', 'REINTRODUCED', 1, 2),
      ok('artifact', 'LOST', 0, 2),
    ],
    'eca-full-history-',
  );
  try {
    const result = verifyBundle(built.bundleDir);
    assert.deepEqual(result.findings, []);
    assert.equal(result.verdict, VERDICT.CLEAN);
  } finally {
    built.scratch.dispose();
  }
});

/**
 * Edit a sealed record in place and re-seal the record digest and the manifest
 * around it, so the only defect in the bundle is the one the test introduced.
 */
function reseal(bundleDir, mutate) {
  const recordPath = join(bundleDir, 'evidence.json');
  const record = JSON.parse(readFileSync(recordPath, 'utf8'));
  mutate(record);
  delete record.evidenceDigest;
  record.evidenceDigest = rederiveDigest(record);
  writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`, 'utf8');

  const manifestPath = join(bundleDir, 'manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  for (const entry of manifest.files) {
    const bytes = readFileSync(join(bundleDir, entry.path));
    entry.bytes = bytes.length;
    entry.sha256 = sha256Hex(bytes);
  }
  manifest.evidenceDigest = record.evidenceDigest;
  manifest.binds.evidenceDigest = record.evidenceDigest;
  delete manifest.bundleDigest;
  manifest.bundleDigest = rederiveDigest(manifest, { selfKey: 'bundleDigest' });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
}
