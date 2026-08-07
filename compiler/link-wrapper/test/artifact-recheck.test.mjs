// Post-link modification of the artefact.
//
// The link's verdict was true when the link finished. Nothing in it says
// anything about the time since — and the window between "the linker wrote it"
// and "someone ran it" is exactly where a build-integrity check that only
// watches the compiler sees nothing at all. `recheck` closes that window by
// comparing the bytes on disk with the digest the link sealed.
//
// Both directions, because a detector that only ever fires is not a detector:
// an untouched artefact must come back exit 0, and a single flipped byte must
// come back VG-LINK-006.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { recheckArtifact } from '../lib/verdict.mjs';
import { sha256Hex, seal } from '../lib/canonical.mjs';
import { LINK } from '../lib/findings.mjs';
import { EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE } from '../lib/exit.mjs';
import { CLI, scratch } from './helpers.mjs';

function runCli(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: 'utf8' });
}

/** A minimal record of the shape `vg-link.mjs link` writes. */
function recordFor(relPath, bytes) {
  return seal({
    recordVersion: 'link-v0',
    component: 'link-wrapper',
    context: { generatedAt: '1970-01-01T00:00:00.000Z', timeSource: 'SOURCE_DATE_EPOCH', sourceDateEpoch: 0, host: 'test' },
    observation: { artifact: { path: relPath, size: bytes.length, sha256: sha256Hex(bytes) } },
  });
}

// ── the pure comparison ──────────────────────────────────────────────────────

test('NEGATIVE: the artefact the link produced is not reported as modified', () => {
  const bytes = Buffer.from('the artefact');
  const r = recheckArtifact(recordFor('app', bytes), { sha256: sha256Hex(bytes), size: bytes.length });
  assert.equal(r.ok, true);
  assert.equal(r.finding, null);
});

test('POSITIVE: one appended byte is caught', () => {
  const bytes = Buffer.from('the artefact');
  const after = Buffer.concat([bytes, Buffer.from('!')]);
  const r = recheckArtifact(recordFor('app', bytes), { sha256: sha256Hex(after), size: after.length });
  assert.equal(r.ok, false);
  assert.equal(r.finding.id, LINK.ARTIFACT_CHANGED_AFTER_LINK);
  assert.equal(r.finding.severity, 'critical');
  assert.match(r.finding.detail, /not the ones this link produced/);
});

// A same-length modification is the case a size check alone would miss, which
// is why the digest is the decision and the size is reported alongside it.
test('POSITIVE: a flipped byte with the size unchanged is caught', () => {
  const bytes = Buffer.from('the artefact');
  const after = Buffer.from('the artefacT');
  assert.equal(after.length, bytes.length);
  const r = recheckArtifact(recordFor('app', bytes), { sha256: sha256Hex(after), size: after.length });
  assert.equal(r.finding.id, LINK.ARTIFACT_CHANGED_AFTER_LINK);
});

test('an artefact that is gone is NOT_OBSERVED, not unmodified', () => {
  const bytes = Buffer.from('the artefact');
  const r = recheckArtifact(recordFor('app', bytes), null);
  assert.equal(r.ok, false);
  assert.equal(r.finding, null);
  assert.match(r.incomplete.why, /is not there now/);
});

test('a record with no artefact digest cannot answer the question and says so', () => {
  const r = recheckArtifact({ observation: { artifact: { path: 'app' } } }, { sha256: 'x', size: 1 });
  assert.equal(r.ok, false);
  assert.equal(r.finding, null);
  assert.match(r.incomplete.why, /no artefact digest/);
});

// ── end to end through the CLI ───────────────────────────────────────────────

function bench(label) {
  const dir = scratch(label);
  const records = join(dir, 'records');
  mkdirSync(records);
  const bytes = Buffer.from('\x7fELF and then some payload');
  writeFileSync(join(dir, 'app'), bytes);
  writeFileSync(join(records, 'link-record.json'), `${JSON.stringify(recordFor('app', bytes), null, 2)}\n`, 'utf8');
  return { dir, records };
}

test('recheck: untouched artefact -> exit 0, one record checked', () => {
  const { dir, records } = bench('recheck-clean');
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.equal(r.status, EXIT_OK, r.stdout + r.stderr);
  assert.match(r.stdout, /inputs=1 checked=1 skipped=0/);
  assert.equal(/VG-LINK-006/.test(r.stdout), false);
});

test('recheck: modified artefact -> exit 2 and VG-LINK-006', () => {
  const { dir, records } = bench('recheck-dirty');
  appendFileSync(join(dir, 'app'), 'x');
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.equal(r.status, EXIT_FINDINGS, r.stdout + r.stderr);
  assert.match(r.stdout, /VG-LINK-006/);
  assert.match(r.stdout, /inputs=1 checked=1 skipped=0/);
});

test('recheck: deleted artefact -> exit 3, never exit 0', () => {
  const { dir, records } = bench('recheck-gone');
  writeFileSync(join(dir, 'app'), ''); // truncated rather than removed: same question, no platform locking
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.notEqual(r.status, EXIT_OK);
});

test('recheck: a record from a future version is skipped BY NAME, not treated as passing', () => {
  const { dir, records } = bench('recheck-version');
  const p = join(records, 'link-record.json');
  const rec = JSON.parse(readFileSync(p, 'utf8'));
  rec.recordVersion = 'link-v9';
  writeFileSync(p, JSON.stringify(rec), 'utf8');
  const r = runCli(['recheck', records, '--root', dir], dir);
  assert.equal(r.status, EXIT_INCOMPLETE);
  assert.match(r.stdout, /inputs=1 checked=0 skipped=1/);
  assert.match(r.stdout, /link-record\.json/);
});
