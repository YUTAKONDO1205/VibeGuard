// Policy -> findings -> exit code.

import test from 'node:test';
import assert from 'node:assert/strict';

import { readElf } from '../src/elf.mjs';
import { STATE } from '../src/properties.mjs';
import {
  observe, verifyArtifact, exitCodeFor, ART, SEVERITY,
  EXIT_OK, EXIT_FINDINGS, EXIT_INCOMPLETE,
} from '../src/verify.mjs';
import { RECIPES, buildElf } from './synth-elf.mjs';

const FULL = ['pie', 'nx', 'relro-full', 'stack-protector', 'fortify', 'build-id',
  'no-writable-executable-section', 'no-debug-path'];

const of = (name) => readElf(RECIPES[name](), { path: name });

test('the finding ids are the reserved namespace and nothing else', () => {
  for (const id of Object.values(ART)) assert.match(id, /^VG-ART-0\d\d$/);
  assert.equal(ART.FORBIDDEN_STRING, 'VG-ART-005',
    'policy.schema.json pins artifact.forbidStrings to VG-ART-005; this is not a free choice');
  assert.equal(Object.keys(SEVERITY).length, Object.keys(ART).length);
  for (const id of Object.values(ART)) {
    assert.ok(['low', 'medium', 'high', 'critical'].includes(SEVERITY[id]), id);
  }
});

test('VG-ART-001 is not emitted here: the digest-mismatch id is owned elsewhere', () => {
  assert.equal(Object.values(ART).includes('VG-ART-001'), false);
  assert.equal(Object.values(ART).includes('VG-ART-002'), false);
});

// ── the clean direction ─────────────────────────────────────────────────────

test('the hardened artefact produces no findings and exits 0', () => {
  const r = verifyArtifact(of('hardened'), {
    require: FULL,
    forbidStrings: ['AKIA', 'BEGIN PRIVATE KEY'],
    expectStrings: ['artefact-integrity-control-string'],
  });
  assert.deepEqual(r.findings, [], JSON.stringify(r.findings, null, 1));
  assert.deepEqual(r.incomplete, []);
  assert.equal(exitCodeFor(r), EXIT_OK);
});

// ── the finding direction ───────────────────────────────────────────────────

test('every absent hardening property produces one VG-ART-003', () => {
  const r = verifyArtifact(of('unhardened'), { require: FULL, expectStrings: [] });
  const hardening = r.findings.filter((f) => f.id === ART.HARDENING_ABSENT);
  assert.deepEqual(
    hardening.map((f) => f.where.unit).sort(),
    ['build-id', 'fortify', 'nx', 'pie', 'relro-full', 'stack-protector'],
  );
  for (const f of hardening) {
    assert.equal(f.severity, 'high');
    assert.equal(f.where.kind, 'artifact');
    assert.ok(f.detail.length > 20, 'a finding must carry the fields that decided it');
  }
  assert.equal(exitCodeFor(r), EXIT_FINDINGS);
});

test('a W+X section is VG-ART-004 and critical', () => {
  const r = verifyArtifact(of('wx-section'), { require: ['no-writable-executable-section'] });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].id, ART.WRITABLE_EXECUTABLE);
  assert.equal(r.findings[0].severity, 'critical');
  assert.match(r.findings[0].detail, /\.vgwx/);
  assert.match(r.findings[0].detail, /SHF_WRITE/);
});

test('a W+X segment is VG-ART-004 even with no W+X section', () => {
  const r = verifyArtifact(of('wx-segment'), { require: ['no-writable-executable-section'] });
  assert.equal(r.findings.length, 1);
  assert.match(r.findings[0].detail, /PF_W\|PF_X/);
});

test('a forbidden literal is VG-ART-005, one finding per occurrence, with the section', () => {
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], rodata: 'ctl\0AKIAIOSFODNN7EXAMPLE\0more\0AKIAIOSFODNN7EXAMPLE\0',
  }), { path: 'secret' });
  const r = verifyArtifact(elf, { forbidStrings: ['AKIAIOSFODNN7EXAMPLE'], expectStrings: ['ctl'] });
  assert.equal(r.findings.length, 2);
  for (const f of r.findings) {
    assert.equal(f.id, ART.FORBIDDEN_STRING);
    assert.equal(f.severity, 'critical');
    assert.match(f.detail, /\.rodata/);
  }
});

test('a build-host path is VG-ART-006', () => {
  const SEP = String.fromCharCode(47);
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], debugSections: ['.debug_line_str'],
    debugPayload: `${SEP}h${'ome'}${SEP}somebody${SEP}proj`,
  }), { path: 'dbg' });
  const r = verifyArtifact(elf, { require: ['no-debug-path'] });
  assert.ok(r.findings.length >= 1);
  assert.equal(r.findings[0].id, ART.BUILD_PATH_RESIDUE);
  assert.equal(r.findings[0].severity, 'medium');
  assert.equal(r.findings[0].detail.includes('somebody'), false, 'the report must redact the path it found');
});

test('debug sections with no absolute path are still VG-ART-006', () => {
  const elf = readElf(buildElf({
    form: 'exec-pie', gnuStackFlags: 6, dtFlags: 0x8, dtFlags1: 0x8000001,
    undefinedSymbols: ['puts'], debugSections: ['.debug_info'], debugPayload: 'no paths in here',
  }), { path: 'dbg2' });
  const r = verifyArtifact(elf, { require: ['no-debug-path'] });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].id, ART.BUILD_PATH_RESIDUE);
  assert.match(r.findings[0].detail, /debug section/);
});

test('a release build is not flagged for debug residue — the negative direction', () => {
  const r = verifyArtifact(of('hardened'), { require: ['no-debug-path'] });
  assert.deepEqual(r.findings, []);
});

test('an unauthorised DT_NEEDED and a baked-in search path are VG-ART-007', () => {
  const r = verifyArtifact(of('rpath'), { allowedDynamicDependencies: ['libc.so.6'] });
  const ids = r.findings.map((f) => f.id);
  assert.deepEqual(ids, [ART.UNAUTHORISED_DEPENDENCY]);
  assert.match(r.findings[0].detail, /DT_RUNPATH/);

  const r2 = verifyArtifact(of('hardened'), { allowedDynamicDependencies: [] });
  assert.equal(r2.findings.length, 1);
  assert.match(r2.findings[0].detail, /libc\.so\.6/);
});

test('an authorised dependency list that matches produces nothing', () => {
  const r = verifyArtifact(of('hardened'), { allowedDynamicDependencies: ['libc.so.6'] });
  assert.deepEqual(r.findings, []);
});

// ── incompleteness ──────────────────────────────────────────────────────────

test('NOT_OBSERVED is exit 3, and no finding is invented for it', () => {
  const r = verifyArtifact(of('static-hardened'), { require: ['stack-protector', 'fortify'] });
  assert.deepEqual(r.findings, [], 'a property that could not be observed must not become a finding');
  assert.equal(r.notObserved.length, 2);
  assert.equal(exitCodeFor(r), EXIT_INCOMPLETE);
  assert.notEqual(exitCodeFor(r), EXIT_OK);
});

test('a missing residue control makes the scan INCOMPLETE and suppresses the clean claim', () => {
  const r = verifyArtifact(of('hardened'), {
    forbidStrings: ['AKIA'],
    expectStrings: ['a-control-string-this-artefact-does-not-contain'],
  });
  assert.deepEqual(r.findings, []);
  assert.equal(r.incomplete.length, 1);
  assert.match(r.incomplete[0], /control string/);
  assert.equal(r.observation.forbiddenHits, null, 'the forbidden scan must not report 0 when its control failed');
  assert.equal(exitCodeFor(r), EXIT_INCOMPLETE);
});

test('a policy naming an unknown property is INCOMPLETE, not silently ignored', () => {
  const r = verifyArtifact(of('hardened'), { require: ['cfi', 'shadow-stack'] });
  assert.equal(r.incomplete.length, 2);
  assert.equal(exitCodeFor(r), EXIT_INCOMPLETE);
});

test('NOT_APPLICABLE is not a finding and not incompleteness', () => {
  const r = verifyArtifact(of('shared-object'), { require: ['pie'] });
  assert.deepEqual(r.findings, []);
  assert.deepEqual(r.incomplete, []);
  assert.equal(exitCodeFor(r), EXIT_OK);
});

test('findings outrank incompleteness, but 3 is never collapsed into 0', () => {
  const both = { findings: [{ severity: 'critical' }], incomplete: ['x'] };
  assert.equal(exitCodeFor(both), EXIT_FINDINGS);
  assert.equal(exitCodeFor({ findings: [], incomplete: ['x'] }), EXIT_INCOMPLETE);
  assert.equal(exitCodeFor({ findings: [], incomplete: [] }), EXIT_OK);
});

test('--fail-on filters by severity without hiding the finding from the record', () => {
  const r = verifyArtifact(of('unhardened'), { require: ['no-debug-path'] });
  assert.ok(r.findings.length > 0);
  assert.equal(exitCodeFor(r, 'medium'), EXIT_FINDINGS);
  assert.equal(exitCodeFor(r, 'critical'), EXIT_OK);
});

// ── the observation record ──────────────────────────────────────────────────

test('the observation carries everything the brief asks a verifier to report', () => {
  const o = observe(of('hardened'));
  for (const key of [
    'sha256', 'sections', 'executableSections', 'writableExecutable', 'symbolCounts',
    'imports', 'exports', 'dynamicDependencies', 'runPaths', 'notes', 'buildId',
    'initFunctions', 'debugSections', 'stringCount', 'properties', 'linkForm',
  ]) {
    assert.ok(key in o, `the observation is missing ${key}`);
  }
  assert.equal(o.sha256.length, 64);
  assert.ok(o.executableSections.includes('.text'));
  assert.ok(o.imports.includes('__stack_chk_fail'));
  assert.ok(o.stringCount > 0);
});

test('the observation reports the states with the interfaces.md vocabulary', () => {
  const o = observe(of('static-hardened'));
  const allowed = new Set(Object.values(STATE));
  for (const rec of Object.values(o.properties)) assert.ok(allowed.has(rec.state));
  assert.equal(o.properties['stack-protector'].state, STATE.NOT_OBSERVED);
});
