// (A) The measurement record store: where it may live, and what a record must
// carry to be one.
//
// Every detector gets a positive fixture AND a negative one. A detector tested
// in one direction only is a false-positive factory: it can be satisfied by a
// function that returns a finding for every input, and nothing in a
// one-directional suite would notice.

import { strict as assert } from 'node:assert';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import {
  comparePair,
  listRecordFiles,
  MEASUREMENT_SCHEMA,
  REPO_ROOT,
  reproducibleCore,
  resolveStoreRoot,
  STORE_ENV,
  validateRecord,
  validateStore,
} from '../store.mjs';
import { classifyMachineIdentity, findMachineIdentity } from '../machine.mjs';
import { cleanup, goodRecord, linkDir, makeScratch, putRecord } from './helpers.mjs';

const IDENTITY = { hostname: 'a-machine-name', account: 'a-person' };

/** Re-seal after a mutation so that only the intended check is the one failing. */
async function mutated(mutate, { reseal = true } = {}) {
  const { sealRecord } = await import('../canon.mjs');
  const base = await goodRecord();
  const copy = JSON.parse(JSON.stringify(base));
  mutate(copy);
  if (!reseal) return copy;
  delete copy.evidenceDigest;
  return sealRecord(copy, { context: copy.context });
}

const check = (rec) => validateRecord(rec, { path: 'fixture.json', identity: IDENTITY, shapeHits: [] });
const ids = (r) => r.findings.map((f) => f.id);

// ── Where the store lives ───────────────────────────────────────────────────

test('the store root comes from the flag, then the environment, then the default', () => {
  assert.equal(resolveStoreRoot({ cli: 'X:/given', env: {} }).source, 'flag');
  assert.equal(resolveStoreRoot({ cli: null, env: { [STORE_ENV]: 'X:/from-env' } }).source, 'env');
  assert.equal(resolveStoreRoot({ cli: null, env: {} }).source, 'default');
  assert.equal(resolveStoreRoot({ cli: null, env: { [STORE_ENV]: '   ' } }).source, 'default');
});

test('the default store root is outside the checkout', () => {
  const r = resolveStoreRoot({ cli: null, env: {} });
  assert.equal(r.insideWorkTree, false, `the default ${r.root} is inside ${REPO_ROOT}`);
});

test('a store inside the checkout is refused, and one outside it is not', () => {
  const inside = validateStore(join(REPO_ROOT, 'compiler', 'evidence'), { delegate: false });
  assert.ok(inside.findings.some((f) => f.id === 'VG-ART-070'), `expected VG-ART-070, got ${inside.findings.map((f) => f.id)}`);
  assert.equal(inside.inputs, 0);

  const dir = makeScratch('store-outside');
  try {
    const outside = validateStore(dir, { delegate: false });
    assert.equal(outside.findings.filter((f) => f.id === 'VG-ART-070').length, 0);
  } finally {
    cleanup(dir);
  }
});

// ── The record's required fields, both directions ───────────────────────────

test('a good record produces no finding at all', async () => {
  const r = check(await goodRecord());
  assert.deepEqual(ids(r), [], JSON.stringify(r.findings, null, 2));
  assert.ok(r.checked.includes('provenance.gitSha'));
  assert.ok(r.checked.includes('toolchain'));
  assert.deepEqual(r.unchecked, []);
});

test('a missing gitSha is caught; a real one is not', async () => {
  assert.ok(ids(check(await mutated((r) => { delete r.provenance.gitSha; }))).includes('VG-ART-072'));
  assert.ok(ids(check(await mutated((r) => { r.provenance.gitSha = 'not-a-sha'; }))).includes('VG-ART-072'));
  assert.ok(ids(check(await mutated((r) => { r.provenance.gitSha = 'A'.repeat(40); }))).includes('VG-ART-072'));
  assert.deepEqual(ids(check(await mutated((r) => { r.provenance.gitSha = 'abcdef0123456789'.padEnd(40, '0'); }))), []);
});

test('the dirty-tree flag must be present, and a dirty tree must pin its diff', async () => {
  assert.ok(ids(check(await mutated((r) => { delete r.provenance.dirty; }))).includes('VG-ART-073'));
  assert.ok(ids(check(await mutated((r) => { r.provenance.dirty = 'yes'; }))).includes('VG-ART-073'));
  assert.ok(ids(check(await mutated((r) => { r.provenance.dirty = true; r.provenance.diffSha256 = null; }))).includes('VG-ART-073'));
  // Both legitimate shapes stay silent.
  assert.deepEqual(ids(check(await mutated((r) => { r.provenance.dirty = true; r.provenance.diffSha256 = 'a'.repeat(64); }))), []);
  assert.deepEqual(ids(check(await mutated((r) => { r.provenance.dirty = false; }))), []);
});

test('a toolchain entry needs a version and the digest of the binary', async () => {
  assert.ok(ids(check(await mutated((r) => { r.toolchain = []; }))).includes('VG-ART-074'));
  assert.ok(ids(check(await mutated((r) => { delete r.toolchain[0].version; }))).includes('VG-ART-074'));
  assert.ok(ids(check(await mutated((r) => { delete r.toolchain[0].sha256; }))).includes('VG-ART-074'));
  assert.ok(ids(check(await mutated((r) => { r.toolchain[0].sha256 = 'short'; }))).includes('VG-ART-074'));
  assert.deepEqual(ids(check(await mutated((r) => { r.toolchain.push({ name: 'ld', version: '18.1.3', sha256: '2'.repeat(64) }); }))), []);
});

test('the oracle must count a call site, not a symbol name', async () => {
  assert.ok(ids(check(await mutated((r) => { r.oracle = { kind: 'symbol-name', pattern: 'llvm.memset' }; }))).includes('VG-ART-077'));
  assert.ok(ids(check(await mutated((r) => { r.oracle = { kind: 'call-site', pattern: 'llvm.memset' }; }))).includes('VG-ART-077'));
  assert.ok(ids(check(await mutated((r) => { delete r.oracle; }))).includes('VG-ART-077'));
  assert.deepEqual(ids(check(await mutated((r) => { r.oracle = { kind: 'call-site', pattern: 'call void @llvm.memset.p0.i64' }; }))), []);
});

test('every observation needs a control that survived', async () => {
  assert.ok(ids(check(await mutated((r) => { r.observations = []; }))).includes('VG-ART-079'));
  assert.ok(ids(check(await mutated((r) => { r.observations[1].control = 0; }))).includes('VG-ART-079'));
  assert.ok(ids(check(await mutated((r) => { delete r.observations[0].control; }))).includes('VG-ART-079'));
  assert.ok(ids(check(await mutated((r) => { r.observations[0].subject = -1; }))).includes('VG-ART-079'));
  // The 0-vs-nonzero shape the oracle rule asks for: subject gone at O2, control kept.
  assert.deepEqual(
    ids(check(await mutated((r) => { r.observations = [{ config: 'O0', subject: 1, control: 1 }, { config: 'O2', subject: 0, control: 1 }]; }))),
    [],
  );
});

test('a record must say which re-run pair it belongs to', async () => {
  assert.ok(ids(check(await mutated((r) => { delete r.reproduction; }))).includes('VG-ART-078'));
  assert.ok(ids(check(await mutated((r) => { r.reproduction = { pairId: 'p', run: 3 }; }))).includes('VG-ART-078'));
  assert.deepEqual(ids(check(await mutated((r) => { r.reproduction = { pairId: 'p', run: 2 }; }))), []);
});

test('a broken seal is caught, and re-sealing clears it', async () => {
  const tampered = await mutated((r) => { r.recordId = 'edited-after-sealing'; }, { reseal: false });
  assert.ok(ids(check(tampered)).includes('VG-ART-050'));
  assert.deepEqual(ids(check(await mutated((r) => { r.recordId = 'edited-then-resealed'; }))), []);
});

test('a record of the wrong schema is reported once and not analysed further', async () => {
  const r = check(await mutated((r2) => { r2.schemaVersion = 'evidence-v0'; }));
  assert.deepEqual(ids(r), ['VG-ART-072']);
  assert.deepEqual(r.unchecked, ['*']);
});

// ── Machine identity ────────────────────────────────────────────────────────

test('an absolute path is caught by the existing gate', async () => {
  const r = check(await mutated((rec) => { rec.toolchain[0].path = '/usr/lib/llvm-18/bin/clang-18'; }, { reseal: false }));
  assert.ok(ids(r).includes('VG-ART-051'));
});

test('a home path with the leading slash stripped is still caught', async () => {
  // This is the gap the absolute-path gate leaves on purpose: the convention
  // here strips the leading slash, and `home/<name>/…` is not an absolute path.
  const r = check(await mutated((rec) => { rec.toolchain[0].path = 'home/a-person/bin/cc'; }));
  assert.ok(ids(r).includes('VG-ART-075'), JSON.stringify(r.findings));
});

test('a role account in the same shape is not reported as a person', async () => {
  for (const who of ['runner', 'root', 'ubuntu', 'ci']) {
    const r = check(await mutated((rec) => { rec.toolchain[0].path = `home/${who}/bin/cc`; }));
    assert.deepEqual(ids(r), [], `home/${who} was flagged`);
  }
});

test("this machine's hostname and account are looked for by value", () => {
  assert.equal(classifyMachineIdentity('built on a-machine-name today', { identity: IDENTITY })[0].kind, 'hostname-of-this-machine');
  assert.equal(classifyMachineIdentity('/data/a-person/out', { identity: IDENTITY })[0].kind, 'account-of-this-machine');
  assert.deepEqual(classifyMachineIdentity('built on some-other-box', { identity: IDENTITY }), []);
});

test('a user@host token is machine identity whatever the names are', () => {
  const hits = classifyMachineIdentity('scp nobody-here@build-42.example.net:/x', { identity: { hostname: null, account: null } });
  assert.ok(hits.some((h) => h.kind === 'user-at-host'), JSON.stringify(hits));
  assert.deepEqual(classifyMachineIdentity('clang version 18.1.3', { identity: { hostname: null, account: null } }), []);
  assert.deepEqual(classifyMachineIdentity('call void @llvm.memset.p0.i64', { identity: { hostname: null, account: null } }), []);
  assert.deepEqual(classifyMachineIdentity('-O2', { identity: { hostname: null, account: null } }), []);
});

test('identity in an object KEY is caught, not only in a value', () => {
  const hits = findMachineIdentity({ perHost: { 'a-machine-name': 3 } }, { identity: IDENTITY });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].in, 'key');
});

test('a disclosure hit from the delegate becomes a finding; no hits becomes a pass; a failed delegate becomes UNCHECKED', async () => {
  const rec = await goodRecord();
  assert.ok(
    validateRecord(rec, { identity: IDENTITY, shapeHits: [{ shape: 'HOME-DIRECTORY', line: 4, match: '/home/x' }] })
      .findings.map((f) => f.id)
      .includes('VG-ART-076'),
  );
  assert.deepEqual(validateRecord(rec, { identity: IDENTITY, shapeHits: [] }).findings, []);
  assert.deepEqual(validateRecord(rec, { identity: IDENTITY, shapeHits: null }).unchecked, ['disclosureShape']);
});

// ── Byte-identity on re-run ─────────────────────────────────────────────────

test('the pair comparison ignores the clock and the run number, and nothing else', async () => {
  const one = await goodRecord({ reproduction: { pairId: 'p', run: 1 } });
  const two = await goodRecord({ reproduction: { pairId: 'p', run: 2 } });
  two.context = { generatedAt: '2030-01-01T00:00:00.000Z', timeSource: 'wall-clock', sourceDateEpoch: null };
  assert.equal(comparePair(one, two).identical, true);

  const three = JSON.parse(JSON.stringify(two));
  three.observations[0].subject = 99;
  const cmp = comparePair(one, three);
  assert.equal(cmp.identical, false);
  assert.match(cmp.detail, /diverge at byte/);
});

test('reproducibleCore removes the bookkeeping and leaves the measurement', async () => {
  const core = reproducibleCore(await goodRecord());
  assert.equal('reproduction' in core, false);
  assert.equal('observations' in core, true);
  assert.equal('context' in core, true, 'context is dropped by the canonicaliser, not here');
});

// ── Walking a store ─────────────────────────────────────────────────────────

test('a store with a matched pair is clean, and one with a half pair is incomplete', async () => {
  const dir = makeScratch('store-pairs');
  try {
    await putRecord(dir, 'p1', 1);
    await putRecord(dir, 'p1', 2);
    await putRecord(dir, 'p2', 1);
    const r = validateStore(dir, { identity: IDENTITY, delegate: false });
    assert.equal(r.inputs, 3);
    assert.equal(r.checked, 3);
    assert.equal(r.skipped, 0);
    const half = r.findings.filter((f) => f.id === 'VG-ART-078');
    assert.equal(half.length, 1, JSON.stringify(r.findings.map((f) => [f.id, f.title])));
    assert.match(half[0].detail, /pair p2/);
    assert.ok(r.unchecked.includes('pair:p2'));
  } finally {
    cleanup(dir);
  }
});

test('two runs that disagree outside context are caught', async () => {
  const dir = makeScratch('store-drift');
  try {
    await putRecord(dir, 'p', 1);
    await putRecord(dir, 'p', 2, { observations: [{ config: 'O0', subject: 7, control: 1 }] });
    const r = validateStore(dir, { identity: IDENTITY, delegate: false });
    const drift = r.findings.filter((f) => f.id === 'VG-ART-078' && f.severity === 'critical');
    assert.equal(drift.length, 1, JSON.stringify(r.findings.map((f) => f.id)));
  } finally {
    cleanup(dir);
  }
});

test('a linked entry inside the store is refused, counted as skipped, and not followed', async () => {
  const dir = makeScratch('store-linked-entry');
  try {
    const store = join(dir, 'store');
    const elsewhere = join(dir, 'elsewhere');
    mkdirSync(store, { recursive: true });
    mkdirSync(elsewhere, { recursive: true });
    writeFileSync(join(elsewhere, 'run-1.json'), '{"schemaVersion":"measurement-v0"}\n', 'utf8');
    await putRecord(store, 'real', 1);
    await putRecord(store, 'real', 2);
    linkDir(elsewhere, join(store, 'substituted'));

    const r = validateStore(store, { identity: IDENTITY, delegate: false });
    assert.equal(r.inputs, 3, JSON.stringify(r));
    assert.equal(r.checked, 2);
    assert.equal(r.skipped, 1);
    assert.ok(r.findings.some((f) => f.id === 'VG-ART-071'));
    assert.equal(r.records.length, 2, 'the linked directory was walked into');
  } finally {
    cleanup(dir);
  }
});

test('a store root reached through a link is refused before anything is read', async () => {
  const dir = makeScratch('store-linked-root');
  try {
    const real = join(dir, 'real-store');
    mkdirSync(real, { recursive: true });
    await putRecord(real, 'p', 1);
    linkDir(real, join(dir, 'link-store'));
    const r = validateStore(join(dir, 'link-store'), { identity: IDENTITY, delegate: false });
    assert.ok(r.findings.some((f) => f.id === 'VG-ART-071'), JSON.stringify(r.findings.map((f) => f.id)));
    assert.equal(r.inputs, 0);
    assert.equal(r.records.length, 0);
  } finally {
    cleanup(dir);
  }
});

test('an unparseable record is a finding and a skip, not a crash', () => {
  const dir = makeScratch('store-garbage');
  try {
    mkdirSync(join(dir, 'p'), { recursive: true });
    writeFileSync(join(dir, 'p', 'run-1.json'), '{not json', 'utf8');
    const r = validateStore(dir, { identity: IDENTITY, delegate: false });
    assert.equal(r.inputs, 1);
    assert.equal(r.checked, 0);
    assert.equal(r.skipped, 1);
    assert.ok(r.findings.some((f) => f.id === 'VG-ART-072'));
  } finally {
    cleanup(dir);
  }
});

test('a record that cannot be canonicalised is reported as malformed', () => {
  const dir = makeScratch('store-malformed');
  try {
    mkdirSync(join(dir, 'p'), { recursive: true });
    writeFileSync(
      join(dir, 'p', 'run-1.json'),
      JSON.stringify({ schemaVersion: MEASUREMENT_SCHEMA, ratio: 0.5 }),
      'utf8',
    );
    const r = validateStore(dir, { identity: IDENTITY, delegate: false });
    assert.equal(r.malformed, 1);
    assert.equal(r.skipped, 1);
  } finally {
    cleanup(dir);
  }
});

test('listRecordFiles sorts, ignores non-json, and never descends a link', () => {
  const dir = makeScratch('store-listing');
  try {
    mkdirSync(join(dir, 'b'), { recursive: true });
    mkdirSync(join(dir, 'a'), { recursive: true });
    const target = join(dir, 'target');
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, 'hidden.json'), '{}', 'utf8');
    writeFileSync(join(dir, 'b', '2.json'), '{}', 'utf8');
    writeFileSync(join(dir, 'a', '1.json'), '{}', 'utf8');
    writeFileSync(join(dir, 'a', 'notes.txt'), 'x', 'utf8');
    linkDir(target, join(dir, 'a', 'link'));

    const { files, refused } = listRecordFiles(dir);
    assert.deepEqual(
      files.map((f) => f.slice(dir.length + 1).split(/[\\/]/).join('/')),
      ['a/1.json', 'b/2.json', 'target/hidden.json'],
    );
    assert.equal(refused.length, 1);
  } finally {
    cleanup(dir);
  }
});
