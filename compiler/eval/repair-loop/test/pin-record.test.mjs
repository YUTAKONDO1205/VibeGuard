/**
 * pin-record.mjs is the only thing between the plugin's own account of itself and
 * the outcome table. These tests show it refuses each way a record can be wrong,
 * and accepts the one shape the contract describes. No compiler, no lab: every
 * record is built here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { validatePinRecord, readPinRecord, unresolvedNames, OPT_LEVELS } from '../lib/pin-record.mjs';
import { evidenceDigest } from '../../../evidence/canon.mjs';

/**
 * A record sealed AFTER the override, as the plugin seals what it writes: a test
 * that breaks one field then tests that field, not the digest. `unsealed` lets a
 * test edit the record after sealing, which is what tampering looks like.
 */
function good(over = {}) {
  const rec = unsealed(over);
  if (!('evidenceDigest' in over)) {
    const { evidenceDigest: _d, context: _c, ...body } = rec;
    try { rec.evidenceDigest = evidenceDigest(body); } catch { /* an unserialisable field: the test is about that field */ }
  }
  return rec;
}
/** One v1 resolution entry. */
function res(name, resolution = 'resolved', { exact = resolution === 'resolved' ? true : null, linkage = resolution === 'resolved' ? 'external' : null } = {}) {
  return { name, resolution, exact, linkage };
}
/** One v1 pinned entry for encrypt_blob. */
function site(over = {}) {
  return { function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41, followedByUse: false, ...over };
}
function unsealed(over = {}) {
  return {
    schemaVersion: 'wipe-pin-v1',
    component: 'WipePin',
    module: 'fable_N_aeskey_r3.w.c',
    optLevel: { speedup: 2, size: 0 },
    scope: 'functions',
    requested: ['encrypt_blob'],
    resolution: [{ name: 'encrypt_blob', resolution: 'resolved', exact: true, linkage: 'external' }],
    dryRun: false,
    pinned: [{ function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41, followedByUse: false }],
    pinnedCount: 1,
    wouldPinCount: 1,
    seen: { zeroFillMemsetInScope: 1, zeroFillMemsetInModule: 2 },
    unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 },
    toolchain: { digest: 'a'.repeat(64), clang: 'Ubuntu clang version 18.1.3 (1ubuntu1)', packages: [{ name: 'clang-18', version: '1:18.1.3-1ubuntu1' }] },
    evidenceDigest: '0'.repeat(64),
    context: { generatedAt: 1, sourceDateEpoch: null, timeSource: 'wall-clock' },
    ...over,
  };
}

test('a record edited after sealing is refused on the digest', () => {
  const rec = good();
  assert.equal(validatePinRecord(rec, EXPECT).ok, true);
  rec.pinnedCount = 2;
  rec.pinned.push({ ...rec.pinned[0], index: 1 });
  rec.seen = { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 2 };
  rec.wouldPinCount = 2;
  refused(rec, EXPECT, /digest-mismatch/);
});

test('context is outside the digest, as interfaces.md section 5 says', () => {
  const rec = good();
  rec.context = { generatedAt: 999, sourceDateEpoch: 5, timeSource: 'source-date-epoch' };
  assert.equal(validatePinRecord(rec, EXPECT).ok, true);
});

test('a record without a digest or a context is refused', () => {
  const noDigest = good(); delete noDigest.evidenceDigest;
  refused(noDigest, EXPECT, /missing-field: evidenceDigest/);
  const noCtx = good(); delete noCtx.context;
  refused(noCtx, EXPECT, /missing-field: context/);
  refused(good({ evidenceDigest: 'ABC' }), EXPECT, /evidenceDigest must be 64/);
});
const EXPECT = { scope: 'functions', dryRun: false, opt: '-O2', module: 'fable_N_aeskey_r3.w.c', requested: ['encrypt_blob'] };

const refused = (rec, expect, re) => {
  const r = validatePinRecord(rec, expect);
  assert.equal(r.ok, false, `expected a refusal, got ok: ${JSON.stringify(rec)}`);
  assert.equal(r.record, null);
  if (re) assert.ok(r.problems.some((p) => re.test(p)), `no problem matched ${re}: ${JSON.stringify(r.problems)}`);
  return r;
};

test('the contract shape is accepted, and the record comes back unchanged', () => {
  const rec = good();
  const r = validatePinRecord(rec, EXPECT);
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
  assert.equal(r.record, rec);
});

test('a module-scope record with an empty request list is accepted', () => {
  const r = validatePinRecord(good({ scope: 'module', requested: [], resolution: [] }), { scope: 'module', opt: '-O2' });
  assert.equal(r.ok, true, JSON.stringify(r.problems));
});

test('a dry-run record with nothing pinned and something that would be is accepted', () => {
  const r = validatePinRecord(good({ dryRun: true, pinnedCount: 0, wouldPinCount: 1 }), { ...EXPECT, dryRun: true });
  assert.equal(r.ok, true, JSON.stringify(r.problems));
});

test('null is admitted for lengthBytes, line, followedByUse, exact and linkage, and nowhere else', () => {
  const pinned = [site({ lengthBytes: null, destKind: 'argument', line: null, followedByUse: null })];
  assert.equal(validatePinRecord(good({ pinned }), EXPECT).ok, true);
  assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { exact: null, linkage: null })] }), EXPECT).ok, true);
  refused(good({ pinnedCount: null }), EXPECT, /not-a-count: pinnedCount/);
  refused(good({ pinned: [{ ...pinned[0], index: null }] }), EXPECT, /pinned\[0\]\.index/);
  refused(good({ pinned: [{ ...pinned[0], alreadyVolatile: null }] }), EXPECT, /pinned\[0\]\.alreadyVolatile/);
});

test('an unknown schemaVersion is refused, and v0 is no longer known', () => {
  refused(good({ schemaVersion: 'wipe-pin-v0' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: 'wipe-pin-v2' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: undefined }), EXPECT, /unknown-schemaVersion/);
});

test('a v0-shaped record is refused for each field v1 added', () => {
  const v0 = good({ schemaVersion: 'wipe-pin-v1' });
  delete v0.toolchain;
  v0.pinned = v0.pinned.map(({ followedByUse: _f, ...p }) => p);
  v0.resolution = v0.resolution.map(({ exact: _e, linkage: _l, ...r }) => r);
  const r = refused(v0, EXPECT, /missing-field: toolchain$/);
  assert.ok(r.problems.some((p) => /missing-field: pinned\[0\]\.followedByUse/.test(p)), JSON.stringify(r.problems));
  assert.ok(r.problems.some((p) => /missing-field: resolution\[0\]\.exact/.test(p)), JSON.stringify(r.problems));
  assert.ok(r.problems.some((p) => /missing-field: resolution\[0\]\.linkage/.test(p)), JSON.stringify(r.problems));
});

test('v1 fields: followedByUse, exact and linkage are typed', () => {
  for (const bad of [0, 1, 'true', 'yes', {}]) {
    refused(good({ pinned: [site({ followedByUse: bad })] }), EXPECT, /pinned\[0\]\.followedByUse must be true, false or null/);
    refused(good({ resolution: [res('encrypt_blob', 'resolved', { exact: bad })] }), EXPECT, /resolution\[0\]\.exact must be true, false or null/);
  }
  for (const f of [true, false]) {
    assert.equal(validatePinRecord(good({ pinned: [site({ followedByUse: f })] }), EXPECT).ok, true, `followedByUse ${f}`);
    assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { exact: f })] }), EXPECT).ok, true, `exact ${f}`);
  }
  for (const bad of [0, true, {}, []]) {
    refused(good({ resolution: [res('encrypt_blob', 'resolved', { linkage: bad })] }), EXPECT, /resolution\[0\]\.linkage must be a string or null/);
  }
  assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { linkage: 'internal' })] }), EXPECT).ok, true);
});

test('v1 toolchain: exactly digest, clang and packages, loosely typed', () => {
  // an empty digest is allowed; an empty package list is allowed
  assert.equal(validatePinRecord(good({ toolchain: { digest: '', clang: '', packages: [] } }), EXPECT).ok, true);
  // package entries are objects, whatever they carry
  assert.equal(validatePinRecord(good({ toolchain: { digest: 'x', clang: 'c', packages: [{}, { anything: 'goes', n: 3 }] } }), EXPECT).ok, true);
  refused(good({ toolchain: null }), EXPECT, /toolchain must be an object/);
  refused(good({ toolchain: [] }), EXPECT, /toolchain must be an object/);
  refused(good({ toolchain: { digest: '', clang: '' } }), EXPECT, /missing-field: toolchain\.packages/);
  refused(good({ toolchain: { digest: '', clang: '', packages: [], extra: 1 } }), EXPECT, /unknown-field: toolchain\.extra/);
  refused(good({ toolchain: { digest: null, clang: '', packages: [] } }), EXPECT, /toolchain\.digest must be a string/);
  refused(good({ toolchain: { digest: '', clang: 18, packages: [] } }), EXPECT, /toolchain\.clang must be a string/);
  refused(good({ toolchain: { digest: '', clang: '', packages: {} } }), EXPECT, /toolchain\.packages must be an array/);
  refused(good({ toolchain: { digest: '', clang: '', packages: ['clang-18'] } }), EXPECT, /toolchain\.packages\[0\] must be an object/);
});

test('the toolchain is inside the digest: editing it after sealing is refused', () => {
  const rec = good();
  rec.toolchain = { ...rec.toolchain, clang: 'another clang' };
  refused(rec, EXPECT, /digest-mismatch/);
});

test('a record from another component is refused', () => {
  refused(good({ component: 'IrCheckpoints' }), EXPECT, /wrong-component/);
});

test('an absolute path in module is refused, in every spelling', () => {
  for (const m of ['/home/someone/x.w.c', '/mnt/c/work/x.w.c', 'C:\\work\\x.w.c', 'C:x.w.c', 'sub/x.w.c', '~/x.w.c']) {
    refused(good({ module: m }), {}, /module-not-a-basename/);
  }
  refused(good({ module: '' }), {}, /module must be a non-empty string/);
});

test('every missing top-level field is named', () => {
  for (const k of Object.keys(good())) {
    const rec = good();
    delete rec[k];
    refused(rec, {}, new RegExp(`missing-field: ${k}$`));
  }
});

test('missing nested fields are named', () => {
  refused(good({ seen: { zeroFillMemsetInScope: 1 } }), {}, /missing-field: seen\.zeroFillMemsetInModule/);
  refused(good({ unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0 } }), {}, /missing-field: unhandled\.atomicMemset/);
  refused(good({ optLevel: { speedup: 2 } }), {}, /missing-field: optLevel\.size/);
  const p = { ...good().pinned[0] }; delete p.destKind;
  refused(good({ pinned: [p] }), {}, /missing-field: pinned\[0\]\.destKind/);
  refused(good({ resolution: [{ name: 'encrypt_blob' }] }), {}, /missing-field: resolution\[0\]\.resolution/);
});

test('unknown fields are refused rather than skipped', () => {
  refused(good({ extra: 1 }), {}, /unknown-field: extra/);
  refused(good({ seen: { zeroFillMemsetInScope: 1, zeroFillMemsetInModule: 2, other: 0 } }), {}, /unknown-field: seen\.other/);
});

test('non-integers are refused wherever a count is expected', () => {
  refused(good({ pinnedCount: 1.5 }), {}, /not-a-count: pinnedCount/);
  refused(good({ pinnedCount: '1' }), {}, /not-a-count: pinnedCount/);
  refused(good({ wouldPinCount: -1 }), {}, /not-a-count: wouldPinCount/);
  refused(good({ optLevel: { speedup: 2.0001, size: 0 } }), {}, /not-a-count: optLevel\.speedup/);
  refused(good({ seen: { zeroFillMemsetInScope: '1', zeroFillMemsetInModule: 2 } }), {}, /not-a-count: seen\.zeroFillMemsetInScope/);
  refused(good({ unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: NaN, atomicMemset: 0 } }), {}, /not-a-count: unhandled\.nonZeroFill/);
  const p = good().pinned[0];
  refused(good({ pinned: [{ ...p, lengthBytes: 3.5 }] }), {}, /lengthBytes/);
  refused(good({ pinned: [{ ...p, line: '41' }] }), {}, /pinned\[0\]\.line/);
});

test('wrong types for the rest are refused', () => {
  refused(null, {}, /not-an-object/);
  refused([], {}, /not-an-object/);
  refused(good({ dryRun: 'false' }), {}, /dryRun must be a boolean/);
  refused(good({ scope: 'file' }), {}, /bad-scope/);
  refused(good({ requested: 'encrypt_blob' }), {}, /requested must be an array/);
  refused(good({ resolution: [{ name: 'encrypt_blob', resolution: 'found' }] }), {}, /bad-resolution/);
  refused(good({ pinned: [{ ...good().pinned[0], alreadyVolatile: 0 }] }), {}, /alreadyVolatile/);
});

test('a dry run that mutated something contradicts itself', () => {
  refused(good({ dryRun: true, pinnedCount: 1 }), {}, /dryRun is true but pinnedCount/);
});

test('counts that contradict the lists they count are refused', () => {
  refused(good({ pinnedCount: 2, wouldPinCount: 2, seen: { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 2 } }), {}, /pinnedCount 2, but 1 listed site\(s\) are not already volatile/);
  refused(good({ seen: { zeroFillMemsetInScope: 3, zeroFillMemsetInModule: 2 } }), {}, /InScope exceeds/);
  refused(good({ seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 2 } }), {}, /pinnedCount 1 exceeds seen/);
  refused(good({ pinnedCount: 0, pinned: [] }), {}, /pinnedCount 0 differs from wouldPinCount 1/);
});

// ---- v1 count consistency: pinnedCount, wouldPinCount and the list agree exactly ----

const two = [site(), site({ index: 1, lengthBytes: 16, line: 44 })];
const seen2 = { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 3 };

test('outside a dry run: pinnedCount === wouldPinCount === listed sites not already volatile', () => {
  assert.equal(validatePinRecord(good({ pinned: two, pinnedCount: 2, wouldPinCount: 2, seen: seen2 }), EXPECT).ok, true);
  // nothing listed, nothing counted
  assert.equal(validatePinRecord(good({ pinned: [], pinnedCount: 0, wouldPinCount: 0 }), EXPECT).ok, true);
  // an already-volatile site is listed and counted in neither
  const oneVol = [site(), site({ index: 1, alreadyVolatile: true })];
  assert.equal(validatePinRecord(good({ pinned: oneVol, pinnedCount: 1, wouldPinCount: 1, seen: seen2 }), EXPECT).ok, true);
  refused(good({ pinned: oneVol, pinnedCount: 2, wouldPinCount: 2, seen: seen2 }), EXPECT, /pinnedCount 2, but 1 listed site/);
  // pinnedCount below the list: a site listed as pinned that was not
  refused(good({ pinned: two, pinnedCount: 1, wouldPinCount: 1, seen: seen2 }), EXPECT, /pinnedCount 1, but 2 listed site/);
  // the two counts disagree although one of them matches the list
  refused(good({ pinned: two, pinnedCount: 2, wouldPinCount: 1, seen: seen2 }), EXPECT, /pinnedCount 2 differs from wouldPinCount 1/);
  refused(good({ pinned: two, pinnedCount: 1, wouldPinCount: 2, seen: seen2 }), EXPECT, /pinnedCount 1 differs from wouldPinCount 2/);
  // counts above zero with an empty list
  refused(good({ pinned: [], pinnedCount: 1, wouldPinCount: 1 }), EXPECT, /pinnedCount 1, but 0 listed site/);
});

test('in a dry run: pinnedCount 0, and wouldPinCount === listed sites not already volatile', () => {
  const D = { ...EXPECT, dryRun: true };
  assert.equal(validatePinRecord(good({ dryRun: true, pinned: two, pinnedCount: 0, wouldPinCount: 2, seen: seen2 }), D).ok, true);
  assert.equal(validatePinRecord(good({ dryRun: true, pinned: [], pinnedCount: 0, wouldPinCount: 0 }), D).ok, true);
  const oneVol = [site(), site({ index: 1, alreadyVolatile: true })];
  assert.equal(validatePinRecord(good({ dryRun: true, pinned: oneVol, pinnedCount: 0, wouldPinCount: 1, seen: seen2 }), D).ok, true);
  refused(good({ dryRun: true, pinned: oneVol, pinnedCount: 0, wouldPinCount: 2, seen: seen2 }), D, /dry run with wouldPinCount 2, but 1 listed site/);
  refused(good({ dryRun: true, pinned: two, pinnedCount: 0, wouldPinCount: 1, seen: seen2 }), D, /dry run with wouldPinCount 1, but 2 listed site/);
  refused(good({ dryRun: true, pinned: two, pinnedCount: 2, wouldPinCount: 2, seen: seen2 }), D, /dryRun is true but pinnedCount is 2/);
  // a dry run that lists nothing cannot claim it would have pinned something
  refused(good({ dryRun: true, pinned: [], pinnedCount: 0, wouldPinCount: 1 }), D, /dry run with wouldPinCount 1, but 0 listed site/);
});

test('in functions scope every requested name resolves exactly once, and nothing else is resolved or pinned', () => {
  refused(good({ resolution: [] }), {}, /has 0 resolution entries/);
  refused(good({ resolution: [res('encrypt_blob'), res('encrypt_blob')] }), {}, /has 2 resolution entries/);
  refused(good({ resolution: [res('encrypt_blob'), res('other')] }), {}, /resolution names other/);
  refused(good({ pinned: [site({ function: 'vgctl_control' })] }), {}, /pinned site in vgctl_control/);
});

test('a record that describes a different compile is refused', () => {
  refused(good(), { ...EXPECT, opt: '-O3' }, /optLevel \{2,0\} does not match -O3/);
  refused(good(), { ...EXPECT, opt: '-Os' }, /does not match -Os/);
  refused(good(), { ...EXPECT, module: 'fable_N_aeskey_r3.wo.c' }, /wrong-compile: module/);
  refused(good(), { ...EXPECT, dryRun: true }, /wrong-compile: dryRun/);
  refused(good(), { ...EXPECT, scope: 'module' }, /wrong-compile: scope/);
  refused(good(), { ...EXPECT, requested: ['encrypt_blob', 'secure_wipe'] }, /wrong-compile: requested/);
});

test('request order and duplicates do not matter; the set does', () => {
  const rec = good({
    requested: ['secure_wipe', 'encrypt_blob'],
    resolution: [res('secure_wipe'), res('encrypt_blob')],
  });
  assert.equal(validatePinRecord(rec, { ...EXPECT, requested: ['encrypt_blob', 'secure_wipe', 'encrypt_blob'] }).ok, true);
});

test('the optimisation pairs are the ones LLVM reports', () => {
  assert.deepEqual(OPT_LEVELS['-O0'], { speedup: 0, size: 0 });
  assert.deepEqual(OPT_LEVELS['-Os'], { speedup: 2, size: 1 });
  assert.deepEqual(OPT_LEVELS['-Oz'], { speedup: 2, size: 2 });
  for (const o of ['-O0', '-O1', '-O2', '-O3', '-Os']) {
    assert.equal(validatePinRecord(good({ optLevel: { ...OPT_LEVELS[o] } }), { opt: o }).ok, true, o);
  }
});

test('problem strings never carry a path, even for an unreadable or missing file', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pinrec-'));
  try {
    const missing = readPinRecord(path.join(dir, 'nope.json'));
    assert.deepEqual(missing, { ok: false, record: null, problems: ['record-missing'] });
    const bad = path.join(dir, 'bad.json');
    writeFileSync(bad, '{ not json');
    assert.deepEqual(readPinRecord(bad).problems, ['record-not-json']);
    const ok = path.join(dir, 'ok.json');
    writeFileSync(ok, JSON.stringify(good()));
    assert.equal(readPinRecord(ok, EXPECT).ok, true);
    for (const p of [...missing.problems, ...readPinRecord(bad).problems]) assert.ok(!p.includes(dir));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unresolvedNames lists what did not resolve, and nothing in module scope', () => {
  const rec = good({
    requested: ['encrypt_blob', 'wipe'],
    resolution: [res('encrypt_blob'), res('wipe', 'not-in-module')],
  });
  assert.deepEqual(unresolvedNames(rec), ['wipe:not-in-module']);
  assert.deepEqual(unresolvedNames(good({ scope: 'module', requested: [], resolution: [] })), []);
  assert.deepEqual(unresolvedNames(null), []);
});
