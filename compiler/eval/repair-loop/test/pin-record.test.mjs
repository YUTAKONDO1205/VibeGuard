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

function good(over = {}) {
  return {
    schemaVersion: 'wipe-pin-v0',
    component: 'WipePin',
    module: 'fable_N_aeskey_r3.w.c',
    optLevel: { speedup: 2, size: 0 },
    scope: 'functions',
    requested: ['encrypt_blob'],
    resolution: [{ name: 'encrypt_blob', resolution: 'resolved' }],
    dryRun: false,
    pinned: [{ function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41 }],
    pinnedCount: 1,
    wouldPinCount: 1,
    seen: { zeroFillMemsetInScope: 1, zeroFillMemsetInModule: 2 },
    unhandled: { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0 },
    ...over,
  };
}
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

test('null is admitted for lengthBytes and line and nowhere else', () => {
  const pinned = [{ function: 'encrypt_blob', index: 0, lengthBytes: null, destKind: 'argument', alreadyVolatile: false, line: null }];
  assert.equal(validatePinRecord(good({ pinned }), EXPECT).ok, true);
  refused(good({ pinnedCount: null }), EXPECT, /not-a-count: pinnedCount/);
  refused(good({ pinned: [{ ...pinned[0], index: null }] }), EXPECT, /pinned\[0\]\.index/);
});

test('an unknown schemaVersion is refused', () => {
  refused(good({ schemaVersion: 'wipe-pin-v1' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: undefined }), EXPECT, /unknown-schemaVersion/);
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
  refused(good({ pinnedCount: 2, wouldPinCount: 2, seen: { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 2 } }), {}, /exceeds the 1 pinned site/);
  refused(good({ seen: { zeroFillMemsetInScope: 3, zeroFillMemsetInModule: 2 } }), {}, /InScope exceeds/);
  refused(good({ seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 2 } }), {}, /pinnedCount 1 exceeds seen/);
  refused(good({ pinnedCount: 0, pinned: [] }), {}, /wouldPinCount 1 with pinnedCount 0/);
});

test('in functions scope every requested name resolves exactly once, and nothing else is resolved or pinned', () => {
  refused(good({ resolution: [] }), {}, /has 0 resolution entries/);
  refused(good({ resolution: [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'encrypt_blob', resolution: 'resolved' }] }), {}, /has 2 resolution entries/);
  refused(good({ resolution: [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'other', resolution: 'resolved' }] }), {}, /resolution names other/);
  refused(good({ pinned: [{ ...good().pinned[0], function: 'vgctl_control' }] }), {}, /pinned site in vgctl_control/);
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
    resolution: [{ name: 'secure_wipe', resolution: 'resolved' }, { name: 'encrypt_blob', resolution: 'resolved' }],
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
    resolution: [{ name: 'encrypt_blob', resolution: 'resolved' }, { name: 'wipe', resolution: 'not-in-module' }],
  });
  assert.deepEqual(unresolvedNames(rec), ['wipe:not-in-module']);
  assert.deepEqual(unresolvedNames(good({ scope: 'module', requested: [], resolution: [] })), []);
  assert.deepEqual(unresolvedNames(null), []);
});
