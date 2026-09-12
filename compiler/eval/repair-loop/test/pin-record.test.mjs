/**
 * pin-record.mjs is the only thing between the plugin's own account of itself and
 * the outcome table. These tests show it refuses each way a record can be wrong,
 * and accepts the one shape compiler/schema/wipe-pin.md describes. No compiler, no lab: every
 * record is built here.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { validatePinRecord, readPinRecord, unresolvedNames, followedByUseCounts, OPT_LEVELS, COMPONENTS, LINKAGES } from '../lib/pin-record.mjs';
import { evidenceDigest, canonicalJsonRaw, sha256Hex } from '../../../evidence/canon.mjs';

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
/**
 * The toolchain block as wipe-pin.md defines it, with the digest taken by
 * canon.mjs (not by the reader under test): {<key>: v, packages: [{name, version: v}],
 * digest: sha256(canonical {<key>, packages})}.
 */
function toolchainOf(key, version, pkgName = key === 'clang' ? 'llvm' : key) {
  const packages = [{ name: pkgName, version }];
  return { [key]: version, packages, digest: sha256Hex(canonicalJsonRaw({ [key]: version, packages })) };
}
const CLANG_TC = toolchainOf('clang', '18.1.3');
const GCC_TC = toolchainOf('gcc', '13.3.0');
/** One v2 resolution entry. */
function res(name, resolution = 'resolved', { exact = resolution === 'resolved' ? true : null, linkage = resolution === 'resolved' ? 'external' : null } = {}) {
  return { name, resolution, exact, linkage };
}
/** One v2 pinned entry for encrypt_blob. */
function site(over = {}) {
  return { function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41, followedByUse: false, ...over };
}
function unsealed(over = {}) {
  return {
    schemaVersion: 'wipe-pin-v2',
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
    toolchain: CLANG_TC,
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
const EXPECT = { component: 'WipePin', scope: 'functions', dryRun: false, opt: '-O2', module: 'fable_N_aeskey_r3.w.c', requested: ['encrypt_blob'] };
const EXPECT_GCC = { ...EXPECT, component: 'WipePinGcc' };

const refused = (rec, expect, re) => {
  const r = validatePinRecord(rec, expect);
  assert.equal(r.ok, false, `expected a refusal, got ok: ${JSON.stringify(rec)}`);
  assert.equal(r.record, null);
  if (re) assert.ok(r.problems.some((p) => re.test(p)), `no problem matched ${re}: ${JSON.stringify(r.problems)}`);
  return r;
};

test('the wipe-pin.md shape is accepted, and the record comes back unchanged', () => {
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
  // exact and linkage are null for a name that did not resolve, and only then
  const unresolved = good({ resolution: [res('encrypt_blob', 'not-in-module')], pinned: [], pinnedCount: 0, wouldPinCount: 0,
    seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 2 } });
  assert.equal(validatePinRecord(unresolved, EXPECT).ok, true, JSON.stringify(validatePinRecord(unresolved, EXPECT).problems));
  refused(good({ resolution: [res('encrypt_blob', 'resolved', { exact: null, linkage: null })] }), EXPECT, /bad-linkage: resolution\[0\]\.linkage null/);
  refused(good({ pinnedCount: null }), EXPECT, /not-a-count: pinnedCount/);
  refused(good({ pinned: [{ ...pinned[0], index: null }] }), EXPECT, /pinned\[0\]\.index/);
  refused(good({ pinned: [{ ...pinned[0], alreadyVolatile: null }] }), EXPECT, /pinned\[0\]\.alreadyVolatile/);
});

test('an unknown schemaVersion is refused, and v0 and v1 are no longer known', () => {
  refused(good({ schemaVersion: 'wipe-pin-v0' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: 'wipe-pin-v1' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: 'wipe-pin-v3' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: undefined }), EXPECT, /unknown-schemaVersion/);
});

test('a v1 record exactly as the v1 plugin wrote it is refused', () => {
  // The v1 shape: same fields, v1's name, and the toolchain v1 admitted (any
  // string digest, any package objects). Sealed, so the refusal is the version.
  const v1 = good({
    schemaVersion: 'wipe-pin-v1',
    toolchain: { digest: 'a'.repeat(64), clang: 'Ubuntu clang version 18.1.3 (1ubuntu1)', packages: [{ name: 'clang-18', version: '1:18.1.3-1ubuntu1' }] },
  });
  const r = refused(v1, EXPECT, /unknown-schemaVersion: "wipe-pin-v1"/);
  assert.equal(r.problems.some((p) => /toolchain-digest-mismatch/.test(p)), true, JSON.stringify(r.problems));
  // and with v1's name on an otherwise valid v2 record, the version alone refuses it
  refused(good({ schemaVersion: 'wipe-pin-v1' }), EXPECT, /unknown-schemaVersion/);
});

test('the fields v1 added are still required', () => {
  const r0 = good();
  delete r0.toolchain;
  r0.pinned = r0.pinned.map(({ followedByUse: _f, ...p }) => p);
  r0.resolution = r0.resolution.map(({ exact: _e, linkage: _l, ...r }) => r);
  const r = refused(r0, EXPECT, /missing-field: toolchain$/);
  assert.ok(r.problems.some((p) => /missing-field: pinned\[0\]\.followedByUse/.test(p)), JSON.stringify(r.problems));
  assert.ok(r.problems.some((p) => /missing-field: resolution\[0\]\.exact/.test(p)), JSON.stringify(r.problems));
  assert.ok(r.problems.some((p) => /missing-field: resolution\[0\]\.linkage/.test(p)), JSON.stringify(r.problems));
});

// ---- v2: two components, one reader ----

test('a v2 WipePin record with the clang toolchain is accepted', () => {
  const r = validatePinRecord(good(), EXPECT);
  assert.deepEqual(r.problems, []);
  assert.equal(validatePinRecord(good(), { ...EXPECT, component: undefined }).ok, true, 'expect.component left out is not compared');
});

test('a v2 WipePinGcc record with the gcc toolchain is accepted', () => {
  const rec = good({ component: 'WipePinGcc', toolchain: GCC_TC });
  const r = validatePinRecord(rec, EXPECT_GCC);
  assert.deepEqual(r.problems, []);
  assert.equal(r.record, rec);
  // module scope and a dry run, as the GCC runner will ask for them
  assert.equal(validatePinRecord(good({ component: 'WipePinGcc', toolchain: GCC_TC, scope: 'module', requested: [], resolution: [] }),
    { component: 'WipePinGcc', scope: 'module', opt: '-O2' }).ok, true);
  assert.equal(validatePinRecord(good({ component: 'WipePinGcc', toolchain: GCC_TC, dryRun: true, pinnedCount: 0 }),
    { ...EXPECT_GCC, dryRun: true }).ok, true);
});

test('the toolchain must carry the compiler key its component names, and only that one', () => {
  // WipePin with gcc's block, WipePinGcc with clang's
  let r = refused(good({ toolchain: GCC_TC }), EXPECT, /toolchain-vendor: component WipePin carries toolchain\.gcc; its compiler key is toolchain\.clang/);
  assert.ok(r.problems.some((p) => p === 'missing-field: toolchain.clang'), JSON.stringify(r.problems));
  assert.ok(r.problems.some((p) => p === 'unknown-field: toolchain.gcc'), JSON.stringify(r.problems));
  r = refused(good({ component: 'WipePinGcc', toolchain: CLANG_TC }), EXPECT_GCC, /toolchain-vendor: component WipePinGcc carries toolchain\.clang; its compiler key is toolchain\.gcc/);
  assert.ok(r.problems.some((p) => p === 'missing-field: toolchain.gcc'), JSON.stringify(r.problems));
  // both keys: refused for each component
  const both = { ...CLANG_TC, gcc: '13.3.0' };
  refused(good({ toolchain: both }), EXPECT, /toolchain-vendor: component WipePin carries toolchain\.gcc/);
  refused(good({ component: 'WipePinGcc', toolchain: both }), EXPECT_GCC, /toolchain-vendor: component WipePinGcc carries toolchain\.clang/);
  // neither key
  const { clang: _c, ...neither } = CLANG_TC;
  refused(good({ toolchain: neither }), EXPECT, /missing-field: toolchain\.clang/);
  refused(good({ component: 'WipePinGcc', toolchain: neither }), EXPECT_GCC, /missing-field: toolchain\.gcc/);
  // an unknown component: exactly one vendor key is still demanded of the block
  refused(good({ component: 'IrCheckpoints', toolchain: both }), {}, /toolchain-vendor: toolchain must carry exactly one of clang, gcc \(it carries 2\)/);
});

test('the toolchain package list is exactly one entry naming the vendor package at the same version', () => {
  refused(good({ toolchain: toolchainOf('clang', '18.1.3', 'clang-18') }), EXPECT, /packages\[0\]\.name "clang-18", component WipePin names "llvm"/);
  refused(good({ component: 'WipePinGcc', toolchain: toolchainOf('gcc', '13.3.0', 'llvm') }), EXPECT_GCC, /packages\[0\]\.name "llvm", component WipePinGcc names "gcc"/);
  const skew = { clang: '18.1.3', packages: [{ name: 'llvm', version: '18.1.8' }] };
  skew.digest = sha256Hex(canonicalJsonRaw(skew));
  refused(good({ toolchain: skew }), EXPECT, /packages\[0\]\.version "18\.1\.8" differs from toolchain\.clang "18\.1\.3"/);
  const two = { clang: '18.1.3', packages: [{ name: 'llvm', version: '18.1.3' }, { name: 'llvm', version: '18.1.3' }] };
  two.digest = sha256Hex(canonicalJsonRaw(two));
  refused(good({ toolchain: two }), EXPECT, /exactly one \{name, version\} object \(it has 2 entries\)/);
  const none = { clang: '18.1.3', packages: [] };
  none.digest = sha256Hex(canonicalJsonRaw(none));
  refused(good({ toolchain: none }), EXPECT, /it has 0 entries/);
  const extra = { clang: '18.1.3', packages: [{ name: 'llvm', version: '18.1.3', build: 'x' }] };
  extra.digest = sha256Hex(canonicalJsonRaw(extra));
  refused(good({ toolchain: extra }), EXPECT, /unknown-field: toolchain\.packages\[0\]\.build/);
});

test('a toolchain digest that does not re-derive is refused, whichever vendor', () => {
  refused(good({ toolchain: { ...CLANG_TC, digest: 'a'.repeat(64) } }), EXPECT, /toolchain-digest-mismatch: .*\{clang, packages\}/);
  refused(good({ component: 'WipePinGcc', toolchain: { ...GCC_TC, digest: 'a'.repeat(64) } }), EXPECT_GCC, /toolchain-digest-mismatch: .*\{gcc, packages\}/);
  // gcc's digest carried over onto a clang block of the same version: the key is in the digest
  const crossed = { ...toolchainOf('clang', '13.3.0', 'llvm'), digest: toolchainOf('gcc', '13.3.0', 'llvm').digest };
  refused(good({ toolchain: crossed }), EXPECT, /toolchain-digest-mismatch/);
  for (const d of ['', 'A'.repeat(64), 'a'.repeat(63), null, 7]) {
    refused(good({ toolchain: { ...CLANG_TC, digest: d } }), EXPECT, /toolchain\.digest must be 64 lowercase hex/);
  }
});

test('an evidenceDigest that does not re-derive is refused for a GCC record too', () => {
  const rec = good({ component: 'WipePinGcc', toolchain: GCC_TC });
  assert.equal(validatePinRecord(rec, EXPECT_GCC).ok, true);
  rec.toolchain = toolchainOf('gcc', '13.2.0');
  refused(rec, EXPECT_GCC, /digest-mismatch: evidenceDigest/);
});

test('a record whose component is not the one this compile loaded is wrong-compile', () => {
  refused(good(), EXPECT_GCC, /wrong-compile: component WipePin, this compile loaded WipePinGcc/);
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC }), EXPECT, /wrong-compile: component WipePinGcc, this compile loaded WipePin/);
  refused(good(), { ...EXPECT, component: 'WipePinLLVM' }, /bad-expect: component "WipePinLLVM"/);
  assert.deepEqual([...COMPONENTS], ['WipePin', 'WipePinGcc']);
});

test('v1 fields: followedByUse, exact and linkage are typed', () => {
  for (const bad of [0, 1, 'true', 'yes', {}]) {
    refused(good({ pinned: [site({ followedByUse: bad })] }), EXPECT, /pinned\[0\]\.followedByUse must be true, false or null/);
    refused(good({ resolution: [res('encrypt_blob', 'resolved', { exact: bad })] }), EXPECT, /resolution\[0\]\.exact must be true, false or null/);
  }
  for (const f of [true, false]) {
    assert.equal(validatePinRecord(good({ pinned: [site({ followedByUse: f })] }), EXPECT).ok, true, `followedByUse ${f}`);
    const linkage = f ? 'external' : 'linkonce_odr';
    assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { exact: f, linkage })] }), EXPECT).ok, true, `exact ${f}`);
  }
  for (const bad of [0, true, {}, []]) {
    refused(good({ resolution: [res('encrypt_blob', 'resolved', { linkage: bad })] }), EXPECT, /resolution\[0\]\.linkage must be a string or null/);
  }
  assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { linkage: 'internal' })] }), EXPECT).ok, true);
});

test('v2 toolchain: typed exactly, where v1 admitted any string and any package objects', () => {
  // what v1 accepted and v2 refuses
  refused(good({ toolchain: { digest: '', clang: '', packages: [] } }), EXPECT, /toolchain\.digest must be 64 lowercase hex/);
  refused(good({ toolchain: { ...CLANG_TC, packages: [{}] } }), EXPECT, /missing-field: toolchain\.packages\[0\]\.name/);
  refused(good({ toolchain: null }), EXPECT, /toolchain must be an object/);
  refused(good({ toolchain: [] }), EXPECT, /toolchain must be an object/);
  const { packages: _p, ...noPkgs } = CLANG_TC;
  refused(good({ toolchain: noPkgs }), EXPECT, /missing-field: toolchain\.packages/);
  refused(good({ toolchain: { ...CLANG_TC, extra: 1 } }), EXPECT, /unknown-field: toolchain\.extra/);
  refused(good({ toolchain: { ...CLANG_TC, clang: 18 } }), EXPECT, /toolchain\.clang must be a non-empty string/);
  refused(good({ toolchain: { ...CLANG_TC, clang: '' } }), EXPECT, /toolchain\.clang must be a non-empty string/);
  refused(good({ component: 'WipePinGcc', toolchain: { ...GCC_TC, gcc: null } }), EXPECT_GCC, /toolchain\.gcc must be a non-empty string/);
  refused(good({ toolchain: { ...CLANG_TC, packages: {} } }), EXPECT, /toolchain\.packages must be an array/);
  refused(good({ toolchain: { ...CLANG_TC, packages: ['llvm'] } }), EXPECT, /exactly one \{name, version\} object/);
});

test('the toolchain is inside the digest: editing it after sealing is refused', () => {
  const rec = good();
  // a well-formed block of another version: only the evidenceDigest can notice
  rec.toolchain = toolchainOf('clang', '18.1.8');
  refused(rec, EXPECT, /^digest-mismatch: evidenceDigest/);
});

test('a record from another component is refused', () => {
  refused(good({ component: 'IrCheckpoints' }), EXPECT, /wrong-component/);
  refused(good({ component: 'IrCheckpoints' }), {}, /wrong-component: "IrCheckpoints" \(this reader knows WipePin, WipePinGcc\)/);
  refused(good({ component: undefined }), {}, /wrong-component/);
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
const seen0 = { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 3 };

test('outside a dry run: pinnedCount === wouldPinCount === listed sites not already volatile', () => {
  assert.equal(validatePinRecord(good({ pinned: two, pinnedCount: 2, wouldPinCount: 2, seen: seen2 }), EXPECT).ok, true);
  // nothing listed, nothing counted
  assert.equal(validatePinRecord(good({ pinned: [], pinnedCount: 0, wouldPinCount: 0, seen: seen0 }), EXPECT).ok, true);
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
  assert.equal(validatePinRecord(good({ dryRun: true, pinned: [], pinnedCount: 0, wouldPinCount: 0, seen: seen0 }), D).ok, true);
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

test('the optimisation pairs are the ones LLVM reports, per component', () => {
  const L = OPT_LEVELS.WipePin;
  assert.deepEqual(L['-O0'], { speedup: 0, size: 0 });
  assert.deepEqual(L['-Os'], { speedup: 2, size: 1 });
  assert.deepEqual(L['-Oz'], { speedup: 2, size: 2 });
  assert.deepEqual(Object.keys(OPT_LEVELS).sort(), [...COMPONENTS].sort());
  for (const o of ['-O0', '-O1', '-O2', '-O3', '-Os']) {
    assert.equal(validatePinRecord(good({ optLevel: { ...L[o] } }), { opt: o }).ok, true, o);
    assert.equal(validatePinRecord(good({ optLevel: { ...L[o] } }), { component: 'WipePin', opt: o }).ok, true, o);
    const G = OPT_LEVELS.WipePinGcc;
    assert.equal(validatePinRecord(good({ component: 'WipePinGcc', toolchain: GCC_TC, optLevel: { ...G[o] } }),
      { component: 'WipePinGcc', opt: o }).ok, true, `gcc ${o}`);
  }
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC }), { ...EXPECT_GCC, opt: '-O3' }, /optLevel \{2,0\} does not match -O3/);
});

// ---- structural rules both writers hold (wipe-pin.md §5-§11); 78,855 real
// records (22,360 distinct evidence digests) break none of them ----

test('seen.zeroFillMemsetInScope is the number of sites pinned[] lists', () => {
  refused(good({ seen: { zeroFillMemsetInScope: 2, zeroFillMemsetInModule: 2 }, wouldPinCount: 1 }), EXPECT,
    /seen\.zeroFillMemsetInScope 2, but pinned\[\] lists 1 site/);
  const oneVol = [site(), site({ index: 1, alreadyVolatile: true })];
  assert.equal(validatePinRecord(good({ pinned: oneVol, pinnedCount: 1, wouldPinCount: 1, seen: seen2 }), EXPECT).ok, true,
    'an already-volatile site is listed, so it is in the in-scope count');
});

test('destKind is one of the observer words, and followedByUse is null exactly when it is not alloca', () => {
  for (const d of ['stack', 'heap', 'Alloca', 'param']) {
    refused(good({ pinned: [site({ destKind: d, followedByUse: null })] }), EXPECT, /bad-destKind/);
  }
  for (const d of ['argument', 'global', 'other']) {
    assert.equal(validatePinRecord(good({ pinned: [site({ destKind: d, followedByUse: null })] }), EXPECT).ok, true, d);
    refused(good({ pinned: [site({ destKind: d, followedByUse: false })] }), EXPECT, /null exactly when destKind is not alloca/);
  }
  refused(good({ pinned: [site({ destKind: 'alloca', followedByUse: null })] }), EXPECT, /destKind alloca and followedByUse null/);
});

test('a resolved name carries an LLVM linkage word, and exact says whether it is external, internal or private', () => {
  refused(good({ resolution: [res('encrypt_blob', 'resolved', { linkage: 'public' })] }), EXPECT, /bad-linkage/);
  refused(good({ resolution: [res('encrypt_blob', 'resolved', { exact: false, linkage: 'external' })] }), EXPECT,
    /linkage external and exact false/);
  refused(good({ resolution: [res('encrypt_blob', 'resolved', { exact: true, linkage: 'weak' })] }), EXPECT,
    /linkage weak and exact true/);
  for (const [linkage, exact] of [['internal', true], ['private', true], ['available_externally', false], ['weak_odr', false]]) {
    assert.equal(validatePinRecord(good({ resolution: [res('encrypt_blob', 'resolved', { exact, linkage })] }), EXPECT).ok, true, linkage);
  }
  const bare = { pinned: [], pinnedCount: 0, wouldPinCount: 0, seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 2 } };
  refused(good({ ...bare, resolution: [res('encrypt_blob', 'not-in-module', { exact: false })] }), EXPECT, /did not resolve but carries/);
  refused(good({ ...bare, resolution: [res('encrypt_blob', 'declaration-only', { linkage: 'external' })] }), EXPECT, /did not resolve but carries/);
  assert.deepEqual([...LINKAGES].slice(0, 2), ['external', 'internal']);
});

test('a WipePinGcc record has no atomic or inline-wrapper memsets to count', () => {
  const U = { libcallMemset: 0, memsetChk: 0, nonZeroFill: 0, atomicMemset: 0, inlineWrapperMemset: 0 };
  for (const k of ['atomicMemset', 'inlineWrapperMemset']) {
    refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, unhandled: { ...U, [k]: 1 } }), EXPECT_GCC,
      new RegExp(`unhandled\\.${k} is 1 on a WipePinGcc record`));
    assert.equal(validatePinRecord(good({ unhandled: { ...U, [k]: 1 } }), EXPECT).ok, true, `WipePin may count ${k}`);
  }
});

test('module scope names no functions, and in functions scope resolution[] follows requested[]', () => {
  refused(good({ scope: 'module', requested: ['encrypt_blob'], resolution: [res('encrypt_blob')] }), { scope: 'module', opt: '-O2' },
    /a module-scope record names requested functions/);
  const pinned2 = [site(), site({ function: 'secure_wipe', index: 0 })];
  const base = { pinned: pinned2, pinnedCount: 2, wouldPinCount: 2, seen: seen2 };
  assert.equal(validatePinRecord(good({ ...base, requested: ['encrypt_blob', 'secure_wipe'],
    resolution: [res('encrypt_blob'), res('secure_wipe')] }), {}).ok, true);
  refused(good({ ...base, requested: ['encrypt_blob', 'secure_wipe'], resolution: [res('secure_wipe'), res('encrypt_blob')] }), {},
    /resolution\[\] is not in the order of requested\[\]/);
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

test('followedByUseCounts: a listed site already volatile, or listed in a dry run, is not a pinned one', () => {
  // haiku_E_pinpad_r1's shape: one site, already volatile in the source, followed by a use; nothing pinned
  const alreadyVolatile = good({
    pinned: [site({ alreadyVolatile: true, followedByUse: true })], pinnedCount: 0, wouldPinCount: 0,
  });
  assert.equal(validatePinRecord(alreadyVolatile, EXPECT).ok, true);
  assert.deepEqual(followedByUseCounts(alreadyVolatile), { listed: 1, pinned: 0 });
  // two pinned sites (one initialiser-like) and one already-volatile initialiser-like site
  const mixed = good({
    pinned: [site({ followedByUse: true }), site({ index: 1, followedByUse: false }),
      site({ index: 2, alreadyVolatile: true, followedByUse: true }), site({ index: 3, destKind: 'argument', followedByUse: null })],
    pinnedCount: 3, wouldPinCount: 3, seen: { zeroFillMemsetInScope: 4, zeroFillMemsetInModule: 4 },
  });
  assert.equal(validatePinRecord(mixed, EXPECT).ok, true);
  assert.deepEqual(followedByUseCounts(mixed), { listed: 2, pinned: 1 });
  // a dry run changes nothing: every site is listed, none is pinned
  const dry = good({ dryRun: true, pinned: [site({ followedByUse: true })], pinnedCount: 0, wouldPinCount: 1 });
  assert.equal(validatePinRecord(dry, { ...EXPECT, dryRun: true }).ok, true);
  assert.deepEqual(followedByUseCounts(dry), { listed: 1, pinned: 0 });
  assert.deepEqual(followedByUseCounts(good()), { listed: 0, pinned: 0 });
  assert.deepEqual(followedByUseCounts(null), { listed: 0, pinned: 0 });
});
