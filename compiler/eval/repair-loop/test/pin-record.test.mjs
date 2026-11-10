/**
 * pin-record.mjs is the only thing between the plugin's own account of itself and
 * the outcome table. These tests show it refuses each way a record can be wrong,
 * and accepts the one shape compiler/schema/wipe-pin.md describes -- v3, §14 on
 * top of §1-§13. No compiler, no lab: every record is built here, apart from
 * the two constructed examples of wipe-pin.md §14.11, which are read out of
 * that document so that the reader and the contract cannot drift apart.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  validatePinRecord, readPinRecord, unresolvedNames, followedByUseCounts, OPT_LEVELS, COMPONENTS, LINKAGES,
  SCHEMA_VERSION, TOP_KEYS, UNHANDLED_KEYS, UNHANDLED_KEYS_V2, GCC_ALWAYS_ZERO, SWITCHES, CONTEXT_KEYS,
  stripIdent, identMajorOf, repairCount,
} from '../lib/pin-record.mjs';
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
/** The four v3 blocks with every switch off, as both writers write them by default. */
const OFF = () => ({
  barrierCalls: { enabled: false, sites: [], barrierCount: 0, wouldBarrierCount: 0 },
  zeroCopy: { enabled: false, sites: [], repairedCount: 0, wouldRepairCount: 0 },
  bufferBarriers: { enabled: false, count: 0, sites: [] },
});
/** host as each writer fills it on its own compiler (wipe-pin.md §14.7). */
const CLANG_HOST = { ident: 'Ubuntu clang version 18.1.3', identMajor: 18, builtMajor: 18, checked: true, intrinsicsCompared: null };
const GCC_HOST = { ident: '13.3.0', identMajor: 13, builtMajor: 13, checked: true, intrinsicsCompared: null };
const U0 = () => Object.fromEntries(UNHANDLED_KEYS.map((k) => [k, 0]));
/** One resolution entry (unchanged since v2). */
function res(name, resolution = 'resolved', { exact = resolution === 'resolved' ? true : null, linkage = resolution === 'resolved' ? 'external' : null } = {}) {
  return { name, resolution, exact, linkage };
}
/** One pinned entry for encrypt_blob (unchanged since v2). */
function site(over = {}) {
  return { function: 'encrypt_blob', index: 0, lengthBytes: 32, destKind: 'alloca', alreadyVolatile: false, line: 41, followedByUse: false, ...over };
}
function unsealed(over = {}) {
  const rec = {
    schemaVersion: 'wipe-pin-v3',
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
    unhandled: U0(),
    toolchain: CLANG_TC,
    ...OFF(),
    evidenceDigest: '0'.repeat(64),
    context: { generatedAt: 1, sourceDateEpoch: null, timeSource: 'wall-clock' },
    ...over,
  };
  // host follows the component unless the test sets it: each writer reads its own compiler
  if (!('host' in over)) rec.host = rec.component === 'WipePinGcc' ? { ...GCC_HOST } : { ...CLANG_HOST };
  return rec;
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

test('an unknown schemaVersion is refused, and v0, v1 and v2 are no longer known', () => {
  assert.equal(SCHEMA_VERSION, 'wipe-pin-v3');
  refused(good({ schemaVersion: 'wipe-pin-v0' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: 'wipe-pin-v1' }), EXPECT, /unknown-schemaVersion/);
  refused(good({ schemaVersion: 'wipe-pin-v2' }), EXPECT, /unknown-schemaVersion: "wipe-pin-v2" \(this reader knows wipe-pin-v3\)/);
  refused(good({ schemaVersion: 'wipe-pin-v4' }), EXPECT, /unknown-schemaVersion/);
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
  // and with v1's name on an otherwise valid v3 record, the version alone refuses it
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

// ---- since v2: two components, one reader ----

test('a WipePin record with the clang toolchain is accepted', () => {
  const r = validatePinRecord(good(), EXPECT);
  assert.deepEqual(r.problems, []);
  assert.equal(validatePinRecord(good(), { ...EXPECT, component: undefined }).ok, true, 'expect.component left out is not compared');
});

test('a WipePinGcc record with the gcc toolchain is accepted', () => {
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

test('a WipePinGcc record has no atomic or inline-wrapper memsets, and no inline-wrapper bzero, to count', () => {
  const U = U0();
  assert.deepEqual([...GCC_ALWAYS_ZERO], ['atomicMemset', 'inlineWrapperMemset', 'inlineWrapperBzero']);
  for (const k of GCC_ALWAYS_ZERO) {
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

// ---- v3 (wipe-pin.md §14): the four blocks, nine counters, the handshake ----

/** The two constructed examples of wipe-pin.md §14.11, read out of the contract itself. */
function schemaExamples() {
  const md = readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'schema', 'wipe-pin.md'), 'utf8');
  const sec = md.slice(md.indexOf('### 14.11'));
  return [...sec.matchAll(/```json\n(\{.*\})\n```/g)].map((m) => JSON.parse(m[1]));
}
const V3_EXPECT_CLANG = { component: 'WipePin', scope: 'functions', dryRun: false, opt: '-O2', module: 'session.c',
  requested: ['close_session'], barrierCalls: true, zeroCopy: true, bufferBarriers: false };
const V3_EXPECT_GCC = { component: 'WipePinGcc', scope: 'module', dryRun: true, opt: '-O2', module: 'session.c',
  barrierCalls: true, zeroCopy: true, bufferBarriers: false };
/** One barrier site, one zero-copy site and one buffer site, in encrypt_blob. */
const bsite = (over = {}) => ({ function: 'encrypt_blob', callee: 'memset.inline', lengthBytes: 32, line: 57, ...over });
const zsite = (over = {}) => ({ function: 'encrypt_blob', form: 'call', callee: 'memcpy.inline', source: 'zero_block', destKind: 'alloca', lengthBytes: 64, line: 58, ...over });
const fsite = (over = {}) => ({ function: 'encrypt_blob', buffer: 'key', bytes: 32, reason: 'memset', anchor: 'lifetime-end', ...over });
const barrierOn = (sites = [bsite()], dry = false) => ({ enabled: true, sites, barrierCount: dry ? 0 : sites.length, wouldBarrierCount: sites.length });
const zeroOn = (sites = [zsite()], dry = false) => ({ enabled: true, sites, repairedCount: dry ? 0 : sites.length, wouldRepairCount: sites.length });

test('the two examples of wipe-pin.md §14.11 are accepted as the compiles they describe', () => {
  const ex = schemaExamples();
  assert.equal(ex.length, 2, 'wipe-pin.md §14.11 no longer holds two ```json examples');
  const [clang, gcc] = ex;
  assert.deepEqual(validatePinRecord(clang, V3_EXPECT_CLANG).problems, []);
  assert.deepEqual(validatePinRecord(gcc, V3_EXPECT_GCC).problems, []);
  // and the keys this reader holds are the keys the contract writes, in both
  for (const r of ex) {
    assert.deepEqual(Object.keys(r).sort(), [...TOP_KEYS].sort());
    assert.deepEqual(Object.keys(r.unhandled).sort(), [...UNHANDLED_KEYS].sort());
    assert.deepEqual(Object.keys(r.context).sort(), [...CONTEXT_KEYS].sort());
  }
  assert.equal(TOP_KEYS.length, 20);
  assert.equal(UNHANDLED_KEYS.length, 9);
  assert.deepEqual([...UNHANDLED_KEYS].slice(0, 5), [...UNHANDLED_KEYS_V2], 'v3 keeps the five v2 counters, in order, and adds four');
  assert.deepEqual(Object.values(SWITCHES), ['WPIN_BARRIER_CALLS', 'WPIN_ZERO_COPY', 'WPIN_BUFFER_BARRIER']);
});

test('a v2 record, exactly as a v2 writer wrote it, is refused by its version and by the shape v3 adds', () => {
  const v2 = good({ schemaVersion: 'wipe-pin-v2', unhandled: Object.fromEntries(UNHANDLED_KEYS_V2.map((k) => [k, 0])) });
  for (const k of ['barrierCalls', 'zeroCopy', 'bufferBarriers', 'host']) delete v2[k];
  const r = refused(v2, EXPECT, /unknown-schemaVersion: "wipe-pin-v2"/);
  for (const want of ['missing-field: barrierCalls', 'missing-field: zeroCopy', 'missing-field: bufferBarriers', 'missing-field: host',
    'missing-field: unhandled.bzeroCall', 'missing-field: unhandled.inlineWrapperBzero', 'missing-field: unhandled.zeroGlobalCopy',
    'missing-field: unhandled.zeroGlobalCopyCall']) {
    assert.ok(r.problems.includes(want), `${want} not in ${JSON.stringify(r.problems)}`);
  }
});

test('S2: unhandled has exactly the nine keys, each a count', () => {
  refused(good({ unhandled: Object.fromEntries(UNHANDLED_KEYS_V2.map((k) => [k, 0])) }), EXPECT, /missing-field: unhandled\.bzeroCall/);
  refused(good({ unhandled: { ...U0(), zeroGlobalCopyMemmove: 0 } }), EXPECT, /unknown-field: unhandled\.zeroGlobalCopyMemmove/);
  refused(good({ unhandled: { ...U0(), bzeroCall: -1 } }), EXPECT, /not-a-count: unhandled\.bzeroCall/);
  refused(good({ unhandled: { ...U0(), zeroGlobalCopyCall: 0.5 } }), EXPECT, /not-a-count: unhandled\.zeroGlobalCopyCall/);
  // WipePin may count every one of the four new shapes
  for (const k of ['bzeroCall', 'inlineWrapperBzero', 'zeroGlobalCopy', 'zeroGlobalCopyCall']) {
    assert.equal(validatePinRecord(good({ unhandled: { ...U0(), [k]: 2 } }), EXPECT).ok, true, k);
  }
  // WipePinGcc may count bzero and the two copy keys, and never inlineWrapperBzero
  for (const k of ['bzeroCall', 'zeroGlobalCopy', 'zeroGlobalCopyCall']) {
    assert.equal(validatePinRecord(good({ component: 'WipePinGcc', toolchain: GCC_TC, unhandled: { ...U0(), [k]: 1 } }), EXPECT_GCC).ok, true, k);
  }
});

test('S3-S5: the blocks the gcc patches wrote (bare counts) are refused, and so is every mistyped field', () => {
  // the shapes of patch 03 and patch 06, which wipe-pin.md §14.1 replaces
  refused(good({ barrierCalls: { barrierCount: 0 } }), EXPECT, /missing-field: barrierCalls\.enabled/);
  refused(good({ zeroCopy: { repairedCount: 0, wouldRepairCount: 1 } }), EXPECT, /missing-field: zeroCopy\.sites/);
  refused(good({ barrierCalls: { ...OFF().barrierCalls, enabled: 1 } }), EXPECT, /barrierCalls\.enabled must be a boolean/);
  refused(good({ barrierCalls: { ...OFF().barrierCalls, sites: {} } }), EXPECT, /barrierCalls\.sites must be an array/);
  refused(good({ barrierCalls: { ...OFF().barrierCalls, barrierCount: '0' } }), EXPECT, /not-a-count: barrierCalls\.barrierCount/);
  refused(good({ barrierCalls: { ...OFF().barrierCalls, extra: 0 } }), EXPECT, /unknown-field: barrierCalls\.extra/);
  refused(good({ barrierCalls: barrierOn([bsite({ callee: '' })]) }), {}, /barrierCalls\.sites\[0\]\.callee must be a non-empty string/);
  refused(good({ barrierCalls: barrierOn([{ ...bsite(), lengthBytes: 1.5 }]) }), {}, /not-a-count: barrierCalls\.sites\[0\]\.lengthBytes/);
  refused(good({ barrierCalls: barrierOn([{ function: 'encrypt_blob', callee: 'memset', lengthBytes: 32 }]) }), {}, /missing-field: barrierCalls\.sites\[0\]\.line/);
  refused(good({ zeroCopy: zeroOn([zsite({ destKind: 'stack' })]) }), {}, /bad-destKind: zeroCopy\.sites\[0\]\.destKind "stack"/);
  refused(good({ zeroCopy: zeroOn([zsite({ callee: '' })]) }), {}, /zeroCopy\.sites\[0\]\.callee must be a non-empty string or null/);
  refused(good({ zeroCopy: zeroOn([zsite({ source: null })]) }), {}, /zeroCopy\.sites\[0\]\.source must be a string/);
  refused(good({ zeroCopy: zeroOn([zsite({ form: 7 })]) }), {}, /zeroCopy\.sites\[0\]\.form must be a string/);
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ reason: 'wipe' })] } }), {}, /bad-reason: bufferBarriers\.sites\[0\]\.reason "wipe"/);
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ anchor: 'end' })] } }), {}, /bad-anchor: bufferBarriers\.sites\[0\]\.anchor "end"/);
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ buffer: '' })] } }), {}, /bufferBarriers\.sites\[0\]\.buffer must be a non-empty string or null/);
  refused(good({ bufferBarriers: { enabled: false, count: 0 } }), {}, /missing-field: bufferBarriers\.sites/);
  // null is admitted where §14 admits it, and only there
  assert.equal(validatePinRecord(good({ barrierCalls: barrierOn([bsite({ lengthBytes: null, line: null })]) }), {}).ok, true);
  assert.equal(validatePinRecord(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ buffer: null, bytes: null })] } }), {}).ok, true);
});

test('S6: host is typed exactly, and the patch-era `mismatch` key is not one of its keys', () => {
  refused(good({ host: { ...CLANG_HOST, mismatch: false } }), EXPECT, /unknown-field: host\.mismatch/);
  refused(good({ host: { ...CLANG_HOST, identMajor: 0 } }), EXPECT, /host\.identMajor must be an integer >= 1 or null/);
  refused(good({ host: { ...CLANG_HOST, builtMajor: null } }), EXPECT, /host\.builtMajor must be an integer >= 1/);
  refused(good({ host: { ...CLANG_HOST, checked: 'yes' } }), EXPECT, /host\.checked must be a boolean/);
  refused(good({ host: { ...CLANG_HOST, intrinsicsCompared: -1 } }), EXPECT, /host\.intrinsicsCompared must be an integer >= 0 or null/);
  refused(good({ host: { ...CLANG_HOST, ident: 18 } }), EXPECT, /host\.ident must be a string or null/);
  refused(good({ host: null }), EXPECT, /host must be an object/);
  // a build that implements the M6 self-check reports how many llvm.* declarations it compared
  assert.equal(validatePinRecord(good({ host: { ...CLANG_HOST, intrinsicsCompared: 12 } }), EXPECT).ok, true);
});

test('context holds exactly its three keys (§14.8)', () => {
  refused(good({ context: { generatedAt: 1, sourceDateEpoch: null, timeSource: 'wall-clock', host: 'x' } }), EXPECT, /unknown-field: context\.host/);
  refused(good({ context: { generatedAt: 1, timeSource: 'wall-clock' } }), EXPECT, /missing-field: context\.sourceDateEpoch/);
});

test('C1: a block that is not enabled lists nothing and counts nothing', () => {
  refused(good({ barrierCalls: { enabled: false, sites: [bsite()], barrierCount: 0, wouldBarrierCount: 0 } }), {},
    /inconsistent: barrierCalls\.enabled is false but barrierCalls\.sites lists 1 site/);
  refused(good({ zeroCopy: { enabled: false, sites: [], repairedCount: 0, wouldRepairCount: 1 } }), {},
    /inconsistent: zeroCopy\.enabled is false but zeroCopy\.wouldRepairCount is 1/);
  refused(good({ bufferBarriers: { enabled: false, count: 1, sites: [] } }), {}, /bufferBarriers\.enabled is false but bufferBarriers\.count is 1/);
});

test('C2/C3: the would-count is the list, a dry run repairs nothing, and outside one every listed site is repaired', () => {
  // accepted: enabled, both modes
  assert.equal(validatePinRecord(good({ barrierCalls: barrierOn(), zeroCopy: zeroOn() }), {}).ok, true);
  assert.equal(validatePinRecord(good({ dryRun: true, pinnedCount: 0, barrierCalls: barrierOn([bsite()], true), zeroCopy: zeroOn([zsite()], true) }),
    {}).ok, true);
  // enabled with nothing to repair is not a contradiction
  assert.equal(validatePinRecord(good({ barrierCalls: barrierOn([]) }), {}).ok, true);
  // a dry run that says it placed a barrier, or repaired a copy
  refused(good({ dryRun: true, pinnedCount: 0, barrierCalls: { ...barrierOn(), barrierCount: 1 } }), {},
    /inconsistent: dry run with barrierCalls\.barrierCount 1/);
  refused(good({ dryRun: true, pinnedCount: 0, zeroCopy: { ...zeroOn(), repairedCount: 1 } }), {}, /dry run with zeroCopy\.repairedCount 1/);
  // a GCC barrier that could not be placed (barrierCount below the list)
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, barrierCalls: { ...barrierOn([bsite({ callee: 'bzero' })]), barrierCount: 0 } }), {},
    /outside a dry run barrierCalls\.barrierCount 0 differs from barrierCalls\.wouldBarrierCount 1/);
  // a would-count that is not the list
  refused(good({ barrierCalls: { ...barrierOn(), wouldBarrierCount: 2, barrierCount: 2 } }), {}, /barrierCalls\.wouldBarrierCount 2, but barrierCalls\.sites lists 1/);
  refused(good({ zeroCopy: { ...zeroOn(), wouldRepairCount: 0, repairedCount: 0 } }), {}, /zeroCopy\.wouldRepairCount 0, but zeroCopy\.sites lists 1/);
});

test('C4: bufferBarriers counts its sites outside a dry run and nothing in one', () => {
  assert.equal(validatePinRecord(good({ bufferBarriers: { enabled: true, count: 2, sites: [fsite(), fsite({ anchor: 'ret' })] } }), {}).ok, true);
  assert.equal(validatePinRecord(good({ dryRun: true, pinnedCount: 0, bufferBarriers: { enabled: true, count: 0, sites: [fsite()] } }), {}).ok, true);
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite(), fsite()] } }), {}, /bufferBarriers\.count 1, but bufferBarriers\.sites lists 2/);
  refused(good({ dryRun: true, pinnedCount: 0, bufferBarriers: { enabled: true, count: 1, sites: [fsite()] } }), {}, /dry run with bufferBarriers\.count 1/);
});

test('C5: in functions scope every site of the three blocks is in a requested function', () => {
  refused(good({ barrierCalls: barrierOn([bsite({ function: 'helper' })]) }), {}, /barrierCalls site in helper, which was not requested/);
  refused(good({ zeroCopy: zeroOn([zsite({ function: 'vgctl_control' })]) }), {}, /zeroCopy site in vgctl_control/);
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ function: 'helper' })] } }), {}, /bufferBarriers site in helper/);
  // module scope names no function, so any function may carry a site
  assert.equal(validatePinRecord(good({ scope: 'module', requested: [], resolution: [], barrierCalls: barrierOn([bsite({ function: 'helper' })]) }), {}).ok, true);
});

test('C6: the handshake -- checked iff a major was read, the major is the build\'s, and it re-derives from ident', () => {
  // no ident, or an ident with no clang version: a record, unchecked (D26)
  const unchecked = { ident: null, identMajor: null, builtMajor: 18, checked: false, intrinsicsCompared: null };
  assert.equal(validatePinRecord(good({ host: unchecked }), EXPECT).ok, true);
  assert.equal(validatePinRecord(good({ host: { ...unchecked, ident: 'Apple LLVM' } }), EXPECT).ok, true);
  refused(good({ host: { ...CLANG_HOST, identMajor: null } }), EXPECT, /host\.checked true with host\.identMajor null/);
  refused(good({ host: { ...unchecked, checked: true } }), EXPECT, /host\.checked true with host\.identMajor null/);
  // a mismatch writes no record, so a record showing one is refused
  refused(good({ host: { ...CLANG_HOST, ident: 'Ubuntu clang version 19.1.1', identMajor: 19 } }), EXPECT,
    /host\.identMajor 19 differs from host\.builtMajor 18 \(a version mismatch writes no record\)/);
  refused(good({ host: { ...CLANG_HOST, ident: 'Ubuntu clang version 17.0.6' } }), EXPECT, /host\.identMajor 18 does not re-derive from host\.ident/);
  refused(good({ host: { ...CLANG_HOST, ident: 'Ubuntu clang version 18.1.3 (1ubuntu1)' } }), EXPECT, /host\.ident keeps a parenthesised group/);
  refused(good({ host: { ...CLANG_HOST, builtMajor: 19, identMajor: 19, ident: 'clang version 19.1.1' } }), EXPECT,
    /host\.builtMajor 19 is not the major version of toolchain\.clang "18\.1\.3"/);
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, host: { ...GCC_HOST, ident: '14.2.0', identMajor: 14, builtMajor: 14 } }), EXPECT_GCC,
    /host\.builtMajor 14 is not the major version of toolchain\.gcc "13\.3\.0"/);
});

test('C7: per-vendor value sets -- zeroCopy forms and callees, barrier callees, anchors, and the GCC host', () => {
  // WipePin: intrinsic <-> llvm.memcpy; call <-> the memcpy family
  assert.equal(validatePinRecord(good({ zeroCopy: zeroOn([zsite({ form: 'intrinsic', callee: 'llvm.memcpy' })]) }), {}).ok, true);
  for (const c of ['memcpy', '__memcpy_chk', 'memcpy.inline']) assert.equal(validatePinRecord(good({ zeroCopy: zeroOn([zsite({ callee: c })]) }), {}).ok, true, c);
  refused(good({ zeroCopy: zeroOn([zsite({ form: 'intrinsic' })]) }), {}, /zeroCopy\.sites\[0\] has form intrinsic and callee "memcpy\.inline"/);
  refused(good({ zeroCopy: zeroOn([zsite({ callee: 'llvm.memcpy' })]) }), {}, /has form call and callee "llvm\.memcpy"/);
  refused(good({ zeroCopy: zeroOn([zsite({ callee: 'memmove' })]) }), {}, /bad-callee: zeroCopy\.sites\[0\]\.callee "memmove"/);
  refused(good({ zeroCopy: zeroOn([zsite({ form: 'aggregate', callee: null })]) }), {}, /bad-form: zeroCopy\.sites\[0\]\.form "aggregate" on a WipePin record/);
  // WipePinGcc: callee null exactly for aggregate
  const G = (z, over = {}) => good({ component: 'WipePinGcc', toolchain: GCC_TC, zeroCopy: zeroOn(z), ...over });
  assert.equal(validatePinRecord(G([zsite({ form: 'aggregate', callee: null })]), {}).ok, true);
  assert.equal(validatePinRecord(G([zsite({ form: 'builtin', callee: 'memcpy' })]), {}).ok, true);
  assert.equal(validatePinRecord(G([zsite({ form: 'call', callee: '__builtin___memcpy_chk' })]), {}).ok, true, 'GCC callee spellings are not enumerated');
  refused(G([zsite({ form: 'aggregate', callee: 'memcpy' })]), {}, /has form aggregate and callee "memcpy" \(callee null exactly for form aggregate\)/);
  refused(G([zsite({ form: 'builtin', callee: null })]), {}, /has form builtin and callee null/);
  refused(G([zsite({ form: 'intrinsic', callee: 'llvm.memcpy' })]), {}, /bad-form: .* on a WipePinGcc record/);
  // WipePin barrier callees: the memset and bzero families only
  for (const c of ['memset', '__memset_chk', 'bzero', 'memset.inline', 'bzero.inline']) {
    assert.equal(validatePinRecord(good({ barrierCalls: barrierOn([bsite({ callee: c })]) }), {}).ok, true, c);
  }
  refused(good({ barrierCalls: barrierOn([bsite({ callee: 'explicit_bzero' })]) }), {}, /bad-callee: barrierCalls\.sites\[0\]\.callee "explicit_bzero"/);
  assert.equal(validatePinRecord(good({ component: 'WipePinGcc', toolchain: GCC_TC, barrierCalls: barrierOn([bsite({ callee: '__builtin___memset_chk' })]) }), {}).ok,
    true, 'GCC barrier callees are its DECL_NAMEs, not enumerated');
  // anchors per vendor
  refused(good({ bufferBarriers: { enabled: true, count: 1, sites: [fsite({ anchor: 'clobber' })] } }), {}, /bad-anchor: bufferBarriers\.sites\[0\]\.anchor clobber on a WipePin record/);
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, bufferBarriers: { enabled: true, count: 1, sites: [fsite({ anchor: 'lifetime-end' })] } }), {},
    /anchor lifetime-end on a WipePinGcc record/);
  // the GCC host is always checked, with an ident, and never compares intrinsics
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, host: { ident: null, identMajor: null, builtMajor: 13, checked: false, intrinsicsCompared: null } }), {},
    /a WipePinGcc record's host must be checked, with an ident/);
  refused(good({ component: 'WipePinGcc', toolchain: GCC_TC, host: { ...GCC_HOST, intrinsicsCompared: 3 } }), {}, /host\.intrinsicsCompared must be null on a WipePinGcc record/);
});

test('W1: each switch the caller states must be what the record says; the repair loop states false for all three', () => {
  const OFF_EXPECT = { ...EXPECT, barrierCalls: false, zeroCopy: false, bufferBarriers: false };
  assert.equal(validatePinRecord(good(), OFF_EXPECT).ok, true);
  refused(good({ barrierCalls: barrierOn() }), OFF_EXPECT, /wrong-compile: barrierCalls\.enabled true, this compile did not set WPIN_BARRIER_CALLS=1/);
  refused(good({ zeroCopy: zeroOn() }), OFF_EXPECT, /wrong-compile: zeroCopy\.enabled true, this compile did not set WPIN_ZERO_COPY=1/);
  refused(good({ bufferBarriers: { enabled: true, count: 0, sites: [] } }), OFF_EXPECT, /wrong-compile: bufferBarriers\.enabled true, this compile did not set WPIN_BUFFER_BARRIER=1/);
  refused(good(), { ...EXPECT, zeroCopy: true }, /wrong-compile: zeroCopy\.enabled false, this compile set WPIN_ZERO_COPY=1/);
  // a switch left out of expect is not compared
  assert.equal(validatePinRecord(good({ barrierCalls: barrierOn() }), EXPECT).ok, true);
  refused(good(), { ...EXPECT, barrierCalls: '1' }, /bad-expect: barrierCalls must be true or false/);
});

test('stripIdent and identMajorOf give the §14.7 table for every installed compiler', () => {
  const clang = [
    ['Ubuntu clang version 15.0.7', 'Ubuntu clang version 15.0.7', 15],
    ['Ubuntu clang version 16.0.6 (23ubuntu4)', 'Ubuntu clang version 16.0.6', 16],
    ['Ubuntu clang version 17.0.6 (9ubuntu1)', 'Ubuntu clang version 17.0.6', 17],
    ['Ubuntu clang version 18.1.3 (1ubuntu1)', 'Ubuntu clang version 18.1.3', 18],
    ['Ubuntu clang version 19.1.1 (1ubuntu1~24.04.2)', 'Ubuntu clang version 19.1.1', 19],
    ['Ubuntu clang version 20.1.2 (0ubuntu1~24.04.3)', 'Ubuntu clang version 20.1.2', 20],
    // a local checkout's path is inside the group and goes with it; nested groups and a stray ')' too
    ['clang version 19.1.0 (/home/user/llvm-project 0123abc)', 'clang version 19.1.0', 19],
    ['Android (8490178, based on r450784d) clang version 14.0.6 (https://x/llvm-project 4c603efb)', 'Android clang version 14.0.6', 14],
    ['clang version 18.1.3 (a (nested) b)) trailing', 'clang version 18.1.3 trailing', 18],
  ];
  for (const [raw, ident, major] of clang) {
    assert.equal(stripIdent(raw), ident, raw);
    assert.equal(identMajorOf('WipePin', stripIdent(raw)), major, raw);
  }
  for (const [v, major] of [['10.5.0', 10], ['11.5.0', 11], ['12.4.0', 12], ['13.3.0', 13], ['14.2.0', 14]]) assert.equal(identMajorOf('WipePinGcc', v), major);
  assert.equal(identMajorOf('WipePin', null), null);
  assert.equal(identMajorOf('WipePin', 'GCC: 13.3.0'), null);
  assert.equal(identMajorOf('WipePinGcc', '13'), null, 'the GCC major is the digits before a dot');
});

test('repairCount is the §14.8 sum, so a barrier-only repair is a repair', () => {
  assert.equal(repairCount(good()), 1);
  assert.equal(repairCount(good({ pinned: [], pinnedCount: 0, wouldPinCount: 0, seen: { zeroFillMemsetInScope: 0, zeroFillMemsetInModule: 0 },
    barrierCalls: barrierOn() })), 1);
  assert.equal(repairCount(good({ barrierCalls: barrierOn([bsite(), bsite({ line: 60 })]), zeroCopy: zeroOn(),
    bufferBarriers: { enabled: true, count: 1, sites: [fsite()] } })), 5);
  assert.equal(repairCount(good({ dryRun: true, pinnedCount: 0, barrierCalls: barrierOn([bsite()], true) })), 0, 'a dry run repairs nothing');
  assert.equal(repairCount(null), 0);
});
