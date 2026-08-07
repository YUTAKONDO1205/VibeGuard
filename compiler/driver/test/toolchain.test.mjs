import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  locateExecutable, loadPin, pinnedSet, reconcileCompiler, resolveCompiler, verifyPin,
} from '../lib/toolchain.mjs';
import {
  CLANG, evidenceRecords, liveBuildSkipReason, makePin, makeScratch, makeSyntheticPin,
  posixFakeCompilerSkipReason, runDriver, sha256File, writeFakeCompiler,
} from './helpers.mjs';

function writePin(pin) {
  const dir = makeScratch('pin');
  const p = join(dir, 'toolchain.pin.json');
  writeFileSync(p, typeof pin === 'string' ? pin : JSON.stringify(pin), 'utf8');
  return p;
}

test('a pin with the wrong version does not load', () => {
  const r = loadPin(writePin({ pinVersion: 'toolchain-pin-v1', packages: [] }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-version');
});

test('a pin that pins nothing is not a pin', () => {
  const r = loadPin(writePin({ pinVersion: 'toolchain-pin-v0', packages: [] }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-packages');
});

test('a package entry without a well-formed digest does not load', () => {
  const r = loadPin(writePin({
    pinVersion: 'toolchain-pin-v0',
    packages: [{ name: 'clang-18', path: 'usr/bin/clang-18', sha256: 'nope' }],
  }));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-package');
});

test('a missing pin file is reported, not treated as an empty pin', () => {
  const r = loadPin(join(makeScratch('pin-missing'), 'absent.json'));
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'unreadable');
});

test('the installed toolchain matches a pin generated from it', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'match', JSON.stringify(v.mismatches));
  assert.equal(v.reportedClang, pin.clang);
});

test('one changed character in a pinned digest is a mismatch', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const original = pin.packages[0].sha256;
  pin.packages[0].sha256 = flipOneHexChar(original);
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  const m = v.mismatches.find((x) => x.kind === 'digest');
  assert.ok(m, 'expected a digest mismatch');
  assert.equal(m.actual, original);
});

test('a pinned file that is not there is a mismatch of its own kind', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  pin.packages[0].path = 'usr/bin/clang-18-that-does-not-exist';
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  assert.equal(v.mismatches[0].kind, 'missing');
});

test('a version disagreement is a mismatch even when every digest matches', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  pin.clang = '17.0.6';
  const v = verifyPin(pin, { ccPath: CLANG });
  assert.equal(v.status, 'mismatch');
  assert.equal(v.mismatches.find((m) => m.kind === 'version').actual, '18.1.3');
});

test('the digested pinned set carries no path', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  const set = pinnedSet(pin, verifyPin(pin, { ccPath: CLANG }));
  assert.equal(JSON.stringify(set).includes('/'), false, JSON.stringify(set));
});

test('the compiler comes from the pin when the pin names one', { skip: liveBuildSkipReason() }, () => {
  const pin = makePin();
  assert.equal(resolveCompiler({ mode: 'c', pin, override: null }).source, 'pin');
  assert.equal(resolveCompiler({ mode: 'c', pin: null, override: null }).path, 'clang-18');
  assert.equal(resolveCompiler({ mode: 'cxx', pin: null, override: null }).path, 'clang++-18');
});

function flipOneHexChar(hex) {
  const c = hex[0];
  return (c === '0' ? '1' : '0') + hex.slice(1);
}

// ---------------------------------------------------------------------------
// The pin covers the binary that actually runs
//
// Every check below is paired. A reconciliation that only ever says
// "outside-pin" would pass the adversarial fixtures and fail every real build,
// so each positive has the negative that shows it can say "in-pin" too.
// ---------------------------------------------------------------------------

/** A directory holding a pinned stand-in compiler and, optionally, a decoy. */
function pinLab(label) {
  const dir = makeScratch(label);
  const pinned = writeFakeCompiler(dir, 'cc-pinned');
  const pin = makeSyntheticPin(dir, [{ name: 'cc-pinned' }]);
  return { dir, pinned, pin };
}

test('the pinned compiler reconciles with the pin — the negative for everything below', () => {
  const { pin } = pinLab('recon-ok');
  const compiler = resolveCompiler({ mode: 'c', pin, override: null });
  const r = reconcileCompiler({ pin, compiler });
  assert.equal(r.status, 'in-pin');
  assert.equal(r.inPinSet, true);
  assert.equal(r.pinnedAs, 'cc-pinned');
  assert.equal(r.overriddenByFlag, false);
});

test('a byte-identical copy at another path is outside the pin — the digest is right and the file is not', () => {
  const { dir, pinned, pin } = pinLab('recon-copy');
  const decoy = join(dir, 'cc-decoy');
  copyFileSync(pinned, decoy);
  // Same bytes: `verifyPin` cannot tell these apart, which is the whole point.
  assert.equal(sha256File(decoy), pin.packages[0].sha256);

  const r = reconcileCompiler({ pin, compiler: { path: decoy, source: 'flag' } });
  assert.equal(r.status, 'outside-pin');
  assert.equal(r.inPinSet, false);
  assert.equal(r.pinnedAs, null);
});

test('a symlink to the pinned file is the pinned file — realpath is resolved on both sides', { skip: posixFakeCompilerSkipReason() }, () => {
  const { dir, pinned, pin } = pinLab('recon-symlink');
  const link = join(dir, 'cc-link');
  symlinkSync(pinned, link);
  const r = reconcileCompiler({ pin, compiler: { path: link, source: 'flag' } });
  assert.equal(r.status, 'in-pin', r.detail);
  assert.equal(r.pinnedAs, 'cc-pinned');
});

test('the pin naming a symlink still reconciles with the file behind it', { skip: posixFakeCompilerSkipReason() }, () => {
  const dir = makeScratch('recon-pin-symlink');
  const real = writeFakeCompiler(dir, 'cc-real');
  symlinkSync(real, join(dir, 'cc-link'));
  const pin = makeSyntheticPin(dir, [{ name: 'cc-link' }]);
  const r = reconcileCompiler({ pin, compiler: { path: real, source: 'pin' } });
  assert.equal(r.status, 'in-pin', r.detail);
});

test('a compiler that is not on this machine is unresolvable, which is not in the pin', () => {
  const { dir, pin } = pinLab('recon-missing');
  const r = reconcileCompiler({ pin, compiler: { path: join(dir, 'cc-absent'), source: 'flag' } });
  assert.equal(r.status, 'unresolvable');
  assert.equal(r.inPinSet, false);
});

test('with no pin there is nothing to reconcile against, and that is said rather than passed', () => {
  const { pinned } = pinLab('recon-nopin');
  const r = reconcileCompiler({ pin: null, compiler: { path: pinned, source: 'path' } });
  assert.equal(r.status, 'not-configured');
  assert.equal(r.inPinSet, null);
});

test('reconciliation never lets an absolute path into its detail string', () => {
  const { dir, pinned, pin } = pinLab('recon-detail');
  const decoy = join(dir, 'cc-decoy');
  copyFileSync(pinned, decoy);
  for (const r of [
    reconcileCompiler({ pin, compiler: { path: decoy, source: 'flag' } }),
    reconcileCompiler({ pin, compiler: { path: join(dir, 'nope'), source: 'flag' } }),
    reconcileCompiler({ pin: null, compiler: { path: decoy, source: 'flag' } }),
  ]) {
    assert.equal(r.detail.includes(dir), false, r.detail);
    assert.equal(/(^|\s)\//.test(r.detail), false, r.detail);
    assert.equal(/[A-Za-z]:[\\/]/.test(r.detail), false, r.detail);
  }
});

test('locateExecutable finds a bare name on PATH and reports nothing when it is not there', () => {
  const { dir } = pinLab('locate');
  const env = { PATH: dir, PATHEXT: '' };
  assert.equal(locateExecutable('cc-pinned', { env }), join(dir, 'cc-pinned'));
  assert.equal(locateExecutable('cc-not-here', { env }), null);
});

test('ADVERSARIAL: a fake that answers --version correctly satisfies verifyPin and is still not in the pin', () => {
  // The pin is intact: every pinned file hashes as pinned, and the compiler
  // reports exactly the version the pin names. Everything the driver used to
  // check is green. The executed file is a different one, and only the
  // reconciliation can say so.
  const { dir, pinned, pin } = pinLab('adversarial-unit');
  pin.clang = '18.1.3';
  const fake = writeFakeCompiler(dir, 'cc-fake', 'clang version 18.1.3 (fake)');
  assert.notEqual(sha256File(fake), sha256File(pinned));

  const v = verifyPin(pin, { ccPath: fake, probeVersion: () => '18.1.3' });
  assert.equal(v.status, 'match', JSON.stringify(v.mismatches));
  assert.equal(v.reportedClang, '18.1.3');

  const r = reconcileCompiler({ pin, compiler: { path: fake, source: 'flag' } });
  assert.equal(r.status, 'outside-pin');
  assert.equal(r.overriddenByFlag, true);
});

// ---------------------------------------------------------------------------
// packages[].version is compared
// ---------------------------------------------------------------------------

test('a pinned package version that agrees with the observed one is a match, not a silent record', () => {
  const { dir } = pinLab('version-ok');
  const pin = makeSyntheticPin(dir, [{ name: 'cc-pinned', version: '1:18.1.3-1ubuntu1' }]);
  const v = verifyPin(pin, { observePackageVersion: () => ({ version: '1:18.1.3-1ubuntu1', method: 'test' }) });
  assert.equal(v.status, 'match', JSON.stringify(v.mismatches));
  assert.deepEqual(v.unobserved, []);
  assert.equal(v.versions[0].verdict, 'match');
});

test('a pinned package version that disagrees is a mismatch of its own kind', () => {
  const { dir } = pinLab('version-bad');
  const pin = makeSyntheticPin(dir, [{ name: 'cc-pinned', version: '1:18.1.3-1ubuntu1' }]);
  const v = verifyPin(pin, { observePackageVersion: () => ({ version: '1:18.1.3-2ubuntu9', method: 'test' }) });
  assert.equal(v.status, 'mismatch');
  const m = v.mismatches.find((x) => x.kind === 'package-version');
  assert.ok(m, JSON.stringify(v.mismatches));
  assert.equal(m.expected, '1:18.1.3-1ubuntu1');
  assert.equal(m.actual, '1:18.1.3-2ubuntu9');
});

test('a pinned version nobody could read is unobserved, and unobserved is not a mismatch and not a pass', () => {
  const { dir } = pinLab('version-unobserved');
  const pin = makeSyntheticPin(dir, [{ name: 'cc-pinned', version: '1:18.1.3-1ubuntu1' }]);
  const v = verifyPin(pin, { observePackageVersion: () => ({ version: null, method: 'unavailable' }) });
  // Not exit 4 material: nothing disagreed. Not a pass either — the caller
  // turns this into VG-CFG-014 and exit 3.
  assert.equal(v.status, 'match');
  assert.equal(v.unobserved.length, 1);
  assert.equal(v.unobserved[0].kind, 'package-version-unobserved');
  assert.equal(v.versions[0].verdict, 'unobserved');
});

test('a pin that states no version states nothing, and says so', () => {
  const { dir } = pinLab('version-absent');
  const pin = makeSyntheticPin(dir, [{ name: 'cc-pinned' }]);
  let asked = 0;
  const v = verifyPin(pin, { observePackageVersion: () => { asked += 1; return { version: 'x', method: 'test' }; } });
  assert.equal(asked, 0, 'a version that is not pinned is not gone looking for');
  assert.equal(v.versions[0].verdict, 'not-pinned');
  assert.deepEqual(v.unobserved, []);
});

// ---------------------------------------------------------------------------
// The driver as a process
// ---------------------------------------------------------------------------

/**
 * A fixture whose pin covers files this test made, so that the pin gate can be
 * exercised on a host with no clang at all.
 */
function makePinFixture(label, { pinExtra = {}, policyOverrides = {} } = {}) {
  const dir = makeScratch(label);
  const src = join(dir, 'src');
  const evidence = join(dir, 'evidence');
  const bin = join(dir, 'bin');
  mkdirSync(src, { recursive: true });
  mkdirSync(evidence, { recursive: true });
  mkdirSync(bin, { recursive: true });

  writeFileSync(join(src, 'hello.c'), 'int main(void){return 0;}\n', 'utf8');
  const pinned = writeFakeCompiler(bin, 'cc-pinned');
  const pin = makeSyntheticPin(bin, [{ name: 'cc-pinned' }], pinExtra);
  writeFileSync(join(src, 'toolchain.pin.json'), `${JSON.stringify(pin, null, 2)}\n`, 'utf8');

  writeFileSync(join(src, '.vgpolicy.json'), `${JSON.stringify({
    policyVersion: 'policy-v0',
    failOn: 'critical',
    verification: { failOnIncomplete: false },
    toolchain: { pin: 'toolchain.pin.json', requireDigestMatch: true },
    flags: { optLevels: ['-O0', '-O2'] },
    evidence: { out: '../evidence', sourceDateEpoch: 1700000000 },
    ...policyOverrides,
  }, null, 2)}\n`, 'utf8');

  return { dir, src, bin, evidence, pinned, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('a compiler outside the pinned set is exit 4 even though every pinned digest matches', (t) => {
  const fx = makePinFixture('e2e-outside-pin');
  const fake = writeFakeCompiler(fx.bin, 'cc-fake', 'clang version 18.1.3 (fake)');

  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o', '--vg-clang', fake], { cwd: fx.src });
  assert.equal(r.status, 4, r.stderr);

  const rec = evidenceRecords(fx.evidence).find((x) => x.record.exitCode === 4);
  assert.ok(rec, 'the integrity failure is recorded');
  const ids = rec.record.findings.map((f) => f.id);
  assert.ok(ids.includes('VG-CFG-012'), JSON.stringify(ids));
  // The killer assertion: everything the pin check used to look at is clean.
  assert.equal(rec.record.checks.toolchainPin.mismatchCount, 0, JSON.stringify(rec.record.checks.toolchainPin.mismatches));
  assert.equal(rec.record.checks.toolchainPin.status, 'match');
  assert.equal(rec.record.toolchain.compiler.reconciliation, 'outside-pin');
  assert.equal(rec.record.build.shipping.attempted, false);
});

test('ADVERSARIAL, live: a fake clang that really prints the pinned version is still exit 4', { skip: posixFakeCompilerSkipReason() }, () => {
  const fx = makePinFixture('e2e-outside-pin-live', { pinExtra: { clang: '18.1.3' } });
  const fake = writeFakeCompiler(fx.bin, 'cc-fake', 'clang version 18.1.3 (Fake Distro 18.1.3-1)');

  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o', '--vg-clang', fake], { cwd: fx.src });
  assert.equal(r.status, 4, r.stderr);

  const rec = evidenceRecords(fx.evidence).find((x) => x.record.exitCode === 4);
  assert.ok(rec);
  // The version probe believed the fake — that is what makes it adversarial.
  assert.equal(rec.record.toolchain.clang, '18.1.3');
  assert.equal(rec.record.checks.toolchainPin.mismatchCount, 0);
  assert.ok(rec.record.findings.some((f) => f.id === 'VG-CFG-012'));
});

test('--vg-clang pointing back at the pinned binary is not exit 4, and is still confessed', () => {
  // The negative fixture for the detector above: the good case must not be
  // flagged as leaving the pinned set, while the override itself is recorded.
  const fx = makePinFixture('e2e-override-in-pin');
  const r = runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o', '--vg-clang', fx.pinned], { cwd: fx.src });
  assert.notEqual(r.status, 4, r.stderr);

  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec, r.stderr);
  const ids = rec.record.findings.map((f) => f.id);
  assert.equal(ids.includes('VG-CFG-012'), false, JSON.stringify(ids));
  assert.ok(ids.includes('VG-CFG-015'), JSON.stringify(ids));
  assert.equal(rec.record.toolchain.compiler.inPinSet, true);
  assert.equal(rec.record.toolchain.compiler.overriddenByFlag, true);
  assert.equal(rec.record.toolchain.compiler.pinnedAs, 'cc-pinned');
  assert.notEqual(rec.record.exitReason, 'toolchain-or-policy-integrity');
});

test('the override confession is inside the digest, and a context field is not', async () => {
  // Directly against the canonicaliser the records are digested with, in both
  // directions: the field that must move the digest moves it, and the subtree
  // that must not, does not.
  const { evidenceDigest } = await import('../../evidence/canon.mjs');
  const pinned = {
    toolchain: { compiler: { overriddenByFlag: false, resolvedFrom: 'pin' } },
    context: { generatedAt: 'a' },
  };
  const overridden = {
    toolchain: { compiler: { overriddenByFlag: true, resolvedFrom: 'flag' } },
    context: { generatedAt: 'a' },
  };
  const laterClock = {
    toolchain: { compiler: { overriddenByFlag: false, resolvedFrom: 'pin' } },
    context: { generatedAt: 'b' },
  };
  assert.notEqual(evidenceDigest(pinned), evidenceDigest(overridden));
  assert.equal(evidenceDigest(pinned), evidenceDigest(laterClock));
});

test('the record no longer carries the compiler in the undigested subtree', () => {
  const fx = makePinFixture('e2e-confession-place');
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec);
  assert.equal(rec.record.context.compiler, undefined, 'context is excluded from the digest as a whole subtree');
  assert.equal(typeof rec.record.toolchain.compiler.overriddenByFlag, 'boolean');
});

test('two builds that differ only in whether the pin was overridden get different record digests', () => {
  const a = makePinFixture('e2e-digest-pinned');
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: a.src });
  const b = makePinFixture('e2e-digest-overridden');
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o', '--vg-clang', b.pinned], { cwd: b.src });

  const ra = evidenceRecords(a.evidence)[0];
  const rb = evidenceRecords(b.evidence)[0];
  assert.ok(ra && rb);
  assert.equal(ra.record.toolchain.compiler.overriddenByFlag, false);
  assert.equal(rb.record.toolchain.compiler.overriddenByFlag, true);
  assert.notEqual(ra.record.evidenceDigest, rb.record.evidenceDigest);
});

test('a pinned version this machine cannot observe is a finding, not a silent record', () => {
  const fx = makePinFixture('e2e-version-unobserved');
  // Rewrite the pin so it states a package version. Nothing here can observe a
  // dpkg version for a file a test made, which is the point.
  const pinPath = join(fx.src, 'toolchain.pin.json');
  const pin = JSON.parse(readFileSync(pinPath, 'utf8'));
  pin.packages[0].version = '1:18.1.3-1ubuntu1';
  writeFileSync(pinPath, JSON.stringify(pin, null, 2), 'utf8');

  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec);
  assert.ok(rec.record.findings.some((f) => f.id === 'VG-CFG-014'), JSON.stringify(rec.record.findings.map((f) => f.id)));
  assert.equal(rec.record.checks.toolchainPin.unobservedCount, 1);
  assert.equal(rec.record.checks.toolchainPin.versions[0].verdict, 'unobserved');
});

test('a pin that states no version produces no version finding — the negative for the one above', () => {
  const fx = makePinFixture('e2e-version-absent');
  runDriver(['-c', 'hello.c', '-O2', '-o', 'out.o'], { cwd: fx.src });
  const rec = evidenceRecords(fx.evidence)[0];
  assert.ok(rec);
  assert.equal(rec.record.findings.some((f) => f.id === 'VG-CFG-014'), false);
  assert.equal(rec.record.checks.toolchainPin.unobservedCount, 0);
  assert.equal(rec.record.checks.toolchainPin.versions[0].verdict, 'not-pinned');
});
