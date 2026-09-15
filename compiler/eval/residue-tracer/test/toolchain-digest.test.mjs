/**
 * lib/toolchain-digest.mjs -- the digest a record may carry, and the refusals.
 *
 * WHAT THIS IS FOR
 *
 * `toolchain.digest` used to be computed in this lane:
 *
 *     sha256(JSON.stringify({ cc, version: versions[cc], observer: observerSha }))
 *
 * Nothing was wrong with the arithmetic. What was wrong is that the number is a
 * digest of nothing anyone else digests: it equals no value this tree computes
 * for the same toolchain, and a reader holding the compiler cannot recompute it,
 * so it can only ever be compared with another record from this same lane. The
 * one derivation in this tree is in compiler/driver/lib/run.mjs --
 * `evidenceDigest(pinnedSet(pin, pinVerification))` -- and the file this lane
 * feeds says of the same field, in its driver adapter, "this adapter will not
 * invent a digest for it".
 *
 * The first test below therefore does NOT call `evidenceDigest`: it rebuilds the
 * canonical bytes by hand from the rules in interfaces.md section 5 (keys sorted
 * at every level, no insignificant whitespace, SHA-256 over the UTF-8 bytes) and
 * compares. Two sides that share an implementation agree by construction, which
 * is the same reason compiler/evidence/verify.mjs re-derives instead of importing.
 *
 * No compiler and no dpkg are needed: verifyPin takes its two probes as
 * arguments, and the "pinned file" here is a temporary file with known bytes.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DIGEST_SOURCE, DIGEST_DERIVATION, digestOfPinnedSet, toolchainDigestFromPin,
} from '../lib/toolchain-digest.mjs';
import { loadPin, verifyPin } from '../../../driver/lib/toolchain.mjs';

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/** A pin over one real file, and the probes a machine without clang cannot run. */
function makePin({ bytes = 'not really a compiler, but it has a sha256\n', clang = '18.1.3' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'vg-residue-pin-'));
  const binary = join(dir, 'clang-18');
  writeFileSync(binary, bytes, 'utf8');
  const pin = {
    pinVersion: 'toolchain-pin-v0',
    clang,
    root: dir,
    drivers: { cc: 'clang-18' },
    packages: [{ name: 'clang-18', version: '1:18.1.3-1ubuntu1', path: 'clang-18', sha256: sha256(bytes) }],
  };
  const pinPath = join(dir, 'toolchain.pin');
  writeFileSync(pinPath, `${JSON.stringify(pin, null, 2)}\n`, 'utf8');
  return {
    dir,
    pinPath,
    pin,
    bytes,
    options: {
      // verifyPin only compares pin.clang with what the compiler reports when it
      // is given a path to ask; the runner passes the cc it actually invoked.
      ccPath: binary,
      verifyOptions: {
        probeVersion: () => clang,
        observePackageVersion: () => ({ version: '1:18.1.3-1ubuntu1', method: 'test-double' }),
      },
    },
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test('the digest is the tree digest: canonical bytes over the pinned set, rebuilt here from the rules', () => {
  const fx = makePin();
  try {
    const got = toolchainDigestFromPin(fx.pinPath, fx.options);
    assert.equal(got.ok, true, got.ok ? '' : got.why);
    assert.equal(got.source, DIGEST_SOURCE);

    // interfaces.md section 5, applied by hand rather than by importing the
    // canonicaliser: keys sorted at every level (clang, packages, pinVersion --
    // and name, sha256, version inside each package), no whitespace, SHA-256
    // over the UTF-8 bytes, lowercase hex.
    const pkg = fx.pin.packages[0];
    const canonical = '{'
      + `"clang":${JSON.stringify(fx.pin.clang)},`
      + '"packages":[{'
      + `"name":${JSON.stringify(pkg.name)},`
      + `"sha256":${JSON.stringify(pkg.sha256)},`
      + `"version":${JSON.stringify(pkg.version)}`
      + '}],'
      + '"pinVersion":"toolchain-pin-v0"'
      + '}';
    assert.equal(got.digest, sha256(canonical),
      'the digest is not the SHA-256 of the canonical pinned set; it is some other number again');

    // and it is the same number the driver writes, computed the driver's way.
    assert.equal(got.digest, digestOfPinnedSet(loadPin(fx.pinPath).pin,
      verifyPin(fx.pin, { ccPath: fx.options.ccPath, ...fx.options.verifyOptions })));
    assert.match(got.digest, /^[0-9a-f]{64}$/);
  } finally { fx.cleanup(); }
});

test('the digest covers the pinned BYTES: change the file and the number moves', () => {
  const a = makePin({ bytes: 'one\n' });
  const b = makePin({ bytes: 'two\n' });
  try {
    const da = toolchainDigestFromPin(a.pinPath, a.options);
    const db = toolchainDigestFromPin(b.pinPath, b.options);
    assert.equal(da.ok, true);
    assert.equal(db.ok, true);
    assert.notEqual(da.digest, db.digest,
      'two different pinned binaries produced the same toolchain digest; the digest is not over the bytes');
  } finally { a.cleanup(); b.cleanup(); }
});

test('a pin that does not describe this machine yields no digest, and says which check failed', () => {
  const fx = makePin();
  try {
    // The pinned file is replaced after the pin was written: same name, same
    // version, different bytes. This is the case the whole pin exists for.
    writeFileSync(join(fx.dir, 'clang-18'), 'a different build of the same version\n', 'utf8');
    const got = toolchainDigestFromPin(fx.pinPath, fx.options);
    assert.equal(got.ok, false, 'a digest was returned over a pin whose file does not match');
    assert.match(got.why, /does not describe the toolchain on this machine/);
    assert.match(got.why, /clang-18 \(digest\)/);
    assert.equal(got.digest, undefined);
  } finally { fx.cleanup(); }
});

test('a pin this machine could only half check yields no digest either', () => {
  const fx = makePin();
  try {
    const got = toolchainDigestFromPin(fx.pinPath, {
      ccPath: join(fx.dir, 'clang-18'),
      verifyOptions: {
        probeVersion: () => '18.1.3',
        // dpkg is not installed: verifyPin keeps this OUT of `mismatches` on
        // purpose, because "could not measure" is not "measured a disagreement".
        observePackageVersion: () => ({ version: null, method: 'unavailable' }),
      },
    });
    assert.equal(got.ok, false, 'a digest was returned over a pin nobody finished checking');
    assert.match(got.why, /could not check at all/);
    assert.match(got.why, /package-version-unobserved/);
  } finally { fx.cleanup(); }
});

test('a missing or malformed pin is a reason, not a fallback', () => {
  const fx = makePin();
  try {
    const missing = toolchainDigestFromPin(join(fx.dir, 'no-such.pin'), fx.options);
    assert.equal(missing.ok, false);
    assert.match(missing.why, /could not be read/);

    writeFileSync(fx.pinPath, '{"pinVersion":"something-else","packages":[]}\n', 'utf8');
    const wrong = toolchainDigestFromPin(fx.pinPath, fx.options);
    assert.equal(wrong.ok, false);
    assert.match(wrong.why, /bad-version/);
  } finally { fx.cleanup(); }
});

test('the sentence the record carries names the derivation, not this lane', () => {
  assert.match(DIGEST_DERIVATION, /evidenceDigest\(pinnedSet\(pin, verifyPin\(pin\)\)\)/);
  assert.match(DIGEST_DERIVATION, /not computed by this lane/);
});
