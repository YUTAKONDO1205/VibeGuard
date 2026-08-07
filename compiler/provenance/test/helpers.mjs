// Fixture construction for the provenance tests. Not a test file itself —
// `node --test` only collects `*.test.mjs`.
//
// NO KEY IS CHECKED IN. Every test that needs one generates it, in a temporary
// directory created here and removed by the caller. A repository that carries a
// private key has published it, and a test suite that needs a published private
// key in order to pass is a suite that cannot be run against a real one.

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const PROVENANCE_DIR = resolve(HERE, '..');
export const TOOLS = {
  keygen: join(PROVENANCE_DIR, 'tools', 'keygen.mjs'),
  makeProvenance: join(PROVENANCE_DIR, 'tools', 'make-provenance.mjs'),
  rebuildCompare: join(PROVENANCE_DIR, 'tools', 'rebuild-compare.mjs'),
  signEvidence: join(PROVENANCE_DIR, 'tools', 'sign-evidence.mjs'),
  verifyProvenance: join(PROVENANCE_DIR, 'tools', 'verify-provenance.mjs'),
};

/** A temporary directory. The caller removes it; `removeTemp` is the pair. */
export function makeTemp(label) {
  const root = process.env.PROVENANCE_TEST_TMP ?? tmpdir();
  mkdirSync(root, { recursive: true });
  return mkdtempSync(join(root, `prov-${label}-`));
}

export function removeTemp(dir) {
  rmSync(dir, { force: true, recursive: true });
}

/**
 * A pin with the shape `loadPin` accepts. The digests are made up, and that is
 * fine here: `declaredToolchainDigest` reads the pin and never the filesystem,
 * so what is under test is whether two documents agree about a pin — which is
 * exactly the claim the verifier makes about it.
 */
export function writeFakePin(dir, { name = 'toolchain-pin.json', clang = '18.1.3', bump = 0 } = {}) {
  const hex = (seed) => seed.toString(16).padStart(2, '0').repeat(32);
  const pin = {
    clang,
    drivers: { cc: 'usr/bin/clang-18', cxx: 'usr/bin/clang++-18' },
    packages: [
      { name: 'clang-18', path: 'usr/bin/clang-18', sha256: hex(0x11 + bump), version: '1:18.1.3-1ubuntu1' },
      { name: 'lld-18', path: 'usr/bin/ld.lld-18', sha256: hex(0x22 + bump), version: '1:18.1.3-1ubuntu1' },
    ],
    pinVersion: 'toolchain-pin-v0',
    root: '/',
  };
  const path = join(dir, name);
  writeFileSync(path, `${JSON.stringify(pin, null, 2)}\n`, 'utf8');
  return { path, pin };
}

/** A 40-hex string that looks like a commit sha. */
export function fakeCommit(seed = 'a') {
  return seed.repeat(40).slice(0, 40);
}

/** Write an artefact and return its relative name. */
export function writeArtifact(root, rel, contents) {
  const p = join(root, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, contents);
  return rel;
}
