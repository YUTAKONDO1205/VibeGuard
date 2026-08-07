// Shared fixture loading for the pure suites.
//
// Everything under testdata/ is REAL OUTPUT, captured from LLD 18.1.3 by
// tools/make-fixtures.sh, not written by hand. A hand-written map agrees with
// the parser by construction and proves only that the author was consistent
// with themselves; these files disagreed with the parser three times while it
// was being written, which is what a fixture is for.
//
// They are testdata, which means they are the PARSER'S input and never a
// verdict's. The provenance rule — a verdict is only computed from a map this
// wrapper produced — is enforced in lib/verdict.mjs and exercised in
// test/external-map.test.mjs; loading a captured map here does not go near it,
// because these tests call the parser directly and never ask for a verdict on
// wrapper-made evidence.

import { readFileSync } from 'node:fs';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const TESTDATA = resolve(HERE, '..', 'testdata');
export const CLI = resolve(HERE, '..', 'vg-link.mjs');

/** A stand-in link root. Absolute and platform-neutral: the parser never touches the disk. */
export const LINK_ROOT = '/fixtures';

export function fixture(name) {
  return readFileSync(join(TESTDATA, name), 'utf8');
}

export function fixtureBytes(name) {
  return readFileSync(join(TESTDATA, name));
}

/** The first 64 bytes of a real linked artefact, stored hex-encoded. */
export function elfHeader(name) {
  return Buffer.from(fixture(name).replace(/\s+/g, ''), 'hex');
}

export function scratch(label) {
  return mkdtempSync(join(tmpdir(), `vg-link-${label}-`));
}

/** A policy that authorises exactly the negative fixture's link and nothing else. */
export function approvingPolicy(extra = {}) {
  return {
    policyVersion: 'policy-v0',
    failOn: 'high',
    link: {
      allowedObjects: [
        'main.o',
        'helper.o',
        'system:lib/x86_64-linux-gnu/*.o',
        'system:usr/lib/gcc/**/*.o',
      ],
      allowedLibraries: ['system:lib/x86_64-linux-gnu/*.so*', 'system:lib64/*.so*'],
      allowedLinkers: ['lld'],
      forbidLinkerScripts: true,
      ...extra,
    },
  };
}

export const NEG_ARGV = ['clang-18', '-fuse-ld=lld', 'main.o', 'helper.o', '-o', 'neg.bin'];
export const POS_ARGV = ['clang-18', '-fuse-ld=lld', 'main.o', 'helper.o', 'rogue.o', '-o', 'pos.bin'];
export const SCR_ARGV = ['clang-18', '-fuse-ld=lld', '-Wl,-T,extra.ld', 'main.o', 'helper.o', '-o', 'scr.bin'];
export const ARC_ARGV = ['clang-18', '-fuse-ld=lld', 'mainarc.o', 'helper.o', '-L.', '-larch', '-o', 'arc.bin'];

/** The provenance the runner produces. Nothing else in the tree constructs one. */
export const WRAPPER_PROVENANCE = { producedBy: 'wrapper', existedBefore: false, writtenByThisRun: true, nonce: 'deadbeefdeadbeef' };
