// The compatibility oracle for this side of the pair.
//
// The vectors are vendored here as well, byte-for-byte, rather than imported
// from the generator package next door. That is not tidiness lost — it is the
// same rule as `rederive.mjs`: the verifier does not take anything from the
// generator except the contract, and it must be able to state the contract on
// its own. Two copies of a DATA file that a repository-wide check keeps
// identical is a different thing from two copies of an IMPLEMENTATION, which
// nothing can keep honest.
//
// `contract-copies.mjs` is what keeps them identical, and it finds every copy
// by name rather than by a hard-coded path — so it covers the toolchain
// workspace's original as well, without this package naming a path into it.
//
// The pin is over parsed CONTENT, not over file bytes: this checkout converts
// line endings on checkout for everything outside the toolchain directory, so a
// byte pin would fail for a reason that has nothing to do with the vectors.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

export const VECTORS_FILE = join(HERE, '..', 'testdata', 'digest-vectors.json');

/** Measured 2026-08-07: 22 vectors, 8 must-fail cases. */
export const VECTORS_FINGERPRINT =
  'c859dc00f76f81b73fd574d65996e6ae4285c128d60705378dcc47c20a3cd3e4';

export const VECTORS_EXPECTED = Object.freeze({ vectors: 22, mustFail: 8 });

/** Formatting-independent by construction: taken over the re-serialised parse. */
export function fingerprintVectors(parsed) {
  return createHash('sha256').update(JSON.stringify(parsed), 'utf8').digest('hex');
}

export class VectorsError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VectorsError';
  }
}

/**
 * @param {{file?: string, requirePin?: boolean}} [opts]
 * @returns {{parsed: object, fingerprint: string, file: string}}
 */
export function loadVectors(opts = {}) {
  const file = opts.file ?? VECTORS_FILE;
  const requirePin = opts.requirePin ?? true;
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch (e) {
    throw new VectorsError(`the digest vectors could not be read from ${file}: ${e.message}`);
  }
  const fingerprint = fingerprintVectors(parsed);
  if (requirePin && fingerprint !== VECTORS_FINGERPRINT) {
    throw new VectorsError(
      `the digest vectors do not match the pin.\n  pinned ${VECTORS_FINGERPRINT}\n  found  ${fingerprint}\n` +
        '  Either the contract moved (raise VECTORS_FINGERPRINT in the same commit, in every ' +
        'package that pins it) or this copy was edited to make a failing canonicaliser pass.',
    );
  }
  const n = Array.isArray(parsed.vectors) ? parsed.vectors.length : 0;
  const m = Array.isArray(parsed.mustFail) ? parsed.mustFail.length : 0;
  if (n < VECTORS_EXPECTED.vectors || m < VECTORS_EXPECTED.mustFail) {
    throw new VectorsError(
      `the vectors document has shrunk: ${n} vector(s) and ${m} must-fail case(s), below the ` +
        `measured ${VECTORS_EXPECTED.vectors} and ${VECTORS_EXPECTED.mustFail}.`,
    );
  }
  return { parsed, fingerprint, file };
}
