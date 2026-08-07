// The compatibility oracle: the digest vectors, vendored, and pinned by
// content rather than by bytes.
//
// ── WHAT IS VENDORED, AND WHAT IS NOT ───────────────────────────────────────
//
// `testdata/digest-vectors.json` here is a byte-for-byte copy of the file the
// toolchain workspace uses. The CODE is not vendored — see the header of
// `canon.mjs` for why copying an implementation proves nothing. What is copied
// is the CONTRACT: input, expected canonical text, expected digest, and the
// inputs a canonicaliser must refuse. A canonicaliser that reproduces every
// vector is calibrated against the same reference every other implementation
// in this repository is calibrated against; one that does not has a bug in its
// own serialisation, not a finding about a record.
//
// ── WHY THE PIN IS OVER CONTENT AND NOT OVER THE FILE ───────────────────────
//
// Measured, not assumed: this checkout has `core.autocrlf=true`, and the
// repository's `.gitattributes` forces LF only for the toolchain directory.
// A pin over raw file bytes would therefore be correct on the machine that
// wrote it and wrong on the next checkout, for a reason that has nothing to do
// with the vectors having changed — and the standard response to a check that
// cries wolf is to delete the check.
//
// So the pin is `sha256(JSON.stringify(JSON.parse(bytes)))`: it moves when a
// vector, an expected digest or a must-fail case moves, and it does not move
// when a line ending or an indent does. There is a `.gitattributes` in this
// package pinning LF as well, so the raw bytes SHOULD also stay put; that is a
// belt, and this is the braces.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The vendored copy. */
export const VECTORS_FILE = join(HERE, '..', 'testdata', 'digest-vectors.json');

/**
 * The pin. Raise it in the same commit that changes the vectors, never
 * separately — the point of the constant is that the change appears in a diff
 * a human reads.
 *
 * Measured 2026-08-07 against the toolchain copy: 22 vectors, 8 must-fail
 * cases, raw file 21094 bytes.
 */
export const VECTORS_FINGERPRINT =
  'c859dc00f76f81b73fd574d65996e6ae4285c128d60705378dcc47c20a3cd3e4';

/** How many of each the pin was taken over, so a shortfall is visible. */
export const VECTORS_EXPECTED = Object.freeze({ vectors: 22, mustFail: 8 });

/**
 * The fingerprint of a parsed vectors document. Formatting-independent by
 * construction: it is taken over the re-serialised parse, not over the file.
 *
 * @param {unknown} parsed
 * @returns {string}
 */
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
 * Load a vectors document and check it against the pin.
 *
 * Refuses rather than warns. A canonicaliser calibrated against a document
 * that is not the contract is not calibrated, and every digest it produces is
 * a guess wearing a checksum.
 *
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
        '  Either the contract moved (raise VECTORS_FINGERPRINT in the same commit, and check ' +
        'every copy in the repository still agrees) or this copy was edited to make a failing ' +
        'canonicaliser pass, which is the failure the pin is here to prevent.',
    );
  }
  const n = Array.isArray(parsed.vectors) ? parsed.vectors.length : 0;
  const m = Array.isArray(parsed.mustFail) ? parsed.mustFail.length : 0;
  if (n < VECTORS_EXPECTED.vectors || m < VECTORS_EXPECTED.mustFail) {
    throw new VectorsError(
      `the vectors document has shrunk: ${n} vector(s) and ${m} must-fail case(s), below the ` +
        `measured ${VECTORS_EXPECTED.vectors} and ${VECTORS_EXPECTED.mustFail}. A calibration ` +
        'suite that quietly covers less than it claims to is the failure this floor exists for.',
    );
  }
  return { parsed, fingerprint, file };
}
