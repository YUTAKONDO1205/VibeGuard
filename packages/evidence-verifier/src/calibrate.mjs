// Calibration for the re-derivation: reproduce every vector, refuse every
// must-fail case.
//
// A verifier that has not been calibrated cannot tell a bad record from its own
// bug, and it will report the second as the first — with a critical severity
// and a plausible-looking digest comparison attached. So this runs before any
// verdict this package produces is worth reading, and its failure mode is a
// refusal rather than a warning.

import { rederiveCanonicalText, rederiveDigest } from './rederive.mjs';
import { loadVectors } from './vectors.mjs';

/**
 * @param {{file?: string, requirePin?: boolean}} [opts]
 * @returns {{
 *   inputs: number, checked: number, skipped: number, skippedNames: string[],
 *   passed: number, failed: Array<{name: string, reason: string}>,
 *   fingerprint: string, file: string,
 * }}
 */
export function calibrate(opts = {}) {
  const { parsed, fingerprint, file } = loadVectors(opts);
  const vectors = Array.isArray(parsed.vectors) ? parsed.vectors : [];
  const mustFail = Array.isArray(parsed.mustFail) ? parsed.mustFail : [];
  const failed = [];
  let passed = 0;

  for (const v of vectors) {
    let text;
    let digest;
    try {
      text = rederiveCanonicalText(v.input);
      digest = rederiveDigest(v.input);
    } catch (e) {
      failed.push({ name: v.name, reason: `threw where the reference did not: ${e.message}` });
      continue;
    }
    if (text !== v.canonicalText) {
      failed.push({
        name: v.name,
        reason: `canonicalText\n      want ${JSON.stringify(v.canonicalText)}\n      got  ${JSON.stringify(text)}`,
      });
      continue;
    }
    if (digest !== v.digest) {
      failed.push({ name: v.name, reason: `digest want ${v.digest} got ${digest}` });
      continue;
    }
    passed += 1;
  }

  for (const v of mustFail) {
    let threw = null;
    try {
      rederiveCanonicalText(v.input);
    } catch (e) {
      threw = e;
    }
    if (threw === null) {
      failed.push({ name: v.name, reason: 'the re-derivation accepted an input it must refuse' });
      continue;
    }
    passed += 1;
  }

  const inputs = vectors.length + mustFail.length;
  return {
    inputs,
    checked: inputs,
    skipped: 0,
    skippedNames: [],
    passed,
    failed,
    fingerprint,
    file,
  };
}
