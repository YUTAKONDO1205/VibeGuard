// Calibration: reproduce every vector, refuse every must-fail case.
//
// This is the only claim this package makes about its canonicaliser being
// right. It is not "the code looks correct" and it is not "it agrees with the
// other implementation" — two implementations that agree can be wrong together,
// which is exactly why the toolchain workspace keeps its generator and its
// verifier from sharing a line. The claim is: the expected values came from a
// reference implementation outside this repository, and this implementation
// reproduces them byte for byte.
//
// A vector that THROWS is a failure, not a skip. A must-fail case that is
// accepted is a failure too — a canonicaliser that is merely permissive
// produces digests nobody else can reproduce, which is the same bug wearing a
// friendlier face.

import { canonicalText, evidenceDigest } from './canon.mjs';
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
      text = canonicalText(v.input);
      digest = evidenceDigest(v.input);
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
      canonicalText(v.input);
    } catch (e) {
      threw = e;
    }
    if (threw === null) {
      failed.push({
        name: v.name,
        reason: 'the canonicaliser accepted an input it must refuse',
      });
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
