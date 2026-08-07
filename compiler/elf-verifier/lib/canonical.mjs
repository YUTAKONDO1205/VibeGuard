// Canonical JSON and digests, per compiler/schema/interfaces.md section 5.
//
// The rules are copied out here as executable form, not paraphrased: a second
// implementation that "does roughly the same normalisation" produces digests
// that disagree with the verifier's, and a digest that disagrees with the
// verifier is worse than no digest at all.

import { createHash } from 'node:crypto';

/** Sort object keys at every level. Array *order* is significant and is kept. */
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

/**
 * Rule 4 is a hard error rather than a rounding step. A component that emits
 * 0.75 meant something — a ratio, a rate, a mean — and silently turning it into
 * 1 or into "0.75" would keep the record parseable while making it wrong.
 */
function assertIntegers(v, path = '$') {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) {
      throw new Error(
        `non-integer number at ${path}: ${v}. Ratios are a pair {"num":…,"den":…}; ` +
          `see interfaces.md section 5 rule 4.`,
      );
    }
    // Two canonicalisers that agree on every valid record and disagree on what
    // they refuse are not the same canonicaliser. Measured against the shared
    // vectors: this one accepted three inputs the evidence implementation
    // rejects, so a record written here could be refused as malformed on the
    // other side of the same directory. The three are below, in the same order
    // the vectors name them.
    //
    // Beyond 2^53 an integer is no longer exactly representable, so "the same
    // number" stops being a property that survives a round trip through JSON.
    if (!Number.isSafeInteger(v)) {
      throw new Error(
        `integer ${v} at ${path} is outside the exact-integer range; a value that ` +
          `cannot survive a JSON round trip cannot be digested.`,
      );
    }
    // `1e21` serialises as "1e+21", which is a different byte string from the
    // digits, and rule 3 is about bytes.
    if (!/^-?\d+$/.test(String(v))) {
      throw new Error(
        `integer ${v} at ${path} serialises in exponent form; rule 3 is about ` +
          `bytes, and two implementations must not have to agree on how to print one.`,
      );
    }
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, i) => assertIntegers(x, `${path}[${i}]`));
    return;
  }
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      // An array-index key is reordered by the JavaScript object itself, before
      // any sort of ours runs, so rule 2 cannot be honoured for it.
      if (/^(0|[1-9]\d*)$/.test(k)) {
        throw new Error(
          `the key "${k}" at ${path} is an array index in JavaScript, and rule 2 ` +
            `does not determine its position.`,
        );
      }
      assertIntegers(x, `${path}.${k}`);
    }
  }
}

/** `context` and `evidenceDigest` are removed as whole subtrees, top level only. */
export function canonicalBytes(record) {
  const shallow = { ...record };
  delete shallow.context;
  delete shallow.evidenceDigest;
  assertIntegers(shallow);
  return Buffer.from(JSON.stringify(sortDeep(shallow)), 'utf8');
}

export function evidenceDigest(record) {
  return createHash('sha256').update(canonicalBytes(record)).digest('hex');
}

export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

export function sha256OfJson(value) {
  assertIntegers(value);
  return createHash('sha256').update(Buffer.from(JSON.stringify(sortDeep(value)), 'utf8')).digest('hex');
}

/** Attach the digest last, so it covers everything else that is in the record. */
export function seal(record) {
  return { ...record, evidenceDigest: evidenceDigest(record) };
}
