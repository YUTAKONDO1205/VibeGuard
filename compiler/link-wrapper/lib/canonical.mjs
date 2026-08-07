// Canonical JSON and digests, per compiler/schema/interfaces.md §5.
//
// This is the fourth implementation of these rules in this directory, and the
// reason it exists rather than importing one of the others is that each
// component is built and reviewed independently — but the reason it is TESTED
// against compiler/evidence/testdata/digest-vectors.json is stronger: two
// canonicalisers that agree on every valid record and disagree about which
// inputs to REFUSE are not the same canonicaliser, and a record written here
// that the verifier next door calls malformed is a bug with no finding
// attached. The refusals below are therefore as much of the contract as the
// acceptances, and each one names what a round trip would otherwise lose.

import { createHash } from 'node:crypto';

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

function assertIntegers(v, path = '$') {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) {
      throw new Error(`non-integer number at ${path}: ${v}. Ratios are a pair {"num":…,"den":…}; see interfaces.md §5 rule 4.`);
    }
    if (!Number.isSafeInteger(v)) {
      throw new Error(`integer ${v} at ${path} is outside the exact-integer range; a value that cannot survive a JSON round trip cannot be digested.`);
    }
    if (!/^-?\d+$/.test(String(v))) {
      throw new Error(`integer ${v} at ${path} serialises in exponent form; rule 3 is about bytes.`);
    }
    return;
  }
  if (Array.isArray(v)) {
    v.forEach((x, i) => assertIntegers(x, `${path}[${i}]`));
    return;
  }
  if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (/^(0|[1-9]\d*)$/.test(k)) {
        throw new Error(`the key "${k}" at ${path} is an array index in JavaScript, and rule 2 does not determine its position.`);
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

/** Attach the digest last, so it covers everything else in the record. */
export function seal(record) {
  return { ...record, evidenceDigest: evidenceDigest(record) };
}
