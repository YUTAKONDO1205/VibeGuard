// Evidence canonicalisation, per compiler/schema/interfaces.md section 5.
//
// Reimplemented here rather than imported. That is on purpose and it is the
// same reason the independent verifier reimplements it: a record and the thing
// that checks the record must not share the bug. It is forty lines, and the
// rules it obeys are the five in the interface document:
//
//   1. `context` and `evidenceDigest` are removed as whole subtrees from the
//      TOP LEVEL only. Nothing else is removed, at any depth.
//   2. Keys sort lexicographically at every level, inside arrays of objects
//      too. Array ORDER is significant and is never sorted.
//   3. No insignificant whitespace.
//   4. Every number is an integer. A ratio is `{num, den}`. A non-integer is a
//      malformed record and the canonicaliser fails rather than rounding.
//   5. SHA-256 over the UTF-8 bytes, lowercase hex.

import { createHash } from 'node:crypto';

/** Paths, so a rejection says which field was wrong. */
function walk(value, path, out) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    out.push(JSON.stringify(value));
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) {
      throw new TypeError(`non-integer number at ${path || '/'}: ${value} (a ratio is {num, den})`);
    }
    out.push(String(value));
    return;
  }
  if (Array.isArray(value)) {
    out.push('[');
    value.forEach((v, i) => {
      if (i > 0) out.push(',');
      walk(v, `${path}/${i}`, out);
    });
    out.push(']');
    return;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    out.push('{');
    keys.forEach((k, i) => {
      if (i > 0) out.push(',');
      out.push(JSON.stringify(k));
      out.push(':');
      walk(value[k], `${path}/${k}`, out);
    });
    out.push('}');
    return;
  }
  throw new TypeError(`value of type ${typeof value} cannot appear in a record, at ${path || '/'}`);
}

/** The canonical serialisation of a record, with the two top-level removals. */
export function canonicalJson(record) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new TypeError('a record is a JSON object');
  }
  const shallow = {};
  for (const k of Object.keys(record)) {
    if (k === 'context' || k === 'evidenceDigest') continue;
    shallow[k] = record[k];
  }
  const out = [];
  walk(shallow, '', out);
  return out.join('');
}

export function digestOf(record) {
  return createHash('sha256').update(canonicalJson(record), 'utf8').digest('hex');
}

/** Absolute paths must not appear anywhere in a record. */
const ABSOLUTE_RE = /(^|[\s"'(=:])(\/[A-Za-z0-9._-]+\/|[A-Za-z]:[\\/])/;

export function findAbsolutePaths(record, path = '') {
  const hits = [];
  if (typeof record === 'string') {
    if (ABSOLUTE_RE.test(record)) hits.push({ pointer: path || '/', value: record });
    return hits;
  }
  if (Array.isArray(record)) {
    record.forEach((v, i) => hits.push(...findAbsolutePaths(v, `${path}/${i}`)));
    return hits;
  }
  if (record !== null && typeof record === 'object') {
    for (const k of Object.keys(record)) hits.push(...findAbsolutePaths(record[k], `${path}/${k}`));
  }
  return hits;
}

/** A finding, in the one shape interfaces.md section 2 defines. */
export function makeFinding({ id, severity, title, detail, where }) {
  const w = where ?? {};
  return {
    detail,
    id,
    severity,
    title,
    where: {
      kind: w.kind ?? 'ir',
      pass: w.pass ?? null,
      path: w.path ?? null,
      unit: w.unit ?? null,
    },
  };
}
