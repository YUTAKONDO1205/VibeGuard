// Canonical serialisation and digesting for evidence records.
//
// GENERATOR SIDE. Everything that writes a record goes through `sealRecord`
// here; `verify.mjs` deliberately does not import this file and re-derives the
// digest from the written rules instead, because two sides that share an
// implementation agree by construction and the agreement proves nothing.
//
// THE RULES (interfaces.md §5)
//
//   1. `context` and `evidenceDigest` are removed from the top level before
//      digesting, and `context` is removed as a WHOLE SUBTREE. Nothing else is
//      removed, at any depth: a key called `context` below the top level is an
//      ordinary key and is digested like any other.
//   2. Object keys sort lexicographically at every level, inside arrays of
//      objects too. Array order itself is significant and is never sorted.
//   3. No insignificant whitespace.
//   4. Every number is an integer. A non-integer is a malformed record, not a
//      rounding question — the canonicaliser fails rather than rounds. Ratios
//      are carried as `{"num": 3, "den": 4}`.
//   5. SHA-256 over the UTF-8 bytes of the canonical text, lowercase hex.
//
// WHY RULE 1 IS A PLACE AND NOT A LIST OF NAMES
//
//   It used to be a list: drop `generatedAt` and `evidenceDigest`. A list only
//   covers what was known when it was written. Provenance for a *different*
//   repository was later added to the record, was not on the list, and so went
//   into the digest; the next uncommitted edit over there moved all forty
//   digests without a single measurement having changed. Nothing detected it,
//   because there was nothing to detect it with — the digest did exactly what
//   it had been told to do.
//
//   With the exclusion expressed as a place, the schema itself says where
//   volatile fields live, and adding one more cannot move a digest. Anything a
//   re-run cannot reproduce goes in `context`. That is the whole convention.
//
// STRICTNESS BEYOND THE FIVE RULES
//
//   These reject inputs that a laxer canonicaliser would silently mangle. None
//   of them changes the output for any input the rules already accept, which
//   is checked against the vectors in `testdata/` and against real records:
//
//   * integers outside the exact-integer range are rejected, because
//     `JSON.stringify(1e21)` is `"1e+21"` and an implementation in another
//     language would write the digits — same value, different bytes, different
//     digest;
//   * `undefined` as an object member is rejected rather than dropped. The
//     contract says `null` means "not applicable"; a member that vanishes says
//     nothing at all, and the two records differ in the digest either way;
//   * `Date`, `Map`, `Set`, class instances and the like are rejected rather
//     than serialised as `{}`;
//   * a cycle is reported as a cycle instead of as stack exhaustion;
//   * a key that JavaScript treats as an array index (`"0"`, `"10"`) is
//     rejected. This one was found by the vectors rather than reasoned out:
//     sorting the keys is not enough to fix the byte order, because a JS engine
//     puts integer-index keys first in ascending numeric order no matter what
//     order they were inserted in. So `{"-":6,"0":7,"10":8,"9":9}` — the order
//     rule 2 asks for — serialises as `{"0":7,"9":9,"10":8,"-":6}` if you build
//     an object and stringify it, and as the sorted order if you build the text
//     directly. Two implementations, both obeying rule 2, different bytes,
//     different digest. Rule 2 does not say which is right, so neither does
//     this file: the key is refused, the ambiguity is unrepresentable, and
//     nothing has to guess. Prefix such a key (`"k10"`) or carry the map as an
//     array of `{key, value}` pairs.

import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { assertNoAbsolutePaths } from './paths.mjs';
import { runContext } from './clock.mjs';

/** Removed from the top level before digesting. `context` goes as a subtree. */
export const EXCLUDED_TOP_LEVEL_KEYS = Object.freeze(['context', 'evidenceDigest']);

export const CANON_RULES = Object.freeze({
  keyOrder: 'lexicographic at every object level',
  whitespace: 'none',
  excludedTopLevelKeys: ['context', 'evidenceDigest'],
  exclusionIsBySubtree:
    'the whole `context` value is removed, including every key nested inside it; ' +
    'a key named `context` anywhere below the top level is kept, like any other key',
  volatileFieldsConvention:
    'anything a re-run cannot reproduce (wall clock, host, durations, provenance of other ' +
    'repositories) belongs in top-level `context`; nothing else is excluded',
  numbers: 'integers only; a non-integer anywhere is an error',
  hash: 'sha256, lowercase hex, over the UTF-8 bytes of the canonical text',
});

export class CanonicalisationError extends Error {
  constructor(message, where) {
    super(where ? `${message} (at ${where})` : message);
    this.name = 'CanonicalisationError';
    this.where = where ?? null;
  }
}

function isPlainObject(v) {
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/**
 * True when a JS engine treats this key as an array index and therefore moves
 * it to the front of the property order, ahead of every string key, in
 * ascending numeric order. The test is the language's own: a key `P` is an
 * array index when `String(ToUint32(P)) === P` and `ToUint32(P) < 2**32 - 1`.
 */
export function isArrayIndexKey(k) {
  if (typeof k !== 'string' || k.length === 0 || k.length > 10) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(k)) return false;
  const n = Number(k);
  return n < 4294967295;
}

function canonicalise(v, where, seen) {
  if (v === null) return null;

  const t = typeof v;

  if (t === 'number') {
    if (!Number.isFinite(v)) {
      throw new CanonicalisationError(
        `canonical JSON forbids the non-finite number ${String(v)}`,
        where,
      );
    }
    if (!Number.isInteger(v)) {
      throw new CanonicalisationError(
        `canonical JSON forbids non-integer numbers, found ${v}; carry a ratio as a pair of ` +
          'integer counts — {"num": 3, "den": 4} — rather than rounding it here',
        where,
      );
    }
    if (!Number.isSafeInteger(v)) {
      throw new CanonicalisationError(
        `the integer ${v} is outside the exact-integer range, so its canonical text is not ` +
          'agreed between implementations; split it or move it into `context`',
        where,
      );
    }
    return v;
  }

  if (t === 'string' || t === 'boolean') return v;

  if (t === 'undefined') {
    throw new CanonicalisationError(
      'canonical JSON forbids undefined; write null, which the contract defines as ' +
        '"not applicable" — a member that simply vanishes says nothing at all',
      where,
    );
  }
  if (t === 'bigint' || t === 'function' || t === 'symbol') {
    throw new CanonicalisationError(`canonical JSON forbids a value of type ${t}`, where);
  }

  if (seen.has(v)) {
    throw new CanonicalisationError('the record contains a cycle', where);
  }
  seen.add(v);
  try {
    if (Array.isArray(v)) {
      // Array order is significant and is never sorted.
      return v.map((x, i) => canonicalise(x, `${where}[${i}]`, seen));
    }
    if (!isPlainObject(v)) {
      const name = v?.constructor?.name ?? 'object';
      throw new CanonicalisationError(
        `canonical JSON accepts plain objects only, found ${name}; convert it to plain data ` +
          'before digesting rather than letting it serialise as {}',
        where,
      );
    }
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (isArrayIndexKey(k)) {
        throw new CanonicalisationError(
          `the key ${JSON.stringify(k)} is an array index as far as JavaScript is concerned, so ` +
            'the engine puts it ahead of every string key in ascending numeric order and rule 2 ' +
            'no longer decides the byte order; prefix it (e.g. "k' +
            k +
            '") or carry the map as an array of {key, value} pairs',
          where,
        );
      }
      out[k] = canonicalise(v[k], `${where}.${k}`, seen);
    }
    return out;
  } finally {
    seen.delete(v);
  }
}

/**
 * Canonical text of any value, with **no** top-level keys removed.
 * Use this for sub-objects; use {@link canonicalJson} for whole records.
 */
export function canonicalJsonRaw(value) {
  return JSON.stringify(canonicalise(value, '$', new Set()));
}

/**
 * The canonical text a record's digest is taken over: rules 1–3 applied.
 *
 * The top-level keys `context` and `evidenceDigest` are removed first,
 * `context` as a whole subtree. `evidenceDigest(record)` is exactly
 * `sha256(canonicalJson(record))` and the two must never drift apart.
 *
 * @param {unknown} obj
 * @returns {string}
 */
export function canonicalJson(obj) {
  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj) && isPlainObject(obj)) {
    const copy = { ...obj };
    for (const k of EXCLUDED_TOP_LEVEL_KEYS) delete copy[k];
    return canonicalJsonRaw(copy);
  }
  return canonicalJsonRaw(obj);
}

/** The name the out-of-repo reference uses for the same function. */
export const canonicalText = canonicalJson;

/**
 * SHA-256 of the canonical text, lowercase hex.
 *
 * @param {unknown} record
 * @returns {string}
 */
export function evidenceDigest(record) {
  return createHash('sha256').update(canonicalJson(record), 'utf8').digest('hex');
}

/** SHA-256 of arbitrary bytes, lowercase hex. Used for artefact digests. */
export function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * The generation-side chokepoint. Every writer of a record calls this and
 * writes what it returns; nothing computes `evidenceDigest` by hand.
 *
 * In order:
 *   1. attach `context` (from `clock.mjs`, the only clock in this component)
 *      unless the caller already supplied one;
 *   2. **gate on absolute paths** — this runs before the digest so that a
 *      record carrying a machine-specific path is never written, never
 *      digested, and never referenced by anything downstream;
 *   3. canonicalise, which is where a non-integer number fails;
 *   4. set `evidenceDigest`.
 *
 * @param {Record<string, unknown>} record
 * @param {{
 *   context?: Record<string, unknown>,
 *   contextExtra?: Record<string, unknown>,
 *   pathMode?: 'strict'|'machine-roots',
 *   label?: string,
 * }} [opts]
 * @returns {Record<string, unknown>} a new record; the input is not mutated.
 */
export function sealRecord(record, opts = {}) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new CanonicalisationError('a record must be a JSON object');
  }
  const context = opts.context ?? record.context ?? runContext(opts.contextExtra ?? {});
  const sealed = { ...record, context };
  delete sealed.evidenceDigest;

  assertNoAbsolutePaths(sealed, {
    mode: opts.pathMode ?? 'strict',
    label: opts.label ?? 'record',
  });

  const digest = evidenceDigest(sealed);
  // Key order on disk is the authored order; only the canonical text is sorted.
  const out = {};
  for (const k of Object.keys(record)) {
    if (k === 'evidenceDigest') out.evidenceDigest = digest;
    else if (k === 'context') out.context = context;
    else out[k] = record[k];
  }
  if (!('context' in out)) out.context = context;
  if (!('evidenceDigest' in out)) out.evidenceDigest = digest;
  return out;
}

/**
 * Seal and write. The file is pretty-printed — the canonical text is what gets
 * digested, not what gets stored, and a record nobody can read in a diff is a
 * record nobody checks.
 *
 * @returns {Record<string, unknown>} the sealed record that was written.
 */
export function writeRecordSync(file, record, opts = {}) {
  const sealed = sealRecord(record, opts);
  writeFileSync(file, `${JSON.stringify(sealed, null, 2)}\n`, 'utf8');
  return sealed;
}
