// Canonical serialisation and digesting, for the packages side of the fence.
//
// ── WHY THIS FILE EXISTS AT ALL, AND WHY IT IS NOT AN IMPORT ────────────────
//
// The toolchain workspace at the repository root already has a canonicaliser.
// Nothing under `packages/` may import it: the boundary between the two is
// zero in both directions and a release-time invariant asserts it, because a
// user who installs an editor extension has not agreed to install a compiler.
// So the choice was (a) vendor the implementation, or (b) something better.
//
// This is (b), and the difference is worth stating because it changes what the
// tests can prove:
//
//   (a) VENDORING copies the code. A drift test then compares two files and
//       fails when they differ. That catches an edit to one copy — and it is
//       also the weakest possible check, because it proves only that two files
//       are the same file. If the shared implementation has a bug, both copies
//       have it, the drift test is green, and the digest is wrong in both
//       places. Worse, the drift test needs to READ the toolchain copy, and a
//       quoted path reaching into that directory is exactly what the boundary
//       invariant refuses; the check could not live here.
//
//   (b) WHAT IS ACTUALLY VENDORED IS THE CONTRACT, NOT THE CODE — the digest
//       vectors, byte for byte. This file is a THIRD independent implementation
//       written from the five rules, in a third shape: the generator at the
//       root sorts keys into a new object and hands it to `JSON.stringify`; the
//       verifier at the root is a recursive text emitter; this one is an
//       ITERATIVE emitter driven by an explicit work stack, with a hand-rolled
//       string escaper and an explicit code-unit key comparator, so it shares
//       no line of reasoning with either. Three implementations that reproduce
//       the same vectors are three pieces of evidence about the rules. Two
//       copies of one implementation are one.
//
// The drift question does not go away, it moves: it becomes "does every copy of
// the CONTRACT in this repository still say the same thing?", which is a
// question about data files and is answered by
// `evidence-verifier/src/contract-copies.mjs`. That check needs no path into
// the toolchain directory — it finds every copy by name.
//
// ── THE RULES (schema/interfaces.md section 5) ──────────────────────────────
//
//   1. `context` and `evidenceDigest` are removed from the TOP LEVEL before
//      digesting, and `context` goes as a WHOLE SUBTREE. Nothing else is
//      removed at any depth: a key called `context` below the top level is an
//      ordinary key.
//   2. Object keys sort lexicographically at every level, inside arrays of
//      objects too. Array order is significant and is never sorted.
//   3. No insignificant whitespace.
//   4. Every number is an integer. A non-integer is a malformed record, not a
//      rounding question. Ratios are carried as `{"num": 3, "den": 4}`.
//   5. SHA-256 over the UTF-8 bytes of the canonical text, lowercase hex.
//
// ── STRICTNESS BEYOND THE FIVE RULES ────────────────────────────────────────
//
// Each of these refuses an input a laxer canonicaliser would silently mangle,
// and none of them changes the output for any input the rules already accept —
// which is what the vectors check.
//
//   * an integer outside the exact-integer range, because two implementations
//     need not agree on its digits;
//   * `undefined` as a member, because the contract says `null` means "not
//     applicable" and a member that vanishes says nothing at all;
//   * `Date`, `Map`, `Set` and class instances, rather than letting them
//     serialise as `{}`;
//   * a cycle, reported as a cycle rather than as stack exhaustion — and here
//     that is not automatic, because an iterative walker does not blow the
//     stack, it hangs;
//   * a key the language treats as an array index, because a JS engine orders
//     those ahead of every string key in ascending numeric order, so rule 2 no
//     longer decides the bytes;
//   * an unpaired surrogate, which has no UTF-8 encoding, so rule 5 has no
//     bytes to hash.

import { createHash } from 'node:crypto';

/** Removed from the top level before digesting. `context` goes as a subtree. */
export const EXCLUDED_TOP_LEVEL_KEYS = Object.freeze(['context', 'evidenceDigest']);

export const CANON_RULES = Object.freeze({
  keyOrder: 'lexicographic by UTF-16 code unit at every object level',
  arrayOrder: 'significant, never sorted',
  whitespace: 'none',
  excludedTopLevelKeys: ['context', 'evidenceDigest'],
  exclusionIsBySubtree:
    'the whole `context` value is removed, including every key nested inside it; a key named ' +
    '`context` anywhere below the top level is kept, like any other key',
  numbers: 'integers only, within the exact-integer range; a non-integer anywhere is an error',
  hash: 'sha256, lowercase hex, over the UTF-8 bytes of the canonical text',
});

export class CanonError extends Error {
  constructor(message, where) {
    super(where ? `${message} (at ${where})` : message);
    this.name = 'CanonError';
    this.where = where ?? null;
  }
}

/**
 * True when a JS engine treats this key as an array index and therefore moves
 * it ahead of every string key, in ascending numeric order, whatever order it
 * was inserted in. The test is the language's own: `String(ToUint32(P)) === P`
 * and `ToUint32(P) < 2**32 - 1`.
 *
 * @param {unknown} k
 * @returns {boolean}
 */
export function isArrayIndexKey(k) {
  if (typeof k !== 'string' || k.length === 0 || k.length > 10) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(k)) return false;
  return Number(k) < 4294967295;
}

/**
 * Lexicographic by UTF-16 code unit — written out rather than left to the
 * default `Array.prototype.sort`, so that the ordering this file relies on is
 * stated instead of inherited. The default happens to agree; a locale-aware
 * comparator would not, and the difference only shows up on the day someone
 * "tidies" the sort into `localeCompare`.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareCodeUnits(a, b) {
  const n = a.length < b.length ? a.length : b.length;
  for (let i = 0; i < n; i += 1) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x !== y) return x < y ? -1 : 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

const SHORT_ESCAPE = new Map([
  [0x08, '\\b'],
  [0x09, '\\t'],
  [0x0a, '\\n'],
  [0x0c, '\\f'],
  [0x0d, '\\r'],
  [0x22, '\\"'],
  [0x5c, '\\\\'],
]);

/**
 * A JSON string literal, escaped by hand.
 *
 * Deliberately not `JSON.stringify`: the verifier side uses that, so if this
 * side used it too the two implementations would agree about escaping by
 * construction and the vectors covering control characters, astral planes and
 * combining marks would be testing one function twice.
 *
 * @param {string} s
 * @param {string} where
 * @returns {string}
 */
function quote(s, where) {
  let out = '"';
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    const short = SHORT_ESCAPE.get(c);
    if (short !== undefined) {
      out += short;
      continue;
    }
    if (c < 0x20) {
      out += `\\u${c.toString(16).padStart(4, '0')}`;
      continue;
    }
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new CanonError(
          'the string contains an unpaired high surrogate, which has no UTF-8 encoding, so ' +
            'there are no bytes for rule 5 to hash',
          where,
        );
      }
      out += s[i] + s[i + 1];
      i += 1;
      continue;
    }
    if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonError(
        'the string contains an unpaired low surrogate, which has no UTF-8 encoding, so ' +
          'there are no bytes for rule 5 to hash',
        where,
      );
    }
    out += s[i];
  }
  return `${out}"`;
}

function isPlainObject(v) {
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/**
 * A scalar's canonical text, or `null` when the value is a container and the
 * caller has to expand it.
 */
function scalarText(v, where) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'string') return quote(v, where);
  if (t === 'number') {
    if (!Number.isFinite(v)) {
      throw new CanonError(`canonical JSON forbids the non-finite number ${String(v)}`, where);
    }
    if (!Number.isInteger(v)) {
      throw new CanonError(
        `canonical JSON forbids non-integer numbers, found ${v}; carry a ratio as a pair of ` +
          'integer counts - {"num": 3, "den": 4} - rather than rounding it here',
        where,
      );
    }
    if (!Number.isSafeInteger(v)) {
      throw new CanonError(
        `the integer ${v} is outside the exact-integer range, so its canonical text is not ` +
          'agreed between implementations; split it or move it into `context`',
        where,
      );
    }
    return String(v);
  }
  if (t === 'undefined') {
    throw new CanonError(
      'canonical JSON forbids undefined; write null, which the contract defines as "not ' +
        'applicable" - a member that simply vanishes says nothing at all',
      where,
    );
  }
  if (t === 'bigint' || t === 'function' || t === 'symbol') {
    throw new CanonError(`canonical JSON forbids a value of type ${t}`, where);
  }
  return null; // an object or an array: the caller expands it
}

/**
 * Canonical text of any value, with **no** top-level keys removed. Use this for
 * sub-objects; use {@link canonicalText} for whole records.
 *
 * Iterative on purpose. Recursion is the obvious shape and it is the shape both
 * implementations in the toolchain workspace already have; a walker with an
 * explicit stack fails differently, which is the point of a third opinion. The
 * cost is that a cycle no longer announces itself by exhausting the stack, so
 * the cycle check below is load-bearing rather than a nicety.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalTextRaw(value) {
  const chunks = [];
  /** Containers on the current path, for cycle detection. */
  const open = new Set();
  /** LIFO. `emit` appends text; `leave` pops a container off the path. */
  const work = [{ value, where: '$' }];

  while (work.length > 0) {
    const item = work.pop();

    if (item.emit !== undefined) {
      chunks.push(item.emit);
      continue;
    }
    if (item.leave !== undefined) {
      open.delete(item.leave);
      continue;
    }

    const { value: v, where } = item;
    const scalar = scalarText(v, where);
    if (scalar !== null) {
      chunks.push(scalar);
      continue;
    }

    if (open.has(v)) {
      throw new CanonError('the record contains a cycle', where);
    }
    open.add(v);

    if (Array.isArray(v)) {
      chunks.push('[');
      // Pushed in reverse so they pop in source order. Array order is
      // significant and is never sorted.
      work.push({ emit: ']' });
      work.push({ leave: v });
      for (let i = v.length - 1; i >= 0; i -= 1) {
        work.push({ value: v[i], where: `${where}[${i}]` });
        if (i > 0) work.push({ emit: ',' });
      }
      continue;
    }

    if (!isPlainObject(v)) {
      const name = v?.constructor?.name ?? 'object';
      throw new CanonError(
        `canonical JSON accepts plain objects only, found ${name}; convert it to plain data ` +
          'before digesting rather than letting it serialise as {}',
        where,
      );
    }

    const keys = Object.keys(v).sort(compareCodeUnits);
    for (const k of keys) {
      if (isArrayIndexKey(k)) {
        throw new CanonError(
          `the key ${JSON.stringify(k)} is an array index as far as JavaScript is concerned, so ` +
            'the engine puts it ahead of every string key in ascending numeric order and rule 2 ' +
            `no longer decides the byte order; prefix it (e.g. "k${k}") or carry the map as an ` +
            'array of {key, value} pairs',
          where,
        );
      }
    }

    chunks.push('{');
    work.push({ emit: '}' });
    work.push({ leave: v });
    for (let i = keys.length - 1; i >= 0; i -= 1) {
      const k = keys[i];
      work.push({ value: v[k], where: `${where}.${k}` });
      work.push({ emit: `${quote(k, where)}:` });
      if (i > 0) work.push({ emit: ',' });
    }
  }

  return chunks.join('');
}

/**
 * The canonical text a record's digest is taken over: rules 1 to 3 applied.
 *
 * @param {unknown} record
 * @returns {string}
 */
export function canonicalText(record) {
  if (
    record !== null &&
    typeof record === 'object' &&
    !Array.isArray(record) &&
    isPlainObject(record)
  ) {
    const subject = {};
    for (const k of Object.keys(record)) {
      if (!EXCLUDED_TOP_LEVEL_KEYS.includes(k)) subject[k] = record[k];
    }
    return canonicalTextRaw(subject);
  }
  return canonicalTextRaw(record);
}

/**
 * Rule 5. `evidenceDigest(r)` is exactly `sha256(canonicalText(r))` and the two
 * must never drift apart.
 *
 * @param {unknown} record
 * @returns {string}
 */
export function evidenceDigest(record) {
  return createHash('sha256').update(canonicalText(record), 'utf8').digest('hex');
}

/** SHA-256 of arbitrary bytes, lowercase hex. Used for artefact digests. */
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * The digest of a value with one extra top-level key removed as well.
 *
 * A manifest has to carry its own digest, and a field cannot commit to itself.
 * Rule 1 removes `context` and `evidenceDigest` and nothing else, so rather
 * than widening rule 1 — which would move every digest in the repository — the
 * self-digest field is named here, at the one call site that needs it.
 *
 * @param {Record<string, unknown>} record
 * @param {string} selfKey
 * @returns {string}
 */
export function digestExcludingSelf(record, selfKey) {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    throw new CanonError('a self-digested record must be a JSON object');
  }
  const copy = { ...record };
  delete copy[selfKey];
  return evidenceDigest(copy);
}
