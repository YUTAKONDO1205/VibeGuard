// Re-derivation of the canonical text, written from the rules — the FOURTH
// implementation in this repository, and deliberately not the third.
//
// ── WHY A VERIFIER MAY NOT IMPORT ITS GENERATOR ─────────────────────────────
//
// `@vibeguard/evidence-bundle` next door already has a canonicaliser, and
// importing it here would be one line. It would also make every check in this
// package vacuous: two sides that share an implementation agree by
// construction, so "the digest matches" would mean "the same function was run
// twice", which is true of a correct record and of a broken one alike.
//
// The toolchain workspace made the same decision for the same reason and says
// so in its own header. This file follows it. Nothing on the verification path
// imports the generator; the only shared thing is the CONTRACT — the digest
// vectors — and the calibration test proves both sides reproduce it.
//
// ── AND WHY IT IS A DIFFERENT SHAPE AGAIN ───────────────────────────────────
//
// Three implementations already exist: sort-into-a-new-object-then-stringify,
// a recursive text emitter, and (next door) an iterative emitter with an
// explicit work stack and a hand-rolled string escaper. This one is TWO-PHASE:
// it validates the entire tree first, collecting the violation with its path,
// and only then emits. The practical difference shows up on a record with two
// problems — a single-pass emitter reports whichever it reaches first and
// stops, which makes fixing a bad record a sequence of runs. The reason for
// doing it here, though, is simply that a fourth opinion arrived at the same
// way as the third is not a fourth opinion.
//
// It also uses `JSON.stringify` for string literals where the generator hand-
// rolls the escaper, so the vectors covering control characters, astral planes
// and combining marks compare two genuinely different escapers rather than one
// function against itself.
//
// ── FINDING IDS ─────────────────────────────────────────────────────────────
//
// This package emits `VG-ART-08N` and `VG-ART-09N`. The namespace is the
// artefact verifier's (schema/interfaces.md section 2). The 050-069 band is
// taken by the toolchain-side record checks and 070-079 was observed in use by
// the provenance component, so the bundle-integrity checks start at 080.
// Where a condition is EXACTLY one the toolchain side already names —
// `evidenceDigest` disagreeing with the record it seals, or an artefact whose
// bytes do not hash to what the record says — the SAME id is reused on purpose.
// Two ids for one condition is worse than a shared one: it makes a report that
// has to be read twice to notice it says one thing.

import { createHash } from 'node:crypto';

export class MalformedRecordError extends Error {
  constructor(message, where) {
    super(where ? `${message} (at ${where})` : message);
    this.name = 'MalformedRecordError';
    this.where = where ?? null;
  }
}

/** Rule 1: the top-level keys removed before digesting. `context` goes whole. */
const EXCLUDED = ['context', 'evidenceDigest'];

/** A key the language treats as an array index. Derived here, not imported. */
function isArrayIndexKey(k) {
  if (typeof k !== 'string' || k.length === 0 || k.length > 10) return false;
  if (!/^(0|[1-9][0-9]*)$/.test(k)) return false;
  return Number(k) < 4294967295;
}

/**
 * Phase one. Walks the whole tree and returns EVERY violation, each with the
 * path it was found at. An empty array means the tree can be emitted.
 *
 * @param {unknown} value
 * @param {string} where
 * @param {Array<{where: string, message: string}>} problems
 * @param {Set<object>} onPath
 */
function validate(value, where, problems, onPath) {
  if (value === null) return;
  const t = typeof value;

  if (t === 'boolean' || t === 'string') return;

  if (t === 'number') {
    if (!Number.isFinite(value)) {
      problems.push({ where, message: `non-finite number ${String(value)}` });
      return;
    }
    if (!Number.isInteger(value)) {
      problems.push({
        where,
        message:
          `non-integer number ${value}; a ratio is a pair of integer counts and this is not a ` +
          'rounding question',
      });
      return;
    }
    if (!Number.isSafeInteger(value)) {
      problems.push({ where, message: `integer ${value} is outside the exact-integer range` });
    }
    return;
  }

  if (t === 'undefined') {
    problems.push({
      where,
      message: 'undefined is not a JSON value; null is what the contract means by "not applicable"',
    });
    return;
  }
  if (t === 'bigint' || t === 'function' || t === 'symbol') {
    problems.push({ where, message: `a value of type ${t} cannot appear in a record` });
    return;
  }

  if (onPath.has(value)) {
    problems.push({ where, message: 'the record contains a cycle' });
    return;
  }
  onPath.add(value);

  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      validate(value[i], `${where}[${i}]`, problems, onPath);
    }
    onPath.delete(value);
    return;
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    problems.push({
      where,
      message:
        `a ${value?.constructor?.name ?? 'non-plain object'} cannot appear in a record; convert ` +
        'it to plain data rather than letting it serialise as {}',
    });
    onPath.delete(value);
    return;
  }

  for (const k of Object.keys(value)) {
    if (isArrayIndexKey(k)) {
      problems.push({
        where,
        message:
          `the key ${JSON.stringify(k)} is an array index in JavaScript, so the engine orders it ` +
          'ahead of every string key and rule 2 no longer determines the byte order',
      });
    }
    validate(value[k], `${where}.${k}`, problems, onPath);
  }
  onPath.delete(value);
}

/** Phase two. Only ever called on a tree phase one accepted. */
function emit(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number') return String(value);
  if (Array.isArray(value)) {
    // Rule 2, second half: array order is significant and is never sorted.
    const parts = new Array(value.length);
    for (let i = 0; i < value.length; i += 1) parts[i] = emit(value[i]);
    return `[${parts.join(',')}]`;
  }
  // Rule 2, first half: keys sort at every level. The default comparator is
  // lexicographic by UTF-16 code unit, which is the ordering the rule means.
  const keys = Object.keys(value).sort();
  const parts = new Array(keys.length);
  for (let i = 0; i < keys.length; i += 1) {
    parts[i] = `${JSON.stringify(keys[i])}:${emit(value[keys[i]])}`;
  }
  // Rule 3 holds by construction: nothing above emits a space.
  return `{${parts.join(',')}}`;
}

/**
 * Every rule violation in a value, with its path. Empty when the value is a
 * well-formed record body.
 *
 * @param {unknown} value
 * @returns {Array<{where: string, message: string}>}
 */
export function canonicalisationProblems(value) {
  const problems = [];
  validate(value, '$', problems, new Set());
  return problems;
}

/**
 * The canonical text a digest is taken over, re-derived from the rules.
 *
 * @param {unknown} record
 * @param {{selfKey?: string}} [opts] an extra top-level key to remove, for a
 *   manifest whose own digest cannot commit to itself.
 * @returns {string}
 */
export function rederiveCanonicalText(record, opts = {}) {
  let subject = record;
  if (record !== null && typeof record === 'object' && !Array.isArray(record)) {
    const proto = Object.getPrototypeOf(record);
    if (proto === Object.prototype || proto === null) {
      subject = {};
      for (const k of Object.keys(record)) {
        if (EXCLUDED.includes(k)) continue;
        if (opts.selfKey !== undefined && k === opts.selfKey) continue;
        subject[k] = record[k];
      }
    }
  }
  const problems = canonicalisationProblems(subject);
  if (problems.length > 0) {
    const first = problems[0];
    const more = problems.length > 1 ? ` (and ${problems.length - 1} more)` : '';
    throw new MalformedRecordError(`${first.message}${more}`, first.where);
  }
  return emit(subject);
}

/**
 * The canonical text of a SUB-object: rules 2 to 4, with no top-level key
 * removed. Rule 1 applies to a record's top level and nowhere else — a key
 * called `context` inside `context` is an ordinary key, and the vectors say so
 * — which is why the manifest's `contextDigest` is taken over this and not
 * over {@link rederiveCanonicalText}.
 *
 * @param {unknown} value
 * @returns {string}
 */
export function rederiveCanonicalTextRaw(value) {
  const problems = canonicalisationProblems(value);
  if (problems.length > 0) {
    const first = problems[0];
    const more = problems.length > 1 ? ` (and ${problems.length - 1} more)` : '';
    throw new MalformedRecordError(`${first.message}${more}`, first.where);
  }
  return emit(value);
}

/** Rule 5. */
export function rederiveDigest(record, opts = {}) {
  return createHash('sha256')
    .update(rederiveCanonicalText(record, opts), 'utf8')
    .digest('hex');
}

/** SHA-256 of arbitrary bytes, lowercase hex. */
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}
