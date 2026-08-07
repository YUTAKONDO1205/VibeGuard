// Keeping machine-specific paths out of the record, at the moment the record is
// built rather than in a scan afterwards.
//
// interfaces.md §5: "Absolute paths must not appear anywhere in a record. Write
// paths relative to the fixture root. A component that cannot avoid one reports
// the problem instead of emitting it."
//
// The reason the gate is here and not in a later pass is the same reason the
// evidence component gives: by the time a scan runs, the offending string has
// already been digested, and every digest computed over it is reproducible on
// exactly one machine. So a record with an absolute path is never written; the
// run reports the offenders and exits 3.
//
// Note what is scrubbed and what is asserted. Link options are SCRUBBED, because
// `-rpath=/opt/x/lib` is a legitimate option whose path is incidental to it and
// the option is worth recording. Everything else is ASSERTED, because a path
// turning up somewhere unexpected means this component built the record wrong,
// and quietly rewriting it would hide that.

import { makeRef } from './refs.mjs';

const DRIVE = /(?:^|[^A-Za-z0-9_])([A-Za-z]:[\\/])/;
const UNC = /^\\\\[^\\]/;
const FILE_URL = /\bfile:\/\/\//i;
const HOME_TILDE = /(?:^|[\s"'(=,;:])~\//;
const LEADING_SLASH = /^\//;
const EMBEDDED_ABS = /(?:^|[\s"'(=,;:])\/[A-Za-z0-9_.]/;

/** null when clean, otherwise `{kind, match}`. */
export function classifyAbsolutePath(s) {
  if (typeof s !== 'string' || s.length === 0) return null;
  let m;
  if (UNC.test(s)) return { kind: 'unc', match: s.slice(0, 12) };
  if ((m = DRIVE.exec(s))) return { kind: 'windows-drive', match: m[1] };
  if ((m = FILE_URL.exec(s))) return { kind: 'file-url', match: m[0] };
  if ((m = HOME_TILDE.exec(s))) return { kind: 'home-relative', match: m[0].trim() };
  if (LEADING_SLASH.test(s)) return { kind: 'posix-absolute', match: s.slice(0, 32) };
  if ((m = EMBEDDED_ABS.exec(s))) return { kind: 'embedded-absolute', match: m[0].trim() };
  return null;
}

/** Every absolute-looking string in `value`, in keys as well as values. */
export function findAbsolutePaths(value, { skipTopLevelKeys = [] } = {}) {
  const skip = new Set(skipTopLevelKeys);
  const out = [];
  const visit = (v, where, depth) => {
    if (v === null || v === undefined) return;
    if (typeof v === 'string') {
      const hit = classifyAbsolutePath(v);
      if (hit) out.push({ where, in: 'value', value: v, ...hit });
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => visit(x, `${where}[${i}]`, depth + 1));
      return;
    }
    if (typeof v === 'object') {
      for (const k of Object.keys(v)) {
        if (depth === 0 && skip.has(k)) continue;
        const kw = `${where}.${k}`;
        const hit = classifyAbsolutePath(k);
        if (hit) out.push({ where: kw, in: 'key', value: k, ...hit });
        visit(v[k], kw, depth + 1);
      }
    }
  };
  visit(value, '$', 0);
  return out;
}

/**
 * Replace every absolute path inside a free-text string with its portable ref.
 * Used on linker options and on the text of problems, which are the two places
 * a path arrives inside a sentence rather than as a field of its own.
 */
export function scrubText(s, linkRoot) {
  if (typeof s !== 'string') return s;
  return s
    .replace(/[A-Za-z]:[\\/][^\s,;"']*/g, (p) => makeRef(p.replace(/\\/g, '/'), linkRoot).ref)
    .replace(/(^|[\s,=:("'])(\/[^\s,;"')]*)/g, (whole, lead, p) => `${lead}${makeRef(p, linkRoot).ref}`);
}
