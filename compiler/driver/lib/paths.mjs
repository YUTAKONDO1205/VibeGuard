// Paths in records. interfaces.md §5: "Absolute paths must not appear anywhere
// in a record. Write paths relative to the fixture root. A component that
// cannot avoid one reports the problem instead of emitting it."
//
// The second sentence is the load-bearing one, and it is why the guard here
// runs over the finished record rather than over the places the driver
// remembered to call a helper. A record is only as portable as its worst
// string, and the strings that leak are the ones nobody routed through the
// helper: a peer component's finding detail, a clang diagnostic quoted into a
// field, an `-I/opt/...` that arrived joined.

import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve, sep } from 'node:path';

/** Make `p` relative to `root`, in POSIX form. Returns null if p is not a path-ish string. */
export function toRecordPath(p, root) {
  if (typeof p !== 'string' || p.length === 0) return p;
  const abs = isAbsolute(p) ? p : resolve(root, p);
  const rel = relative(root, abs);
  // The root itself is `.`, not the empty string. An empty string in a record
  // reads as "no value", and the root is a value.
  return rel === '' ? '.' : rel.split(sep).join('/');
}

/**
 * Rewrite a command-line token so that any absolute path inside it becomes
 * relative to `root`. Handles bare paths and the joined forms clang accepts
 * (`-I/abs`, `-o/abs`, `--sysroot=/abs`).
 *
 * A path that resolves outside `root` cannot be written relatively without
 * leaking the shape of the machine above the root, so it is replaced by a
 * stable content-addressed placeholder: deterministic across runs on the same
 * machine, meaningless off it, and — the point — not an absolute path.
 */
export function relativiseToken(token, root) {
  if (typeof token !== 'string' || token.length === 0) return token;

  const rewriteOne = (p) => {
    const abs = resolve(p);
    const rel = relative(root, abs);
    if (rel === '' ) return '.';
    if (!rel.startsWith('..')) return rel.split(sep).join('/');
    return `<outside:${createHash('sha256').update(abs).digest('hex').slice(0, 12)}>`;
  };

  if (looksAbsolute(token)) return rewriteOne(token);

  // Joined forms: a leading flag, then something absolute.
  //
  // The split cannot be done with one greedy match. `-IC:\x` is a joined flag
  // carrying a Windows path, and a flag class that accepts letters swallows the
  // DRIVE LETTER along with the flag: the halves come out as `-IC` and `:\x`,
  // the second of which is not absolute, so the token passed through unrewritten
  // and an absolute path reached the record — the one thing interfaces.md §5
  // forbids. It only ever showed on a host with drive letters, which is why a
  // suite that is green on Linux did not say so.
  //
  // So every split point is tried, longest flag first, and the first one whose
  // tail is genuinely absolute wins. `-IC:\x` falls through `-IC` (tail `:\x`,
  // not absolute) to `-I` (tail `C:\x`, absolute).
  const FLAG = /^-{1,2}[A-Za-z0-9_+-]*=?$/;
  for (let i = token.length - 1; i >= 1; i -= 1) {
    const head = token.slice(0, i);
    if (!FLAG.test(head)) continue;
    const tail = token.slice(i);
    if (looksAbsolute(tail)) return head + rewriteOne(tail);
  }

  return token;
}

export function looksAbsolute(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  if (s.startsWith('/')) return true;
  if (/^[A-Za-z]:[\\/]/.test(s)) return true;
  if (s.startsWith('\\\\')) return true;
  return false;
}

// Strings that contain an absolute path somewhere inside them rather than at
// the start. Deliberately conservative — a false hit costs a loud exit 3 and a
// one-line fix, a missed one costs a record that is wrong on another machine
// and nobody notices until it is quoted in a paper.
const EMBEDDED = [
  /\/mnt\/[a-z]\//,
  /(^|[\s:="'(,[])\/(?:home|root|usr|opt|var|etc|tmp|proc|sys|bin|sbin|lib|lib64|srv|dev|Users)\//,
  /(^|[\s:="'(,[])[A-Za-z]:[\\/]/,
];

/**
 * Walk a finished record and return JSON-pointer locations of every string that
 * still holds an absolute path.
 */
export function findAbsolutePaths(value, pointer = '', out = []) {
  if (typeof value === 'string') {
    if (looksAbsolute(value) || EMBEDDED.some((re) => re.test(value))) {
      out.push({ pointer: pointer || '(root)', value });
    }
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => findAbsolutePaths(v, `${pointer}/${i}`, out));
    return out;
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      findAbsolutePaths(v, `${pointer}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`, out);
    }
  }
  return out;
}

/**
 * Every number in a record must be an integer (interfaces.md §5 rule 4). The
 * canonicaliser is specified to fail rather than round, so the driver finds its
 * own violations first and says which field, instead of handing the
 * canonicaliser a record and relaying whatever it says.
 */
export function findNonIntegerNumbers(value, pointer = '', out = []) {
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) out.push({ pointer: pointer || '(root)', value });
    return out;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => findNonIntegerNumbers(v, `${pointer}/${i}`, out));
    return out;
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      findNonIntegerNumbers(v, `${pointer}/${k.replace(/~/g, '~0').replace(/\//g, '~1')}`, out);
    }
  }
  return out;
}
