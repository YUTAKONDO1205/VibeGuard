// Path hygiene for evidence records.
//
// THE RULE (interfaces.md §5, last paragraph)
//
//   Absolute paths must not appear anywhere in a record. Paths are written
//   relative to the fixture root. A component that cannot avoid an absolute
//   path reports the problem instead of emitting it.
//
// WHY THIS IS A GENERATION-SIDE GATE AND NOT A LATER INSPECTION
//
//   A scan that runs after the fact finds a leak in a file that has already
//   been digested, referenced by an index, and possibly sealed. By then the
//   cheapest repair is to regenerate everything downstream of it, and the
//   expensive part is not the regeneration — it is that every digest computed
//   in between was computed over a machine-specific string and is therefore
//   not reproducible on any other machine. So the check runs *before* the
//   digest, inside `sealRecord`, and a record containing an absolute path is
//   never written at all. `verify.mjs` repeats the scan, but only as a second
//   opinion on records that some other generator produced; the first opinion
//   is the one that matters and it is here.
//
// WHAT COUNTS AS ABSOLUTE
//
//   Two modes, because two documents in the tree disagree and both are right
//   about their own scope:
//
//   'strict'        — the interfaces.md rule. Any leading `/`, any drive
//                     letter, any UNC prefix, any `file://`, any `~/`. This is
//                     the default and it is what a record written here obeys.
//   'machine-roots' — the looser convention the prototype workspace's own
//                     hygiene report uses: toolchain paths under /usr and
//                     device paths such as /dev/null are provenance rather
//                     than machine identity, and are allowed; anything rooted
//                     at a user or workspace directory is not. Offered so that
//                     records imported from elsewhere can be measured against
//                     the rule they were written under, rather than being
//                     reported as broken by a rule they never claimed.
//
//   Both modes look at object *keys* as well as string values. A record that
//   carries a per-file map keyed by path leaks exactly as much through its
//   keys as it would through its values, and a scanner that only reads values
//   would pass it.

/** Roots that identify a machine or a user rather than a toolchain. */
export const MACHINE_ROOTS = Object.freeze([
  'root',
  'home',
  'Users',
  'mnt',
  'media',
  'srv',
  'tmp',
  'var/folders',
  'private/var',
]);

const MACHINE_ROOT_RE = new RegExp(
  String.raw`(?:^|[^A-Za-z0-9_.\-])\/(?:${MACHINE_ROOTS.map((r) => r.replace('/', '\\/')).join('|')})(?:\/|$)`,
);

// A Windows drive letter anywhere in the string, not only at the start: an
// absolute path embedded in a sentence ("loaded from C:\...") is the same leak.
const DRIVE_RE = /(?:^|[^A-Za-z0-9_])([A-Za-z]:[\\/])/;
const UNC_RE = /^\\\\[^\\]/;
const FILE_URL_RE = /\bfile:\/\/\//i;
const HOME_TILDE_RE = /(?:^|[\s"'(=,;:])~\//;
const LEADING_SLASH_RE = /^\//;

/**
 * Classify one string. Returns null when the string is clean, otherwise
 * `{ kind, match }` naming which rule it broke and the text that broke it.
 *
 * @param {string} s
 * @param {{mode?: 'strict'|'machine-roots'}} [opts]
 */
export function classifyAbsolutePath(s, opts = {}) {
  if (typeof s !== 'string' || s.length === 0) return null;
  const mode = opts.mode ?? 'strict';

  let m;
  if ((m = UNC_RE.exec(s))) return { kind: 'unc', match: s.slice(0, 12) };
  if ((m = DRIVE_RE.exec(s))) return { kind: 'windows-drive', match: m[1] };
  if ((m = FILE_URL_RE.exec(s))) return { kind: 'file-url', match: m[0] };
  if ((m = HOME_TILDE_RE.exec(s))) return { kind: 'home-relative', match: m[0].trim() };
  if ((m = MACHINE_ROOT_RE.exec(s))) return { kind: 'machine-root', match: m[0].trim() };
  if (mode === 'strict' && (m = LEADING_SLASH_RE.exec(s))) {
    return { kind: 'posix-absolute', match: s.slice(0, 24) };
  }
  return null;
}

/** True when `s` would be rejected under `opts.mode`. */
export function isAbsoluteLike(s, opts = {}) {
  return classifyAbsolutePath(s, opts) !== null;
}

function isPlainObject(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/**
 * Walk a record and collect every absolute-looking string, in both keys and
 * values. Returns `[{ where, in: 'key'|'value', value, kind, match }]`.
 *
 * `where` is a JavaScript-ish access path (`$.command.argv[2]`) so that the
 * report names the field rather than the offending text alone — a bare string
 * in an error message is not enough to find where it came from.
 *
 * @param {unknown} value
 * @param {{mode?: 'strict'|'machine-roots', skipTopLevelKeys?: string[]}} [opts]
 */
export function findAbsolutePaths(value, opts = {}) {
  const mode = opts.mode ?? 'strict';
  const skip = new Set(opts.skipTopLevelKeys ?? []);
  const out = [];

  const visit = (v, where, depth) => {
    if (v === null || v === undefined) return;
    if (typeof v === 'string') {
      const hit = classifyAbsolutePath(v, { mode });
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
        const hit = classifyAbsolutePath(k, { mode });
        if (hit) out.push({ where: kw, in: 'key', value: k, ...hit });
        visit(v[k], kw, depth + 1);
      }
    }
  };

  visit(value, '$', 0);
  return out;
}

export class AbsolutePathError extends Error {
  constructor(offenders, label) {
    const lines = offenders.map(
      (o) => `  ${o.where} (${o.in}, ${o.kind}): ${JSON.stringify(o.value)}`,
    );
    super(
      `${label} contains ${offenders.length} absolute path${offenders.length === 1 ? '' : 's'}; ` +
        'records carry paths relative to the fixture root, and a component that cannot ' +
        'produce one reports the problem instead of emitting it:\n' +
        lines.join('\n'),
    );
    this.name = 'AbsolutePathError';
    this.offenders = offenders;
  }
}

/**
 * Generation-side gate. Throws `AbsolutePathError` listing every offender —
 * all of them, not the first, because fixing them one exception at a time is
 * how a generator ends up being run five times to find five paths.
 */
export function assertNoAbsolutePaths(value, opts = {}) {
  const offenders = findAbsolutePaths(value, opts);
  if (offenders.length > 0) throw new AbsolutePathError(offenders, opts.label ?? 'record');
}

function splitSegments(p) {
  return String(p)
    .replace(/\\/g, '/')
    .split('/')
    .filter((s) => s !== '' && s !== '.');
}

function isAbsolutePathname(p) {
  const s = String(p);
  return /^\//.test(s) || /^[A-Za-z]:[\\/]/.test(s) || /^\\\\/.test(s);
}

function driveOf(p) {
  const m = /^([A-Za-z]):[\\/]/.exec(String(p));
  return m ? m[1].toLowerCase() : null;
}

/**
 * The path a record should carry: `p` expressed relative to `root`, with
 * forward slashes on every platform. Both arguments may be absolute; the
 * result never is.
 *
 * Throws when the result would have to escape `root` (unless
 * `allowOutside: true`), and when `p` and `root` are on different Windows
 * drives — in both cases there is no relative path that means the same thing
 * on another machine, which is the condition the contract says to report
 * rather than paper over.
 *
 * @param {string} p
 * @param {string} root
 * @param {{allowOutside?: boolean}} [opts]
 */
export function relativise(p, root, opts = {}) {
  if (typeof p !== 'string' || typeof root !== 'string') {
    throw new TypeError('relativise(p, root): both arguments must be strings');
  }
  const pd = driveOf(p);
  const rd = driveOf(root);
  if (pd && rd && pd !== rd) {
    throw new Error(
      `cannot express ${JSON.stringify(p)} relative to ${JSON.stringify(root)}: different drives`,
    );
  }
  if (!isAbsolutePathname(p)) {
    // Already relative. Normalise the separators and leave it alone.
    const segs = splitSegments(p);
    const rel = segs.join('/');
    if (!opts.allowOutside && segs[0] === '..') {
      throw new Error(`relative path ${JSON.stringify(p)} escapes its root`);
    }
    return rel === '' ? '.' : rel;
  }

  const ps = splitSegments(pd ? p.slice(2) : p);
  const rs = splitSegments(rd ? root.slice(2) : root);
  let i = 0;
  while (i < ps.length && i < rs.length && ps[i] === rs[i]) i++;
  const up = rs.length - i;
  if (up > 0 && !opts.allowOutside) {
    throw new Error(
      `cannot express ${JSON.stringify(p)} relative to ${JSON.stringify(root)} without leaving ` +
        'the root; pass { allowOutside: true } only if the record is allowed to point outside it',
    );
  }
  const segs = [...Array(up).fill('..'), ...ps.slice(i)];
  return segs.length === 0 ? '.' : segs.join('/');
}
