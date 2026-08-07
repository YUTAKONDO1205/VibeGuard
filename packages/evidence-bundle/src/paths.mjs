// Absolute paths must not appear in a record (schema/interfaces.md section 5).
//
// Two reasons, and they are different reasons:
//
//   * a record carrying `/home/<someone>/work/...` publishes an account name
//     the moment it is committed, and no word list can contain an account name
//     because it is whatever the person who installed the machine typed;
//   * a record is supposed to be reproducible from a fixture root. A path that
//     only resolves on one machine makes the record unusable everywhere else
//     while still looking complete.
//
// The gate runs BEFORE the digest, so a record carrying such a path is never
// written, never digested, and never referenced by anything downstream.

/**
 * Shapes that make a string an absolute path rather than a fixture-relative
 * one. MOST SPECIFIC FIRST: `mounted-drive` also matches the `posix` shape, and
 * the first match wins, so listing `posix` first would report every mounted
 * Windows path as "starts with a slash" and lose the one detail that says which
 * machine it came from.
 */
const ABSOLUTE_SHAPES = [
  // A Windows path reached from the Linux side of the same machine.
  { kind: 'mounted-drive', re: /^\/mnt\/[A-Za-z]\//i },
  { kind: 'unc', re: /^\\\\/ },
  { kind: 'drive-letter', re: /^[A-Za-z]:[\\/]/ },
  { kind: 'home-tilde', re: /^~[\\/]/ },
  { kind: 'posix', re: /^\/(?!\/)/ },
];

/**
 * Every absolute-looking path string in a value, with the place it was found.
 *
 * Walks strings only. A key is never treated as a path: a key is schema, and a
 * schema that had an absolute path for a key would be a different problem.
 *
 * @param {unknown} value
 * @param {{ where?: string }} [opts]
 * @returns {Array<{where: string, kind: string, value: string}>}
 */
export function findAbsolutePaths(value, opts = {}) {
  const found = [];
  const seen = new Set();
  const walk = (v, where) => {
    if (typeof v === 'string') {
      for (const shape of ABSOLUTE_SHAPES) {
        if (shape.re.test(v)) {
          found.push({ where, kind: shape.kind, value: v });
          return;
        }
      }
      return;
    }
    if (v === null || typeof v !== 'object') return;
    if (seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) {
      v.forEach((x, i) => walk(x, `${where}[${i}]`));
      return;
    }
    for (const k of Object.keys(v)) walk(v[k], `${where}.${k}`);
  };
  walk(value, opts.where ?? '$');
  return found;
}

export class AbsolutePathError extends Error {
  constructor(leaks, label) {
    super(
      `${label} carries ${leaks.length} absolute path(s): ` +
        `${leaks.map((l) => `${l.where} (${l.kind}) ${JSON.stringify(l.value)}`).join('; ')}. ` +
        'Write paths relative to the fixture root. A component that cannot avoid one reports ' +
        'the problem instead of emitting it.',
    );
    this.name = 'AbsolutePathError';
    this.leaks = leaks;
  }
}

/**
 * Throw unless the value is free of absolute paths.
 *
 * @param {unknown} value
 * @param {{ label?: string }} [opts]
 */
export function assertNoAbsolutePaths(value, opts = {}) {
  const leaks = findAbsolutePaths(value);
  if (leaks.length > 0) throw new AbsolutePathError(leaks, opts.label ?? 'record');
}
