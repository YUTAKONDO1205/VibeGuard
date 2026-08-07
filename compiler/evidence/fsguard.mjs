// Refusing a symlinked input instead of following it.
//
// WHAT THIS DEFENDS AND WHAT IT DOES NOT
//
//   A verifier that opens whatever path it is handed reports on the bytes at
//   the far end of the link while naming the near end. Every line of the report
//   — the file name, the digest, the counts — is then true of a file the reader
//   is not looking at, and the substitution needs no privileges and leaves no
//   trace in the record. It is also survivable by accident: a store directory
//   restored as a link to an older copy verifies clean and dates from last
//   month.
//
//   So the resolution is refused rather than performed, and the refusal names
//   the link. It is not a security boundary against a determined author of the
//   evidence — see the detection-range statement in STORE.md, which says
//   plainly that a coherent REGENERATION of the whole store is outside what
//   anything here can see. It is a guard against the report describing a
//   different file from the one it names.
//
// THE ANCESTORS ARE CHECKED TOO
//
//   Checking only the final component catches `store/run-1.json -> elsewhere`
//   and misses `store -> elsewhere/`, which redirects every file beneath it at
//   once and is the cheaper substitution of the two. It is also the one that
//   was found first, by pointing the validator at a junctioned copy of a real
//   store and watching it report every record clean while naming paths that did
//   not hold them. So the walk goes all the way up to the filesystem root by
//   default.
//
//   A machine whose home directory is itself a link — an H: mapping, a macOS
//   `/tmp` — will trip that, and legitimately so: the tool cannot tell that
//   redirection apart from the other kind. `boundary` stops the walk at a named
//   directory for exactly that case. It is a parameter and not an inferred
//   exemption because someone has to say which link is the expected one; a
//   guard that works out for itself which redirections are fine is not a guard.
//
// ON WINDOWS
//
//   `lstat` reports a directory junction as a symbolic link, which is what is
//   wanted: a junction performs exactly the redirection described above. An
//   unprivileged process on Windows cannot create a *file* symlink at all, so
//   the junction is also the only form the tests here can build on that
//   platform; the code path is one and the same `isSymbolicLink()` test over
//   one and the same list of components.

import { lstatSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';

export class SymlinkRefused extends Error {
  /**
   * @param {string} target The path that was asked for.
   * @param {string[]} links The offending components, nearest first.
   * @param {string} role What the path was going to be used as.
   */
  constructor(target, links, role) {
    super(
      `refusing to follow a symbolic link on the path to ${role} ${JSON.stringify(target)}:\n` +
        links.map((l) => `  ${l} is a link`).join('\n') +
        '\nA report that names one path and reads another is wrong in every line. Point the ' +
        'tool at the real path, or replace the link with the thing itself.',
    );
    this.name = 'SymlinkRefused';
    this.target = target;
    this.links = links;
    this.role = role;
  }
}

/** True when `child` is `parent` or lies beneath it. */
export function isWithin(parent, child) {
  const p = resolve(parent);
  const c = resolve(child);
  if (p === c) return true;
  const rel = relative(p, c);
  return rel !== '' && !rel.startsWith('..') && !rel.startsWith(`${sep}`) && !/^[A-Za-z]:/.test(rel);
}

/**
 * Every component of the path to `target` that is a symbolic link, nearest
 * first. Components that do not exist are not links and are not reported;
 * a missing file is a different complaint, raised by the caller.
 *
 * @param {string} target
 * @param {{ancestors?: boolean, boundary?: string|null}} [opts]
 *   `ancestors` defaults to true: the walk climbs to the filesystem root.
 *   `boundary`, when given, stops it at that directory, inclusive.
 * @returns {string[]}
 */
export function findSymlinks(target, opts = {}) {
  const abs = resolve(target);
  const ancestors = opts.ancestors !== false;
  const boundary = opts.boundary == null ? null : resolve(opts.boundary);
  // A boundary that the target is not under cannot stop the walk, and silently
  // ignoring it would turn a mis-set boundary into a walk to the root that the
  // caller did not ask for. It is honoured only when it is really above.
  const stopAt = boundary !== null && isWithin(boundary, abs) ? boundary : null;

  const found = [];
  let cur = abs;
  for (;;) {
    let st = null;
    try {
      st = lstatSync(cur);
    } catch {
      st = null;
    }
    if (st !== null && st.isSymbolicLink()) found.push(cur);
    if (!ancestors || cur === stopAt) break;
    const parent = dirname(cur);
    if (parent === cur) break;
    cur = parent;
  }
  return found;
}

/**
 * Throw {@link SymlinkRefused} when any component of the path is a link.
 *
 * @param {string} target
 * @param {{ancestors?: boolean, boundary?: string|null, role?: string}} [opts]
 */
export function assertNoSymlink(target, opts = {}) {
  const links = findSymlinks(target, opts);
  if (links.length > 0) throw new SymlinkRefused(target, links, opts.role ?? 'the input');
  return resolve(target);
}
