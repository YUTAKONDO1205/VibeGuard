// Turning a linker's idea of an input into something a policy can name, and a
// record can carry.
//
// THE PROBLEM
//
// A link's inputs are absolute paths on the machine that ran it:
//
//     /lib/x86_64-linux-gnu/Scrt1.o
//     /usr/bin/../lib/gcc/x86_64-linux-gnu/13/crtbeginS.o
//     ./libarch.a(arch.o)
//     main.o
//
// interfaces.md §5 forbids absolute paths in a record, for a reason that is not
// tidiness: a digest computed over a machine-specific string is not reproducible
// anywhere else, so the record stops being evidence. But the crt objects are
// genuinely outside any fixture root, and dropping them would leave the policy
// unable to say anything about the inputs that run before `main`.
//
// THE SHAPE USED HERE
//
// Each input gets a `ref`: a portable string that identifies it well enough for
// a policy to authorise it and for a record to be compared across machines.
//
//     main.o                                        under the link root
//     libarch.a(arch.o)                             under the link root, archive member
//     system:lib/x86_64-linux-gnu/Scrt1.o           outside it, on a toolchain root
//     system:usr/lib/gcc/x86_64-linux-gnu/13/crtbeginS.o
//     withheld:rogue.o                              outside it, on a MACHINE root
//
// The last form is the interesting one. A path through /home, /root, /mnt or
// /Users names a person's account, and emitting it is the disclosure the
// repository's own gate exists to catch. So the path is withheld, the basename
// and the digest of the bytes are kept — which is what identifies the input
// anyway — and the withholding is RECORDED as a problem rather than done
// silently. "Reports the problem instead of emitting it", per §5.
//
// MATCHING
//
// A policy entry matches a ref when it is equal to it, when it glob-matches it,
// or — only when the entry contains no `/` — when it equals the ref's basename.
// The record says which of the three matched, because a basename match is the
// weakest of them and a reader should be able to see that it was the one used.

import { basename as pathBasename } from 'node:path';

/** Path roots that identify a machine or a person rather than a toolchain. */
export const MACHINE_ROOTS = Object.freeze(['root', 'home', 'Users', 'users', 'mnt', 'media', 'srv', 'tmp', 'private']);

/** Collapse `.` and `..`, force forward slashes. Does not touch the filesystem. */
export function normalisePath(p) {
  const s = String(p).replace(/\\/g, '/');
  const absolute = s.startsWith('/');
  const out = [];
  for (const seg of s.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length > 0 && out[out.length - 1] !== '..') out.pop();
      else if (!absolute) out.push('..');
      continue;
    }
    out.push(seg);
  }
  return (absolute ? '/' : '') + out.join('/');
}

/**
 * Split `libfoo.a(member.o)` into its two halves. Returns null when the string
 * is not an archive member reference.
 */
export function splitArchiveMember(s) {
  const m = /^(.*)\(([^()]+)\)$/.exec(String(s));
  if (!m) return null;
  return { archive: m[1], member: m[2] };
}

function isUnder(child, root) {
  if (root === '') return false;
  const r = root.endsWith('/') ? root.slice(0, -1) : root;
  return child === r || child.startsWith(r + '/');
}

function relativeTo(child, root) {
  const r = root.endsWith('/') ? root.slice(0, -1) : root;
  return child === r ? '.' : child.slice(r.length + 1);
}

/**
 * Portable identity for one linker input.
 *
 * @param {string} raw       what the linker called it
 * @param {string} linkRoot  absolute, normalised directory the link ran in
 * @returns {{ref: string, kind: 'in-root'|'system'|'withheld', base: string,
 *            archive: string|null, member: string|null, pathWithheld: boolean,
 *            withheldReason: string|null}}
 */
export function makeRef(raw, linkRoot) {
  const arch = splitArchiveMember(raw);
  const filePart = arch ? arch.archive : String(raw);

  // `<internal>` is lld's synthetic input: sections it generates itself. It is
  // not a file and must never be reported as an unauthorised one.
  if (filePart === '<internal>' || filePart === '<internal>:') {
    return { ref: 'internal:<linker-generated>', kind: 'system', base: '<linker-generated>', archive: null, member: null, pathWithheld: false, withheldReason: null };
  }

  const root = normalisePath(linkRoot);
  const abs = filePart.startsWith('/') ? normalisePath(filePart) : normalisePath(root + '/' + filePart);
  const base = pathBasename(abs);

  const wrap = (stem) => (arch ? `${stem}(${arch.member})` : stem);

  if (isUnder(abs, root)) {
    return {
      ref: wrap(relativeTo(abs, root)),
      kind: 'in-root',
      base: arch ? arch.member : base,
      archive: arch ? relativeTo(abs, root) : null,
      member: arch ? arch.member : null,
      pathWithheld: false,
      withheldReason: null,
    };
  }

  const firstSeg = abs.split('/').filter(Boolean)[0] ?? '';
  if (MACHINE_ROOTS.includes(firstSeg)) {
    return {
      ref: wrap(`withheld:${base}`),
      kind: 'withheld',
      base: arch ? arch.member : base,
      archive: arch ? `withheld:${base}` : null,
      member: arch ? arch.member : null,
      pathWithheld: true,
      // Worded without a leading slash on purpose: this string goes into the
      // record, and a record may not carry an absolute path even inside an
      // explanation of why it is not carrying one.
      withheldReason: `the path is rooted at a directory that names an account rather than a toolchain (root segment: ${firstSeg})`,
    };
  }

  const stem = `system:${abs.replace(/^\//, '')}`;
  return {
    ref: wrap(stem),
    kind: 'system',
    base: arch ? arch.member : base,
    archive: arch ? stem : null,
    member: arch ? arch.member : null,
    pathWithheld: false,
    withheldReason: null,
  };
}

/** `*` matches within a segment, `**` across segments, `?` matches one character. */
export function globToRegExp(pattern) {
  let re = '';
  const p = String(pattern);
  for (let i = 0; i < p.length; i += 1) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        re += '.*';
        i += 1;
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return new RegExp(`^${re}$`);
}

/**
 * Decide whether `ref` is on `allowed`.
 *
 * @returns {{allowed: boolean, by: 'exact'|'glob'|'basename'|null, pattern: string|null}}
 */
export function matchRef(ref, allowed, base) {
  const list = Array.isArray(allowed) ? allowed : [];
  for (const pat of list) if (pat === ref) return { allowed: true, by: 'exact', pattern: pat };
  for (const pat of list) {
    if (!/[*?]/.test(pat)) continue;
    if (globToRegExp(pat).test(ref)) return { allowed: true, by: 'glob', pattern: pat };
  }
  // Basename matching only for entries that carry no path of their own: an
  // entry that names a directory meant that directory, and quietly ignoring it
  // would turn a specific authorisation into a general one.
  for (const pat of list) {
    if (pat.includes('/') || /[*?]/.test(pat)) continue;
    if (pat === base) return { allowed: true, by: 'basename', pattern: pat };
  }
  return { allowed: false, by: null, pattern: null };
}
