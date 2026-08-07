// Machine identity in a record, and the delegation to the shape checker.
//
// WHAT A RECORD MAY NOT CARRY
//
//   A measurement record is meant to be readable by someone who did not run
//   it. Four kinds of string make that untrue, and the four are not the same
//   problem:
//
//     1. an absolute path under a home directory
//     2. an account name
//     3. a hostname
//     4. a disclosure-shaped string
//
//   (1) is already refused on the generation side by `paths.mjs`, before the
//   digest, and repeated here as a second opinion on records some other
//   generator wrote.
//
//   (4) IS NOT RE-IMPLEMENTED HERE. `scripts/check-disclosure-shape.mjs` in the
//   repository root already detects those by SHAPE — it carries no proper noun
//   at all, which is why it can be tracked and run in CI — and it fires each of
//   its needles against a positive control before it will report a zero.
//   Writing a second detector here would mean a second list to keep in step
//   with the first, and the whole reason that file exists is that lists cannot
//   be kept in step. So it is run, as a process, over the record files, and its
//   verdict is taken. When it cannot be run, the check is reported as NOT
//   COMPLETED — never as clean.
//
//   (2) and (3) are what is left, and they need a different technique, because
//   an account name and a hostname are not words. Two things are done, neither
//   of which is a list of names:
//
//     * The identity of the machine doing the checking is read at runtime and
//       looked for in the record. This is the case that actually happens: the
//       record is written on the machine whose name it leaks, and validated on
//       it too, at least once, before it goes anywhere.
//     * Shapes that are machine identity whatever the name is: a `user@host`
//       token, a UNC prefix, and a home-directory path segment. The last of
//       these overlaps with the shape checker on purpose but not redundantly —
//       the shape checker anchors on a leading slash, and the convention in
//       this tree is to strip it (`usr/bin/clang-18`), which turns
//       `/home/<name>/x` into `home/<name>/x` and slips underneath both that
//       needle and the absolute-path gate. That gap is this function's.
//
//   The allow-list below is a list of accounts that are NOT a person: system
//   users, CI users, placeholders. An allow-list is the opposite of a
//   forbidden-word list — it does not grow with the thing it is trying to
//   catch, and publishing it discloses nothing. Without it, every record
//   produced on a CI runner would report the word `runner` as an account leak.

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { hostname as osHostname, userInfo } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

/** The repository root, from this file's own position. */
export const REPO_ROOT = resolve(HERE, '..', '..');

/** The tracked shape checker this module delegates to. */
export const SHAPE_CHECKER = join(REPO_ROOT, 'scripts', 'check-disclosure-shape.mjs');

/** Accounts that name a role rather than a person. */
const SYSTEM_ACCOUNTS = new Set([
  'root', 'user', 'users', 'username', 'ubuntu', 'debian', 'runner', 'node', 'vscode',
  'admin', 'administrator', 'default', 'public', 'ci', 'build', 'builder', 'test', 'tester',
  'nobody', 'daemon', 'www-data', 'linuxbrew', 'containeruser', 'vagrant', 'docker',
  'example', 'someone', 'somebody', 'you', 'me', 'name', 'yourname', 'your-name',
]);

/** Hostnames that name a role rather than a machine. */
const SYSTEM_HOSTS = new Set(['localhost', 'localhost.localdomain', 'buildkitsandbox', 'runner', 'docker-desktop']);

/**
 * The identity of the machine this process is running on. Read at call time,
 * never stored: it is an input to the check, not data the component keeps.
 *
 * @returns {{hostname: string|null, account: string|null}}
 */
export function currentIdentity() {
  let host = null;
  let account = null;
  try {
    host = osHostname();
  } catch {
    host = null;
  }
  try {
    account = userInfo().username;
  } catch {
    account = null;
  }
  return { hostname: host || null, account: account || null };
}

/** A token that is worth looking for: long enough, and not a role name. */
function usableName(name, roles) {
  if (typeof name !== 'string') return null;
  const t = name.trim();
  if (t.length < 3) return null;
  if (roles.has(t.toLowerCase())) return null;
  return t;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A whole-token occurrence of `name`, case-insensitive. */
function tokenRe(name) {
  return new RegExp(`(?:^|[^A-Za-z0-9])(${escapeRe(name)})(?:$|[^A-Za-z0-9])`, 'i');
}

// A home-directory path segment, with or without the leading separator, and
// with or without a WSL/drive prefix in front of it. The captured group is the
// account name; whether it is one is decided by the allow-list, not here.
const HOME_SEGMENT_RE =
  /(?:^|[\s"'`(=,;:[])(?:[A-Za-z]:[\\/]{1,2}|\/|\\\\)?(?:mnt[\\/][a-z][\\/])?(?:home|users|Users|Documents and Settings)[\\/]+([^\\/\s"'`<>${}%*?,;:)\]]+)/g;

// scp/ssh-style `user@host`, and the same shape inside a URL's authority.
const USER_AT_HOST_RE = /(?:^|[\s"'`(=,;[])([A-Za-z0-9][A-Za-z0-9._-]{1,63})@([A-Za-z0-9][A-Za-z0-9.-]{1,253})(?=[\s"'`),;:\]]|$)/g;

// A UNC prefix. `paths.mjs` refuses this as a path; here it is refused as the
// NAME it carries, which is the first component after the slashes.
const UNC_HOST_RE = /\\\\([A-Za-z0-9][A-Za-z0-9._-]{1,62})[\\/]/g;

/**
 * Classify one string for machine identity.
 *
 * @param {string} s
 * @param {{identity?: {hostname: string|null, account: string|null}}} [opts]
 * @returns {Array<{kind: string, match: string}>}
 */
export function classifyMachineIdentity(s, opts = {}) {
  if (typeof s !== 'string' || s.length === 0) return [];
  const id = opts.identity ?? currentIdentity();
  const hits = [];

  const account = usableName(id.account, SYSTEM_ACCOUNTS);
  if (account) {
    const m = tokenRe(account).exec(s);
    if (m) hits.push({ kind: 'account-of-this-machine', match: m[1] });
  }

  const host = usableName(id.hostname, SYSTEM_HOSTS);
  if (host) {
    for (const cand of [host, host.split('.')[0]]) {
      const c = usableName(cand, SYSTEM_HOSTS);
      if (!c) continue;
      const m = tokenRe(c).exec(s);
      if (m) {
        hits.push({ kind: 'hostname-of-this-machine', match: m[1] });
        break;
      }
    }
  }

  for (const re of [HOME_SEGMENT_RE, UNC_HOST_RE]) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(s)) !== null) {
      const seg = m[1];
      if (seg.includes('…') || seg.includes('...') || seg.includes('<') || seg.includes('$') || seg.includes('%')) continue;
      if (SYSTEM_ACCOUNTS.has(seg.toLowerCase())) continue;
      hits.push({
        kind: re === UNC_HOST_RE ? 'hostname-in-a-unc-path' : 'account-in-a-home-path',
        match: m[0].trim(),
      });
    }
  }

  USER_AT_HOST_RE.lastIndex = 0;
  let m;
  while ((m = USER_AT_HOST_RE.exec(s)) !== null) {
    // An e-mail address in a commit trailer is the same disclosure as a login
    // on a host; both name a person and a machine, and neither belongs here.
    hits.push({ kind: 'user-at-host', match: `${m[1]}@${m[2]}` });
  }

  // Deduplicate: one string reported once per kind is enough to act on.
  const seen = new Set();
  return hits.filter((h) => {
    const k = `${h.kind} ${h.match}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * Walk a record and collect machine identity in keys and values alike. A map
 * keyed by hostname leaks exactly as much through its keys as through its
 * values.
 *
 * @returns {Array<{where: string, in: 'key'|'value', value: string, kind: string, match: string}>}
 */
export function findMachineIdentity(value, opts = {}) {
  const id = opts.identity ?? currentIdentity();
  const out = [];
  const visit = (v, where) => {
    if (v === null || v === undefined) return;
    if (typeof v === 'string') {
      for (const h of classifyMachineIdentity(v, { identity: id })) {
        out.push({ where, in: 'value', value: v, ...h });
      }
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((x, i) => visit(x, `${where}[${i}]`));
      return;
    }
    if (typeof v === 'object') {
      for (const k of Object.keys(v)) {
        const kw = `${where}.${k}`;
        for (const h of classifyMachineIdentity(k, { identity: id })) {
          out.push({ where: kw, in: 'key', value: k, ...h });
        }
        visit(v[k], kw);
      }
    }
  };
  visit(value, '$');
  return out;
}

// ---------------------------------------------------------------------------
// Delegation to the shape checker.
// ---------------------------------------------------------------------------

/**
 * Prove the delegate's needles still fire, by running its own `--self-test`.
 * A delegate that has stopped matching reports the same zero as a clean file,
 * which is the failure its self-test exists to rule out — so it is run, and
 * its result is reported, rather than assumed.
 *
 * @returns {{ok: boolean, detail: string}}
 */
export function shapeCheckerSelfTest() {
  if (!existsSync(SHAPE_CHECKER)) {
    return { ok: false, detail: `${relative(REPO_ROOT, SHAPE_CHECKER)} is not present` };
  }
  const r = spawnSync(process.execPath, [SHAPE_CHECKER, '--self-test'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const detail = `${(r.stdout ?? '').trim()}${(r.stderr ?? '').trim()}`.slice(0, 400);
  return { ok: r.status === 0, detail: detail || `exit ${r.status}` };
}

/**
 * Run the tracked shape checker over a set of files.
 *
 * The checker resolves the paths it is given against the repository root, so
 * out-of-tree files are handed to it as a relative path that climbs out
 * (`../store/run-1.json`). When no such path exists — a different Windows
 * drive — the delegation is reported as UNAVAILABLE and the caller must treat
 * the check as not completed. Reporting it as clean would be the same lie the
 * counting contract exists to prevent, one level down.
 *
 * @param {string[]} files Absolute paths.
 * @returns {{available: boolean, reason: string|null, hits: Array<{file: string, line: number, shape: string, match: string, text: string}>, scanned: number}}
 */
export function runShapeChecker(files) {
  if (files.length === 0) return { available: true, reason: null, hits: [], scanned: 0 };
  if (!existsSync(SHAPE_CHECKER)) {
    return { available: false, reason: `${SHAPE_CHECKER} is not present`, hits: [], scanned: 0 };
  }

  const rels = [];
  for (const f of files) {
    const abs = resolve(f);
    const rel = relative(REPO_ROOT, abs);
    if (rel === '' || /^[A-Za-z]:/.test(rel) || rel.startsWith(sep) || rel.startsWith('/')) {
      return {
        available: false,
        reason:
          `${abs} cannot be expressed relative to the repository root, so the tracked shape ` +
          'checker cannot be pointed at it (it resolves its arguments against that root). ' +
          'Put the store on the same volume as the checkout, or run the checker by hand.',
        hits: [],
        scanned: 0,
      };
    }
    rels.push(rel.split(sep).join('/'));
  }

  const r = spawnSync(process.execPath, [SHAPE_CHECKER, '--paths', ...rels], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (r.error) {
    return { available: false, reason: `could not run the shape checker: ${r.error.message}`, hits: [], scanned: 0 };
  }
  // 0 clean, 1 hits, 3 vacuous or a needle that failed its own control. Only
  // the first two are answers.
  if (r.status !== 0 && r.status !== 1) {
    return {
      available: false,
      reason: `the shape checker exited ${r.status}, which is not a verdict:\n${(r.stderr ?? '').trim().slice(0, 400)}`,
      hits: [],
      scanned: 0,
    };
  }

  const hits = [];
  const line = /^(.*?):(\d+): ([A-Z][A-Z0-9-]*) \((.*)\) \| (.*)$/;
  for (const l of (r.stdout ?? '').split(/\r?\n/)) {
    const m = line.exec(l);
    if (!m) continue;
    let match = m[4];
    try {
      match = JSON.parse(m[4]);
    } catch {
      /* the checker prints JSON.stringify of the match; keep the raw text if not */
    }
    hits.push({ file: m[1], line: Number(m[2]), shape: m[3], match, text: m[5] });
  }
  const scannedM = /^scanned:\s+(\d+)/m.exec(r.stdout ?? '');
  const scanned = scannedM ? Number(scannedM[1]) : 0;

  // A run that reported hits but printed none, or scanned fewer files than it
  // was given, has not answered the question that was asked.
  if (scanned !== files.length) {
    return {
      available: false,
      reason: `the shape checker scanned ${scanned} of the ${files.length} file(s) it was given`,
      hits,
      scanned,
    };
  }
  if (r.status === 1 && hits.length === 0) {
    return { available: false, reason: 'the shape checker reported findings it did not print', hits, scanned };
  }
  return { available: true, reason: null, hits, scanned };
}

/** The account/host names a human reader would want echoed back. Not stored. */
export function describeIdentity(id = currentIdentity()) {
  const parts = [];
  parts.push(usableName(id.account, SYSTEM_ACCOUNTS) ? 'account: looked for' : 'account: not distinctive, not looked for');
  parts.push(usableName(id.hostname, SYSTEM_HOSTS) ? 'hostname: looked for' : 'hostname: not distinctive, not looked for');
  return parts.join('; ');
}
