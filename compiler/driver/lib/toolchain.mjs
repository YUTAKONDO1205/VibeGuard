// The toolchain pin.
//
// "Same version" is not the same bytes — two builds of clang 18.1.3 from
// different distribution revisions optimise differently, and a property
// observed to survive one has not been observed to survive the other. So the
// pin records package versions *and* per-package digests, and the digests are
// what decides. See compiler/README.md, "Building".
//
// Pin file shape (`toolchain.pin` in the policy points at it, relative to the
// policy file):
//
//   {
//     "pinVersion": "toolchain-pin-v0",
//     "clang": "18.1.3",
//     "root": "/",                                     // optional, default "/"
//     "drivers": { "cc": "usr/bin/clang-18", "cxx": "usr/bin/clang++-18" },
//     "packages": [
//       { "name": "clang-18", "version": "1:18.1.3-1ubuntu1",
//         "path": "usr/bin/clang-18", "sha256": "<64 lowercase hex>" }
//     ]
//   }
//
// `path` is relative to `root` so that a pin is portable between machines that
// install the toolchain in different prefixes, and so that no absolute path has
// to be written into a record (interfaces.md §5).

import { createHash } from 'node:crypto';
import { readFileSync, createReadStream, realpathSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { delimiter, isAbsolute, join, resolve } from 'node:path';

export const PIN_VERSION = 'toolchain-pin-v0';

export function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function loadPin(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    // The errno, not the message: an fs error message carries the absolute
    // path it failed on, and this reason is quoted into a finding.
    return { ok: false, reason: 'unreadable', detail: err.code ?? 'read failed' };
  }
  let pin;
  try {
    pin = JSON.parse(text);
  } catch (err) {
    return { ok: false, reason: 'not-json', detail: err.message };
  }
  if (pin?.pinVersion !== PIN_VERSION) {
    return { ok: false, reason: 'bad-version', detail: `expected pinVersion ${PIN_VERSION}, got ${JSON.stringify(pin?.pinVersion)}` };
  }
  if (!Array.isArray(pin.packages) || pin.packages.length === 0) {
    return { ok: false, reason: 'no-packages', detail: 'pin lists no packages; a pin that pins nothing is not a pin' };
  }
  for (const p of pin.packages) {
    if (typeof p?.name !== 'string' || typeof p?.path !== 'string' || !/^[0-9a-f]{64}$/.test(p?.sha256 ?? '')) {
      return { ok: false, reason: 'bad-package', detail: `malformed package entry ${JSON.stringify(p)}` };
    }
  }
  return { ok: true, pin };
}

export function pinRoot(pin) {
  const r = typeof pin.root === 'string' ? pin.root : '/';
  return resolve(r);
}

export function resolvePinnedPath(pin, relPath) {
  return isAbsolute(relPath) ? resolve(relPath) : join(pinRoot(pin), relPath);
}

/**
 * Ask a compiler what version it is. Injectable so that a test can present a
 * binary that answers convincingly without having to build one.
 */
export function defaultProbeVersion(ccPath) {
  try {
    const out = execFileSync(ccPath, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const m = /clang version (\d+\.\d+\.\d+)/.exec(out);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/**
 * Observe the *package* version of a pinned entry, as opposed to the upstream
 * version the binary prints.
 *
 * `packages[].version` is written by `tools/make-pin.mjs`, which gets it from
 * `dpkg-query`. So dpkg is what can be asked to say it again; there is no way
 * to read a distribution package version out of the bytes of a file. On a
 * machine with no dpkg the answer is "not observed", which the caller turns
 * into a finding rather than into a pass — a pinned version nobody checked is
 * exactly the silent record this work exists to remove.
 *
 * @returns {{version: string|null, method: string}}
 */
export function defaultObservePackageVersion(entry) {
  try {
    const out = execFileSync('dpkg-query', ['-W', '-f=${Version}', entry.name], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return out ? { version: out, method: 'dpkg-query' } : { version: null, method: 'dpkg-query-empty' };
  } catch {
    return { version: null, method: 'unavailable' };
  }
}

/**
 * Hash every pinned file and compare. Also compares the version clang reports
 * with the version the pin records, because a pin that matched only on digests
 * would pass silently against a binary that is the pinned bytes under a
 * different name — and compares `packages[].version`, which until now was
 * copied into the record and never looked at.
 *
 * Two lists come back, and they are separate on purpose:
 *
 *   `mismatches` — something was observed and disagreed with the pin. Fail
 *                  closed: the caller makes this exit 4.
 *   `unobserved` — the pin states something this machine could not check at
 *                  all. That is exit 3, not exit 4 and certainly not exit 0.
 *                  Merging it into `mismatches` would report "we measured a
 *                  disagreement" when the truth is "we could not measure".
 *
 * @returns {{status: 'match'|'mismatch', packages: object[], mismatches: object[],
 *            unobserved: object[], versions: object[], reportedClang: string|null}}
 */
export function verifyPin(pin, {
  ccPath = null,
  probeVersion = defaultProbeVersion,
  observePackageVersion = defaultObservePackageVersion,
} = {}) {
  const packages = [];
  const mismatches = [];
  const unobserved = [];
  const versions = [];

  for (const entry of pin.packages) {
    const abs = resolvePinnedPath(pin, entry.path);
    let actual = null;
    let error = null;
    try {
      actual = sha256File(abs);
    } catch (err) {
      error = err.code === 'ENOENT' ? 'missing' : 'unreadable';
    }
    // Recorded without the path: interfaces.md §5 forbids absolute paths in a
    // record, and the pin's own `path` is only meaningful next to its `root`.
    packages.push({ name: entry.name, version: entry.version ?? null, sha256: entry.sha256 });
    if (error !== null) {
      mismatches.push({ name: entry.name, kind: error, expected: entry.sha256, actual: null });
    } else if (actual !== entry.sha256) {
      mismatches.push({ name: entry.name, kind: 'digest', expected: entry.sha256, actual });
    }

    // `version` is a claim like every other field in the pin, so it is checked
    // like every other field. A pin that does not state one states nothing,
    // and "not-pinned" is recorded as itself rather than as a pass.
    const pinnedVersion = typeof entry.version === 'string' && entry.version.length > 0 ? entry.version : null;
    if (pinnedVersion === null) {
      versions.push({ name: entry.name, pinned: null, observed: null, method: 'not-pinned', verdict: 'not-pinned' });
      continue;
    }
    const observation = observePackageVersion(entry, abs) ?? { version: null, method: 'unavailable' };
    const method = typeof observation.method === 'string' ? observation.method : 'unavailable';
    const observedVersion = typeof observation.version === 'string' && observation.version.length > 0
      ? observation.version
      : null;
    if (observedVersion === null) {
      versions.push({ name: entry.name, pinned: pinnedVersion, observed: null, method, verdict: 'unobserved' });
      unobserved.push({
        name: entry.name, kind: 'package-version-unobserved', expected: pinnedVersion, actual: null, method,
      });
    } else if (observedVersion !== pinnedVersion) {
      versions.push({ name: entry.name, pinned: pinnedVersion, observed: observedVersion, method, verdict: 'mismatch' });
      mismatches.push({ name: entry.name, kind: 'package-version', expected: pinnedVersion, actual: observedVersion });
    } else {
      versions.push({ name: entry.name, pinned: pinnedVersion, observed: observedVersion, method, verdict: 'match' });
    }
  }

  let reportedClang = null;
  if (ccPath) reportedClang = probeVersion(ccPath) ?? null;
  if (typeof pin.clang === 'string') {
    if (reportedClang === null) {
      mismatches.push({ name: 'clang --version', kind: 'unreadable', expected: pin.clang, actual: null });
    } else if (reportedClang !== pin.clang) {
      mismatches.push({ name: 'clang --version', kind: 'version', expected: pin.clang, actual: reportedClang });
    }
  }

  return {
    status: mismatches.length === 0 ? 'match' : 'mismatch',
    packages,
    mismatches,
    unobserved,
    versions,
    reportedClang,
  };
}

/**
 * The set that `toolchain.digest` in the record is the digest of. Kept as a
 * separate function so that the digest is over a value with a written-down
 * shape rather than over whatever the record happened to contain.
 */
export function pinnedSet(pin, verification) {
  return {
    clang: typeof pin.clang === 'string' ? pin.clang : null,
    packages: verification.packages.map((p) => ({ name: p.name, sha256: p.sha256, version: p.version })),
    pinVersion: PIN_VERSION,
  };
}

/** Which compiler binary to run. `--vg-clang` wins, then the pin, then PATH. */
export function resolveCompiler({ mode, pin, override }) {
  if (override) return { path: override, source: 'flag' };
  const fromPin = mode === 'cxx' ? pin?.drivers?.cxx : pin?.drivers?.cc;
  if (typeof fromPin === 'string' && pin) return { path: resolvePinnedPath(pin, fromPin), source: 'pin' };
  return { path: mode === 'cxx' ? 'clang++-18' : 'clang-18', source: 'path' };
}

// ---------------------------------------------------------------------------
// Reconciling the pin with the binary that actually runs
// ---------------------------------------------------------------------------
//
// `verifyPin` hashes `packages[].path`. `resolveCompiler` decides what is
// EXECUTED. Those were two unrelated questions: the pin could be perfect and
// the driver could still run something the pin has never heard of, because
// `--vg-clang`, `drivers.cc` and a bare PATH lookup were all trusted without
// being reconciled with the pinned set. Everything below exists to join them.
//
// The comparison is between REAL paths on both sides. Comparing the strings
// would let `/usr/bin/clang-18` and a symlink to it read as different files,
// and — the direction that matters — would let a decoy whose bytes happen to
// hash correctly read as the pinned file merely because someone pointed the
// pin's `path` at it and the driver at another copy. Where the platform gives
// a usable device/inode pair, that is compared too, so that two names for two
// different files cannot collapse onto one entry.

/** Resolve every symlink in `p`. Returns null when the path does not resolve. */
export function realpathOrNull(p) {
  if (typeof p !== 'string' || p.length === 0) return null;
  try {
    return realpathSync.native(p);
  } catch { /* fall through to the portable implementation */ }
  try {
    return realpathSync(p);
  } catch {
    return null;
  }
}

/** Comparison key for a resolved path. Windows filenames are case-insensitive. */
function pathKey(p) {
  if (typeof p !== 'string' || p.length === 0) return null;
  const n = resolve(p);
  return process.platform === 'win32' ? n.toLowerCase() : n;
}

/**
 * `dev:ino` when the platform reports a usable one, else null. Used only to
 * *reject* a match, never to make one: a null identity must not turn into an
 * accidental pass on a filesystem that does not number its files.
 */
export function fileIdentity(p) {
  try {
    const s = statSync(p);
    const dev = Number(s.dev);
    const ino = Number(s.ino);
    if (!Number.isFinite(dev) || !Number.isFinite(ino) || ino === 0) return null;
    return `${dev}:${ino}`;
  } catch {
    return null;
  }
}

function isFile(p) {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

/**
 * Where a program name or path actually lands, using the same rules the spawn
 * would. A bare name is looked up on PATH; anything with a separator is
 * resolved against `cwd`. Returns null when nothing is there.
 */
export function locateExecutable(nameOrPath, { cwd = process.cwd(), env = process.env } = {}) {
  if (typeof nameOrPath !== 'string' || nameOrPath.length === 0) return null;
  const hasSeparator = nameOrPath.includes('/') || nameOrPath.includes('\\');
  if (isAbsolute(nameOrPath) || hasSeparator) {
    const abs = resolve(cwd, nameOrPath);
    return isFile(abs) ? abs : null;
  }
  const pathVar = env.PATH ?? env.Path ?? '';
  const extensions = process.platform === 'win32'
    ? ['', ...String(env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean)]
    : [''];
  for (const dir of String(pathVar).split(delimiter)) {
    if (!dir) continue;
    for (const ext of extensions) {
      const candidate = resolve(dir, nameOrPath + ext);
      if (isFile(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * Join `resolveCompiler`'s answer to the pin.
 *
 * Nothing here reads a digest. Identity and integrity are different questions
 * and are answered by different code: `verifyPin` says whether the pinned files
 * are the pinned bytes, this says whether the file about to be executed is one
 * of them. Folding the digest in here would mean a policy that has knowingly
 * set `requireDigestMatch: false` also loses the "you are running something
 * else entirely" check, which is not what that switch is for.
 *
 * `locatedPath` is what the caller should spawn and `realPath` is what was
 * compared. They are deliberately different values: clang's driver branches on
 * its own argv[0], so spawning the realpath of `clang++-18` (which on a Debian
 * install is the file `clang`) would silently put a C++ build into C mode. The
 * symlink is followed to decide identity and not followed to decide behaviour.
 *
 * @returns {{status: 'in-pin'|'outside-pin'|'unresolvable'|'not-configured',
 *            inPinSet: boolean|null, pinnedAs: string|null, invokedAs: string,
 *            resolvedFrom: string, overriddenByFlag: boolean, located: boolean,
 *            locatedPath: string|null, realPath: string|null, detail: string}}
 */
export function reconcileCompiler({ pin, compiler, cwd = process.cwd(), env = process.env }) {
  const located = locateExecutable(compiler.path, { cwd, env });
  const executedPath = located === null ? null : realpathOrNull(located);
  // Only a basename ever leaves this function in `detail`: interfaces.md §5
  // forbids an absolute path anywhere in a record, and `detail` is quoted into
  // a finding. `locatedPath`/`realPath` are for the caller's own use and are
  // never put in the record.
  const invokedAs = String(compiler.path).split(/[\\/]/).pop();
  const base = {
    status: 'not-configured',
    inPinSet: null,
    pinnedAs: null,
    invokedAs,
    resolvedFrom: compiler.source,
    overriddenByFlag: compiler.source === 'flag',
    located: located !== null,
    locatedPath: located,
    realPath: executedPath,
    detail: 'no toolchain pin is configured, so nothing says which binary was allowed to run',
  };
  if (!pin) return base;

  if (executedPath === null) {
    return {
      ...base,
      status: 'unresolvable',
      inPinSet: false,
      detail: `the compiler the driver would execute (${invokedAs}) does not resolve to a file on this machine, `
        + 'so it cannot be reconciled with the pin; an unreconcilable compiler is not a pinned one',
    };
  }

  const wantKey = pathKey(executedPath);
  const wantIdentity = fileIdentity(executedPath);
  for (const entry of pin.packages) {
    const pinnedReal = realpathOrNull(resolvePinnedPath(pin, entry.path));
    if (pinnedReal === null) continue;
    if (pathKey(pinnedReal) !== wantKey) continue;
    const pinnedIdentity = fileIdentity(pinnedReal);
    if (wantIdentity !== null && pinnedIdentity !== null && pinnedIdentity !== wantIdentity) continue;
    return {
      ...base,
      status: 'in-pin',
      inPinSet: true,
      pinnedAs: entry.name,
      detail: `the binary the driver executes resolves to the pinned package ${entry.name}`,
    };
  }

  return {
    ...base,
    status: 'outside-pin',
    inPinSet: false,
    detail: `the driver would execute ${invokedAs}, which after resolving symlinks is none of the `
      + `${pin.packages.length} file(s) the pin covers; the pin's digests say nothing about it`,
  };
}
