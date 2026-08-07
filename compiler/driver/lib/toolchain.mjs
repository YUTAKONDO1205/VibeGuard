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
import { readFileSync, createReadStream } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { isAbsolute, join, resolve } from 'node:path';

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
 * Hash every pinned file and compare. Also compares the version clang reports
 * with the version the pin records, because a pin that matched only on digests
 * would pass silently against a binary that is the pinned bytes under a
 * different name.
 *
 * @returns {{status: 'match'|'mismatch', packages: object[], mismatches: object[], reportedClang: string|null}}
 */
export function verifyPin(pin, { ccPath = null } = {}) {
  const packages = [];
  const mismatches = [];

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
  }

  let reportedClang = null;
  if (ccPath) {
    try {
      const out = execFileSync(ccPath, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
      const m = /clang version (\d+\.\d+\.\d+)/.exec(out);
      reportedClang = m ? m[1] : null;
    } catch {
      reportedClang = null;
    }
  }
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
