// The toolchain digest that goes into `materials[]`.
//
// THIS FILE DOES NOT REIMPLEMENT THE PIN
//
//   `../../driver/lib/toolchain.mjs` already loads a pin, validates it, hashes
//   the pinned files and defines `pinnedSet` — the written-down shape that the
//   toolchain digest is a digest OF. All of that is imported. What is added
//   here is one thing the driver has no reason to want: the digest of the pin
//   AS DECLARED, computed from the pin file alone without touching the
//   filesystem.
//
//   The distinction matters and is easy to lose:
//
//     declared  — sha256 over `pinnedSet` built from the pin's own entries.
//                 Computable anywhere, including on a machine that has no
//                 clang. This is what goes into the provenance statement and
//                 what a verifier compares against the pin file it was given.
//     measured  — the same, after `verifyPin` has hashed the files on disk and
//                 confirmed they are the pinned bytes. Only computable where
//                 the toolchain is installed.
//
//   A verifier that only ever compares DECLARED digests has checked that two
//   documents agree about a pin, not that any binary matched it. That is a real
//   limit, so `verifyPinLive` exists, is off by default, and when it has not
//   been run the result is reported as NOT_OBSERVED rather than as a pass.

import { createHash } from 'node:crypto';

import { canonicalJsonRaw } from '../../evidence/canon.mjs';
import { loadPin, pinnedSet, resolvePinnedPath, verifyPin } from '../../driver/lib/toolchain.mjs';

export { loadPin, resolvePinnedPath };

/**
 * The digest of the pinned set as the pin file declares it. No file is read
 * beyond the pin itself.
 *
 * @param {Record<string, unknown>} pin a pin that `loadPin` accepted
 * @returns {string} 64 lowercase hex
 */
export function declaredToolchainDigest(pin) {
  const declared = {
    packages: pin.packages.map((p) => ({
      name: p.name,
      sha256: p.sha256,
      version: p.version ?? null,
    })),
  };
  const set = pinnedSet(pin, declared);
  return createHash('sha256').update(canonicalJsonRaw(set), 'utf8').digest('hex');
}

/**
 * The `toolchain` block interfaces.md §5 requires every record to carry outside
 * `context`. Package paths are deliberately not copied in: they are relative to
 * the pin's `root`, and a record that carried them would be describing one
 * machine's prefix.
 *
 * @param {Record<string, unknown>} pin
 */
export function toolchainBlock(pin) {
  return {
    clang: typeof pin.clang === 'string' ? pin.clang : null,
    digest: declaredToolchainDigest(pin),
    packages: pin.packages.map((p) => ({
      name: p.name,
      sha256: p.sha256,
      version: p.version ?? null,
    })),
  };
}

/**
 * Hash the pinned files on disk and compare. Wraps `verifyPin` so that callers
 * of this package do not have to know where it lives; the return value adds the
 * declared digest so a caller can report both numbers side by side.
 *
 * @param {Record<string, unknown>} pin
 * @param {{ccPath?: string|null}} [opts]
 */
export function verifyPinLive(pin, opts = {}) {
  const v = verifyPin(pin, { ccPath: opts.ccPath ?? null });
  return { ...v, declaredDigest: declaredToolchainDigest(pin) };
}
