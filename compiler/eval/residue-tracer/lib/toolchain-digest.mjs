/**
 * `toolchain.digest`, taken from where the tree already computes it.
 *
 * WHY THIS FILE EXISTS
 *
 * This lane used to compute its own:
 *
 *     sha256(JSON.stringify({ cc, version, observer }))
 *
 * That number is a digest of nothing anyone else digests. It matches no value
 * this tree computes for the same toolchain, it cannot be re-derived by a reader
 * who has the toolchain in front of them, and it collides with nothing -- so two
 * records of the same pinned clang under two lab layouts could disagree, and two
 * records of DIFFERENT clangs whose `--version` lines happen to match could
 * agree. An invented digest is worse than no digest, because it looks like one.
 *
 * The file this lane feeds says so itself. compiler/schema/emit-observation.mjs,
 * in the adapter that turns a driver record into an observation record:
 *
 *   "the driver record carries no toolchain.digest (it is null when no pin was
 *    configured). An observation record has to name the toolchain it measured,
 *    and this adapter will not invent a digest for it."
 *
 * So neither will this lane. There is exactly one derivation in this tree, in
 * compiler/driver/lib/run.mjs:
 *
 *     record.toolchain.digest = evidenceDigest(pinnedSet(pin, pinVerification))
 *
 * -- the SHA-256 of compiler/evidence/canon.mjs canonical JSON over the pinned
 * set, which is `{clang, packages: [{name, sha256, version}], pinVersion}` with
 * the package digests in it. That is the value below, computed by importing the
 * same two functions rather than by reimplementing either of them. A record from
 * this lane and a record from the driver, taken against the same pin, carry the
 * same 64 characters; a reader with the pin can recompute them.
 *
 * THE PRICE, STATED RATHER THAN HIDDEN: a digest needs a pin, and a pin is a
 * file listing package digests. A run with no pin cannot have one, and this
 * module's answer there is a refusal with a reason, not a number. The runner
 * turns that into "--emit-observation needs --toolchain-pin", which is a setup
 * failure and exits 5. Nothing falls back to a made-up value.
 */
import { loadPin, pinnedSet, verifyPin } from '../../../driver/lib/toolchain.mjs';
import { evidenceDigest } from '../../../evidence/canon.mjs';

/**
 * The name of the derivation, carried in the run facts and checked by
 * lib/observation.mjs before a record is built. A digest whose provenance is not
 * this string is not written into a record.
 */
export const DIGEST_SOURCE = 'evidence-digest-of-pinned-set';

/** The same sentence, for the record's own note. */
export const DIGEST_DERIVATION =
  'toolchain.digest is not computed by this lane: it is evidenceDigest(pinnedSet(pin, verifyPin(pin))) over the '
  + 'toolchain pin this run was given -- the SHA-256 of compiler/evidence/canon.mjs canonical JSON over the pinned '
  + 'set, which is the one derivation in this tree (compiler/driver/lib/run.mjs) and the same number the driver '
  + 'writes into toolchain.digest for the same pin';

/** The digest itself, over a verified pin. Separate so the digest has one spelling. */
export function digestOfPinnedSet(pin, verification) {
  return evidenceDigest(pinnedSet(pin, verification));
}

/**
 * Read a pin, check it against the machine, and return the digest -- or say why
 * there is none.
 *
 * A pin that does not match is not a digest with a caveat: the pin then does not
 * describe the compiler that ran, and a digest taken from it would name a
 * toolchain that was not measured. Same for a pin this machine could only half
 * check (`unobserved`), which verifyPin keeps separate from `mismatches` for
 * exactly this reason.
 *
 * `load` and `verify` are injectable so that the refusals can be tested without
 * a clang installation; the defaults are the tree's own functions.
 */
export function toolchainDigestFromPin(pinPath, {
  ccPath = null, load = loadPin, verify = verifyPin, verifyOptions = {},
} = {}) {
  const l = load(pinPath);
  if (!l.ok) {
    return { ok: false, why: `the toolchain pin could not be read (${l.reason}: ${l.detail})` };
  }
  const v = verify(l.pin, { ccPath, ...verifyOptions });
  if (v.mismatches.length) {
    return {
      ok: false,
      why: 'the toolchain pin does not describe the toolchain on this machine, so a digest taken from it would name '
        + `a toolchain that was not measured: ${v.mismatches.map((m) => `${m.name} (${m.kind})`).join(', ')}`,
    };
  }
  if (v.unobserved.length) {
    return {
      ok: false,
      why: 'the toolchain pin states things this machine could not check at all, and a digest over a half-checked '
        + `pin is a claim nobody made: ${v.unobserved.map((m) => `${m.name} (${m.kind})`).join(', ')}`,
    };
  }
  return {
    ok: true,
    digest: digestOfPinnedSet(l.pin, v),
    source: DIGEST_SOURCE,
    clang: typeof l.pin.clang === 'string' ? l.pin.clang : null,
    packages: v.packages,
  };
}
