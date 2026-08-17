// config-axes — this build's value for each axis of the nominal configuration
// key, read off one already-normalised command line.
//
// The axes are the six `derive-fallback-table.mjs` fixes in its `CONFIG_KEYS`:
// cc, freestanding, lto, ndebug, opt, target. TWO components now have to turn a
// command line into them, and they are on opposite ends of the same lookup:
//
//   - `fallback.mjs` reads the invocation in hand and finds the table row
//     measured at that configuration;
//   - `compiler/envelope/derive-frontier-sidecar.mjs` reads the invocation a
//     ladder frontier was measured under and files that frontier under the same
//     key, so that the driver can ask whether the build in hand is in the
//     exposure the row was measured in.
//
// The two must agree BYTE FOR BYTE, and the reason they must is not symmetry.
// The sidecar is looked up BY the driver's key, so a second reading of
// `-O2 -ffreestanding` that spelled one axis differently would not report a
// disagreement — it would miss the key entirely, the sidecar would have nothing
// to say about any build, and from the driver's side that reads exactly like a
// clean run. A silent key miss is the failure mode this file exists to make
// impossible, so the reading lives here once and both sides import it.
//
// It sits in `compiler/driver/lib/` rather than beside the sidecar because this
// is where a command line is already understood — `cmdline.mjs` is the file that
// knows clang's ordering rules — and because the dependency runs that way
// anyway: `fallback.mjs` imports the sidecar's `configKey`, so the sidecar
// importing these two functions back out of `fallback.mjs` would close a cycle.
//
// ── WHAT A COMMAND LINE CANNOT SAY ──────────────────────────────────────────
//
//   - `cc`: which clang this is, is a toolchain fact rather than a command-line
//     one. `toolchain.mjs` knows it for the driver, and a ladder frontier
//     document carries it at `toolchain.cc` because the runner recorded it.
//     Neither is read here, and nothing here invents it.
//   - `lto`: `-flto=thin` does not say whether the envelope's `"thin-prelink"`
//     or `"thin-backend"` cell is the one to compare against. The two differ by
//     WHEN the observation was taken, not by any flag, so no reading of the line
//     can choose between them. ★ But that argument only bites when an LTO token
//     is present. A command line with no `-flto*` and no `-fno-lto` on it is
//     `lto: "none"` — that is not a convention, it is what the line says.
//
// ── THE ONE CONVENTION, STATED RATHER THAN HIDDEN ───────────────────────────
//
// No `-target` at all is matched against the envelope's `"host"`. That is a
// convention: clang with no `-target` compiles for the machine's default
// triple, and the envelope's `host` cells were swept on SOME machine's default
// triple, and nothing here checks those are the same machine. It is written
// down here rather than buried because it is the one place this reader assumes
// instead of reads.
//
// ── WHAT AN AXIS'S ABSENCE MEANS ────────────────────────────────────────────
//
// `driverConfigAxes` omits a key rather than writing a default for it, and the
// callers depend on that: `fallback.mjs` matches only on the axes a line stated
// and pays for the rest with its spanning rule, and the sidecar deriver reports
// an omitted axis as an `underspecified-axis` anomaly. A default written here
// would state something about the build that was never read, and both of those
// consumers would then be reasoning about a value nobody measured.

/**
 * The level this invocation actually compiles at. Last `-O` wins, as clang does
 * it, and no `-O` at all is `-O0`, as clang does that too.
 */
export function shippingOptLevel(normalised) {
  const levels = Array.isArray(normalised?.optLevels) ? normalised.optLevels : [];
  return levels.length > 0 ? levels[levels.length - 1] : '-O0';
}

/**
 * This build's value for each axis this command line actually stated — no key
 * for an axis it did not.
 *
 * Every branch below is guarded on the FIELD's presence and type rather than on
 * its value, so that a normalised object which never reported an axis is not
 * read as having reported the axis's default. "cmdline.mjs did not tell me" and
 * "cmdline.mjs told me false" are different sentences and produce different
 * objects: the first omits the key, the second sets it.
 *
 * Insertion order is deliberate — `opt` first, because it is the axis every
 * refusal message leads with.
 */
export function driverConfigAxes(normalised) {
  const axes = { opt: shippingOptLevel(normalised) };
  const n = normalised ?? {};

  // No `-target` is the envelope's `host`. The one convention here; see the
  // header. A stated triple is used verbatim, so a triple the sweep never
  // measured matches no row and is refused rather than rounded to a neighbour.
  // `-m32`/`-m64` change the triple without a `-target` on the line, so the
  // build is not the `host` the envelope measured and the axis is not readable.
  if (Object.prototype.hasOwnProperty.call(n, 'target') && n.targetOpaque !== true) {
    axes.target = typeof n.target === 'string' && n.target.length > 0 ? n.target : 'host';
  }
  if (typeof n.ndebug === 'boolean') axes.ndebug = n.ndebug;
  if (typeof n.freestanding === 'boolean') axes.freestanding = n.freestanding;
  // The asymmetry that makes this whole change safe: no LTO token on the line
  // is `lto: "none"`, which is a reading. Any LTO token at all leaves the axis
  // out, because `-flto=thin` cannot be resolved to a prelink/backend cell from
  // the line, and a guess here would pick which measurement gets quoted.
  if (Array.isArray(n.ltoTokens) && n.ltoTokens.length === 0) axes.lto = 'none';

  return axes;
}
