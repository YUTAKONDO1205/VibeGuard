/**
 * One family, three builds, one word -- the wiring, with the compiler injected.
 *
 * This is the sequence tools/check-which-wipe-plumbing.mjs performs and the one
 * tools/which-wipe-survived.mjs performs: hand the builder the as-written source
 * and the two cuts, collect the fill each one reads, gate the result, and only
 * then grade. It is a function rather than a loop inside a tool so that the
 * wiring itself can be tested -- with a builder that returns readings instead of
 * running a compiler, every branch below is reachable on a machine with no
 * toolchain, including the two that a real run would have to be broken to show:
 * a variant that was not rebuilt, and a fill counted in the wrong body.
 *
 * `build` is injected and defaults to the real one. Nothing here decides
 * anything about wipes: ordering is lib/plumbing-gates.mjs, grading is
 * lib/record.mjs. This file only guarantees that the three sources that reach
 * the compiler are the three the cut produced, and that a verdict is not reached
 * except through the gates.
 */
import { buildAndRead } from './build-variants.mjs';
import { gatedSubjectReading } from './plumbing-gates.mjs';
import { WHICH_WIPE, whichWipeSurvived } from './record.mjs';

/** WHICH_WIPE's key for one of its values, so a record can name a word without retyping it. */
export function wordKeyOf(reading) {
  if (!reading) return null;
  return Object.entries(WHICH_WIPE).find(([, v]) => v === reading.reading)?.[0] ?? null;
}

/**
 * The grade of one family's three byte counts.
 *
 * Shared with tools/which-wipe-survived.mjs so that the tool and the check on
 * the tool cannot grade differently. A surviving memset CALL is a length this
 * reading cannot see: it is refused rather than treated as an absence, which
 * would count the inline bytes that are visible and call the rest gone.
 */
export function gradeFill(fill, memsetIn = []) {
  if (memsetIn.length) {
    return {
      reading: WHICH_WIPE.INCONCLUSIVE,
      proves: null,
      why: `${memsetIn.join(', ')} left a memset call, whose length this reading cannot see`,
    };
  }
  return whichWipeSurvived(fill);
}

/** The three tags, in the order they are built and reported. */
export const VARIANTS = Object.freeze(['asWritten', 'subjectCut', 'controlCut']);

/**
 * @param spec      what buildAndRead needs, minus `tag` and `useSource`.
 * @param variants  a cutWipeVariants() result.
 * @param build     injected builder; defaults to the real compile-link-read.
 * @param spec.controlWipeBytes  optional; how many bytes the control's own wipe
 *                  writes. Defaults to spec.bufferBytes, which is right for both
 *                  of this lane's families and for the positive control.
 * @returns {{readings, fill, memsetIn, result, word}} `word` is null whenever a
 *          gate failed -- the gates are the only path to a verdict.
 */
export function runFamily({ spec, variants, build = buildAndRead }) {
  const sources = {
    asWritten: variants.asWritten,
    subjectCut: variants.subjectCut.text,
    controlCut: variants.controlCut.text,
  };
  // ONE AT A TIME, IN THIS ORDER. The edited unit is written to one path and
  // compiled to one object path for every variant (lib/build-variants.mjs, and
  // the measured reason it has to be), so a variant must be built, linked and
  // read before the next one is written over it. Building them in parallel, or
  // out of order, would read the wrong program.
  const readings = {};
  for (const tag of VARIANTS) readings[tag] = build({ ...spec, tag, useSource: sources[tag] });

  const fill = Object.fromEntries(VARIANTS.map((t) => [t, readings[t].subject?.bytes ?? null]));
  // A surviving memset CALL is a length this reading cannot see. Refuse rather
  // than count the inline bytes that are visible and treat the call as absent.
  const memsetIn = VARIANTS.filter((t) => (readings[t].subject?.memsetCalls ?? 0) > 0);

  const result = gatedSubjectReading({
    // The source texts as they were read back off disk, before the object
    // digests: a cut that removed nothing is a fact about the sources, and it
    // is the failure the object digests were once believed to catch and did not.
    sourceDigests: Object.fromEntries(VARIANTS.map((t) => [t, readings[t].sourceDigest])),
    digests: Object.fromEntries(VARIANTS.map((t) => [t, readings[t].useDigest])),
    caller: spec.caller,
    subjectReading: readings.asWritten.subject,
    controlReading: readings.asWritten.control,
    fill,
    // How many bytes the control's OWN wipe writes, so that deleting it can be
    // required to remove that many. It is the subject's buffer size unless the
    // caller says otherwise: in both families the two wipes are one buffer each
    // and the buffers are the same size. A family whose control wipes a
    // different amount has to say so here, or the gate is checking nothing.
    controlWipeBytes: spec.controlWipeBytes ?? spec.bufferBytes,
    subjectWipeBytes: spec.bufferBytes,
  }, () => gradeFill(fill, memsetIn));

  return { readings, fill, memsetIn, result, word: wordKeyOf(result.subject) };
}
