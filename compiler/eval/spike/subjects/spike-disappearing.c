/* The KNOWN-DISAPPEARING spike.
 *
 * This is the erasure fixture's `handle_request` shape, with the names changed
 * so that a run's two spikes cannot be confused with a corpus file's subject:
 * a buffer that escapes into two functions this translation unit cannot see,
 * filled, read, and then wiped. The wipe is the last use, so it is a dead
 * store and the optimiser is permitted to delete it.
 *
 * "Permitted" is the whole point. This file is not here to be a bug; it is
 * here because the instrument's claim is that it can SEE an elimination, and
 * an instrument that has not seen one in this run has not been shown to be
 * working in this run. Its disappearance is the recovery reading, the way a
 * spiked analyte's recovery is the reading in an analytical assay.
 *
 * Two details are load-bearing and neither is decoration.
 *
 * The subject returns `int`, not `void`. wipeHelpers() in
 * ../../ai-generated/lib/ablation-cell.mjs treats every VOID function whose
 * body zeroes as a wipe helper and then looks for calls to it, and its
 * call pattern -- name, `(`, anything up to the first `;` -- matches the
 * helper's own DEFINITION header when the body's first statement is a
 * declaration. Written `void`, this file's ablated form deleted
 * `vgspike_disappearing(void) {\n unsigned char secret[32];` and every cell
 * read ABLATION_DID_NOT_COMPILE (measured, 2026-09-12, all four of
 * clang-18/gcc-13 x -O0/-O2). The r2 corpus does not hit this because its
 * twenty subjects all return `int`; a spike written outside that population
 * would be gating the instrument on an input it is never given. The spike is
 * therefore shaped like the corpus, and the interaction is written down here
 * rather than fixed in a file this lane does not own.
 *
 * The buffer is called `secret` on purpose: wipeSpans() falls back to a name
 * gate when it cannot find the target function's body, which is exactly what
 * happens on the deliberately-misspelt injected run, and the fallback has to
 * reach the same span so that the injected reading fails for the reason being
 * injected (no body to read) rather than for a second, accidental one.
 *
 * Nothing here decides the verdict. Whether the wipe disappeared is decided by
 * compiling this file and its ablated form and comparing the target function's
 * body -- differential compilation -- never by searching the listing for
 * `memset`. The positive control is appended at compile time from
 * ../../ai-generated/lib/ablation-cell.mjs.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
#include <string.h>

/* Defined nowhere in this translation unit, so the compiler must assume the
 * buffer's address escapes and materialise it in memory. */
void vgspike_fill(unsigned char *out, unsigned long n);
void vgspike_consume(const unsigned char *p, unsigned long n);

int vgspike_disappearing(void) {
    unsigned char secret[32];
    vgspike_fill(secret, sizeof secret);
    vgspike_consume(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    return 0;
}
