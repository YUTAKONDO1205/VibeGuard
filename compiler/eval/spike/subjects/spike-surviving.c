/* The KNOWN-SURVIVING spike.
 *
 * The erasure fixture's `wipe_kept` shape: the same escaped buffer, wiped, and
 * then READ. The read makes the zeroes observable, so no optimisation level of
 * either vendor is allowed to remove the wipe, and it is removed at none.
 *
 * It is the other half of the recovery pair and it is the half that catches a
 * different failure. A spike pair with only the disappearing member would pass
 * for an instrument that reports WIPE_ELIMINATED for everything -- an ablation
 * whose two compiles were accidentally the same file, say, or a body reader
 * that returns the same empty string for both listings. This one has to come
 * back SURVIVED, and it cannot unless the two listings really are different
 * compilations of two different sources.
 *
 * No wipe-symbol list is written here and none is written in the harness: the
 * survival is structural (the wipe is read afterwards) rather than a property
 * of a spelling the optimiser is told to leave alone, so the pair keeps working
 * on a toolchain whose libc lacks `explicit_bzero` and on a version of the
 * instrument that was handed a different effect-symbol list.
 *
 * It returns `int` for the reason its twin's header gives at length: a `void`
 * subject is picked up by wipeHelpers() as a wipe helper and its own definition
 * header is then ablated. The r2 corpus's twenty subjects all return `int`.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */
#include <string.h>

void vgspike_fill(unsigned char *out, unsigned long n);
void vgspike_consume(const unsigned char *p, unsigned long n);

int vgspike_surviving(void) {
    unsigned char secret[32];
    vgspike_fill(secret, sizeof secret);
    memset(secret, 0, sizeof secret);
    vgspike_consume(secret, sizeof secret);
    return 0;
}
