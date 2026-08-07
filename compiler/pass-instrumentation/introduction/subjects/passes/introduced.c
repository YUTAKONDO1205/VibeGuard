/* The fixture for the pass-level half: a translation unit in which the
 * optimiser introduces an external call the source never wrote.
 *
 * WHY THIS IS THE MIRROR OF THE FIRST-LOSS MEASUREMENT. On the loss side the
 * subject is a `memset` that a pass deletes, and the question is which pass.
 * Here the subject is a zeroing loop that the loop-idiom recogniser *turns
 * into* a `memset` -- the same effect, the same oracle, and the arrow the other
 * way round. The two measurements read the same IR object model and count the
 * same thing, so the pair of them is one experiment rather than two that
 * happen to be adjacent.
 *
 * THE CONTROL. interfaces.md §4 requires an effect that cannot be optimised
 * away, so that a run in which everything came out zero is recognisable as a
 * broken run rather than read as a clean result. Here the control is an
 * external call that is present in the source and must therefore be present at
 * the very first observation of its function -- `atEntry`, attributed to no
 * pass at all. Contrasting it with the subject is what makes the subject's
 * attribution mean something: one element with a pass name against one element
 * without, from the same log, in the same run.
 *
 * `intro_sink` is declared and never defined on purpose. An external call whose
 * callee has a body in this module is not an external call, and the optimiser
 * would inline it and remove the site.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

#include <stddef.h>

/* Defined in another translation unit, so the calls survive to the end of the
 * pipeline and the count is not an artefact of nothing having happened yet. */
extern void intro_sink(const void *p, size_t n);
extern size_t intro_len(const char *s);

/* CONTROL. Its external call is written in the source, so the observer must
 * record it as present at the first observation of this function and must not
 * attribute it to any pass. If this one ever comes back with a pass name, the
 * run is broken and the subject's attribution is worth nothing. */
size_t intro_pass_control(const char *s) {
  size_t n = intro_len(s);
  intro_sink(s, n);
  return n;
}

/* SUBJECT. There is no call in this loop. At -O2 the loop-idiom recogniser
 * replaces it with a call to the memset intrinsic, which is an external call
 * that appeared during the pipeline -- exactly what the introduction side
 * exists to attribute. The trailing sink keeps the stores live so that dead-
 * store elimination does not delete the loop before the idiom is recognised;
 * without it the fixture would measure nothing and look like a clean result. */
void intro_pass_subject(char *buf, size_t n) {
  for (size_t i = 0; i < n; i++)
    buf[i] = 0;
  intro_sink(buf, n);
}

/* A second subject, so that "which unit" is a question with more than one
 * possible answer. Two functions introducing the same element at different
 * points is the case a flat P0..Pn pass list cannot represent: one pass, two
 * callbacks, two different (pass, IR unit) pairs. */
void intro_pass_subject_two(char *buf, size_t n) {
  for (size_t i = 0; i < n; i++)
    buf[i] = 0;
  intro_sink(buf, n);
}

/* THE WHOLE-SERIES SUBJECT. interfaces.md §3 says a state history must keep the
 * whole sequence and must not stop at the first transition, and the reason it
 * says so is this shape: an effect removed in one form and rebuilt in another.
 *
 * The fixed-size builtin below is a `llvm.memset` call the front end emits, so
 * the element is PRESENT before any pass runs. InstCombine lowers a short
 * constant-size memset to a plain store, and the call site goes -- LOST. The
 * loop underneath is then recognised by the loop-idiom pass and turned back
 * into a `llvm.memset` call -- REINTRODUCED, because the element has a history
 * by then and coming back is not the same event as arriving.
 *
 * A checker that stopped at the first PRESENT -> LOST would report this
 * function as having lost its zeroing, which a later pass had already put back.
 * That is a false positive with a plausible story attached, and interfaces.md
 * names those as the expensive kind. */
void intro_pass_reintroduced(char *buf, size_t n) {
  __builtin_memset(buf, 0, 8);
  for (size_t i = 8; i < n; i++)
    buf[i] = 0;
  intro_sink(buf, n);
}
