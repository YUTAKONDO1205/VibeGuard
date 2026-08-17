/* NC-07: sanitizer instrumentation, on its own.
 *
 * This is the hardest of the seven, and the reason is worth stating rather than
 * discovering. Every other structure in this corpus exists in the front end's
 * output: a vtable, a thunk, a template instantiation and a static initialiser
 * are all emitted by clang's code generation *before* the optimisation pipeline
 * runs, so `-Xclang -disable-llvm-passes -emit-llvm` -- the measured half of the
 * toolchain baseline -- contains them and the subtraction can find them there.
 *
 * Sanitizer instrumentation is not. AddressSanitizer is an LLVM pass. It runs
 * *after* the point at which the measured baseline is taken, so every symbol,
 * every section and every .init_array slot it adds is, from the baseline's point
 * of view, something that appeared out of nowhere between the measurement and
 * the object -- which is a precise description of what VG-INTRO-001..004 exist
 * to report.
 *
 * That makes this file the one that decides whether the structural half of the
 * baseline is real or decorative. If the `__asan_` / `asan.module_ctor` shapes
 * in lib/origins.mjs cover what the pass actually emits, the verdict is clean.
 * If they cover only the names somebody remembered, this file says so.
 *
 * What the compiler is being made to instrument:
 *
 *   * a global array          -> a redzone, a global descriptor, and the
 *                                registration of both at start-up
 *   * a stack array           -> stack poisoning, and the fake-stack calls
 *   * a heap allocation       -> the interceptors around malloc/free
 *   * a memcpy of known size  -> __asan_memcpy rather than memcpy
 *   * a partial-word access   -> the byte-granular check path
 *
 * Nothing here is a bug. The reads and writes are all in bounds; a sanitizer
 * build of this file is silent at run time. What is being measured is what the
 * *instrumentation* leaves in the object, not what it catches.
 *
 * Licence: Apache-2.0 WITH LLVM-exception (see compiler/LICENSE).
 */

#include <stdlib.h>
#include <string.h>

/* A global with an address that is taken, so ASan gives it a redzone and a
 * descriptor rather than deciding it is unobservable. */
char nc07_global_buffer[64] = {0};
int nc07_global_counter = 0;

__attribute__((noinline)) static int touch_stack(const char *s, int n) {
  char local[32];
  int i = 0;
  for (; i < n && i < 31 && s[i]; ++i)
    local[i] = s[i];
  local[i] = '\0';
  /* A partial-word read at the end of a valid region: the byte-granular check. */
  return (int)(unsigned char)local[i > 0 ? i - 1 : 0] + i;
}

__attribute__((noinline)) static int touch_heap(const char *s, int n) {
  char *heap = (char *)malloc(64);
  int total = 0;
  if (!heap)
    return 0;
  memset(heap, 0, 64);
  /* A memcpy with a size the compiler knows: ASan rewrites it to __asan_memcpy. */
  memcpy(heap, s, (size_t)(n < 63 ? n : 63));
  for (int i = 0; i < 63; ++i)
    total += (unsigned char)heap[i];
  free(heap);
  return total;
}

/* The control. interfaces.md §4. */
int nc07_control_sum(const char *s) {
  int n = 0;
  for (const char *p = s; *p; ++p)
    n += (unsigned char)*p;
  return n;
}

int nc07_sanitizer_main(const char *text) {
  int n = nc07_control_sum(text);
  int total = n;

  /* Global: written and read through a volatile index the optimiser cannot
   * resolve, so the access survives to the object. */
  volatile int idx = n & 31;
  nc07_global_buffer[idx] = (char)(n & 0x7f);
  total += (int)(unsigned char)nc07_global_buffer[idx];
  nc07_global_counter += n;
  total += nc07_global_counter;

  total += touch_stack(text, n & 15);
  total += touch_heap(text, n & 15);

  return total;
}
