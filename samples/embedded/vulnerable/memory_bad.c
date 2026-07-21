/* Intentionally vulnerable C — exercises the VG-MEM family (17d).
 * Lives under samples/, which the self-scan ignores by directory, so no
 * disable pragma is needed and these findings are expected. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void read_line(void) {
  char buf[64];
  gets(buf);                          /* VG-MEM-001: unbounded stack read */
}

void copy_in(char *input) {
  char dst[32];
  strcpy(dst, input);                 /* VG-MEM-002: unbounded copy */
  sprintf(dst, "%s", input);          /* VG-MEM-002 */
}

void size_from_source(char *src) {
  char *p = malloc(16);
  memcpy(p, src, strlen(src));        /* VG-MEM-003: sized from source */
  free(p);
  free(p);                            /* VG-MEM-004: double free (straight-line) */
}

void use_after(char *data) {
  char *q = malloc(32);
  memcpy(q, data, 8);
  free(q);
  q[0] = 'x';                         /* VG-MEM-005: use after free */
}
