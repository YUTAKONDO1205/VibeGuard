/* Safe counterpart to memory_bad.c — bounded calls, free-then-null. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void read_line(void) {
  char buf[64];
  fgets(buf, sizeof(buf), stdin);
}

void copy_in(const char *input) {
  char dst[32];
  strncpy(dst, input, sizeof(dst) - 1);
  dst[sizeof(dst) - 1] = '\0';
  snprintf(dst, sizeof(dst), "%s", input);
}

void manage(const char *src) {
  char *p = malloc(64);
  if (!p) return;
  size_t n = strlen(src);
  if (n >= 64) n = 63;
  memcpy(p, src, n);
  free(p);
  p = NULL;
}
