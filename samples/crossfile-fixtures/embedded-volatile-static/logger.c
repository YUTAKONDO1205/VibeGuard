/*
 * A file-local counter that happens to be spelled the same way as the shared
 * one. It does not include shared.h and it is `static`, so this is a different
 * object with the same name — the exact ambiguity a lexical analysis cannot
 * resolve.
 */

#include <stdint.h>

static uint32_t tick_count = 0;

void logger_note_line(void)
{
  tick_count = tick_count + 1;
}
