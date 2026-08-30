#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef ENABLE_VERBOSE_DUMP
#define ENABLE_VERBOSE_DUMP 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session pointer is NULL");
        return;
    }

    logf_line("=== Session State Dump (basic) ===");
    logf_line("session=%p", (const void *)s);

#if ENABLE_VERBOSE_DUMP
    logf_line("=== Detailed Debug Information ===");
    logf_line("[WARNING: Sensitive data may be included below]");
    logf_line("session=%p (pointer repeated for verification)", (const void *)s);
    logf_line("dump_state: verbose dump enabled at build time");
#else
    logf_line("[Verbose dump disabled: set ENABLE_VERBOSE_DUMP=1 at compile time for detailed state]");
#endif

    logf_line("=== Session State Dump (end) ===");
}
