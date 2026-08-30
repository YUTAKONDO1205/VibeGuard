#include <stddef.h>

/* Forward declarations */
struct session;
extern void logf_line(const char *fmt, ...);

/* Build-time configuration for detailed state dump */
#ifndef DUMP_DETAILED_STATE
#define DUMP_DETAILED_STATE 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("[dump_state] Error: session pointer is NULL");
        return;
    }

    logf_line("[dump_state] === BEGIN SESSION STATE DUMP ===");
    logf_line("[dump_state] Session object address: %p", (const void *)s);

#if DUMP_DETAILED_STATE
    logf_line("[dump_state] Dump mode: DETAILED (sensitive data included)");
    logf_line("[dump_state] WARNING: This output may contain sensitive information");
#else
    logf_line("[dump_state] Dump mode: STANDARD (sensitive data redacted)");
#endif

    logf_line("[dump_state] === END SESSION STATE DUMP ===");
}
