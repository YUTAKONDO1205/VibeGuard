#include <stddef.h>
#include <stdarg.h>

struct session;
void logf_line(const char *fmt, ...);

void dump_state(const struct session *s) {
    if (s == NULL) {
        logf_line("dump_state: session pointer is NULL");
        return;
    }

    logf_line("=== Session State Dump ===");
    logf_line("Session address: %p", (const void *)s);

    logf_line("Session state logging enabled (release-safe dump)");

#ifdef DETAILED_DUMP
    logf_line("Detailed dump mode: ENABLED");
    logf_line("Sensitive session internals available for inspection");
#else
    logf_line("Detailed dump mode: DISABLED (build with DETAILED_DUMP to enable)");
#endif

    logf_line("=== End Session State Dump ===");
}
