#include <stddef.h>
#include <string.h>
#include <stdarg.h>

struct session;
void logf_line(const char *fmt, ...);

#ifdef DEBUG_DETAILED_DUMP
#define DUMP_DETAIL(fmt, ...) logf_line("[DETAIL] " fmt, ##__VA_ARGS__)
#else
#define DUMP_DETAIL(fmt, ...) do {} while (0)
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session pointer is NULL");
        return;
    }

    logf_line("=== Session State Dump ===");
    logf_line("Session address: %p", (const void *)s);

    DUMP_DETAIL("Internal session structure inspection enabled");
    DUMP_DETAIL("Note: detailed output is controlled by DEBUG_DETAILED_DUMP build flag");

    logf_line("=== End of Dump ===");
}
