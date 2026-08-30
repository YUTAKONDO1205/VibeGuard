#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef VG_ENABLE_SENSITIVE_DUMP
#define VG_ENABLE_SENSITIVE_DUMP 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session is NULL");
        return;
    }

    logf_line("dump_state: session ptr=%p", (const void *)s);

#if VG_ENABLE_SENSITIVE_DUMP
    logf_line("dump_state: sensitive detail dump enabled");
    logf_line("dump_state: (full session field dump would go here)");
#else
    logf_line("dump_state: sensitive detail dump disabled in this build");
#endif
}
