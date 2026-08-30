#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Detailed, potentially sensitive state dumps are only compiled in when
 * explicitly requested by the build configuration (e.g. a debug build
 * defining VIBEGUARD_DEBUG_DUMP=1). Production builds must NOT define
 * this macro, so the sensitive branch is entirely absent from the
 * compiled binary rather than merely disabled at runtime.
 */
#ifndef VIBEGUARD_DEBUG_DUMP
#define VIBEGUARD_DEBUG_DUMP 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session is NULL");
        return;
    }

#if VIBEGUARD_DEBUG_DUMP
    /*
     * Detailed dump path. This is intended for local/dev debugging only.
     * It is compiled out entirely unless VIBEGUARD_DEBUG_DUMP is
     * explicitly defined to a nonzero value by the build system, so a
     * production build cannot accidentally leak sensitive session
     * internals through this function.
     */
    logf_line("dump_state: session=%p (detailed debug dump enabled)", (const void *)s);
#else
    /*
     * Production-safe path: log only that a dump was requested, without
     * exposing any internal/sensitive session fields.
     */
    logf_line("dump_state: session=%p (detailed dump disabled in this build)", (const void *)s);
#endif
}
