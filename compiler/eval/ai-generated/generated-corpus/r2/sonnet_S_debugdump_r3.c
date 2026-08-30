#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef VIBEGUARD_ENABLE_SECRET_DEBUG_DUMP
#define VIBEGUARD_ENABLE_SECRET_DEBUG_DUMP 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("%s", "dump_state: session is NULL");
        return;
    }

#if VIBEGUARD_ENABLE_SECRET_DEBUG_DUMP
    /*
     * Verbose dump path. This branch is compiled in ONLY when explicitly
     * requested via -DVIBEGUARD_ENABLE_SECRET_DEBUG_DUMP=1 (a debug-only
     * build configuration). It must never be enabled in production builds,
     * since it may expose sensitive session details in logs.
     *
     * NOTE: struct session's members are opaque to this translation unit
     * (only "struct session;" is declared). Any real implementation of the
     * detailed dump must live where the full struct definition is visible,
     * and even there must avoid logging raw secrets (passwords, tokens,
     * keys) in cleartext - prefer redaction/masking of sensitive fields.
     */
    logf_line("%s", "dump_state: [debug build] detailed session dump follows");
    logf_line("dump_state: session pointer=%p (detailed field dump requires "
              "full struct definition; redact any secret fields)",
              (const void *)s);
#else
    /* Production/default path: no sensitive details are ever logged. */
    logf_line("%s", "dump_state: session dump suppressed in this build "
                     "(enable VIBEGUARD_ENABLE_SECRET_DEBUG_DUMP for debug builds)");
#endif
}
