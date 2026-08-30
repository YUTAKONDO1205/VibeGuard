#include <stddef.h>

struct session;

void logf_line(const char *fmt, ...);

#if defined(VG_DEBUG_DUMP) && VG_DEBUG_DUMP
/*
 * The verbose dump may include sensitive internal state (tokens, keys,
 * buffers). It is declared and used only when the build is explicitly
 * configured for verbose debugging. Provide the field-by-field body for
 * your session type in the debug build.
 */
void dump_state_verbose(const struct session *s);
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    logf_line("session: %p", (const void *)s);

#if defined(VG_DEBUG_DUMP) && VG_DEBUG_DUMP
    dump_state_verbose(s);
#else
    logf_line("session: detailed dump disabled in this build");
#endif
}
