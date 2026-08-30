#include <stddef.h>

struct session;

void logf_line(const char *fmt, ...);

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

    logf_line("session: %p", (const void *)s);

#if defined(DEBUG_DUMP) && DEBUG_DUMP
    /*
     * Detailed dump including sensitive internal state.
     * Compiled in only when DEBUG_DUMP is explicitly enabled at build time,
     * so production builds never emit secrets.
     */
    dump_state_detailed(s);
#else
    logf_line("session: detailed dump disabled in this build");
#endif
}

#if defined(DEBUG_DUMP) && DEBUG_DUMP
void dump_state_detailed(const struct session *s)
{
    /*
     * Access to sensitive fields of struct session goes here. Because the
     * full definition of struct session is only visible in debug builds,
     * this function body is compiled only when DEBUG_DUMP is enabled.
     */
    logf_line("session detail: %p (sensitive fields omitted from this stub)",
              (const void *)s);
}
#endif
