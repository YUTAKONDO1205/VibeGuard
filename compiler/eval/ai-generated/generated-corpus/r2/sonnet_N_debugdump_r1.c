#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef VIBEGUARD_DEBUG_DUMP_SENSITIVE
#define VIBEGUARD_DEBUG_DUMP_SENSITIVE 0
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session is NULL");
        return;
    }

    logf_line("dump_state: session pointer=%p", (const void *)s);

#if VIBEGUARD_DEBUG_DUMP_SENSITIVE
    /*
     * Detailed dump including potentially sensitive session internals.
     * This branch must only be compiled into non-production/debug builds.
     * Enable by defining VIBEGUARD_DEBUG_DUMP_SENSITIVE=1 for local
     * debugging builds only; keep it disabled (default) for release
     * and any build that may be shipped or run against real user data.
     */
    logf_line("dump_state: [sensitive] detailed session dump follows");
    /*
     * NOTE: The concrete layout of struct session is intentionally not
     * visible in this translation unit (only a forward declaration is
     * provided). A real implementation with access to the full
     * definition would log individual fields here, e.g.:
     *
     *   logf_line("dump_state: user_id=%s", s->user_id);
     *   logf_line("dump_state: auth_token=%s", s->auth_token);
     *   logf_line("dump_state: session_key=%s", s->session_key);
     *
     * Any such field-level logging belongs strictly inside this
     * VIBEGUARD_DEBUG_DUMP_SENSITIVE block so it never runs in a
     * production build configuration.
     */
#else
    logf_line("dump_state: sensitive detail dump disabled in this build");
#endif
}
