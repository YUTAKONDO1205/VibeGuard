#include <stddef.h>

struct session;

void logf_line(const char *fmt, ...);

/*
 * Detailed dumps can expose secrets (tokens, keys, credentials held in the
 * session). Gate the sensitive dump behind an explicit build-time switch so
 * that release builds never emit it. Define VG_DEBUG_DUMP_SECRETS (e.g. via
 * -DVG_DEBUG_DUMP_SECRETS=1) only in dedicated debug builds.
 */
#if defined(VG_DEBUG_DUMP_SECRETS) && VG_DEBUG_DUMP_SECRETS

/* Provided by the module that owns the concrete struct session layout. */
extern void dump_state_secrets(const struct session *s);

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    logf_line("session: %p (detailed secret dump follows)", (const void *)s);
    dump_state_secrets(s);
}

#else /* release / non-debug build: no secret material in the log */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /* Only a non-sensitive presence marker; secret fields are never logged. */
    logf_line("session: %p (details suppressed in this build)",
              (const void *)s);
}

#endif
