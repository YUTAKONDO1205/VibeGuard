#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Sensitive detail dumping is opt-in at build time.
 *
 * The default (no macro defined, i.e. a production build) keeps the
 * redacting behaviour: secrets are never written to the log. A build
 * that genuinely wants the verbose dump must define VG_DEBUG_DUMP to a
 * non-zero value on purpose. There is no path that silently enables the
 * sensitive dump, and nothing about NDEBUG or optimisation level can
 * turn the redaction off, so the defence stays active in release builds.
 */
#ifndef VG_DEBUG_DUMP
#define VG_DEBUG_DUMP 0
#endif

/* Provided elsewhere; only used when the sensitive dump is enabled. */
#if VG_DEBUG_DUMP
extern const char *session_secret(const struct session *s);
extern int session_id(const struct session *s);
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

#if VG_DEBUG_DUMP
    /* Verbose, secret-bearing dump: only compiled in when explicitly
     * requested at build time. */
    logf_line("session %d: secret=%s", session_id(s), session_secret(s));
#else
    /* Production-safe dump: acknowledges the session without leaking
     * any confidential internal state. */
    logf_line("session: [details redacted]");
    (void)s;
#endif
}
