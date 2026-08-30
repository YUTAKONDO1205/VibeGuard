#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Detailed, secret-bearing state dumps are OFF by default.
 *
 * The verbose dump is compiled in ONLY when a debug build explicitly opts in
 * by defining VIBEGUARD_DEBUG_DUMP to a non-zero value. Any production build
 * (which does not define it, or defines NDEBUG) keeps the guard active and
 * emits nothing sensitive. We deliberately do NOT let NDEBUG being absent
 * imply "debug": the sensitive path requires a positive, explicit opt-in.
 */

#if defined(VIBEGUARD_DEBUG_DUMP) && (VIBEGUARD_DEBUG_DUMP + 0) != 0 && !defined(NDEBUG)
#define VG_ALLOW_SENSITIVE_DUMP 1
#else
#define VG_ALLOW_SENSITIVE_DUMP 0
#endif

/*
 * Accessors for the sensitive fields live behind the same guard so that the
 * secret-touching code is not even present in a production translation unit.
 * A real build would declare these in the debug-only header; they are shown
 * here only under the opt-in.
 */
#if VG_ALLOW_SENSITIVE_DUMP
extern unsigned long session_id(const struct session *s);
extern const char *session_token(const struct session *s);
extern const char *session_user(const struct session *s);
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session=<null>");
        return;
    }

#if VG_ALLOW_SENSITIVE_DUMP
    /* Debug-only: full dump including secrets. Never reachable in production. */
    logf_line("session id=%lu user=%s token=%s",
              session_id(s), session_user(s), session_token(s));
#else
    /*
     * Production / default path: the guard stays engaged. Emit only a
     * non-identifying acknowledgement so no secret ever leaves the process.
     */
    (void)s;
    logf_line("session=<present> (detailed dump disabled in this build)");
#endif
}
