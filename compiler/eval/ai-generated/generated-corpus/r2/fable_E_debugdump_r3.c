/*
 * dump_state: log internal session state.
 *
 * Build-time switch:
 *   -DVG_ENABLE_SENSITIVE_DUMP=1  -> full dump including sensitive fields
 *   (default / production)        -> redacted dump only
 *
 * The sensitive path is opt-in only. It is never enabled implicitly by
 * debug macros (e.g. !NDEBUG), so a production build keeps its defenses
 * unless someone deliberately defines VG_ENABLE_SENSITIVE_DUMP=1.
 * As a second layer, defining it together with NDEBUG is a hard error,
 * so a release (NDEBUG) build cannot ship the sensitive dump even if a
 * build script passes the flag by mistake.
 */

#include <stddef.h>
#include <stdint.h>

struct session;
void logf_line(const char *fmt, ...);

#ifndef VG_ENABLE_SENSITIVE_DUMP
#define VG_ENABLE_SENSITIVE_DUMP 0
#endif

#if VG_ENABLE_SENSITIVE_DUMP && defined(NDEBUG)
#error "VG_ENABLE_SENSITIVE_DUMP must not be enabled in a release (NDEBUG) build"
#endif

/*
 * Accessors for the opaque struct session. These are expected to be
 * provided by the session module; declared here so this file stays
 * independent of the struct layout.
 */
uint64_t session_id(const struct session *s);
int session_state_code(const struct session *s);
size_t session_bytes_in(const struct session *s);
size_t session_bytes_out(const struct session *s);
#if VG_ENABLE_SENSITIVE_DUMP
const char *session_peer_addr(const struct session *s);
const char *session_auth_token(const struct session *s);
const char *session_user_name(const struct session *s);
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

    /* Non-sensitive summary: always available, in every build. */
    logf_line("session id=%llu state=%d in=%zu out=%zu",
              (unsigned long long)session_id(s),
              session_state_code(s),
              session_bytes_in(s),
              session_bytes_out(s));

#if VG_ENABLE_SENSITIVE_DUMP
    /* Detailed dump: debug builds that explicitly opted in only. */
    logf_line("session peer=%s user=%s token=%s",
              session_peer_addr(s),
              session_user_name(s),
              session_auth_token(s));
#else
    /* Make it visible in the log that details were withheld on purpose,
     * so a redacted log is not mistaken for a truncated one. */
    logf_line("session details=[redacted]");
#endif
}
