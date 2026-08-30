#include <stddef.h>

struct session;
void logf_line(const char *fmt, ...);

#if defined(VIBEGUARD_DEBUG_DUMP) && !defined(NDEBUG)
#define VG_ENABLE_SENSITIVE_DUMP 1
#else
#define VG_ENABLE_SENSITIVE_DUMP 0
#endif

#if VG_ENABLE_SENSITIVE_DUMP

/*
 * Sensitive field accessors are intentionally left as extern declarations
 * so this translation unit can be built standalone. In the real codebase
 * these must resolve to accessors that do not expose secrets outside of
 * a debug-only build.
 */
extern const void *session_get_raw_ptr(const struct session *s);
extern unsigned long session_get_id(const struct session *s);
extern const char *session_get_user_token(const struct session *s);
extern const char *session_get_internal_state_name(const struct session *s);

static void dump_state_sensitive(const struct session *s)
{
    logf_line("[dump_state][DEBUG BUILD] session ptr=%p", session_get_raw_ptr(s));
    logf_line("[dump_state][DEBUG BUILD] session id=%lu", session_get_id(s));
    logf_line("[dump_state][DEBUG BUILD] internal_state=%s",
              session_get_internal_state_name(s));
    /*
     * Even in a debug build, avoid ever writing the raw token to logs.
     * Only its presence/length is reported so this function stays useful
     * for debugging without becoming a credential leak vector by itself.
     */
    {
        const char *tok = session_get_user_token(s);
        size_t len = 0;
        if (tok != NULL) {
            while (tok[len] != '\0') {
                ++len;
            }
        }
        logf_line("[dump_state][DEBUG BUILD] user_token_present=%s user_token_len=%zu",
                  (tok != NULL) ? "yes" : "no", len);
    }
}

#endif /* VG_ENABLE_SENSITIVE_DUMP */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("[dump_state] session=NULL");
        return;
    }

#if VG_ENABLE_SENSITIVE_DUMP
    dump_state_sensitive(s);
#else
    logf_line("[dump_state] session dump suppressed (production build)");
#endif
}
