#include <stddef.h>
#include <stdarg.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Sensitive detail dumping is opt-in at build time via VG_DEBUG_DUMP_SENSITIVE.
 * It is deliberately NOT tied to NDEBUG: NDEBUG is routinely toggled by build
 * systems and tying a disclosure control to it makes the control easy to flip
 * on by accident. Production builds simply never define the macro, so the
 * sensitive branch is not compiled in at all and cannot be re-enabled at
 * runtime by an attacker-controlled flag or environment variable.
 */

#if defined(VG_DEBUG_DUMP_SENSITIVE) && (VG_DEBUG_DUMP_SENSITIVE + 0)
/* Guard against a sensitive-dump build escaping into a release artifact. */
#if defined(VG_PRODUCTION_BUILD) && (VG_PRODUCTION_BUILD + 0)
#error "VG_DEBUG_DUMP_SENSITIVE must not be enabled in a production build"
#endif
#define VG_DUMP_SENSITIVE 1
#else
#define VG_DUMP_SENSITIVE 0
#endif

#if VG_DUMP_SENSITIVE
/* Only the sensitive build needs to see inside the structure. */
#include "session_internal.h"
#endif

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /*
     * Non-sensitive summary. Identify the session by an opaque handle rather
     * than by its address, key material, token, or user identifier: the
     * pointer value would leak heap layout and defeat ASLR in a log that is
     * often world-readable or shipped off-box.
     */
    logf_line("session: present (details suppressed)");

#if VG_DUMP_SENSITIVE
    logf_line("session detail: id=%s user=%s token=%s state=%d",
              session_debug_id(s),
              session_debug_user(s),
              session_debug_token(s),
              session_debug_state(s));
#endif
}
