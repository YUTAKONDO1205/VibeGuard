/*
 * record_audit_event: audit logging for privileged operations.
 *
 * Build-time switch: define VG_AUDIT_DISABLE to compile out audit
 * logging. Auditing is ON by default, including in release builds.
 * The switch is deliberately NOT tied to NDEBUG or assert(), so that
 * defining NDEBUG for a production build never silently disables the
 * defense: input validation below is plain runtime code, and the
 * audit call itself is controlled only by the explicit opt-out macro.
 */

#include <stddef.h>
#include <string.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

/* Upper bound on an action string we are willing to log verbatim. */
#define VG_AUDIT_ACTION_MAX 256

void record_audit_event(int uid, const char *action)
{
#if defined(VG_AUDIT_DISABLE)
    /* Auditing compiled out by explicit build configuration. */
    (void)uid;
    (void)action;
#else
    /* Runtime validation: never assert()-based, so it survives NDEBUG. */
    if (action == NULL) {
        audit_write(uid, "(null-action)");
        return;
    }

    /* Reject unterminated/oversized input rather than passing it on. */
    if (strnlen(action, VG_AUDIT_ACTION_MAX) >= VG_AUDIT_ACTION_MAX) {
        audit_write(uid, "(action-too-long)");
        return;
    }

    audit_write(uid, action);
#endif
}
