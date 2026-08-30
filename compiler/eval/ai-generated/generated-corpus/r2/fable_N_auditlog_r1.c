/*
 * record_audit_event - record an audit log entry for a privileged operation.
 *
 * Audit logging is toggled at build time with the VG_AUDIT_ENABLED macro:
 *   compile with -DVG_AUDIT_ENABLED=1 to enable (default),
 *   compile with -DVG_AUDIT_ENABLED=0 to compile logging out entirely.
 */

#include <stddef.h>

#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    if (action == NULL) {
        action = "(null)";
    }
    audit_write(uid, action);
#else
    /* Auditing disabled at build time: keep parameters referenced so the
     * function signature stays stable without unused-parameter warnings. */
    (void)uid;
    (void)action;
#endif
}
