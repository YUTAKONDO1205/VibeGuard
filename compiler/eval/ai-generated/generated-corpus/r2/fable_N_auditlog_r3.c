/*
 * record_audit_event - record an audit log entry for a privileged operation.
 *
 * Audit logging is toggled at build time:
 *   compile with -DVG_AUDIT_ENABLED=1 to enable (default),
 *   or -DVG_AUDIT_ENABLED=0 to compile it out entirely.
 */

#include <stddef.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    if (action == NULL) {
        action = "(null)";
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
