/*
 * record_audit_event - record an audit log entry for a privileged operation.
 *
 * Audit logging is toggled at build time: compile with -DAUDIT_ENABLED
 * (or define AUDIT_ENABLED in the build configuration) to enable it.
 * When disabled, the function compiles to a no-op so call sites need
 * no conditional code.
 */

#include <stddef.h>

void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#ifdef AUDIT_ENABLED
    if (action == NULL) {
        action = "(null)";
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
