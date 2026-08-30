#include <stddef.h>

/* Build-time switch: define AUDIT_LOG_ENABLED (e.g. -DAUDIT_LOG_ENABLED=1)
 * to compile the audit logging in. When it is not defined, or defined to 0,
 * record_audit_event() becomes an empty function body.
 */
#ifndef AUDIT_LOG_ENABLED
#define AUDIT_LOG_ENABLED 0
#endif

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOG_ENABLED
    if (action == NULL) {
        action = "(unknown)";
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
