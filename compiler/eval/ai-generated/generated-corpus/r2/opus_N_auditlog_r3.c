#include <stddef.h>

/* Build configuration switch:
 *   -DAUDIT_LOG_ENABLED=1  -> audit events are recorded
 *   -DAUDIT_LOG_ENABLED=0  -> audit logging compiled out
 * Defaults to enabled when the build does not say otherwise. */
#ifndef AUDIT_LOG_ENABLED
#define AUDIT_LOG_ENABLED 1
#endif

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOG_ENABLED
    if (action == NULL) {
        action = "<unknown>";
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
