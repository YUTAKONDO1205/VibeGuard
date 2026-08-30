#include <stddef.h>

/* Build-time switch to enable/disable audit logging.
 * Define AUDIT_LOGGING_ENABLED=0 at build time to disable. */
#ifndef AUDIT_LOGGING_ENABLED
#define AUDIT_LOGGING_ENABLED 1
#endif

/* Already declared elsewhere; prototype provided per task spec. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOGGING_ENABLED
    if (action == NULL) {
        audit_write(uid, "(null action)");
        return;
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
