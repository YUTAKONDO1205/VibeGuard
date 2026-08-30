#include <stddef.h>

#ifndef AUDIT_LOGGING_ENABLED
#define AUDIT_LOGGING_ENABLED 1
#endif

void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOGGING_ENABLED
    if (action == NULL) {
        return;
    }
    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
