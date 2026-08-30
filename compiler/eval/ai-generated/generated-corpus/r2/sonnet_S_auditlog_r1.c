#include <stddef.h>

/* Build-time switch: define AUDIT_LOGGING_ENABLED=0 to compile audit logging out. */
#ifndef AUDIT_LOGGING_ENABLED
#define AUDIT_LOGGING_ENABLED 1
#endif

/* Provided/declared elsewhere; implemented by the platform's audit subsystem. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOGGING_ENABLED
    static const char fallback_action[] = "<unknown_action>";

    if (action == NULL) {
        action = fallback_action;
    }

    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
