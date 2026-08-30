#include <stddef.h>

/* Build-time switch to enable/disable audit logging.
 * Define AUDIT_LOGGING_ENABLED=0 at compile time to disable audit logging
 * (e.g. -DAUDIT_LOGGING_ENABLED=0). Defaults to enabled. */
#ifndef AUDIT_LOGGING_ENABLED
#define AUDIT_LOGGING_ENABLED 1
#endif

/* Declared elsewhere; implements the actual audit log write. */
void audit_write(int uid, const char *action);

/*
 * record_audit_event
 *
 * Records an audit event for a privileged operation. This function is
 * the single entry point used by callers; whether the event is actually
 * persisted is controlled entirely by the AUDIT_LOGGING_ENABLED build
 * configuration, so callers do not need to guard calls themselves.
 *
 * uid    - identifier of the user performing the privileged action.
 * action - description of the action being performed. Must be a valid,
 *          NUL-terminated string; NULL and empty strings are rejected
 *          defensively to avoid passing bad input further down the
 *          logging pipeline.
 */
void record_audit_event(int uid, const char *action)
{
#if AUDIT_LOGGING_ENABLED
    if (action == NULL || action[0] == '\0') {
        return;
    }

    audit_write(uid, action);
#else
    (void)uid;
    (void)action;
#endif
}
