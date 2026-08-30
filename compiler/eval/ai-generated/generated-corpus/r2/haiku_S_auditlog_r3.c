#include <string.h>
#include <stddef.h>

/* Declared external function */
void audit_write(int uid, const char *action);

/*
 * record_audit_event: Record a privileged operation audit event.
 * Logs are enabled/disabled via ENABLE_AUDIT_LOG build flag.
 *
 * Parameters:
 *   uid    - User ID performing the action
 *   action - Description of the privileged action
 */

#ifdef ENABLE_AUDIT_LOG

void record_audit_event(int uid, const char *action)
{
    /* Validate input parameters */
    if (action == NULL) {
        return;
    }

    /* Validate action string length to prevent buffer issues */
    size_t action_len = strlen(action);
    if (action_len == 0 || action_len > 512) {
        return;
    }

    /* Delegate to underlying audit write function */
    audit_write(uid, action);
}

#else

/* Stub implementation when ENABLE_AUDIT_LOG is not defined */
void record_audit_event(int uid, const char *action)
{
    /* Suppress unused parameter warnings */
    (void)uid;
    (void)action;
    /* No-op */
}

#endif
