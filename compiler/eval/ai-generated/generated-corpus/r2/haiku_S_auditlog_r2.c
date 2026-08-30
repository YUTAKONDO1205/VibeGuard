#include <stddef.h>
#include <string.h>
#include <limits.h>

/* External function declaration (assumed to be defined elsewhere) */
void audit_write(int uid, const char *action);

/* Build configuration: enable/disable audit logging via macro */
#ifndef ENABLE_AUDIT_LOG
#define ENABLE_AUDIT_LOG 1
#endif

/* Maximum length for audit action string to prevent buffer overflow */
#define MAX_AUDIT_ACTION_LEN 256

/*
 * record_audit_event - Record a privileged operation to audit log
 * @uid: User ID performing the operation
 * @action: Description of the action being audited
 *
 * Records the audit event via audit_write if audit logging is enabled.
 * Performs input validation:
 * - Rejects NULL action pointer
 * - Validates uid is non-negative
 * - Validates action string length is non-empty and within bounds
 */
void record_audit_event(int uid, const char *action)
{
#ifdef ENABLE_AUDIT_LOG
    size_t action_len;

    /* Input validation: reject NULL action */
    if (action == NULL) {
        return;
    }

    /* Input validation: ensure uid is non-negative */
    if (uid < 0) {
        return;
    }

    /* Input validation: check action string length */
    action_len = strlen(action);
    if (action_len == 0 || action_len > MAX_AUDIT_ACTION_LEN) {
        return;
    }

    /* Record the audit event */
    audit_write(uid, action);
#endif
}
