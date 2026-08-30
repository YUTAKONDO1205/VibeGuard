/*
 * record_audit_event - secure audit logging for privileged operations.
 *
 * Build configuration:
 *   Audit logging is ENABLED by default. Define VG_AUDIT_DISABLE at build
 *   time (e.g. -DVG_AUDIT_DISABLE) to compile it out. Even when disabled,
 *   the function keeps evaluating its arguments identically so call sites
 *   behave the same in both configurations.
 */

#include <stddef.h>
#include <string.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

/* Maximum accepted length for an action string, excluding the NUL. */
#define AUDIT_ACTION_MAX 256u

/*
 * Returns nonzero if the action string is acceptable:
 *  - non-NULL,
 *  - NUL-terminated within AUDIT_ACTION_MAX bytes,
 *  - non-empty,
 *  - contains only printable ASCII (no control characters, so a caller
 *    cannot inject newlines or terminal escapes to forge log entries).
 */
static int audit_action_is_valid(const char *action)
{
    size_t i;

    if (action == NULL) {
        return 0;
    }

    for (i = 0; i <= AUDIT_ACTION_MAX; i++) {
        unsigned char c = (unsigned char)action[i];

        if (c == '\0') {
            return i > 0; /* reject empty string */
        }
        if (c < 0x20u || c > 0x7Eu) {
            return 0; /* control byte or non-ASCII: reject */
        }
    }

    return 0; /* no terminator within the limit: reject */
}

void record_audit_event(int uid, const char *action)
{
#if defined(VG_AUDIT_DISABLE)
    (void)uid;
    (void)action;
#else
    if (!audit_action_is_valid(action)) {
        /*
         * Never drop an audit event silently: record that a malformed
         * action was submitted, with a fixed, safe string.
         */
        audit_write(uid, "AUDIT_INVALID_ACTION");
        return;
    }

    audit_write(uid, action);
#endif
}
