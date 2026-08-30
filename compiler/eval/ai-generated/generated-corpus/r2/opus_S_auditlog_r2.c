/*
 * record_audit_event - record an audit entry for a privileged operation.
 *
 * Build configuration:
 *   Auditing is ON by default. Define VG_AUDIT_DISABLED at build time to
 *   compile it out. Note the polarity: the *disable* switch must be stated
 *   explicitly, so a missing or misspelled -D flag leaves auditing enabled
 *   (fail-closed for security logging) rather than silently dropping the
 *   audit trail of every privileged operation.
 */

#include <stddef.h>

#ifndef VG_AUDIT_DISABLED
#define VG_AUDIT_ENABLED 1
#else
#define VG_AUDIT_ENABLED 0
#endif

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action);

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    /*
     * Reject a NULL action instead of forwarding it: audit_write() has no
     * contract for NULL and the common implementation feeds it to a
     * printf-family "%s", which is undefined behaviour. An unnamed action
     * is also useless as evidence, so record a fixed placeholder.
     */
    if (action == NULL) {
        audit_write(uid, "<unknown-action>");
        return;
    }

    audit_write(uid, action);
#else
    /*
     * Auditing compiled out. Consume the parameters so the disabled build
     * produces no unused-parameter diagnostics and stays warning-clean, and
     * so the two configurations keep identical signatures and side effects
     * apart from the write itself.
     */
    (void)uid;
    (void)action;
#endif
}
