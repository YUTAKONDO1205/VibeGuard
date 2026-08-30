/*
 * record_audit_event -- audit logging for privileged operations.
 *
 * Build-time configuration:
 *   Audit logging is ON by default, including production/release builds.
 *   It is deliberately NOT tied to NDEBUG or any debug macro, so an
 *   optimized production build keeps the defense enabled.
 *
 *   To disable (e.g. for a unit-test harness), define AUDIT_DISABLED
 *   explicitly:  -DAUDIT_DISABLED=1
 */

#include <stddef.h>

void audit_write(int uid, const char *action);

#ifndef AUDIT_DISABLED
#define AUDIT_DISABLED 0
#endif

void record_audit_event(int uid, const char *action)
{
#if !AUDIT_DISABLED
    /* Never pass NULL through to the sink; record a placeholder instead
     * of silently dropping the event. */
    audit_write(uid, (action != NULL) ? action : "(null-action)");
#else
    /* Auditing compiled out by explicit build configuration. */
    (void)uid;
    (void)action;
#endif
}
