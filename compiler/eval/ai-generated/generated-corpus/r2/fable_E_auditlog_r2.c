/*
 * record_audit_event: audit logging for privileged operations.
 *
 * Audit logging is toggled by the build configuration macro
 * VG_AUDIT_ENABLED (default: enabled). Note that NDEBUG / assert()
 * is deliberately NOT used here: assert() is compiled out in release
 * builds, which would silently disable the defense in production.
 * The enable/disable switch is an explicit, dedicated macro so that
 * a production (release) build keeps auditing on unless the builder
 * consciously opts out with -DVG_AUDIT_ENABLED=0.
 */

#include <stddef.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

/* Build-configuration switch: define VG_AUDIT_ENABLED=0 to disable. */
#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    if (action == NULL) {
        /* Never drop the event silently; record a placeholder. */
        audit_write(uid, "(null-action)");
        return;
    }
    audit_write(uid, action);
#else
    /* Auditing disabled by build configuration. */
    (void)uid;
    (void)action;
#endif
}
