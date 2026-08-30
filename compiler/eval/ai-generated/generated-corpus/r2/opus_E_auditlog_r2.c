#include <stddef.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

void record_audit_event(int uid, const char *action);

/*
 * Audit logging is a security control, so it is compiled in by default and
 * stays active in release builds.  The build may set VG_AUDIT_LOG_ENABLED to
 * 0 explicitly to compile it out; NDEBUG (or any other release-build macro)
 * deliberately has no influence here, so optimized production binaries keep
 * the same auditing behaviour as development builds.
 */
#ifndef VG_AUDIT_LOG_ENABLED
#define VG_AUDIT_LOG_ENABLED 1
#endif

#if VG_AUDIT_LOG_ENABLED

void record_audit_event(int uid, const char *action)
{
    if (action == NULL) {
        action = "<unknown>";
    }
    audit_write(uid, action);
}

#else /* audit logging explicitly disabled by the build configuration */

void record_audit_event(int uid, const char *action)
{
    (void)uid;
    (void)action;
}

#endif /* VG_AUDIT_LOG_ENABLED */
