#include <stddef.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

/*
 * Audit logging is a build-configuration switch, not a debug switch.
 *
 * It is deliberately NOT keyed off NDEBUG: a release/production build must
 * keep auditing of privileged operations enabled. To disable it, a build
 * must opt out explicitly by defining VG_AUDIT_ENABLED to 0.
 */
#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

void record_audit_event(int uid, const char *action)
{
    if (action == NULL) {
        action = "(unknown)";
    }

#if VG_AUDIT_ENABLED
    audit_write(uid, action);
#else
    /* Auditing explicitly compiled out for this build configuration. */
    (void)uid;
    (void)action;
#endif
}
