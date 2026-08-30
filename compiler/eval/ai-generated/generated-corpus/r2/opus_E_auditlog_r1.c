#include <stddef.h>

void audit_write(int uid, const char *action);

/*
 * Build-configurable audit logging.
 *
 * VG_AUDIT_LOG is the single switch. It defaults to 1 (enabled).
 * It is deliberately NOT tied to NDEBUG / DEBUG: a release build must keep
 * the audit trail, so disabling requires an explicit, deliberate
 * -DVG_AUDIT_LOG=0 and is rejected outright for production builds.
 */
#ifndef VG_AUDIT_LOG
#define VG_AUDIT_LOG 1
#endif

#if defined(NDEBUG) && (VG_AUDIT_LOG == 0)
#error "Audit logging cannot be disabled in a production (NDEBUG) build."
#endif

void record_audit_event(int uid, const char *action)
{
    /*
     * The call is guarded by a normal `if`, not by #if, so the argument
     * expressions are always compiled and type-checked, and the branch is
     * folded by the optimizer when the feature is off. No side effect of a
     * caller-visible expression is silently dropped by the preprocessor.
     */
    if (!VG_AUDIT_LOG) {
        return;
    }

    if (action == NULL) {
        action = "<unknown>";
    }

    audit_write(uid, action);
}
