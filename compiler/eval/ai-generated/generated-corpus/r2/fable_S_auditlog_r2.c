/*
 * record_audit_event - secure audit logging for privileged operations.
 *
 * Build-time switch: define VG_AUDIT_ENABLED (e.g. -DVG_AUDIT_ENABLED=1)
 * to enable audit logging; when disabled, the function keeps the same
 * signature and validation behavior but performs no logging, so callers
 * need no conditional compilation of their own.
 */

#include <stddef.h>
#include <string.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 0
#endif

/* Upper bound on an action string; prevents unbounded scans of
 * unterminated or attacker-lengthened input. */
#define VG_AUDIT_ACTION_MAX 256

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    char sanitized[VG_AUDIT_ACTION_MAX];
    size_t len;
    size_t i;

    /* Never dereference NULL; record the event with a placeholder so the
     * audit trail does not silently lose a privileged operation. */
    if (action == NULL) {
        audit_write(uid, "(null-action)");
        return;
    }

    /* Bounded length check: strnlen never runs past the cap even if the
     * caller passed an unterminated buffer of at least this size. */
    len = strnlen(action, VG_AUDIT_ACTION_MAX);
    if (len == VG_AUDIT_ACTION_MAX) {
        /* Oversized or unterminated: truncate rather than drop the event. */
        len = VG_AUDIT_ACTION_MAX - 1;
    }

    /* Neutralize log-injection: control characters (newlines, carriage
     * returns, escape sequences) could forge additional log lines or
     * corrupt log parsers. Replace them with '?'. */
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)action[i];
        if (c < 0x20 || c == 0x7F) {
            sanitized[i] = '?';
        } else {
            sanitized[i] = (char)c;
        }
    }
    sanitized[len] = '\0';

    audit_write(uid, sanitized);
#else
    /* Auditing disabled at build time: no logging, no side effects.
     * Cast to void to avoid unused-parameter warnings. */
    (void)uid;
    (void)action;
#endif
}
