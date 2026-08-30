/*
 * record_audit_event - secure audit logging for privileged operations.
 *
 * Build configuration:
 *   Compile with -DVG_AUDIT_ENABLED=1 to enable audit logging (default),
 *   or -DVG_AUDIT_ENABLED=0 to compile it out entirely.
 */

#include <stddef.h>
#include <string.h>

/* Provided by the audit subsystem. */
void audit_write(int uid, const char *action);

#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

/* Maximum accepted length for an action string, excluding the terminator. */
#define AUDIT_ACTION_MAX 256u

#if VG_AUDIT_ENABLED

void record_audit_event(int uid, const char *action)
{
    char sanitized[AUDIT_ACTION_MAX + 1u];
    size_t len;
    size_t i;

    /* Never dereference a NULL action; log a placeholder instead of
     * silently dropping the event (audit trails must not lose records). */
    if (action == NULL) {
        audit_write(uid, "(null-action)");
        return;
    }

    /* Bounded length scan: refuse to walk past AUDIT_ACTION_MAX so an
     * unterminated buffer cannot cause an out-of-bounds read. */
    len = 0u;
    while (len < AUDIT_ACTION_MAX && action[len] != '\0') {
        len++;
    }

    /* Neutralize log-injection: replace control characters (including
     * '\n', '\r', ESC) so a caller-supplied string cannot forge extra
     * log lines or emit terminal escape sequences. */
    for (i = 0u; i < len; i++) {
        unsigned char c = (unsigned char)action[i];
        if (c < 0x20u || c == 0x7Fu) {
            sanitized[i] = '_';
        } else {
            sanitized[i] = (char)c;
        }
    }
    sanitized[len] = '\0';

    /* Mark truncation explicitly so a truncated entry cannot be
     * mistaken for a complete one. We never read action[len] here:
     * that byte lies outside the bounded scan and may be OOB. */
    if (len == AUDIT_ACTION_MAX) {
        /* Overwrite the tail with a truncation marker; buffer is large
         * enough by construction (AUDIT_ACTION_MAX >= sizeof marker). */
        static const char marker[] = "...(truncated)";
        memcpy(&sanitized[AUDIT_ACTION_MAX - (sizeof(marker) - 1u)],
               marker, sizeof(marker));
    }

    audit_write(uid, sanitized);
}

#else /* !VG_AUDIT_ENABLED */

void record_audit_event(int uid, const char *action)
{
    /* Auditing compiled out: explicitly discard arguments. */
    (void)uid;
    (void)action;
}

#endif /* VG_AUDIT_ENABLED */
