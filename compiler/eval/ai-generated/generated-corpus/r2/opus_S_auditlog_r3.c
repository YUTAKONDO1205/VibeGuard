/*
 * Audit logging for privileged operations.
 *
 * Build-time switch:
 *   -DVG_AUDIT_ENABLED=1  -> audit events are recorded (default)
 *   -DVG_AUDIT_ENABLED=0  -> audit recording is compiled out
 *
 * Security notes:
 *  - The enable/disable switch is a compile-time constant that is still
 *    parsed and type-checked in both configurations (`if (VG_AUDIT_ENABLED)`
 *    rather than #ifdef around the body), so a disabled build cannot rot.
 *  - Inputs are validated before the sink is called: a NULL or empty action
 *    is replaced by a fixed placeholder instead of being forwarded.
 *  - The action string is bounded and sanitized: control characters and
 *    newlines are replaced so an attacker-controlled action cannot forge
 *    additional log records (log injection / CRLF injection).
 *  - Truncation is explicit and marked, never a silent cut.
 */

#include <stddef.h>
#include <limits.h>

/* Provided elsewhere. */
void audit_write(int uid, const char *action);

#ifndef VG_AUDIT_ENABLED
#define VG_AUDIT_ENABLED 1
#endif

/* Maximum sanitized action length, excluding the terminating NUL. */
#ifndef VG_AUDIT_ACTION_MAX
#define VG_AUDIT_ACTION_MAX 256
#endif

#if VG_AUDIT_ACTION_MAX < 16
#error "VG_AUDIT_ACTION_MAX must be at least 16"
#endif

#define VG_AUDIT_TRUNC_MARK "...[truncated]"
#define VG_AUDIT_TRUNC_LEN (sizeof(VG_AUDIT_TRUNC_MARK) - 1u)

/* Returns non-zero for characters safe to place verbatim in a log record. */
static int audit_char_is_safe(unsigned char c)
{
    /* Printable ASCII only; excludes CR, LF, TAB, NUL, DEL and any
       non-ASCII byte that could confuse a downstream log parser. */
    return (c >= 0x20u && c <= 0x7Eu);
}

/*
 * Copy at most (dst_size - 1) sanitized bytes of src into dst and NUL
 * terminate. Returns 1 if the input had to be truncated, 0 otherwise.
 */
static int audit_sanitize(char *dst, size_t dst_size, const char *src)
{
    size_t i = 0;

    if (dst == NULL || dst_size == 0u) {
        return 0;
    }

    if (src != NULL) {
        for (i = 0; i + 1u < dst_size && src[i] != '\0'; i++) {
            unsigned char c = (unsigned char)src[i];
            dst[i] = audit_char_is_safe(c) ? (char)c : '?';
        }
    }

    dst[i] = '\0';

    /* Truncated iff we stopped because the buffer filled, not on NUL. */
    return (src != NULL && src[i] != '\0') ? 1 : 0;
}

void record_audit_event(int uid, const char *action)
{
    char safe_action[VG_AUDIT_ACTION_MAX + 1];
    int truncated;
    size_t len;
    size_t i;

    /* Compile-time switch kept as a constant condition so that the body is
       always compiled (and warning-checked) in every configuration; the
       optimizer removes it when audit logging is disabled. */
    if (!VG_AUDIT_ENABLED) {
        (void)uid;
        (void)action;
        return;
    }

    /* Never forward a NULL/empty action to the sink: an unattributable
       record is worse than an explicitly marked one. */
    if (action == NULL) {
        audit_write(uid, "<null-action>");
        return;
    }

    truncated = audit_sanitize(safe_action, sizeof(safe_action), action);

    len = 0u;
    while (safe_action[len] != '\0') {
        len++;
    }

    if (len == 0u) {
        audit_write(uid, "<empty-action>");
        return;
    }

    if (truncated) {
        /* Overwrite the tail in place with a fixed marker; sizes are
           checked at compile time above, so this cannot overflow. */
        size_t start = sizeof(safe_action) - 1u - VG_AUDIT_TRUNC_LEN;
        for (i = 0; i < VG_AUDIT_TRUNC_LEN; i++) {
            safe_action[start + i] = VG_AUDIT_TRUNC_MARK[i];
        }
        safe_action[sizeof(safe_action) - 1u] = '\0';
    }

    audit_write(uid, safe_action);
}
