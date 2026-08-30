/*
 * record_audit_event: record an audit entry for a privileged operation.
 *
 * Build configuration:
 *   Audit logging is enabled by default. Define VG_AUDIT_DISABLE (or define
 *   VG_AUDIT_ENABLED to 0) at build time to compile the audit sink out.
 *
 * Security notes:
 *   - The enable/disable switch never removes the argument validation, and it
 *     never removes the call site: when logging is compiled out the function
 *     still exists with the same signature and still consumes its arguments,
 *     so a disabled build cannot change the caller's control flow or leave
 *     an unused-parameter warning that masks a real bug.
 *   - `action` is treated as untrusted input: it may be NULL, may be
 *     unterminated within the bound we accept, and may contain control
 *     characters or newlines that would let an attacker forge extra log
 *     lines (log injection). It is copied into a bounded, always
 *     NUL-terminated buffer and sanitized before it reaches the sink.
 *   - The sanitized copy is scrubbed before returning so that the audited
 *     action string does not linger on the stack.
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>

/* Declared elsewhere; provided by the audit backend. */
void audit_write(int uid, const char *action);

/* --- build-configuration switch ------------------------------------- */

#if !defined(VG_AUDIT_ENABLED)
#  if defined(VG_AUDIT_DISABLE)
#    define VG_AUDIT_ENABLED 0
#  else
#    define VG_AUDIT_ENABLED 1
#  endif
#endif

/* Maximum action text we are willing to forward, excluding the NUL. */
#ifndef VG_AUDIT_ACTION_MAX
#  define VG_AUDIT_ACTION_MAX 255
#endif

#if VG_AUDIT_ACTION_MAX < 1
#  error "VG_AUDIT_ACTION_MAX must be at least 1"
#endif

/* Placeholder used when the caller supplies no usable action string. */
#define VG_AUDIT_UNKNOWN_ACTION "<unspecified>"

/* --- helpers --------------------------------------------------------- */

/*
 * Overwrite a buffer without letting the optimizer discard the stores.
 * volatile-qualified pointer write is the portable freestanding-safe idiom;
 * memset() on a dead local is allowed to be elided.
 */
static void audit_scrub(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n-- > 0) {
        *q++ = 0;
    }
}

/*
 * Map one byte to a safe representation for a single-line log record.
 * Only printable ASCII survives; everything else (control characters,
 * CR/LF used for log forging, and high-bit bytes whose encoding we cannot
 * validate) becomes '.'. The mapping never changes the length, so the
 * bound checks in the caller remain valid.
 */
static char audit_sanitize_byte(unsigned char c)
{
    return (c >= 0x20u && c < 0x7Fu) ? (char)c : '.';
}

/* --- public entry point ---------------------------------------------- */

void record_audit_event(int uid, const char *action)
{
#if VG_AUDIT_ENABLED
    char safe[VG_AUDIT_ACTION_MAX + 1];
    size_t len = 0;

    if (action == NULL) {
        /* Fixed literal; length is known at compile time and fits. */
        memcpy(safe, VG_AUDIT_UNKNOWN_ACTION, sizeof(VG_AUDIT_UNKNOWN_ACTION));
        audit_write(uid, safe);
        audit_scrub(safe, sizeof(safe));
        return;
    }

    /*
     * Bounded copy: stop at the terminator or at the cap, whichever comes
     * first. strlen() is deliberately avoided so that a non-terminated
     * buffer cannot be walked past its end.
     */
    while (len < VG_AUDIT_ACTION_MAX && action[len] != '\0') {
        safe[len] = audit_sanitize_byte((unsigned char)action[len]);
        len++;
    }
    safe[len] = '\0';

    if (len == 0) {
        memcpy(safe, VG_AUDIT_UNKNOWN_ACTION, sizeof(VG_AUDIT_UNKNOWN_ACTION));
    }

    audit_write(uid, safe);

    audit_scrub(safe, sizeof(safe));
    len = 0;
    (void)len;
#else
    /*
     * Audit logging compiled out. Consume the parameters so the disabled
     * build type-checks identically and produces no warnings, but perform
     * no I/O and dereference nothing.
     */
    (void)uid;
    (void)action;
#endif
}
