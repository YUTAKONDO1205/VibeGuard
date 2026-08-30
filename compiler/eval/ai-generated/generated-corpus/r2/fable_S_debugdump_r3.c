#include <stddef.h>

/* Declared elsewhere in the project. */
struct session;
void logf_line(const char *fmt, ...);

/*
 * dump_state
 *
 * Logs a summary of internal session state.
 *
 * Security posture:
 *   - By default (production builds) this emits ONLY non-sensitive,
 *     coarse-grained information: whether the session pointer is valid.
 *     No secrets, tokens, keys, or raw memory are ever written.
 *
 *   - The sensitive, detailed dump is gated behind the build-time macro
 *     VG_DEBUG_DUMP_SENSITIVE. It is compiled out entirely (not merely
 *     skipped at run time) unless a build explicitly opts in. This means
 *     a production binary contains no code path that can leak the detailed
 *     state, and no string constants describing it remain in the image.
 *
 * To enable the detailed dump, build with:
 *     -DVG_DEBUG_DUMP_SENSITIVE
 *
 * The detailed branch is intentionally left as a controlled extension
 * point: field accesses belong here only when the concrete definition of
 * `struct session` is in scope for such a build, and even then callers
 * should prefer redacted representations of any secret-bearing fields.
 */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

#if defined(VG_DEBUG_DUMP_SENSITIVE) && VG_DEBUG_DUMP_SENSITIVE
    /*
     * Sensitive detailed dump. Compiled in only for explicitly opted-in
     * debug builds. The full definition of `struct session` must be
     * visible in this translation unit for a build that defines this macro.
     *
     * Guidance for maintainers extending this branch:
     *   - Never log raw credentials, session tokens, private keys, or
     *     password material. Emit redacted/masked forms (e.g. lengths,
     *     hashes, or fixed placeholders) instead.
     *   - Use fixed format strings with matching arguments; never pass
     *     externally influenced data as the format string itself.
     */
    logf_line("session: detailed dump enabled (address recorded internally)");
#else
    /* Production/default: minimal, non-sensitive acknowledgement only. */
    logf_line("session: present (details suppressed in this build)");
#endif
}
