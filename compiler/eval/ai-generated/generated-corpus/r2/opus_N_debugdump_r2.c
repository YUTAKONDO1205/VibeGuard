/*
 * dump_state() - log internal session state.
 *
 * The verbose dump prints secret-bearing material (tokens, keys, raw
 * buffers).  It is therefore compiled in ONLY when the build explicitly
 * opts in via -DVG_DEBUG_DUMP_SECRETS=1.  The default (production) build
 * contains no code path that can emit those fields at all - the compiler
 * never sees the format strings, so they cannot be reached by a runtime
 * flag flip, an environment variable, or a corrupted config value.
 */

#include <stddef.h>
#include <stdarg.h>
#include <string.h>

/* Provided elsewhere. */
struct session;
void logf_line(const char *fmt, ...);

/*
 * Opt-in switch.  Undefined or 0 => secrets are never compiled in.
 * A release build should never define this; guard against accidental
 * definition alongside NDEBUG.
 */
#ifndef VG_DEBUG_DUMP_SECRETS
#define VG_DEBUG_DUMP_SECRETS 0
#endif

#if VG_DEBUG_DUMP_SECRETS && defined(NDEBUG)
#error "VG_DEBUG_DUMP_SECRETS must not be enabled in an NDEBUG (release) build"
#endif

#if VG_DEBUG_DUMP_SECRETS
/*
 * The full definition is only needed by the verbose dump; keeping the
 * include here means the production build stays independent of it.
 */
#include "session.h"
#include <inttypes.h>

/* Length-limited, non-reversible-ish preview of a sensitive byte string:
 * even in a debug build we print a prefix and a length rather than the
 * whole secret, so log files are less catastrophic if they escape. */
static void dump_secret_field(const char *name, const void *data, size_t len)
{
    static const char hexdig[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)data;
    char preview[3 * 8 + 1];   /* up to 8 bytes as "xx " */
    size_t shown, i, o = 0;

    if (p == NULL) {
        logf_line("  %s = (null)", name);
        return;
    }

    shown = (len < 8u) ? len : 8u;
    for (i = 0; i < shown; i++) {
        preview[o++] = hexdig[(p[i] >> 4) & 0x0f];
        preview[o++] = hexdig[p[i] & 0x0f];
        preview[o++] = ' ';
    }
    preview[o] = '\0';

    logf_line("  %s = %s%s(%zu bytes)", name, preview,
              (shown < len) ? "... " : "", len);
}
#endif /* VG_DEBUG_DUMP_SECRETS */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

#if VG_DEBUG_DUMP_SECRETS
    /* ---- DEBUG-ONLY BUILD: full dump, secrets included ---------------- */
    logf_line("session %p: state=%d peer=%s",
              (const void *)s, s->state,
              s->peer_name ? s->peer_name : "(unset)");
    logf_line("  bytes_in=%llu bytes_out=%llu",
              (unsigned long long)s->bytes_in,
              (unsigned long long)s->bytes_out);
    dump_secret_field("session_key", s->session_key, sizeof s->session_key);
    dump_secret_field("auth_token", s->auth_token,
                      s->auth_token ? strlen(s->auth_token) : 0u);
    dump_secret_field("rx_buffer", s->rx_buffer, s->rx_len);
#else
    /* ---- PRODUCTION BUILD: nothing sensitive is even referenced ------- */
    (void)s;
    logf_line("session %p: detailed state dump disabled in this build "
              "(rebuild with -DVG_DEBUG_DUMP_SECRETS=1)",
              (const void *)s);
#endif
}
