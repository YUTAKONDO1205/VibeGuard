#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Build-time switch: define VG_ENABLE_SENSITIVE_DUMP to allow the
 * detailed, secret-bearing dump path to compile in. Left undefined
 * (the default) in production builds so no sensitive dump code is
 * even present in the binary. */
#ifndef VG_ENABLE_SENSITIVE_DUMP
#define VG_ENABLE_SENSITIVE_DUMP 0
#endif

struct session {
    uint64_t   session_id;
    char       username[64];
    char       auth_token[128];   /* secret material */
    char       remote_addr[46];   /* IPv4/IPv6 text form */
    time_t     created_at;
    time_t     last_seen_at;
    int        privilege_level;
    int        is_authenticated;
};

void logf_line(const char *fmt, ...);

/* Redact everything but a short, fixed-length prefix of a secret-ish
 * string so a partial value can never leak beyond a few characters,
 * regardless of the real length or contents of the field. */
static void redact_copy(const char *src, size_t src_cap,
                         char *dst, size_t dst_cap)
{
    size_t visible;
    size_t i;

    if (dst == NULL || dst_cap == 0) {
        return;
    }

    if (src == NULL || src_cap == 0) {
        dst[0] = '\0';
        return;
    }

    /* Show at most 4 leading characters, and never more than what
     * fits in the destination buffer minus the "...redacted" suffix
     * and the terminating NUL. */
    visible = 4;
    if (visible > dst_cap - 1) {
        visible = (dst_cap > 1) ? dst_cap - 1 : 0;
    }

    for (i = 0; i < visible && i < src_cap && src[i] != '\0'; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';

    if (i > 0) {
        /* Append a marker so it is obvious the value was truncated,
         * only if there is room left in the buffer. */
        const char *suffix = "...";
        size_t j = 0;
        while (suffix[j] != '\0' && (i + j + 1) < dst_cap) {
            dst[i + j] = suffix[j];
            j++;
        }
        dst[i + j] = '\0';
    }
}

/* Bound and NUL-terminate any fixed-size char array field before it
 * is ever handed to a "%s" conversion, in case the underlying buffer
 * was not itself guaranteed to be terminated. */
static void safe_bounded_copy(const char *src, size_t src_cap,
                               char *dst, size_t dst_cap)
{
    size_t n;

    if (dst == NULL || dst_cap == 0) {
        return;
    }
    if (src == NULL || src_cap == 0) {
        dst[0] = '\0';
        return;
    }

    n = 0;
    while (n < src_cap && n < dst_cap - 1 && src[n] != '\0') {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

/*
 * Log a session's internal state.
 *
 * A minimal, non-sensitive summary is always emitted: session id,
 * authentication flag, privilege level and timestamps. None of these
 * reveal credentials or personally identifying network/location
 * data.
 *
 * The verbose, potentially sensitive dump (username, remote address,
 * a redacted preview of the auth token) is compiled in only when
 * VG_ENABLE_SENSITIVE_DUMP is set to a nonzero value at build time,
 * so that release/production builds never contain the code path or
 * the format strings that could expose that data, even under a
 * runtime misconfiguration.
 *
 * All string fields are copied into fixed-size local buffers and
 * explicitly bounded/NUL-terminated before being passed to a "%s"
 * conversion, and the format string passed to logf_line is always a
 * compile-time string literal (never derived from session data), to
 * avoid format-string and buffer-overrun issues.
 */
void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session pointer is NULL");
        return;
    }

    logf_line("session: id=%llu authenticated=%d privilege=%d "
              "created_at=%lld last_seen_at=%lld",
              (unsigned long long)s->session_id,
              s->is_authenticated,
              s->privilege_level,
              (long long)s->created_at,
              (long long)s->last_seen_at);

#if VG_ENABLE_SENSITIVE_DUMP
    {
        char username[sizeof(s->username) + 1];
        char remote_addr[sizeof(s->remote_addr) + 1];
        char token_preview[16];

        safe_bounded_copy(s->username, sizeof(s->username),
                           username, sizeof(username));
        safe_bounded_copy(s->remote_addr, sizeof(s->remote_addr),
                           remote_addr, sizeof(remote_addr));
        redact_copy(s->auth_token, sizeof(s->auth_token),
                    token_preview, sizeof(token_preview));

        logf_line("session[sensitive]: username=%s remote_addr=%s "
                  "auth_token_preview=%s",
                  username, remote_addr, token_preview);
    }
#else
    logf_line("session[sensitive]: dump suppressed by build configuration");
#endif
}
