#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct session;
void logf_line(const char *fmt, ...);

/*
 * Accessors expected to be provided by the real session implementation.
 * Declared here only so this translation unit is self-contained; in the
 * actual codebase these would live in the session module's header and
 * would not expose raw secret material, only masked/derived views.
 */
size_t session_get_id(const struct session *s);
int session_get_state_code(const struct session *s);
size_t session_get_secret_len(const struct session *s);
/* Copies at most max bytes of the sensitive secret into out; returns the
 * number of bytes actually available (may be > max). Only compiled in
 * when VIBEGUARD_DEBUG_DUMP_SECRETS is enabled. */
size_t session_copy_secret(const struct session *s, unsigned char *out, size_t max);

/* Masks a secret buffer for safe logging: shows only length and a short
 * non-reversible fingerprint (first/last byte class), never raw bytes. */
static void mask_summary(const unsigned char *buf, size_t len, char *out, size_t out_sz)
{
    if (out_sz == 0) {
        return;
    }
    (void)buf;
    /* Minimal, dependency-free formatting to avoid pulling in stdio just
     * for this helper; only length is disclosed. */
    size_t pos = 0;
    const char *prefix = "len=";
    while (*prefix && pos + 1 < out_sz) {
        out[pos++] = *prefix++;
    }
    /* Convert len to decimal without stdio. */
    char digits[32];
    size_t dpos = 0;
    size_t v = len;
    if (v == 0) {
        digits[dpos++] = '0';
    } else {
        while (v > 0 && dpos < sizeof(digits)) {
            digits[dpos++] = (char)('0' + (v % 10));
            v /= 10;
        }
    }
    while (dpos > 0 && pos + 1 < out_sz) {
        out[pos++] = digits[--dpos];
    }
    out[pos] = '\0';
}

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("dump_state: session=NULL");
        return;
    }

    size_t id = session_get_id(s);
    int state_code = session_get_state_code(s);

    /* Always-safe summary: identifiers and state, never secret contents. */
    logf_line("session: id=%zu state=%d", id, state_code);

#if defined(VIBEGUARD_DEBUG_DUMP_SECRETS) && VIBEGUARD_DEBUG_DUMP_SECRETS
    /*
     * Detailed dump including sensitive material is opt-in only, intended
     * for local debug builds. Even then, raw secret bytes are never
     * written to the log; only a masked summary (length) is emitted, to
     * avoid leaking credentials/tokens into log files that may be
     * captured, shipped, or read by unauthorized parties.
     */
    size_t secret_len = session_get_secret_len(s);
    unsigned char secret_buf[256];
    size_t to_copy = secret_len < sizeof(secret_buf) ? secret_len : sizeof(secret_buf);
    size_t copied = session_copy_secret(s, secret_buf, to_copy);

    char summary[64];
    mask_summary(secret_buf, copied, summary, sizeof(summary));
    logf_line("session: secret=[REDACTED %s]", summary);

    /* Wipe the local copy immediately; it held sensitive data. */
    if (copied > 0) {
        volatile unsigned char *wipe = secret_buf;
        for (size_t i = 0; i < sizeof(secret_buf); i++) {
            wipe[i] = 0;
        }
    }
#else
    logf_line("session: secret=[hidden: debug dump disabled]");
#endif
}
