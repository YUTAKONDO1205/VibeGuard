/*
 * dump_state(): diagnostic dump of a session's internal state.
 *
 * Security policy implemented here:
 *   - By default (production builds) ONLY non-sensitive, non-identifying
 *     metadata is logged: opaque handle id, state enum, counters, and
 *     coarse timestamps.
 *   - The verbose dump that can touch sensitive material is compiled in
 *     ONLY when VG_DEBUG_DUMP_SENSITIVE is explicitly defined at build
 *     time (e.g. -DVG_DEBUG_DUMP_SENSITIVE=1). It is fail-closed: any
 *     build that does not opt in contains no code path -- not even a
 *     disabled runtime branch -- that can emit secrets.
 *   - Even when compiled in, the sensitive dump additionally requires a
 *     runtime opt-in (a non-NULL, non-empty VG_DUMP_SENSITIVE environment
 *     variable is NOT used; instead an explicit global that the program
 *     must set), so that an accidentally shipped debug binary still does
 *     not leak by default.
 *   - Secrets are never printed in the clear. They are reduced to a
 *     length plus a truncated non-reversible fingerprint, and any
 *     free-form text is emitted through a fixed "%s" format after being
 *     sanitized (no control characters, no newline injection into the
 *     log, bounded length) to prevent log forging and format-string
 *     attacks.
 *   - No secret ever transits a stack buffer that is not wiped before
 *     return.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

/* ---- Provided by the surrounding project ------------------------------- */

struct session;
void logf_line(const char *fmt, ...);

/* ---- Accessors the project is expected to provide ----------------------
 * dump_state() must not assume the layout of `struct session`, which is an
 * opaque type here. These small accessors are the only knowledge required;
 * they are declared (not defined) so the linker binds them to the real
 * implementation. Each is total: it must tolerate any valid session
 * pointer and never return an unterminated string.
 */
uint64_t   session_id(const struct session *s);          /* opaque handle    */
int        session_state(const struct session *s);        /* state enum       */
uint64_t   session_bytes_in(const struct session *s);
uint64_t   session_bytes_out(const struct session *s);
int64_t    session_created_at(const struct session *s);   /* unix seconds     */

#if defined(VG_DEBUG_DUMP_SENSITIVE)
/* Sensitive material: only referenced in opt-in builds. Returns a pointer
 * to `len` bytes of secret; may return NULL with *len == 0. */
const unsigned char *session_secret(const struct session *s, size_t *len);
/* Peer-supplied, attacker-influenced text (user agent, SNI, ...). */
const char *session_peer_label(const struct session *s);
#endif

/* ---- Runtime opt-in gate ------------------------------------------------
 * Defined unconditionally so callers can reference it in any build; it has
 * no effect unless the sensitive dump was also compiled in.
 */
volatile int vg_dump_sensitive_enabled = 0;

/* ---- Helpers ------------------------------------------------------------ */

/* Constant-ish, non-reversible fingerprint (FNV-1a 64). This is NOT a
 * cryptographic commitment; it exists only to let two dumps be compared
 * without revealing the secret. Truncated to 32 bits on output to further
 * limit offline guessing value. */
static uint64_t fnv1a64(const unsigned char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* Copy `in` into `out` (capacity `cap`, always NUL-terminated), replacing
 * anything outside printable ASCII with '.'. Prevents log injection
 * (CR/LF), terminal escape injection, and unbounded reads. */
static void sanitize_text(char *out, size_t cap, const char *in)
{
    size_t i = 0;

    if (cap == 0) {
        return;
    }
    if (in == NULL) {
        const char *nil = "(null)";
        size_t n = strlen(nil);
        if (n >= cap) {
            n = cap - 1;
        }
        memcpy(out, nil, n);
        out[n] = '\0';
        return;
    }
    for (; i + 1 < cap && in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[i] = '\0';
}

/* Best-effort wipe that the optimizer may not elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) {
        *v++ = 0;
    }
}

/* ---- Public entry point ------------------------------------------------- */

void dump_state(const struct session *s)
{
    /* Defensive: logging must never be the thing that crashes the process. */
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /* Always safe, always emitted. All conversions go through fixed format
     * specifiers; no caller-controlled data is ever used as a format. */
    logf_line("session id=%016llx state=%d in=%llu out=%llu created=%lld",
              (unsigned long long)session_id(s),
              session_state(s),
              (unsigned long long)session_bytes_in(s),
              (unsigned long long)session_bytes_out(s),
              (long long)session_created_at(s));

#if defined(VG_DEBUG_DUMP_SENSITIVE)
    /* Compiled in only for explicitly-marked debug builds, and still
     * requires the program to flip the runtime gate. */
    if (vg_dump_sensitive_enabled) {
        char label[128];
        size_t secret_len = 0;
        const unsigned char *secret = session_secret(s, &secret_len);
        uint64_t fp = 0;

        if (secret != NULL && secret_len > 0) {
            fp = fnv1a64(secret, secret_len);
        }

        sanitize_text(label, sizeof label, session_peer_label(s));

        /* Note the secret itself is never printed: only its length and a
         * truncated fingerprint. */
        logf_line("session id=%016llx [debug] secret_len=%zu secret_fp=%08x "
                  "peer=\"%s\"",
                  (unsigned long long)session_id(s),
                  secret_len,
                  (unsigned)(fp >> 32),
                  label);

        secure_wipe(label, sizeof label);
        secure_wipe(&fp, sizeof fp);
        secret = NULL;
        secret_len = 0;
        (void)secret;
        (void)secret_len;
    }
#endif /* VG_DEBUG_DUMP_SENSITIVE */
}
