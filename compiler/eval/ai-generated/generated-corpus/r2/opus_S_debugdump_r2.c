/*
 * dump_state() - log internal session state.
 *
 * Security design:
 *   - By default (production build) ONLY non-sensitive, non-identifying
 *     summary information is logged.
 *   - The detailed dump, which may touch secret-bearing fields, is compiled
 *     in ONLY when VG_DEBUG_DUMP_SECRETS is explicitly defined at build time
 *     (e.g. -DVG_DEBUG_DUMP_SECRETS=1). It is a hard compile-time switch, not
 *     a runtime flag, so the secret-printing code (and the secrets themselves)
 *     never exist in a release binary.
 *   - Guard against accidentally shipping the debug dump: it is refused when
 *     NDEBUG is defined, unless the developer additionally opts in with
 *     VG_DEBUG_DUMP_SECRETS_I_KNOW_THIS_IS_UNSAFE.
 *   - Even in the debug build, secrets are never printed verbatim: only a
 *     truncated, salt-free length + a masked prefix-free representation is
 *     emitted. Full key/token material is never written to the log.
 *   - All format strings are literals (no user data used as a format string),
 *     so this is not vulnerable to uncontrolled-format-string attacks.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Provided elsewhere. */
struct session;
void logf_line(const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* Build-configuration resolution                                      */
/* ------------------------------------------------------------------ */

#if defined(VG_DEBUG_DUMP_SECRETS) && (VG_DEBUG_DUMP_SECRETS + 0)
#  if defined(NDEBUG) && !defined(VG_DEBUG_DUMP_SECRETS_I_KNOW_THIS_IS_UNSAFE)
#    error "VG_DEBUG_DUMP_SECRETS must not be enabled in an NDEBUG (release) build."
#  endif
#  define VG_DETAILED_DUMP 1
#else
#  define VG_DETAILED_DUMP 0
#endif

/* ------------------------------------------------------------------ */
/* Session definition                                                  */
/* ------------------------------------------------------------------ */
/*
 * The concrete layout is needed to dump anything at all. In a real tree this
 * comes from the owning header; it is reproduced here so the file compiles
 * standalone.
 */
struct session {
    uint64_t      id;             /* opaque, non-guessable session handle   */
    int           state;          /* protocol state machine value           */
    int           authenticated;  /* 0/1                                    */
    uint32_t      peer_ipv4;      /* network peer address (sensitive-ish)   */
    char          user[64];       /* NUL-terminated account name (PII)      */
    unsigned char token[32];      /* SECRET: bearer/session token           */
    size_t        token_len;      /* valid bytes in token[]                 */
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/*
 * Constant-ish, allocation-free fingerprint of secret material.
 * FNV-1a truncated to 32 bits: enough to correlate two log lines, far too
 * little to recover the secret. Never log the secret itself.
 */
static uint32_t vg_fingerprint(const unsigned char *p, size_t n)
{
    uint32_t h = 2166136261u;
    size_t   i;

    if (p == NULL) {
        return 0u;
    }
    for (i = 0; i < n; i++) {
        h ^= (uint32_t)p[i];
        h *= 16777619u;
    }
    return h;
}

/*
 * Copy at most dst_sz-1 bytes of a possibly-unterminated fixed-size field and
 * always NUL-terminate. Also replaces control characters, so a hostile user
 * name cannot inject newlines / terminal escapes into the log.
 */
static void vg_sanitize(char *dst, size_t dst_sz,
                        const char *src, size_t src_sz)
{
    size_t i;
    size_t limit;

    if (dst == NULL || dst_sz == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }

    limit = dst_sz - 1;
    if (limit > src_sz) {
        limit = src_sz;
    }

    for (i = 0; i < limit && src[i] != '\0'; i++) {
        unsigned char c = (unsigned char)src[i];
        /* Printable ASCII only; everything else becomes '.'. */
        dst[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    dst[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /*
     * Always-on part: nothing here identifies a user or reveals secret
     * material. The session id is an opaque handle, logged truncated so that
     * a leaked log cannot be replayed as a session identifier.
     */
    logf_line("session %08lx: state=%d auth=%s",
              (unsigned long)(uint32_t)(s->id >> 32),
              s->state,
              s->authenticated ? "yes" : "no");

#if VG_DETAILED_DUMP
    {
        char     user_safe[sizeof s->user];
        size_t   tlen;
        uint32_t tfp;

        vg_sanitize(user_safe, sizeof user_safe, s->user, sizeof s->user);

        tlen = s->token_len;
        if (tlen > sizeof s->token) {
            tlen = sizeof s->token; /* defend against a corrupt length */
        }
        tfp = vg_fingerprint(s->token, tlen);

        logf_line("  peer=%u.%u.%u.%u user=\"%s\"",
                  (unsigned)((s->peer_ipv4 >> 24) & 0xffu),
                  (unsigned)((s->peer_ipv4 >> 16) & 0xffu),
                  (unsigned)((s->peer_ipv4 >> 8) & 0xffu),
                  (unsigned)(s->peer_ipv4 & 0xffu),
                  user_safe);

        /*
         * Token: length + fingerprint only. The bytes themselves are never
         * formatted, never copied to a buffer, and never reach the log.
         */
        logf_line("  token: len=%zu fp=%08x (contents withheld)", tlen, tfp);

        /* Scrub the stack copy of the (PII) user name before returning. */
        {
            volatile char *vp = (volatile char *)user_safe;
            size_t i;
            for (i = 0; i < sizeof user_safe; i++) {
                vp[i] = 0;
            }
        }
    }
#else
    /*
     * Release build: state the omission explicitly so an operator reading the
     * log knows detail exists but was deliberately not compiled in.
     */
    logf_line("  (detailed dump disabled at build time)");
#endif
}
