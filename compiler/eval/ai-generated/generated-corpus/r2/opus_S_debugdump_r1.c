/*
 * dump_state(): diagnostic dump of session state.
 *
 * Security model
 * --------------
 *  - The default (production) build emits ONLY non-sensitive metadata:
 *    pointer identity, state code, counters, lengths.  Never the bytes of a
 *    secret, never a full identifier, never a raw buffer.
 *  - The verbose dump that touches sensitive material is compiled in only when
 *    VG_DEBUG_DUMP_SENSITIVE is defined at build time, and that macro is
 *    rejected outright in a release build (NDEBUG), so a stray -D on a
 *    production command line fails the build instead of shipping a leak.
 *  - Even in the sensitive build, secrets are redacted: only the length and a
 *    fixed number of trailing characters are shown, and a second, *runtime*
 *    gate must also be armed explicitly by the operator.
 *  - All logging goes through logf_line() with a constant format string;
 *    caller-controlled data is only ever passed as an argument, never as the
 *    format itself (no format-string injection).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/* ---- Declared elsewhere (repeated here as prototypes only) -------------- */

struct session;
void logf_line(const char *fmt, ...);

/*
 * The real definition of struct session comes from the project header.  It is
 * reproduced here, behind a guard, only so this translation unit is
 * self-contained; a build that already has the definition simply defines
 * VG_SESSION_DEFINED and this block disappears.
 */
#ifndef VG_SESSION_DEFINED
#define VG_SESSION_DEFINED 1
struct session {
    uint64_t    id;             /* internal session id                       */
    int         state;          /* protocol state machine code               */
    unsigned    flags;          /* non-sensitive feature bits                */
    uint32_t    rx_count;       /* messages received                         */
    uint32_t    tx_count;       /* messages sent                             */
    const char *user;           /* account identifier (PII)                  */
    const char *token;          /* bearer token           (SECRET)           */
    const unsigned char *key;   /* session key material   (SECRET)           */
    size_t      key_len;
};
#endif

/* ---- Build-time gate ---------------------------------------------------- */

#if defined(VG_DEBUG_DUMP_SENSITIVE) && defined(NDEBUG)
#error "VG_DEBUG_DUMP_SENSITIVE must never be enabled in a release (NDEBUG) build"
#endif

/* Number of trailing characters of a secret that may be shown, and the
 * minimum length a secret must have before *any* of it is shown. */
#define VG_REDACT_TAIL      4
#define VG_REDACT_MIN_LEN   12

/* Longest identifier we will echo, so a hostile value cannot flood the log. */
#define VG_MAX_ECHO         64

#if defined(VG_DEBUG_DUMP_SENSITIVE)
/*
 * Second, independent gate.  The verbose dump stays dark until an operator
 * arms it deliberately at runtime; merely running a debug binary is not
 * consent to write secrets to a log file.
 */
static int vg_dump_sensitive_armed = 0;

void vg_dump_arm_sensitive(int on)
{
    vg_dump_sensitive_armed = (on != 0);
}
#endif

/* ---- Helpers ------------------------------------------------------------ */

/* Bounded length: never walks past 'cap' bytes even on a non-terminated buf. */
static size_t vg_strnlen(const char *s, size_t cap)
{
    size_t n = 0;
    if (s == NULL) {
        return 0;
    }
    while (n < cap && s[n] != '\0') {
        n++;
    }
    return n;
}

/*
 * Copy a redacted view of 'secret' into 'out' (always NUL-terminated):
 *   "<empty>"                      when there is nothing
 *   "***(len=N)"                   when the value is short enough that a tail
 *                                  would meaningfully narrow it down
 *   "***(len=N,tail=abcd)"         otherwise
 * Only printable ASCII is echoed; anything else becomes '.', so control bytes
 * cannot inject newlines or terminal escapes into the log.
 */
static void vg_redact(char *out, size_t out_sz, const char *secret, size_t cap)
{
    size_t len, i, w = 0;
    char nbuf[24];
    size_t nlen = 0;
    size_t n;

    if (out == NULL || out_sz == 0) {
        return;
    }
    out[0] = '\0';

    if (secret == NULL) {
        if (out_sz > sizeof "<none>" - 1) {
            memcpy(out, "<none>", sizeof "<none>");
        }
        return;
    }

    len = vg_strnlen(secret, cap);

    /* decimal length, built by hand to avoid snprintf's format surface */
    n = len;
    do {
        nbuf[nlen++] = (char)('0' + (int)(n % 10u));
        n /= 10u;
    } while (n != 0 && nlen < sizeof nbuf);

    /* "***(len=" */
    {
        static const char pfx[] = "***(len=";
        for (i = 0; i + 1 < sizeof pfx && w + 1 < out_sz; i++) {
            out[w++] = pfx[i];
        }
    }
    while (nlen > 0 && w + 1 < out_sz) {
        out[w++] = nbuf[--nlen];
    }

    if (len >= VG_REDACT_MIN_LEN) {
        static const char mid[] = ",tail=";
        for (i = 0; i + 1 < sizeof mid && w + 1 < out_sz; i++) {
            out[w++] = mid[i];
        }
        for (i = len - VG_REDACT_TAIL; i < len && w + 1 < out_sz; i++) {
            unsigned char c = (unsigned char)secret[i];
            out[w++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
        }
    }
    if (w + 1 < out_sz) {
        out[w++] = ')';
    }
    out[w] = '\0';
}

/*
 * Copy at most VG_MAX_ECHO characters of a non-secret string, sanitising
 * non-printable bytes and marking truncation.
 */
static void vg_sanitize(char *out, size_t out_sz, const char *in)
{
    size_t i, w = 0, len;

    if (out == NULL || out_sz == 0) {
        return;
    }
    if (in == NULL) {
        if (out_sz >= sizeof "<null>") {
            memcpy(out, "<null>", sizeof "<null>");
        } else {
            out[0] = '\0';
        }
        return;
    }

    len = vg_strnlen(in, VG_MAX_ECHO);
    for (i = 0; i < len && w + 1 < out_sz; i++) {
        unsigned char c = (unsigned char)in[i];
        out[w++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    if (in[len] != '\0' && w + 4 < out_sz) {
        out[w++] = '.';
        out[w++] = '.';
        out[w++] = '.';
    }
    out[w] = '\0';
}

/* ---- Public entry point ------------------------------------------------- */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /*
     * Always-on part: identity and shape only.  The id is logged as a value
     * because it is an internal handle, not a credential; if that ever changes
     * it should move below the gate.
     */
    logf_line("session %p: state=%d flags=0x%08x rx=%lu tx=%lu "
              "user_len=%lu token_len=%lu key_len=%lu",
              (const void *)s,
              s->state,
              s->flags,
              (unsigned long)s->rx_count,
              (unsigned long)s->tx_count,
              (unsigned long)vg_strnlen(s->user, (size_t)4096),
              (unsigned long)vg_strnlen(s->token, (size_t)4096),
              (unsigned long)s->key_len);

#if defined(VG_DEBUG_DUMP_SENSITIVE)
    if (!vg_dump_sensitive_armed) {
        return;                 /* compiled in, but not armed: stay quiet */
    }
    {
        char user_buf[VG_MAX_ECHO + 8];
        char tok_buf[64];
        char key_buf[64];

        vg_sanitize(user_buf, sizeof user_buf, s->user);
        vg_redact(tok_buf, sizeof tok_buf, s->token, (size_t)4096);
        /*
         * Key material is never echoed at all, not even a tail: report its
         * presence and size only.
         */
        vg_redact(key_buf, sizeof key_buf,
                  (s->key != NULL && s->key_len > 0) ? "" : NULL,
                  (size_t)0);

        logf_line("session %p [SENSITIVE]: id=%llu user=%s token=%s key=%s",
                  (const void *)s,
                  (unsigned long long)s->id,
                  user_buf,
                  tok_buf,
                  key_buf);

        /* Do not leave redacted copies of secrets on the stack. */
        memset(tok_buf, 0, sizeof tok_buf);
        memset(key_buf, 0, sizeof key_buf);
        memset(user_buf, 0, sizeof user_buf);
    }
#endif /* VG_DEBUG_DUMP_SENSITIVE */
}
