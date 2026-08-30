#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Provided elsewhere. */
struct session;
void logf_line(const char *fmt, ...);

/* Accessors provided by the session module; struct session stays opaque here. */
const char *session_id(const struct session *s);            /* non-secret handle */
const char *session_user(const struct session *s);          /* login name */
const char *session_token(const struct session *s);         /* SECRET */
const char *session_peer(const struct session *s);          /* remote address */
unsigned    session_state(const struct session *s);
unsigned    session_flags(const struct session *s);

/*
 * Build configuration
 * -------------------
 * The verbose dump that includes secret material is opt-in only:
 * it requires VG_DEBUG_DUMP_SECRETS to be defined explicitly AND the build
 * to be a non-production build (NDEBUG undefined).  A production build can
 * therefore never be talked into emitting secrets by a stray -D on the
 * command line: the two conditions below are evaluated at compile time and
 * NDEBUG wins.
 *
 * Crucially, the *defenses* (redaction, NULL handling, bounded output) are
 * NOT inside any #ifdef.  They are unconditional code that every build
 * compiles and executes.  Only the extra, non-secret-free detail is
 * conditional; disabling it removes output, never protection.
 */
#if defined(VG_DEBUG_DUMP_SECRETS) && !defined(NDEBUG)
#define VG_DUMP_SECRETS_ENABLED 1
#else
#define VG_DUMP_SECRETS_ENABLED 0
#endif

#if defined(VG_DEBUG_DUMP_SECRETS) && defined(NDEBUG)
/* Loud, non-fatal signal that the flag was ignored on purpose. */
#if defined(__GNUC__) || defined(__clang__)
#warning "VG_DEBUG_DUMP_SECRETS ignored: secret dumping is disabled in NDEBUG builds"
#endif
#endif

#define VG_SAFE(p) ((p) ? (p) : "(null)")

/*
 * Unconditional redaction: never returns the secret itself.  Emits a shape
 * hint (length) and a short non-reversible fingerprint so that logs from any
 * build remain useful for correlation without carrying the value.
 */
static void vg_redact(const char *secret, char *out, size_t out_sz)
{
    size_t len;
    uint32_t h = 2166136261u; /* FNV-1a, 32-bit: fingerprint only, not a MAC */
    size_t i;
    static const char hex[] = "0123456789abcdef";

    if (out == NULL || out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (out_sz < 32) { /* refuse to emit a truncated, misleading marker */
        out[0] = '\0';
        return;
    }
    if (secret == NULL) {
        memcpy(out, "<absent>", sizeof("<absent>"));
        return;
    }

    len = strlen(secret);
    for (i = 0; i < len; i++) {
        h ^= (unsigned char)secret[i];
        h *= 16777619u;
    }

    /* "<redacted len=NNNN fp=xxxxxxxx>" */
    {
        char num[16];
        size_t n = 0, pos = 0, k;
        size_t v = len;

        do {
            num[n++] = (char)('0' + (int)(v % 10u));
            v /= 10u;
        } while (v != 0 && n < sizeof(num));

        memcpy(out + pos, "<redacted len=", 14); pos += 14;
        while (n > 0) {
            out[pos++] = num[--n];
        }
        memcpy(out + pos, " fp=", 4); pos += 4;
        for (k = 0; k < 8; k++) {
            out[pos++] = hex[(h >> (28 - 4 * k)) & 0xfu];
        }
        out[pos++] = '>';
        out[pos] = '\0';
    }
}

void dump_state(const struct session *s)
{
    char tok[48];

    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    /* Always-on summary: no secret ever reaches this path. */
    logf_line("session id=%s user=%s state=%u flags=0x%x",
              VG_SAFE(session_id(s)),
              VG_SAFE(session_user(s)),
              session_state(s),
              session_flags(s));

    /* Redaction runs in every build, including production. */
    vg_redact(session_token(s), tok, sizeof(tok));
    logf_line("session token=%s", tok[0] ? tok : "<redacted>");

#if VG_DUMP_SECRETS_ENABLED
    /* Extra detail for local debugging only; the lines above are unchanged. */
    logf_line("session peer=%s", VG_SAFE(session_peer(s)));
    logf_line("session token(plaintext)=%s", VG_SAFE(session_token(s)));
#else
    /* Reference the accessor so the disabled build stays warning-clean. */
    (void)session_peer;
    logf_line("session detail: disabled in this build");
#endif

    /* Do not leave the fingerprint buffer on the stack for a later reader. */
    memset(tok, 0, sizeof(tok));
    /* Defeat dead-store elimination of the wipe above. */
    {
        volatile char *vp = (volatile char *)tok;
        *vp = *vp;
    }
}
