/*
 * dump_state - log internal session state.
 *
 * Sensitive detail dumping is compile-time gated: build with
 * -DVG_DEBUG_DUMP=1 to enable the detailed (secret-bearing) dump.
 * Release builds (default) log only non-sensitive metadata.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Provided elsewhere. */
void logf_line(const char *fmt, ...);

#ifndef VG_DEBUG_DUMP
#define VG_DEBUG_DUMP 0
#endif

/*
 * The session layout is assumed to be defined in the project's header.
 * A representative definition is given here so the file is self-contained;
 * in the real build this comes from the session header.
 */
struct session {
    uint64_t      id;            /* non-sensitive session identifier */
    const char   *user;          /* username (PII-lite; logged redacted) */
    unsigned      state;         /* protocol state machine value */
    unsigned long requests;      /* request counter */
    char          token[64];     /* SECRET: bearer/authn token */
    unsigned char key[32];       /* SECRET: symmetric key material */
};

/*
 * Redact a string: keep at most the first `keep` characters, then "...".
 * Writes into caller buffer; always NUL-terminates. Never copies secrets.
 */
static void redact_str(const char *src, size_t keep, char *dst, size_t dstlen)
{
    size_t i = 0;

    if (dst == NULL || dstlen == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    while (i < keep && i + 4 < dstlen && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    if (src[i] != '\0' && i + 4 < dstlen) {
        dst[i++] = '.';
        dst[i++] = '.';
        dst[i++] = '.';
    }
    dst[i] = '\0';
}

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

    /* Non-sensitive summary: always available. Field values are passed as
     * arguments, never spliced into the format string, so untrusted data
     * cannot introduce format-string vulnerabilities. */
    {
        char user_red[16];

        redact_str(s->user, 2, user_red, sizeof(user_red));
        logf_line("session id=%llu user=%s state=%u requests=%lu",
                  (unsigned long long)s->id, user_red,
                  s->state, s->requests);
    }

#if VG_DEBUG_DUMP
    /* Detailed dump: DEBUG BUILDS ONLY. Even here, raw secrets are not
     * written to the log. We log lengths and a short prefix so a debug
     * log leak does not hand out usable credentials. */
    {
        char token_local[sizeof(s->token)];
        char token_red[12];
        size_t token_len;
        size_t key_nonzero = 0;
        size_t i;

        /* Bound the copy; the token field may lack a terminator. */
        memcpy(token_local, s->token, sizeof(token_local));
        token_local[sizeof(token_local) - 1] = '\0';
        token_len = strlen(token_local);

        redact_str(token_local, 4, token_red, sizeof(token_red));

        for (i = 0; i < sizeof(s->key); i++) {
            if (s->key[i] != 0) {
                key_nonzero++;
            }
        }

        logf_line("session[debug] token_len=%zu token_prefix=%s "
                  "key_set=%s key_nonzero_bytes=%zu",
                  token_len, token_red,
                  (key_nonzero != 0) ? "yes" : "no", key_nonzero);

        /* Scrub the stack copy of the token; volatile pointer prevents
         * the compiler from eliding the wipe as a dead store. */
        {
            volatile unsigned char *p = (volatile unsigned char *)token_local;
            for (i = 0; i < sizeof(token_local); i++) {
                p[i] = 0;
            }
        }
    }
#endif /* VG_DEBUG_DUMP */
}
