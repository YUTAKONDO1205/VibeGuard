/*
 * dump_state() - log the internal state of a session.
 *
 * Build configuration:
 *   The detailed dump may expose sensitive material (tokens, keys, raw
 *   buffers).  It is compiled in ONLY when SESSION_DEBUG_DUMP is defined
 *   at build time (e.g. -DSESSION_DEBUG_DUMP=1) AND NDEBUG is not set.
 *   Production builds therefore emit only a minimal, non-sensitive summary.
 */

#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

struct session;

void logf_line(const char *fmt, ...);

/* ---- build-time gate ------------------------------------------------- */

#if defined(SESSION_DEBUG_DUMP) && (SESSION_DEBUG_DUMP + 0) != 0 && !defined(NDEBUG)
#  define SESSION_DUMP_SENSITIVE 1
#else
#  define SESSION_DUMP_SENSITIVE 0
#endif

/*
 * The full definition of struct session is only needed by the sensitive
 * dump path.  Guarding it keeps production builds free of any code that
 * touches secret-bearing fields.
 */
#if SESSION_DUMP_SENSITIVE

struct session {
    uint64_t    id;
    int         state;
    int         authenticated;
    const char *user;
    const char *token;      /* sensitive */
    unsigned char key[32];  /* sensitive */
    size_t      key_len;
    size_t      bytes_in;
    size_t      bytes_out;
};

/* Render a byte buffer as lowercase hex into out (NUL-terminated).
   out must hold 2*len + 1 bytes; the buffer is truncated if it cannot. */
static void hexify(char *out, size_t out_size,
                   const unsigned char *buf, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i, o = 0;

    if (out == NULL || out_size == 0)
        return;

    for (i = 0; i < len && o + 2 < out_size; i++) {
        out[o++] = digits[(buf[i] >> 4) & 0x0f];
        out[o++] = digits[buf[i] & 0x0f];
    }
    out[o] = '\0';
}

#endif /* SESSION_DUMP_SENSITIVE */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

#if SESSION_DUMP_SENSITIVE
    {
        char keyhex[2 * sizeof s->key + 1];
        size_t key_len = s->key_len;

        if (key_len > sizeof s->key)
            key_len = sizeof s->key;

        hexify(keyhex, sizeof keyhex, s->key, key_len);

        logf_line("session %llu: state=%d auth=%s user=%s",
                  (unsigned long long)s->id,
                  s->state,
                  s->authenticated ? "yes" : "no",
                  s->user ? s->user : "(none)");
        logf_line("  io: in=%zu out=%zu", s->bytes_in, s->bytes_out);
        logf_line("  token=%s", s->token ? s->token : "(none)");
        logf_line("  key[%zu]=%s", key_len, keyhex);

        /* Do not leave secret material on the stack. */
        memset(keyhex, 0, sizeof keyhex);
        /* Defeat dead-store elimination of the wipe above. */
        __asm__ __volatile__("" : : "r"(keyhex) : "memory");
    }
#else
    /* Production build: no sensitive detail is compiled in at all. */
    logf_line("session %p: detailed dump disabled in this build",
              (const void *)s);
#endif
}
