#include <stddef.h>
#include <stdarg.h>
#include <string.h>

struct session;

void logf_line(const char *fmt, ...);

/*
 * Detailed dumps expose secret material (tokens, keys, raw buffers) and are
 * compiled in only when VG_DEBUG_DUMP_SECRETS is explicitly defined by the
 * build configuration. Production builds must never define it.
 */
#if defined(VG_DEBUG_DUMP_SECRETS) && defined(NDEBUG)
#error "VG_DEBUG_DUMP_SECRETS must not be enabled in a release (NDEBUG) build"
#endif

struct session {
    unsigned long id;
    int state;
    unsigned int flags;
    char user[64];
    char token[64];
    unsigned char key[32];
    size_t key_len;
};

#if defined(VG_DEBUG_DUMP_SECRETS)
static void dump_hex(const char *label, const unsigned char *buf, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    char line[3 * 32 + 1];
    size_t i;
    size_t n = len;

    if (buf == NULL || len == 0) {
        logf_line("  %s: (none)", label);
        return;
    }

    if (n > 32) {
        n = 32;
    }

    for (i = 0; i < n; i++) {
        line[3 * i + 0] = digits[(buf[i] >> 4) & 0x0f];
        line[3 * i + 1] = digits[buf[i] & 0x0f];
        line[3 * i + 2] = ' ';
    }
    line[3 * n] = '\0';

    logf_line("  %s (%lu bytes)%s: %s", label, (unsigned long)len,
              (len > n) ? " [truncated]" : "", line);
}
#endif /* VG_DEBUG_DUMP_SECRETS */

void dump_state(const struct session *s)
{
    if (s == NULL) {
        logf_line("session: (null)");
        return;
    }

    /* Always safe: non-sensitive identifiers only. */
    logf_line("session %lu: state=%d flags=0x%08x",
              (unsigned long)s->id, s->state, (unsigned int)s->flags);

#if defined(VG_DEBUG_DUMP_SECRETS)
    logf_line("  user: %.*s", (int)sizeof s->user, s->user);
    logf_line("  token: %.*s", (int)sizeof s->token, s->token);
    dump_hex("key", s->key, s->key_len);
#else
    logf_line("  user: %s", (s->user[0] != '\0') ? "<set>" : "<unset>");
    logf_line("  token: %s", (s->token[0] != '\0') ? "<redacted>" : "<unset>");
    logf_line("  key: %s", (s->key_len > 0) ? "<redacted>" : "<unset>");
#endif
}
