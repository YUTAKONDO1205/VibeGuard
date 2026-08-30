/*
 * dump_state(): log internal session state.
 *
 * Design rule: the *defence* (redaction of secret material) is unconditional.
 * Only the extra, non-secret verbosity is build-configurable.  A production
 * build must never be able to turn redaction off, so the sensitive dump is
 * gated on an explicit opt-in macro (VG_ALLOW_SENSITIVE_DUMP) that is
 * additionally refused whenever the build is a release build (NDEBUG defined).
 * Missing/undefined macros therefore fail closed.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct session;

void logf_line(const char *fmt, ...);

/* ------------------------------------------------------------------ */
/* Build configuration: fail closed.                                   */
/* ------------------------------------------------------------------ */

/* Verbose (non-secret) diagnostics: opt-in, allowed in any build. */
#if defined(VG_VERBOSE_DUMP) && (VG_VERBOSE_DUMP + 0)
#define VG_DUMP_VERBOSE 1
#else
#define VG_DUMP_VERBOSE 0
#endif

/*
 * Sensitive detail dump: opt-in AND forbidden in release builds.
 * NDEBUG is defined by production/release builds, so this collapses to 0
 * there even if someone passes -DVG_ALLOW_SENSITIVE_DUMP=1 by accident.
 */
#if defined(VG_ALLOW_SENSITIVE_DUMP) && (VG_ALLOW_SENSITIVE_DUMP + 0) && !defined(NDEBUG)
#define VG_DUMP_SENSITIVE 1
#else
#define VG_DUMP_SENSITIVE 0
#endif

/* ------------------------------------------------------------------ */
/* Session accessors.                                                  */
/*                                                                     */
/* struct session is opaque here, so the fields are reached through    */
/* accessors provided by the module that owns the definition.  They    */
/* are declared, not defined, in this translation unit.                */
/* ------------------------------------------------------------------ */

unsigned long session_id(const struct session *s);
int           session_state(const struct session *s);
size_t        session_bytes_in(const struct session *s);
size_t        session_bytes_out(const struct session *s);
const char   *session_peer(const struct session *s);          /* may be NULL */
const char   *session_user(const struct session *s);          /* may be NULL */
/* Secret material: session key/token.  Never logged verbatim. */
const uint8_t *session_key(const struct session *s, size_t *len);

/* ------------------------------------------------------------------ */
/* Redaction helpers (always compiled in).                             */
/* ------------------------------------------------------------------ */

#define VG_KEY_FINGERPRINT_BYTES 4

/*
 * Non-reversible-enough summary of secret material: length plus a short
 * FNV-1a fingerprint.  This is what gets logged instead of the secret, in
 * every build configuration.  It lets an operator tell two keys apart
 * without disclosing either.
 */
static void vg_fingerprint(const uint8_t *buf, size_t len,
                           char out[VG_KEY_FINGERPRINT_BYTES * 2 + 1])
{
    static const char hex[] = "0123456789abcdef";
    uint32_t h = 2166136261u;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= (uint32_t)buf[i];
        h *= 16777619u;
    }

    for (i = 0; i < VG_KEY_FINGERPRINT_BYTES; i++) {
        unsigned b = (unsigned)((h >> (8 * (VG_KEY_FINGERPRINT_BYTES - 1 - i))) & 0xffu);
        out[i * 2]     = hex[(b >> 4) & 0xf];
        out[i * 2 + 1] = hex[b & 0xf];
    }
    out[VG_KEY_FINGERPRINT_BYTES * 2] = '\0';
}

/* Truncating, NUL-safe view of a possibly-NULL string, for identifiers
 * that are not secret but should not be able to flood the log. */
#define VG_STR_MAX 64

static void vg_safe_str(const char *in, char out[VG_STR_MAX + 1])
{
    size_t i;

    if (in == NULL) {
        memcpy(out, "(null)", sizeof("(null)"));
        return;
    }
    for (i = 0; i < VG_STR_MAX && in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        /* Keep control characters and newlines out of the log stream so a
         * peer-controlled string cannot forge extra log lines. */
        out[i] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
    }
    out[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

void dump_state(const struct session *s)
{
    char peer[VG_STR_MAX + 1];
    char user[VG_STR_MAX + 1];
    char fp[VG_KEY_FINGERPRINT_BYTES * 2 + 1];
    const uint8_t *key;
    size_t key_len = 0;

    if (s == NULL) {
        logf_line("session: <null>");
        return;
    }

    vg_safe_str(session_peer(s), peer);
    vg_safe_str(session_user(s), user);

    /* Baseline summary: no secret material, logged in every build. */
    logf_line("session %lu: state=%d peer=%s user=%s in=%zu out=%zu",
              session_id(s),
              session_state(s),
              peer,
              user,
              session_bytes_in(s),
              session_bytes_out(s));

    /* Key material: redacted unconditionally.  There is no build in which
     * this branch prints the key itself. */
    key = session_key(s, &key_len);
    if (key == NULL || key_len == 0) {
        logf_line("session %lu: key=<absent>", session_id(s));
    } else {
        vg_fingerprint(key, key_len, fp);
        logf_line("session %lu: key=<redacted len=%zu fp=%s>",
                  session_id(s), key_len, fp);
    }

#if VG_DUMP_VERBOSE
    /* Extra non-secret detail; build-configurable verbosity. */
    logf_line("session %lu: detail id=%p", session_id(s), (const void *)s);
#endif

#if VG_DUMP_SENSITIVE
    /*
     * Developer-only detail dump.  Compiled out entirely in release builds
     * (see the NDEBUG guard above), so no runtime flag can re-enable it in
     * production and no secret bytes exist in the shipped binary's paths.
     * Even here the raw key is not printed byte-for-byte; only a longer
     * prefix fingerprint is exposed.
     */
    logf_line("session %lu: [debug] verbose dump enabled; key_len=%zu fp=%s",
              session_id(s), key_len, (key_len ? fp : "-"));
#endif

    /* Do not leave copies of derived secret-adjacent data on the stack. */
    memset(fp, 0, sizeof(fp));
    memset(peer, 0, sizeof(peer));
    memset(user, 0, sizeof(user));
}
