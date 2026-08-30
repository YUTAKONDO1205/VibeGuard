#include <stddef.h>
#include <string.h>
#include <errno.h>

/* Provided elsewhere. */
int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK          0
#define ACCESS_EINVAL    (-1)
#define ACCESS_EDENIED   (-2)
#define ACCESS_EFETCH    (-3)

/*
 * Constant-time-ish exact comparison against a fixed literal role name.
 * Uses a bounded length so an unterminated or overlong role string can never
 * be walked past the allowed limit.
 */
#define ROLE_MAX 32

static int role_equals(const char *role, size_t role_len, const char *literal)
{
    size_t lit_len = strlen(literal);
    if (role_len != lit_len) {
        return 0;
    }
    return memcmp(role, literal, lit_len) == 0;
}

/*
 * Read a record on behalf of a role.
 *
 * Allow-list: only the exact roles "reader" and "admin" may read. Anything
 * else -- including NULL, empty, mixed case, whitespace-padded, or overlong
 * role strings -- is denied. There is no wildcard, prefix, or substring match.
 *
 * On any failure the output buffer is left as an empty C string (when there is
 * room for one) so a caller that ignores the return value cannot read stale or
 * partially fetched record data.
 *
 * Returns ACCESS_OK on success, or a negative ACCESS_* code on failure.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    size_t role_len;
    int rc;

    /* Validate the output buffer first so every later path can safely clear it. */
    if (out == NULL || n == 0) {
        return ACCESS_EINVAL;
    }
    out[0] = '\0';

    if (role == NULL) {
        return ACCESS_EINVAL;
    }

    /* Bounded length: never scan past ROLE_MAX bytes. */
    role_len = strnlen(role, ROLE_MAX);
    if (role_len == 0 || role_len == ROLE_MAX) {
        /* Empty, or missing terminator within the allowed length. */
        return ACCESS_EDENIED;
    }

    if (record_id < 0) {
        return ACCESS_EINVAL;
    }

    /* Deny by default; grant only on an exact allow-list hit. */
    if (!role_equals(role, role_len, "reader") &&
        !role_equals(role, role_len, "admin")) {
        return ACCESS_EDENIED;
    }

    rc = fetch_record(record_id, out, n);
    if (rc != 0) {
        /* Do not expose whatever fetch_record may have left behind. */
        memset(out, 0, n);
        return ACCESS_EFETCH;
    }

    /* Defensively guarantee NUL termination regardless of callee behaviour. */
    out[n - 1] = '\0';
    return ACCESS_OK;
}
