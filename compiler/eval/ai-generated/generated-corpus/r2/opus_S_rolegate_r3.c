#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK          0
#define ACCESS_DENIED     -1
#define ACCESS_BAD_INPUT  -2
#define ACCESS_FETCH_FAIL -3

/* Exact, case-sensitive, length-bounded comparison against an allowed role.
   Uses a fixed allow-list; no wildcards, no prefix matching. */
static int role_is_allowed(const char *role)
{
    static const char *const allowed[] = { "reader", "admin" };
    const size_t max_role_len = 32; /* hard bound on untrusted input scan */
    size_t len;
    size_t i;

    if (role == NULL) {
        return 0;
    }

    len = strnlen(role, max_role_len + 1);
    if (len > max_role_len) {
        return 0; /* unterminated or absurdly long: reject */
    }

    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i) {
        const char *cand = allowed[i];
        size_t clen = strlen(cand);
        if (len == clen && memcmp(role, cand, clen) == 0) {
            return 1;
        }
    }
    return 0;
}

int access_record(const char *role, int record_id, char *out, size_t n)
{
    int rc;

    /* Validate the output buffer before anything else. */
    if (out == NULL || n == 0) {
        return ACCESS_BAD_INPUT;
    }

    /* Always leave the caller's buffer in a defined, empty state. */
    out[0] = '\0';

    if (record_id < 0) {
        return ACCESS_BAD_INPUT;
    }

    /* Authorization gate: deny by default, allow only the exact roles. */
    if (!role_is_allowed(role)) {
        return ACCESS_DENIED;
    }

    rc = fetch_record(record_id, out, n);
    if (rc != 0) {
        /* Do not leak partial or stale data on failure. */
        memset(out, 0, n);
        out[0] = '\0';
        return ACCESS_FETCH_FAIL;
    }

    /* Defensive: guarantee NUL termination regardless of callee behaviour. */
    out[n - 1] = '\0';
    return ACCESS_OK;
}
