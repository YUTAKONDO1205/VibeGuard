#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK              0
#define ACCESS_ERR_INVALID    -1
#define ACCESS_ERR_DENIED     -2
#define ACCESS_ERR_BACKEND    -3

/*
 * Constant-time-ish exact string comparison against a fixed literal.
 * Avoids strcmp early-exit timing differences and never reads past
 * the NUL of either side.
 */
static int role_equals(const char *role, const char *expected)
{
    size_t i = 0;
    unsigned char diff = 0;

    if (role == NULL || expected == NULL) {
        return 0;
    }

    /* Walk to the end of `expected`; fold in the terminator comparison so
       a shorter or longer `role` also produces a non-zero diff. */
    for (i = 0; expected[i] != '\0'; i++) {
        unsigned char a = (unsigned char)role[i];
        unsigned char b = (unsigned char)expected[i];
        diff |= (unsigned char)(a ^ b);
        if (a == '\0') {
            /* role ended early: mark mismatch, stop reading role. */
            diff |= 1u;
            return 0;
        }
    }
    /* role must also end here. */
    diff |= (unsigned char)((unsigned char)role[i] ^ 0u);

    return diff == 0;
}

static int role_is_allowed(const char *role)
{
    /* Allow-list only. No prefix matching, no case folding, no wildcards. */
    int ok_reader = role_equals(role, "reader");
    int ok_admin  = role_equals(role, "admin");
    return ok_reader | ok_admin;
}

int access_record(const char *role, int record_id, char *out, size_t n)
{
    int rc;

    /* Validate the output buffer before anything else. */
    if (out == NULL || n == 0) {
        return ACCESS_ERR_INVALID;
    }

    /* Always leave the buffer in a defined, empty, NUL-terminated state. */
    out[0] = '\0';

    if (role == NULL) {
        return ACCESS_ERR_INVALID;
    }

    if (record_id < 0) {
        return ACCESS_ERR_INVALID;
    }

    /* Authorization gate: deny by default. */
    if (!role_is_allowed(role)) {
        return ACCESS_ERR_DENIED;
    }

    rc = fetch_record(record_id, out, n);
    if (rc != 0) {
        /* Do not leak partial or stale backend data to the caller. */
        memset(out, 0, n);
        out[0] = '\0';
        return ACCESS_ERR_BACKEND;
    }

    /* Defensively guarantee NUL termination regardless of backend behavior. */
    out[n - 1] = '\0';

    return ACCESS_OK;
}
