#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

/*
 * Read a record subject to role-based access control.
 *
 * Returns 0 on success, -1 on failure (bad arguments, access denied,
 * or fetch failure). On any failure the output buffer, if usable,
 * is left as an empty string so no stale data leaks to the caller.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    /* Validate output buffer first so we can always leave it in a
       defined state. */
    if (out == NULL || n == 0) {
        return -1;
    }
    out[0] = '\0';

    if (role == NULL) {
        return -1;
    }

    /* Allowlist check: exact match only. strcmp on the caller-supplied
       role is safe because we compare against fixed literals and stop
       at the first NUL; no allocation or copying of the input occurs. */
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        return -1; /* deny by default */
    }

    if (fetch_record(record_id, out, n) != 0) {
        /* Do not expose partially written data on failure. */
        out[0] = '\0';
        return -1;
    }

    /* Defensively ensure NUL termination even if fetch_record
       misbehaves. */
    out[n - 1] = '\0';
    return 0;
}
