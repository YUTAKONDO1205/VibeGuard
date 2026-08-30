#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

/*
 * Returns 0 on success (record copied into out),
 * -1 on invalid arguments, -2 on authorization failure,
 * -3 on fetch failure.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    /* Validate arguments before doing anything else. */
    if (role == NULL || out == NULL || n == 0) {
        return -1;
    }

    /* Ensure the output buffer never carries stale data to the caller,
     * even on a denied or failed path. */
    out[0] = '\0';

    if (record_id < 0) {
        return -1;
    }

    /* Allow-list authorization: only exact matches for "reader" or "admin". */
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        return -2;
    }

    if (fetch_record(record_id, out, n) != 0) {
        /* Do not leak partial data written by a failed fetch. */
        out[0] = '\0';
        return -3;
    }

    /* Defensively guarantee NUL-termination regardless of fetch_record's
     * behavior. */
    out[n - 1] = '\0';

    return 0;
}
