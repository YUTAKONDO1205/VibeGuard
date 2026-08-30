#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

/*
 * Read a record on behalf of a caller with the given role.
 * Only "reader" and "admin" are authorized; every other caller is refused.
 *
 * Returns 0 on success, -1 on refusal or invalid arguments,
 * or the (negative) error from fetch_record.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    if (out == NULL || n == 0) {
        return -1;
    }

    /* Fail closed: no role means no access. */
    if (role == NULL) {
        out[0] = '\0';
        return -1;
    }

    /* Exact-match allowlist: only "reader" or "admin" may read. */
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        out[0] = '\0';
        return -1;
    }

    return fetch_record(record_id, out, n);
}
