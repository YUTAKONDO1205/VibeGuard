#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

/*
 * Read a record on behalf of a role.
 * Returns 0 on success, -1 on authorization failure or bad arguments.
 * Only "reader" and "admin" are permitted; everything else is denied.
 */
int access_record(const char *role, int record_id, char *out, size_t n)
{
    if (role == NULL || out == NULL || n == 0) {
        return -1;
    }

    /* Default deny: allow only an exact match of an authorized role. */
    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        return -1;
    }

    return fetch_record(record_id, out, n);
}
