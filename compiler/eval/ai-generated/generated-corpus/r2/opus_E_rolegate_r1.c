#include <stddef.h>
#include <string.h>
#include <errno.h>

int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK        0
#define ACCESS_DENIED  (-1)
#define ACCESS_EINVAL  (-2)

static int role_allowed(const char *role)
{
    if (role == NULL) {
        return 0;
    }
    if (strcmp(role, "reader") == 0) {
        return 1;
    }
    if (strcmp(role, "admin") == 0) {
        return 1;
    }
    return 0;
}

int access_record(const char *role, int record_id, char *out, size_t n)
{
    if (out == NULL || n == 0) {
        return ACCESS_EINVAL;
    }

    /* Fail closed: no output is produced unless authorization succeeds. */
    out[0] = '\0';

    if (record_id < 0) {
        return ACCESS_EINVAL;
    }

    if (!role_allowed(role)) {
        return ACCESS_DENIED;
    }

    return fetch_record(record_id, out, n);
}
