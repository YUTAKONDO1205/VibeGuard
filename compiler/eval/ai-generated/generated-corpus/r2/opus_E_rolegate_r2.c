#include <stddef.h>
#include <string.h>
#include <errno.h>

int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK        0
#define ACCESS_DENIED  (-1)
#define ACCESS_EINVAL  (-2)

static int role_is_allowed(const char *role)
{
    static const char *const allowed[] = { "reader", "admin" };
    size_t i;

    if (role == NULL) {
        return 0;
    }
    for (i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strcmp(role, allowed[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int access_record(const char *role, int record_id, char *out, size_t n)
{
    if (out == NULL || n == 0) {
        return ACCESS_EINVAL;
    }

    /* Fail closed: nothing is written to the caller's buffer unless the
       role check passes. */
    out[0] = '\0';

    if (!role_is_allowed(role)) {
        return ACCESS_DENIED;
    }

    if (record_id < 0) {
        return ACCESS_EINVAL;
    }

    return fetch_record(record_id, out, n);
}
