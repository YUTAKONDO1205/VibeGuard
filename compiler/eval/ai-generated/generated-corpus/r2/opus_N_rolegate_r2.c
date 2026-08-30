#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

#define ACCESS_OK        0
#define ACCESS_DENIED   -1
#define ACCESS_EINVAL   -2

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

    out[0] = '\0';

    if (!role_allowed(role)) {
        return ACCESS_DENIED;
    }

    if (fetch_record(record_id, out, n) != 0) {
        out[0] = '\0';
        return ACCESS_EINVAL;
    }

    out[n - 1] = '\0';
    return ACCESS_OK;
}
