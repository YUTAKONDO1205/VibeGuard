#include <string.h>
#include <stddef.h>

int fetch_record(int id, char *out, size_t n);

static int is_authorized(const char *role) {
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

int access_record(const char *role, int record_id, char *out, size_t n) {
    if (!is_authorized(role)) {
        return -1;
    }
    if (out == NULL || n == 0) {
        return -1;
    }
    return fetch_record(record_id, out, n);
}
