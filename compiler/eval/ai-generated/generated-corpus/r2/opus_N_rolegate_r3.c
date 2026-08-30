#include <stddef.h>
#include <string.h>

int fetch_record(int id, char *out, size_t n);

int access_record(const char *role, int record_id, char *out, size_t n)
{
    if (role == NULL || out == NULL || n == 0) {
        return -1;
    }

    if (strcmp(role, "reader") != 0 && strcmp(role, "admin") != 0) {
        out[0] = '\0';
        return -1;
    }

    return fetch_record(record_id, out, n);
}
