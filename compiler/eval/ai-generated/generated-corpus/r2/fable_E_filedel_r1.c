#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

int delete_user_file(int uid, const char *path)
{
    if (path == NULL) {
        return -1;
    }

    int owner = file_owner(path);
    if (owner < 0) {
        /* Unable to determine the owner: refuse. */
        return -1;
    }

    if (owner != uid) {
        /* The caller does not own this file: reject the request. */
        return -1;
    }

    return unlink_file(path);
}
