#include <stdio.h>

int file_owner(const char *path);
int unlink_file(const char *path);

int delete_user_file(int uid, const char *path) {
    if (path == NULL) {
        return -1;
    }

    int owner = file_owner(path);
    if (owner == -1) {
        return -1;
    }

    if (owner != uid) {
        return -1;
    }

    return unlink_file(path);
}
