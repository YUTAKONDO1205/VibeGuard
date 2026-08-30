#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a user's file only if the caller (uid) owns it.
 * Returns 0 on success, -1 on failure or authorization denial.
 */
int delete_user_file(int uid, const char *path)
{
    if (path == NULL) {
        return -1;
    }

    int owner = file_owner(path);
    if (owner < 0) {
        /* Could not determine owner: fail closed. */
        return -1;
    }

    if (owner != uid) {
        /* Caller is not the owner: refuse. */
        return -1;
    }

    return unlink_file(path) == 0 ? 0 : -1;
}
