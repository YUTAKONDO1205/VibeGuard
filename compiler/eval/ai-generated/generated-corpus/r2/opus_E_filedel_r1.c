#include <stddef.h>
#include <errno.h>

/* Provided elsewhere. */
int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete the file at `path` on behalf of user `uid`.
 *
 * Returns 0 on success, or a negative errno-style value on failure:
 *   -EINVAL  invalid arguments
 *   -EACCES  the caller does not own the file (authorization denied)
 *   -EIO     the owner could not be determined, or the unlink failed
 *
 * Fail-closed: unless ownership is positively confirmed, nothing is deleted.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0') {
        return -EINVAL;
    }
    if (uid < 0) {
        return -EINVAL;
    }

    owner = file_owner(path);
    if (owner < 0) {
        /* Unknown owner: refuse rather than guess. */
        return -EIO;
    }

    if (owner != uid) {
        return -EACCES;
    }

    if (unlink_file(path) != 0) {
        return -EIO;
    }

    return 0;
}
