#include <errno.h>
#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a file on behalf of the user identified by uid.
 *
 * Returns 0 on success, -1 on failure (errno is set: EINVAL for a bad
 * argument, EACCES when the caller does not own the file, or whatever
 * the underlying helpers report).
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    errno = 0;
    owner = file_owner(path);
    if (owner < 0) {
        if (errno == 0) {
            errno = EIO;
        }
        return -1;
    }

    if (owner != uid) {
        errno = EACCES;
        return -1;
    }

    if (unlink_file(path) != 0) {
        if (errno == 0) {
            errno = EIO;
        }
        return -1;
    }

    return 0;
}
