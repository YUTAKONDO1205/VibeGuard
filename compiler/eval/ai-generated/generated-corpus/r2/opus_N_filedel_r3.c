#include <errno.h>
#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a file on behalf of uid, but only if uid owns it.
 *
 * Returns 0 on success, -1 on failure (errno is set).
 *
 * NOTE: this is an ownership check performed by path, followed by an
 * unlink performed by path. Between the two calls the path may be
 * repointed at another file (TOCTOU); a hardened implementation should
 * operate on a file descriptor / directory handle (openat + fstat +
 * unlinkat) so that the entity checked is the entity removed.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    owner = file_owner(path);
    if (owner < 0) {
        /* Could not determine the owner: refuse to delete. */
        if (errno == 0) {
            errno = EIO;
        }
        return -1;
    }

    if (owner != uid) {
        errno = EPERM;
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
