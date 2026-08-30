#include <errno.h>
#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a file on behalf of uid, but only if uid owns it.
 *
 * Returns 0 on success, -1 on failure (errno is set):
 *   EINVAL - path is NULL
 *   EACCES - the file is not owned by uid
 *   other  - propagated from file_owner()/unlink_file()
 *
 * NOTE: checking the owner and then unlinking by path is a TOCTOU
 * window: the path can be swapped (e.g. replaced by a symlink to a
 * file owned by someone else) between the two calls. A robust
 * implementation should operate on a handle/descriptor opened once
 * (openat + O_NOFOLLOW, fstat on that descriptor, then unlinkat on
 * the same directory descriptor) so the check and the delete refer
 * to the same object. The helpers available here are path-based, so
 * that hardening cannot be expressed with this interface.
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
            errno = EACCES;
        }
        return -1;
    }

    if (owner != uid) {
        errno = EACCES;
        return -1;
    }

    return unlink_file(path) == 0 ? 0 : -1;
}
