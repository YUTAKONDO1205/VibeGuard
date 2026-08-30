#include <stddef.h>
#include <errno.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a file on behalf of uid, only if uid owns it.
 *
 * Returns 0 on success, -1 on failure (errno set):
 *   EINVAL - bad arguments
 *   EACCES - caller is not the owner
 *   other  - propagated from the helpers
 *
 * NOTE on TOCTOU: file_owner()/unlink_file() take paths, so the ownership
 * check and the unlink are two separate lookups; a symlink or directory
 * component swapped in between them can redirect the delete to another
 * file. A path-based interface cannot close that window. The robust form
 * is to resolve the parent directory once (open with O_DIRECTORY|O_NOFOLLOW),
 * fstatat(dirfd, name, ..., AT_SYMLINK_NOFOLLOW) to check the owner, then
 * unlinkat(dirfd, name, 0) against that same descriptor. Where the helpers
 * below are the only interface available, they must be implemented so that
 * they do not follow symlinks and operate on a stable directory handle.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    /* Reject missing or empty paths rather than passing them down. */
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    /* Negative uids are not valid principals; refuse instead of matching. */
    if (uid < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Fail closed: any error from the ownership lookup denies the delete. */
    errno = 0;
    owner = file_owner(path);
    if (owner < 0) {
        if (errno == 0) {
            errno = EACCES;
        }
        return -1;
    }

    /* Authorization: only the owner may delete. */
    if (owner != uid) {
        errno = EACCES;
        return -1;
    }

    if (unlink_file(path) != 0) {
        if (errno == 0) {
            errno = EACCES;
        }
        return -1;
    }

    return 0;
}
