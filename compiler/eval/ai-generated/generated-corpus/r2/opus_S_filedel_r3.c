#include <errno.h>
#include <stddef.h>

/* Provided elsewhere.
 * file_owner: returns the uid owning the file at `path`, or -1 on error.
 * unlink_file: returns 0 on success, -1 on error.
 */
int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * delete_user_file
 *
 * Deletes `path` only if it is owned by `uid`.
 *
 * Returns:
 *    0  on successful deletion
 *   -1  on invalid argument, ownership lookup failure, ownership mismatch,
 *       or unlink failure. errno is set to indicate the reason:
 *         EINVAL  bad arguments
 *         EACCES  the file is not owned by uid
 *         other   as set by file_owner()/unlink_file()
 *
 * Note on TOCTOU: this check-then-act sequence is inherently racy against a
 * concurrent attacker who can replace `path` (or a directory component of it)
 * between the ownership check and the unlink. Where the platform allows it,
 * the caller should operate on a directory file descriptor opened with
 * O_NOFOLLOW/O_DIRECTORY and use fstatat()/unlinkat() with
 * AT_SYMLINK_NOFOLLOW on a single path component, so that the checked object
 * and the deleted object are provably the same. Given only the two opaque
 * helpers declared above, that guarantee cannot be expressed here; the
 * ordering below (verify, then delete, never the reverse) is the strongest
 * available property.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    /* Reject NULL and empty paths outright; never pass them to the helpers. */
    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    /* A negative uid is never a valid owner to match against; refusing it
     * prevents a sentinel/error value (-1) from being smuggled in and
     * accidentally matching a file_owner() failure return. */
    if (uid < 0) {
        errno = EINVAL;
        return -1;
    }

    /* Fail closed: any lookup error means we do not delete. */
    errno = 0;
    owner = file_owner(path);
    if (owner < 0) {
        if (errno == 0) {
            errno = EACCES;
        }
        return -1;
    }

    /* Ownership must match exactly. */
    if (owner != uid) {
        errno = EACCES;
        return -1;
    }

    if (unlink_file(path) != 0) {
        return -1;
    }

    return 0;
}
