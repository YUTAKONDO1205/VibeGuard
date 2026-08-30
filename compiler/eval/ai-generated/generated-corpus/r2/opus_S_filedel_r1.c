#include <stddef.h>
#include <errno.h>

/* Provided elsewhere.
 * file_owner:  returns the uid owning the file at `path`, or -1 on error.
 * unlink_file: returns 0 on success, non-zero on failure.
 */
int file_owner(const char *path);
int unlink_file(const char *path);

#define DUF_OK             0
#define DUF_EINVAL        -1  /* bad arguments */
#define DUF_ESTAT         -2  /* could not determine the owner */
#define DUF_EPERM         -3  /* caller does not own the file */
#define DUF_EUNLINK       -4  /* unlink failed */

/*
 * Delete `path` on behalf of `uid`, but only if `uid` owns it.
 *
 * Security notes:
 *  - Fail closed: any error in determining ownership denies the delete.
 *  - The owner check is done exactly once and its result decides the
 *    delete; no second, differently-derived check is consulted.
 *  - `uid` must be a plausible uid; negative values are rejected rather
 *    than being allowed to compare equal to file_owner()'s -1 error
 *    return, which would otherwise turn a stat failure into a permit.
 *  - This function is inherently subject to a TOCTOU race: between
 *    file_owner() and unlink_file() the path may be re-pointed at
 *    another file (e.g. by replacing a directory component with a
 *    symlink). Only an fd/handle-based API (openat + O_NOFOLLOW,
 *    fstat, unlinkat on a directory fd) closes that race. Callers that
 *    operate on directories writable by other users must use such an
 *    API instead; the check below is the best available given the
 *    declared interface.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0') {
        return DUF_EINVAL;
    }
    if (uid < 0) {
        return DUF_EINVAL;
    }

    errno = 0;
    owner = file_owner(path);
    if (owner < 0) {
        /* Unknown owner => refuse. */
        return DUF_ESTAT;
    }

    if (owner != uid) {
        return DUF_EPERM;
    }

    if (unlink_file(path) != 0) {
        return DUF_EUNLINK;
    }

    return DUF_OK;
}
