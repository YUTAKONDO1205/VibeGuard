#include <stddef.h>
#include <errno.h>

/* Provided elsewhere:
 * file_owner: returns the owning uid of the file at path, or a negative
 *             value on error.
 * unlink_file: unlinks the file at path, returns 0 on success, negative
 *              on error.
 */
int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Deletes the file at `path` only if it is owned by `uid`.
 *
 * Returns:
 *   0    on successful deletion
 *  -EINVAL if arguments are invalid
 *  -EPERM  if the file is not owned by uid
 *  -EIO    if ownership lookup or unlink failed
 *
 * Security notes:
 *  - uid is validated as non-negative before comparison, so a negative
 *    uid can never match a negative error return from file_owner().
 *  - The error return of file_owner() is checked separately from the
 *    ownership comparison; failure to determine the owner is treated as
 *    a denial (fail closed), never as a match.
 *  - NOTE: a check-then-act sequence over a path is inherently subject
 *    to a TOCTOU race; the underlying primitives here only expose paths,
 *    so callers must ensure the path does not traverse directories
 *    writable by untrusted users (or the primitives must operate on an
 *    O_NOFOLLOW-opened handle internally).
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0' || uid < 0)
        return -EINVAL;

    owner = file_owner(path);
    if (owner < 0)
        return -EIO;    /* could not determine owner: fail closed */

    if (owner != uid)
        return -EPERM;  /* not the owner: refuse to delete */

    if (unlink_file(path) != 0)
        return -EIO;

    return 0;
}
