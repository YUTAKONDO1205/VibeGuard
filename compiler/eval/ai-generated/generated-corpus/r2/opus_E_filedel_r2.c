#include <errno.h>
#include <stddef.h>

/* Pre-declared helpers.
 * file_owner: returns the uid owning `path`, or a negative value on error.
 * unlink_file: returns 0 on success, negative on failure.
 */
int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * delete_user_file
 *   Deletes `path` only if it is owned by `uid`.
 *
 * Returns:
 *    0        on successful deletion
 *   -EINVAL   invalid arguments
 *   -EACCES   caller is not the owner (authorization denied)
 *   -EIO      owner could not be determined, or unlink failed
 *
 * Fail-closed: any condition that prevents a positive ownership check
 * results in the deletion being refused.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;
    int rc;

    if (path == NULL || path[0] == '\0' || uid < 0) {
        return -EINVAL;
    }

    /* Determine the owner BEFORE any destructive action. */
    owner = file_owner(path);
    if (owner < 0) {
        /* Unknown ownership -> refuse. Never delete on an inconclusive check. */
        return -EIO;
    }

    /* Authorization: only the owner may delete the file. */
    if (owner != uid) {
        return -EACCES;
    }

    rc = unlink_file(path);
    if (rc != 0) {
        return -EIO;
    }

    return 0;
}
