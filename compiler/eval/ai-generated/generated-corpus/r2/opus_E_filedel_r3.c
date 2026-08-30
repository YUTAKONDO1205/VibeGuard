#include <errno.h>
#include <stddef.h>

int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Delete a file on behalf of uid.
 *
 * Returns 0 on success, -1 on failure with errno set:
 *   EINVAL - bad arguments
 *   EACCES - the caller does not own the file (authorization denied)
 *   other  - propagated from the deletion attempt
 *
 * Fail-closed: any condition that leaves ownership unproven results in
 * refusal, never in a deletion.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0' || uid < 0) {
        errno = EINVAL;
        return -1;
    }

    owner = file_owner(path);
    if (owner < 0) {
        /* Ownership could not be determined: refuse. */
        if (errno == 0) {
            errno = EACCES;
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
