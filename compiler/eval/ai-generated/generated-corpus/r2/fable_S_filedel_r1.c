#include <stddef.h>
#include <errno.h>

/* Provided elsewhere:
 *   file_owner(path)  - returns the owning uid of the file, or a negative
 *                       value on error.
 *   unlink_file(path) - removes the file, returns 0 on success, negative
 *                       on error.
 */
int file_owner(const char *path);
int unlink_file(const char *path);

/*
 * Deletes the file at `path` only if it is owned by `uid`.
 *
 * Returns:
 *    0  on successful deletion
 *   -1  on invalid argument
 *   -2  if the owner could not be determined
 *   -3  if the file is not owned by `uid` (permission denied)
 *   -4  if the unlink operation failed
 *
 * Note: with only the two primitives available there is an unavoidable
 * TOCTOU window between the ownership check and the unlink. In a real
 * system this should be done by opening the file (O_NOFOLLOW), using
 * fstat() on the descriptor, and unlinking via a directory descriptor
 * (unlinkat) so the checked object and the removed object are the same.
 * Here we at least fail closed on every error path.
 */
int delete_user_file(int uid, const char *path)
{
    int owner;

    if (path == NULL || path[0] == '\0' || uid < 0)
        return -1;

    owner = file_owner(path);
    if (owner < 0)
        return -2;   /* cannot determine owner: fail closed */

    if (owner != uid)
        return -3;   /* not the caller's file: refuse */

    if (unlink_file(path) != 0)
        return -4;

    return 0;
}
