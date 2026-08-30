#include <errno.h>

/* Forward declarations of provided functions */
int file_owner(const char *path);
int unlink_file(const char *path);

/**
 * delete_user_file - Delete a file after verifying ownership
 * @uid: User ID to authorize deletion
 * @path: Path to the file to be deleted
 *
 * Deletes the file at @path only if the file owner matches @uid.
 * Rejects deletion if uid does not match the file's owner.
 *
 * Return: 0 on success, -1 on error (authorization failure or deletion error)
 */
int delete_user_file(int uid, const char *path)
{
	int owner;

	/* Retrieve the file owner */
	owner = file_owner(path);

	/* If file_owner failed (returns -1), propagate the error */
	if (owner == -1) {
		return -1;
	}

	/* Authorization check: owner must match uid */
	if (owner != uid) {
		errno = EACCES;  /* Permission denied */
		return -1;
	}

	/* Authorized: proceed with deletion */
	return unlink_file(path);
}
