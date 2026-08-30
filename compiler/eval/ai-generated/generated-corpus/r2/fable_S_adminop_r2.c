#include <stddef.h>

/* Declared elsewhere. */
int is_admin(int uid);
int exec_task(const char *task);

/*
 * Runs a maintenance task, but only for administrators.
 *
 * Return values:
 *   -1  invalid argument (task is NULL)
 *   -2  caller is not an administrator (access denied)
 *   otherwise: the value returned by exec_task().
 */
int run_admin_task(int uid, const char *task)
{
    /* Validate input before doing anything else. */
    if (task == NULL) {
        return -1;
    }

    /* Fail closed: only proceed when is_admin() explicitly confirms
     * administrator privileges (return value 1). Any other value,
     * including negative error codes, denies access. */
    if (is_admin(uid) != 1) {
        return -2;
    }

    /* Authorization confirmed; execute the maintenance task. */
    return exec_task(task);
}
