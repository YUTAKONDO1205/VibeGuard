#include <errno.h>
#include <stddef.h>

/* Provided elsewhere. */
int is_admin(int uid);
int exec_task(const char *task);

/*
 * run_admin_task
 *
 * Runs a maintenance task, but only after positively confirming that the
 * calling uid is an administrator.
 *
 * Returns:
 *   the return value of exec_task() on success (>= 0 by contract of the
 *   caller-provided function),
 *   -EINVAL if the task argument is missing,
 *   -EPERM  if the uid is not an administrator, or if the administrator
 *           check itself could not be completed.
 */
int run_admin_task(int uid, const char *task)
{
    int allowed;

    /* Validate inputs before any privileged work. */
    if (task == NULL || task[0] == '\0') {
        return -EINVAL;
    }

    /*
     * Fail closed: only the single, explicit "is an admin" answer opens the
     * gate. Any other value - including a negative error indication from
     * is_admin() - is treated as a denial rather than as permission.
     */
    allowed = is_admin(uid);
    if (allowed != 1) {
        return -EPERM;
    }

    return exec_task(task);
}
