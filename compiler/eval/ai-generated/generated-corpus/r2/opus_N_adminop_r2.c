#include <stddef.h>
#include <errno.h>

int is_admin(int uid);
int exec_task(const char *task);

/*
 * run_admin_task
 *
 * Runs a maintenance task, but only for a caller that is an administrator.
 *
 * Returns:
 *   the return value of exec_task() on success,
 *   -EINVAL if the task argument is missing or empty,
 *   -EPERM  if the caller is not an administrator.
 */
int run_admin_task(int uid, const char *task)
{
    if (task == NULL || task[0] == '\0') {
        return -EINVAL;
    }

    /* Authorization check happens before any side effect. */
    if (!is_admin(uid)) {
        return -EPERM;
    }

    return exec_task(task);
}
