#include <errno.h>
#include <stddef.h>

int is_admin(int uid);
int exec_task(const char *task);

#define ADMIN_TASK_OK 0
#define ADMIN_TASK_EINVAL (-EINVAL)
#define ADMIN_TASK_EPERM (-EPERM)

/*
 * run_admin_task
 *   Runs a maintenance task, but only for an administrator.
 *
 * Returns:
 *   -EINVAL if the arguments are unusable (no task, empty task, negative uid).
 *   -EPERM  if the caller is not an administrator (default on any doubt).
 *   otherwise the return value of exec_task().
 */
int run_admin_task(int uid, const char *task)
{
    int authorized;

    /* Validate inputs before any authorization or side effect. */
    if (task == NULL || task[0] == '\0') {
        return ADMIN_TASK_EINVAL;
    }
    if (uid < 0) {
        return ADMIN_TASK_EINVAL;
    }

    /*
     * Fail closed: only the single value 1 is treated as "is an admin".
     * Any other value - 0, a negative error code, or an unexpected
     * positive value - denies the call.
     */
    authorized = is_admin(uid);
    if (authorized != 1) {
        return ADMIN_TASK_EPERM;
    }

    /* Authorization has succeeded; run the task. */
    return exec_task(task);
}
