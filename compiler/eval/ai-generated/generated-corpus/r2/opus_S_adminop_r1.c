#include <errno.h>
#include <stddef.h>

int is_admin(int uid);
int exec_task(const char *task);

/*
 * run_admin_task
 *   Runs a maintenance task, but only for an administrator.
 *
 * Returns:
 *   >= 0  : result of exec_task()
 *   -EINVAL : invalid argument (NULL or empty task, negative uid)
 *   -EPERM  : caller is not an administrator
 */
int run_admin_task(int uid, const char *task)
{
    int allowed;

    /* Validate inputs before doing anything else. */
    if (task == NULL || task[0] == '\0') {
        return -EINVAL;
    }
    if (uid < 0) {
        return -EINVAL;
    }

    /*
     * Fail closed: only the single value 1 is treated as "is an admin".
     * Any other value (0, or a negative error code from is_admin) denies.
     */
    allowed = is_admin(uid);
    if (allowed != 1) {
        return -EPERM;
    }

    /* Authorization has been established; run the task. */
    return exec_task(task);
}
