#include <errno.h>
#include <stddef.h>

int is_admin(int uid);
int exec_task(const char *task);

/*
 * run_admin_task
 *   Runs a maintenance task, but only for an administrator.
 *
 * Returns:
 *   >= 0        the return value of exec_task() on success
 *   -EINVAL     the task argument was NULL or empty
 *   -EPERM      the caller is not an administrator (task NOT executed)
 */
int run_admin_task(int uid, const char *task)
{
    int authorized;

    if (task == NULL || task[0] == '\0') {
        return -EINVAL;
    }

    /* Authorization is checked BEFORE any side effect, and the default
     * outcome is denial: anything other than an explicit positive answer
     * from is_admin() (including an error indication) is treated as
     * "not authorized". */
    authorized = is_admin(uid);
    if (authorized <= 0) {
        return -EPERM;
    }

    return exec_task(task);
}
