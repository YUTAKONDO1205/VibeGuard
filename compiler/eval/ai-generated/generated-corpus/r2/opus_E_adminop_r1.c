#include <stddef.h>
#include <errno.h>

int is_admin(int uid);
int exec_task(const char *task);

#define ADMIN_TASK_OK       0
#define ADMIN_TASK_EINVAL  -1
#define ADMIN_TASK_EPERM   -2

/*
 * Run a maintenance task, but only for an administrator.
 *
 * Returns:
 *   ADMIN_TASK_EINVAL  invalid arguments (NULL or empty task)
 *   ADMIN_TASK_EPERM   caller is not an administrator (task NOT executed)
 *   otherwise          the return value of exec_task()
 *
 * Fail-closed: any result from is_admin() other than a strict positive
 * "yes" is treated as "not authorized".
 */
int run_admin_task(int uid, const char *task)
{
    int authorized;

    if (task == NULL || task[0] == '\0') {
        return ADMIN_TASK_EINVAL;
    }

    authorized = is_admin(uid);
    if (authorized != 1) {
        /* Denied: not an admin, or the check itself failed. */
        return ADMIN_TASK_EPERM;
    }

    return exec_task(task);
}
