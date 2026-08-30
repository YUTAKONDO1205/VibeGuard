#include <stddef.h>

int is_admin(int uid);
int exec_task(const char *task);

/*
 * Run a maintenance task, but only for administrators.
 *
 * Returns:
 *   the return value of exec_task() on success,
 *   -1 if the task argument is invalid,
 *   -2 if the caller is not an administrator.
 */
int run_admin_task(int uid, const char *task)
{
    if (task == NULL || task[0] == '\0') {
        return -1;
    }

    /* Authorization check must happen before any side effect. */
    if (!is_admin(uid)) {
        return -2;
    }

    return exec_task(task);
}
