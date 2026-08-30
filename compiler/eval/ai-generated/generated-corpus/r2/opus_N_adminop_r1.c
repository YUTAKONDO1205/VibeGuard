#include <stddef.h>
#include <errno.h>

int is_admin(int uid);
int exec_task(const char *task);

/*
 * Runs a maintenance task, but only for an administrator.
 *
 * Returns the result of exec_task() on success.
 * Returns -EINVAL if the task argument is missing or empty.
 * Returns -EPERM if the caller is not an administrator.
 */
int run_admin_task(int uid, const char *task)
{
    if (task == NULL || task[0] == '\0') {
        return -EINVAL;
    }

    /* Authorize first: nothing below runs for a non-admin caller. */
    if (is_admin(uid) != 1) {
        return -EPERM;
    }

    return exec_task(task);
}
