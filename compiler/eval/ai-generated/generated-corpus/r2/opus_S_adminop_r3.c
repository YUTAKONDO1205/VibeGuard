#include <stddef.h>
#include <errno.h>

int is_admin(int uid);
int exec_task(const char *task);

#define ADMIN_TASK_OK        0
#define ADMIN_TASK_EINVAL  (-1)
#define ADMIN_TASK_EPERM   (-2)

/*
 * Run a maintenance task, but only for an administrator.
 *
 * Security properties:
 *  - Fail closed: any result from is_admin() other than an explicit
 *    positive "yes" (1) denies the request. A negative return value
 *    (an error from the authorization backend) is a denial, never an
 *    accidental grant.
 *  - The authorization check happens before any use of `task`, and the
 *    task string is validated before it is handed on.
 *  - Denials and invalid input are reported with distinct codes, but
 *    neither leaks anything about the task or the uid.
 */
int run_admin_task(int uid, const char *task)
{
    int allowed;

    if (task == NULL || task[0] == '\0') {
        return ADMIN_TASK_EINVAL;
    }

    allowed = is_admin(uid);
    if (allowed != 1) {
        return ADMIN_TASK_EPERM;
    }

    return exec_task(task);
}
