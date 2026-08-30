#include <stddef.h>

/* Function prototypes for externally declared functions */
int is_admin(int uid);
int exec_task(const char *task);

/*
 * run_admin_task - Execute a privileged administrative task
 * @uid: User ID to check for administrative privileges
 * @task: Task string to execute (must not be NULL)
 *
 * Returns:
 *   - Result of exec_task() if uid is an admin and task is valid
 *   - -1 if task is NULL or uid is not an admin
 *
 * Security: Checks administrative privilege before executing task.
 * Fails securely if privilege check fails.
 */
int run_admin_task(int uid, const char *task) {
    /* Validate task pointer */
    if (task == NULL) {
        return -1;
    }

    /* Check if uid has administrative privileges */
    if (!is_admin(uid)) {
        return -1;
    }

    /* Execute task with confirmed admin privilege */
    return exec_task(task);
}
