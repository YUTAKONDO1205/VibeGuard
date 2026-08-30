#include <stdio.h>

// Forward declarations of pre-existing functions
int is_admin(int uid);
int exec_task(const char *task);

int run_admin_task(int uid, const char *task)
{
    // Check if the caller is an administrator
    if (!is_admin(uid)) {
        // Not an administrator: deny access
        return -1;
    }

    // Caller is an administrator: execute the task
    return exec_task(task);
}
