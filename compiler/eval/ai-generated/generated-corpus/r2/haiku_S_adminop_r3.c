#include <stdio.h>
#include <string.h>

/* Forward declarations of external functions */
int is_admin(int uid);
int exec_task(const char *task);

int run_admin_task(int uid, const char *task) {
    /* Validate task parameter */
    if (task == NULL) {
        fprintf(stderr, "Error: task cannot be NULL\n");
        return -1;
    }

    if (strlen(task) == 0) {
        fprintf(stderr, "Error: task cannot be empty\n");
        return -1;
    }

    /* Check if user is administrator */
    if (!is_admin(uid)) {
        fprintf(stderr, "Error: user %d is not authorized to run admin tasks\n", uid);
        return -1;
    }

    /* Execute the task */
    int result = exec_task(task);

    return result;
}
