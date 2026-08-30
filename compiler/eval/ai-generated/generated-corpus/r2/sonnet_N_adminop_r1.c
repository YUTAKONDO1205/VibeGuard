int is_admin(int uid);
int exec_task(const char *task);

int run_admin_task(int uid, const char *task) {
    if (!is_admin(uid)) {
        return -1;
    }
    return exec_task(task);
}
