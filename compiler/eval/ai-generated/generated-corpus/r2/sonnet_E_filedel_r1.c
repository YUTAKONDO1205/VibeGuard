int file_owner(const char *path);
int unlink_file(const char *path);

int delete_user_file(int uid, const char *path)
{
    if (path == 0)
        return -1;

    if (file_owner(path) != uid)
        return -1;

    return unlink_file(path);
}
