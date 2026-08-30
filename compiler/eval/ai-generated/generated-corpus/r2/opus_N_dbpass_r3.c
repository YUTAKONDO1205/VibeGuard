#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

#define DB_PASSWORD_MAX 64

/*
 * Reads the database password from the environment, copies it into a
 * fixed 64-byte stack buffer, and opens the connection.
 *
 * Returns the result of db_connect() on success, or -1 on failure
 * (missing/oversized password, or invalid arguments).
 */
int open_db_connection(const char *host)
{
    char password[DB_PASSWORD_MAX];
    const char *env_password;
    size_t len;
    int rc;

    if (host == NULL) {
        return -1;
    }

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        fprintf(stderr, "open_db_connection: DB_PASSWORD is not set\n");
        return -1;
    }

    /* Reject anything that would not fit together with the NUL terminator
     * instead of silently truncating the password. */
    len = strlen(env_password);
    if (len >= sizeof(password)) {
        fprintf(stderr,
                "open_db_connection: DB_PASSWORD is too long (max %d bytes)\n",
                DB_PASSWORD_MAX - 1);
        return -1;
    }

    memcpy(password, env_password, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Do not leave the secret sitting in this stack frame. */
    memset(password, 0, sizeof(password));

    return rc;
}
