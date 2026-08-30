#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

/*
 * Fetch the database password from the environment, copy it into a
 * fixed-size stack buffer, connect, and scrub the buffer before returning.
 *
 * Returns the db_connect() result on success, or -1 on error.
 */
int open_db_connection(const char *host)
{
    char password[64];
    const char *env_password;
    size_t len;
    int rc;

    if (host == NULL) {
        return -1;
    }

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    len = strlen(env_password);
    if (len >= sizeof(password)) {
        /* Refuse to truncate: a truncated password is a wrong password. */
        return -1;
    }

    memcpy(password, env_password, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Do not leave the secret sitting on the stack. */
#if defined(__STDC_LIB_EXT1__)
    memset_s(password, sizeof(password), 0, sizeof(password));
#elif defined(_WIN32)
    SecureZeroMemory(password, sizeof(password));
#else
    {
        volatile char *p = (volatile char *)password;
        size_t i;
        for (i = 0; i < sizeof(password); i++) {
            p[i] = 0;
        }
    }
#endif

    return rc;
}
