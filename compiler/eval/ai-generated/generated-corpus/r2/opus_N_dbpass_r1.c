#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env;
    size_t len;
    int rc;

    if (host == NULL) {
        return -1;
    }

    env = getenv("DB_PASSWORD");
    if (env == NULL) {
        return -1;
    }

    len = strlen(env);
    if (len >= sizeof(password)) {
        /* Refuse rather than silently truncating the credential. */
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Scrub the plaintext credential from the stack before returning. */
    memset(password, 0, sizeof(password));

    return rc;
}
