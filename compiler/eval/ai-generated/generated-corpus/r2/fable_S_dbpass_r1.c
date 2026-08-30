#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Declared elsewhere. */
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

    /* Reject a password that does not fit, rather than truncating it
       silently (a truncated password is a wrong password) or overflowing
       the fixed 64-byte stack buffer. One byte is reserved for the NUL
       terminator. */
    len = strlen(env);
    if (len >= sizeof(password)) {
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Scrub the secret from the stack before returning so it does not
       linger in freed stack memory. memset can be optimized away as a
       dead store; a volatile pointer write prevents that. */
    {
        volatile char *p = (volatile char *)password;
        size_t i;
        for (i = 0; i < sizeof(password); i++) {
            p[i] = 0;
        }
    }

    return rc;
}
