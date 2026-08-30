#include <string.h>
#include <stdlib.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env;
    int rc;

    env = getenv("DB_PASSWORD");
    if (env == NULL) {
        return -1;
    }

    /* Copy the secret into the stack buffer, guarding against overflow. */
    memset(password, 0, sizeof(password));
    strncpy(password, env, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    rc = db_connect(host, password);

    /*
     * Scrub the secret from the stack before returning so it does not
     * linger in memory. memset alone can be elided by the optimizer, so
     * force the write to be observed via a volatile pointer.
     */
    {
        volatile char *p = (volatile char *)password;
        size_t i;
        for (i = 0; i < sizeof(password); i++) {
            p[i] = 0;
        }
    }

    return rc;
}
