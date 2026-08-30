#include <stdlib.h>
#include <stddef.h>
#include <string.h>

int db_connect(const char *host, const char *password);

/* Portable best-effort secure zeroization that the optimizer must not drop. */
static void secure_wipe(void *buf, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)buf;
    while (len--) {
        *p++ = 0;
    }
}

int open_db_connection(const char *host)
{
    char password[64];
    const char *env;
    size_t len;
    int rc;

    if (host == NULL) {
        return -1;
    }

    /* Read the password from the environment. */
    env = getenv("DB_PASSWORD");
    if (env == NULL) {
        return -1;
    }

    /* Copy into the fixed 64-byte stack buffer with a strict bounds check.
       Reject any password that would not fit together with its NUL
       terminator instead of truncating it silently. */
    len = strlen(env);
    if (len >= sizeof(password)) {
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Erase the password from the stack as soon as it is no longer needed
       so it cannot linger in memory after this frame is reused. */
    secure_wipe(password, sizeof(password));

    return rc;
}
