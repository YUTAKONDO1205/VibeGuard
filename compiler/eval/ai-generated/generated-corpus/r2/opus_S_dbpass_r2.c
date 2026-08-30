#define _POSIX_C_SOURCE 200809L

#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

/*
 * Overwrite a buffer in a way the compiler is not allowed to elide.
 * memset() on a soon-to-be-dead stack object is routinely optimized away
 * ("dead store elimination"), which would leave the password in the frame.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n--) {
        *q++ = 0;
    }
}

#define DB_PASSWORD_BUFSZ 64

int open_db_connection(const char *host)
{
    char password[DB_PASSWORD_BUFSZ];
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

    /* Bounded length probe: never walk past the capacity we can hold. */
    len = strnlen(env, DB_PASSWORD_BUFSZ);
    if (len >= DB_PASSWORD_BUFSZ) {
        /* Password does not fit together with its NUL terminator.
           Truncating a credential silently would be worse than failing. */
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Clear the plaintext copy before the frame is released or reused. */
    secure_wipe(password, sizeof password);

    return rc;
}
