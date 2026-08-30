#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

#define DB_PASSWORD_ENV "DB_PASSWORD"
#define DB_PASSWORD_BUFSZ 64u

/*
 * Overwrite a buffer in a way the compiler is not allowed to elide.
 * memset() on a soon-to-be-dead stack buffer is routinely optimized away
 * ("dead store elimination"), which would leave the plaintext password
 * sitting in the stack frame.
 */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *q = (volatile unsigned char *)p;
    while (n-- > 0u) {
        *q++ = 0u;
    }
}

/*
 * Fetch the database password from the environment, copy it into a
 * fixed 64-byte stack buffer, connect, then scrub the buffer.
 *
 * Returns the result of db_connect() on success, or -1 on failure
 * (bad argument, missing/empty password, password too long).
 */
int open_db_connection(const char *host)
{
    char password[DB_PASSWORD_BUFSZ];
    const char *env;
    size_t len;
    int rc;

    if (host == NULL || host[0] == '\0') {
        return -1;
    }

    /* getenv() returns a pointer into the process environment; do not free. */
    env = getenv(DB_PASSWORD_ENV);
    if (env == NULL || env[0] == '\0') {
        /* Never log or echo the variable's contents, only its absence. */
        fprintf(stderr, "open_db_connection: %s is not set\n", DB_PASSWORD_ENV);
        return -1;
    }

    /*
     * Bounded length check BEFORE copying: strlen() is safe here because the
     * environment string is NUL-terminated, and we reject anything that would
     * not fit together with its terminator rather than silently truncating.
     * Truncation would send a wrong password (and could mask a config error).
     */
    len = strlen(env);
    if (len >= sizeof password) {
        fprintf(stderr,
                "open_db_connection: %s is too long (%zu bytes, max %zu)\n",
                DB_PASSWORD_ENV, len, sizeof password - 1u);
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Minimize the lifetime of the plaintext copy. */
    secure_wipe(password, sizeof password);

    return rc;
}
