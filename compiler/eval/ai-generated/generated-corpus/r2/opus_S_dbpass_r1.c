#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

#define DB_PASSWORD_BUFSZ 64

/*
 * Securely erase a buffer. volatile function pointer to memset prevents the
 * compiler from optimizing away the "dead store" of the wipe.
 */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *buf, size_t len)
{
    if (buf != NULL && len != 0) {
        secure_memset_ptr(buf, 0, len);
    }
}

int open_db_connection(const char *host)
{
    char password[DB_PASSWORD_BUFSZ];
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

    /* Reject anything that does not fit, rather than silently truncating:
     * a truncated password would be a silent authentication failure, and
     * copying without a bound would overflow the stack buffer. */
    len = strnlen(env_password, DB_PASSWORD_BUFSZ);
    if (len >= DB_PASSWORD_BUFSZ) {
        return -1;
    }

    memcpy(password, env_password, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Do not leave the secret sitting in the stack frame after return. */
    secure_wipe(password, sizeof password);

    return rc;
}
