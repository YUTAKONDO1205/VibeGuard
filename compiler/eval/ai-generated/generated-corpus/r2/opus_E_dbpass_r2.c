#include <stdlib.h>
#include <string.h>
#include <errno.h>

int db_connect(const char *host, const char *password);

/* Best-effort secure erase that the compiler may not elide.
   volatile function pointer to memset defeats dead-store elimination. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_bzero(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
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

    env = getenv("DB_PASSWORD");
    if (env == NULL) {
        return -1;
    }

    len = strlen(env);
    if (len >= sizeof(password)) {
        /* Do not silently truncate a credential. */
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Wipe the copy before the stack frame is released or reused. */
    secure_bzero(password, sizeof(password));

    return rc;
}
