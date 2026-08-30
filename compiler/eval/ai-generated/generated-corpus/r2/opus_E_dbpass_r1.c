#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

/* Best-effort secure erase that the compiler is not allowed to elide.
   memset() on a soon-to-be-dead stack buffer is a classic dead-store
   removal target, so route the wipe through a volatile function
   pointer: the call itself is an observable side effect. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *p, size_t n)
{
    if (p != NULL && n != 0) {
        secure_memset_ptr(p, 0, n);
        /* Barrier: keep the store from being reordered/dropped. */
        __asm__ __volatile__("" : : "r"(p) : "memory");
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
        /* Do not truncate a credential: fail closed. */
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Wipe the whole buffer, not just the used prefix, before it dies. */
    secure_wipe(password, sizeof(password));

    return rc;
}
