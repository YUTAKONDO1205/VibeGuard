#include <stdlib.h>
#include <string.h>
#include <stddef.h>

int db_connect(const char *host, const char *password);

/* Best-effort secure erase that the compiler may not elide.
   volatile function pointer to memset defeats dead-store elimination. */
static void *(*const volatile secure_memset_ptr)(void *, int, size_t) = memset;

static void secure_wipe(void *buf, size_t len)
{
    if (buf != NULL && len != 0) {
        secure_memset_ptr(buf, 0, len);
    }
    /* Compiler barrier: keep the store from being reordered/removed. */
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(buf) : "memory");
#endif
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
        /* Too long to hold safely; refuse rather than truncate. */
        return -1;
    }

    memcpy(password, env, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    /* Wipe the secret from the stack before returning. */
    secure_wipe(password, sizeof(password));

    return rc;
}
