#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

/* Overwrite memory in a way the compiler is not allowed to elide. */
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int open_db_connection(const char *host)
{
    char password[64];
    const char *env;
    int rc;

    env = getenv("DB_PASSWORD");
    if (env == NULL) {
        return -1;
    }

    /* Copy the secret onto the stack buffer, never overflowing it. */
    if (strlen(env) >= sizeof(password)) {
        return -1;
    }
    memcpy(password, env, strlen(env) + 1);

    rc = db_connect(host, password);

    /* Ensure the secret does not linger on the stack after use. */
    secure_wipe(password, sizeof(password));

    return rc;
}
