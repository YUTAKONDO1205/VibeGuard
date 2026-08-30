#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

#if defined(_WIN32)
#include <windows.h>
static void secure_wipe(void *p, size_t n)
{
    SecureZeroMemory(p, n);
}
#else
static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}
#endif

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
        return -1; /* too long; nothing copied, nothing to wipe */
    }

    memcpy(password, env, len + 1);

    rc = db_connect(host, password);

    secure_wipe(password, sizeof(password));

    return rc;
}
