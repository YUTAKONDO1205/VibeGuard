#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env_password;
    size_t len;
    int rc;

    if (host == NULL) {
        return -1;
    }

    memset(password, 0, sizeof(password));

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    len = strlen(env_password);
    if (len >= sizeof(password)) {
        return -1;
    }

    memcpy(password, env_password, len);
    password[len] = '\0';

    rc = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return rc;
}
