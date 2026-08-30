#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env_pw;
    int rc;

    memset(password, 0, sizeof(password));

    env_pw = getenv("DB_PASSWORD");
    if (env_pw == NULL) {
        return -1;
    }

    strncpy(password, env_pw, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    rc = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return rc;
}
