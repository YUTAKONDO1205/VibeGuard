#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env_password;
    int result;

    if (host == NULL) {
        return -1;
    }

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    if (strlen(env_password) >= sizeof(password)) {
        return -1;
    }

    memcpy(password, env_password, strlen(env_password) + 1);

    result = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return result;
}
