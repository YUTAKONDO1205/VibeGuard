#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    const char *password_env = getenv("DB_PASSWORD");
    if (password_env == NULL) {
        return -1;
    }

    char password[64];
    strncpy(password, password_env, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    int result = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return result;
}
