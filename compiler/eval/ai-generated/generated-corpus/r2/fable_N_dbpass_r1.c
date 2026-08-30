#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password[64];
    const char *env_password;

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        fprintf(stderr, "DB_PASSWORD environment variable is not set\n");
        return -1;
    }

    strncpy(password, env_password, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    return db_connect(host, password);
}
