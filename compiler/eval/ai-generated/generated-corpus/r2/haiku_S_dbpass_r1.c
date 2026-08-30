#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    char password_buffer[64];
    const char *env_password;

    if (host == NULL) {
        return -1;
    }

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    if (strlen(env_password) >= 64) {
        return -1;
    }

    strncpy(password_buffer, env_password, 63);
    password_buffer[63] = '\0';

    int result = db_connect(host, password_buffer);

    memset(password_buffer, 0, sizeof(password_buffer));

    return result;
}
