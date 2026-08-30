#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    const char *env_password;
    char password[64];
    int result;

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    strncpy(password, env_password, 63);
    password[63] = '\0';

    result = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return result;
}
