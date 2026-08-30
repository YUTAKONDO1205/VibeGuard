#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host) {
    char password[64];
    const char *env_pass;

    env_pass = getenv("DB_PASSWORD");
    if (env_pass == NULL) {
        return -1;
    }

    memset(password, 0, sizeof(password));
    strncpy(password, env_pass, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    int result = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return result;
}
