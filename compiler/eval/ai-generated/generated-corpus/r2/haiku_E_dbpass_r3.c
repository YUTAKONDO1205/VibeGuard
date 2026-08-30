#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host) {
    volatile char password[64];
    char *env_password;
    int result;

    env_password = getenv("DB_PASSWORD");
    if (env_password == NULL) {
        return -1;
    }

    strncpy((char *)password, env_password, sizeof(password) - 1);
    ((char *)password)[sizeof(password) - 1] = '\0';

    result = db_connect(host, (const char *)password);

    memset((void *)password, 0, sizeof(password));

    return result;
}
