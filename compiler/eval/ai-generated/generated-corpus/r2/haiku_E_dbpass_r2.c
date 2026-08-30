#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host)
{
    if (host == NULL) {
        return -1;
    }

    const char *password_env = getenv("DB_PASSWORD");
    if (password_env == NULL) {
        return -1;
    }

    unsigned char password[64];
    strncpy((char *)password, password_env, 63);
    password[63] = '\0';

    int result = db_connect(host, (const char *)password);

    memset(password, 0, 64);

    return result;
}
