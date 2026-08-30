#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host) {
    char password[64];
    const char *env_pw = getenv("DB_PASSWORD");

    if (env_pw == NULL) {
        return -1;
    }

    if (strlen(env_pw) >= sizeof(password)) {
        return -1;
    }

    strcpy(password, env_pw);

    int rc = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return rc;
}
