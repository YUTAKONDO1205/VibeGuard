#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int db_connect(const char *host, const char *password);

int open_db_connection(const char *host) {
    const char *env_password = getenv("DB_PASSWORD");

    if (env_password == NULL) {
        fprintf(stderr, "Error: DB_PASSWORD environment variable not set\n");
        return -1;
    }

    size_t password_len = strlen(env_password);

    if (password_len >= 64) {
        fprintf(stderr, "Error: Password exceeds 64 bytes\n");
        return -1;
    }

    if (host == NULL) {
        fprintf(stderr, "Error: Host cannot be NULL\n");
        return -1;
    }

    char password[64];

    memcpy(password, env_password, password_len);
    password[password_len] = '\0';

    int result = db_connect(host, password);

    memset(password, 0, sizeof(password));

    return result;
}
