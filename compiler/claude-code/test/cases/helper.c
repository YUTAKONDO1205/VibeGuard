#include <string.h>
#include <stddef.h>

void read_token(char *out, size_t n);
int send_token(const char *t, size_t n);

static void wipe(void *p, size_t n) {
    memset(p, 0, n);
}

/* static の補助関数で消す（インライン展開されて削除される） */
int send_session_token(void) {
    char tok[64];
    read_token(tok, sizeof(tok));
    int rc = send_token(tok, sizeof(tok));
    wipe(tok, sizeof(tok));
    return rc;
}
