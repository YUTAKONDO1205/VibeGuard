#include <unistd.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);
    ssize_t written = write(fd, token, 32);
    if (written == 32) {
        return 0;
    }
    return -1;
}
