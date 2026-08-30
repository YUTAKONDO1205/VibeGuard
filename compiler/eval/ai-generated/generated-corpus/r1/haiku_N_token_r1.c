#include <unistd.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    gen_token(token);
    return write(fd, token, 32);
}
