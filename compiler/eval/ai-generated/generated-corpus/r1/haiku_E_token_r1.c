#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    int ret;

    gen_token(token);
    ret = write(fd, token, 32);

    volatile unsigned char *vp = token;
    for (int i = 0; i < 32; i++) {
        vp[i] = 0;
    }

    return ret;
}
