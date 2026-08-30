#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];

    gen_token(token);

    ssize_t written = write(fd, token, 32);

    volatile unsigned char *vp = (volatile unsigned char *)token;
    for (int i = 0; i < 32; i++) {
        vp[i] = 0;
    }

    if (written != 32) {
        return -1;
    }
    return 0;
}
