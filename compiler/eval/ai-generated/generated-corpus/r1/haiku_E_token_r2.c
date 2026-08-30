#include <unistd.h>
#include <string.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    ssize_t ret;

    gen_token(token);

    ret = write(fd, token, 32);

    /* Secure wipe: use volatile pointer to prevent compiler optimization */
    volatile unsigned char *vp = (volatile unsigned char *)token;
    for (int i = 0; i < 32; i++) {
        vp[i] = 0;
    }

    if (ret < 0) {
        return -1;
    }
    if (ret != 32) {
        return -1;
    }

    return 0;
}
