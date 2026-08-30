#include <unistd.h>
#include <string.h>
#include <errno.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
    unsigned char token[32];
    ssize_t written;

    gen_token(token);

    written = write(fd, token, sizeof(token));

    memset(token, 0, sizeof(token));

    if (written < 0) {
        return -1;
    }
    if (written != sizeof(token)) {
        return -1;
    }

    return 0;
}
