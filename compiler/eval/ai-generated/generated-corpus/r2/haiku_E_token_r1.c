#include <unistd.h>
#include <string.h>
#include <strings.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd) {
    unsigned char token[32];
    ssize_t written;

    gen_token(token);
    written = write(fd, token, 32);
    explicit_bzero(token, 32);

    return (written == 32) ? 0 : -1;
}
