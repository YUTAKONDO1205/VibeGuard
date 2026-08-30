#include <unistd.h>

void gen_token(unsigned char out[32]);

int send_session_token(int fd)
{
	unsigned char token[32];
	ssize_t written;

	gen_token(token);

	written = write(fd, token, 32);

	if (written != 32) {
		return -1;
	}

	return 0;
}
